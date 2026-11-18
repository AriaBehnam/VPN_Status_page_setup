#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN status page (port 8081).

Shows every OpenVPN client. Routers get a card with their LAN, the router itself and the
components behind it (scan + latency on demand). PCs are listed in a table. Clients can be
enabled / disabled, OpenVPN can be restarted, and new PC clients can be created with one click
(the VPN address is picked automatically).

Extra commands (run inside the container):
  python3 /app/vpn_status.py set-admin-password   change the enable/disable + restart password
  python3 /app/vpn_status.py hash-password        print a hash, e.g. for CREATE_PASSWORD_HASH
"""
import getpass
import glob
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

import common
from common import esc, ic, read_status

# ---------- configuration ----------

CFG = common.CONFIG
SERVER_DIR = CFG.get("server_dir", "/etc/openvpn/server")
CCD = SERVER_DIR + "/ccd"
DEVICES = SERVER_DIR + "/devices.txt"
CA_FILE = SERVER_DIR + "/ca.crt"
EASYRSA = CFG.get("easyrsa_dir", "/etc/openvpn/easy-rsa")
PKI = EASYRSA + "/pki"
BUNDLES = CFG.get("profiles_dir", "/root/router-bundles")   # new .ovpn profiles are kept here
# client.conf whose remote/proto/cipher settings are copied into new PC profiles
TEMPLATE = CFG.get("client_template", BUNDLES + "/template/client.conf")
VPN_NET = ipaddress.ip_network(CFG.get("vpn_network", "10.8.0.0/24"))
PC_HOSTS = range(*CFG.get("pc_host_range", [2, 255]))     # host numbers new PCs may get (.2 – .254)
NAME_RE = re.compile(r"^client-[a-z0-9][a-z0-9_-]{0,47}$")
DL_TTL = 3600                              # download links live 1 hour

# A client whose ccd file has no iroute line is a PC; list exceptions (e.g. PCs without a ccd file) here.
PC_CLIENTS = set(CFG.get("pc_clients", []))

# 1:1 NAT: announced LANs inside the NAT pool are virtual subnets that map to
# the real LAN inside the vehicle (host byte unchanged).
NAT_POOL = ipaddress.ip_network(CFG.get("nat", {}).get("pool", "172.16.0.0/16"))
NAT_REAL_LAN = CFG.get("nat", {}).get("real_lan", "192.168.1.0/24")

SCAN_MAX_HOSTS = 512

# ---------- passwords ----------
# Only PBKDF2-SHA256 hashes are stored, never the passwords themselves.
# Admin password (enable/disable, OpenVPN restart): hash in ADMIN_PASSFILE. A plain-text
# password found there (old setup) is replaced by its hash when the page starts.
ADMIN_PASSFILE = SERVER_DIR + "/status-password"
# "New PC" and "Update" password. Change it with: python3 /app/vpn_status.py hash-password
CREATE_PASSWORD_HASH = os.environ.get("CREATE_PASSWORD_HASH") or (
    "pbkdf2_sha256$200000$5b2ed4c8a551971d298e57356ce9df1c$40fce35328e94cc2af47598c29517f23dc7d0782869dbe403fabee26f0b3c8a4")
PBKDF2_ITERATIONS = 200_000
MAX_FAILS, FAIL_WINDOW = 5, 300            # wrong passwords allowed per address per 5 minutes

# restart buttons: key -> systemd units (in Docker, "vpn-status" = this container, which exits)
SERVICES = {"openvpn": ["openvpn-server@server", "vpn-status"], "status": ["vpn-status"]}
NO_PASSWORD = {"status"}
RESTART_MSG = {
    "openvpn": "OpenVPN is restarting. Clients reconnect in a few seconds, and this page reloads by itself when it is back.",
    "status": "The status page is restarting and reloads by itself when it is back.",
}
HOST = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--"] if os.environ.get("IN_CONTAINER") else []

scan, lat, fails, flashes, downloads = {}, {}, {}, {}, {}
lock = threading.Lock()
create_lock = threading.Lock()
update_lock = threading.Lock()

# "Update" button: new versions come from this public GitHub repo
GITHUB_REPO = "https://github.com/AriaBehnam/VPN_Status_page_setup.git"
GITHUB_BRANCH = "main"
COMPOSE_SERVICE = "vpn-status"          # used to find the project folder on the server
UPDATE_LOG = "update.log"               # in the project folder, written by the rebuild


# ---------- small helpers ----------

def read_text(path):
    with open(path) as f:
        return f.read()


def write_file(path, text, mode=0o644):
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def flash(text, kind="err"):
    fid = secrets.token_hex(4)
    now = time.time()
    with lock:
        for k in [k for k, v in flashes.items() if now - v[2] > 300]:
            del flashes[k]
        flashes[fid] = (text, kind, now)
    return fid


def pill(text, cls=""):
    return '<span class="pill %s">%s</span>' % (cls, esc(text))


def human_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.1f %s" % (n, u)
        n /= 1024
    return "%.1f TB" % n


def uptime(c):
    try:
        s = max(0, int(time.time()) - int(c.get("Connected Since (time_t)")))
    except (TypeError, ValueError):
        return c.get("Connected Since", "")
    d, r = divmod(s, 86400)
    h, m = r // 3600, r % 3600 // 60
    return "%dd %dh" % (d, h) if d else "%dh %dm" % (h, m) if h else "%dm" % m


def ip_key(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def net_sort(items):
    try:
        return sorted(items, key=lambda s: ipaddress.ip_network(s, strict=False))
    except (ValueError, TypeError):
        return sorted(items)


# ---------- passwords ----------

def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt, digest)


def verify_password(password, stored):
    try:
        algo, iterations, salt, _ = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        return hmac.compare_digest(hash_password(password, salt, int(iterations)), stored)
    except ValueError:
        return False


def is_hash(s):
    return s.startswith("pbkdf2_sha256$")


def admin_hash():
    try:
        return read_text(ADMIN_PASSFILE).strip()
    except OSError:
        return ""


def migrate_admin_password():
    """Replace an old plain-text admin password file by its hash (same password)."""
    stored = admin_hash()
    if stored and not is_hash(stored):
        try:
            write_file(ADMIN_PASSFILE, hash_password(stored) + "\n", 0o600)
            print("admin password file converted to a hash", flush=True)
        except OSError as e:
            print("could not hash %s: %s" % (ADMIN_PASSFILE, e), flush=True)


def check_password(ip, given, stored):
    """Return "" if the password is right, otherwise the message to show."""
    now = time.time()
    with lock:
        recent = [t for t in fails.get(ip, []) if now - t < FAIL_WINDOW]
        fails[ip] = recent
        if len(recent) >= MAX_FAILS:
            return "Too many wrong attempts. Try again in a few minutes."
    if not stored:
        return "No password is configured on the server."
    # a plain-text file that could not be converted still works
    ok = verify_password(given, stored) if is_hash(stored) else hmac.compare_digest(given.encode(), stored.encode())
    with lock:
        if ok:
            fails[ip] = []
            return ""
        fails.setdefault(ip, []).append(now)
    return "Wrong password."


def password_cli(cmd):
    pw = getpass.getpass("New password: ")
    if not pw or pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords are empty or do not match.")
    h = hash_password(pw)
    if cmd == "set-admin-password":
        write_file(ADMIN_PASSFILE, h + "\n", 0o600)
        print("Saved to", ADMIN_PASSFILE)
    else:
        print(h)


# ---------- ccd files, devices.txt ----------

def read_ccd():
    out = {}
    for f in sorted(glob.glob(CCD + "/*")):
        ip, disabled, iroutes = "", False, []
        try:
            lines = read_text(f).splitlines()
        except OSError:
            continue
        for line in lines:
            p = line.split()
            if not p or p[0].startswith("#"):
                continue
            if p[0] == "ifconfig-push" and len(p) > 1:
                ip = p[1]
            elif p[0] == "disable":
                disabled = True
            elif p[0] == "iroute" and len(p) > 2:
                try:
                    iroutes.append(str(ipaddress.ip_network(p[1] + "/" + p[2], strict=False)))
                except ValueError:
                    pass
        out[os.path.basename(f)] = {"ip": ip, "disabled": disabled, "iroutes": iroutes}
    return out


def is_pc(name, ccd):
    d = ccd.get(name)
    return name in PC_CLIENTS or (d is not None and not d["iroutes"])


def set_access(name, enable):
    if name not in read_ccd():          # also stops path tricks: only existing ccd names
        return False
    path = os.path.join(CCD, name)
    lines = [l for l in read_text(path).splitlines() if l.strip() != "disable"]
    if not enable:
        lines.append("disable")
    write_file(path, "\n".join(lines) + "\n", os.stat(path).st_mode & 0o777)
    return True


def read_devices():
    """devices.txt line: client | .2 PLC, .253 router | optional real LAN (NAT override)"""
    out = {}
    try:
        lines = read_text(DEVICES).splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = [x.strip() for x in line.split("|")]
        labels = {}
        if len(p) > 1:
            for item in p[1].split(","):
                t = item.strip().split(None, 1)
                if t and t[0].startswith(".") and t[0][1:].isdigit():
                    labels[t[0][1:]] = t[1] if len(t) > 1 else "device"
        real = None
        if len(p) > 2 and p[2]:
            try:
                real = str(ipaddress.ip_network(p[2], strict=False))
            except ValueError:
                pass
        out[p[0]] = {"labels": labels, "real": real}
    return out


def is_router(label):
    return label.strip().lower() == "router"


def real_lan(net, cfg):
    if cfg.get("real"):
        return cfg["real"]
    try:
        if ipaddress.ip_network(net, strict=False).subnet_of(NAT_POOL):
            return NAT_REAL_LAN
    except (ValueError, TypeError):
        pass
    return None


def real_of(ip, nets, cfg):
    """Address inside the vehicle for a VPN-side NAT address, or None."""
    try:
        a = ipaddress.ip_address(ip)
        for net in nets:
            v = ipaddress.ip_network(net, strict=False)
            if a in v:
                r = real_lan(net, cfg)
                if not r:
                    return None
                r = ipaddress.ip_network(r, strict=False)
                off = int(a) - int(v.network_address)
                return str(r.network_address + off) if off < r.num_addresses else None
    except (ValueError, TypeError):
        pass
    return None


def labelled(nets, labels):
    """[(ip, label)] for every labelled host number in every LAN, sorted by address."""
    out = []
    for net in net_sort(nets):
        base = net.split("/")[0].rsplit(".", 1)[0]
        out += [(base + "." + last, label) for last, label in labels.items()]
    return sorted(out, key=lambda t: ip_key(t[0]))


# ---------- scan and latency (only when a button is pressed) ----------

def alive(ip):
    return subprocess.call(["ping", "-c", "1", "-W", "1", "-n", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def do_scan(name, nets):
    found = []
    try:
        for net in nets:
            try:
                network = ipaddress.ip_network(net, strict=False)
            except ValueError:
                continue
            if network.num_addresses > SCAN_MAX_HOSTS:
                continue
            addrs = [str(h) for h in network.hosts()]
            with ThreadPoolExecutor(64) as ex:
                found += [a for a, ok in zip(addrs, ex.map(alive, addrs)) if ok]
    finally:
        with lock:
            scan[name] = {"nets": nets, "hosts": found, "time": time.time(), "running": False}


def ping_one(ip):
    res = {"ok": False, "loss": 100.0}
    try:
        p = subprocess.run(["ping", "-c", "5", "-i", "0.3", "-W", "2", "-n", ip],
                           capture_output=True, text=True, timeout=30)
        m = re.search(r"(\d+(?:\.\d+)?)% packet loss", p.stdout)
        if m:
            res["loss"] = float(m.group(1))
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", p.stdout)
        if m:
            res.update(ok=True, min=float(m.group(1)), avg=float(m.group(2)), max=float(m.group(3)))
    except (OSError, subprocess.SubprocessError):
        pass
    return res


def do_ping(name, targets, sess):
    results = {}
    try:
        with ThreadPoolExecutor(8) as ex:
            results = dict(zip(targets, ex.map(ping_one, targets)))
    finally:
        with lock:
            lat[name] = {"running": False, "time": time.time(), "sess": sess, "items": results}


def router_lans(name):
    """(client info, announced LANs) for an online router, else (None, ())."""
    live, lans = read_status()
    c = live.get(name)
    if not c or is_pc(name, read_ccd()):
        return None, ()
    return c, tuple(sorted(lans.get(name, [])))


def start_scan(name):
    c, nets = router_lans(name)
    if not nets:
        return
    with lock:
        if scan.get(name, {}).get("running"):
            return
        scan[name] = {"nets": nets, "hosts": [], "time": time.time(), "running": True}
    threading.Thread(target=do_scan, args=(name, nets), daemon=True).start()


def start_ping(name):
    c, nets = router_lans(name)
    labels = read_devices().get(name, {}).get("labels", {})
    targets = [ip for ip, label in labelled(nets, labels) if not is_router(label)]
    if not targets:
        return
    sess = c.get("Connected Since (time_t)")
    with lock:
        if lat.get(name, {}).get("running"):
            return
        lat[name] = {"running": True, "time": time.time(), "sess": sess, "items": {}}
    threading.Thread(target=do_ping, args=(name, targets, sess), daemon=True).start()


# ---------- restart ----------

def schedule_restart(key):
    if HOST:
        # in Docker: restart host services through nsenter, then exit so Docker restarts this page
        def run():
            time.sleep(2)
            units = [u for u in SERVICES[key] if u != "vpn-status"]
            if units:
                subprocess.call(HOST + ["systemctl", "restart"] + units,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os._exit(0)
        threading.Thread(target=run, daemon=True).start()
        return
    # on the host: a transient unit restarts us after 2 s, so this page can answer first
    subprocess.Popen(["systemd-run", "--quiet", "--on-active=2", "systemctl", "restart"] + SERVICES[key],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------- update from GitHub ----------

_project = {}
_version = {"t": 0, "text": "", "last": ""}


def host_run(args, timeout=60):
    """Run a command on the server itself (through nsenter when in Docker)."""
    try:
        return subprocess.run(HOST + args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(args, 1, "", str(e))


def last_line(r):
    lines = (r.stderr or r.stdout or "").strip().splitlines()
    return lines[-1] if lines else "exit code %d" % r.returncode


def project():
    """{dir, name, files} of this docker compose project, read from the container labels."""
    if not _project and HOST:
        fmt = "|".join('{{index .Labels "com.docker.compose.%s"}}' % k
                       for k in ("project.working_dir", "project", "project.config_files"))
        r = host_run(["docker", "ps", "--filter", "label=com.docker.compose.service=" + COMPOSE_SERVICE,
                      "--format", fmt], 20)
        for line in r.stdout.splitlines():
            p = line.split("|")
            if len(p) == 3 and p[0]:
                _project.update(dir=p[0], name=p[1], files=[f for f in p[2].split(",") if f])
                break
    return _project


def git(*args, timeout=30):
    d = project().get("dir", "")
    return host_run(["env", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes",
                     "git", "-c", "safe.directory=" + d, "-C", d] + list(args), timeout)


def version_info():
    """(current version, last update result) for the page; cached for a minute."""
    if time.time() - _version["t"] < 60:
        return _version["text"], _version["last"]
    _version["t"] = time.time()
    if project():
        r = git("log", "-1", "--format=%h · %cs", timeout=10)
        _version["text"] = r.stdout.strip() if r.returncode == 0 else ""
        r = host_run(["tail", "-n", "1", os.path.join(project()["dir"], UPDATE_LOG)], 10)
        m = re.match(r"== (\S+ \S+) (start|done exit (\d+))", r.stdout.strip())
        _version["last"] = "" if not m else (
            "running since " + m.group(1) if m.group(2) == "start" else
            "%s · %s" % (m.group(1)[:16], "ok" if m.group(3) == "0" else "failed, see %s" % UPDATE_LOG))
    return _version["text"], _version["last"]


def update():
    """Fetch GitHub; if there is a new version, apply it and rebuild the containers. Returns (message, kind)."""
    if not HOST:
        return "The update button works only when the pages run in Docker.", "err"
    if not update_lock.acquire(blocking=False):
        return "An update check is already running.", "info"
    try:
        p = project()
        if not p:
            return "Could not find the docker compose project of this page on the server.", "err"
        if git("rev-parse", "--git-dir").returncode:
            return "%s on the server is not a git clone, so it can't be updated from GitHub." % p["dir"], "err"
        r = git("fetch", "--quiet", GITHUB_REPO, GITHUB_BRANCH, timeout=90)
        if r.returncode:
            return "Could not read GitHub: %s" % last_line(r), "err"
        head = git("rev-parse", "HEAD").stdout.strip()
        new = git("rev-parse", "FETCH_HEAD").stdout.strip()
        if head == new:
            return "Already up to date (version %s)." % head[:7], "ok"
        if git("merge-base", "--is-ancestor", "HEAD", "FETCH_HEAD").returncode:
            return "The server has its own changes that are not on GitHub; update it by hand.", "err"
        changes = git("log", "--format=%s", "HEAD..FETCH_HEAD").stdout.strip().splitlines()
        r = git("merge", "--ff-only", "--quiet", "FETCH_HEAD")
        if r.returncode:
            return "Could not apply the new version: %s" % last_line(r), "err"
        # rebuild in a separate systemd unit on the server, so it survives this container being replaced
        compose = "docker compose -p '%s' %s" % (p["name"], " ".join("-f '%s'" % f for f in p["files"]))
        script = ('cd "$0" || exit 1; { echo "== $(date \'+%%F %%T\') start"; %s up -d --build --remove-orphans; '
                  'rc=$?; echo "== $(date \'+%%F %%T\') done exit $rc"; } >> %s 2>&1') % (compose, UPDATE_LOG)
        r = host_run(["systemd-run", "--quiet", "--collect", "--unit", "vpn-status-update-%d" % time.time(),
                      "sh", "-c", script, p["dir"]], 20)
        if r.returncode:
            git("reset", "--quiet", "--keep", head)    # back to the running version, so the next click retries
            return "The rebuild could not start, nothing was changed: %s" % last_line(r), "err"
        _version["t"] = 0
        shown = "; ".join(changes[:5]) + (" …" if len(changes) > 5 else "")
        return ("Updating %s → %s (%d change%s: %s). The pages restart in about a minute and this page "
                "reloads by itself." % (head[:7], new[:7], len(changes), "" if len(changes) == 1 else "s", shown)), "info"
    finally:
        update_lock.release()


# ---------- new PC client ----------

def clean_name(raw):
    n = re.sub(r"[\s.]+", "-", raw.strip().lower())
    return n if not n or n.startswith("client-") else "client-" + n


def name_taken(n):
    if os.path.exists(os.path.join(CCD, n)):
        return "a client with this name already exists"
    for p in ("issued/%s.crt", "private/%s.key", "reqs/%s.req"):
        if os.path.exists(os.path.join(PKI, p % n)):
            return "a certificate with this name already exists"
    try:
        with open(os.path.join(PKI, "index.txt")) as f:
            if any(line.rstrip().endswith("/CN=" + n) for line in f):
                return "this name was used before and can't be reused, add for example -2 to it"
    except OSError:
        pass
    return ""


def next_free_ip(ccd, live):
    """Lowest VPN address not given to any client (ccd file) and not in use right now."""
    used = {d["ip"] for d in ccd.values()} | {c.get("Virtual Address", "") for c in live.values()}
    server = VPN_NET.network_address + 1
    for h in PC_HOSTS:
        a = VPN_NET.network_address + h
        if a in VPN_NET and a not in (server, VPN_NET.broadcast_address) and str(a) not in used:
            return a
    return None


def router_networks(ccd):
    return sorted({ipaddress.ip_network(x) for d in ccd.values() if not d["disabled"] for x in d["iroutes"]})


def pem_cert(path):
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", read_text(path), re.S)
    if not m:
        raise RuntimeError("no certificate found in " + path)
    return m.group(0)


def build_pc_ovpn(name, crt, key):
    """Single-file .ovpn: template settings + inline CA, certificate, key (and tls key if used)."""
    tdir = os.path.dirname(TEMPLATE)
    tfile = lambda p: p if os.path.isabs(p) and os.path.isfile(p) else os.path.join(tdir, os.path.basename(p))
    keep, tls, ca, key_dir = [], [], None, None
    for line in read_text(TEMPLATE).splitlines():
        p = line.split()
        d = p[0] if p else ""
        if d not in ("ca", "cert", "key", "tls-auth", "tls-crypt", "key-direction"):
            keep.append(line)
        elif d == "ca" and len(p) > 1:
            ca = tfile(p[1])
        elif d == "key-direction" and len(p) > 1:
            key_dir = p[1]
        elif d in ("tls-auth", "tls-crypt") and len(p) > 1:
            tls.append("<%s>\n%s\n</%s>" % (d, read_text(tfile(p[1])).strip(), d))
            if d == "tls-auth" and len(p) > 2:
                key_dir = p[2]
    ca = CA_FILE if os.path.isfile(CA_FILE) else ca
    if not ca:
        raise RuntimeError("no CA certificate found")
    parts = ["\n".join(keep).rstrip()]
    if key_dir and any(t.startswith("<tls-auth>") for t in tls):
        parts.append("key-direction " + key_dir)
    parts += ["<ca>\n%s\n</ca>" % read_text(ca).strip(),
              "<cert>\n%s\n</cert>" % pem_cert(crt),
              "<key>\n%s\n</key>" % read_text(key).strip()] + tls
    os.makedirs(BUNDLES, exist_ok=True)
    path = os.path.join(BUNDLES, name + ".ovpn")
    write_file(path, "\n".join(parts) + "\n", 0o600)
    return path


def create_pc(raw_name):
    """Certificate + .ovpn profile + ccd file with an automatic VPN address and routes to every router LAN."""
    name = clean_name(raw_name)
    if not NAME_RE.match(name):
        return False, "Name: use letters, numbers, - or _ (for example laptop-1)."
    with create_lock:
        why = name_taken(name)
        if why:
            return False, "%s: %s." % (name, why)
        if not os.path.isfile(TEMPLATE):
            return False, "Template %s not found." % TEMPLATE
        live, _ = read_status()
        ccd = read_ccd()
        addr = next_free_ip(ccd, live)
        if addr is None:
            return False, "No free VPN address left in %s." % VPN_NET
        # 1. certificate
        try:
            r = subprocess.run(["./easyrsa", "--batch", "build-client-full", name, "nopass"],
                               cwd=EASYRSA, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            return False, "Easy-RSA failed: %s" % e
        crt = os.path.join(PKI, "issued", name + ".crt")
        key = os.path.join(PKI, "private", name + ".key")
        if r.returncode != 0 or not (os.path.isfile(crt) and os.path.isfile(key)):
            tail = (r.stderr or r.stdout or "").strip().splitlines()
            return False, "Easy-RSA failed: %s" % (tail[-1] if tail else "exit code %d" % r.returncode)
        # 2. profile, 3. ccd file (fixed address + routes to all router LANs)
        nets = router_networks(ccd)
        try:
            path = build_pc_ovpn(name, crt, key)
            lines = ["ifconfig-push %s %s" % (addr, VPN_NET.netmask)] + [
                'push "route %s %s"' % (n.network_address, n.netmask) for n in nets]
            write_file(os.path.join(CCD, name), "\n".join(lines) + "\n")
        except Exception as e:
            return False, "Certificate %s was created, but the next step failed: %s" % (name, e)
        with lock:
            downloads[secrets.token_urlsafe(16)] = {
                "path": path, "info": "VPN address %s · %d sites" % (addr, len(nets)), "exp": time.time() + DL_TTL}
        return True, ("Created %s with VPN address %s and access to %d router networks. "
                      "Download the profile below (link valid %d min) and import it in the OpenVPN app on the PC. "
                      "A copy is in %s." % (name, addr, len(nets), DL_TTL // 60, BUNDLES))


# ---------- page ----------

def site_devices(nets, cfg, s, l):
    """Split the addresses behind a router into (router, components, note).
    Each item: ip, real, label, state (ok / bad / idle / unk), lat (ping result or None)."""
    labels = cfg.get("labels", {})
    seen = {}     # ip -> (time, reachable), newest of scan and latency wins
    if s:
        for net_ip, _ in labelled(s["nets"], labels):
            seen[net_ip] = (s["time"], False)
        for h in s["hosts"]:
            seen[h] = (s["time"], True)
    pings = (l or {}).get("items", {})
    for ip, r in pings.items():
        if ip not in seen or l["time"] >= seen[ip][0]:
            seen[ip] = (l["time"], r.get("ok", False))

    def item(ip, label, state=None, hint=None):
        if state is None:
            state = ("ok" if seen[ip][1] else "bad") if ip in seen else "idle"
        return {"ip": ip, "real": real_of(ip, nets, cfg), "label": label, "state": state,
                "hint": hint, "lat": pings.get(ip)}

    router, comps = [], []
    for ip, label in labelled(nets, labels):
        if is_router(label):
            router.append(item(ip, "Router"))
        else:
            comps.append(item(ip, label))
    known = {x["ip"] for x in router + comps}
    unlabelled = sorted((h for h in (s["hosts"] if s else []) if h not in known), key=ip_key)
    note = ""
    if router or not unlabelled:
        comps += [item(h, "unlabelled", "unk") for h in unlabelled]
    else:   # no router labelled: whatever answers is probably the router
        router = [item(h, "Router", "ok", "found by scan") for h in unlabelled]
        if len(unlabelled) > 1:
            note = pill("several answer – label the router in devices.txt", "warn")
    return router, sorted(comps, key=lambda x: ip_key(x["ip"])), note


STATE = {"ok": ("ok", "reachable"), "bad": ("bad", "no reply"), "idle": ("idle", "not checked"),
         "unk": ("warn", "found by scan, not in devices.txt")}


def latency_html(r, measuring):
    if measuring:
        return '<span class="muted pulse">measuring…</span>'
    if not r:
        return ""
    if not r.get("ok"):
        return '<span class=bad-t>%s no reply</span>' % ic("activity")
    cls = "ok-t" if r["avg"] < 100 else "warn-t" if r["avg"] < 300 else "bad-t"
    loss = " · %d%% loss" % round(r["loss"]) if r["loss"] > 0 else ""
    return '<span class=%s title="min %d / max %d ms">%s %d ms%s</span>' % (
        cls, round(r["min"]), round(r["max"]), ic("activity"), round(r["avg"]), loss)


def device_row(x, measuring=False):
    dot, text = STATE[x["state"]]
    lt = latency_html(x["lat"], measuring)
    return ('<div class=dv><span class="dot %s" title="%s"></span>'
            '<div class=dn>%s<small>%s</small></div>'
            '<div class=da><span class=mono>%s</span>%s</div>%s</div>') % (
        dot, text, esc(x["label"]), esc(x["hint"] or text), esc(x["ip"]),
        "<small>in vehicle %s</small>" % esc(x["real"]) if x["real"] else "",
        "<div class=lt>%s</div>" % lt if lt else "")


def form_button(action, name, title, icon, enabled=True):
    return ("<form method=post action=%s><input type=hidden name=c value=\"%s\">"
            "<button class=btn title=\"%s\"%s>%s</button></form>") % (
        action, esc(name), esc(title), "" if enabled else " disabled", icon)


def toggle_button(name, disabled):
    verb = "Enable" if disabled else "Disable"
    return ("<button type=button class='btn %s' title='%s' data-c=\"%s\" data-a='%s' "
            "data-t=\"%s\" onclick='ask(this)'>%s</button>") % (
        "go" if disabled else "stop", verb, esc(name), verb.lower(), esc("%s %s?" % (verb, name)), ic("power"))


def status_bits(c, d):
    """(dot class, pills html, VPN address) shared by router cards and PC rows."""
    on, dis = c is not None, bool(d and d["disabled"])
    pills = ""
    if not d:
        pills = pill("no ccd file")
    elif dis:
        pills = pill("disabled", "bad") + (pill("still connected", "warn") if on else "")
    dot = "bad" if dis else "ok" if on else "idle"
    vip = (c or {}).get("Virtual Address") or (d or {}).get("ip", "")
    return dot, pills, vip


def session_html(c):
    if not c:
        return '<span class=muted>offline</span>'
    return '<span title="connected since %s">up %s</span><div class=sub>↓ %s &nbsp;↑ %s</div>' % (
        esc(c.get("Connected Since", "")), esc(uptime(c)),
        human_bytes(c.get("Bytes Received")), human_bytes(c.get("Bytes Sent")))


def short(n):
    return n[7:] if n.startswith("client-") else n


def site_card(n, c, d, cfg, nets, s, l):
    on = c is not None
    dot, pills, vip = status_bits(c, d)
    shown = nets or tuple((d or {}).get("iroutes", []))
    if any(real_lan(x, cfg) for x in shown):
        pills += pill("NAT", "acc")

    s = s if (on and s and s["nets"] == nets) else None
    scanning = bool(s and s["running"])
    l = l if (on and l and l.get("sess") == c.get("Connected Since (time_t)")) else None
    measuring = bool(l and l["running"])
    router, comps, note = site_devices(shown, cfg, None if scanning else s, None if measuring else l)

    # LAN line
    chips = []
    for x in net_sort(shown):
        r = real_lan(x, cfg)
        chips.append('<span class=chip>%s%s</span>' % (
            esc(x), ' <span class=arrow>⇄</span> %s <span class=muted>in vehicle</span>' % esc(r) if r else ""))
    if not chips:
        chips = ['<span class=muted>no LAN announced</span>']
    elif not on:
        chips.append('<span class=muted>(configured)</span>')
    if not on:
        when = ""
    elif scanning:
        when = '<span class="muted pulse">scanning…</span>'
    elif s:
        when = '<span class=muted>checked %s</span>' % time.strftime("%H:%M", time.localtime(s["time"]))
    else:
        when = '<span class=muted>not checked yet – press %s</span>' % ic("scan")
    lanrow = '<div class=lanrow>%s<b>LAN</b>%s<span class=when>%s</span></div>' % (ic("network"), "".join(chips), when)

    router_html = "".join(device_row(x) for x in router) or (
        '<div class=empty>Press scan to find the router.</div>' if on else '<div class=empty>–</div>')
    comps_html = "".join(device_row(x, measuring and x["state"] != "unk") for x in comps) or (
        '<div class=empty>No components listed in devices.txt.</div>')
    panels = ('<div class=panels>'
              '<section class=panel><h3>%s Router %s</h3>%s</section>'
              '<section class=panel><h3>%s Components <span class=cnt>%d</span></h3>%s</section></div>') % (
        ic("router"), note, router_html, ic("cpu"), len(comps), comps_html)

    actions = ""
    if on:
        has_targets = bool(nets) and any(x["state"] != "unk" for x in comps)
        actions += form_button("/ping", n, "Latency to the components" if has_targets
                               else "No components listed in devices.txt",
                               ic("activity", "pulse" if measuring else ""), has_targets and not measuring)
        actions += form_button("/scan", n, "Scan the LAN" + (" (last %s)" % time.strftime(
            "%H:%M", time.localtime(s["time"])) if s and not scanning else ""),
            ic("scan", "spin" if scanning else ""), bool(nets) and not scanning)
    if d:
        actions += toggle_button(n, d["disabled"])

    return ('<article class="card site %s"><div class=site-head>'
            '<div class=cname title="%s"><span class="dot %s"></span>%s%s</div>'
            '<span class=mono>%s</span>%s<div class=sess>%s</div><div class=act>%s</div></div>'
            '<div class=site-body>%s%s</div></article>') % (
        "" if on else "off", esc(n), dot, ic("router"), esc(short(n)), esc(vip), pills,
        session_html(c), actions, lanrow, panels)


def pc_row(n, c, d):
    dot, pills, vip = status_bits(c, d)
    return ('<tr class="%s"><td><div class=cname title="%s"><span class="dot %s"></span>%s%s</div>%s'
            '<td class=mono>%s<td class=hide>%s<td><div class=act>%s</div></tr>') % (
        "" if c else "off", esc(n), dot, ic("monitor"), esc(short(n)),
        "<div class=sub>%s</div>" % pills if pills else "", esc(vip), session_html(c),
        toggle_button(n, d["disabled"]) if d else "")


def downloads_html():
    now = time.time()
    with lock:
        for k in [k for k, d in downloads.items() if d["exp"] < now]:
            del downloads[k]
        items = sorted(downloads.items(), key=lambda kv: -kv[1]["exp"])
    if not items:
        return ""
    return '<div class="card dls">%s</div>' % "".join(
        '<div class=dl>%s<a href="/dl/%s" download>%s</a><span class=muted>%s · expires in %d min</span></div>' % (
            ic("download"), tok, esc(os.path.basename(d["path"])), esc(d["info"]),
            max(1, int((d["exp"] - now) / 60))) for tok, d in items)


SCRIPT = """
var $=function(i){return document.getElementById(i)};
function ask(b){$("dc").value=b.dataset.c;$("da").value=b.dataset.a;$("dt").textContent=b.dataset.t;$("dp").value="";$("dlg").showModal();$("dp").focus()}
function restart(){$("rp").value="";$("rdlg").showModal();$("rp").focus()}
function upd(){$("up").value="";$("udlg").showModal();$("up").focus()}
function newc(){$("cf").reset();$("cdlg").showModal()}
if(location.search)history.replaceState(null,"","/");
setInterval(function(){if(document.querySelector("dialog[open]"))return;
 fetch("/",{cache:"no-store"}).then(function(r){if(r.ok)location.reload()}).catch(function(){})},10000);
"""


def render(msg="", kind=""):
    live, lans = read_status()
    ccd, devcfg = read_ccd(), read_devices()
    names = sorted(set(ccd) | set(live),
                   key=lambda n: (n not in live, ccd.get(n, {}).get("disabled", False), n))
    with lock:
        scans = {k: dict(v) for k, v in scan.items()}
        lats = {k: dict(v) for k, v in lat.items()}
    sites, pcs = [], []
    for n in names:
        c, d = live.get(n), ccd.get(n)
        if is_pc(n, ccd):
            pcs.append(pc_row(n, c, d))
        else:
            nets = tuple(sorted(lans.get(n, []))) if c else ()
            sites.append(site_card(n, c, d, devcfg.get(n, {}), nets, scans.get(n), lats.get(n)))
    ndis = sum(1 for d in ccd.values() if d["disabled"])
    free_ip = next_free_ip(ccd, live)

    tools = (
        '<button type=button class="tbtn primary" onclick="newc()">%sNew PC</button>' % ic("plus") +
        '<button type=button class=tbtn onclick="restart()">%sRestart OpenVPN</button>' % ic("restart") +
        "<form method=post action=/restart onsubmit=\"return confirm('Restart the status page?')\">"
        "<input type=hidden name=c value=status><button class=tbtn title='Restart this page'>%sPage</button></form>"
        % ic("restart") +
        '<button type=button class=tbtn onclick="upd()" title="Get the newest version from GitHub">%sUpdate</button>'
        % ic("download"))
    version, last_update = version_info()
    body = (
        '<div class=head><h1>VPN clients</h1>'
        '<span class=stat><b>%d</b> online · <b>%d</b> disabled · %d total</span>'
        '<span class=tools>%s</span></div>%s%s'
        '<h2>%s Routers <span class=cnt>%d</span></h2>%s'
        '<h2>%s PCs <span class=cnt>%d</span></h2>'
        '<div class=card><table><tr><th>PC<th>VPN address<th class=hide>Session<th></tr>%s</table></div>'
        '<div class=foot>Scan and latency run only when pressed. Latency is the round trip from the server to each '
        'component behind the router. NAT sites show the address you use over the VPN and the real address inside '
        'the vehicle. Disabling blocks new connections; a connected client stays up until it drops or OpenVPN '
        'restarts. Component names come from %s.%s</div>') % (
        len(live), ndis, len(names), tools,
        '<div class="msg %s">%s</div>' % (kind, esc(msg)) if msg else "", downloads_html(),
        ic("router"), len(sites), "".join(sites) or '<div class="card dls muted">No routers.</div>',
        ic("monitor"), len(pcs), "".join(pcs) or '<tr><td colspan=4 class=muted>No PCs.</td></tr>', esc(DEVICES),
        "<br>Version %s" % esc(version) if version else "")

    dialogs = (
        # enable / disable
        '<dialog id=dlg><form method=post action=/toggle>'
        '<div class=dh id=dt></div><input type=hidden name=c id=dc><input type=hidden name=a id=da>'
        '<label>Admin password<input type=password name=p id=dp required autocomplete=off></label>'
        '<div class=row><button type=button class=b2 onclick="this.closest(\'dialog\').close()">Cancel</button>'
        '<button class=b1>Confirm</button></div></form></dialog>'
        # restart OpenVPN
        '<dialog id=rdlg><form method=post action=/restart>'
        '<div class=dh>Restart OpenVPN?</div><div class=sub style="margin-bottom:12px">'
        'All clients disconnect for a few seconds.</div><input type=hidden name=c value=openvpn>'
        '<label>Admin password<input type=password name=p id=rp required autocomplete=off></label>'
        '<div class=row><button type=button class=b2 onclick="this.closest(\'dialog\').close()">Cancel</button>'
        '<button class=b1>Restart</button></div></form></dialog>'
        # update from GitHub
        '<dialog id=udlg><form method=post action=/update '
        'onsubmit="var b=this.querySelector(\'.b1\');b.disabled=true;b.textContent=\'Checking…\'">'
        '<div class=dh>Update from GitHub</div>'
        '<div class=facts><div><span>Installed version</span><b class=mono>%s</b></div>'
        '<div><span>Last update</span><b>%s</b></div></div>'
        '<div class=sub style="margin-bottom:12px">Checks GitHub for a new version. If there is one, it is '
        'downloaded and installed, and the pages restart (about a minute).</div>'
        '<label>Password<input type=password name=p id=up required autocomplete=off></label>'
        '<div class=row><button type=button class=b2 onclick="this.closest(\'dialog\').close()">Cancel</button>'
        '<button class=b1>Check and update</button></div></form></dialog>'
        # new PC
        '<dialog id=cdlg><form method=post action=/create id=cf '
        'onsubmit="var b=this.querySelector(\'.b1\');b.disabled=true;b.textContent=\'Creating…\'">'
        '<div class=dh>New PC</div>'
        '<label>Name of the PC or person<input name=name placeholder="laptop-1" required autocomplete=off '
        'pattern="[A-Za-z0-9][A-Za-z0-9 _.\\-]{0,40}" title="Letters, numbers, - or _"></label>'
        '<div class=facts><div><span>VPN address</span><b class=mono>%s</b></div>'
        '<div><span>Access to</span><b>%d router networks</b></div></div>'
        '<label>Password<input type=password name=p required autocomplete=off></label>'
        '<div class=sub>Everything is set up automatically. You get a .ovpn file to import in the OpenVPN app '
        'on the PC. No OpenVPN restart is needed.</div>'
        '<div class=row><button type=button class=b2 onclick="this.closest(\'dialog\').close()">Cancel</button>'
        '<button class=b1>Create</button></div></form></dialog>') % (
        esc(version or "unknown"), esc(last_update or "–"),
        esc(free_ip or "none free"), len(router_networks(ccd)))

    return common.page_shell("VPN clients", "vpn", body + dialogs, SCRIPT)


# ---------- HTTP ----------

class H(common.Handler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path.startswith("/dl/"):
            with lock:
                d = downloads.get(u.path[4:])
            if not d or d["exp"] < time.time() or not os.path.isfile(d["path"]):
                self.send_error(404, "Link expired. The file is still in " + BUNDLES)
                return
            with open(d["path"], "rb") as f:
                data = f.read()
            fn = os.path.basename(d["path"])
            self.send_body(data, "application/octet-stream", [("Content-Disposition", 'attachment; filename="%s"' % fn)])
        elif u.path in ("/", "/index.html"):
            with lock:
                f = flashes.get((parse_qs(u.query).get("m") or [""])[0])
            self.send_body(render(f[0], f[1]) if f else render())
        else:
            self.send_error(404)

    def same_origin(self):
        origin = self.headers.get("Origin")
        return origin is None or origin in (common.VPN_PAGE.rstrip("/"), "http://" + (self.headers.get("Host") or ""))

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = parse_qs(self.rfile.read(min(n, 4096)).decode(errors="replace"))
        v = lambda k: (data.get(k) or [""])[0]
        res = self.action(urlparse(self.path).path, v) if self.same_origin() else None
        self.send_response(303)
        self.send_header("Location", "/?m=" + flash(*res) if res else "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def action(self, path, v):
        """Run a button; return (message, kind) to show, or None."""
        name, who = v("c"), self.client_address[0]
        if path == "/scan":
            start_scan(name)
        elif path == "/ping":
            start_ping(name)
        elif path == "/toggle" and v("a") in ("enable", "disable"):
            err = check_password(who, v("p"), admin_hash())
            if err:
                return err, "err"
            enable = v("a") == "enable"
            if set_access(name, enable):
                return ("%s enabled." % name if enable else
                        "%s disabled. If it is connected it stays up until it drops or OpenVPN restarts." % name), "ok"
        elif path == "/restart" and name in SERVICES:
            if name not in NO_PASSWORD:
                err = check_password(who, v("p"), admin_hash())
                if err:
                    return err, "err"
            schedule_restart(name)
            return RESTART_MSG[name], "info"
        elif path == "/create":
            err = check_password(who, v("p"), CREATE_PASSWORD_HASH)
            if err:
                return err, "err"
            ok, text = create_pc(v("name"))
            return text, "ok" if ok else "err"
        elif path == "/update":
            err = check_password(who, v("p"), CREATE_PASSWORD_HASH)
            return (err, "err") if err else update()
        return None


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] not in ("set-admin-password", "hash-password"):
            sys.exit(__doc__)
        password_cli(sys.argv[1])
    else:
        migrate_admin_password()
        common.serve(common.VPN_PORT, H)
