#!/usr/bin/env python3
import glob, hmac, html, ipaddress, os, re, secrets, shutil, subprocess, threading, time, zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STATUS_FILES = [os.environ.get("STATUS_FILE", "/run/openvpn-server/status-server.log")]
CCD = "/etc/openvpn/server/ccd"
DEVICES = "/etc/openvpn/server/devices.txt"
PASSFILE = "/etc/openvpn/server/status-password"
BIND = ("10.8.0.1", 8081)
TL_PAGE = "http://10.8.0.1:8082/"
MAX_HOSTS = 512
MAX_FAILS = 5          # wrong passwords allowed per address
FAIL_WINDOW = 300      # seconds
# PCs are also detected automatically: a ccd file with no iroute line is a PC
PC_CLIENTS = {"client-mypc", "client-pcire", "client-pcrobi", "client-movvo"}

# New client button: same procedure as by hand (UDP server)
EASYRSA = "/etc/openvpn/easy-rsa"
PKI = EASYRSA + "/pki"
SERVER_CONF = "/etc/openvpn/server/server.conf"
CA_FILE = "/etc/openvpn/server/ca.crt"
BUNDLES = "/root/router-bundles"
TEMPLATE_DIR = BUNDLES + "/tcrouter1"
VPN_NET = ipaddress.ip_network("10.8.0.0/24")
TUN = "tun0"
ROUTE_MTU = "1400"     # same cap as site-routes.sh
DL_TTL = 3600          # download links live 1 hour
NAME_RE = re.compile(r"^client-[a-z0-9][a-z0-9_-]{0,47}$")

# 1:1 NAT detection: announced LANs inside NAT_POOL are virtual subnets
# that map to NAT_REAL_LAN inside the vehicle (host byte unchanged).
NAT_POOL = ipaddress.ip_network("172.16.0.0/16")
NAT_REAL_LAN = "192.168.1.0/24"

# restart buttons: key -> services restarted
SERVICES = {
    "openvpn": ["openvpn-server@server", "vpn-status"],
    "status": ["vpn-status"],
}
NO_PASSWORD = {"status"}   # restarts that don't ask for the password

scan = {}
lat = {}
fails = {}
flashes = {}
downloads = {}
lock = threading.Lock()
create_lock = threading.Lock()

MESSAGES = {
    "1": "Wrong password.",
    "2": "Too many wrong attempts. Try again in a few minutes.",
    "3": "No password is configured on the server.",
    "4": "OpenVPN is restarting. Clients reconnect in a few seconds, and this page reloads by itself when it is back.",
    "5": "The status page is restarting and reloads by itself when it is back.",
}
INFO = {"4", "5"}

ICONS = {
    "power": '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>',
    "scan": '<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/>',
    "restart": '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
    "router": '<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>',
    "monitor": '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
    "cpu": '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>',
    "activity": '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
    "plus": '<path d="M5 12h14"/><path d="M12 5v14"/>',
    "link": '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
}

def ic(name, cls=""):
    return '<svg class="ic %s" viewBox="0 0 24 24">%s</svg>' % (cls, ICONS[name])

def flash(text, kind="err"):
    fid = secrets.token_hex(4)
    now = time.time()
    with lock:
        for k in [k for k, v in flashes.items() if now - v[2] > 300]:
            del flashes[k]
        flashes[fid] = (text, kind, now)
    return fid

def read_password():
    try:
        return open(PASSFILE).read().strip()
    except OSError:
        return ""

def check_password(ip, given):
    now = time.time()
    with lock:
        recent = [t for t in fails.get(ip, []) if now - t < FAIL_WINDOW]
        fails[ip] = recent
        if len(recent) >= MAX_FAILS:
            return 2
    secret = read_password()
    if not secret:
        return 3
    if hmac.compare_digest(given.encode(), secret.encode()):
        with lock:
            fails[ip] = []
        return 0
    with lock:
        fails.setdefault(ip, []).append(now)
    return 1

HOST = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--"] if os.environ.get("IN_CONTAINER") else []

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
    # runs from a separate transient unit after 2 s, so this page can answer first
    subprocess.Popen(["systemd-run", "--quiet", "--on-active=2", "systemctl", "restart"] + SERVICES[key],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def read_status():
    clients, lans = {}, {}
    for path in STATUS_FILES:
        try:
            lines = open(path).read().splitlines()
        except OSError:
            continue
        hdr = {}
        for line in lines:
            row = line.split(",")
            if row[0] == "HEADER" and len(row) > 1:
                hdr[row[1]] = row[2:]
            elif row[0] == "CLIENT_LIST":
                d = dict(zip(hdr.get("CLIENT_LIST", []), row[1:]))
                clients[d.get("Common Name", row[1])] = d
            elif row[0] == "ROUTING_TABLE":
                d = dict(zip(hdr.get("ROUTING_TABLE", []), row[1:]))
                v = d.get("Virtual Address", "")
                if "/" in v:
                    lans.setdefault(d.get("Common Name", ""), set()).add(v)
    return clients, lans

def read_ccd():
    out = {}
    for f in sorted(glob.glob(CCD + "/*")):
        ip, disabled, iroutes = "", False, []
        try:
            lines = open(f).read().splitlines()
        except OSError:
            continue
        for l in lines:
            p = l.split()
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

def write_file(path, text, mode=0o644):
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)

def set_access(name, enable):
    if name not in read_ccd():
        return
    path = os.path.join(CCD, name)
    lines = [l for l in open(path).read().splitlines() if l.strip() != "disable"]
    if not enable:
        lines.append("disable")
    tmp = os.path.join(CCD, "." + name + ".tmp")
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    shutil.copymode(path, tmp)
    os.replace(tmp, path)

# ---------- new client ----------

def name_taken(n):
    if os.path.exists(os.path.join(CCD, n)):
        return "a ccd file with this name already exists"
    for p in ("issued/%s.crt", "private/%s.key", "reqs/%s.req"):
        if os.path.exists(os.path.join(PKI, p % n)):
            return "a certificate with this name already exists"
    try:
        for line in open(os.path.join(PKI, "index.txt")):
            if line.rstrip().endswith("/CN=" + n):
                return "this name was used before and Easy-RSA can't reuse it (add -v2 or -new)"
    except OSError:
        pass
    return ""

def template():
    conf = open(os.path.join(TEMPLATE_DIR, "client.conf")).read()
    names = {}
    for l in conf.splitlines():
        p = l.split()
        if len(p) > 1 and p[0] in ("ca", "cert", "key"):
            names[p[0]] = os.path.basename(p[1])
    return conf, names

def pem_cert(path):
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open(path).read(), re.S)
    if not m:
        raise RuntimeError("no certificate found in " + path)
    return m.group(0) + "\n"

def build_router_bundle(n, names, crt, key):
    out = os.path.join(BUNDLES, n)
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(TEMPLATE_DIR, out)
    with open(os.path.join(out, names["cert"]), "w") as f:
        f.write(pem_cert(crt))
    shutil.copyfile(key, os.path.join(out, names["key"]))
    os.chmod(os.path.join(out, names["key"]), 0o600)
    files = sorted(fn for fn in os.listdir(out) if os.path.isfile(os.path.join(out, fn)))
    missing = {"client.conf", names["ca"], names["cert"], names["key"]} - set(files)
    if missing:
        raise RuntimeError("bundle is missing " + ", ".join(sorted(missing)))
    zpath = out + ".zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:   # files only, no folder entries (like zip -D)
        for fn in files:
            z.write(os.path.join(out, fn), fn)
    return zpath

def build_pc_ovpn(n, conf, names, crt, key):
    ca = CA_FILE if os.path.isfile(CA_FILE) else os.path.join(TEMPLATE_DIR, names.get("ca", "ca.crt"))
    keep = [l for l in conf.splitlines()
            if not re.match(r"^\s*(ca|cert|key|tls-auth|tls-crypt|key-direction)(\s|$)", l)]
    body = "\n".join(keep).rstrip() + "\n"
    body += "<ca>\n%s\n</ca>\n" % open(ca).read().strip()
    body += "<cert>\n%s</cert>\n" % pem_cert(crt)
    body += "<key>\n%s\n</key>\n" % open(key).read().strip()
    path = os.path.join(BUNDLES, n + ".ovpn")
    write_file(path, body, 0o600)
    return path

def append_line(path, line, pattern):
    txt = open(path).read()
    if re.search(pattern, txt, re.M):
        return
    with open(path, "a") as f:
        f.write(("\n" if txt and not txt.endswith("\n") else "") + line + "\n")

def add_router_routes(net, ccd):
    a, m = str(net.network_address), str(net.netmask)
    notes = []
    try:
        append_line(SERVER_CONF, "route %s %s" % (a, m), r"^\s*route\s+%s\s" % re.escape(a))
    except OSError as e:
        notes.append("server.conf not updated (%s)" % e.strerror)
    try:
        rc = subprocess.call(["ip", "route", "replace", str(net), "dev", TUN, "mtu", ROUTE_MTU],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        rc = 1
    if rc != 0:
        notes.append("live route not added, restart OpenVPN once")
    pcs = 0
    for other in ccd:
        if is_pc(other, ccd):
            try:
                append_line(os.path.join(CCD, other), 'push "route %s %s"' % (a, m),
                            r'^\s*push\s+"route\s+%s\s' % re.escape(a))
                pcs += 1
            except OSError:
                pass
    return pcs, notes

def create_client(name, kind, ip, lan):
    name = name.strip().lower()
    if name and not name.startswith("client-"):
        name = "client-" + name
    if not NAME_RE.match(name):
        return False, "Name: use lowercase letters, numbers, - or _ (for example trafficlight6-new)."
    kind = "pc" if kind == "pc" else "router"
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False, "VPN IP '%s' is not a valid address." % ip
    if addr not in VPN_NET or addr in (VPN_NET.network_address, VPN_NET.network_address + 1, VPN_NET.broadcast_address):
        return False, "VPN IP must be inside %s, from .2 to .254." % VPN_NET
    with create_lock:
        why = name_taken(name)
        if why:
            return False, "%s: %s." % (name, why)
        ccd = read_ccd()
        for other, d in ccd.items():
            if d["ip"] == str(addr):
                return False, "VPN IP %s is already used by %s%s." % (addr, other, " (disabled)" if d["disabled"] else "")
        net = None
        if kind == "router":
            lan = lan.strip()
            try:
                net = ipaddress.ip_network(lan if "/" in lan else lan + "/24", strict=False)
            except ValueError:
                return False, "Router LAN '%s' is not valid. Use for example 192.168.18.1 or 192.168.18.0/24." % lan
            if net.version != 4 or not net.is_private or not 16 <= net.prefixlen <= 30:
                return False, "Router LAN must be a private IPv4 subnet between /16 and /30."
            if net.overlaps(VPN_NET):
                return False, "Router LAN %s overlaps the VPN network %s." % (net, VPN_NET)
            for other, d in ccd.items():
                for r in d["iroutes"]:
                    if net.overlaps(ipaddress.ip_network(r)):
                        return False, "Router LAN %s overlaps %s of %s%s." % (
                            net, r, other, " (disabled)" if d["disabled"] else "")
        try:
            conf, names = template()
        except OSError:
            return False, "Template %s/client.conf not found." % TEMPLATE_DIR
        if kind == "router" and not all(k in names for k in ("ca", "cert", "key")):
            return False, "Template client.conf has no ca/cert/key line."
        # 1. certificate
        try:
            r = subprocess.run(["./easyrsa", "--batch", "build-client-full", name, "nopass"],
                               cwd=EASYRSA, capture_output=True, text=True, timeout=120)
        except Exception as e:
            return False, "Easy-RSA failed: %s" % e
        crt = os.path.join(PKI, "issued", name + ".crt")
        key = os.path.join(PKI, "private", name + ".key")
        if r.returncode != 0 or not (os.path.isfile(crt) and os.path.isfile(key)):
            tail = (r.stderr or r.stdout or "").strip().splitlines()
            return False, "Easy-RSA failed: %s" % (tail[-1] if tail else "exit code %d, certificate not found" % r.returncode)
        # 2. bundle, 3. ccd file, 4. routes
        try:
            if kind == "router":
                path = build_router_bundle(name, names, crt, key)
                write_file(os.path.join(CCD, name), "ifconfig-push %s 255.255.255.0\niroute %s %s\n" % (
                    addr, net.network_address, net.netmask))
                pcs, notes = add_router_routes(net, ccd)
                info = "router · %s · LAN %s" % (addr, net)
                text = "Created %s (router, %s, LAN %s). Route added on the server and pushed to %d PC client(s), which get it at their next reconnect." % (
                    name, addr, net, pcs)
            else:
                lans = sorted({ipaddress.ip_network(x) for d in ccd.values() if not d["disabled"] for x in d["iroutes"]})
                lines = ["ifconfig-push %s 255.255.255.0" % addr] + [
                    'push "route %s %s"' % (x.network_address, x.netmask) for x in lans]
                path = build_pc_ovpn(name, conf, names, crt, key)
                write_file(os.path.join(CCD, name), "\n".join(lines) + "\n")
                notes = []
                info = "PC · %s · %d routes" % (addr, len(lans))
                text = "Created %s (PC, %s) with routes to %d router LANs." % (name, addr, len(lans))
        except Exception as e:
            return False, "Certificate %s was created, but the next step failed: %s" % (name, e)
        if notes:
            text += " Note: " + "; ".join(notes) + "."
        text += " Download it below (link valid %d min). A copy is in %s." % (DL_TTL // 60, BUNDLES)
        with lock:
            downloads[secrets.token_urlsafe(16)] = {"path": path, "info": info, "exp": time.time() + DL_TTL}
        return True, text

# ---------- devices, scan, latency ----------

def read_devices():
    # line format: client | .2 PLC, .253 router | optional real LAN (NAT override)
    out = {}
    try:
        for line in open(DEVICES):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = [x.strip() for x in line.split("|")]
            labels = {}
            if len(p) > 1:
                for item in p[1].split(","):
                    t = item.strip().split(None, 1)
                    if t and t[0].startswith("."):
                        labels[t[0][1:]] = t[1] if len(t) > 1 else "device"
            real = None
            if len(p) > 2 and p[2]:
                try:
                    real = str(ipaddress.ip_network(p[2], strict=False))
                except ValueError:
                    real = None
            out[p[0]] = {"labels": labels, "real": real}
    except OSError:
        pass
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
                if 0 <= off < r.num_addresses:
                    return str(r.network_address + off)
    except (ValueError, TypeError):
        pass
    return None

def show_ip(ip, nets, cfg):
    real = real_of(ip, nets, cfg)
    return ip + (" ⇄ " + real if real else "")

def hostnum(ip):
    try:
        return int(ip.rsplit(".", 1)[1])
    except (ValueError, IndexError):
        return 0

def device_targets(nets, labels):
    out = []
    for net in sorted(nets):
        base = net.split("/")[0].rsplit(".", 1)[0]
        for last, label in sorted(labels.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
            if not is_router(label):
                out.append((base + "." + last, label))
    return out

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
            if network.num_addresses > MAX_HOSTS:
                continue
            addrs = [str(h) for h in network.hosts()]
            with ThreadPoolExecutor(64) as ex:
                res = list(ex.map(alive, addrs))
            found += [a for a, ok in zip(addrs, res) if ok]
    finally:
        with lock:
            scan[name] = {"nets": nets, "hosts": found, "time": time.time(), "running": False}

def start_scan(name):
    live, lans = read_status()
    if name not in live or is_pc(name, read_ccd()):
        return
    nets = tuple(sorted(lans.get(name, [])))
    if not nets:
        return
    with lock:
        s = scan.get(name)
        if s and s.get("running"):
            return
        scan[name] = {"nets": nets, "hosts": [], "time": time.time(), "running": True}
    threading.Thread(target=do_scan, args=(name, nets), daemon=True).start()

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
    except Exception:
        pass
    return res

def do_ping(name, targets, sess):
    items = []
    try:
        with ThreadPoolExecutor(8) as ex:
            results = list(ex.map(lambda t: ping_one(t[0]), targets))
        items = [(ip, label, r) for (ip, label), r in zip(targets, results)]
    finally:
        with lock:
            lat[name] = {"running": False, "time": time.time(), "sess": sess, "items": items}

def start_ping(name):
    live, lans = read_status()
    c = live.get(name)
    if not c or is_pc(name, read_ccd()):
        return
    cfg = read_devices().get(name, {})
    targets = device_targets(lans.get(name, []), cfg.get("labels", {}))
    if not targets:
        return
    sess = c.get("Connected Since (time_t)")
    with lock:
        l = lat.get(name)
        if l and l.get("running"):
            return
        lat[name] = {"running": True, "time": time.time(), "sess": sess, "items": []}
    threading.Thread(target=do_ping, args=(name, targets, sess), daemon=True).start()

def net_sort(items):
    try:
        return sorted(items, key=lambda s: ipaddress.ip_network(s, strict=False))
    except (ValueError, TypeError):
        return sorted(items)

def hb(n):
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
    h, r = divmod(r, 3600)
    m = r // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m

def analyse(s, cfg):
    labels = cfg.get("labels", {})
    nets = s["nets"]
    live_set = set(s["hosts"])
    bases = [net.split("/")[0].rsplit(".", 1)[0] for net in nets]
    pinned = [k for k, v in labels.items() if is_router(v)]
    devs, unl = [], []
    for h in s["hosts"]:
        last = h.rsplit(".", 1)[1]
        if last in labels:
            if last not in pinned:
                devs.append(("ok", h, labels[last]))
        else:
            unl.append(h)
    for b in bases:
        for last, label in labels.items():
            if last in pinned:
                continue
            ip = b + "." + last
            if ip not in live_set:
                devs.append(("no", ip, label + " · no reply"))
    if pinned:
        parts = []
        for b in bases:
            for k in pinned:
                ip = b + "." + k
                parts.append(html.escape(show_ip(ip, nets, cfg)) +
                             ("" if ip in live_set else ' <span class="pill bad">no reply</span>'))
        r = ic("router") + "<br>".join(parts)
        devs += [("unk", h, "unlabelled") for h in unl]
    elif unl:
        r = ic("router") + "<br>".join(html.escape(show_ip(h, nets, cfg)) for h in unl)
        if len(unl) > 1:
            r += ' <span class="pill warn">several – label the router</span>'
    else:
        r = '<span class="muted">router not found</span>'
    devs.sort(key=lambda d: hostnum(d[1]))
    dh = "".join('<div class="dev %s">%s%s <small>%s</small></div>' % (
        st, ic("cpu"), html.escape(show_ip(ip, nets, cfg)), html.escape(label)) for st, ip, label in devs)
    return r, dh

def lat_html(l, nets, cfg):
    if l.get("running"):
        return '<div class=sub>measuring…</div>'
    out = ""
    for ip, label, r in l.get("items", []):
        who = html.escape("%s · %s" % (label, show_ip(ip, nets, cfg)))
        if not r.get("ok"):
            out += '<div class="lat bad">%sno reply <small>%s</small></div>' % (ic("activity"), who)
            continue
        cls = "ok" if r["avg"] < 100 else ("warn" if r["avg"] < 300 else "bad")
        loss = " · %d%% loss" % round(r["loss"]) if r["loss"] > 0 else ""
        out += '<div class="lat %s" title="%d–%d ms, %d%% loss">%s%d ms <small>%s%s</small></div>' % (
            cls, round(r["min"]), round(r["max"]), round(r["loss"]),
            ic("activity"), round(r["avg"]), who, loss)
    return out

TEMPLATE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>VPN status</title>
<style>
:root{--bg:#fafafa;--card:#fff;--fg:#1f2328;--mut:#8b949e;--line:#e6e8eb;--ok:#1a9d50;--bad:#d1242f;--warn:#b7791f;--acc:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--mut:#7d8590;--line:#262b33;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--acc:#58a6ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:900px;margin:0 auto;padding:24px 16px}
.head{display:flex;align-items:center;flex-wrap:wrap;gap:8px 14px;margin-bottom:14px}
h1{font-size:18px;font-weight:600;margin:0}
.stat{color:var(--mut);font-size:13px}
.stat b{color:var(--fg);font-weight:600}
.tools{margin-left:auto;display:flex;flex-wrap:wrap;gap:6px}
.tools form{margin:0}
.tbtn{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:7px;border:1px solid var(--line);background:transparent;color:var(--mut);cursor:pointer;font:inherit;font-size:12px;text-decoration:none}
.tbtn:hover{color:var(--fg);border-color:var(--mut)}
.tbtn .ic{margin:0}
.msg{border:1px solid var(--bad);color:var(--bad);border-radius:8px;padding:8px 12px;margin-bottom:12px}
.msg.info{border-color:var(--line);color:var(--fg)}
.msg.ok{border-color:var(--ok);color:var(--fg)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.dls{padding:6px 14px;margin-bottom:12px}
.dl{padding:4px 0}.dl a{color:var(--acc);text-decoration:none;font-weight:500}.dl .ic{color:var(--acc);margin-right:6px}
.dl small{color:var(--mut);font-size:12px;margin-left:6px}
table{width:100%;border-collapse:collapse}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:500;text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
tr.off td{opacity:.6}tr.dis td{opacity:.7}tr:hover td{opacity:1}
.ic{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--mut);margin-right:8px}
.dot.on{background:var(--ok)}.dot.dis{background:var(--bad)}
.cname{font-weight:500;white-space:nowrap}
.cname .ic{color:var(--mut);margin-right:6px}
.sub{color:var(--mut);font-size:12px;margin-top:2px}
.pill{display:inline-block;font-size:11px;line-height:16px;padding:0 6px;border-radius:9px;border:1px solid var(--line);margin-left:6px;color:var(--mut)}
.pill.bad{color:var(--bad);border-color:var(--bad)}
.pill.warn{color:var(--warn);border-color:var(--warn)}
.pill.nat{color:var(--acc);border-color:var(--acc)}
.lan{color:var(--mut);font-size:12px}
.rt{margin-top:2px}.rt .ic{color:var(--mut);margin-right:6px}
.dev{font-size:12.5px;margin-top:2px}.dev .ic{margin-right:6px}
.dev.ok .ic{color:var(--ok)}.dev.no .ic{color:var(--bad)}.dev.unk .ic{color:var(--mut)}
.dev small{color:var(--mut);font-size:12px}
.lat{margin-top:4px;font-size:12.5px}.lat .ic{margin-right:6px}
.lat.ok{color:var(--ok)}.lat.warn{color:var(--warn)}.lat.bad{color:var(--bad)}
.lat small{color:var(--mut);font-size:12px}
.muted{color:var(--mut);font-size:12px}
.act{white-space:nowrap;text-align:right}
.act form{display:inline-block;margin:0 0 0 4px}
.btn{width:30px;height:30px;border-radius:7px;border:1px solid var(--line);background:transparent;color:var(--mut);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;padding:0;margin-left:4px}
.act form .btn{margin-left:0}
.btn:hover{color:var(--fg);border-color:var(--mut)}
.btn:disabled{opacity:.35;cursor:default}
.btn.go{color:var(--ok);border-color:var(--ok)}
.btn.stop:hover{color:var(--bad);border-color:var(--bad)}
@keyframes sp{to{transform:rotate(360deg)}}.spin{animation:sp 1s linear infinite}
@keyframes pu{50%{opacity:.3}}.pulse{animation:pu 1s ease-in-out infinite}
.foot{color:var(--mut);font-size:12px;margin-top:12px}
dialog{border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--fg);padding:18px;width:min(340px,90vw)}
dialog::backdrop{background:rgba(0,0,0,.45)}
dialog input,dialog select{display:block;width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--card);color:var(--fg);margin:12px 0;font:inherit}
dialog label{display:block;font-size:12px;color:var(--mut)}
dialog label input,dialog label select{margin:4px 0 10px}
.dh{font-weight:600;margin-bottom:12px}
.row{display:flex;gap:8px;justify-content:flex-end;margin-top:8px}
.b1,.b2{padding:6px 14px;border-radius:7px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer;font:inherit}
.b1{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.b1:disabled{opacity:.5;cursor:default}
@media(max-width:640px){.sess{display:none}}
</style>
<main>
<div class=head><h1>VPN clients</h1>
<span class=stat><b>@@ON@@</b> online · <b>@@DIS@@</b> disabled · @@TOTAL@@ total</span>
<span class=tools>@@TOOLS@@</span></div>
@@MSG@@
@@DLS@@
<div class=card><table>
<tr><th>Client<th>Network<th class=sess>Session<th></tr>
@@ROWS@@
</table></div>
<div class=foot>Scan and latency run only when pressed. Latency is the round trip from the server to each device behind the router. NAT rows show the VPN address ⇄ the real address inside the vehicle. Disabling blocks new connections; a connected client stays up until it drops or OpenVPN restarts.</div>
</main>
<dialog id=dlg><form method=post id=df action=/toggle>
<div id=dt></div>
<input type=hidden name=c id=dc><input type=hidden name=a id=da>
<input type=password name=p id=dp placeholder="Password" required autocomplete=off>
<div class=row><button type=button class=b2 onclick="dlg.close()">Cancel</button><button class=b1>Confirm</button></div>
</form></dialog>
<dialog id=cdlg><form method=post id=cf action=/create onsubmit="var b=this.querySelector('.b1');b.disabled=true;b.textContent='Creating…'">
<div class=dh>New VPN client</div>
<label>Name<input name=name placeholder="trafficlight6-new" required autocomplete=off></label>
<label>Type<select name=kind id=ck onchange="ckc()"><option value=router>Router (zip bundle)<option value=pc>PC (single .ovpn)</select></label>
<label>VPN IP<input name=ip placeholder="10.8.0.x" required autocomplete=off></label>
<label id=cl>Router LAN<input name=lan id=clan placeholder="192.168.18.1 or 192.168.18.0/24" autocomplete=off></label>
<label>Password<input type=password name=p required autocomplete=off></label>
<div class=sub>"client-" is added to the name. Certificate, ccd file, server route and bundle are made like the manual procedure. No OpenVPN restart is needed.</div>
<div class=row><button type=button class=b2 onclick="cdlg.close()">Cancel</button><button class=b1>Create</button></div>
</form></dialog>
<script>
var $=function(i){return document.getElementById(i)};
var dlg=$("dlg"),cdlg=$("cdlg");
function ask(b){$("df").action=b.dataset.u;$("dc").value=b.dataset.c;$("da").value=b.dataset.a;$("dt").textContent=b.dataset.t;$("dp").value="";dlg.showModal();$("dp").focus()}
function ckc(){var r=$("ck").value=="router";$("cl").style.display=r?"":"none";$("clan").required=r}
function newc(){$("cf").reset();ckc();cdlg.showModal()}
if(location.search)history.replaceState(null,"","/");
setInterval(function(){if(document.querySelector("dialog[open]"))return;fetch("/",{cache:"no-store"}).then(function(r){if(r.ok)location.reload()}).catch(function(){})},10000);
</script>"""

def tools_html():
    return (
        '<a class=tbtn href="%s" title="Open the traffic light page">%sTraffic lights</a>' % (TL_PAGE, ic("link")) +
        '<button type=button class=tbtn title="Create a new VPN client" onclick="newc()">%sNew client</button>' % ic("plus") +
        '<button type=button class=tbtn title="Restart OpenVPN (password)" data-u="/restart" data-c="openvpn" data-a="restart" '
        'data-t="Restart the OpenVPN server? All clients disconnect for a few seconds." onclick="ask(this)">%sOpenVPN</button>' % ic("restart") +
        "<form method=post action=/restart onsubmit=\"return confirm('Restart the status page?')\">"
        "<input type=hidden name=c value=status><button class=tbtn title=\"Restart the status page\">%sPage</button></form>" % ic("restart"))

def downloads_html():
    now = time.time()
    with lock:
        for k in [k for k, d in downloads.items() if d["exp"] < now]:
            del downloads[k]
        items = sorted(downloads.items(), key=lambda kv: -kv[1]["exp"])
    if not items:
        return ""
    return '<div class="card dls">%s</div>' % "".join(
        '<div class=dl>%s<a href="/dl/%s" download>%s</a><small>%s · expires in %d min</small></div>' % (
            ic("download"), tok, html.escape(os.path.basename(d["path"])), html.escape(d["info"]),
            max(1, int((d["exp"] - now) / 60))) for tok, d in items)

def page(msg="", kind=""):
    live, lans = read_status()
    ccd, devcfg = read_ccd(), read_devices()
    names = sorted(set(ccd) | set(live),
                   key=lambda n: (n not in live, ccd.get(n, {}).get("disabled", False), n))
    rows, ndis = [], 0
    for n in names:
        c, d = live.get(n), ccd.get(n)
        on = c is not None
        pc = is_pc(n, ccd)
        dis = bool(d and d["disabled"])
        ndis += dis
        d = d or {}
        cfg = devcfg.get(n, {})
        en = html.escape(n, quote=True)
        short = html.escape(n[7:] if n.startswith("client-") else n)
        vip = html.escape((c or {}).get("Virtual Address") or d.get("ip", ""))
        pills = ""
        if not d:
            pills = '<span class="pill">no ccd file</span>'
        elif dis:
            pills = '<span class="pill bad">disabled</span>'
            if on:
                pills += '<span class="pill warn">still connected</span>'
        nets = tuple(sorted(lans.get(n, []))) if on else ()
        if any(real_lan(x, cfg) for x in nets):
            pills += '<span class="pill nat">NAT</span>'
        dot = "dis" if dis else ("on" if on else "")
        cell1 = '<div class=cname title="%s"><span class="dot %s"></span>%s%s</div><div class=sub>%s%s</div>' % (
            en, dot, ic("monitor" if pc else "router"), short, vip, pills)

        net = ""
        scan_btn = ""
        ping_btn = ""
        lat_cell = ""
        if not pc and on:
            if nets:
                parts = []
                for x in net_sort(nets):
                    r = real_lan(x, cfg)
                    parts.append(html.escape(x + (" ⇄ " + r if r else "")))
                lan = "<br>".join(parts)
            else:
                lan = "no LAN announced"
            net = '<div class=lan>%s</div>' % lan
            with lock:
                s = scan.get(n)
                s = dict(s) if s else None
                l = lat.get(n)
                l = dict(l) if l else None
            running = False
            tip = "Scan"
            if s and s["nets"] == nets:
                if s["running"]:
                    running = True
                    net += '<div class=muted>scanning…</div>'
                else:
                    r, dh = analyse(s, cfg)
                    net += '<div class=rt>%s</div>%s' % (r, dh)
                    tip = "Rescan (last %s)" % time.strftime("%H:%M", time.localtime(s["time"]))
            else:
                net += '<div class=muted>not scanned</div>'
            off = "" if (nets and not running) else " disabled"
            scan_btn = ("<form method=post action=/scan><input type=hidden name=c value='%s'>"
                        "<button class=btn title='%s'%s>%s</button></form>") % (
                en, html.escape(tip, quote=True), off, ic("scan", "spin" if running else ""))
            lrun = bool(l and l.get("running"))
            has_devs = bool(nets and device_targets(nets, cfg.get("labels", {})))
            if l and l.get("sess") == c.get("Connected Since (time_t)"):
                lat_cell = lat_html(l, nets, cfg)
            ping_btn = ("<form method=post action=/ping><input type=hidden name=c value='%s'>"
                        "<button class=btn title='%s'%s>%s</button></form>") % (
                en,
                "Latency to devices behind the router" if has_devs else "No devices labelled in devices.txt",
                "" if (has_devs and not lrun) else " disabled",
                ic("activity", "pulse" if lrun else ""))

        if on:
            sess = '<div title="%s">up %s</div><div class=sub>↓ %s &nbsp;↑ %s</div>%s' % (
                html.escape(c.get("Connected Since", ""), quote=True), html.escape(uptime(c)),
                hb(c.get("Bytes Received")), hb(c.get("Bytes Sent")), lat_cell)
        else:
            sess = ""

        toggle = ""
        if d:
            verb = "Enable" if dis else "Disable"
            toggle = ("<button type=button class='btn %s' title='%s' data-u='/toggle' data-c='%s' data-a='%s' data-t='%s' onclick='ask(this)'>%s</button>") % (
                "go" if dis else "stop", verb, en, verb.lower(),
                html.escape("%s %s?" % (verb, n), quote=True), ic("power"))

        cls = "dis" if dis else ("on" if on else "off")
        rows.append("<tr class='%s'><td>%s<td>%s<td class=sess>%s<td class=act>%s%s%s</tr>" % (
            cls, cell1, net, sess, ping_btn, scan_btn, toggle))
    banner = '<div class="msg %s">%s</div>' % (kind, html.escape(msg)) if msg else ""
    return (TEMPLATE.replace("@@ON@@", str(len(live))).replace("@@DIS@@", str(ndis))
            .replace("@@TOTAL@@", str(len(names))).replace("@@TOOLS@@", tools_html())
            .replace("@@MSG@@", banner).replace("@@DLS@@", downloads_html())
            .replace("@@ROWS@@", "\n".join(rows)))

class H(BaseHTTPRequestHandler):
    def send_body(self, b, ctype, extra=()):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path.startswith("/dl/"):
            with lock:
                d = downloads.get(u.path[4:])
            if not d or d["exp"] < time.time() or not os.path.isfile(d["path"]):
                self.send_error(404, "Link expired. The file is still in " + BUNDLES)
                return
            fn = os.path.basename(d["path"])
            self.send_body(open(d["path"], "rb").read(), "application/octet-stream",
                           [("Content-Disposition", 'attachment; filename="%s"' % fn)])
            return
        q = parse_qs(u.query)
        with lock:
            f = flashes.get((q.get("m") or [""])[0])
        body = page(f[0], f[1]) if f else page()
        self.send_body(body.encode(), "text/html; charset=utf-8")
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = parse_qs(self.rfile.read(min(n, 4096)).decode(errors="replace"))
        v = lambda k: (data.get(k) or [""])[0]
        origin = self.headers.get("Origin")
        fid, code = "", 0
        if origin is None or origin == "http://%s:%d" % BIND:
            name, who = v("c"), self.client_address[0]
            if self.path == "/scan":
                start_scan(name)
            elif self.path == "/ping":
                start_ping(name)
            elif self.path == "/toggle":
                act = v("a")
                if act in ("enable", "disable"):
                    code = check_password(who, v("p"))
                    if code == 0:
                        set_access(name, act == "enable")
            elif self.path == "/restart":
                if name in SERVICES:
                    code = 0 if name in NO_PASSWORD else check_password(who, v("p"))
                    if code == 0:
                        schedule_restart(name)
                        code = 4 if name == "openvpn" else 5
            elif self.path == "/create":
                code = check_password(who, v("p"))
                if code == 0:
                    ok, text = create_client(v("name"), v("kind"), v("ip"), v("lan"))
                    fid = flash(text, "ok" if ok else "err")
        if code and not fid:
            fid = flash(MESSAGES[str(code)], "info" if str(code) in INFO else "err")
        self.send_response(303)
        self.send_header("Location", "/?m=" + fid if fid else "/")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    while True:
        try:
            srv = ThreadingHTTPServer(BIND, H)
            break
        except OSError:
            time.sleep(3)   # 10.8.0.1 not up yet (OpenVPN is starting)
    srv.serve_forever()
