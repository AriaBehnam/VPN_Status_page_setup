# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared by both pages: settings, OpenVPN status file, icons, theme and HTTP helpers."""
import html
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# All site-specific values (addresses, client names, stations) live in config.json, not in the code.
CONFIG_FILE = os.environ.get("CONFIG_FILE", "/app/config.json")


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        print("no %s, using defaults" % CONFIG_FILE, flush=True)
        return {}


CONFIG = load_config()
SERVER_IP = os.environ.get("SERVER_IP") or CONFIG.get("server_ip", "10.8.0.1")
VPN_PORT, TL_PORT = 8081, 8082
VPN_PAGE = "http://%s:%d/" % (SERVER_IP, VPN_PORT)
TL_PAGE = "http://%s:%d/" % (SERVER_IP, TL_PORT)
STATUS_FILE = os.environ.get("STATUS_FILE", "/run/openvpn-server/status-server.log")


def esc(s):
    return html.escape(str(s), quote=True)


# ---------- OpenVPN status file ----------

def read_status():
    """Return ({common name: client info}, {common name: set of announced LANs})."""
    clients, lans = {}, {}
    try:
        with open(STATUS_FILE) as f:
            lines = f.read().splitlines()
    except OSError:
        return clients, lans
    hdr = {}
    for line in lines:
        row = line.split(",")
        if row[0] == "HEADER" and len(row) > 1:
            hdr[row[1]] = row[2:]
        elif row[0] == "CLIENT_LIST" and len(row) > 1:
            d = dict(zip(hdr.get("CLIENT_LIST", []), row[1:]))
            clients[d.get("Common Name", row[1])] = d
        elif row[0] == "ROUTING_TABLE" and len(row) > 1:
            d = dict(zip(hdr.get("ROUTING_TABLE", []), row[1:]))
            v = d.get("Virtual Address", "")
            if "/" in v:
                lans.setdefault(d.get("Common Name", ""), set()).add(v)
    return clients, lans


# ---------- icons (Lucide, MIT) ----------

ICONS = {
    "shield": '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    "light": '<rect width="10" height="20" x="7" y="2" rx="3"/><circle cx="12" cy="7" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="17" r="1.5"/>',
    "power": '<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/>',
    "scan": '<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/>',
    "restart": '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
    "router": '<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>',
    "monitor": '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
    "cpu": '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>',
    "network": '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
    "activity": '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
    "gear": '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    "pencil":'<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/>',
    "plus":'<path d="M5 12h14"/><path d="M12 5v14"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
}


def ic(name, cls=""):
    return '<svg class="ic %s" viewBox="0 0 24 24" aria-hidden="true">%s</svg>' % (cls, ICONS[name])


# ---------- theme (same look on both pages) ----------

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--soft:#f3f4f6;--fg:#1f2328;--mut:#6e7781;--line:#e3e6ea;
 --ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--acc:#0969da;--mono:ui-monospace,SFMono-Regular,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--soft:#1d222b;--fg:#e6e8eb;--mut:#8b949e;
 --line:#262b33;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--acc:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:0 16px}
.ic{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px;flex:none}
.mono{font-family:var(--mono);font-size:13px}
.muted{color:var(--mut);font-size:12px}
.sub{color:var(--mut);font-size:12px;margin-top:2px}

/* top bar */
.top{background:var(--card);border-bottom:1px solid var(--line)}
.top .wrap{display:flex;align-items:stretch;gap:18px;height:50px}
.brand{display:flex;align-items:center;gap:8px;font-weight:600}
.brand .ic{color:var(--acc);width:18px;height:18px}
nav{display:flex;gap:2px}
nav a{display:flex;align-items:center;gap:6px;padding:0 12px;color:var(--mut);text-decoration:none;border-bottom:2px solid transparent}
nav a:hover{color:var(--fg)}
nav a.on{color:var(--fg);border-bottom-color:var(--acc);font-weight:500}
main.wrap{padding-top:22px;padding-bottom:40px}

/* page head */
.head{display:flex;align-items:center;flex-wrap:wrap;gap:8px 14px;margin-bottom:16px}
h1{font-size:20px;font-weight:600;margin:0}
h2{display:flex;align-items:center;gap:8px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:600;margin:26px 0 10px}
.cnt{font-weight:500;letter-spacing:0;text-transform:none;background:var(--soft);border:1px solid var(--line);border-radius:9px;padding:0 7px;color:var(--mut)}
.stat{color:var(--mut);font-size:13px}
.stat b{color:var(--fg);font-weight:600}
.tools{margin-left:auto;display:flex;flex-wrap:wrap;gap:6px}
.tools form{margin:0}

/* building blocks */
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--mut);flex:none}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.dot.idle{background:transparent;border:1.5px solid var(--mut)}
.pill{display:inline-block;font-size:11px;line-height:16px;padding:0 7px;border-radius:9px;border:1px solid var(--line);color:var(--mut);white-space:nowrap}
.pill+.pill{margin-left:4px}
.pill.ok{color:var(--ok);border-color:var(--ok)}.pill.bad{color:var(--bad);border-color:var(--bad)}
.pill.warn{color:var(--warn);border-color:var(--warn)}.pill.acc{color:var(--acc);border-color:var(--acc)}
.chip{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:12.5px;background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:2px 8px}
.chip .arrow{color:var(--acc)}
.ok-t{color:var(--ok)}.bad-t{color:var(--bad)}.warn-t{color:var(--warn)}
.tbtn{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;font:inherit;font-size:13px;text-decoration:none}
.tbtn:hover{border-color:var(--mut)}
.tbtn.primary{background:var(--acc);border-color:var(--acc);color:#fff}
.btn{width:30px;height:30px;border-radius:7px;border:1px solid var(--line);background:transparent;color:var(--mut);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;padding:0}
.btn:hover{color:var(--fg);border-color:var(--mut)}
.btn:disabled{opacity:.35;cursor:default}
.btn.go{color:var(--ok);border-color:var(--ok)}
.btn.stop:hover{color:var(--bad);border-color:var(--bad)}
.act{display:flex;gap:4px;justify-content:flex-end;white-space:nowrap}
.act form{margin:0}
.msg{border:1px solid var(--bad);color:var(--bad);background:var(--card);border-radius:8px;padding:9px 12px;margin-bottom:14px}
.msg.info{border-color:var(--line);color:var(--fg)}
.msg.ok{border-color:var(--ok);color:var(--fg)}
.foot{color:var(--mut);font-size:12px;margin-top:16px}

/* tables */
table{width:100%;border-collapse:collapse}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:500;text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
tr.off td{opacity:.6}tr.off:hover td{opacity:1}
.cname{display:flex;align-items:center;gap:8px;font-weight:500;white-space:nowrap}
.cname .ic{color:var(--mut)}
.val{font:600 15px var(--mono)}

/* dialogs */
dialog{border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--fg);padding:20px;width:min(380px,92vw)}
dialog::backdrop{background:rgba(0,0,0,.45)}
dialog input{display:block;width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--fg);margin:4px 0 12px;font:inherit}
dialog label{display:block;font-size:12px;color:var(--mut)}
dialog.wide{width:min(760px,96vw)}
dialog select{width:100%;padding:7px 8px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--fg);font:inherit}
.st td,.st th{padding:6px 8px;vertical-align:middle}
.st input{margin:0}
dialog .msg{margin:10px 0 0}
.dh{font-weight:600;font-size:16px;margin-bottom:12px}
.facts{background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin-bottom:12px;font-size:13px}
.facts div{display:flex;justify-content:space-between;gap:12px;padding:2px 0}
.facts span{color:var(--mut)}
.row{display:flex;gap:8px;justify-content:flex-end;margin-top:8px}
.b1,.b2{padding:7px 14px;border-radius:7px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer;font:inherit}
.b1{background:var(--acc);color:#fff;border-color:var(--acc)}
.b1:disabled{opacity:.5;cursor:default}

/* VPN page: one card per router */
.site{margin-bottom:12px}
.site.off{opacity:.7}.site.off:hover{opacity:1}
.site-head{display:flex;align-items:center;flex-wrap:wrap;gap:6px 14px;padding:12px 14px;border-bottom:1px solid var(--line)}
.site-head .cname{font-size:15px}
.site-head .sess{margin-left:auto;text-align:right;font-size:12.5px}
.site-body{padding:12px 14px;display:grid;grid-template-columns:minmax(0,1fr);gap:12px}
.chip{flex-wrap:wrap;max-width:100%}
.lanrow{display:flex;align-items:center;flex-wrap:wrap;gap:6px 10px;font-size:13px}
.lanrow>.ic{color:var(--mut)}
.lanrow .when{margin-left:auto}
.panels{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.warnbox{color:var(--warn);border:1px solid var(--warn);border-radius:6px;padding:6px 8px;font-size:12px;margin:0 0 6px;overflow-wrap:anywhere}
.warnbox .ic{width:13px;height:13px}
.panel{border:1px solid var(--line);border-radius:8px;background:var(--soft);padding:8px 10px;min-width:0}
.panel h3{display:flex;align-items:center;gap:6px;margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:600}
.panel .cnt{background:var(--card)}
.panel .empty{color:var(--mut);font-size:12.5px;padding:4px 0}
.dv{display:grid;grid-template-columns:auto minmax(0,1fr) auto auto;align-items:center;gap:4px 10px;padding:6px 2px;border-top:1px solid var(--line)}
.dv .bt{display:flex;gap:2px}.dv .bt form{margin:0}
.btn.sm{width:24px;height:24px;border-color:transparent}.btn.sm .ic{width:14px;height:14px}
.btn.sm:hover{border-color:var(--line)}
.dv:first-of-type{border-top:0}
.dv .dn{font-weight:500;overflow:hidden;text-overflow:ellipsis}
.dv .dn small{display:block;font-weight:400;color:var(--mut);font-size:12px}
.dv .da{text-align:right}
.dv .da small{display:block;color:var(--mut);font-size:11.5px;font-family:var(--mono)}
.dv .lt{grid-column:2/-1;font-size:12px}
.dn,.dv .da{overflow-wrap:anywhere}
@keyframes sp{to{transform:rotate(360deg)}}.spin{animation:sp 1s linear infinite}
@keyframes pu{50%{opacity:.3}}.pulse{animation:pu 1s ease-in-out infinite}
.dls{padding:6px 14px;margin-bottom:14px}
.dl{padding:5px 0;display:flex;align-items:center;flex-wrap:wrap;gap:6px}
.dl a{color:var(--acc);text-decoration:none;font-weight:500}
.dl .ic{color:var(--acc)}

/* traffic light page */
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.tile{padding:12px 14px}
.tile .t{display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--mut)}
.tile .v{margin-top:6px}
.flash{animation:fl 1.5s ease-out}
@keyframes fl{from{background:color-mix(in srgb,var(--warn) 25%,transparent)}to{background:transparent}}
.log{font:12.5px/1.6 var(--mono);padding:10px 14px;max-height:280px;overflow:auto}
.log .tm{color:var(--mut);margin-right:10px}.log .fm{color:var(--fg)}.log .cmd{color:var(--ok)}.log .st{color:var(--warn)}.log .bad{color:var(--bad)}

@media(max-width:700px){
 .brand span{display:none}
 nav a{padding:0 8px}
 .hide{display:none}
 .tiles,.panels{grid-template-columns:minmax(0,1fr)}
 td,th{padding:9px 8px}
 .site-head .sess{margin-left:0;text-align:left;width:100%}
 .tools{margin-left:0}
}
"""


def page_shell(title, active, body, script=""):
    """Full HTML page with the shared top bar. active: "vpn" or "tl"."""
    tabs = [("vpn", VPN_PAGE, "shield", "VPN clients")]
    if CONFIG.get("traffic_lights"):
        tabs.append(("tl", TL_PAGE, "light", "Traffic lights"))
    nav = "".join('<a href="%s"%s>%s%s</a>' % (url, ' class="on"' if key == active else "", ic(icon), label)
                  for key, url, icon, label in tabs)
    return ("<!doctype html><html lang=en><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style>"
            "<header class=top><div class=wrap><div class=brand>%s<span>%s</span></div><nav>%s</nav></div></header>"
            "<main class=wrap>%s</main>%s</html>") % (
        esc(title), CSS, ic("shield"), esc(CONFIG.get("title", "VPN status")), nav, body, "<script>%s</script>" % script if script else "")


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    server_version = "status"
    sys_version = ""

    def send_body(self, body, ctype="text/html; charset=utf-8", headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def serve(port, handler):
    while True:
        try:
            srv = ThreadingHTTPServer((SERVER_IP, port), handler)
            break
        except OSError:
            time.sleep(3)   # SERVER_IP not up yet (OpenVPN is starting)
    srv.serve_forever()
