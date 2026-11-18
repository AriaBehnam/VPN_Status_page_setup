#!/usr/bin/env python3
# Traffic light live status page: passively reads tun0 (no extra traffic on the 4G links)
import json, os, socket, struct, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IFACE = "tun0"
BIND = ("10.8.0.1", 8082)
VPN_PAGE = "http://10.8.0.1:8081/"
STATUS_FILES = [os.environ.get("STATUS_FILE", "/run/openvpn-server/status-server.log")]
FM, PLC = "192.168.12.127", "192.168.0.3"
FM_ROUTER, PLC_ROUTER = "client-fleetmanager-new", "client-mainplc-new"
# name, PLC address, router client, fleet manager register index
STATIONS = [
    ("TL1", "192.168.13.2", "client-trafficlight1-new", 0),
    ("TL2", "192.168.14.2", "client-trafficlight2-new", 1),
    ("TL3", "192.168.15.2", "client-trafficlight3-new", 2),
    ("TL4", "192.168.16.2", "client-trafficlight4-new", 3),
    ("TL5", "192.168.17.2", "client-trafficlight5-new", 4),
]
NO_ANSWER = 3.0   # seconds without a reply before a station is shown as not answering

lock = threading.Lock()
BY_IP = {s[1]: s[0] for s in STATIONS}
tl = {s[0]: {"cmd": None, "status": None, "ok": None, "delay": None, "delays": [], "tw": None,
             "seen": None, "changed": None, "writes": 0, "errors": 0} for s in STATIONS}
fm = {"regs": None, "seen": None, "changed": None}
plc = {"sent": None}
log = []

def ts(t):
    return time.strftime("%H:%M:%S", time.localtime(t)) + ".%03d" % int((t % 1) * 1000)

def add_log(now, kind, text):
    log.append({"t": ts(now), "k": kind, "x": text})
    del log[:-20]

def handle(pkt, now):
    if len(pkt) < 20 or pkt[0] >> 4 != 4 or pkt[9] != 6:
        return
    ihl = (pkt[0] & 15) * 4
    tot = struct.unpack("!H", pkt[2:4])[0]
    src, dst = socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20])
    tcp = pkt[ihl:tot]
    if len(tcp) < 20:
        return
    sp, dp = struct.unpack("!HH", tcp[:4])
    pl = tcp[(tcp[12] >> 4) * 4:]
    with lock:
        # Fleet manager -> main PLC: Modbus "write multiple registers" (function 16)
        if src == FM and dst == PLC and dp == 502 and len(pl) >= 13 and pl[7] == 16:
            n = pl[12] // 2
            regs = list(struct.unpack("!%dH" % n, pl[13:13 + 2 * n]))
            if fm["regs"] is not None and regs != fm["regs"]:
                add_log(now, "fm", "Fleet manager → main PLC  %s → %s" % (
                    ",".join(map(str, fm["regs"])), ",".join(map(str, regs))))
                fm["changed"] = now
            fm["regs"], fm["seen"] = regs, now
        # Main PLC -> traffic light: S7 write (36 bytes, value = last byte)
        elif src == PLC and dst in BY_IP and dp == 102 and len(pl) == 36:
            name = BY_IP[dst]
            s = tl[name]
            v = pl[-1]
            if s["cmd"] is not None and v != s["cmd"]:
                extra = ""
                if fm["changed"] and now - fm["changed"] < 5:
                    extra = "  (%.2f s after fleet manager)" % (now - fm["changed"])
                add_log(now, "cmd", "Main PLC → %s  command %02X → %02X%s" % (name, s["cmd"], v, extra))
                s["changed"] = now
            s["cmd"], s["tw"] = v, now
            s["writes"] += 1
            plc["sent"] = now
        # Traffic light -> main PLC: write confirmation (22 bytes) or read answer (26 bytes)
        elif src in BY_IP and sp == 102 and len(pl) in (22, 26):
            name = BY_IP[src]
            s = tl[name]
            s["seen"] = now
            if len(pl) == 22:
                ok = pl[-1] == 0xFF
                if not ok:
                    s["errors"] += 1
                    if s["ok"] is not False:
                        add_log(now, "bad", "%s  write refused (code %02X)" % (name, pl[-1]))
                s["ok"] = ok
                if s["tw"]:
                    d = now - s["tw"]
                    s["delay"] = d
                    s["delays"] = (s["delays"] + [d])[-30:]
            else:
                v = pl[-1]
                if s["status"] is not None and v != s["status"]:
                    add_log(now, "st", "%s → main PLC  status %02X → %02X" % (name, s["status"], v))
                s["status"] = v

def sniff():
    while True:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
            s.bind((IFACE, 0))
            while True:
                pkt, addr = s.recvfrom(65535)
                if addr[2] != socket.PACKET_OUTGOING:   # count each forwarded packet once
                    handle(pkt, time.time())
        except OSError:
            time.sleep(2)   # tun0 gone (OpenVPN restart): wait and reopen

def online_clients():
    names = set()
    for path in STATUS_FILES:
        try:
            for line in open(path):
                if line.startswith("CLIENT_LIST,"):
                    names.add(line.split(",")[1])
        except OSError:
            pass
    return names

def age(t, now):
    return None if t is None else round(now - t, 1)

def snapshot():
    now = time.time()
    on = online_clients()
    with lock:
        rows = []
        for name, ip, router, reg in STATIONS:
            s = tl[name]
            req = fm["regs"][reg] if fm["regs"] and reg < len(fm["regs"]) else None
            a = age(s["seen"], now)
            if router not in on:
                state = "router"
            elif s["seen"] is None:
                state = "nodata"
            elif a > NO_ANSWER:
                state = "noanswer"
            elif s["ok"] is False:
                state = "error"
            else:
                state = "ok"
            avg = sum(s["delays"]) / len(s["delays"]) if s["delays"] else None
            rows.append({"name": name, "ip": ip, "router": router, "router_online": router in on,
                         "fm_req": req, "cmd": s["cmd"], "status": s["status"], "ok": s["ok"],
                         "delay": None if s["delay"] is None else round(s["delay"], 2),
                         "avg_delay": None if avg is None else round(avg, 2),
                         "age": a, "changed_age": age(s["changed"], now),
                         "writes": s["writes"], "errors": s["errors"], "state": state})
        return {"time": ts(now),
                "fm": {"regs": fm["regs"], "age": age(fm["seen"], now),
                       "changed_age": age(fm["changed"], now), "router_online": FM_ROUTER in on},
                "plc": {"sent_age": age(plc["sent"], now), "router_online": PLC_ROUTER in on},
                "stations": rows, "log": list(reversed(log))}

PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Traffic lights</title>
<style>
:root{--bg:#fafafa;--card:#fff;--fg:#1f2328;--mut:#8b949e;--line:#e6e8eb;--ok:#1a9d50;--bad:#d1242f;--warn:#b7791f}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--mut:#7d8590;--line:#262b33;--ok:#3fb950;--bad:#f85149;--warn:#d29922}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px}
.head{display:flex;align-items:baseline;gap:14px;margin-bottom:14px;flex-wrap:wrap}
h1{font-size:18px;font-weight:600;margin:0}
h2{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:500;margin:22px 0 8px}
.stat{color:var(--mut);font-size:13px}.stat b{color:var(--fg);font-weight:600}
.link{margin-left:auto;font-size:13px;color:var(--mut);text-decoration:none}.link:hover{color:var(--fg)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:500;text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
tr.off td{opacity:.6}tr:hover td{opacity:1}
.ic{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--mut);margin-right:8px}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.cname{font-weight:500;white-space:nowrap}.cname .ic{color:var(--mut);margin-right:6px}
.sub{color:var(--mut);font-size:12px;margin-top:2px}
.pill{display:inline-block;font-size:11px;line-height:16px;padding:0 6px;border-radius:9px;border:1px solid var(--line);margin-left:6px;color:var(--mut)}
.pill.ok{color:var(--ok);border-color:var(--ok)}.pill.bad{color:var(--bad);border-color:var(--bad)}.pill.warn{color:var(--warn);border-color:var(--warn)}
.val{font:600 15px ui-monospace,SFMono-Regular,Consolas,monospace}
.val.mis{color:var(--warn)}
.flash{animation:fl 1.5s ease-out}
@keyframes fl{from{background:color-mix(in srgb,var(--warn) 25%,transparent)}to{background:transparent}}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tile{padding:12px 14px}.tile .t{font-size:12px;color:var(--mut)}.tile .t .ic{margin-right:6px}
.tile .v{margin-top:4px}
.log{font:12.5px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;padding:10px 14px;max-height:280px;overflow:auto}
.log .tm{color:var(--mut);margin-right:10px}.log .fm{color:var(--fg)}.log .cmd{color:var(--ok)}.log .st{color:var(--warn)}.log .bad{color:var(--bad)}
.muted{color:var(--mut);font-size:12px}
.foot{color:var(--mut);font-size:12px;margin-top:12px}
@media(max-width:640px){.hide{display:none}.tiles{grid-template-columns:1fr}}
</style>
<main>
<div class=head><h1>Traffic lights</h1><span class=stat id=sum>loading…</span>
<a class=link href="@@VPN@@">VPN clients →</a></div>
<div class=tiles>
 <div class="card tile"><div class=t><svg class=ic viewBox="0 0 24 24"><rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg>Fleet manager → main PLC <span class=muted>(Modbus)</span></div><div class=v id=fm>–</div></div>
 <div class="card tile"><div class=t><svg class=ic viewBox="0 0 24 24"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>Main PLC → traffic lights <span class=muted>(S7)</span></div><div class=v id=plc>–</div></div>
</div>
<h2>Stations</h2>
<div class=card><table>
<tr><th>Station<th>Requested<th>Command<th>Status<th class=hide>Link</tr>
<tbody id=rows></tbody></table></div>
<h2>Recent changes</h2>
<div class="card log" id=log></div>
<div class=foot>Read passively from the VPN server's tunnel, so it adds no traffic on the 4G links. Requested = fleet manager register, Command = byte the main PLC writes (DB1.DBB0), Status = byte it reads back (DB2.DBB0). Link = server ↔ station round trip over 4G. Updates every second.</div>
</main>
<script>
const IC={cpu:'<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/>'};
const ic=n=>'<svg class=ic viewBox="0 0 24 24">'+IC[n]+'</svg>';
const hx=v=>v==null?'–':v.toString(16).toUpperCase().padStart(2,'0');
const ago=a=>a==null?'never':a<60?a.toFixed(1)+' s ago':Math.round(a/60)+' min ago';
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ST={ok:['ok','answering','ok'],error:['bad','write refused','bad'],noanswer:['bad','no answer','bad'],
          router:['bad','router offline','bad'],nodata:['','no data yet','']};
let prev={};
function render(d){
  let n={ok:0,bad:0,idle:0};
  const rows=d.stations.map(s=>{
    const [dot,label,pc]=ST[s.state];
    if(s.state=='ok')n.ok++;else if(s.state=='nodata')n.idle++;else n.bad++;
    const p=prev[s.name]||{};
    const fl=k=>(p[k]!==undefined&&p[k]!==s[k])?' flash':'';
    const link=s.delay==null?'<span class=muted>–</span>':
      s.delay.toFixed(2)+' s<div class=sub>avg '+s.avg_delay.toFixed(2)+' s · '+ago(s.age)+'</div>';
    return '<tr class="'+(s.state=='nodata'?'off':'')+'"><td><div class=cname><span class="dot '+dot+'"></span>'+ic('cpu')+esc(s.name)+'</div>'+
      '<div class=sub>'+esc(s.ip)+'<span class="pill '+pc+'">'+label+'</span></div>'+
      (s.errors?'<div class=sub>'+s.errors+' refused of '+s.writes+'</div>':'')+
      '<td class="'+fl('fm_req')+'"><span class=val>'+(s.fm_req==null?'–':s.fm_req)+'</span>'+
      '<td class="'+fl('cmd')+'"><span class=val>'+hx(s.cmd)+'</span>'+(s.changed_age!=null?'<div class=sub>changed '+ago(s.changed_age)+'</div>':'')+
      '<td class="'+fl('status')+'"><span class=val>'+hx(s.status)+'</span>'+
      '<td class=hide>'+link+'</tr>';
  });
  document.getElementById('rows').innerHTML=rows.join('');
  prev={};d.stations.forEach(s=>prev[s.name]=s);
  document.getElementById('sum').innerHTML='<b>'+n.ok+'</b> answering · <b>'+n.bad+'</b> problem · '+n.idle+' no data · '+esc(d.time);
  const f=d.fm;
  document.getElementById('fm').innerHTML=f.regs?'<span class=val>'+f.regs.join(' · ')+'</span><div class=sub>'+
    (f.age>NO?'<span class="pill bad">no writes</span> ':'')+'last write '+ago(f.age)+(f.changed_age!=null?' · changed '+ago(f.changed_age):'')+
    (f.router_online?'':' <span class="pill bad">router offline</span>')+'</div>':'<span class=muted>no data yet</span>';
  const q=d.plc;
  document.getElementById('plc').innerHTML=q.sent_age==null?'<span class=muted>no data yet</span>':
    '<span class="dot '+(q.sent_age>NO?'bad':'ok')+'"></span>'+(q.sent_age>NO?'not sending':'sending')+
    '<div class=sub>last write '+ago(q.sent_age)+(q.router_online?'':' <span class="pill bad">router offline</span>')+'</div>';
  document.getElementById('log').innerHTML=d.log.length?d.log.map(l=>'<div><span class=tm>'+esc(l.t)+'</span><span class='+l.k+'>'+esc(l.x)+'</span></div>').join(''):
    '<span class=muted>No changes yet. Change a traffic light in the fleet manager.</span>';
}
const NO=@@NO@@;
async function tick(){
  try{const r=await fetch('/api/status',{cache:'no-store'});render(await r.json());}
  catch(e){document.getElementById('sum').textContent='connection lost – retrying…';}
  setTimeout(tick,1000);
}
tick();
</script>"""

class H(BaseHTTPRequestHandler):
    def send(self, body, ctype):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/api/status"):
            self.send(json.dumps(snapshot()), "application/json")
        elif self.path in ("/", "/index.html"):
            self.send(PAGE.replace("@@VPN@@", VPN_PAGE).replace("@@NO@@", str(NO_ANSWER)), "text/html; charset=utf-8")
        else:
            self.send_error(404)
    def log_message(self, *a):
        pass

if __name__ == "__main__":
    threading.Thread(target=sniff, daemon=True).start()
    ThreadingHTTPServer(BIND, H).serve_forever()
