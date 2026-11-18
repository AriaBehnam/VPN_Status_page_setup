#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Traffic light live page (port 8082).

Passively reads the packets on tun0 (adds no traffic on the 4G links) and shows what the fleet
manager asks for, what the main PLC writes to each traffic light and what each light answers.
"""
import json
import socket
import struct
import threading
import time
import urllib.request
from urllib.error import URLError
from urllib.parse import parse_qs, urlencode, urlparse

import common
from common import ic, read_status

# addresses come from the "traffic_lights" part of config.json; the stations are chosen in the
# Settings dialog and kept by the VPN page service (config.json stations are the starting list)
CFG = common.CONFIG.get("traffic_lights", {})
SETTINGS_URL = common.VPN_PAGE + "api/tl-settings"
IFACE = CFG.get("interface", "tun0")
FM, FM_ROUTER = CFG.get("fleet_manager", {}).get("ip"), CFG.get("fleet_manager", {}).get("client")
PLC, PLC_ROUTER = CFG.get("main_plc", {}).get("ip"), CFG.get("main_plc", {}).get("client")
# name, PLC address, router client, fleet manager register index
STATIONS = [(s["name"], s["ip"], s["client"], s["register"]) for s in CFG.get("stations", [])]
NO_ANSWER = float(CFG.get("no_answer_seconds", 3.0))   # no reply this long = station not answering
LOG_LINES = 20

lock = threading.Lock()
BY_IP = {}
tl = {}
settings = {"routers": [], "stations": [], "error": ""}


def new_state(ip):
    return {"ip": ip, "cmd": None, "status": None, "ok": None, "delay": None, "delays": [], "tw": None,
            "seen": None, "changed": None, "writes": 0, "errors": 0}


def apply_stations(stations):
    """Use a new station list; a station keeps its live data while its name and PLC stay the same."""
    global STATIONS, BY_IP
    with lock:
        STATIONS = stations
        BY_IP = {s[1]: s[0] for s in stations}
        for name in [k for k in tl if k not in {s[0] for s in stations}]:
            del tl[name]
        for name, ip, _, _ in stations:
            if name not in tl or tl[name]["ip"] != ip:
                tl[name] = new_state(ip)


def load_settings():
    """Read the stations and the PLC candidates from the VPN page service."""
    try:
        with urllib.request.urlopen(SETTINGS_URL, timeout=5) as r:
            data = json.load(r)
        stations = [(s["name"], s["ip"], s["client"], int(s["register"])) for s in data["stations"]]
    except (URLError, OSError, ValueError, KeyError, TypeError) as e:
        settings["error"] = "VPN page not reachable (%s)" % getattr(e, "reason", e)
        return False
    settings.update(routers=data.get("routers", []), stations=data["stations"], error="")
    apply_stations(stations)
    return True


def settings_loop():
    while True:
        load_settings()
        time.sleep(30)


def save_settings(form, who):
    """Pass the new station list and the password on to the VPN page service."""
    body = urlencode({"p": form.get("p", ""), "data": form.get("data", ""), "who": who}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(SETTINGS_URL, data=body), timeout=10) as r:
            res = json.load(r)
    except (URLError, OSError, ValueError) as e:
        return {"ok": False, "msg": "VPN page not reachable (%s)." % getattr(e, "reason", e)}
    if res.get("ok"):
        load_settings()
    return res


apply_stations(STATIONS)
fm = {"regs": None, "seen": None, "changed": None}
plc = {"sent": None}
log = []


def ts(t):
    return time.strftime("%H:%M:%S", time.localtime(t)) + ".%03d" % int((t % 1) * 1000)


def add_log(now, kind, text):
    log.append({"t": ts(now), "k": kind, "x": text})
    del log[:-LOG_LINES]


def handle(pkt, now):
    if len(pkt) < 20 or pkt[0] >> 4 != 4 or pkt[9] != 6:     # IPv4 + TCP only
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
            n = min(pl[12] // 2, (len(pl) - 13) // 2)
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
            with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as s:
                s.bind((IFACE, 0))
                while True:
                    pkt, addr = s.recvfrom(65535)
                    if addr[2] != socket.PACKET_OUTGOING:   # count each forwarded packet once
                        handle(pkt, time.time())
        except OSError:
            time.sleep(2)   # tun0 gone (OpenVPN restart): wait and reopen


def age(t, now):
    return None if t is None else round(now - t, 1)


def snapshot():
    now = time.time()
    on = set(read_status()[0])
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


BODY = """
<div class=head><h1>Traffic lights</h1><span class=stat id=sum>loading…</span>
<span class=tools><button type=button class=tbtn onclick="openSettings()">@@GEAR@@Settings</button></span></div>
<div class=tiles>
 <div class="card tile"><div class=t>@@MONITOR@@Fleet manager → main PLC <span class=muted>(Modbus)</span></div><div class=v id=fm>–</div></div>
 <div class="card tile"><div class=t>@@CPU@@Main PLC → traffic lights <span class=muted>(S7)</span></div><div class=v id=plc>–</div></div>
</div>
<h2>@@LIGHT@@ Stations</h2>
<div class=card><table>
<tr><th>Station<th>Requested<th>Command<th>Status<th class=hide>Link</tr>
<tbody id=rows></tbody></table></div>
<h2>Recent changes</h2>
<div class="card log" id=log></div>
<div class=foot>Read passively from the VPN server's tunnel, so it adds no traffic on the 4G links.
Requested = fleet manager register, Command = byte the main PLC writes (DB1.DBB0), Status = byte it reads back
(DB2.DBB0). Link = server ↔ station round trip over 4G. Updates every second.</div>
<dialog id=sdlg class=wide><form id=sf onsubmit="return saveSettings()">
<div class=dh>Traffic light stations</div>
<div class=sub style="margin-bottom:10px">For each station choose the router and which of its components is the
traffic light PLC. The list of components comes from the names given on the VPN clients page.</div>
<div class=card><table class=st><tr><th>Name<th>Router<th>PLC<th>Register<th></tr><tbody id=srows></tbody></table></div>
<div class=row style="justify-content:flex-start;margin:10px 0 14px"><button type=button class=b2 onclick="addRow()">+ Add station</button></div>
<div id=smsg></div>
<label>Admin password<input type=password id=spw required autocomplete=off></label>
<div class=row><button type=button class=b2 onclick="$('sdlg').close()">Cancel</button><button class=b1 id=ssave>Save</button></div>
</form></dialog>
"""

SCRIPT = """
const NO=@@NO@@, CPU='@@CPU@@';
const $=i=>document.getElementById(i);
const hx=v=>v==null?'–':v.toString(16).toUpperCase().padStart(2,'0');
const ago=a=>a==null?'never':a<60?a.toFixed(1)+' s ago':Math.round(a/60)+' min ago';
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pill=(t,c)=>'<span class="pill '+c+'">'+t+'</span>';
const ST={ok:['ok','answering'],error:['bad','write refused'],noanswer:['bad','no answer'],
          router:['bad','router offline'],nodata:['idle','no data yet']};
let prev={};
function render(d){
  const n={ok:0,bad:0,idle:0};
  const rows=d.stations.map(s=>{
    const [c,label]=ST[s.state];
    if(s.state=='ok')n.ok++;else if(s.state=='nodata')n.idle++;else n.bad++;
    const p=prev[s.name]||{};
    const fl=k=>(p[k]!==undefined&&p[k]!==s[k])?' class=flash':'';
    const link=s.delay==null?'<span class=muted>–</span>':
      s.delay.toFixed(2)+' s<div class=sub>avg '+s.avg_delay.toFixed(2)+' s · '+ago(s.age)+'</div>';
    return '<tr class="'+(s.state=='nodata'?'off':'')+'"><td><div class=cname><span class="dot '+c+'"></span>'+CPU+esc(s.name)+'</div>'+
      '<div class=sub><span class=mono>'+esc(s.ip)+'</span> '+pill(label,c)+'</div>'+
      (s.errors?'<div class=sub>'+s.errors+' refused of '+s.writes+'</div>':'')+
      '<td'+fl('fm_req')+'><span class=val>'+(s.fm_req==null?'–':s.fm_req)+'</span>'+
      '<td'+fl('cmd')+'><span class=val>'+hx(s.cmd)+'</span>'+(s.changed_age!=null?'<div class=sub>changed '+ago(s.changed_age)+'</div>':'')+
      '<td'+fl('status')+'><span class=val>'+hx(s.status)+'</span>'+
      '<td class=hide>'+link+'</tr>';
  });
  $('rows').innerHTML=rows.join('');
  prev={};d.stations.forEach(s=>prev[s.name]=s);
  $('sum').innerHTML='<b>'+n.ok+'</b> answering · <b>'+n.bad+'</b> problem · '+n.idle+' no data · '+esc(d.time);
  const f=d.fm, off=' '+pill('router offline','bad');
  $('fm').innerHTML=f.regs?'<span class=val>'+f.regs.join(' · ')+'</span><div class=sub>'+
    (f.age>NO?pill('no writes','bad')+' ':'')+'last write '+ago(f.age)+(f.changed_age!=null?' · changed '+ago(f.changed_age):'')+
    (f.router_online?'':off)+'</div>':'<span class=muted>no data yet</span>';
  const q=d.plc;
  $('plc').innerHTML=q.sent_age==null?'<span class=muted>no data yet</span>':
    '<span class=cname><span class="dot '+(q.sent_age>NO?'bad':'ok')+'"></span>'+(q.sent_age>NO?'not sending':'sending')+'</span>'+
    '<div class=sub>last write '+ago(q.sent_age)+(q.router_online?'':off)+'</div>';
  $('log').innerHTML=d.log.length?d.log.map(l=>'<div><span class=tm>'+esc(l.t)+'</span><span class='+l.k+'>'+esc(l.x)+'</span></div>').join(''):
    '<span class=muted>No changes yet. Change a traffic light in the fleet manager.</span>';
}
let ROUTERS=[];
async function openSettings(){
  $('smsg').innerHTML='';$('spw').value='';$('srows').innerHTML='<tr><td colspan=5 class=muted>loading…</td></tr>';
  $('sdlg').showModal();
  try{const d=await (await fetch('/api/settings',{cache:'no-store'})).json();
    if(d.error){$('smsg').innerHTML='<div class=msg>'+esc(d.error)+'</div>'}
    ROUTERS=d.routers;$('srows').innerHTML='';d.stations.forEach(addRow);if(!d.stations.length)addRow();}
  catch(e){$('srows').innerHTML='<tr><td colspan=5 class=muted>could not load the settings</td></tr>'}
}
function plcOptions(sel,client,ip){
  const r=ROUTERS.find(x=>x.client==client),c=r?r.components:[];
  let o=c.map(x=>'<option value="'+esc(x.ip)+'"'+(x.ip==ip?' selected':'')+'>'+esc(x.label)+' – '+esc(x.ip)+'</option>');
  if(ip&&!c.some(x=>x.ip==ip))o.unshift('<option value="'+esc(ip)+'" selected>'+esc(ip)+' (not named)</option>');
  if(!o.length)o=['<option value="">no components named on the VPN page</option>'];
  sel.innerHTML=o.join('');
}
function addRow(s){
  s=s&&s.name!==undefined?s:{name:'',client:'',ip:'',register:$('srows').rows.length};
  const tr=document.createElement('tr');
  tr.innerHTML='<td><input class=sn maxlength=20 required placeholder="TL1"><td><select class=sr></select>'+
    '<td><select class=sp></select><td><input class=sg type=number min=0 max=255 required style="width:70px">'+
    '<td><button type=button class="btn sm" title="Remove" onclick="this.parentNode.parentNode.remove()">×</button>';
  const sr=tr.querySelector('.sr'),sp=tr.querySelector('.sp');
  let ro=ROUTERS.map(r=>'<option value="'+esc(r.client)+'"'+(r.client==s.client?' selected':'')+'>'+esc(r.name)+(r.disabled?' (disabled)':'')+'</option>');
  if(s.client&&!ROUTERS.some(r=>r.client==s.client))ro.unshift('<option value="'+esc(s.client)+'" selected>'+esc(s.client)+' (unknown)</option>');
  sr.innerHTML=ro.join('');
  sr.onchange=()=>plcOptions(sp,sr.value,'');
  plcOptions(sp,sr.value,s.ip);
  tr.querySelector('.sn').value=s.name;tr.querySelector('.sg').value=s.register;
  $('srows').appendChild(tr);
}
async function saveSettings(){
  const st=[...$('srows').rows].map(r=>({name:r.querySelector('.sn').value,client:r.querySelector('.sr').value,
    ip:r.querySelector('.sp').value,register:r.querySelector('.sg').value}));
  const b=$('ssave');b.disabled=true;b.textContent='Saving…';
  try{const r=await fetch('/settings',{method:'POST',body:new URLSearchParams({p:$('spw').value,data:JSON.stringify(st)})});
    const d=await r.json();
    $('smsg').innerHTML='<div class="msg '+(d.ok?'ok':'')+'">'+esc(d.msg)+'</div>';
    if(d.ok)setTimeout(()=>$('sdlg').close(),1200);}
  catch(e){$('smsg').innerHTML='<div class=msg>Could not save.</div>'}
  b.disabled=false;b.textContent='Save';return false;
}
async function tick(){
  try{const r=await fetch('/api/status',{cache:'no-store'});render(await r.json());}
  catch(e){$('sum').textContent='connection lost – retrying…';}
  setTimeout(tick,1000);
}
tick();
if(location.hash=='#settings')openSettings();
"""

PAGE = common.page_shell(
    "Traffic lights", "tl",
    BODY.replace("@@MONITOR@@", ic("monitor")).replace("@@CPU@@", ic("cpu")).replace("@@LIGHT@@", ic("light"))
    .replace("@@GEAR@@", ic("gear")),
    SCRIPT.replace("@@NO@@", str(NO_ANSWER)).replace("@@CPU@@", ic("cpu")))


class H(common.Handler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/status":
            self.send_body(json.dumps(snapshot()), "application/json")
        elif path == "/api/settings":
            load_settings()
            self.send_body(json.dumps({k: settings[k] for k in ("routers", "stations", "error")}), "application/json")
        elif path in ("/", "/index.html"):
            self.send_body(PAGE)
        else:
            self.send_error(404)


    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(min(n, 16384)).decode(errors="replace")).items()}
        origin = self.headers.get("Origin")
        if urlparse(self.path).path != "/settings":
            self.send_error(404)
        elif origin not in (None, common.TL_PAGE.rstrip("/"), "http://" + (self.headers.get("Host") or "")):
            self.send_error(403)
        else:
            self.send_body(json.dumps(save_settings(form, self.client_address[0])), "application/json")


if __name__ == "__main__":
    threading.Thread(target=sniff, daemon=True).start()
    threading.Thread(target=settings_loop, daemon=True).start()
    common.serve(common.TL_PORT, H)
