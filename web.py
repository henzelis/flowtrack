#!/usr/bin/env python3
"""flowtrack-web: minimal dashboard for flowtrack SQLite data.
Stdlib only (http.server). Serves / (HTML+JS) and /api/*.
Day/month bucketing uses Europe/Kyiv = fixed UTC+3 (no DST since 2022).
"""
import json
import os
import time
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Configuration via environment variables (see README / deploy/flowtrack.env.example).
DB_PATH = os.environ.get('FLOWTRACK_DB', '/opt/flowtrack/data.db')
HOST = os.environ.get('FLOWTRACK_BIND', '0.0.0.0')   # LAN-only by design; bind to a specific IP if you must
PORT = int(os.environ.get('FLOWTRACK_WEB_PORT', '3020'))
TZ_OFF = 3 * 3600          # Europe/Kyiv fixed UTC+3 (no DST since 2022)
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))

HTML = r"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlowTrack — WAN Traffic</title>
<script src="/chart.umd.min.js"></script>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;
--down:#58a6ff;--up:#3fb950;--accent:#bc8cff;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;padding:20px 24px;max-width:1280px;margin:auto}
h1{font-size:20px;font-weight:600;display:flex;align-items:center;gap:10px}
h1 .dot{width:9px;height:9px;border-radius:50%;background:var(--up);box-shadow:0 0 8px var(--up)}
.sub{color:var(--dim);font-size:12.5px;margin-top:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.card .k{color:var(--dim);font-size:12.5px;text-transform:uppercase;letter-spacing:.4px}
.card .v{font-size:26px;font-weight:700;margin-top:6px;font-variant-numeric:tabular-nums}
.card .s{color:var(--dim);font-size:12px;margin-top:3px}
.row{display:grid;grid-template-columns:3fr 2fr;gap:14px;margin-bottom:14px}
@media(max-width:900px){.row{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.panel h2{font-size:14px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.4px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
select{background:#21262d;color:var(--text);border:1px solid var(--border);border-radius:6px;padding:5px 10px;font-size:13px}
canvas{width:100%!important;height:280px!important}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);font-size:13.5px;white-space:nowrap}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td.num,th.num{text-align:right}
.bar{height:6px;border-radius:3px;background:#21262d;overflow:hidden;margin-top:4px;width:100%}
.bar i{display:block;height:100%;background:var(--down);border-radius:3px}
.hname{font-weight:600;color:var(--accent)}
.pct{color:var(--dim)}
footer{margin-top:24px;color:#484f58;font-size:11.5px;text-align:center}
</style></head><body>
<h1><span class="dot"></span>FlowTrack <span style="font-weight:400;color:var(--dim);font-size:13px">— FortiGate WAN traffic (NetFlow v9)</span></h1>
<div class="sub" id="updated"></div>

<div class="cards">
  <div class="card"><div class="k" id="mlabel">Місяць</div><div class="v" id="c_total">—</div><div class="s">всього WAN (down + up)</div></div>
  <div class="card"><div class="k" id="dlabel">Сьогодні</div><div class="v" id="c_today">—</div><div class="s">з 00:00</div></div>
  <div class="card"><div class="k">Топ хост</div><div class="v" id="c_tophost" style="font-size:20px">—</div><div class="s" id="c_topsz"></div></div>
  <div class="card"><div class="k">Сесій у БД</div><div class="v" id="c_ses">—</div><div class="s">зафіксовано (finalized)</div></div>
</div>

<div class="row">
  <div class="panel"><h2>По днях — вибраний місяць <select id="monthsel"></select></h2><canvas id="chartDays"></canvas></div>
  <div class="panel"><h2>Останні 48 годин (по годинах)</h2><canvas id="chartHours"></canvas></div>
</div>

<div class="panel" style="margin-bottom:14px">
<h2>За хостами — вибраний місяць <span class="pct" id="mhostsum"></span></h2>
<table><thead><tr><th>Хост</th><th class="num">↓ Down</th><th class="num">↑ Up</th><th class="num">Разом</th><th class="num">% від WAN</th><th style="width:30%"></th></tr></thead>
<tbody id="hostrows"></tbody></table>
</div>

<footer>flowtrack v1 · колектор: NetFlow v9 (FortiGate, full rate) → SQLite · агрегація 1 хв · TZ Europe/Kyiv</footer>

<script>
const fmt = b => { if(b==null) return '—';
  const u=['B','KB','MB','GB','TB']; let i=0;
  while(b>=1024 && i<u.length-1){b/=1024;i++}
  return (i<2? b.toFixed(1): b.toFixed(i===2?1:0))+' '+u[i]; };

let chartD, chartH;
async function jget(u){ const r=await fetch(u); if(!r.ok) throw new Error(u+': '+r.status); return r.json(); }

function kdate(tsSec){ return new Date(tsSec*1000 + 10800*1000); }   // Kyiv wall-clock via UTC trick (ts in unix SECONDS)
function monthLabel(ts0){ const d=kdate(ts0);
  return d.toLocaleDateString('uk-UA',{month:'long',year:'numeric'}); }

async function loadDays(monthTs){
  const d = await jget('/api/days?ts='+monthTs);
  document.getElementById('mlabel').textContent = monthLabel(monthTs)+' — WAN';
  const tot = d.days.reduce((s,x)=>s+x.down+x.up,0);
  document.getElementById('c_total').textContent = fmt(tot);
  if(chartD) chartD.destroy();
  chartD = new Chart(document.getElementById('chartDays'), {type:'bar',
    data:{labels:d.days.map(x=>kdate(x.ts).getUTCDate()),
      datasets:[
        {label:'↓ Down',data:d.days.map(x=>x.down),backgroundColor:'#58a6ff'},
        {label:'↑ Up',data:d.days.map(x=>x.up),backgroundColor:'#3fb950'}]},
    options:{maintainAspectRatio:false,plugins:{legend:{labels:{color:'#e6edf3'}}},
      scales:{x:{stacked:true,ticks:{color:'#8b949e'},grid:{display:false}},
              y:{stacked:true,ticks:{color:'#8b949e',callback:v=>fmt(v)},grid:{color:'#21262d'}}}}});
  return d;
}

async function loadHours(){
  const h = await jget('/api/hours?h=48');
  if(chartH) chartH.destroy();
  chartH = new Chart(document.getElementById('chartHours'), {type:'line',
    data:{labels:h.hours.map(x=>{const d=kdate(x.ts);return (d.getUTCHours()+'').padStart(2,'0')+':'+(d.getUTCMinutes()?'30':'00');}),
      datasets:[
        {label:'↓ Down',data:h.hours.map(x=>x.down),borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.15)',fill:true,tension:.3,pointRadius:0,borderWidth:2},
        {label:'↑ Up',data:h.hours.map(x=>x.up),borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.12)',fill:true,tension:.3,pointRadius:0,borderWidth:2}]},
    options:{maintainAspectRatio:false,plugins:{legend:{labels:{color:'#e6edf3'}}},
      scales:{x:{ticks:{color:'#8b949e',maxTicksLimit:12},grid:{display:false}},
              y:{ticks:{color:'#8b949e',callback:v=>fmt(v)},grid:{color:'#21262d'}}}}});
}

async function loadHosts(monthTs){
  const h = await jget('/api/hosts?ts='+monthTs);
  const wan = h.wan_total;
  document.getElementById('mhostsum').textContent = 'WAN: '+fmt(wan);
  const tb = document.getElementById('hostrows'); tb.innerHTML='';
  let top=null;
  for(const row of h.hosts){
    if(row.host==='__WAN__') continue;
    const sum=row.down+row.up;
    if(!top||sum>top.sum) top={h:row.host,sum};
    const pct = wan? (100*sum/wan):0;
    const tr=document.createElement('tr');
    tr.innerHTML=`<td class="hname">${row.host}</td>
      <td class="num">${fmt(row.down)}</td><td class="num">${fmt(row.up)}</td>
      <td class="num"><b>${fmt(sum)}</b></td><td class="num pct">${pct.toFixed(1)}%</td>
      <td><div class="bar"><i style="width:${Math.min(100,pct).toFixed(1)}%"></i></div></td>`;
    tb.appendChild(tr);
  }
  if(top){ document.getElementById('c_tophost').textContent=top.h;
           document.getElementById('c_topsz').textContent=fmt(top.sum)+' за місяць'; }
  document.getElementById('c_ses').textContent=(h.sessions!=null)? h.sessions.toLocaleString('uk-UA') : '—';
}

async function refresh(){
  const now = Math.floor(Date.now()/1000)+10800;          // shift to Kyiv epoch
  const kyiv = new Date(now*1000);                        // UTC clock reading "kyiv time"
  const d0 = Date.UTC(kyiv.getUTCFullYear(), kyiv.getUTCMonth(), 1)/1000 - 10800;
  await Promise.all([loadDays(d0), loadHours(), loadHosts(d0)]);

  // today card (independent of selected month)
  try {
    const s = await jget('/api/summary');
    document.getElementById('c_today').textContent = fmt(s.today||0);
  } catch(e){}

  // month selector: current + up to 6 previous months
  const sel=document.getElementById('monthsel');
  if(sel.options.length===0){
    for(let i=0;i<7;i++){
      const dt=new Date(Date.UTC(kyiv.getUTCFullYear(),kyiv.getUTCMonth()-i,1));
      const ts=dt.getTime()/1000-10800;
      const o=document.createElement('option'); o.value=Math.floor(ts);
      o.textContent=(dt.getUTCMonth()+1)+'.'+dt.getUTCFullYear(); sel.appendChild(o);
    }
  }
  document.getElementById('updated').textContent='оновлено '+new Date().toLocaleTimeString('uk-UA');
}

document.addEventListener('DOMContentLoaded', async ()=>{
  await refresh();
  const sel=document.getElementById('monthsel');
  sel.onchange=async()=>{ const ts=+sel.value; await Promise.all([loadDays(ts), loadHosts(ts)]); };
  setInterval(refresh, 60000);
});
</script></body></html>"""


def month_bounds(ts_unix):
    """Return (first, end) unix seconds of the Kyiv-month containing ts."""
    import calendar
    d = time.gmtime(ts_unix + TZ_OFF)
    first = int(calendar.timegm((d.tm_year, d.tm_mon, 1, 0, 0, 0))) - TZ_OFF
    nxt = (d.tm_year + 1, 1, 1, 0, 0, 0) if d.tm_mon == 12 else (d.tm_year, d.tm_mon + 1, 1, 0, 0, 0)
    end = int(calendar.timegm(nxt)) - TZ_OFF
    return first, end


def query_db():
    if not os.path.exists(DB_PATH):
        return None
    db = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    return db


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            self._route()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._json({'error': str(e)}, 500)
            except Exception:
                pass

    def _route(self):
        u = urlparse(self.path)
        if u.path in ('/', '/index.html'):
            body = HTML.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(body)
        elif u.path == '/chart.umd.min.js':
            p = os.path.join(STATIC_DIR, 'chart.umd.min.js')
            if not os.path.exists(p):
                return self._json({'error': 'chart.js missing'}, 500)
            with open(p, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.end_headers()
            self.wfile.write(body)
        elif u.path == '/api/days':
            ts = int(parse_qs(u.query).get('ts', ['0'])[0])
            db = query_db()
            if db is None:
                return self._json({'days': []})
            first, end = month_bounds(ts)
            rows = db.execute(
                "SELECT ts, SUM(down_bytes) dn, SUM(up_bytes) up FROM usage_min"
                " WHERE host='__WAN__' AND ts>=? AND ts<? GROUP BY ts ORDER BY ts",
                (first, end)).fetchall()
            # bucket to days (Kyiv midnight = unix where (t+TZ_OFF)%86400==0)
            days = {}
            for r in rows:
                day_start = ((r['ts'] + TZ_OFF) // 86400) * 86400 - TZ_OFF
                cur = days.setdefault(day_start, {'down': 0, 'up': 0})
                cur['down'] += r['dn'] or 0
                cur['up'] += r['up'] or 0
            n_days = (end - first) // 86400
            out = []
            for i in range(n_days):
                t0 = first + i * 86400
                v = days.get(t0, {'down': 0, 'up': 0})
                out.append({'ts': int(t0), 'down': v['down'], 'up': v['up']})
            self._json({'days': out})
        elif u.path == '/api/hours':
            hh = min(int(parse_qs(u.query).get('h', ['48'])[0]), 24 * 14)
            db = query_db()
            if db is None:
                return self._json({'hours': []})
            now = int(time.time())
            t0 = ((now + TZ_OFF) // 3600) * 3600 - TZ_OFF - hh * 3600  # Kyiv hour grid
            rows = db.execute(
                "SELECT ts, SUM(down_bytes) dn, SUM(up_bytes) up FROM usage_min"
                " WHERE host='__WAN__' AND ts>=? GROUP BY ts", (t0,)).fetchall()
            m = {}
            for r in rows:
                hstart = ((r['ts'] + TZ_OFF) // 3600) * 3600 - TZ_OFF
                cur = m.setdefault(hstart, [0, 0])
                cur[0] += r['dn'] or 0
                cur[1] += r['up'] or 0
            out = []
            for i in range(hh + 1):
                t = t0 + i * 3600
                dn, up = m.get(t, (0, 0))
                out.append({'ts': int(t), 'down': dn, 'up': up})
            self._json({'hours': out})
        elif u.path == '/api/hosts':
            ts = int(parse_qs(u.query).get('ts', ['0'])[0])
            db = query_db()
            if db is None:
                return self._json({'hosts': [], 'wan_total': 0})
            first, end = month_bounds(ts)
            rows = db.execute(
                "SELECT host, SUM(down_bytes) dn, SUM(up_bytes) up FROM usage_min"
                " WHERE ts>=? AND ts<? GROUP BY host ORDER BY (dn+up) DESC",
                (first, end)).fetchall()
            wan = 0
            hosts = []
            for r in rows:
                if r['host'] == '__WAN__':
                    wan = (r['dn'] or 0) + (r['up'] or 0)
                    continue
                hosts.append({'host': r['host'], 'down': r['dn'] or 0, 'up': r['up'] or 0})
            ses = db.execute("SELECT COUNT(*) c FROM sessions").fetchone()['c']
            self._json({'hosts': hosts, 'wan_total': wan, 'sessions': ses})
        elif u.path == '/api/summary':
            db = query_db()
            if db is None:
                return self._json({'ok': False})
            now = int(time.time())
            today0 = ((now + TZ_OFF) // 86400) * 86400 - TZ_OFF
            t = db.execute("SELECT SUM(down_bytes)+SUM(up_bytes) s FROM usage_min WHERE host='__WAN__' AND ts>=?", (today0,)).fetchone()['s'] or 0
            month_start, _ = month_bounds(now)
            mm = db.execute("SELECT SUM(down_bytes)+SUM(up_bytes) s FROM usage_min WHERE host='__WAN__' AND ts>=?", (month_start,)).fetchone()['s'] or 0
            self._json({'ok': True, 'today': t, 'month': mm})
        else:
            self._json({'error': 'not found'}, 404)


if __name__ == '__main__':
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f'[flowtrack-web] serving on http://{HOST}:{PORT}', flush=True)
    srv.serve_forever()
