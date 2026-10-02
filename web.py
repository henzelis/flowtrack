#!/usr/bin/env python3
"""flowtrack-web: minimal dashboard for flowtrack SQLite data.
Stdlib only (http.server). Serves / (HTML+JS) and /api/*.
Day/month/hour bucketing uses a real IANA time zone (FLOWTRACK_TZ, default
Europe/Kyiv — which DOES switch between EET/EEST), via zoneinfo.
All labels are produced server-side, so the browser's own TZ never matters.
"""
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from zoneinfo import ZoneInfo

# Configuration via environment variables (see README / deploy/flowtrack.env.example).
DB_PATH = os.environ.get('FLOWTRACK_DB', '/opt/flowtrack/data.db')
HOST = os.environ.get('FLOWTRACK_BIND', '0.0.0.0')   # LAN-only by design; bind to a specific IP if you must
PORT = int(os.environ.get('FLOWTRACK_WEB_PORT', '3020'))
TZ = ZoneInfo(os.environ.get('FLOWTRACK_TZ', 'Europe/Kyiv'))
STATIC_DIR = os.path.dirname(os.path.abspath(__file__))
MONTHS_UK = ['січень', 'лютий', 'березень', 'квітень', 'травень', 'червень',
             'липень', 'серпень', 'вересень', 'жовтень', 'листопад', 'грудень']

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
  <div class="card"><div class="k" id="mlabel">Місяць</div><div class="v" id="c_total">—</div><div class="s" id="c_total_s">всього WAN (down + up)</div></div>
  <div class="card"><div class="k">Сьогодні</div><div class="v" id="c_today">—</div><div class="s" id="c_today_s">з 00:00</div></div>
  <div class="card"><div class="k">Топ хост</div><div class="v" id="c_tophost" style="font-size:20px">—</div><div class="s" id="c_topsz"></div></div>
  <div class="card"><div class="k">Flow-записів</div><div class="v" id="c_flows">—</div><div class="s">за вибраний місяць</div></div>
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

<footer id="foot">flowtrack v1.1 · колектор: NetFlow v9 (FortiGate, full rate) → SQLite · агрегація 1 хв</footer>

<script>
const fmt = b => { if(b==null) return '—';
  const u=['B','KB','MB','GB','TB']; let i=0;
  while(b>=1024 && i<u.length-1){b/=1024;i++}
  return (i<2? b.toFixed(1): b.toFixed(i===2?1:0))+' '+u[i]; };
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

let chartD, chartH, selMonth = null;   // selMonth: 'YYYY-MM' chosen by the user, null = current
async function jget(u){ const r=await fetch(u); if(!r.ok) throw new Error(u+': '+r.status); return r.json(); }

const axis = {ticks:{color:'#8b949e'},grid:{display:false}};
const yaxis = {ticks:{color:'#8b949e',callback:v=>fmt(v)},grid:{color:'#21262d'}};
const tip = {callbacks:{label:c=>c.dataset.label+': '+fmt(c.parsed.y)}};

async function loadMonths(){
  const m = await jget('/api/months');
  const sel = document.getElementById('monthsel');
  const keep = sel.value;
  sel.innerHTML = '';
  for(const x of m.months){
    const o=document.createElement('option'); o.value=x.key; o.textContent=x.label; sel.appendChild(o);
  }
  sel.value = selMonth || keep || m.current;
  if(!sel.value) sel.value = m.current;
  document.getElementById('foot').textContent += ' · TZ ' + m.tz;
  return sel.value;
}

async function loadDays(month){
  const d = await jget('/api/days?month='+month);
  document.getElementById('mlabel').textContent = d.label+' — WAN';
  document.getElementById('c_total').textContent = fmt(d.down+d.up);
  document.getElementById('c_total_s').textContent = '↓ '+fmt(d.down)+' · ↑ '+fmt(d.up);
  document.getElementById('c_flows').textContent = d.flows.toLocaleString('uk-UA');
  if(chartD) chartD.destroy();
  chartD = new Chart(document.getElementById('chartDays'), {type:'bar',
    data:{labels:d.days.map(x=>x.label),
      datasets:[
        {label:'↓ Down',data:d.days.map(x=>x.down),backgroundColor:'#58a6ff'},
        {label:'↑ Up',data:d.days.map(x=>x.up),backgroundColor:'#3fb950'}]},
    options:{maintainAspectRatio:false,animation:false,plugins:{legend:{labels:{color:'#e6edf3'}},tooltip:tip},
      scales:{x:{...axis,stacked:true},y:{...yaxis,stacked:true}}}});
}

async function loadHours(){
  const h = await jget('/api/hours?h=48');
  if(chartH) chartH.destroy();
  chartH = new Chart(document.getElementById('chartHours'), {type:'line',
    data:{labels:h.hours.map(x=>x.label),
      datasets:[
        {label:'↓ Down',data:h.hours.map(x=>x.down),borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.15)',fill:true,tension:.3,pointRadius:0,borderWidth:2},
        {label:'↑ Up',data:h.hours.map(x=>x.up),borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.12)',fill:true,tension:.3,pointRadius:0,borderWidth:2}]},
    options:{maintainAspectRatio:false,animation:false,interaction:{mode:'index',intersect:false},plugins:{legend:{labels:{color:'#e6edf3'}},tooltip:tip},
      scales:{x:{...axis,ticks:{color:'#8b949e',maxTicksLimit:12}},y:yaxis}}});
}

async function loadHosts(month){
  const h = await jget('/api/hosts?month='+month);
  const wan = h.wan_total;
  document.getElementById('mhostsum').textContent = 'WAN: '+fmt(wan);
  const tb = document.getElementById('hostrows'); tb.innerHTML='';
  const top = h.hosts[0];
  for(const row of h.hosts){
    const sum=row.down+row.up;
    const pct = wan? (100*sum/wan):0;
    const tr=document.createElement('tr');
    tr.innerHTML=`<td class="hname">${esc(row.host)}</td>
      <td class="num">${fmt(row.down)}</td><td class="num">${fmt(row.up)}</td>
      <td class="num"><b>${fmt(sum)}</b></td><td class="num pct">${pct.toFixed(1)}%</td>
      <td><div class="bar"><i style="width:${Math.min(100,pct).toFixed(1)}%"></i></div></td>`;
    tb.appendChild(tr);
  }
  document.getElementById('c_tophost').textContent = top? top.host : '—';
  document.getElementById('c_topsz').textContent = top? fmt(top.down+top.up)+' за місяць' : '';
}

async function loadToday(){
  const s = await jget('/api/summary');
  document.getElementById('c_today').textContent = fmt(s.today_down+s.today_up);
  document.getElementById('c_today_s').textContent = 'з 00:00 · ↓ '+fmt(s.today_down)+' · ↑ '+fmt(s.today_up);
}

async function refresh(){
  const month = document.getElementById('monthsel').value;
  try {
    await Promise.all([loadDays(month), loadHours(), loadHosts(month), loadToday()]);
    document.getElementById('updated').textContent='оновлено '+new Date().toLocaleTimeString('uk-UA');
  } catch(e){
    document.getElementById('updated').textContent='помилка оновлення: '+e.message;
  }
}

document.addEventListener('DOMContentLoaded', async ()=>{
  await loadMonths();
  await refresh();
  const sel=document.getElementById('monthsel');
  sel.onchange=async()=>{ selMonth=sel.value; await Promise.all([loadDays(sel.value), loadHosts(sel.value)]); };
  setInterval(refresh, 60000);
});
</script></body></html>"""


def local(ts):
    return datetime.fromtimestamp(ts, TZ)


def month_bounds(key):
    """'YYYY-MM' -> (first_unix, end_unix, datetime_first) in the configured TZ."""
    y, m = (int(x) for x in key.split('-'))
    first = datetime(y, m, 1, tzinfo=TZ)
    nxt = datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=TZ)
    return int(first.timestamp()), int(nxt.timestamp()), first


def month_key(dt):
    return f'{dt.year:04d}-{dt.month:02d}'


def month_label(dt):
    return f'{MONTHS_UK[dt.month - 1]} {dt.year}'


def query_db():
    if not os.path.exists(DB_PATH):
        return None
    db = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    return db


def wan_rows(db, t0, t1):
    return db.execute(
        "SELECT ts, down_bytes dn, up_bytes up, flows FROM usage_min"
        " WHERE host='__WAN__' AND ts>=? AND ts<?", (t0, t1)).fetchall()


def api_months(db):
    now = local(time.time())
    cur = datetime(now.year, now.month, 1, tzinfo=TZ)
    oldest = cur
    if db is not None:
        r = db.execute("SELECT MIN(ts) t FROM usage_min").fetchone()
        if r['t']:
            o = local(r['t'])
            oldest = datetime(o.year, o.month, 1, tzinfo=TZ)
    months, d = [], cur
    while d >= oldest and len(months) < 36:
        months.append({'key': month_key(d), 'label': month_label(d)})
        d = (d - timedelta(days=1)).replace(day=1)
    return {'months': months, 'current': month_key(cur), 'tz': str(TZ)}


def api_days(db, key):
    first, end, dt_first = month_bounds(key)
    days = {}
    tot = {'down': 0, 'up': 0, 'flows': 0}
    for r in (wan_rows(db, first, end) if db else []):
        cur = days.setdefault(local(r['ts']).day, [0, 0])
        cur[0] += r['dn']
        cur[1] += r['up']
        tot['down'] += r['dn']
        tot['up'] += r['up']
        tot['flows'] += r['flows'] or 0
    n_days = (datetime.fromtimestamp(end, TZ) - timedelta(days=1)).day
    out = [{'label': str(i), 'down': days.get(i, [0, 0])[0], 'up': days.get(i, [0, 0])[1]}
           for i in range(1, n_days + 1)]
    return {'days': out, 'label': month_label(dt_first), **tot}


def api_hours(db, hh):
    now = local(time.time())
    cur_hour = now.replace(minute=0, second=0, microsecond=0)
    # step in absolute time so DST transitions give 23/25-hour days correctly
    starts = [int(cur_hour.timestamp()) - i * 3600 for i in range(hh, -1, -1)]
    m = {}
    for r in (wan_rows(db, starts[0], starts[-1] + 3600) if db else []):
        h0 = starts[0] + (r['ts'] - starts[0]) // 3600 * 3600
        cur = m.setdefault(h0, [0, 0])
        cur[0] += r['dn']
        cur[1] += r['up']
    return {'hours': [{'ts': t, 'label': local(t).strftime('%H:%M'),
                       'down': m.get(t, [0, 0])[0], 'up': m.get(t, [0, 0])[1]} for t in starts]}


def api_hosts(db, key):
    if db is None:
        return {'hosts': [], 'wan_total': 0}
    first, end, _ = month_bounds(key)
    rows = db.execute(
        "SELECT host, SUM(down_bytes) dn, SUM(up_bytes) up FROM usage_min"
        " WHERE ts>=? AND ts<? GROUP BY host ORDER BY (dn+up) DESC",
        (first, end)).fetchall()
    wan, hosts = 0, []
    for r in rows:
        if r['host'] == '__WAN__':
            wan = (r['dn'] or 0) + (r['up'] or 0)
        else:
            hosts.append({'host': r['host'], 'down': r['dn'] or 0, 'up': r['up'] or 0})
    return {'hosts': hosts, 'wan_total': wan}


def api_summary(db):
    if db is None:
        return {'ok': False, 'today_down': 0, 'today_up': 0}
    now = local(time.time())
    today0 = int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    r = db.execute("SELECT SUM(down_bytes) dn, SUM(up_bytes) up FROM usage_min"
                   " WHERE host='__WAN__' AND ts>=?", (today0,)).fetchone()
    last = db.execute("SELECT MAX(ts) t FROM usage_min").fetchone()['t']
    return {'ok': True, 'today_down': r['dn'] or 0, 'today_up': r['up'] or 0, 'last_ts': last}


def valid_month(q):
    key = q.get('month', [''])[0]
    try:
        month_bounds(key)
        return key
    except (ValueError, TypeError):
        return month_key(local(time.time()))


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype, code=200, cache='no-store'):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj).encode(), 'application/json', code)

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
        q = parse_qs(u.query)
        if u.path in ('/', '/index.html'):
            return self._send(HTML.encode(), 'text/html; charset=utf-8')
        if u.path == '/chart.umd.min.js':
            p = os.path.join(STATIC_DIR, 'chart.umd.min.js')
            if not os.path.exists(p):
                return self._json({'error': 'chart.js missing'}, 500)
            with open(p, 'rb') as f:
                return self._send(f.read(), 'application/javascript', cache='max-age=86400')
        handlers = {
            '/api/months': lambda db: api_months(db),
            '/api/days': lambda db: api_days(db, valid_month(q)),
            '/api/hours': lambda db: api_hours(db, max(1, min(int(q.get('h', ['48'])[0]), 24 * 14))),
            '/api/hosts': lambda db: api_hosts(db, valid_month(q)),
            '/api/summary': lambda db: api_summary(db),
        }
        fn = handlers.get(u.path)
        if fn is None:
            return self._json({'error': 'not found'}, 404)
        db = query_db()
        try:
            self._json(fn(db))
        finally:
            if db is not None:
                db.close()


if __name__ == '__main__':
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f'[flowtrack-web] serving on http://{HOST}:{PORT} (TZ {TZ})', flush=True)
    srv.serve_forever()
