'use strict';
// FlowTrack web UI — talks to /api/* (see api.py). No build step.

// ===================== language =====================
// English or Ukrainian. Every text is written in both languages side by side: T('English', 'Українська').
// The choice is kept in localStorage and in the ft_lang cookie (the API answers errors and events in it).
const LANG = (() => { try { const s = localStorage.getItem('ft-lang'); if (s === 'en' || s === 'uk') return s; } catch (e) {}
  return /^uk/i.test(navigator.language || '') ? 'uk' : 'en'; })();
const T = (en, uk) => LANG === 'uk' ? uk : en;
const LOC = T('en-GB', 'uk-UA');
document.documentElement.lang = LANG;
document.cookie = `ft_lang=${LANG}; path=/; max-age=31536000; SameSite=Lax`;
function setLang(l){ try { localStorage.setItem('ft-lang', l); } catch (e) {} document.cookie = `ft_lang=${l}; path=/; max-age=31536000; SameSite=Lax`; location.reload(); }
// texts of index.html in the chosen language (the HTML itself is English)
(function i18nStatic(){
  if (LANG === 'en') return;
  const set = (id, prop, v) => { const el = document.getElementById(id); if (!el) return; if (prop === 'textContent') el.textContent = v; else el.setAttribute(prop, v); };
  set('nav', 'aria-label', 'Розділи'); set('collState', 'textContent', 'Колектор'); set('ingK', 'textContent', 'Прийом записів');
  set('q', 'placeholder', 'Пошук: IP, сервіс, країна, порт…  (ip:10.0.0.5  service:Telegram  -country:US  port:443)'); set('q', 'aria-label', 'Пошук і фільтр');
  set('devLbl', 'title', 'Пристрій-експортер'); set('devSel', 'aria-label', 'Пристрій'); set('rangeLbl', 'title', 'Період'); set('rangeSel', 'aria-label', 'Період');
  set('bell', 'aria-label', 'Події'); set('trafLbl', 'title', 'Трафік'); set('trafSel', 'aria-label', 'Трафік');
  const tnames = {internet:'Інтернет', internal:'Внутрішній', all:'Увесь трафік'};
  document.querySelectorAll('#trafSel option').forEach(o => { if (tnames[o.value]) o.textContent = tnames[o.value]; });
  const names = {'1h':'Остання година', '6h':'Останні 6 годин', '24h':'Останні 24 години', '7d':'Останні 7 днів', '30d':'Останні 30 днів'};
  document.querySelectorAll('#rangeSel option').forEach(o => { if (names[o.value]) o.textContent = names[o.value]; });
})();

// ===================== state, api =====================
const state = {view:'overview', range:'24h', filters:[], heroMode:'map', heroLive:true, metric:'flows', scale:'sqrt', flowLive:true, sel:null, sort:{col:'tot', dir:-1}, openFlow:null, ifDev:null, ifEdit:null, traffic:'internet'};
let META = {devices:[]}, ME = null;
const isAdmin = () => ME && ME.role === 'admin';
const isInternal = () => state.traffic === 'internal';
const FILTER_KEYS = ['ip', 'dst', 'service', 'l7', 'country', 'city', 'port', 'device', 'asn', 'dir', 'proto', 'in_if', 'out_if', 'iface'];
const FILTER_LABEL = {iface:T('interface','інтерфейс'), in_if:T('in via','вхід через'), out_if:T('out via','вихід через'), ip:T('host','хост'), dst:T('ext. IP','зовн. IP'), service:T('service','сервіс'), l7:T('protocol','протокол'), country:T('country','країна'), city:T('city','місто'), port:T('port','порт'), device:T('device','пристрій'), asn:'ASN', dir:T('direction','напрямок'), proto:'L4'};
let renderSeq = 0;

// widgets of one page often ask the same thing (Overview: the trend and the KPI sparklines, the map overlay and the
// top lists): an identical request still running or answered in the last 3 s is shared, not sent again
const API_SHARED = new Map();
// an interface's addresses: entered by hand, else read over SNMP, else what the records show (networks, NAT address)
const ifAddrs = i => (i.addrs || []).length ? i.addrs : (i.snmp_addrs || []).length ? i.snmp_addrs : (i.seen_addrs || []);
function api(path, params = {}, extraFilters = []){
  const qs = new URLSearchParams({...periodParams(), t:state.traffic, f:JSON.stringify([...state.filters, ...extraFilters]), ...params});
  const url = `api/${path}?${qs}`, now = Date.now();
  for (const [k, v] of API_SHARED) if (v.done && now - v.done > 3000) API_SHARED.delete(k);
  const hit = API_SHARED.get(url);
  if (hit) return hit.p;
  const e = {done:0}; e.p = apiFetch(url).then(b => { e.done = Date.now(); return b; }, err => { API_SHARED.delete(url); throw err; });
  API_SHARED.set(url, e);
  return e.p;
}
async function apiFetch(url){
  const r = await fetch(url);
  if (r.status === 401) { showLogin(T('Session ended — sign in again', 'Сесія завершилась — увійдіть знову')); throw new Error(T('login required', 'потрібен вхід')); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
async function apiPost(path, body){
  API_SHARED.clear();                    // a change: answers shared before it are stale (the server clears its cache too)
  const r = await fetch(`api/${path}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body || {})});
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== 'login') { showLogin(T('Session ended — sign in again', 'Сесія завершилась — увійдіть знову')); throw new Error(T('login required', 'потрібен вхід')); }
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}
// single entry point for new filters: no duplicates; a positive filter replaces the previous positive
// filter of the same key (two would AND to nothing); exclusions stack; the opposite of a filter replaces it
function putFilter(f){
  const k = f.k, v = String(f.v), neg = !!f.neg;
  if (!FILTER_KEYS.includes(k) || !v) return;
  state.filters = state.filters.filter(x => !(x.k === k && (x.v === v || (!neg && !x.neg))));
  state.filters.push({k, v, neg});
}
function addFilter(k, v, neg){ putFilter({k, v, neg}); state.sel = null; render(); }

// ===================== formatting =====================
const fmtB = b => { b = +b || 0; const u = ['B','KB','MB','GB','TB']; let i = 0; while (b >= 1000 && i < 4) { b /= 1000; i++; } return (i >= 2 ? b.toFixed(b < 10 ? 2 : 1) : Math.round(b)) + ' ' + u[i]; };
const fmtR = bps => { bps = +bps || 0; const u = [T('bit/s','біт/с'), T('kbit/s','Кбіт/с'), T('Mbit/s','Мбіт/с'), T('Gbit/s','Гбіт/с')]; let i = 0; while (bps >= 1000 && i < 3) { bps /= 1000; i++; } return bps.toFixed(bps < 10 && i > 0 ? 1 : 0) + ' ' + u[i]; };
const fmtN = n => { n = +n || 0; return n >= 1e6 ? (n / 1e6).toFixed(2) + ' M' : n >= 1e4 ? (n / 1e3).toFixed(1) + ' K' : Math.round(n).toLocaleString(LOC); };
const hhmm = t => new Date(t * 1000).toLocaleTimeString(LOC, {hour:'2-digit', minute:'2-digit'});
const hms = t => new Date(t * 1000).toLocaleTimeString(LOC, {hour:'2-digit', minute:'2-digit', second:'2-digit'});
const dmy = t => new Date(t * 1000).toLocaleDateString(LOC, {day:'numeric', month:'2-digit'});
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let regionNames; try { regionNames = new Intl.DisplayNames([LANG], {type:'region'}); } catch (e) { regionNames = null; }
const ccName = cc => { if (!cc) return '—'; try { return regionNames ? regionNames.of(cc) : cc; } catch (e) { return cc; } };
const PAL = ['#2F7BFF','#FF4FA0','#FF9F43','#27D3F5','#8B5CFF','#2EE59D','#FFD166','#6E7FA6'];
const C = {down:'#27D3F5', up:'#FF9F43', int:'#8B5CFF', ext:'#2EE59D', other:'#6E7FA6', ink:'#EAF0FF', ink2:'#A9B7D9', ink3:'#6E7FA6', hair:'rgba(120,160,255,.12)'};
const hexA = (hex, a) => { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`; };
const pct = (v, all) => all ? (100 * v / all).toFixed(1) + '%' : '—';
const tot = r => (+r.up || 0) + (+r.dn || 0);
const colorCache = new Map();
const keyColor = k => { if (!colorCache.has(k)) colorCache.set(k, PAL[colorCache.size % (PAL.length - 1)]); return colorCache.get(k); };
const isCustom = () => state.range === 'custom';
const periodParams = () => isCustom() ? {from:state.from, to:state.to} : {range:state.range};
const rangeSecs = () => isCustom() ? state.to - state.from : ({'1h':3600, '6h':21600, '24h':86400, '7d':604800, '30d':2592000})[state.range];
// '5 Oct, 14:05 – 14:20' or '4 Oct, 22:00 – 5 Oct, 01:00'
function periodText(t0, t1){
  const d = t => new Date(t * 1000).toLocaleDateString(LOC, {day:'numeric', month:'short'}), sameDay = d(t0) === d(t1 - 1);
  return `${d(t0)}, ${hhmm(t0)} – ${sameDay ? '' : d(t1) + ', '}${hhmm(t1)}`;
}
// a custom period (unix s); the preset it replaced comes back with the period chip's ×
function setPeriod(t0, t1){
  if (!isCustom()) state.prevRange = state.range;
  state.range = 'custom'; state.from = Math.floor(t0 / 60) * 60; state.to = Math.ceil(t1 / 60) * 60; state.sel = null; render();
}
const rangeLabel = () => isCustom() ? periodText(state.from, state.to) : ({'1h':T('Last hour','остання година'), '6h':T('Last 6 hours','останні 6 годин'), '24h':T('Last 24 hours','останні 24 години'), '7d':T('Last 7 days','останні 7 днів'), '30d':T('Last 30 days','останні 30 днів')})[state.range];
const devName = ip => (META.devices.find(d => d.ip === ip) || {}).name || ip;
const ifLabel = (ip, idx) => { const d = META.devices.find(x => x.ip === ip) || {}, n = (d.if_names || {})[String(idx)] || (d.local_if === idx ? 'local' : ''); return n ? `${n} (${idx})` : String(idx); };
const hostLabel = h => h.name ? `${esc(h.name)}` : esc(h.ip);

// ===================== lifecycle =====================
// cleanup scopes: the page has a root scope; widgets that re-mount on their own (hero, river) get a child scope
const rootScope = [];
let curScope = rootScope;
const onCleanup = fn => curScope.push(fn);
function runScope(list){ while (list.length) { try { list.pop()(); } catch (e) {} } }
function cleanup(){ runScope(rootScope); }
function childScope(){ const list = []; rootScope.push(() => runScope(list));
  return {run:fn => { const prev = curScope; curScope = list; try { return fn(); } finally { curScope = prev; } }, dispose:() => runScope(list)}; }
const setPressed = (id, val) => document.querySelectorAll(`#${id} button`).forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === val)));
const scaleNote = () => '';   // the pressed toggle shows the scale; labels keep a constant length
const charts = [];
function mkChart(el){ const c = echarts.init(el, null, {renderer:'canvas'}); charts.push(c);
  if (window.ResizeObserver) { const ro = new ResizeObserver(() => { if (!c.isDisposed()) c.resize(); }); ro.observe(el); onCleanup(() => ro.disconnect()); }
  // axis labels are measured with the web font; re-layout once it has loaded so nothing gets clipped
  if (document.fonts && document.fonts.status !== 'loaded') document.fonts.ready.then(() => { if (!c.isDisposed()) c.resize(); }); onCleanup(() => { c.dispose(); const i = charts.indexOf(c); if (i >= 0) charts.splice(i, 1); }); return c; }
window.addEventListener('resize', () => charts.forEach(c => c.resize()));
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
function every(ms, fn){ const t = setInterval(() => { if (!document.hidden) fn(); }, ms); onCleanup(() => clearInterval(t)); }   // paused while the tab is hidden

// ===================== chart helpers =====================
// the axis spans the whole period even without data, so an empty chart still maps a drag to real times
const axisX = ts => ({type:'time', ...(ts && ts.length ? {min:ts[0] * 1000, max:ts[ts.length - 1] * 1000} : {}), axisLine:{lineStyle:{color:C.hair}}, axisTick:{show:false}, splitLine:{show:false},
  axisLabel:{color:C.ink3, fontFamily:'JetBrains Mono', fontSize:11, hideOverlap:true, formatter:v => rangeSecs() > 86400 ? dmy(v / 1000) : hhmm(v / 1000)}});
// drag across a time chart to look at that stretch of time (custom period for every page)
function zoomable(c){
  const zr = c.getZr(), gridRect = () => c.getModel().getComponent('grid').coordinateSystem.getRect();
  let x0 = null, x1 = null, drawn = false;
  // remove the selection only if it was drawn: ECharts throws when asked to remove a graphic it does not have
  const clear = () => { x0 = x1 = null; if (drawn && !c.isDisposed()) c.setOption({graphic:[{id:'zoomSel', type:'rect', $action:'remove'}]}); drawn = false; };
  zr.on('mousedown', e => { if (e.event.button === 0 && c.containPixel('grid', [e.offsetX, e.offsetY])) { x0 = e.offsetX; x1 = null; } });
  zr.on('mousemove', e => {
    if (x0 == null) { zr.setCursorStyle(c.containPixel('grid', [e.offsetX, e.offsetY]) ? 'crosshair' : 'default'); return; }
    const g = gridRect(); x1 = Math.max(g.x, Math.min(g.x + g.width, e.offsetX)); if (Math.abs(x1 - x0) < 4) return;
    drawn = true; c.setOption({graphic:[{id:'zoomSel', type:'rect', silent:true, z:100, shape:{x:Math.min(x0, x1), y:g.y, width:Math.abs(x1 - x0), height:g.height},
      style:{fill:'rgba(47,123,255,.16)', stroke:'rgba(110,160,255,.75)', lineWidth:1}}]});
  });
  zr.on('mouseup', () => { if (x0 == null) return; const a = x0, b = x1; clear(); if (b == null || Math.abs(b - a) < 4) return;
    const t = [a, b].map(x => c.convertFromPixel({xAxisIndex:0}, x) / 1000).sort((u, v) => u - v);
    if (t[1] - t[0] >= 60) setTimeout(() => setPeriod(t[0], t[1])); });   // after ECharts finishes this event: render() disposes the chart
  zr.on('globalout', () => { if (x0 != null) clear(); });
  return c;
}
const axisY = fmt => ({type:'value', splitLine:{lineStyle:{color:C.hair}}, axisLabel:{color:C.ink3, fontFamily:'JetBrains Mono', fontSize:11, formatter:v => String(fmt(v)).replace(/\.0 /, ' ')}});
const tipBase = () => ({backgroundColor:'rgba(10,20,46,.94)', borderColor:'rgba(130,175,255,.45)', textStyle:{color:C.ink, fontFamily:'Manrope', fontSize:12}, extraCssText:'border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.4)'});
// fill missing buckets with zeros so lines drop to 0 instead of interpolating across gaps
function grid(series){
  const step = series.step, to = series.to || Date.now() / 1000, end = Math.floor((series.from ? to - 1 : to) / step) * step, start = series.from || end - series.range;
  const ts = []; for (let t = Math.ceil(start / step) * step; t <= end; t += step) ts.push(t);
  return {ts, step};
}
function trendChart(el, series, compact){
  const {ts, step} = grid(series), m = new Map(series.rows.map(r => [r[0], r]));
  const area = c => ({color:new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset:0, color:hexA(c, .35)}, {offset:1, color:hexA(c, .02)}])});
  const c = mkChart(el);
  c.setOption({animation:false, grid:compact ? {left:12, right:8, top:8, bottom:4, containLabel:true} : {left:14, right:10, top:30, bottom:4, containLabel:true},
    legend:{show:!compact, top:0, right:0, icon:'roundRect', itemWidth:14, itemHeight:6, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
    tooltip:{...tipBase(), trigger:'axis', valueFormatter:v => fmtR(v)}, xAxis:axisX(ts), yAxis:axisY(v => fmtR(v)),
    series:[
      {name:'↓ Download', type:'line', smooth:.35, showSymbol:false, lineStyle:{width:2, color:C.down, shadowBlur:12, shadowColor:C.down}, itemStyle:{color:C.down}, areaStyle:area(C.down), data:ts.map(t => [t * 1000, ((m.get(t) || [])[1] || 0) * 8 / step])},
      {name:'↑ Upload', type:'line', smooth:.35, showSymbol:false, lineStyle:{width:2, color:C.up, shadowBlur:12, shadowColor:C.up}, itemStyle:{color:C.up}, areaStyle:area(C.up), data:ts.map(t => [t * 1000, ((m.get(t) || [])[2] || 0) * 8 / step])}]});
  return compact ? c : zoomable(c);
}
function stackChart(el, series, label, onPick){
  const {ts, step} = grid(series), keys = new Map();
  for (const [t, k, b] of series.rows) { if (!keys.has(k)) keys.set(k, new Map()); keys.get(k).set(t, b); }
  const order = [...keys.keys()].sort((a, b) => (a === '__other') - (b === '__other'));
  const c = mkChart(el);
  c.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true}, legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
    tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(ts), yAxis:axisY(v => fmtR(v)),
    series:order.map(k => { const col = k === '__other' ? C.other : keyColor(k); return {name:k === '__other' ? T('Others', 'інше') : label(k), id:k, type:'line', stack:'a', smooth:.25, showSymbol:false,
      lineStyle:{width:1.4, color:col}, itemStyle:{color:col}, areaStyle:{opacity:k === '__other' ? .2 : .35}, emphasis:{focus:'series'}, data:ts.map(t => [t * 1000, (keys.get(k).get(t) || 0) * 8 / step])}; })});
  // ECharts reports clicks on the line only; find the stacked band under the pointer instead (acted on after the event,
  // because the filter re-renders the page and disposes this chart)
  if (onPick) c.getZr().on('click', e => {
    if (c.isDisposed() || !c.containPixel('grid', [e.offsetX, e.offsetY]) || !ts.length) return;
    const [x, y] = c.convertFromPixel({gridIndex:0}, [e.offsetX, e.offsetY]);
    const i = Math.max(0, Math.min(ts.length - 1, Math.round((x / 1000 - ts[0]) / step)));
    let cum = 0;
    for (const k of order) { const v = (keys.get(k).get(ts[i]) || 0) * 8 / step;
      if (v > 0 && y >= cum && y <= cum + v) { if (k !== '__other') setTimeout(() => onPick(k)); return; } cum += v; }
  });
  zoomable(c);
}
function donut(el, rows, colorOf, center){
  const c = mkChart(el);
  c.setOption({animation:false, tooltip:{...tipBase(), formatter:p => `${esc(p.name)}<br><b>${fmtB(p.value)}</b> · ${p.percent}%`},
    title:{text:center[0], subtext:center[1], left:'center', top:'38%', textStyle:{color:C.ink, fontFamily:'JetBrains Mono', fontSize:16, fontWeight:700}, subtextStyle:{color:C.ink2, fontFamily:'Manrope', fontSize:11.5}},
    series:[{type:'pie', radius:['66%', '86%'], padAngle:2, itemStyle:{borderRadius:5}, label:{show:false}, emphasis:{scale:true, scaleSize:4},
      data:rows.map(r => ({name:r.k, value:tot(r), itemStyle:{color:colorOf(r.k), shadowBlur:12, shadowColor:colorOf(r.k)}}))}]});
}
function sparkSvg(vals, color, w = 200, h = 26){
  if (vals.length < 2) vals = [0, ...vals, 0];
  const max = Math.max(...vals, 1), pts = vals.map((v, i) => `${(i / (vals.length - 1) * w).toFixed(1)},${(h - 2 - v / max * (h - 6)).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polyline points="0,${h} ${pts} ${w},${h}" fill="${hexA(color, .12)}" stroke="none"/><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>`;
}

// ===================== river: inside <-> outside exchange =====================
const metricFmt = v => state.metric === 'bytes' ? fmtB(v) : state.metric === 'packets' ? fmtN(v) + T(' pkt', ' пак.') : fmtN(v) + ' flows';
const RIVERS = new Set();   // kick() of every mounted river (scale toggles wake them up)
function createRiver(host, opts){
  const {compact, onSelect, fetchData, refreshMs} = opts;
  host.innerHTML = '<canvas></canvas><div class="rtip" hidden></div>';
  const cv = host.querySelector('canvas'), tip = host.querySelector('.rtip'), ctx = cv.getContext('2d');
  let W = 0, H = 0, dpr = 1, raf = 0, hover = null, sticky = state.sel, data = null, first = true;
  const cur = new Map(), alphas = new Map(), pos = new Map(), flash = new Map(), lastT = new Map();
  let targets = new Map(), left = [], right = [], info = {L:new Map(), R:new Map()};
  // render on demand: frame() keeps scheduling itself only while something is still moving
  let moving = false;
  const ease = (m, k, target) => { const v = m.has(k) ? m.get(k) : target; let n = v + (target - v) * 0.1; if (Math.abs(target - n) < 0.003) n = target; else moving = true; m.set(k, n); return n; };
  const kick = () => { if (!raf) raf = requestAnimationFrame(frame); };
  async function load(){
    try { data = await fetchData(); } catch (e) { host.querySelector('.rtip').hidden = true; return; }
    left = data.left.map(h => h.ip).concat(data.more_left ? ['__other'] : []);
    right = data.right.map(r => r.ip).concat(data.more_right ? ['__other'] : []);
    info = {L:new Map(data.left.map(h => [h.ip, h])), R:new Map(data.right.map(r => [r.ip, r]))};
    targets = new Map(data.links.map(x => [x.l + '|' + x.r, {dn:x.dn, up:x.up}]));
    for (const x of data.links) { const k = x.l + '|' + x.r; if (!first && x.t > (lastT.get(k) || 0)) flash.set(k, 1); lastT.set(k, x.t); }
    for (const k of targets.keys()) if (!cur.has(k)) cur.set(k, {dn:0, up:0});
    if (first || reduceMotion) { for (const [k, v] of targets) cur.set(k, {...v}); first = false; }
    if (opts.onData) opts.onData(data);
    kick();
  }
  load();
  if (refreshMs) every(refreshMs, load);
  function size(){ kick(); const r = host.getBoundingClientRect(); W = r.width; H = r.height; dpr = Math.min(2, devicePixelRatio || 1); cv.width = W * dpr; cv.height = H * dpr; }
  const ro = new ResizeObserver(size); ro.observe(host); size(); onCleanup(() => ro.disconnect());
  const nodeLabel = (side, k) => {
    if (side === 'L') { if (k === '__other') return [isInternal() ? T('Other sources', 'Інші джерела') : T('Other inside', 'Інші внутрішні'), T('Remaining addresses', 'решта адрес')]; const h = info.L.get(k) || {ip:k}; return [h.name || k, h.name ? k : (h.private ? T('Inside', 'внутрішня') : T('Public (self)', 'публічна (self)'))]; }
    if (k === '__other') return [isInternal() ? T('Other destinations', 'Інші отримувачі') : T('Other outside', 'Інші зовнішні'), T('Remaining addresses', 'решта адрес')]; const r = info.R.get(k) || {};
    if (isInternal()) return [r.name || k, r.name ? k : T('Inside', 'внутрішня')];
    return [k, [r.service, r.city || ccName(r.country)].filter(Boolean).join(' · ')];
  };
  let bands = [], cards = [];
  function layout(){
    const headH = compact ? 22 : 30, gap = compact ? 6 : 8, n = Math.max(left.length, right.length, 1);
    const cardH = Math.max(28, Math.min(compact ? 40 : 50, (H - headH - gap * (n - 1)) / n));
    const cardW = Math.min(compact ? 160 : 210, Math.max(118, W * (compact ? 0.21 : 0.18)));
    const x0 = cardW + 6, x1 = W - cardW - 6, totS = new Map(), nodeReal = new Map(), MINW = 1.5;
    for (const [k, v] of cur) { const [l, r] = k.split('|'); const sq = Math.sqrt(Math.max(0, v.dn)) + Math.sqrt(Math.max(0, v.up)), real = v.dn + v.up;
      for (const key of ['L' + l, 'R' + r]) { totS.set(key, (totS.get(key) || 0) + sq); nodeReal.set(key, (nodeReal.get(key) || 0) + real); } }
    // widths blend smoothly between linear and sqrt when the user flips the scale (tooltips always show real values)
    const mix = ease(alphas, '__scale', state.scale === 'sqrt' ? 1 : 0);
    const scaleS = cardH * 0.8 / Math.max(1e-9, ...totS.values()), scaleL = cardH * 0.8 / Math.max(1e-9, ...nodeReal.values());
    const w = v => v <= 0 ? 0 : Math.max(MINW, mix * Math.sqrt(v) * scaleS + (1 - mix) * v * scaleL);
    // cards glide to their slot; new cards fade in from transparent
    const yOf = (side, k, i) => { const key = side + k, target = headH + i * (cardH + gap); if (!pos.has(key)) { pos.set(key, target); alphas.set('card' + key, 0); } const y = pos.get(key) + (target - pos.get(key)) * 0.12; pos.set(key, y); return y; };
    cards = [];
    left.forEach((k, i) => cards.push({side:'L', k, x:0, y:yOf('L', k, i), w:cardW, h:cardH, val:nodeReal.get('L' + k) || 0}));
    right.forEach((k, i) => cards.push({side:'R', k, x:W - cardW, y:yOf('R', k, i), w:cardW, h:cardH, val:nodeReal.get('R' + k) || 0}));
    const cy = new Map(cards.map(c => [c.side + c.k, c.y]));
    const li = new Map(left.map((k, i) => [k, i])), rix = new Map(right.map((k, i) => [k, i]));
    const links = [...cur.entries()].map(([k, v]) => { const [l, r] = k.split('|'); return {k, l, r, dn:v.dn, up:v.up, wu:w(v.up), wd:w(v.dn)}; }).filter(x => li.has(x.l) && rix.has(x.r) && x.wu + x.wd > 0.3);
    const stack = new Map(); for (const lk of links) { stack.set('L' + lk.l, (stack.get('L' + lk.l) || 0) + lk.wu + lk.wd); stack.set('R' + lk.r, (stack.get('R' + lk.r) || 0) + lk.wu + lk.wd); }
    const startY = (side, k) => cy.get(side + k) + cardH / 2 - (stack.get(side + k) || 0) / 2;
    const offL = new Map(), offR = new Map();
    for (const lk of [...links].sort((a, b) => li.get(a.l) - li.get(b.l) || rix.get(a.r) - rix.get(b.r))) { const y = offL.has(lk.l) ? offL.get(lk.l) : startY('L', lk.l); lk.ya = y; offL.set(lk.l, y + lk.wu + lk.wd); }
    for (const lk of [...links].sort((a, b) => rix.get(a.r) - rix.get(b.r) || li.get(a.l) - li.get(b.l))) { const y = offR.has(lk.r) ? offR.get(lk.r) : startY('R', lk.r); lk.yb = y; offR.set(lk.r, y + lk.wu + lk.wd); }
    bands = [];
    for (const lk of links) {
      const tu = lk.wu, td = lk.wd;
      if (tu > 0) bands.push({key:lk.k, l:lk.l, r:lk.r, dir:'up', ya:lk.ya, yb:lk.yb, t:tu, x0, x1});
      if (td > 0) bands.push({key:lk.k, l:lk.l, r:lk.r, dir:'dn', ya:lk.ya + tu, yb:lk.yb + tu, t:td, x0, x1});
    }
    return {headH};
  }
  function bandPath(b){ const p = new Path2D(), xm = (b.x0 + b.x1) / 2; p.moveTo(b.x0, b.ya); p.bezierCurveTo(xm, b.ya, xm, b.yb, b.x1, b.yb); p.lineTo(b.x1, b.yb + b.t); p.bezierCurveTo(xm, b.yb + b.t, xm, b.ya + b.t, b.x0, b.ya + b.t); p.closePath(); return p; }
  const related = b => { const f = sticky; if (!f) return true; if (f.type === 'band') return f.key === b.key; return f.side === 'L' ? b.l === f.k : b.r === f.k; };
  function roundRect(x, y, w, h, r){ ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }
  function frame(){
    moving = false; raf = 0;
    const near = (a, b) => Math.abs(a - b) <= Math.max(1e-6, 0.002 * Math.abs(b));
    for (const [key, v] of cur) { const t = targets.get(key) || {dn:0, up:0};
      v.dn = near(v.dn, t.dn) ? t.dn : v.dn + (t.dn - v.dn) * 0.07; v.up = near(v.up, t.up) ? t.up : v.up + (t.up - v.up) * 0.07;
      if (v.dn !== t.dn || v.up !== t.up) moving = true;
      if (!targets.has(key) && v.dn + v.up < 1e-3) cur.delete(key); }
    for (const [k, v] of flash) { const n = v * 0.965; if (n < 0.01) flash.delete(k); else { flash.set(k, n); moving = true; } }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
    if (!data) return;
    const L = layout();
    ctx.font = `600 ${compact ? 11.5 : 13}px Manrope, sans-serif`; ctx.fillStyle = C.ink2; ctx.textBaseline = 'middle';
    ctx.textAlign = 'left'; ctx.fillText(isInternal() ? T('Sources', 'Джерела') : T('Inside addresses', 'Внутрішні адреси'), 2, L.headH / 2 - 2); ctx.textAlign = 'right'; ctx.fillText(isInternal() ? T('Destinations', 'Отримувачі') : T('Outside addresses', 'Зовнішні адреси'), W - 2, L.headH / 2 - 2);
    if (!left.length) { ctx.textAlign = 'center'; ctx.fillStyle = C.ink3; ctx.fillText(data.live ? T(`No traffic under this filter in the last ${Math.round(data.window / 60)} min — Period shows the whole range`, `Немає трафіку під цей фільтр за останні ${Math.round(data.window / 60)} хв — «За період» покаже весь діапазон`) : T('No traffic under this filter for the selected period', 'Немає трафіку під цей фільтр за вибраний період'), W / 2, H / 2); return; }
    ctx.globalCompositeOperation = 'lighter';
    for (const b of bands) {
      const col = b.dir === 'up' ? C.up : C.down, fl = flash.get(b.key) || 0, a = ease(alphas, b.key + b.dir, related(b) ? 1 : 0.13) * (1 + 0.55 * fl);
      const g = ctx.createLinearGradient(b.x0, 0, b.x1, 0), s = b.dir === 'up' ? [.30, .48, .66] : [.66, .48, .30];
      g.addColorStop(0, hexA(col, Math.min(1, s[0] * a))); g.addColorStop(.5, hexA(col, Math.min(1, s[1] * a))); g.addColorStop(1, hexA(col, Math.min(1, s[2] * a)));
      b.path = bandPath(b); ctx.fillStyle = g; ctx.fill(b.path);
    }
    ctx.shadowBlur = 0; ctx.globalCompositeOperation = 'source-over';
    const f = sticky;
    for (const c of cards) {
      const isOther = c.k === '__other', col = isOther ? C.other : c.side === 'L' ? C.int : C.ext;
      const lit = !f || (f.type === 'card' ? (f.side === c.side && f.k === c.k) || bands.some(b => related(b) && (c.side === 'L' ? b.l === c.k : b.r === c.k)) : (c.side === 'L' ? f.l === c.k : f.r === c.k));
      ctx.globalAlpha = ease(alphas, 'card' + c.side + c.k, lit ? 1 : 0.45);
      roundRect(c.x + .5, c.y + .5, c.w - 1, c.h - 1, 10); ctx.fillStyle = 'rgba(14,26,58,.78)'; ctx.fill();
      ctx.strokeStyle = (hover && hover.type === 'card' && hover.side === c.side && hover.k === c.k) ? hexA(col, .9) : 'rgba(110,160,255,.28)'; ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = col; roundRect(c.x + 6, c.y + 7, 4, c.h - 14, 2); ctx.fill();
      const [l1, l2] = nodeLabel(c.side, c.k), maxW = c.w - 34;
      const clip = (s, font) => { ctx.font = font; if (ctx.measureText(s).width <= maxW) return s; while (s.length > 2 && ctx.measureText(s + '…').width > maxW) s = s.slice(0, -1); return s + '…'; };
      const f1 = `600 ${compact ? 11.5 : 12.5}px "JetBrains Mono", monospace`, f2 = `500 ${compact ? 10.5 : 11.5}px Manrope, sans-serif`;
      ctx.textAlign = 'left'; ctx.fillStyle = C.ink;
      if (c.h >= 36) { ctx.fillText(clip(l1, f1), c.x + 18, c.y + c.h / 2 - 7); ctx.fillStyle = C.ink2; ctx.fillText(clip(compact ? metricFmt(c.val) : `${metricFmt(c.val)} · ${l2}`, f2), c.x + 18, c.y + c.h / 2 + 9); }
      else ctx.fillText(clip(l1, f1), c.x + 18, c.y + c.h / 2);
      ctx.fillStyle = C.ink3; ctx.font = '600 14px Manrope, sans-serif'; ctx.textAlign = 'right'; ctx.fillText('›', c.x + c.w - 10, c.y + c.h / 2);
      ctx.globalAlpha = 1;
    }
    if (moving) raf = requestAnimationFrame(frame);
  }
  kick();
  RIVERS.add(kick); onCleanup(() => { cancelAnimationFrame(raf); RIVERS.delete(kick); });
  function hit(e){
    const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    for (const c of cards) if (x >= c.x && x <= c.x + c.w && y >= c.y && y <= c.y + c.h) return {type:'card', side:c.side, k:c.k, x, y};
    for (let i = bands.length - 1; i >= 0; i--) { const b = bands[i]; if (b.path && ctx.isPointInPath(b.path, x * dpr, y * dpr)) return {type:'band', key:b.key, l:b.l, r:b.r, x, y}; }
    return null;
  }
  const winSecs = () => data ? data.window : rangeSecs();
  function showTip(h){
    if (!h) { tip.hidden = true; return; }
    let html;
    if (h.type === 'band') {
      const v = cur.get(h.key) || {dn:0, up:0}, [l1] = nodeLabel('L', h.l), [r1, r2] = nodeLabel('R', h.r);
      const rate = x => state.metric === 'bytes' ? ' · ' + fmtR(x * 8 / winSecs()) : '';
      html = `<b class="mono">${esc(l1)} ⇄ ${esc(r1)}</b><br><span style="color:${C.ink2}">${esc(r2)}</span><br><span style="color:${C.up}">↑ upload ${metricFmt(v.up)}${rate(v.up)}</span><br><span style="color:${C.down}">↓ download ${metricFmt(v.dn)}${rate(v.dn)}</span><br><span style="color:${C.ink3}">${T('Click to select', 'клік — виділити')}</span>`;
    } else {
      const [a, b] = nodeLabel(h.side, h.k), c = cards.find(x => x.side === h.side && x.k === h.k);
      html = `<b class="mono">${esc(a)}</b><br><span style="color:${C.ink2}">${esc(b)}</span><br>${metricFmt(c ? c.val : 0)}<br><span style="color:${C.ink3}">${T('Click to highlight links · Shift+click to filter', 'клік — виділити зв’язки · Shift+клік — фільтр')}</span>`;
    }
    tip.innerHTML = html; tip.hidden = false;
    tip.style.left = Math.min(W - tip.offsetWidth - 4, Math.max(4, h.x + 14)) + 'px'; tip.style.top = Math.min(H - tip.offsetHeight - 4, Math.max(4, h.y + 14)) + 'px';
  }
  const same = (a, b) => a === b || (a && b && a.type === b.type && a.k === b.k && a.key === b.key && a.side === b.side);
  cv.addEventListener('mousemove', e => { const h = hit(e); if (!same(h, hover)) { hover = h; kick(); } else hover = h; cv.style.cursor = hover ? 'pointer' : 'default'; showTip(hover); });
  cv.addEventListener('mouseleave', () => { hover = null; showTip(null); kick(); });
  cv.addEventListener('click', e => {
    const h = hit(e);
    if (h && e.shiftKey && h.type === 'card' && h.k !== '__other') { addFilter(h.side === 'L' ? 'ip' : 'dst', h.k); return; }
    sticky = h && !(sticky && h.type === sticky.type && h.k === sticky.k && h.key === sticky.key) ? h : null;
    state.sel = sticky; if (onSelect) onSelect(sticky); kick();
  });
}

// ===================== maps =====================
const siteGeo = ip => { const d = META.devices.find(x => x.ip === ip); return d && d.lat != null ? [d.lon, d.lat] : null; };
const siteCity = ip => { const d = META.devices.find(x => x.ip === ip); return d ? (d.city || d.name) : ip; };
function flatMap(el, geo, onConn, arcs = !isCustom()){
  if (!echarts.getMap('world')) { el.innerHTML = '<div class="empty">' + T('Failed to load world map outlines', 'Не вдалося завантажити контури карти світу') + '</div>'; return; }
  const c = mkChart(el);
  let nameEn; try { nameEn = new Intl.DisplayNames(['en'], {type:'region'}); } catch (e) {}
  const EN_FIX = {'United States':'United States', 'Czechia':'Czech Rep.', 'Bosnia & Herzegovina':'Bosnia and Herz.', 'South Korea':'Korea', 'Dominican Republic':'Dominican Rep.'};
  let rmax = 1;
  // everything that depends on the data: applied again when a live map refreshes
  const dataOpt = geo => {
    const rows = geo.rows; rmax = rows.length ? tot(rows[0]) : 1;
    const byCountry = new Map(); for (const r of rows) byCountry.set(r.country, (byCountry.get(r.country) || 0) + tot(r));
    const cmax = Math.max(1, ...byCountry.values());
    const regions = [...byCountry].map(([cc, v]) => { let n = nameEn ? nameEn.of(cc) : cc; n = EN_FIX[n] || n; return {name:n, itemStyle:{areaColor:`rgba(47,123,255,${(0.18 + 0.42 * v / cmax).toFixed(2)})`}}; });
    const cities = new Map(); for (const r of rows) { const k = r.city + '|' + r.country; const g = cities.get(k) || {name:r.city || ccName(r.country), cc:r.country, lon:r.lo, lat:r.la, v:0}; g.v += tot(r); cities.set(k, g); }
    return {geo:{regions}, series:[
      {id:'agg', data:rows.map(r => { const s = siteGeo(r.exporter); return s && {coords:[s, [r.lo, r.la]], lineStyle:{width:.6 + 3.4 * tot(r) / rmax, opacity:.22, color:r.up > r.dn ? C.up : C.down}}; }).filter(Boolean)},
      {id:'remotes', data:[...cities.values()].map(g => { const onSite = META.devices.some(d => d.lat != null && Math.abs(d.lat - g.lat) < 0.6 && Math.abs(d.lon - g.lon) < 0.9);
        return {name:g.name, full:`${g.name}, ${ccName(g.cc)}`, value:[g.lon, g.lat, g.v], v:g.v, label:onSite ? {show:false} : undefined}; })}]};
  };
  const sites = META.devices.filter(d => d.lat != null).map(d => ({name:d.city || d.name, full:`${d.city || ''}${d.country ? ', ' + ccName(d.country) : ''} · ${d.name}`, value:[d.lon, d.lat, 1]}));
  const lbl = (pos, size) => ({show:true, position:pos, distance:7, color:'#F2F6FF', fontFamily:'Manrope', fontWeight:700, fontSize:size, textBorderColor:'rgba(4,10,28,.95)', textBorderWidth:3.5, formatter:'{b}'});
  c.setOption({animation:false, tooltip:{...tipBase(), trigger:'item', formatter:p => p.seriesType === 'lines' ? '' : p.componentType === 'geo' ? esc(p.name) : `${esc(p.data && p.data.full || p.name)}${p.data && p.data.v ? '<br><b>' + fmtB(p.data.v) + '</b>' : ''}`},
    geo:{map:'world', roam:true, zoom:1.25, center:[15, 35], scaleLimit:{min:1, max:10}, label:{show:false},
      itemStyle:{areaColor:'rgba(30,56,120,.38)', borderColor:'rgba(110,160,255,.38)', borderWidth:.5}, emphasis:{label:{show:false}, itemStyle:{areaColor:'rgba(47,123,255,.55)'}}},
    series:[
      {id:'agg', type:'lines', coordinateSystem:'geo', silent:true, zlevel:1, lineStyle:{curveness:.28}, data:[]},
      {id:'live', type:'lines', coordinateSystem:'geo', zlevel:2, silent:true, effect:{show:!reduceMotion, period:2.4, trailLength:0, symbol:'circle', symbolSize:5}, lineStyle:{width:1.4, opacity:.75, curveness:.28}, data:[]},
      {id:'remotes', type:'scatter', coordinateSystem:'geo', zlevel:3, symbolSize:d => 5 + 12 * Math.sqrt(d[2] / rmax), itemStyle:{color:C.ext, shadowBlur:12, shadowColor:C.ext},
        label:lbl('right', 12), labelLayout:{hideOverlap:true}, emphasis:{label:{show:true}}, data:[]},
      {id:'sites', type:'scatter', coordinateSystem:'geo', zlevel:4, symbolSize:12, itemStyle:{color:C.int, borderColor:'rgba(255,255,255,.85)', borderWidth:2, shadowBlur:10, shadowColor:C.int}, label:lbl('left', 13), data:sites},
    ]});
  c.setOption(dataOpt(geo));
  // pin the top of the map (Greenland) to the top edge of the panel; the default layout centres it vertically
  let roamed = false; c.on('georoam', () => { roamed = true; });
  const pinTop = () => { if (roamed || c.isDisposed() || !el.clientHeight) return;
    const dy = c.convertToPixel({geoIndex:0}, [-40, 83.6])[1] - 6; if (Math.abs(dy) < 1) return;
    c.setOption({geo:{center:c.convertFromPixel({geoIndex:0}, [el.clientWidth / 2, el.clientHeight / 2 + dy])}}); };
  pinTop();
  if (window.ResizeObserver) { const ro = new ResizeObserver(() => requestAnimationFrame(pinTop)); ro.observe(el); onCleanup(() => ro.disconnect()); }
  // live arcs: poll new flows, then release them gradually so bursts from the exporter become a steady stream
  let since = Math.floor(Date.now() / 1000) - 120, queue = [], live = [];
  const poll = async () => { try { const r = await api('live', {since}); since = r.rows.length ? r.rows[r.rows.length - 1].t : since; queue.push(...r.rows); if (queue.length > 400) queue = queue.slice(-400); } catch (e) {} };
  const tick = () => {
    const now = performance.now(); live = live.filter(e => now - e.born < 4500);
    const n = Math.min(queue.length, Math.max(1, Math.ceil(queue.length / 4)), Math.max(0, 40 - live.length));
    for (const r of queue.splice(0, n)) {
      const s = siteGeo(r.exporter); if (!s || (s[0] === r.lon && s[1] === r.lat)) continue;
      const up = r.dir === 'up'; live.push({coords:up ? [s, [r.lon, r.lat]] : [[r.lon, r.lat], s], color:up ? C.up : C.down, born:now}); if (onConn) onConn(r);
    }
    if (n || live.length !== lastLen) c.setOption({series:[{id:'live', data:live.map(e => ({coords:e.coords, lineStyle:{color:e.color}}))}]});
    lastLen = live.length;
  };
  let lastLen = -1;
  if (arcs && !isCustom()) { poll(); every(4000, poll); every(reduceMotion ? 3000 : 1000, tick); }    // a past period: no live arcs
  return geo => { if (!c.isDisposed()) c.setOption(dataOpt(geo)); };
}
function globe(el, geo){
  if (!echarts.getMap('world') || !window['echarts-gl']) { el.innerHTML = '<div class="empty">' + T('3D mode is not available in this browser', '3D-режим недоступний у цьому браузері') + '</div>'; return; }
  try {
    const tex = echarts.init(document.createElement('canvas'), null, {width:2048, height:1024});
    tex.setOption({backgroundColor:'#071431', animation:false, geo:{map:'world', silent:true, left:0, top:0, right:0, bottom:0, boundingCoords:[[-180, 90], [180, -90]], itemStyle:{areaColor:'#123072', borderColor:'#4C93FF', borderWidth:1.2}}});
    const c = mkChart(el); onCleanup(() => tex.dispose());
    const arcs = geo => geo.rows.slice(0, 80).map(r => { const s = siteGeo(r.exporter); if (!s) return null; const up = r.up > r.dn; return {coords:up ? [s, [r.lo, r.la]] : [[r.lo, r.la], s], lineStyle:{color:up ? C.up : C.down}}; }).filter(Boolean);
    const places = geo => { const m = new Map(); for (const r of geo.rows.slice(0, 10)) m.set(r.city, {name:r.city || ccName(r.country), value:[r.lo, r.la, 0]}); return [...m.values()]; };
    c.setOption({globe:{baseTexture:tex, shading:'lambert', environment:'none', globeRadius:100, light:{ambient:{intensity:.55}, main:{intensity:1.1, alpha:30, beta:40}},
        atmosphere:{show:true, color:'#2F7BFF', glowPower:5, innerGlowPower:2}, viewControl:{autoRotate:!reduceMotion, autoRotateSpeed:4, autoRotateAfterStill:20, distance:180, minDistance:60, maxDistance:260, alpha:45, beta:115}},
      series:[
        {id:'arcs', type:'lines3D', coordinateSystem:'globe', blendMode:'lighter', effect:{show:!reduceMotion, trailWidth:2.5, trailLength:.22, trailOpacity:1, constantSpeed:28}, lineStyle:{width:1.2, opacity:.35}, data:arcs(geo)},
        {type:'scatter3D', coordinateSystem:'globe', blendMode:'lighter', symbolSize:10, itemStyle:{color:C.int}, label:{show:true, formatter:'{b}', textStyle:{color:'#F2F6FF', fontSize:13, fontWeight:'bold', fontFamily:'Manrope', backgroundColor:'rgba(4,10,28,.7)', padding:[3, 6], borderRadius:4}},
          data:META.devices.filter(d => d.lat != null).map(d => ({name:d.city || d.name, value:[d.lon, d.lat, 0]}))},
        {id:'places', type:'scatter3D', coordinateSystem:'globe', blendMode:'lighter', symbolSize:7, itemStyle:{color:C.ext}, label:{show:true, formatter:'{b}', textStyle:{color:'#DDFBEF', fontSize:12, fontFamily:'Manrope', backgroundColor:'rgba(4,10,28,.6)', padding:[2, 5], borderRadius:4}}, data:places(geo)},
      ]});
    return geo => { if (!c.isDisposed()) c.setOption({series:[{id:'arcs', data:arcs(geo)}, {id:'places', data:places(geo)}]}); };
  } catch (e) { el.innerHTML = '<div class="empty">' + T('3D mode is not available: ', '3D-режим недоступний: ') + esc(e.message) + '</div>'; }
}

// ===================== shared UI =====================
const NAV = [
  ['overview',T('Overview','Огляд'),'M3 9.5L9 4l6 5.5V15H3z'], ['flows',T('Flows','Потоки'),'M2 6c4 0 5 6 9 6h5M2 12c4 0 5-6 9-6h5'], ['paths',T('Through device','Через пристрій'),'M2 4h4M2 9h4M2 14h4M12 4h4M12 9h4M12 14h4M6 4c3 0 3 5 6 5M6 14c3 0 3-10 6-10M6 9h6'], ['network',T('Path analysis','Аналіз шляху'),'M9 2.5a2 2 0 1 0 0 .01M3.5 13a2 2 0 1 0 0 .01M14.5 13a2 2 0 1 0 0 .01M8 4.5L4.5 11M10 4.5l3.5 6.5M5.5 13h7'], ['talkers',T('Top hosts','Топ хостів'),'M6 7a2.5 2.5 0 1 0 0-.01M2 15c0-2.5 2-4 4-4s4 1.5 4 4M13 8a2 2 0 1 0 0-.01M11.5 15c.3-2 1.3-3 3-3'],
  ['apps',T('Services','Сервіси'),'M3 3h5v5H3zM10 3h5v5h-5zM3 10h5v5H3zM10 10h5v5h-5z'], ['ports',T('Ports','Порти'),'M6 2v4M12 2v4M4 6h10v3a5 5 0 0 1-10 0zM9 14v3'], ['geo',T('Geolocation','Геолокація'),'M9 16s5-4.5 5-8.5A5 5 0 0 0 4 7.5C4 11.5 9 16 9 16zM9 9a1.6 1.6 0 1 0 0-.01'],
  ['threats',T('Events','Події'),'M9 2l6 2.5V9c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V4.5z'],
  ['settings',T('Settings','Налаштування'),'M9 6.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5zM9 1.5v2M9 14.5v2M1.5 9h2M14.5 9h2M3.7 3.7l1.4 1.4M12.9 12.9l1.4 1.4M3.7 14.3l1.4-1.4M12.9 5.1l1.4-1.4'],
];
const DEV_ICON = 'M2 5h14v6H2zM5 8h.01M8 8h.01M6 14h6', USER_ICON = 'M6.5 7.5a2.5 2.5 0 1 0 0-.01M2 15c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4M12 4.5h4M14 2.5v4';
const navIcon = k => (NAV.find(n => n[0] === k) || [])[2];
const icon = (d, s = 18) => `<svg width="${s}" height="${s}" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${d}"/></svg>`;
const ICO = {pulse:'M2 9h3l2-5 3 10 2-5h4', nodes:'M9 3a2 2 0 1 0 0 .01M4 13a2 2 0 1 0 0 .01M14 13a2 2 0 1 0 0 .01M8 5l-3 6M10 5l3 6', ip:'M3 5h12v6H3zM6 14h6M7 8h.01M10 8h.01', grid:navIcon('apps'), flow:navIcon('flows'),
  globe:'M9 2a7 7 0 1 0 0 14A7 7 0 0 0 9 2zM2 9h14M9 2c2.5 2.5 2.5 11.5 0 14M9 2c-2.5 2.5-2.5 11.5 0 14', chart:'M2 15l4-6 3 3 5-8 2 2', conv:'M3 5h8l-2-2M15 13H7l2 2', list:'M3 5h12M3 9h12M3 13h8',
  users:navIcon('talkers'), key:'M12 3a3 3 0 1 0 .01 0M9.9 8.1L3 15M5 13l2 2M7 11l2 2', shield:navIcon('threats'), dev:DEV_ICON, pie:'M9 2v7h7A7 7 0 1 1 9 2z', search:'M8 8m-5 0a5 5 0 1 0 10 0a5 5 0 1 0-10 0M12 12l4 4'};
const ph = (ic, title, sub, right = '', big = false) => `<div class="ph"><div class="ttl"><span class="ico">${icon(ICO[ic] || ic)}</span><div><h2${big ? ' class="big"' : ''}>${title}</h2>${sub ? `<span class="sub">${sub}</span>` : ''}</div></div>${right ? `<div class="right">${right}</div>` : ''}</div>`;
const seg = (id, opts, val) => `<div class="seg" id="${id}" role="group">${opts.map(([v, l, tip]) => `<button data-v="${v}" aria-pressed="${v === val}"${tip ? ` title="${tip}"` : ''}>${l}</button>`).join('')}</div>`;
const flowLive = () => state.flowLive && !isCustom();
const heroLive = () => state.heroLive && !isCustom();
// a past period has no live window: the Live button stays visible but off
const lockLive = id => { if (!isCustom()) return; const b = document.querySelector(`#${id} button[data-v="live"]`); if (b) { b.disabled = true; b.title = T('Live shows the last minutes — choose a preset period to use it', 'Наживо показує останні хвилини — виберіть готовий період, щоб увімкнути'); } };
const wireSeg = (id, fn) => document.querySelectorAll(`#${id} button`).forEach(b => b.onclick = () => fn(b.dataset.v));
const hostCell = (ip, name) => `<span class="idot int"></span><b class="mono">${esc(name || ip)}</b>${name ? ` <span class="nat">${esc(ip)}</span>` : ''}`;
// values stored in English (service / protocol names made by the collector) shown in the UI language
const DV_UK = {'Local network':'Локальна мережа', 'Unknown':'Невідомо'};
const dv = v => LANG === 'uk' && v ? (DV_UK[v] || String(v).replace(/ other$/, ' інше')) : v;
const svcBadge = name => { const c = keyColor(name); return `<span class="app-b"><i style="background:${hexA(c, .85)};box-shadow:0 0 8px ${hexA(c, .6)}">${esc((dv(name) || '?')[0])}</i>${esc(dv(name))}</span>`; };
const fill = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; return el; };
const errBox = e => `<div class="err">${T('Failed to load: ', 'Не вдалося завантажити: ')}${esc(e.message)}</div>`;
function wireFilters(root){
  root.querySelectorAll('[data-f]').forEach(b => b.addEventListener('click', e => { e.stopPropagation(); addFilter(b.dataset.f, b.dataset.v, e.shiftKey); }));
  root.querySelectorAll('[data-host]').forEach(tr => tr.addEventListener('click', () => openHost(tr.dataset.host)));
}
// run an async section; ignore results if the user navigated away meanwhile
async function section(id, fn){
  const seq = renderSeq;
  try { const html = await fn(); if (seq === renderSeq && html != null) { const el = fill(id, html); if (el) { el.classList.remove('loading'); wireFilters(el); } } }
  catch (e) { if (seq === renderSeq) { const el = fill(id, errBox(e)); if (el) el.classList.remove('loading'); } }
}
const convRows = (rows, total) => rows.length ? '<div class="blist">' + rows.map(x => { const max = tot(rows[0]) || 1;
  return `<button class="brow" data-f="dst" data-v="${esc(x.ext_ip)}"><span class="n">${esc(x.name || x.int_ip)}<span class="arr">→</span>${esc(x.ext_ip)}</span><span class="t">${fmtB(tot(x))}</span><span class="p">${pct(tot(x), total)}</span>
    <span class="bar2" style="width:${(100 * tot(x) / max).toFixed(1)}%"><i class="u" style="width:${(100 * x.up / (tot(x) || 1)).toFixed(1)}%"></i><i class="d" style="flex:1"></i></span></button>`; }).join('') + '</div>'
  : `<div class="empty">${T('No traffic under this filter', 'Немає трафіку під цей фільтр')}</div>`;

// ===================== views =====================
async function kpiCards(){
  const [s, ser] = await Promise.all([api('summary'), api('series')]);
  // trend vs the previous equal period; until enough history exists, say since when data is collected and when the comparison appears
  const since = s.oldest ? (Date.now() / 1000 - s.oldest > 86400 ? dmy(s.oldest) + ' ' : '') + hhmm(s.oldest) : '';
  const ready = s.oldest && !s.custom ? s.oldest + 2 * s.range : 0, readyTxt = ready ? new Date(ready * 1000).toLocaleString(LOC, {day:'numeric', month:'long', hour:'2-digit', minute:'2-digit'}) : '';
  const noPrev = `<span class="tr nodata" style="color:var(--ink3)" title="${T('Comparison with the previous equal period will appear once twice as much data is collected', 'Порівняння з попереднім таким самим періодом з’явиться, коли назбирається вдвічі більше даних')}${readyTxt ? T(' — approx. ', ' — орієнтовно ') + readyTxt : ''}">${since ? T('data since ', 'дані з ') + since : T('no data', 'немає даних')}</span>`;
  const trend = (a, b) => !s.has_prev || !b ? noPrev : `<span class="tr ${a < b ? 'dn' : ''}" title="${T('compared to the previous equal period', 'порівняно з попереднім таким самим періодом')}">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
  const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]);
  const card = (ic, k, v, tr, sp, col) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sparkSvg(sp, col)}</div>`;
  return card('pulse', T('Total traffic', 'Загальний трафік'), fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
    + card('nodes', T('Flows processed', 'Оброблено flow'), fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext)
    + card('ip', T('Unique IPs', 'Унікальні IP'), fmtN(s.ips), trend(s.ips, s.p_ips), fl.map(Math.sqrt), '#4C93FF')
    + card('grid', T('Top service', 'Топ сервіс'), esc(s.top_service || '—'), s.top_service ? `<span class="tr" style="color:var(--ink2)">${pct(s.top_service_bytes, s.bytes)}</span>` : '', vals.map(Math.sqrt), C.int);
}
let heroScope = null;
function mountHero(){
  if (heroScope) heroScope.dispose();
  heroScope = childScope();
  const g = state.heroMode === 'graph' || isInternal();     // no geography for inside <-> inside traffic
  const live = heroLive();
  // one Live / Period switch for Map, Graph and 3D: live = the last 2 minutes of data, period = the whole range
  const sub = live ? (g ? T('live · 2 min · updating…', 'наживо · 2 хв · оновлюється…') : T('live · the last 2 min', 'наживо · останні 2 хв'))
    : (g ? rangeLabel() : T('the selected period', 'за вибраний період'));
  fill('heroSec', `${ph('flow', T('Network traffic', 'Мережевий трафік'), `<span id="heroLbl" class="tnum">${sub}</span>`,
      (isInternal() ? `<span class="legend"><span><i class="bar" style="background:${C.up}"></i>${T('source → destination', 'джерело → отримувач')}</span></span>`
        : `<span class="legend"><span><i class="bar" style="background:${C.down}"></i>download</span><span><i class="bar" style="background:${C.up}"></i>upload</span>${g ? '' : `<span><i style="background:${C.int}"></i>${T('inside', 'внутр.')}</span><span><i style="background:${C.ext}"></i>${T('outside', 'зовн.')}</span>`}</span>`)
      + (g ? seg('scaleSeg', [['sqrt', T('Compressed', 'Стиснений'), T('Width ∝ √volume — small flows stand out next to large ones', 'Ширина ∝ √обсягу — дрібні потоки помітні поруч із великими')], ['lin', T('Linear', 'Лінійний'), T('Width proportional to volume', 'Ширина пропорційна обсягу')]], state.scale) : '')
      + seg('heroLiveSeg', [['live', T('Live', 'Наживо'), T('The last 2 minutes of data, updated as it arrives', 'Останні 2 хвилини даних, оновлюється з надходженням')], ['period', T('Period', 'За період'), T('The whole selected period', 'Увесь вибраний період')]], live ? 'live' : 'period')
      + (isInternal() ? '' : seg('heroSeg', [['map', 'Map'], ['graph', 'Graph'], ['3d', '3D']], state.heroMode)))}
    <div id="heroBody" class="${g ? 'river' : 'chart hero-h'}"></div><div id="heroNote" class="heronote" hidden></div><div id="heroOvl"></div>`);
  lockLive('heroLiveSeg');
  wireSeg('heroSeg', m => { if (m === state.heroMode) return; state.heroMode = m; mountHero(); });
  wireSeg('heroLiveSeg', m => { const l = m === 'live'; if (l === !!state.heroLive) return; state.heroLive = l; mountHero(); });
  wireSeg('scaleSeg', m => { state.scale = m; setPressed('scaleSeg', m); RIVERS.forEach(k => k()); });
  const hb = document.getElementById('heroBody'), myScope = heroScope;
  heroScope.run(() => {
    if (g) createRiver(hb, {compact:true, refreshMs:live ? 10000 : 0, fetchData:() => api('river', {top:8, live:live ? 1 : 0, win:120, metric:state.metric}),
      onData:() => fill('heroLbl', live ? `${T(`live · 2 min · updated ${hms(Math.floor(Date.now() / 1000))}`, `наживо · 2 хв · оновлено ${hms(Math.floor(Date.now() / 1000))}`)}${scaleNote()}` : rangeLabel() + scaleNote())});
  });
  if (!g) {
    // an empty map or globe says so, like the graph: nothing under this filter in the window
    const note = geo => { const n = document.getElementById('heroNote'); if (!n || heroScope !== myScope) return; n.hidden = !!geo.rows.length;
      n.textContent = geo.live ? T(`No traffic with a location under this filter in the last ${Math.round(geo.window / 60)} min — “Period” shows the whole range`, `Немає трафіку з геолокацією під цей фільтр за останні ${Math.round(geo.window / 60)} хв — «За період» покаже весь діапазон`)
        : T('No traffic with a location under this filter for the selected period', 'Немає трафіку з геолокацією під цей фільтр за вибраний період'); };
    const load = () => api('geo', {live:live ? 1 : 0, win:120});
    load().then(geo => { if (!hb.isConnected || heroScope !== myScope) return; note(geo);
      myScope.run(() => { const update = state.heroMode === 'map' ? flatMap(hb, geo, null, live) : globe(hb, geo);
        if (live && update) every(15000, () => load().then(d => { if (heroScope === myScope) { note(d); update(d); } }).catch(() => {})); }); }).catch(e => fill('heroBody', errBox(e)));
    section('heroOvl', async () => {
      const [h, d, s] = await Promise.all([api('top', {dim:'int_ip', limit:5}), api('top', {dim:'ext_ip', limit:1}), api('top', {dim:'service', limit:5})]);   // the same requests as the top lists beside it
      if (heroScope !== myScope) return null;
      const a = h.rows[0], b = d.rows[0], c = s.rows[0];
      return `<div class="overlay"><div class="ovl">
        <div><span class="ico">${icon(ICO.users, 15)}</span><span>${T('Top source', 'Топ джерело')}</span><b>${esc(a ? a.name || a.k : '—')}</b><small>${a ? fmtB(tot(a)) : ''}</small></div>
        <div><span class="ico">${icon(ICO.globe, 15)}</span><span>${T('Top destination', 'Топ призначення')}</span><b>${esc(b ? b.k : '—')}</b><small>${b ? [b.city, fmtB(tot(b))].filter(Boolean).join(' · ') : ''}</small></div>
        <div><span class="ico">${icon(ICO.grid, 15)}</span><span>${T('Top service', 'Топ сервіс')}</span><b>${esc(c ? c.k : '—')}</b><small>${c ? pct(tot(c), s.total) : ''}</small></div></div>
        ${!live ? '' : `<div class="livebadge"><b>${T('Live', 'Наживо')}</b>${T('new connections', 'нові з’єднання')}</div>`}</div>`;
    });
  }
}
function vOverview(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><div id="kpis" class="s12 grid" style="grid-column:span 12"><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div></div>
    <section class="glass panel s8 hero" id="heroSec"></section>
    <div class="col s4">
      <section class="glass panel">${ph('pie', T('Top services', 'Топ сервісів'), T('by traffic volume', 'за обсягом трафіку'))}<div id="svcBox" class="loading"></div></section>
      <section class="glass panel">${ph('users', T('Top hosts', 'Топ хостів'), T('inside addresses', 'внутрішні адреси'))}<div id="hostBox" class="loading"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', T('Traffic trend', 'Динаміка трафіку'), rangeLabel())}<div class="chart" id="cTrend"></div></section>
    <section class="glass panel s4">${ph('conv', T('Top conversations', 'Топ розмов'), (isInternal() ? T('source → destination', 'джерело → отримувач') : T('inside → outside address', 'внутрішня → зовнішня адреса')))}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('list', T('Recent flows', 'Останні потоки'), T('new network activity', 'нова мережева активність'), `<button class="lnk" id="toFlows">${T('All', 'Усі')}</button>`)}<div id="recentBox" class="loading"></div></section></div>`;
  document.getElementById('toFlows').onclick = () => { state.view = 'flows'; render(); };
  section('kpis', kpiCards);
  mountHero();
  section('svcBox', async () => {
    const t = await api('top', {dim:'service', limit:5}); const rest = t.total - t.rows.reduce((s, r) => s + tot(r), 0);
    const rows = [...t.rows, ...(rest > 0 ? [{k:T('Others', 'Інші'), up:rest, dn:0}] : [])];
    setTimeout(() => { const el = document.getElementById('cDonut'); if (el) donut(el, rows, k => k === T('Others', 'Інші') ? C.other : keyColor(k), [fmtB(t.total), T('total traffic', 'весь трафік')]); });
    return `<div class="donut-wrap"><div class="chart donut" id="cDonut"></div><div class="dl">${rows.map(r => `<i class="idot" style="background:${r.k === T('Others', 'Інші') ? C.other : keyColor(r.k)}"></i>${r.k === T('Others', 'Інші') ? `<span>${T('Others', 'Інші')}</span>` : `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.k)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div></div>`;
  });
  section('hostBox', async () => { const t = await api('top', {dim:'int_ip', limit:5});
    return `<div class="tw"><table class="compact"><thead><tr><th>#</th><th>${T('Host', 'Хост')}</th><th class="num">${T('Traffic', 'Трафік')}</th><th class="num">%</th><th></th></tr></thead><tbody>${t.rows.map((r, i) => `<tr class="click" data-host="${esc(r.k)}"><td class="mono">${i + 1}</td><td><div class="two-line"><b class="mono">${esc(r.name || r.k)}</b>${r.name ? `<span class="nat">${esc(r.k)}</span>` : ''}</div></td><td class="num mono">${fmtB(tot(r))}</td><td class="num mono">${pct(tot(r), t.total)}</td><td class="chev">›</td></tr>`).join('')}</tbody></table></div>`; });
  api('series').then(s => { const el = document.getElementById('cTrend'); if (el) trendChart(el, s); }).catch(e => fill('cTrend', errBox(e)));
  section('convBox', async () => { const t = await api('top', {dim:'conv', limit:5}); return convRows(t.rows, t.total); });
  section('recentBox', async () => { const t = await api('flows', {limit:7});
    return `<div class="tw"><table class="compact"><thead><tr><th>${T('Time', 'Час')}</th><th>${isInternal() ? T('Source → destination · service', 'Джерело → отримувач · сервіс') : T('Inside → outside · service', 'Внутр. → зовн. · сервіс')}</th><th class="num">${T('Volume', 'Обсяг')}</th></tr></thead><tbody>${t.rows.map(f => `<tr><td class="mono">${hms(f.t)}</td><td><div class="two-line"><span class="ipl">${esc(f.name || f.int_ip)} <span class="${f.dir === 'down' ? 'd' : 'u'}">${f.dir === 'down' ? '←' : '→'}</span> ${esc(f.ext_ip)}</span><span class="nat">${esc(dv(f.service))}${f.l7 ? ' · ' + esc(f.l7) : ''}</span></div></td><td class="num mono">${fmtB(f.bytes)}</td></tr>`).join('') || `<tr><td colspan="4"><div class="empty">${T('No records', 'Немає записів')}</div></td></tr>`}</tbody></table></div>`; });
}

// filters that describe a river selection (a host, an outside address, or a conversation band); none for «Інші»
function selFilters(sel){
  if (!sel) return [];
  const isOther = k => k === '__other', out = [];
  if (sel.type === 'band') { if (!isOther(sel.l)) out.push({k:'ip', v:sel.l}); if (!isOther(sel.r)) out.push({k:'dst', v:sel.r}); }
  else if (!isOther(sel.k)) out.push({k:sel.side === 'L' ? 'ip' : 'dst', v:sel.k});
  return out;
}
async function inspectorHtml(sel){
  if (!sel) return `<p class="note" style="margin:0">${T('Hover a ribbon or node to see the volume. A click highlights its links and shows the details here; Shift+click on a node adds it to the filters.', 'Наведіть на стрічку чи вузол, щоб побачити обсяг. Клік виділяє зв’язки й показує деталі тут; Shift+клік на вузлі додає його у фільтри.')}</p>`;
  const extra = selFilters(sel);
  let title, subtitle = '';
  const isOther = k => k === '__other';
  if (sel.type === 'band') { title = `${isOther(sel.l) ? T('Others', 'Інші') : sel.l} ⇄ ${isOther(sel.r) ? T('Others', 'Інші') : sel.r}`; subtitle = T('conversation', 'розмова'); }
  else if (sel.side === 'L') title = isOther(sel.k) ? T('Other inside', 'Інші внутрішні') : sel.k;
  else title = isOther(sel.k) ? T('Other outside', 'Інші зовнішні') : sel.k;
  if (!extra.length) return `<div class="insp"><div class="who"><b>${esc(title)}</b></div><p class="note" style="margin:0">${T('A collapsed group — pick a specific address.', 'Згорнута група — виберіть конкретну адресу.')}</p></div>`;
  const [s, svc, l7, ext] = await Promise.all([api('summary', {}, extra), api('top', {dim:'service', limit:4}, extra), api('top', {dim:'l7', limit:4}, extra), api('top', {dim:'ext_ip', limit:1}, extra)]);
  const e0 = ext.rows[0];
  if (sel.type !== 'band' && sel.side === 'R' && e0) subtitle = [e0.as_org && `AS${e0.asn} ${e0.as_org}`, [e0.city, ccName(e0.country)].filter(Boolean).join(', ')].filter(Boolean).join(' · ');
  return `<div class="insp"><div class="who"><b>${esc(title)}</b><span>${esc(subtitle)}</span></div>
    <div class="dk"><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">${T('Services', 'Сервіси')}</h4><div class="tagrow">${svc.rows.map(g => `<span class="tag">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">${T('Protocols', 'Протоколи')}</h4><div class="tagrow">${l7.rows.map(g => `<span class="tag mono">${esc(dv(g.k))}</span>`).join('') || '—'}</div></div>
    <div class="chart" id="cInsp" style="height:120px" data-extra="${esc(JSON.stringify(extra))}"></div></div>`;
}
function vFlows(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid">
    <section class="glass panel s9">${ph('flow', isInternal() ? T('Exchange between inside addresses', 'Обмін між внутрішніми адресами') : T('Exchange between inside and outside addresses', 'Обмін між внутрішніми та зовнішніми адресами'), isInternal() ? T('source → destination · width = volume (the compressed scale shows small flows too) · top 10 on each side, the rest in «Others»', 'джерело → отримувач · ширина = обсяг (стиснений масштаб показує й дрібні потоки) · топ-10 з кожного боку, решта в «Інші»') : T('Colour = direction · width = volume (the compressed scale shows small flows too) · top 10 on each side, the rest in «Others»', 'Колір = напрямок · ширина = обсяг (стиснений масштаб показує й дрібні потоки) · топ-10 з кожного боку, решта в «Інші»'),
      seg('metricSeg', [['bytes', T('Bytes', 'Байти')], ['packets', T('Packets', 'Пакети')], ['flows', 'Flows']], state.metric) + seg('scaleSeg', [['sqrt', T('Compressed', 'Стиснений'), T('Width ∝ √volume — small flows stay visible next to big ones', 'Ширина ∝ √обсягу — дрібні потоки помітні поруч із великими')], ['lin', T('Linear', 'Лінійний'), T('Width proportional to volume', 'Ширина пропорційна обсягу')]], state.scale) + seg('liveSeg', [['live', T('Live', 'Наживо')], ['period', T('Period', 'За період')]], flowLive() ? 'live' : 'period'), true)}
      <div class="legend" style="margin:-6px 0 10px">${isInternal() ? `<span><i class="bar" style="background:${C.up}"></i>${T('source → destination', 'джерело → отримувач')}</span><span><i style="background:${C.int}"></i>${T('inside address', 'внутрішня адреса')}</span>` : `<span><i class="bar" style="background:${C.down}"></i>${T('download (outside → inside)', 'download (зовн. → внутр.)')}</span><span><i class="bar" style="background:${C.up}"></i>${T('upload (inside → outside)', 'upload (внутр. → зовн.)')}</span><span><i style="background:${C.int}"></i>${T('inside address', 'внутрішня адреса')}</span><span><i style="background:${C.ext}"></i>${T('outside address', 'зовнішня адреса')}</span>`}<span id="winLbl" class="mono" style="margin-left:auto"></span></div>
      <div class="river big" id="river"></div></section>
    <div class="col s3">
      <section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO.pulse, 22)}</span><span class="k">${T('Total traffic', 'Загальний трафік')}</span><span class="v" id="kTot">—</span></section>
      <section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO.nodes, 22)}</span><span class="k">${T('Flow records', 'Flow-записи')}</span><span class="v" id="kFl">—</span></section>
      <section class="glass panel">${ph('search', T('Inspector', 'Інспектор'), T('details of the selection', 'деталі вибраного'))}<div id="insp"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', T('Traffic volume', 'Обсяг трафіку'), 'download / upload')}<div class="chart" id="cVol"></div></section>
    <section class="glass panel s4">${ph('conv', T('Top conversations', 'Топ розмов'), T('with the service', 'з сервісом'))}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', T('Protocols', 'Протоколи'), T('L7 by port', 'рівень L7 за портом'))}<div id="protoBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('list', T('Flow records', 'Записи потоків'), T('raw records, one per session direction · click to expand', 'сирі записи, по одному на напрямок сесії · клік розгортає'))}<div id="recBox" class="loading"></div></section></div>`;
  const showInsp = async sel => {
    const seq = renderSeq; let html; try { html = await inspectorHtml(sel); } catch (e) { html = errBox(e); }
    if (seq !== renderSeq) return; fill('insp', html);
    const el = document.getElementById('cInsp');
    if (el) api('series', {}, JSON.parse(el.dataset.extra)).then(s => { if (el.isConnected) trendChart(el, s, true); });
  };
  showInsp(state.sel);
  // a click on the river highlights the links and shows the details; Shift+click on a node adds a filter (createRiver)
  const onRiverSelect = sel => showInsp(sel);
  let riverScope = null;
  const winLbl = d => { const el = document.getElementById('winLbl'); if (el) el.textContent = (d.live && d.window_end ? T(`2-min window to ${hms(d.window_end)} · updated ${hms(Math.floor(Date.now() / 1000))}`, `вікно 2 хв до ${hms(d.window_end)} · оновлено ${hms(Math.floor(Date.now() / 1000))}`) : rangeLabel()) + scaleNote(); };
  let lastData = null;
  const mountRiver = () => {
    if (riverScope) riverScope.dispose();
    riverScope = childScope();
    riverScope.run(() => createRiver(document.getElementById('river'), {compact:false, refreshMs:flowLive() ? 10000 : 0, onSelect:onRiverSelect,
      fetchData:() => api('river', {top:10, live:flowLive() ? 1 : 0, win:120, metric:state.metric}), onData:d => { lastData = d; winLbl(d); }}));
  };
  mountRiver();
  wireSeg('scaleSeg', m => { state.scale = m; setPressed('scaleSeg', m); RIVERS.forEach(k => k()); if (lastData) winLbl(lastData); });
  wireSeg('metricSeg', m => { if (m === state.metric) return; state.metric = m; setPressed('metricSeg', m); mountRiver(); });
  lockLive('liveSeg');
  wireSeg('liveSeg', m => { const live = m === 'live'; if (live === state.flowLive) return; state.flowLive = live; setPressed('liveSeg', m); mountRiver(); });
  api('summary').then(s => { fill('kTot', fmtB(s.bytes)); fill('kFl', fmtN(s.flows)); }).catch(() => {});
  api('series').then(s => { const el = document.getElementById('cVol'); if (el) trendChart(el, s); }).catch(e => fill('cVol', errBox(e)));
  section('convBox', async () => { const t = await api('top', {dim:'conv', limit:6});
    return `<div class="tw"><table class="compact"><thead><tr><th>${isInternal() ? T('Source', 'Джерело') : T('Inside', 'Внутр.')}</th><th>${isInternal() ? T('Destination', 'Отримувач') : T('Outside', 'Зовн.')}</th><th>${T('Service', 'Сервіс')}</th><th class="num">${T('Volume', 'Обсяг')}</th></tr></thead><tbody>${t.rows.map(x => `<tr class="click" data-conv="${esc(x.int_ip)}|${esc(x.ext_ip)}" title="${T('Filter by this conversation', 'Фільтр за цією розмовою')}"><td class="ipl">${esc(x.name || x.int_ip)}</td><td class="ipl">${esc(x.ext_ip)}</td><td>${svcBadge(x.service)}</td><td class="num mono">${fmtB(tot(x))}</td></tr>`).join('')}</tbody></table></div>`; });
  document.getElementById('convBox').addEventListener('click', e => { const tr = e.target.closest('tr[data-conv]'); if (!tr) return;
    const [ip, dst] = tr.dataset.conv.split('|'); putFilter({k:'ip', v:ip, neg:false}); putFilter({k:'dst', v:dst, neg:false}); state.sel = null; render(); });
  section('protoBox', async () => { const t = await api('top', {dim:'l7', limit:6});
    setTimeout(() => { const el = document.getElementById('cProto'); if (el) donut(el, t.rows, k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), T('protocols', 'протоколів')]); });
    return `<div class="donut-wrap"><div class="chart donut" id="cProto"></div><div class="dl">${t.rows.map((r, i) => `<i class="idot" style="background:${PAL[i]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(dv(r.k))}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div></div>`; });
  section('recBox', async () => { const t = await api('flows', {limit:60}); window.__recs = t.rows; return recTable(t.rows); });
}
// ===================== device map: hosts -> ports (dots on the device contour) -> lines inside -> ports -> hosts =====================
// Inside interfaces are dots on the left edge of the box, WAN interfaces dots on the right edge, the device
// itself is the core. Inside the box every path is a line whose width follows its volume: LAN -> internet
// crosses the box, LAN <-> LAN turns round in an arc and goes back to the left edge, traffic for the device
// itself ends in the core. Hosts sit outside the box, joined to the dot of their interface.
function createDevMap(host, opts){
  host.innerHTML = '<canvas></canvas><div class="rtip" hidden></div>';
  const cv = host.querySelector('canvas'), tip = host.querySelector('.rtip'), ctx = cv.getContext('2d');
  let W = 0, H = 0, dpr = 1, data = null, hover = null, shapes = [];
  const {ifs, dev} = opts;
  const roleOf = i => (ifs.get(i) || {}).role || (i === dev.config.local_if ? 'local' : 'lan');
  const nameOf = i => { const x = ifs.get(i); return x ? (x.custom_name || x.name) : (i === 0 ? 'local' : `if ${i}`); };
  const addrOf = i => { const x = ifs.get(i); return x ? (ifAddrs(x)[0] || '') : ''; };
  const fmtV = v => state.metric === 'bytes' ? fmtB(v) : fmtN(v);
  async function load(){ try { data = await opts.fetchData(); if (opts.onData) opts.onData(data); draw(); } catch (e) { host.innerHTML = errBox(e); } }
  function size(){ const r = host.getBoundingClientRect(); W = r.width; H = r.height; dpr = Math.min(2, devicePixelRatio || 1); cv.width = W * dpr; cv.height = H * dpr; draw(); }
  const ro = new ResizeObserver(size); ro.observe(host); onCleanup(() => ro.disconnect());
  load(); if (opts.refreshMs) every(opts.refreshMs, load);
  const rr = (x, y, w, h, r) => { const p = new Path2D(); p.moveTo(x + r, y); p.arcTo(x + w, y, x + w, y + h, r); p.arcTo(x + w, y + h, x, y + h, r); p.arcTo(x, y + h, x, y, r); p.arcTo(x, y, x + w, y, r); p.closePath(); return p; };
  const clip = (str, font, max) => { ctx.font = font; if (ctx.measureText(str).width <= max) return str; while (str.length > 2 && ctx.measureText(str + '…').width > max) str = str.slice(0, -1); return str + '…'; };
  function draw(){
    if (!W || !H) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H); shapes = [];
    if (!data) return;
    ctx.textBaseline = 'middle'; ctx.lineCap = 'round';
    const v = x => state.scale === 'lin' ? x : Math.sqrt(x);
    const paths = data.paths.filter(p => p.v > 0);
    if (!paths.length) { ctx.font = '600 13px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.textAlign = 'center'; ctx.fillText(data.live ? T(`No traffic through this device under these filters in the last ${Math.round(data.window / 60)} min — Period shows the whole range`, `Немає трафіку через цей пристрій під ці фільтри за останні ${Math.round(data.window / 60)} хв — «За період» покаже весь діапазон`) : T('No traffic through this device for the selected filters', 'Немає трафіку через цей пристрій для вибраних фільтрів'), W / 2, H / 2); return; }
    const sideOf = i => { const r = roleOf(i); return r === 'wan' ? 'R' : r === 'local' ? 'C' : 'L'; };
    const enter = new Map(), leave = new Map(), tot = new Map();
    paths.forEach(p => { enter.set(p.in_if, (enter.get(p.in_if) || 0) + p.v); leave.set(p.out_if, (leave.get(p.out_if) || 0) + p.v);
      for (const i of [p.in_if, p.out_if]) tot.set(i, (tot.get(i) || 0) + p.v); });
    const ports = {L:[], R:[]}; [...tot.keys()].sort((a, b) => tot.get(b) - tot.get(a)).forEach(i => { const sd = sideOf(i); if (sd !== 'C') ports[sd].push(i); });
    const cardW = Math.min(196, Math.max(124, W * .15)), gap = Math.max(56, W * .08);
    const bx0 = cardW + gap, bx1 = W - cardW - gap, by0 = 44, by1 = H - 10, bw = bx1 - bx0, bh = by1 - by0;
    // the box
    ctx.fillStyle = 'rgba(30,60,140,.14)'; ctx.fill(rr(bx0, by0, bw, bh, 22)); ctx.strokeStyle = 'rgba(110,160,255,.4)'; ctx.lineWidth = 1.3; ctx.stroke(rr(bx0, by0, bw, bh, 22));
    ctx.textAlign = 'center'; ctx.font = '700 14px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(dev.name, (bx0 + bx1) / 2, 14);
    ctx.font = '500 11.5px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.fillText([dev.model, dev.ip].filter(Boolean).join(' · '), (bx0 + bx1) / 2, 31);
    // dots: evenly spread along each edge
    const dots = new Map();
    for (const side of ['L', 'R']) { const list = ports[side], n = list.length, step = bh / (n + 1);
      list.forEach((i, k) => dots.set(i, {i, side, x:side === 'L' ? bx0 : bx1, y:by0 + step * (k + 1)})); }
    const core = {x:(bx0 + bx1) / 2, y:by1 - Math.min(70, bh * .14), r:20};     // low, away from the port labels
    // line widths: 1.2 .. 10 px
    const vmax = Math.max(...paths.map(p => v(p.v)));
    const lw = x => 1.2 + 8.8 * v(x) / Math.max(1e-9, vmax);
    const colorOf = p => { if (state.ringColor === 'service') return keyColor((p.services || [])[0] || '?');
      const si = sideOf(p.in_if), so = sideOf(p.out_if); return si === 'C' || so === 'C' ? '#8A96B4' : si === 'L' && so === 'R' ? C.up : si === 'R' && so === 'L' ? C.down : si === 'L' ? C.int : C.ext; };
    // lines fan out a little next to the dot so parallel paths stay apart
    const fanIn = new Map(); paths.forEach(p => { for (const i of [p.in_if, p.out_if]) fanIn.set(i, (fanIn.get(i) || 0) + 1); });
    const fanUsed = new Map(), fan = i => { const n = fanIn.get(i) || 1, k = fanUsed.get(i) || 0; fanUsed.set(i, k + 1); const spread = Math.min(26, 5 * (n - 1)); return n === 1 ? 0 : -spread / 2 + spread * k / (n - 1); };
    const order = [...paths].sort((a, b) => b.v - a.v);
    const lines = [];
    for (const p of [...order].sort((a, b) => (dots.get(a.in_if)?.y ?? core.y) - (dots.get(b.in_if)?.y ?? core.y) || (dots.get(a.out_if)?.y ?? core.y) - (dots.get(b.out_if)?.y ?? core.y))) {
      const A = dots.get(p.in_if), B = dots.get(p.out_if), w = lw(p.v), path = new Path2D();
      if (A && B) {
        const ya = A.y + fan(A.i), yb = B.y + fan(B.i), xa = A.x + (A.side === 'L' ? 9 : -9), xb = B.x + (B.side === 'L' ? 9 : -9);
        path.moveTo(xa, ya);
        if (A.side === B.side) { const dirx = A.side === 'L' ? 1 : -1, depth = Math.min(bw * .4, 50 + Math.abs(yb - ya) * .6); path.bezierCurveTo(xa + dirx * depth, ya, xb + dirx * depth, yb, xb, yb); }
        else { const xm = (xa + xb) / 2; path.bezierCurveTo(xm, ya, xm, yb, xb, yb); }
      } else {
        const P = A || B; if (!P) continue; const yp = P.y + fan(P.i), xp = P.x + (P.side === 'L' ? 9 : -9);
        path.moveTo(xp, yp); path.bezierCurveTo((xp + core.x) / 2, yp, (xp + core.x) / 2, core.y, core.x + (P.side === 'L' ? -core.r : core.r), core.y);
      }
      lines.push({p, path, w, col:colorOf(p)});
    }
    const litPath = p => !hover || (hover.kind === 'path' ? hover.in_if === p.in_if && hover.out_if === p.out_if : hover.kind === 'port' ? hover.i === p.in_if || hover.i === p.out_if : hover.kind !== 'host' || hover.port === p.in_if || hover.port === p.out_if);
    for (const L of lines.sort((a, b) => b.w - a.w)) {
      const lit = litPath(L.p);
      ctx.strokeStyle = hexA(L.col, lit ? (hover ? .95 : .72) : .1); ctx.lineWidth = L.w; ctx.stroke(L.path);
      shapes.push({kind:'path', stroke:L.path, sw:Math.max(10, L.w + 6), in_if:L.p.in_if, out_if:L.p.out_if,
        tip:`<b>${esc(nameOf(L.p.in_if))} → ${esc(nameOf(L.p.out_if))}</b><br>${fmtV(L.p.v)} · ${T('hosts', 'хостів')}: ${L.p.hosts}${(L.p.services || []).length ? '<br>' + esc(L.p.services.map(dv).join(', ')) : ''}`});
    }
    // core
    if (paths.some(p => sideOf(p.in_if) === 'C' || sideOf(p.out_if) === 'C')) {
      const cp = new Path2D(); cp.arc(core.x, core.y, core.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(12,22,52,.96)'; ctx.fill(cp); ctx.strokeStyle = '#8A96B4'; ctx.lineWidth = 1.4; ctx.stroke(cp);
      ctx.textAlign = 'center'; ctx.font = '600 10.5px Manrope, sans-serif'; ctx.fillStyle = C.ink2; ctx.fillText(T('device itself', 'сам пристрій'), core.x, core.y + core.r + 11);
      const li = paths.find(p => sideOf(p.in_if) === 'C' || sideOf(p.out_if) === 'C'), idx = sideOf(li.in_if) === 'C' ? li.in_if : li.out_if;
      shapes.push({kind:'port', path:cp, i:idx, tip:`<b>${T('The device itself', 'Сам пристрій')}</b> (${idx})`});
    }
    // hosts outside, joined to their dot
    const hmax = Math.max(1e-9, ...[...data.inside, ...data.outside].map(h => v(h.v)));
    for (const side of ['L', 'R']) {
      const list = side === 'L' ? data.inside : data.outside, cards = [];
      for (const i of ports[side].slice().sort((a, b) => dots.get(a).y - dots.get(b).y)) {
        const own = list.filter(h => h.iface === i).sort((a, b) => b.v - a.v), shown = own.slice(0, side === 'L' ? 4 : 6);
        shown.forEach(h => cards.push({port:i, h, v:h.v}));
        const rest = Math.max(0, tot.get(i) - shown.reduce((a, h) => a + h.v, 0));
        if (own.length > shown.length && rest > tot.get(i) * .03) cards.push({port:i, other:true, v:rest});
      }
      if (!cards.length) continue;
      const n = cards.length, cg = 6, ch = Math.max(24, Math.min(44, (H - 12 - cg * (n - 1)) / n)), x = side === 'L' ? 0 : W - cardW;
      let y = Math.max(6, (H - n * ch - (n - 1) * cg) / 2);
      for (const c of cards) {
        const D = dots.get(c.port), w = 1.2 + 6.8 * v(c.v) / hmax, x0 = side === 'L' ? x + cardW : x, xd = D.x + (side === 'L' ? -9 : 9);
        const col = c.other ? C.other : side === 'L' ? C.int : C.ext, key = side + '|' + c.port + '|' + (c.other ? '*' : c.h.host);
        const path = new Path2D(); path.moveTo(x0, y + ch / 2); path.bezierCurveTo((x0 + xd) / 2, y + ch / 2, (x0 + xd) / 2, D.y, xd, D.y);
        const lit = !hover || (hover.kind === 'host' && hover.key === key) || (hover.kind === 'port' && hover.i === c.port) || (hover.kind === 'path' && (hover.in_if === c.port || hover.out_if === c.port));
        ctx.strokeStyle = hexA(col, lit ? .6 : .1); ctx.lineWidth = w; ctx.stroke(path);
        const box = rr(x + .5, y + .5, cardW - 1, ch - 1, 10);
        ctx.fillStyle = 'rgba(14,26,58,.82)'; ctx.fill(box); ctx.strokeStyle = hover && hover.key === key ? hexA(col, .9) : 'rgba(110,160,255,.28)'; ctx.lineWidth = 1; ctx.stroke(box);
        ctx.fillStyle = col; ctx.fill(rr(x + 6, y + 6, 4, ch - 12, 2));
        const l1 = c.other ? T('Others', 'Інші') : side === 'L' ? (c.h.name || c.h.host) : c.h.host;
        const l2 = c.other ? fmtV(c.v) : `${fmtV(c.v)} · ${side === 'L' ? (c.h.name ? c.h.host : nameOf(c.port)) : [dv(c.h.service), c.h.city || ccName(c.h.country)].filter(Boolean).join(' · ')}`;
        ctx.textAlign = 'left'; ctx.fillStyle = C.ink;
        if (ch >= 36) { ctx.fillText(clip(l1, '600 12px "JetBrains Mono", monospace', cardW - 26), x + 16, y + ch / 2 - 7); ctx.fillStyle = C.ink2; ctx.fillText(clip(l2, '500 11px Manrope, sans-serif', cardW - 26), x + 16, y + ch / 2 + 9); }
        else ctx.fillText(clip(l1, '600 11.5px "JetBrains Mono", monospace', cardW - 26), x + 16, y + ch / 2);
        if (!c.other) shapes.push({kind:'host', path:box, key, port:c.port, side, ip:c.h.host, tip:`<b>${esc(l1)}</b><br>${esc(c.h.host)} · ${esc(nameOf(c.port))}<br>↑ ${fmtV(c.h.up)} · ↓ ${fmtV(c.h.dn)}`});
        y += ch + cg;
      }
    }
    // dots and their labels (inside the box, next to the dot)
    for (const D of dots.values()) {
      const role = roleOf(D.i), col = role === 'wan' ? C.up : '#2F7BFF', on = hover && hover.kind === 'port' && hover.i === D.i;
      const dp = new Path2D(); dp.arc(D.x, D.y, on ? 9 : 7.5, 0, Math.PI * 2);
      ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = on ? 14 : 8; ctx.fill(dp); ctx.shadowBlur = 0;
      ctx.strokeStyle = 'rgba(8,16,40,.95)'; ctx.lineWidth = 2; ctx.stroke(dp);
      const l1 = nameOf(D.i), l2 = [addrOf(D.i), `↘ ${fmtV(enter.get(D.i) || 0)}  ↗ ${fmtV(leave.get(D.i) || 0)}`].filter(Boolean).join(' · ');
      ctx.font = '700 12px "JetBrains Mono", monospace'; const w1 = ctx.measureText(l1).width; ctx.font = '500 10.5px "JetBrains Mono", monospace'; const w2 = ctx.measureText(l2).width;
      const lwid = Math.max(w1, w2) + 14, lx = D.side === 'L' ? D.x + 16 : D.x - 16 - lwid, ly = D.y - 34;
      ctx.fillStyle = 'rgba(8,16,40,.88)'; ctx.fill(rr(lx, ly, lwid, 30, 8)); ctx.strokeStyle = hexA(col, on ? .9 : .45); ctx.lineWidth = 1; ctx.stroke(rr(lx, ly, lwid, 30, 8));
      ctx.textAlign = 'left'; ctx.font = '700 12px "JetBrains Mono", monospace'; ctx.fillStyle = C.ink; ctx.fillText(l1, lx + 7, ly + 9);
      ctx.font = '500 10.5px "JetBrains Mono", monospace'; ctx.fillStyle = C.ink2; ctx.fillText(l2, lx + 7, ly + 21);
      const hit = new Path2D(); hit.arc(D.x, D.y, 13, 0, Math.PI * 2); hit.addPath(rr(lx, ly, lwid, 30, 8));
      shapes.push({kind:'port', path:hit, i:D.i, tip:`<b>${esc(nameOf(D.i))}</b> (${D.i}) · ${role === 'wan' ? 'WAN' : 'LAN'}<br>${esc(addrOf(D.i))}<br>${T('enters the device', 'входить у пристрій')}: ${fmtV(enter.get(D.i) || 0)}<br>${T('leaves the device', 'виходить з пристрою')}: ${fmtV(leave.get(D.i) || 0)}`});
    }
  }
  // shapes are in CSS pixels and the context is scaled by dpr, so test device pixels; lines are hit by a wide stroke
  const pick = e => { const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    for (let i = shapes.length - 1; i >= 0; i--) { const sh = shapes[i];
      if (sh.path && ctx.isPointInPath(sh.path, x * dpr, y * dpr)) return {s:sh, x, y};
      if (sh.stroke) { ctx.lineWidth = sh.sw; if (ctx.isPointInStroke(sh.stroke, x * dpr, y * dpr)) return {s:sh, x, y}; } }
    return null; };
  const same = (a, b) => a === b || (a && b && a.kind === b.kind && a.key === b.key && a.i === b.i && a.in_if === b.in_if && a.out_if === b.out_if);
  cv.addEventListener('mousemove', e => { const h = pick(e), n = h ? h.s : null;
    if (!same(n, hover)) { hover = n; draw(); }
    if (h) { tip.hidden = false; tip.innerHTML = h.s.tip; tip.style.left = Math.min(W - 240, h.x + 14) + 'px'; tip.style.top = (h.y + 14) + 'px'; cv.style.cursor = 'pointer'; } else { tip.hidden = true; cv.style.cursor = ''; } });
  cv.addEventListener('mouseleave', () => { hover = null; tip.hidden = true; draw(); });
  cv.addEventListener('click', e => { const h = pick(e); if (h && opts.onPick) opts.onPick(h.s); });
}
// ===================== through the device: input interface -> device -> output interface =====================
const ROLE_COLOR = {wan:'#FF9F43', local:'#6E7FA6'};
const IFPAL = ['#2F7BFF', '#27D3F5', '#8B5CFF', '#FF4FA0', '#2EE59D', '#FFD166', '#5AC8FA', '#F0508C'];
// the device this page shows: the global device filter, else the one picked here, else the busiest
function pathDevice(){
  const df = state.filters.find(f => f.k === 'device' && !f.neg);
  return df ? df.v : state.pathDev || (META.devices[0] || {}).ip;
}
function vPaths(){
  const v = document.getElementById('view'), live = !!state.pathsLive && !isCustom();
  v.innerHTML = `<div class="grid">
    <section class="glass panel s9">${ph('nodes', T('Traffic through the device', 'Трафік через пристрій'), T('input interface → device → output interface · width = volume · click a ribbon or an interface to filter', 'вхідний інтерфейс → пристрій → вихідний інтерфейс · ширина = обсяг · клік по стрічці чи інтерфейсу — фільтр'),
      `<span id="pDevSeg"></span>` + seg('pMetricSeg', [['bytes', T('Bytes', 'Байти')], ['packets', T('Packets', 'Пакети')], ['flows', 'Flows']], state.metric) + seg('pColorSeg', [['dir', T('Direction', 'Напрямок')], ['service', T('Service', 'Сервіс')]], state.ringColor || 'dir') + seg('pScaleSeg', [['sqrt', T('Compressed', 'Стиснений'), T('Width ∝ √volume — small paths stay visible next to big ones', 'Ширина ∝ √обсягу — дрібні шляхи помітні поруч із великими')], ['lin', T('Linear', 'Лінійний')]], state.scale) + seg('pLiveSeg', [['live', T('Live', 'Наживо')], ['period', T('Period', 'За період')]], live ? 'live' : 'period'), true)}
      <div class="legend" id="pLegend" style="margin:-6px 0 10px"></div>
      <div class="river devmap" id="cPaths"></div>
      <p class="note">${T('All traffic of the device regardless of the Internet / Internal selector. Wi-Fi SSID (VAP) interfaces of FortiGate are not sampled: traffic between two SSIDs does not appear.', 'Увесь трафік пристрою незалежно від перемикача «Інтернет / Внутрішній». Wi-Fi-інтерфейси (VAP) FortiGate не експортують NetFlow: трафік між двома SSID тут не видно.')}</p></section>
    <div class="col s3">
      <div id="pKpi" class="col"></div>
      <section class="glass panel">${ph('search', T('Path', 'Шлях'), T('the selected input → output', 'вибраний вхід → вихід'))}<div id="pInsp"></div></section>
    </div>
    <section class="glass panel s7">${ph('conv', T('Paths', 'Шляхи'), T('input → output interface · click to filter', 'вхідний → вихідний інтерфейс · клік — фільтр'))}<div id="pTable" class="loading"></div></section>
    <section class="glass panel s5">${ph('ip', T('Interfaces', 'Інтерфейси'), T('traffic entering and leaving each interface', 'трафік, що входить і виходить через кожен інтерфейс'))}<div id="pIfs" class="loading"></div></section></div>`;
  wireSeg('pMetricSeg', m => { if (m === state.metric) return; state.metric = m; render(); });
  wireSeg('pColorSeg', m => { if (m === (state.ringColor || 'dir')) return; state.ringColor = m; render(); });
  wireSeg('pScaleSeg', m => { if (m === state.scale) return; state.scale = m; render(); });
  lockLive('pLiveSeg');
  wireSeg('pLiveSeg', m => { const l = m === 'live'; if (l === !!state.pathsLive) return; state.pathsLive = l; render(); });
  const seq = renderSeq;
  (async () => {
    const devs = (await api('devices')).devices; if (seq !== renderSeq) return;
    const df = state.filters.find(f => f.k === 'device' && !f.neg);
    if (!df && !devs.some(d => d.ip === state.pathDev)) state.pathDev = ([...devs].sort((a, b) => b.rps - a.rps)[0] || {}).ip;
    const ip = pathDevice(), dev = devs.find(d => d.ip === ip);
    // device switcher (only when the global device filter does not decide it)
    // device picker: a list (there may be many exporters); with a device filter set it changes that filter
    const opts = [...devs].sort((a, b) => a.name.localeCompare(b.name)).map(d => `<option value="${esc(d.ip)}"${d.ip === ip ? ' selected' : ''}>${esc(d.name)}${d.vendor ? ' · ' + esc(d.vendor) : ''} (${esc(d.ip)})</option>`).join('');
    fill('pDevSeg', `<label class="sel glass" title="${T('Device', 'Пристрій')}">${icon(ICO.dev, 16)}<select id="pDevSel" aria-label="${T('Device', 'Пристрій')}">${opts}</select></label>`);
    const ds = document.getElementById('pDevSel');
    if (ds) ds.onchange = () => { state.pathDev = ds.value;
      state.filters = state.filters.filter(f => !['in_if', 'out_if', 'iface'].includes(f.k));
      if (df) { state.filters = state.filters.filter(f => f.k !== 'device'); putFilter({k:'device', v:ds.value, neg:false}); }
      render(); };
    if (!dev) { fill('cPaths', `<div class="empty">${T('No device has sent data yet', 'Ще жоден пристрій не надіслав дані')}</div>`); return; }
    const ifs = new Map(dev.interfaces.map(i => [i.index, i]));
    const extra = df ? [] : [{k:'device', v:ip}];
    const load = () => api('paths', {t:'all', metric:state.metric, live:live ? 1 : 0, win:120}, extra);
    const color = new Map();
    // a fixed colour per interface (role colour for WAN / the device itself, else by its place among the device's interfaces)
    const plain = [...ifs.values()].filter(i => !ROLE_COLOR[i.role]).map(i => i.index).sort((a, b) => a - b);
    const ifColor = idx => { if (!color.has(idx)) { const r = (ifs.get(idx) || {}).role; const pos = plain.indexOf(idx);
      color.set(idx, ROLE_COLOR[r] || IFPAL[(pos >= 0 ? pos : plain.length + color.size) % IFPAL.length]); } return color.get(idx); };
    const ifName = idx => { const i = ifs.get(idx); return i ? (i.custom_name || i.name) : (idx === 0 ? 'local' : `if ${idx}`); };
    // an address or network that identifies the interface: entered by hand, else what the flows show
    const ifAddr = idx => { const i = ifs.get(idx); return i ? (ifAddrs(i)[0] || '') : ''; };
    const ifNamed = idx => { const i = ifs.get(idx); return !!(i && (i.custom_name || i.snmp_name)) || idx === 0; };
    const ifRole = idx => { const r = (ifs.get(idx) || {}).role || 'lan'; return r === 'wan' ? 'WAN' : r === 'local' ? T('device itself', 'сам пристрій') : 'LAN'; };
    const unit = state.metric === 'bytes' ? fmtB : fmtN;
    const draw = d => {
      const rows = d.rows.filter(r => r.v > 0), total = rows.reduce((a, r) => a + r.v, 0);
      if (!rows.length) { ['pKpi', 'pTable', 'pIfs'].forEach(id => fill(id, '')); return; }
      [...new Set(rows.flatMap(r => [r.in_if, r.out_if]))].sort((a, b) => a - b).forEach(ifColor);
      const ins = new Map(), outs = new Map();
      rows.forEach(r => { ins.set(r.in_if, (ins.get(r.in_if) || 0) + r.v); outs.set(r.out_if, (outs.get(r.out_if) || 0) + r.v); });
      if (state.ringColor === 'service') {
        const svcs = new Map(); rows.forEach(r => { const k = (r.services || [])[0]; if (k) svcs.set(k, (svcs.get(k) || 0) + r.v); });
        fill('pLegend', [...svcs].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k]) => `<span><i class="bar" style="background:${keyColor(k)}"></i>${esc(dv(k))}</span>`).join('')
          + `<span class="nat">${T('colour = main service of the path', 'колір = головний сервіс шляху')}</span>`);
      } else
      fill('pLegend', `<span><i style="background:${C.int}"></i>${T('inside hosts · inside interfaces', 'локальні хости · локальні інтерфейси')}</span><span><i class="bar" style="background:${C.up}"></i>${T('to the internet', 'в інтернет')}</span><span><i class="bar" style="background:${C.down}"></i>${T('from the internet', 'з інтернету')}</span><span><i class="bar" style="background:${C.int}"></i>${T('between inside networks (arc)', 'між локальними мережами (дуга)')}</span><span><i class="bar" style="background:#6E7FA6"></i>${T('to / from the device itself', 'до / від самого пристрою')}</span><span style="margin-left:auto"><i style="background:${C.ext}"></i>${T('WAN · internet hosts', 'WAN · хости в інтернеті')}</span>` + (d.live && d.window_end ? `<span class="mono">${T(`2-min window to ${hms(d.window_end)}`, `вікно 2 хв до ${hms(d.window_end)}`)}</span>` : `<span class="mono">${rangeLabel()}</span>`));
      // KPIs, tables
      const by = f => rows.reduce((a, r) => a + (f(r) ? r.b : 0), 0), totB = by(() => true);
      const isWan = i => (ifs.get(i) || {}).role === 'wan', isLocal = i => (ifs.get(i) || {}).role === 'local';
      const kc = (ic, k, val, sub) => `<section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span class="v">${val}</span>${sub ? `<span class="nat" style="grid-column:2">${sub}</span>` : ''}</section>`;
      fill('pKpi', kc('pulse', T('Through the device', 'Через пристрій'), fmtB(totB), `${rows.length} ${T('paths', 'шляхів')}`)
        + kc('globe', T('Internet', 'Інтернет'), fmtB(by(r => isWan(r.in_if) || isWan(r.out_if))), `${pct(by(r => isWan(r.in_if) || isWan(r.out_if)), totB)}`)
        + kc('nodes', T('Between inside networks', 'Між внутрішніми мережами'), fmtB(by(r => !isWan(r.in_if) && !isWan(r.out_if) && !isLocal(r.in_if) && !isLocal(r.out_if))), '')
        + kc('dev', T('To / from the device itself', 'До / від самого пристрою'), fmtB(by(r => isLocal(r.in_if) || isLocal(r.out_if))), ''));
      const pill = i => `<span class="idot" style="background:${ifColor(i)};box-shadow:0 0 8px ${ifColor(i)}"></span><b class="mono">${esc(ifName(i))}</b>${ifNamed(i) ? ` <span class="nat">${i}</span>` : ''}`;
      const max = rows.length ? rows[0].v : 1;
      const tb = fill('pTable', `<div class="tw"><table class="compact"><thead><tr><th>${T('Input', 'Вхід')}</th><th></th><th>${T('Output', 'Вихід')}</th><th style="width:26%">${T('Volume', 'Обсяг')}</th><th class="num">%</th><th class="num">Flows</th><th class="num">${T('Hosts', 'Хостів')}</th><th>${T('Main services', 'Головні сервіси')}</th></tr></thead><tbody>
        ${rows.slice(0, 15).map(r => `<tr class="click" data-path="${r.in_if}|${r.out_if}"><td>${pill(r.in_if)}</td><td class="nat">→</td><td>${pill(r.out_if)}</td>
          <td><b class="mono">${unit(r.v)}</b><div class="vbar"><i style="width:${(100 * r.v / max).toFixed(1)}%;background:linear-gradient(90deg,${ifColor(r.in_if)},${ifColor(r.out_if)})"></i></div></td>
          <td class="num mono">${pct(r.v, total)}</td><td class="num mono">${fmtN(r.fl)}</td><td class="num mono">${r.hosts}</td><td class="nat">${esc(r.services.map(dv).join(', '))}</td></tr>`).join('')}</tbody></table></div>`);
      if (tb) { tb.classList.remove('loading'); tb.querySelectorAll('tr[data-path]').forEach(tr => tr.onclick = () => { const [a, b] = tr.dataset.path.split('|');
        putFilter({k:'in_if', v:a, neg:false}); putFilter({k:'out_if', v:b, neg:false}); if (!df) putFilter({k:'device', v:ip, neg:false}); render(); }); }
      const allIf = [...new Set([...ins.keys(), ...outs.keys()])].sort((a, b) => (outs.get(b) || 0) + (ins.get(b) || 0) - (outs.get(a) || 0) - (ins.get(a) || 0));
      const ib = fill('pIfs', `<div class="tw"><table class="compact"><thead><tr><th>${T('Interface', 'Інтерфейс')}</th><th>${T('Role', 'Роль')}</th><th class="num">${T('Entering', 'Входить')}</th><th class="num">${T('Leaving', 'Виходить')}</th><th>${T('Addresses', 'Адреси')}</th></tr></thead><tbody>
        ${allIf.map(i => { const x = ifs.get(i) || {addrs:[], seen_addrs:[]};
          return `<tr><td>${pill(i)}</td><td><span class="tag">${ifRole(i)}</span></td><td class="num mono">${unit(ins.get(i) || 0)}</td><td class="num mono">${unit(outs.get(i) || 0)}</td><td class="nat mono">${esc(ifAddrs(x).slice(0, 2).join(', ') || '—')}</td></tr>`; }).join('')}</tbody></table></div>`);
      if (ib) ib.classList.remove('loading');
    };
    // inspector of the selected path (interface filters)
    const fi = state.filters.find(f => f.k === 'in_if' && !f.neg), fo = state.filters.find(f => f.k === 'out_if' && !f.neg);
    if (fi || fo) {
      const [hosts, svc, dst] = await Promise.all([api('top', {dim:'int_ip', limit:5, t:'all'}, extra), api('top', {dim:'service', limit:5, t:'all'}, extra), api('top', {dim:'ext_ip', limit:5, t:'all'}, extra)]);
      if (seq !== renderSeq) return;
      const list = (rows, name) => rows.map(r => `<div class="brow" style="cursor:default"><span class="n">${esc(name(r))}</span><span class="t">${fmtB(tot(r))}</span><span class="p"></span></div>`).join('') || '—';
      fill('pInsp', `<div class="insp"><div class="who"><b>${esc(fi ? ifName(+fi.v) : '*')} → ${esc(fo ? ifName(+fo.v) : '*')}</b><span>${esc(dev.name)}</span></div>
        <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">${T('Hosts', 'Хости')}</h4><div class="blist">${list(hosts.rows, r => r.name || r.k)}</div></div>
        <div><h4 style="margin:6px 0;font-size:12.5px;color:var(--ink2)">${T('Services', 'Сервіси')}</h4><div class="blist">${list(svc.rows, r => dv(r.k))}</div></div>
        <div><h4 style="margin:6px 0;font-size:12.5px;color:var(--ink2)">${T('Destinations', 'Призначення')}</h4><div class="blist">${list(dst.rows, r => r.k)}</div></div></div>`);
    } else fill('pInsp', `<p class="note" style="margin:0">${T('Click a ribbon to see who and what uses that path. The path then filters every page.', 'Клікніть стрічку, щоб побачити, хто і що йде цим шляхом. Шлях стане фільтром для всіх сторінок.')}</p>`);
    const pickMap = sh => {
      if (sh.kind === 'path') { putFilter({k:'in_if', v:String(sh.in_if), neg:false}); putFilter({k:'out_if', v:String(sh.out_if), neg:false}); }
      else if (sh.kind === 'port') putFilter({k:'iface', v:String(sh.i), neg:false});
      else if (sh.kind === 'host') putFilter({k:sh.side === 'L' ? 'ip' : 'dst', v:sh.ip, neg:false});
      if (!df) putFilter({k:'device', v:ip, neg:false});
      render(); };
    const mapEl = document.getElementById('cPaths');
    if (mapEl) createDevMap(mapEl, {ifs, dev, refreshMs:live ? 10000 : 0, onPick:pickMap,
      fetchData:() => api('devmap', {t:'all', metric:state.metric, live:live ? 1 : 0, win:120, top:6}, extra)});
    try { draw(await load()); } catch (e) { fill('pTable', errBox(e)); }
    if (live) every(10000, () => load().then(d => { if (seq === renderSeq) draw(d); }).catch(() => {}));
  })().catch(e => fill('cPaths', errBox(e)));
}
// ===================== path analysis: layer-3 neighbours of a device and the path of traffic across devices =====================
const LINK_STATE = {
  observed:[T('Observed', 'Видно'), T('traffic recorded by both ends', 'трафік записали обидва кінці')],
  gap:[T('Gap', 'Розрив'), T('one end sent much more than the other received', 'один кінець відправив значно більше, ніж інший отримав')],
  unobserved:[T('No observation', 'Не спостерігається'), T('the other end sends no NetFlow', 'інший кінець не надсилає NetFlow')],
  one_sided:[T('One side', 'З одного боку'), T('the interface of the other end towards this one is not known', 'інтерфейс іншого кінця в цей бік невідомий')],
  adjacent:[T('No traffic', 'Без трафіку'), T('neighbours by addressing, no traffic in the period', 'сусіди за адресацією, трафіку за період немає')]};
const HOP_STATE = {observed:T('recorded', 'записав'), gap:T('recorded nothing — gap', 'нічого не записав — розрив'), unobserved:T('sends no NetFlow', 'не надсилає NetFlow'),
  internet:T('the internet', 'інтернет'), branch:T('on another exit', 'на іншому виході'), unplaced:T('recorded it, place on the path unknown', 'записав, місце на шляху невідоме')};
const RED = '#FF5C7A';
const devIcon = n => n.ip === 'internet' ? ICO.globe : DEV_ICON;
function createTopoMap(host, opts){
  host.innerHTML = '<div class="netin"><canvas></canvas><div class="rtip" hidden></div></div>';
  const box = host.firstChild, cv = box.querySelector('canvas'), tip = box.querySelector('.rtip'), ctx = cv.getContext('2d');
  let W = 0, H = 0, dpr = 1, data = null, hover = null, shapes = [], centred = null, GAP = 184;
  const CW = 136, CH = 74;                // card size; GAP: room between columns for the interface labels
  const CLW = 210, CLH = 72, UP = 84;     // the internet cloud on top; UP: room under it for the WAN ribbons and their labels
  function size(){ const r = host.getBoundingClientRect(); H = r.height; dpr = Math.min(2, devicePixelRatio || 1); draw(); }
  const ro = new ResizeObserver(size); ro.observe(host); onCleanup(() => ro.disconnect());
  const rr = (x, y, w, h, r) => { const p = new Path2D(); p.moveTo(x + r, y); p.arcTo(x + w, y, x + w, y + h, r); p.arcTo(x + w, y + h, x, y + h, r); p.arcTo(x, y + h, x, y, r); p.arcTo(x, y, x + w, y, r); p.closePath(); return p; };
  const clip = (str, font, max) => { ctx.font = font; str = String(str || ''); if (ctx.measureText(str).width <= max) return str; while (str.length > 2 && ctx.measureText(str + '…').width > max) str = str.slice(0, -1); return str + '…'; };
  const vol = l => l.a_out + l.a_in + l.b_out + l.b_in;
  // columns: the Point of View in the middle, the busiest neighbours to the right, the rest to the left; a device
  // further away keeps the side of the one it is reached through. One internet cloud above them all: every device's
  // WAN links go up into it.
  function layout(){
    const pov = data.pov, adj = new Map(), hop = new Map(data.nodes.map(n => [n.ip, n.hop]));
    data.links.forEach(l => { if (l.b === 'internet') return; for (const [a, b] of [[l.a, l.b], [l.b, l.a]]) { if (!adj.has(a)) adj.set(a, []); adj.get(a).push({n:b, l}); } });
    const col = new Map([[pov, 0]]), parent = new Map(), seen = new Set([pov]);
    let right = 0, left = 0;
    const first = (adj.get(pov) || []).sort((x, y) => vol(y.l) - vol(x.l));
    for (const x of first) { if (seen.has(x.n)) continue; seen.add(x.n); const s = right <= left ? 1 : -1; s > 0 ? right++ : left++; col.set(x.n, s); parent.set(x.n, pov); }
    let frontier = first.map(x => x.n);
    while (frontier.length) { const next = [];
      for (const p of frontier) for (const x of (adj.get(p) || []).sort((u, v) => vol(v.l) - vol(u.l))) if (!seen.has(x.n) && hop.has(x.n)) {
        seen.add(x.n); col.set(x.n, col.get(p) + Math.sign(col.get(p))); parent.set(x.n, p); next.push(x.n); }
      frontier = next; }
    const cols = [...new Set(col.values())].sort((a, b) => a - b), lo = cols[0], hi = cols[cols.length - 1];
    // the room between columns shrinks to 120 px before the map scrolls sideways
    const avail = host.clientWidth;
    GAP = hi === lo ? 184 : Math.max(120, Math.min(220, (avail - 28 - (hi - lo + 1) * CW) / (hi - lo)));
    W = Math.max(avail, (hi - lo + 1) * CW + (hi - lo) * GAP + 28, CLW + 28);
    const x0 = 14 + CW / 2, x1 = W - 14 - CW / 2, xs = c => hi === lo ? W / 2 : x0 + (x1 - x0) * (c - lo) / (hi - lo);
    const wan = data.links.filter(l => l.b === 'internet' && col.has(l.a));
    const top = wan.length ? 12 + CLH + UP : 12;            // devices start under the cloud
    const pos = new Map();
    // the middle column first, then outwards: each column ordered by its parents' height, then centred on them
    for (const c of [...cols].sort((a, b) => Math.abs(a) - Math.abs(b) || b - a)) {
      const list = [...col.keys()].filter(n => col.get(n) === c).sort((a, b) => ((pos.get(parent.get(a)) || {}).y || 0) - ((pos.get(parent.get(b)) || {}).y || 0));
      const room = H - top - 12, total = CH * list.length, gap = Math.min(56, Math.max(8, (room - total) / Math.max(1, list.length)));
      let y = top + Math.max(0, (room - total - gap * (list.length - 1)) / 2);
      const ys = list.map(() => { const m = y + CH / 2; y += CH + gap; return m; });
      if (c !== 0 && list.length) {
        const want = list.reduce((s, n) => s + ((pos.get(parent.get(n)) || {y:(top + H) / 2}).y), 0) / list.length, cur = ys.reduce((s, v) => s + v, 0) / ys.length;
        const d = Math.max(top + CH / 2 - ys[0], Math.min(H - 12 - CH / 2 - ys[ys.length - 1], want - cur));
        ys.forEach((v, k) => ys[k] = v + d);
      }
      list.forEach((n, k) => pos.set(n, {x:xs(c), y:ys[k], w:CW, h:CH, c}));
    }
    // the cloud over the devices that reach the internet
    const wx = wan.map(l => pos.get(l.a).x), cx = wx.length ? Math.max(14 + CLW / 2, Math.min(W - 14 - CLW / 2, (Math.min(...wx) + Math.max(...wx)) / 2)) : W / 2;
    return {pos, cloud:wan.length ? {x:cx, y:12 + CLH / 2, w:CLW, h:CLH} : null};
  }
  // a cloud: flat bottom, bumps on top
  const cloudPath = ({x, y, w, h}) => { const x0 = x - w / 2, y0 = y - h / 2, y1 = y + h / 2, p = new Path2D();
    p.moveTo(x0 + .2 * w, y1); p.lineTo(x0 + .8 * w, y1);
    p.bezierCurveTo(x0 + 1.04 * w, y1, x0 + 1.04 * w, y0 + .42 * h, x0 + .83 * w, y0 + .4 * h);
    p.bezierCurveTo(x0 + .86 * w, y0 - .02 * h, x0 + .58 * w, y0 - .12 * h, x0 + .5 * w, y0 + .16 * h);
    p.bezierCurveTo(x0 + .4 * w, y0 - .08 * h, x0 + .14 * w, y0 + .02 * h, x0 + .19 * w, y0 + .38 * h);
    p.bezierCurveTo(x0 - .04 * w, y0 + .38 * h, x0 - .04 * w, y1, x0 + .2 * w, y1); p.closePath(); return p; };
  function draw(){
    if (!H) return;
    if (!data) { W = host.clientWidth; return; }
    const {pos, cloud} = data.nodes.length ? layout() : {pos:new Map(), cloud:null};
    if (!data.nodes.length) W = host.clientWidth;
    box.style.width = W + 'px'; cv.width = W * dpr; cv.height = H * dpr;
    if (centred !== data.pov && pos.has(data.pov)) { centred = data.pov; host.scrollLeft = Math.max(0, pos.get(data.pov).x - host.clientWidth / 2); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H); shapes = [];
    ctx.textBaseline = 'middle'; ctx.lineCap = 'round';
    if (!data.nodes.length) { ctx.font = '600 13px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.textAlign = 'center'; ctx.fillText(T('No device has sent data yet', 'Ще жоден пристрій не надіслав дані'), W / 2, H / 2); return; }
    const node = new Map(data.nodes.map(n => [n.ip, n])), onPath = opts.pathSet ? opts.pathSet() : null;
    const v = x => state.scale === 'lin' ? x : Math.sqrt(x);
    const vmax = Math.max(1e-9, ...data.links.map(l => v(Math.max(l.a_out, l.b_in) + Math.max(l.b_out, l.a_in))));
    const lw = x => x > 0 ? 2 + 14 * v(x) / vmax : 0;
    const nm = d => esc(d === 'internet' ? T('Internet', 'Інтернет') : (node.get(d) || {}).name || d);
    // a ribbon of three strands (from the internet, to the internet, internal) along a path, as one end measured it
    const ribbon = (curve, l, w, horizontal) => {
      const dirs = l.a_dir.up + l.a_dir.down + l.a_dir.internal >= ((l.b_dir || {}).up || 0) + ((l.b_dir || {}).down || 0) + ((l.b_dir || {}).internal || 0) ? l.a_dir : l.b_dir;
      const parts = [[dirs.down || 0, C.down], [dirs.up || 0, C.up], [dirs.internal || 0, C.int]].filter(x => x[0] > 0), sum = parts.reduce((s, x) => s + x[0], 0) || 1;
      let off = -w / 2;
      for (const [val, colr] of parts) { const sw = Math.max(1.2, w * val / sum);
        ctx.strokeStyle = hexA(colr, hover && hover.l === l ? 1 : .82); ctx.lineWidth = sw; ctx.shadowColor = hexA(colr, .55); ctx.shadowBlur = 10; ctx.stroke(curve(off + sw / 2)); off += sw; }
      ctx.shadowBlur = 0;
    };
    const pill = (text, x, y, colr) => { ctx.font = '700 11px Manrope, sans-serif'; const tw = ctx.measureText(text).width + 14;
      ctx.fillStyle = 'rgba(8,16,40,.92)'; ctx.fill(rr(x - tw / 2, y - 9, tw, 18, 9)); ctx.strokeStyle = hexA(colr, .6); ctx.lineWidth = 1; ctx.stroke(rr(x - tw / 2, y - 9, tw, 18, 9));
      ctx.fillStyle = colr; ctx.textAlign = 'center'; ctx.fillText(text, x, y + .5); };
    const stateLook = l => l.state === 'adjacent' ? ['rgba(170,190,230,.55)', T('no traffic', 'без трафіку')] : l.state === 'gap' || l.state === 'unobserved' ? [RED, '⨯ ' + LINK_STATE[l.state][0]] : null;
    const tipOf = l => `<b>${nm(l.a)} ${esc(l.a_name)} ↔ ${nm(l.b)} ${esc(l.b_name)}</b>${l.net ? ` <span class="nat">${esc(l.net)}</span>` : ''}<div style="color:${l.state === 'observed' ? C.ext : l.state === 'adjacent' || l.state === 'one_sided' ? C.ink2 : RED}">${LINK_STATE[l.state][0]} — ${LINK_STATE[l.state][1]}</div>`
      + (l.b === 'internet' ? `<div>${T('to the internet', 'в інтернет')}: <b class="mono">${fmtB(l.a_out)}</b> · ${T('from it', 'з нього')}: <b class="mono">${fmtB(l.a_in)}</b></div>`
        : [[l.a, l.b, l.a_out, l.b_in], [l.b, l.a, l.b_out, l.a_in]].map(([f, t, s, g]) => `<div>${nm(f)} → ${nm(t)}: <b class="mono">${fmtB(s)}</b> ${T('sent', 'відправив')} · <b class="mono">${fmtB(g)}</b> ${T('received', 'отримав')}</div>`).join(''));
    // where each link meets a card: links on the same side of a card are spread over its height, ordered by the far end
    const ends = new Map(), anchor = new Map();
    for (const l of data.links) { const A = pos.get(l.a), B = pos.get(l.b); if (!A || !B) continue;
      for (const [me, other, P, Q] of [[l.a, l.b, A, B], [l.b, l.a, B, A]]) { const k = me + (Q.x > P.x ? '>R' : '>L'); if (!ends.has(k)) ends.set(k, []); ends.get(k).push({l, me, y:Q.y}); } }
    for (const list of ends.values()) { list.sort((a, b) => a.y - b.y); const n = list.length, spread = Math.min(CH - 28, 16 * (n - 1));
      list.forEach((e, k) => anchor.set(e.l, {...anchor.get(e.l), [e.me === e.l.a ? 'a' : 'b']:{dy:n === 1 ? 0 : -spread / 2 + spread * k / (n - 1), first:k === 0, last:k === n - 1, n}})); }
    // the WAN ribbons: spread along the card top (several WANs) and along the cloud bottom (ordered by device)
    const up = new Map();
    if (cloud) {
      const wl = data.links.filter(l => l.b === 'internet' && pos.has(l.a)), per = new Map();
      wl.forEach(l => { if (!per.has(l.a)) per.set(l.a, []); per.get(l.a).push(l); });
      for (const list of per.values()) list.forEach((l, k) => up.set(l, {dx:list.length === 1 ? 0 : -24 + 48 * k / (list.length - 1)}));
      const order = [...wl].sort((a, b) => pos.get(a.a).x + up.get(a).dx - pos.get(b.a).x - up.get(b).dx), span = Math.min(cloud.w * .5, 22 * (order.length - 1));
      order.forEach((l, k) => { up.get(l).cx = cloud.x + (order.length === 1 ? 0 : -span / 2 + span * k / (order.length - 1)); });
    }
    const labels = [];
    for (const l of data.links) {
      const A = pos.get(l.a), B = pos.get(l.b);
      const dim = onPath && !(onPath.has(l.a) && onPath.has(l.b));    // a WAN ribbon stays lit only on a path to / from the internet
      const w = lw(Math.max(l.a_out, l.b_in) + Math.max(l.b_out, l.a_in)), look = stateLook(l);
      ctx.globalAlpha = dim ? .15 : 1;
      if (l.b === 'internet') {
        // up from the top of the card into the cloud; the WAN interface (name over address) beside the ribbon
        const e = up.get(l); if (!A || !e) { ctx.globalAlpha = 1; continue; }
        const rw = Math.min(w, 14), xd = A.x + e.dx, yd = A.y - A.h / 2, xc = e.cx, yc = cloud.y + cloud.h / 2 - 4, ym = (yd + yc) / 2;
        const curve = off => { const p = new Path2D(); p.moveTo(xd + off, yd); p.bezierCurveTo(xd + off, ym, xc + off, ym, xc + off, yc); return p; };
        if (w && l.state !== 'adjacent') ribbon(curve, l, rw, false);
        if (look) { ctx.setLineDash([5, 5]); ctx.strokeStyle = look[0]; ctx.lineWidth = 1.6; ctx.stroke(curve(w ? rw / 2 + 4 : 0)); ctx.setLineDash([]); }
        const inward = xc >= xd;                  // the label on the cloud's side of the ribbon: it stays inside the map
        labels.push({parts:[l.a_name, l.a_addr], x:inward ? xd + rw / 2 + 8 : xd - rw / 2 - 8, top:yd - 36, align:inward ? 'left' : 'right', room:GAP / 2 + CW / 2 - 12, dim});
        ctx.globalAlpha = 1;
        const hit = new Path2D(); hit.moveTo(xd, yd); hit.bezierCurveTo(xd, ym, xc, ym, xc, yc); shapes.push({stroke:hit, sw:Math.max(12, rw + 6), l, tip:tipOf(l)});
        continue;
      }
      if (!A || !B) { ctx.globalAlpha = 1; continue; }
      const L = A.x <= B.x ? A : B, R = L === A ? B : A, flip = L !== A, an = anchor.get(l) || {}, ea = (flip ? an.b : an.a) || {dy:0, n:1}, eb = (flip ? an.a : an.b) || {dy:0, n:1};
      const xa = L.x + L.w / 2, xb = R.x - R.w / 2, ya = L.y + ea.dy, yb = R.y + eb.dy, xm = (xa + xb) / 2;
      const curve = off => { const p = new Path2D(); p.moveTo(xa, ya + off); p.bezierCurveTo(xm, ya + off, xm, yb + off, xb, yb + off); return p; };
      if (w && l.state !== 'adjacent') ribbon(curve, l, w, true);
      if (look) { ctx.setLineDash([5, 5]); ctx.strokeStyle = look[0]; ctx.lineWidth = 1.6; ctx.stroke(curve(w ? w / 2 + 4 : 0)); ctx.setLineDash([]); }
      // interface · address at each end, on the side the ribbon bends away from (two lines when one does not fit)
      const la = flip ? [l.b_name, l.b_addr] : [l.a_name, l.a_addr], lb = flip ? [l.a_name, l.a_addr] : [l.b_name, l.b_addr], room = xb - xa - 14;
      // the outer links of a card side keep their labels outside; a lone link: the side its ribbon bends away from
      const sideOf = (e, bendsUp) => e.n > 1 ? (e.first ? -1 : e.last ? 1 : -1) : bendsUp ? 1 : -1;
      labels.push({parts:la, x:xa + 7, y:ya, align:'left', side:sideOf(ea, yb < ya - 2), w, room, dim});
      if (l.b !== 'internet') labels.push({parts:lb, x:xb - 7, y:yb, align:'right', side:eb.n > 1 ? sideOf(eb, false) : (ya > yb + 2 ? -1 : 1), w, room, dim});
      if (look) pill(look[1], xm, (ya + yb) / 2, look[0]);
      ctx.globalAlpha = 1;
      const hit = new Path2D(); hit.moveTo(xa, ya); hit.bezierCurveTo(xm, ya, xm, yb, xb, yb);
      shapes.push({stroke:hit, sw:Math.max(12, w + 6), l, tip:tipOf(l)});
    }
    // interface name over its address (as on Through device), on a dark plate
    const NAME_F = '700 11px JetBrains Mono, monospace', ADDR_F = '500 10px JetBrains Mono, monospace';
    for (const lb of labels) {
      const [name, addr] = lb.parts; if (!name && !addr) continue;
      const rows = [[clip(name || '', NAME_F, lb.room), NAME_F, C.ink], [clip(addr || '', ADDR_F, lb.room), ADDR_F, C.ink2]].filter(r => r[0]);
      const tw = Math.max(...rows.map(([t, f]) => { ctx.font = f; return ctx.measureText(t).width; })), th = 13 * rows.length;
      const top = lb.top != null ? lb.top : lb.side < 0 ? lb.y - lb.w / 2 - 6 - th : lb.y + lb.w / 2 + 6, x0 = lb.align === 'left' ? lb.x - 4 : lb.x - tw - 4;
      ctx.globalAlpha = lb.dim ? .2 : 1; ctx.fillStyle = 'rgba(9,18,44,.82)'; ctx.fill(rr(x0, top - 2, tw + 8, th + 4, 5));
      ctx.textAlign = lb.align; rows.forEach(([t, f, col], k) => { ctx.font = f; ctx.fillStyle = col; ctx.fillText(t, lb.x, top + 6.5 + 13 * k); }); ctx.globalAlpha = 1;
    }
    if (cloud) {
      const cp = cloudPath(cloud), wl = data.links.filter(l => l.b === 'internet' && pos.has(l.a));
      const dim = onPath && !onPath.has('internet'), on = hover && hover.cloud;
      ctx.globalAlpha = dim ? .35 : 1;
      ctx.fillStyle = 'rgba(14,30,66,.97)'; ctx.fill(cp);
      ctx.strokeStyle = on ? 'rgba(46,229,157,.95)' : 'rgba(46,229,157,.6)'; ctx.lineWidth = 1.4; ctx.shadowColor = 'rgba(46,229,157,.45)'; ctx.shadowBlur = on ? 18 : 10; ctx.stroke(cp); ctx.shadowBlur = 0;
      ctx.save(); ctx.translate(cloud.x - 46, cloud.y); ctx.strokeStyle = C.ext; ctx.lineWidth = 1.5; ctx.stroke(new Path2D(ICO.globe)); ctx.restore();
      ctx.textAlign = 'left'; ctx.font = '700 14px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(T('Internet', 'Інтернет'), cloud.x - 20, cloud.y + 12);
      ctx.globalAlpha = 1;
      shapes.push({path:cp, cloud:true, tip:`<b>${T('Internet', 'Інтернет')}</b>` + wl.map(l => `<div>${nm(l.a)} <span class="mono">${esc(l.a_name)}</span>: ↗ <b class="mono">${fmtB(l.a_out)}</b> · ↘ <b class="mono">${fmtB(l.a_in)}</b></div>`).join('')});
    }
    // device cards
    for (const n of data.nodes) {
      const p = pos.get(n.ip); if (!p) continue;
      const x = p.x - p.w / 2, y = p.y - p.h / 2, isPov = n.ip === data.pov, dim = onPath && !onPath.has(n.ip) && !(n.ip === 'internet' && onPath.has('internet')), card = rr(x, y, p.w, p.h, 14);
      ctx.globalAlpha = dim ? .35 : 1;
      ctx.fillStyle = isPov ? 'rgba(20,52,92,.96)' : 'rgba(14,26,60,.95)'; ctx.fill(card);
      ctx.strokeStyle = isPov ? '#27D3F5' : hover && hover.n === n ? 'rgba(150,190,255,.8)' : 'rgba(110,160,255,.35)'; ctx.lineWidth = isPov ? 2 : 1.2;
      if (isPov) { ctx.shadowColor = 'rgba(39,211,245,.6)'; ctx.shadowBlur = 16; } ctx.stroke(card); ctx.shadowBlur = 0;
      ctx.save(); ctx.translate(x + 11, y + 13); ctx.strokeStyle = n.ip === 'internet' ? C.ext : C.ink2; ctx.lineWidth = 1.5; ctx.stroke(new Path2D(devIcon(n))); ctx.restore();
      ctx.textAlign = 'left'; ctx.font = '700 13px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(clip(n.ip === 'internet' ? T('Internet', 'Інтернет') : n.name || n.ip, ctx.font, p.w - 52), x + 36, y + 22);
      ctx.font = '500 11px Manrope, sans-serif'; ctx.fillStyle = C.ink3;
      ctx.fillText(clip(n.ip === 'internet' ? T('beyond the WAN', 'за WAN') : [n.vendor, n.model].filter(Boolean).join(' ') || T('device', 'пристрій'), ctx.font, p.w - 24), x + 12, y + 44);
      ctx.font = '600 11px JetBrains Mono, monospace'; ctx.fillStyle = C.ink2; if (n.ip !== 'internet') ctx.fillText(n.ip, x + 12, y + 60);
      if (n.ip !== 'internet') { ctx.beginPath(); ctx.arc(x + p.w - 13, y + 14, 4, 0, 7); ctx.fillStyle = n.exporting ? C.ext : C.ink3; ctx.fill(); }
      if (n.more) { const bx = x + p.w - 34, by = y + p.h - 22; ctx.fillStyle = 'rgba(47,123,255,.35)'; ctx.fill(rr(bx, by, 26, 16, 8)); ctx.font = '700 10.5px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.textAlign = 'center'; ctx.fillText('+' + n.more, bx + 13, by + 8.5); }
      const k = onPath && opts.hopNo ? opts.hopNo(n.ip) : 0;
      if (k) { ctx.beginPath(); ctx.arc(x + 2, y + 2, 10, 0, 7); ctx.fillStyle = '#27D3F5'; ctx.fill(); ctx.font = '800 11px Manrope, sans-serif'; ctx.fillStyle = '#04102A'; ctx.textAlign = 'center'; ctx.fillText(k, x + 2, y + 2.5); }
      ctx.globalAlpha = 1;
      shapes.push({path:card, n, tip:`<b>${nm(n.ip)}</b>${n.ip !== 'internet' ? ` <span class="nat">${esc(n.ip)}</span><div>${n.exporting ? T('sends NetFlow', 'надсилає NetFlow') : T('sent no NetFlow in this period', 'не надсилав NetFlow за цей період')}</div>` : ''}${n.more ? `<div>${T(`${n.more} more neighbour(s) beyond`, `ще ${n.more} сусід(и) далі`)}</div>` : ''}${n.ip !== data.pov && n.ip !== 'internet' ? `<div class="nat">${T('Click: look from this device', 'Клік: дивитися з цього пристрою')}</div>` : ''}`});
    }
  }
  const pick = e => { const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    for (let i = shapes.length - 1; i >= 0; i--) { const sh = shapes[i];
      if (sh.path && ctx.isPointInPath(sh.path, x * dpr, y * dpr)) return {s:sh, x, y};
      if (sh.stroke) { ctx.lineWidth = sh.sw; if (ctx.isPointInStroke(sh.stroke, x * dpr, y * dpr)) return {s:sh, x, y}; } }
    return null; };
  cv.addEventListener('mousemove', e => { const h = pick(e), s = h ? h.s : null;
    if (s !== hover) { hover = s; draw(); }
    if (h) { tip.hidden = false; tip.innerHTML = s.tip; tip.style.left = Math.max(0, Math.min(W - tip.offsetWidth - 4, h.x + 14)) + 'px'; tip.style.top = Math.min(H - tip.offsetHeight - 4, h.y + 14) + 'px'; cv.style.cursor = s.n ? 'pointer' : 'default'; } else { tip.hidden = true; cv.style.cursor = ''; } });
  cv.addEventListener('mouseleave', () => { hover = null; tip.hidden = true; draw(); });
  cv.addEventListener('click', e => { const h = pick(e); if (h && h.s.n && opts.onNode) opts.onNode(h.s.n); });
  return {set:d => { data = d; draw(); }, redraw:draw};
}
function vNetwork(){
  const v = document.getElementById('view'), live = !!state.netLive && !isCustom(), depth = state.netDepth || 1;
  v.innerHTML = `<div class="grid">
    <section class="glass panel s9">${ph('nodes', T('Path analysis', 'Аналіз шляху'), T('layer-3 neighbours of the Point of View · width = volume · click a device to look from it', 'L3-сусіди точки огляду · ширина = обсяг · клік по пристрою — дивитися з нього'),
      `<span id="nPovSeg"></span>` + seg('nDepthSeg', [['1', '1'], ['2', '2'], ['3', '3']].map(([k, l]) => [k, l, T(`Neighbours up to ${k} hop(s) away`, `Сусіди на відстані до ${k} хоп(ів)`)]), String(depth))
      + seg('nScaleSeg', [['sqrt', T('Compressed', 'Стиснений'), T('Width ∝ √volume — small links stay visible next to big ones', 'Ширина ∝ √обсягу — дрібні зв’язки помітні поруч із великими')], ['lin', T('Linear', 'Лінійний')]], state.scale)
      + seg('nLiveSeg', [['live', T('Live', 'Наживо')], ['period', T('Period', 'За період')]], live ? 'live' : 'period'))}
      <div class="legend" style="margin:-6px 0 10px"><span><i class="bar" style="background:${C.down}"></i>${T('from the internet', 'з інтернету')}</span><span><i class="bar" style="background:${C.up}"></i>${T('to the internet', 'в інтернет')}</span><span><i class="bar" style="background:${C.int}"></i>${T('internal', 'внутрішній')}</span><span><i class="bar dash" style="border-color:${RED}"></i>${T('no observation / gap', 'не спостерігається / розрив')}</span><span><i class="bar dash" style="border-color:#AABEE6"></i>${T('L3 adjacency, no traffic', 'L3-суміжність, без трафіку')}</span></div>
      <div class="river netmap" id="cNet"></div>
      <p class="note">${T('Devices are neighbours when their interfaces share a subnet (Settings → Devices → Interfaces) or when one records the other’s addresses on an interface. All traffic regardless of the Internet / Internal selector and the device filter.', 'Пристрої — сусіди, коли їхні інтерфейси в одній підмережі (Налаштування → Пристрої → Інтерфейси) або коли один бачить адреси іншого на своєму інтерфейсі. Увесь трафік незалежно від перемикача «Інтернет / Внутрішній» і фільтра пристрою.')}</p></section>
    <div class="col s3">
      <div id="nKpi" class="col"></div>
      <section class="glass panel">${ph('search', T('Path', 'Шлях'), T('the hops from a source to a destination', 'хопи від джерела до призначення'))}
        <form class="form trace" id="nTrace" autocomplete="off"><label>${T('Source', 'Джерело')}<input id="nSrc" class="mono" placeholder="10.20.0.21 ${T('or', 'або')} 10.20.0.0/24" value="${esc(state.netSrc || '')}"></label>
          <label>${T('Destination', 'Призначення')}<input id="nDst" class="mono" placeholder="8.8.8.8 ${T('or', 'або')} 0.0.0.0/0" value="${esc(state.netDst || '')}"></label>
          <div class="acts"><button type="button" class="btn" id="nSwap" title="${T('Swap: the reply direction', 'Поміняти: зворотний напрямок')}">⇄</button><button class="btn primary" id="nGo">${T('Trace', 'Простежити')}</button>${state.netPath ? `<button type="button" class="btn" id="nClear">${T('Clear', 'Скинути')}</button>` : ''}</div></form>
        <div id="nPath"></div></section>
    </div>
    <section class="glass panel s12">${ph('conv', T('Links', 'Зв’язки'), T('what each end of a link sent and the other received', 'що кожен кінець зв’язку відправив і що інший отримав'))}<div id="nLinks" class="loading"></div></section></div>`;
  wireSeg('nDepthSeg', m => { if (+m === depth) return; state.netDepth = +m; render(); });
  wireSeg('nScaleSeg', m => { if (m === state.scale) return; state.scale = m; render(); });
  lockLive('nLiveSeg');
  wireSeg('nLiveSeg', m => { const l = m === 'live'; if (l === !!state.netLive) return; state.netLive = l; render(); });
  const seq = renderSeq, P = () => ({t:'all', live:live ? 1 : 0, win:120});
  let topo = null, path = null;
  const hopIndex = () => { const m = new Map(); if (path) path.hops.forEach((h, k) => { if (!m.has(h.device) && h.state !== 'unplaced' && h.state !== 'branch') m.set(h.device, k + 1); }); return m; };
  const map = createTopoMap(document.getElementById('cNet'), {onNode:n => { if (n.ip === 'internet' || n.ip === state.netPov) return; state.netPov = n.ip; if (n.more) state.netDepth = Math.max(depth, 1); render(); },
    pathSet:() => path && path.hops.length ? new Set(path.hops.filter(h => h.state !== 'unplaced').map(h => h.device)) : null, hopNo:ip => hopIndex().get(ip)});
  const nm = ip => ip === 'internet' ? T('Internet', 'Інтернет') : ((topo && topo.devices.find(d => d.ip === ip)) || {}).name || ip;
  const drawSide = () => {
    const ls = topo.links, cnt = s => ls.filter(l => l.state === s).length;
    const kc = (ic, k, val, sub, col) => `<section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span>${sub ? `<span class="nat" style="grid-column:2">${sub}</span>` : ''}</section>`;
    const pv = topo.devices.find(d => d.ip === topo.pov);
    fill('nKpi', kc('dev', T('Point of View', 'Точка огляду'), esc(pv ? pv.name : '—'), pv ? T(`${pv.neighbours} L3 neighbour(s)`, `${pv.neighbours} L3-сусід(ів)`) : '')
      + kc('nodes', T('Links shown', 'Зв’язків показано'), ls.length, `${cnt('observed')} ${T('observed', 'видно')}`)
      + kc('shield', T('Gaps · not observed', 'Розриви · не видно'), `${cnt('gap')} · ${cnt('unobserved')}`, T('links to check', 'зв’язки, які варто перевірити'), cnt('gap') + cnt('unobserved') ? RED : ''));
    const row = (d, name, addr, seen) => `<b>${esc(nm(d))}</b> <span class="mono">${esc(name)}</span>${addr ? ` <span class="nat mono"${seen ? ` title="${T('seen in the records of 24 h (the interface has no address from the settings or SNMP)', 'видно із записів за 24 год (адреси з налаштувань чи SNMP в інтерфейсу немає)')}"` : ''}>${esc(addr)}</span>` : ''}`;
    const sr = (sent, got, inet) => inet ? `<b class="mono">${fmtB(sent)}</b>` : `<b class="mono">${fmtB(sent)}</b> <span class="nat">/ ${fmtB(got)}</span>`;
    const tb = fill('nLinks', ls.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('End A', 'Кінець A')}</th><th></th><th>${T('End B', 'Кінець B')}</th><th>${T('State', 'Стан')}</th><th class="num">${T('A → B sent / received', 'A → B відправлено / отримано')}</th><th class="num">${T('B → A sent / received', 'B → A відправлено / отримано')}</th><th>${T('Found by', 'Знайдено за')}</th></tr></thead><tbody>
      ${ls.map(l => { const inet = l.b === 'internet', bad = l.state === 'gap' || l.state === 'unobserved';
        return `<tr><td>${row(l.a, l.a_name, l.a_addr, l.a_seen)}</td><td class="nat">↔</td><td>${inet ? `<b>${T('Internet', 'Інтернет')}</b>` : row(l.b, l.b_name, l.b_addr, l.b_seen)}</td>
          <td><span class="tag" title="${esc(LINK_STATE[l.state][1])}"${bad ? ` style="color:${RED};border-color:${hexA(RED, .5)}"` : ''}>${LINK_STATE[l.state][0]}</span></td>
          <td class="num">${sr(l.a_out, l.b_in, inet)}</td><td class="num">${inet ? `<b class="mono">${fmtB(l.a_in)}</b>` : sr(l.b_out, l.a_in)}</td>
          <td class="nat">${l.evidence === 'subnet' ? T('subnet', 'підмережа') + ' ' + esc(l.net) : l.evidence === 'wan' ? T('WAN interface', 'WAN-інтерфейс') : T('addresses in the records', 'адреси в записах')}</td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty">${T('This device has no layer-3 neighbours among the devices: set interface addresses in Settings → Devices → Interfaces, or wait for traffic between the devices.', 'Цей пристрій не має L3-сусідів серед пристроїв: вкажіть адреси інтерфейсів у Налаштування → Пристрої → Інтерфейси або дочекайтеся трафіку між пристроями.')}</div>`);
    if (tb) tb.classList.remove('loading');
  };
  const drawPath = () => {
    if (!path) { fill('nPath', `<p class="note" style="margin:8px 0 0">${T('Enter an address or a network on each side. Each device on the way shows the interfaces the traffic used; a device that should have seen it but recorded nothing marks a gap.', 'Вкажіть адресу або мережу з кожного боку. Кожен пристрій на шляху покаже інтерфейси, якими пройшов трафік; пристрій, який мав його бачити, але нічого не записав, позначає розрив.')}</p>`); return; }
    const hs = path.hops, real = hs.filter(h => !['internet', 'unplaced', 'branch'].includes(h.state)), obs = real.filter(h => h.state === 'observed').length, gaps = real.length - obs;
    if (!hs.length) { fill('nPath', `<div class="empty">${T('No device recorded traffic from this source to this destination in the period.', 'Жоден пристрій не записав трафік від цього джерела до цього призначення за період.')}</div>`); return; }
    const total = Math.max(0, ...hs.map(h => h.bytes));
    const el = fill('nPath', `<div class="pstats"><div><span>${T('Hops', 'Хопів')}</span><b>${real.length}</b></div><div><span>${T('Observed', 'Видно')}</span><b>${obs} / ${real.length}</b></div><div><span>${T('Gaps', 'Розриви')}</span><b${gaps ? ` style="color:${RED}"` : ''}>${gaps}${gaps ? ' ⚠' : ''}</b></div><div><span>${T('Traffic', 'Трафік')}</span><b>${fmtB(total)}</b></div></div>
      <ol class="hops">${hs.map((h, k) => { const bad = h.state === 'gap' || h.state === 'unobserved';
        return `<li class="hop ${h.state}" data-dev="${esc(h.device)}"><span class="no">${h.state === 'unplaced' ? '?' : h.state === 'branch' ? '↳' : k + 1}</span><div><b>${esc(h.state === 'internet' ? T('Internet', 'Інтернет') : h.name)}</b>
          ${h.state === 'observed' || h.state === 'unplaced' || h.state === 'branch' ? `<div class="mono">${esc(h.in_name)} → ${esc(h.out_name)}</div><div class="nat">${fmtB(h.bytes)} · ${fmtN(h.convs)} ${T('conversations', 'розмов')}${h.share < 1 ? ` · ${Math.round(100 * h.share)}% ${T('of the busiest hop', 'від найбільшого хопа')}` : ''}</div>
            <div class="vbar"><i style="width:${(100 * h.share).toFixed(1)}%;background:linear-gradient(90deg,${hexA(C.down, .6)},${C.down})"></i></div>` : ''}
          ${h.nat && h.nat.length ? `<div class="nat">NAT → <span class="mono">${esc(h.nat.join(', '))}</span></div>` : ''}
          ${(h.other_exits || []).map(e => `<div class="nat">${T('also leaves via', 'також виходить через')} <span class="mono">${esc(e.out_name)}</span>${e.next ? ` → ${esc(nm(e.next))}` : ''}: ${fmtB(e.bytes)}</div>`).join('')}
          <div class="st"${bad ? ` style="color:${RED}"` : ''}>${HOP_STATE[h.state]}${h.state === 'branch' ? ` ${T('of hop', 'хопа')} ${h.via_hop + 1}` : ''}</div></div></li>`; }).join('')}</ol>
      <p class="note" style="margin:6px 0 0">${path.complete ? T('Every device on the way recorded the traffic.', 'Кожен пристрій на шляху записав цей трафік.') : T('The path is not seen whole: see the marked hops.', 'Шлях видно не повністю: дивіться позначені хопи.')}</p>`);
    if (el) el.querySelectorAll('li[data-dev]').forEach(li => li.onclick = () => { const d = li.dataset.dev; if (d === 'internet' || d === state.netPov) return; state.netPov = d; render(); });
  };
  const load = () => api('topology', {...P(), pov:state.netPov || '', depth});
  const show = d => { if (seq !== renderSeq) return; topo = d; state.netPov = d.pov;
    const opts = d.devices.slice().sort((a, b) => a.name.localeCompare(b.name)).map(x => `<option value="${esc(x.ip)}"${x.ip === d.pov ? ' selected' : ''}${!x.neighbours ? ' disabled' : ''}>${esc(x.name)} (${esc(x.ip)})${!x.neighbours ? ' — ' + T('no L3 neighbours', 'немає L3-сусідів') : ''}</option>`).join('');
    fill('nPovSeg', `<label class="sel glass" title="${T('Point of View', 'Точка огляду')}">${icon(ICO.dev, 16)}<select id="nPovSel" aria-label="${T('Point of View', 'Точка огляду')}">${opts}</select></label>`);
    const ps = document.getElementById('nPovSel'); if (ps) ps.onchange = () => { state.netPov = ps.value; render(); };
    map.set(d); drawSide(); };
  const trace = async () => {
    const s = document.getElementById('nSrc').value.trim(), t = document.getElementById('nDst').value.trim();
    state.netSrc = s; state.netDst = t;
    if (!s || !t) { path = null; state.netPath = false; drawPath(); map.redraw(); return; }
    fill('nPath', '<div class="loading" style="min-height:60px"></div>');
    try { path = await api('path', {...P(), src:s, dst:t}); if (seq !== renderSeq) return; state.netPath = true; drawPath(); map.redraw(); }
    catch (e) { if (seq === renderSeq) fill('nPath', errBox(e)); }
  };
  document.getElementById('nTrace').onsubmit = e => { e.preventDefault(); trace(); };
  document.getElementById('nSwap').onclick = () => { const a = document.getElementById('nSrc'), b = document.getElementById('nDst'); [a.value, b.value] = [b.value, a.value]; if (state.netPath) trace(); };
  const cl = document.getElementById('nClear'); if (cl) cl.onclick = () => { state.netSrc = state.netDst = ''; state.netPath = false; render(); };
  drawPath();
  load().then(d => { show(d); if (state.netPath && state.netSrc && state.netDst) trace(); }).catch(e => { if (seq === renderSeq) { fill('cNet', errBox(e)); fill('nLinks', ''); } });
  if (live) every(10000, () => load().then(show).catch(() => {}));
}
function recTable(rows){
  return `<div class="tw"><table><thead><tr><th>${T('Time', 'Час')}</th><th>${T('Exporter', 'Експортер')}</th><th>${T('Inside address', 'Внутрішня адреса')}</th><th></th><th>${T('Outside address', 'Зовнішня адреса')}</th><th>${T('Protocol', 'Протокол')}</th><th>${T('Service', 'Сервіс')}</th><th>${T('Country', 'Країна')}</th><th class="num">${T('Bytes', 'Байти')}</th><th class="num">${T('Packets', 'Пакети')}</th><th class="num">${T('Dur.', 'Трив.')}</th></tr></thead><tbody>
    ${rows.map((f, i) => `<tr class="click" data-rec="${i}"><td class="mono">${hms(f.t)}</td><td class="ipl">${esc(devName(f.exporter))}</td>
      <td class="ipl"><button class="link" data-f="ip" data-v="${esc(f.int_ip)}">${esc(f.name || f.int_ip)}</button> <span class="nat">:${f.int_port}</span></td><td class="${f.dir === 'down' || f.dir === 'internal_in' ? 'd' : 'u'}">${f.dir === 'down' || f.dir === 'internal_in' ? '←' : f.dir === 'transit' ? '↔' : '→'}</td>
      <td class="ipl"><button class="link" data-f="dst" data-v="${esc(f.ext_ip)}">${esc(f.ext_ip)}</button> <span class="nat">:${f.ext_port}</span></td><td><span class="tag">${esc(dv(f.l7))}</span></td><td>${svcBadge(f.service)}</td>
      <td>${f.country ? `<button class="link" data-f="country" data-v="${esc(f.country)}">${esc(f.country)}</button>` : '—'}</td><td class="num mono">${fmtB(f.bytes)}</td><td class="num mono">${fmtN(f.packets)}</td><td class="num mono">${Math.max(0, f.t - f.t0).toFixed(0)} ${T('s', 'с')}</td></tr>
      ${state.openFlow === i ? `<tr class="detail"><td colspan="11"><div class="kv"><div><span>${T('Host', 'Хост')}</span><b>${esc(f.name || '—')} · ${esc(f.int_ip)}</b></div><div><span>${T('NAT (after translation)', 'NAT (після трансляції)')}</span><b>${f.nat_ip ? esc(f.nat_ip) + ':' + f.nat_port : '—'}</b></div>
        <div><span>ASN</span><b>${f.asn ? 'AS' + f.asn + ' ' + esc(f.as_org) : '—'}</b></div><div><span>${T('City', 'Місто')}</span><b>${esc([f.city, ccName(f.country)].filter(Boolean).join(', ') || '—')}</b></div>
        <div><span>${T('Interfaces', 'Інтерфейси')}</span><b>${esc(ifLabel(f.exporter, f.in_if))} → ${esc(ifLabel(f.exporter, f.out_if))}</b></div><div><span>${T('Sampling', 'Вибірка')}</span><b>${f.sampling > 1 ? '1:' + f.sampling + T(' (volume scaled up)', ' (обсяг перераховано)') : T('1:1 (not sampled)', '1:1 (без вибірки)')}</b></div><div><span>L4</span><b>${({1:'ICMP', 6:'TCP', 17:'UDP', 50:'ESP', 47:'GRE'})[f.proto] || f.proto}</b></div></div></td></tr>` : ''}`).join('') || `<tr><td colspan="11"><div class="empty">${T('No records for this filter', 'Немає записів під цей фільтр')}</div></td></tr>`}
    </tbody></table></div>`;
}
document.addEventListener('click', e => { const tr = e.target.closest && e.target.closest('tr[data-rec]'); if (!tr || e.target.closest('[data-f]')) return; const i = +tr.dataset.rec; state.openFlow = state.openFlow === i ? null : i; const box = document.getElementById('recBox'); if (box && window.__recs) { box.innerHTML = recTable(window.__recs); wireFilters(box); } });

const HOSTPAL = ['#27D3F5', '#FF4FA0', '#2F7BFF', '#5AC8FA', '#FFB547', '#F0508C', '#2EE59D', '#A06BFF', '#4C7DFF', '#8A96B4'];
const L4 = {1:'ICMP', 6:'TCP', 17:'UDP', 47:'GRE', 50:'ESP', 51:'AH', 58:'ICMPv6', 132:'SCTP'};
function downloadCsv(name, header, rows){
  const q = v => { const t = String(v ?? ''); return /[",\n;]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
  const blob = new Blob(['﻿' + [header, ...rows].map(r => r.map(q).join(',')).join('\n')], {type:'text/csv;charset=utf-8'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function vTalkers(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid">
    <div id="tKpi" class="s12 grid" style="grid-column:span 12"><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div></div>
    <div class="col s8 fillcol">
      <section class="glass panel">${ph('users', T('Top hosts', 'Топ хостів'), T('by total volume · click a row to add the host to the filters', 'за загальним обсягом · клік по рядку додає хост у фільтри'), '<button class="lnk" id="tMore"></button>')}<div id="tBox" class="loading"></div></section>
      <section class="glass panel grow">${ph('chart', T('Top hosts trend', 'Тренд топ-хостів'), T('top 5 and the rest', 'топ-5 і решта'))}<div class="chart" id="cTop5"></div></section>
    </div>
    <div class="col s4">
      <section class="glass panel">${ph('pie', T('Top hosts traffic', 'Трафік топ-хостів'), T('share of the total volume', 'частка від усього обсягу'))}<div id="tDonut" class="loading"></div></section>
      <section class="glass panel">${ph('grid', T('By service', 'За сервісами'), T('share of traffic · click to filter', 'частка трафіку · клік — фільтр'))}<div id="tSvc" class="loading"></div></section>
      <section class="glass panel">${ph('globe', T('Where the traffic goes', 'Куди йде трафік'), T('destination countries', 'країни призначення'))}<div id="tGeo" class="loading"></div></section>
      <section class="glass panel">${ph('search', T('Quick actions', 'Швидкі дії'), '<span id="qaFor">—</span>')}<div class="qa" id="qa"></div></section>
    </div>
    <section class="glass panel s12">${ph('list', T('Top hosts in detail', 'Топ хостів детально'), T('main service and protocol of each · click to filter', 'головний сервіс і протокол кожного · клік — фільтр'), `<button class="lnk" id="toFlows2">${T('Flows →', 'Потоки →')}</button>`)}<div id="tDetail" class="loading"></div></section></div>`;
  document.getElementById('toFlows2').onclick = () => { state.view = 'flows'; render(); };
  const limit = state.talkersAll ? 50 : 10, secs = rangeSecs();
  fill('tMore', state.talkersAll ? T('Show top 10', 'Показати топ-10') : T('Show top 50', 'Показати топ-50'));
  document.getElementById('tMore').onclick = () => { state.talkersAll = !state.talkersAll; render(); };
  const colorOf = new Map();
  let selected = null, topRows = [];
  const drawQa = () => {
    const h = selected; fill('qaFor', h ? T(`for ${esc(h.name || h.k)}`, `для ${esc(h.name || h.k)}`) : T('no data', 'немає даних'));
    const box = fill('qa', h ? [
      ['flow', T('Flow details', 'Деталі потоків'), T('the Flows page with a filter', 'сторінка Потоки з фільтром'), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'flows'; render(); }],
      ['users', T('Host card', 'Картка хоста'), T('services, protocols, destinations', 'сервіси, протоколи, напрямки'), () => openHost(h.k)],
      ['globe', T('Geolocation', 'Геолокація'), T('connection map of this host', 'карта з’єднань цього хоста'), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'geo'; render(); }],
      ['list', T('Export CSV', 'Експорт CSV'), T('the top hosts table', 'таблиця топ-хостів'), () => downloadCsv(`flowtrack-top-hosts-${isCustom() ? state.from + '-' + state.to : state.range}.csv`, ['rank', 'ip', 'name', 'bytes', 'upload', 'download', 'percent', 'flows', 'avg_bps'],
        topRows.map((r, i) => [i + 1, r.k, r.name || '', tot(r), r.up, r.dn, (100 * tot(r) / (window.__tTotal || 1)).toFixed(2), r.fl, Math.round(tot(r) * 8 / secs)]))],
    ].map(([ic, t, sub], i) => `<button class="qa-btn" data-qa="${i}"><span class="ico">${icon(ICO[ic], 18)}</span><span><b>${t}</b><small>${sub}</small></span></button>`).join('') : '');
    if (box && h) { const acts = [() => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'flows'; render(); }, () => openHost(h.k), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'geo'; render(); },
      () => downloadCsv(`flowtrack-top-hosts-${isCustom() ? state.from + '-' + state.to : state.range}.csv`, ['rank', 'ip', 'name', 'bytes', 'upload', 'download', 'percent', 'flows', 'avg_bps'], topRows.map((r, i) => [i + 1, r.k, r.name || '', tot(r), r.up, r.dn, (100 * tot(r) / (window.__tTotal || 1)).toFixed(2), r.fl, Math.round(tot(r) * 8 / secs)]))];
      box.querySelectorAll('[data-qa]').forEach(b => b.onclick = acts[+b.dataset.qa]); }
  };
  section('tKpi', async () => {
    const [s, ser, t] = await Promise.all([api('summary'), api('series'), api('top', {dim:'int_ip', limit:1})]);
    const trend = (a, b) => !s.has_prev || !b ? `<span class="tr nodata" style="color:var(--ink3)">${T(`data since ${hhmm(s.oldest)}`, `дані з ${hhmm(s.oldest)}`)}</span>` : `<span class="tr ${a < b ? 'dn' : ''}">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
    const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]), top = t.rows[0];
    const card = (ic, k, v, tr, sp, col, sub) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sub ? `<span class="s" style="grid-column:2/-1;font-size:12.5px;color:var(--ink2)">${sub}</span>` : ''}${sp ? sparkSvg(sp, col) : ''}</div>`;
    return card('pulse', T('Total traffic', 'Загальний трафік'), fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
      + card('ip', T('Top host (by volume)', 'Топ хост (за обсягом)'), esc(top ? top.name || top.k : '—'), '', null, '', top ? `${esc(top.name ? top.k + ' · ' : '')}${fmtB(tot(top))} (${pct(tot(top), t.total)})` : '')
      + card('users', T('Unique hosts', 'Унікальні хости'), fmtN(s.hosts), trend(s.hosts, s.p_hosts), fl.map(Math.sqrt), C.int)
      + card('nodes', T('Total flows', 'Усього flow'), fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext);
  });
  Promise.all([api('top', {dim:'int_ip', limit}), api('series', {by:'int_ip', top:Math.min(limit, 20)})]).then(([t, ser]) => {
    topRows = t.rows; window.__tTotal = t.total;
    t.rows.forEach((r, i) => colorOf.set(r.k, HOSTPAL[i % HOSTPAL.length]));
    const fip = (state.filters.find(f => f.k === 'ip' && !f.neg) || {}).v;
    selected = t.rows.find(r => r.k === fip) || t.rows[0] || null; drawQa();
    const sp = new Map(); for (const [ts, k, b] of ser.rows) { if (!sp.has(k)) sp.set(k, new Map()); sp.get(k).set(ts, b); }
    const {ts} = grid(ser), max = t.rows.length ? tot(t.rows[0]) : 1;
    const box = fill('tBox', `<div class="tw"><table class="talkers"><thead><tr><th>#</th><th>${T('Host / IP', 'Хост / IP')}</th><th style="width:26%">${T('Volume', 'Обсяг')}</th><th class="num">%</th><th class="num">Flows</th><th class="num">${T('Avg rate', 'Сер. швидкість')}</th><th>${T('Trend', 'Тренд')}</th><th></th></tr></thead><tbody>
      ${t.rows.map((r, i) => { const c = colorOf.get(r.k);
        return `<tr class="click${r.k === fip ? ' is-picked' : ''}" data-pick="${esc(r.k)}" title="${T('Add to filters', 'Додати у фільтри')}"><td class="mono">${i + 1}</td><td><div class="hcell"><span class="hbar" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="htxt"><b class="mono">${esc(r.k)}</b><span class="nat">${esc(r.name || (r.k.startsWith('10.') || r.k.startsWith('192.168.') || r.k.startsWith('172.') ? T('no name', 'без імені') : T('public address', 'публічна адреса')))}</span></span></div></td>
          <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .55)},${c});box-shadow:0 0 8px ${hexA(c, .6)}"></i></div></td>
          <td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${fmtN(r.fl)}</td><td class="num mono">${fmtR(tot(r) * 8 / secs)}</td>
          <td style="width:120px">${sp.has(r.k) ? sparkSvg(ts.map(x => sp.get(r.k).get(x) || 0), c, 120, 26) : ''}</td><td><button class="btn" data-open="${esc(r.k)}" title="${T('Host card', 'Картка хоста')}">›</button></td></tr>`; }).join('') || `<tr><td colspan="8"><div class="empty">${T('No data', 'Немає даних')}</div></td></tr>`}</tbody></table></div>`);
    if (box) { box.classList.remove('loading');
      box.querySelectorAll('tr[data-pick]').forEach(tr => tr.onclick = () => addFilter('ip', tr.dataset.pick));
      box.querySelectorAll('[data-open]').forEach(b => b.onclick = e => { e.stopPropagation(); openHost(b.dataset.open); }); }
    // donut: top 5 + rest, same colours as the table
    const top5 = t.rows.slice(0, 5), rest = t.total - top5.reduce((a, r) => a + tot(r), 0);
    const drows = [...top5.map(r => ({k:r.k, label:r.name || r.k, up:r.up, dn:r.dn})), ...(rest > 0 ? [{k:'__other', label:T('Others', 'Інші'), up:rest, dn:0}] : [])];
    const db = fill('tDonut', `<div class="donut-wrap"><div class="chart donut" id="cTDonut"></div><div class="dl">${drows.map(r => `<i class="idot" style="background:${r.k === '__other' ? C.other : colorOf.get(r.k)}"></i>${r.k === '__other' ? `<span>${T('Others', 'Інші')}</span>` : `<button class="link mono" data-f="ip" data-v="${esc(r.k)}">${esc(r.label)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t"></span>`).join('')}</div></div>`);
    if (db) { db.classList.remove('loading'); wireFilters(db); donut(document.getElementById('cTDonut'), drows.map(r => ({...r, k:r.label})), k => { const r = drows.find(x => x.label === k); return r.k === '__other' ? C.other : colorOf.get(r.k); }, [fmtB(t.total), T('all traffic', 'весь трафік')]); }
    // stacked trend: top 5 + others, same colours
    api('series', {by:'int_ip', top:5}).then(s5 => { const el = document.getElementById('cTop5'); if (!el) return;
      const {ts: t5, step} = grid(s5), keys = new Map(); for (const [x, k, b] of s5.rows) { if (!keys.has(k)) keys.set(k, new Map()); keys.get(k).set(x, b); }
      const order = [...keys.keys()].sort((a, b) => (a === '__other') - (b === '__other'));
      const c = mkChart(el);
      c.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true}, legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
        tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(t5), yAxis:axisY(v => fmtR(v)),
        series:order.map(k => { const col = k === '__other' ? C.other : (colorOf.get(k) || C.other), r = t.rows.find(x => x.k === k);
          return {name:k === '__other' ? T('others', 'інші') : (r && r.name) || k, type:'line', stack:'a', smooth:.3, showSymbol:false, lineStyle:{width:1.6, color:col}, itemStyle:{color:col},
            areaStyle:{color:new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset:0, color:hexA(col, .45)}, {offset:1, color:hexA(col, .05)}])}, data:t5.map(x => [x * 1000, (keys.get(k).get(x) || 0) * 8 / step])}; })});
      zoomable(c);
    }).catch(e => fill('cTop5', errBox(e)));
  }).catch(e => fill('tBox', errBox(e)));
  section('tSvc', async () => { const p = await api('top', {dim:'service', limit:6}); const rows = p.rows.slice(0, 5), rest = p.total - rows.reduce((a, r) => a + tot(r), 0);
    const all = [...rows.map(r => ({label:r.k, v:tot(r), k:r.k})), ...(rest > 0 ? [{label:T('Others', 'Інші'), v:rest}] : [])];
    return `<div class="pbars">${all.map(r => { const c = r.k ? keyColor(r.k) : C.other;
      return `<span>${r.k ? `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.label)}</button>` : r.label}</span><div class="vbar"><i style="width:${Math.max(1, 100 * r.v / (p.total || 1)).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .6)},${c})"></i></div><b class="mono">${pct(r.v, p.total)}</b>`; }).join('') || `<div class="empty">${T('No data', 'Немає даних')}</div>`}</div>`; });
  section('tGeo', async () => { const [cc, city] = await Promise.all([api('top', {dim:'country', limit:5}), api('top', {dim:'city', limit:25})]);
    const rest = cc.total - cc.rows.reduce((a, r) => a + tot(r), 0), cols = ['#27D3F5', '#2F7BFF', '#2EE59D', '#8B5CFF', '#FFB547'];
    setTimeout(() => { const el = document.getElementById('cMini'); if (!el || !echarts.getMap('world')) return; const c = mkChart(el), cmax = city.rows.length ? tot(city.rows[0]) : 1;
      c.setOption({animation:false, geo:{map:'world', silent:true, roam:false, left:0, right:0, top:0, bottom:0, itemStyle:{areaColor:'rgba(30,56,120,.45)', borderColor:'rgba(110,160,255,.25)', borderWidth:.4}},
        series:[{type:'scatter', coordinateSystem:'geo', symbolSize:d => 4 + 10 * Math.sqrt(d[2] / cmax), itemStyle:{color:'#27D3F5', shadowBlur:10, shadowColor:'#27D3F5'},
          data:city.rows.filter(r => r.la || r.lo).map(r => [r.lo, r.la, tot(r)])}]}); });
    return `<div class="geomini"><div class="chart" id="cMini" style="height:120px"></div><div class="dl">${cc.rows.map((r, i) => `<i class="idot" style="background:${cols[i]}"></i><button class="link" data-f="country" data-v="${esc(r.k)}">${esc(r.k ? ccName(r.k) : T('Local', 'Локальні'))}</button><span class="p">${pct(tot(r), cc.total)}</span><span class="t"></span>`).join('')}${rest > 0 ? `<i class="idot" style="background:${C.other}"></i><span>${T('Others', 'Інші')}</span><span class="p">${pct(rest, cc.total)}</span><span class="t"></span>` : ''}</div></div>`; });
  section('tDetail', async () => { const d = await api('top', {dim:'host_svc', limit:6});
    return `<div class="tw"><table class="compact"><thead><tr><th>${T('Host', 'Хост')}</th><th>${T('Main service', 'Головний сервіс')}</th><th>${T('Protocol', 'Протокол')}</th><th class="num">${T('Volume', 'Обсяг')}</th></tr></thead><tbody>${d.rows.map((r, i) => { const c = HOSTPAL[i % HOSTPAL.length];
      return `<tr class="click" data-f="ip" data-v="${esc(r.k)}"><td><span class="idot" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="mono">${esc(r.name || r.k)}</span></td><td>${svcBadge(r.service)}</td><td><span class="tag">${L4[r.proto] || r.proto} · ${esc(dv(r.l7))}</span></td><td class="num mono">${fmtB(tot(r))}</td></tr>`; }).join('')}</tbody></table></div>`; });
}
function vPorts(){
  const v = document.getElementById('view'), all = !!state.portsAll;
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12">${ph('chart', T('Ports over time', 'Порти в часі'), T('top 7 · click a line to filter by port', 'топ-7 · клік по лінії — фільтр за портом'))}<div class="chart" id="cPorts"></div></section>
    <section class="glass panel s8">${ph('list', T('Top ports', 'Топ портів'), T('click to filter by port', 'клік — фільтр за портом'), '<button class="lnk" id="pMore"></button>')}<div id="pTbl" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', T('L7 protocols', 'Протоколи L7'), T('by port', 'за портом'))}<div id="pL7" class="loading"></div></section></div>`;
  api('series', {by:'ext_port', top:7}).then(s => { const el = document.getElementById('cPorts'); if (el) stackChart(el, s, k => ':' + k, k => addFilter('port', k)); }).catch(e => fill('cPorts', errBox(e)));
  section('pTbl', async () => { const t = await api('top', {dim:'ext_port', limit:all ? 100 : 11}), rows = all ? t.rows : t.rows.slice(0, 10), max = rows.length ? tot(rows[0]) : 1;
    moreToggle('pMore', 'portsAll', all, t.rows.length > 10);
    return `<div class="tw"><table><thead><tr><th>${T('Port', 'Порт')}</th><th>${T('Protocol', 'Протокол')}</th><th>${T('Typical service', 'Типовий сервіс')}</th><th style="width:24%">${T('Volume', 'Обсяг')}</th><th class="num">%</th><th class="num">${T('Hosts', 'Хостів')}</th><th class="num">${T('Outside addresses', 'Зовн. адрес')}</th><th class="num">Flows</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="port" data-v="${esc(r.k)}"><td><b class="mono">${esc(r.k)}</b></td><td><span class="tag">${L4[r.proto_n] || r.proto_n} · ${esc(dv(r.l7))}</span></td><td>${svcBadge(r.service)}</td>
        <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,#1aa7d6,#27D3F5)"></i></div></td><td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${r.hosts}</td><td class="num mono">${fmtN(r.peers)}</td><td class="num mono">${fmtN(r.fl)}</td></tr>`).join('') || `<tr><td colspan="8"><div class="empty">${T('No data', 'Немає даних')}</div></td></tr>`}</tbody></table></div>`; });
  section('pL7', async () => { const t = await api('top', {dim:'l7', limit:8});
    setTimeout(() => { const el = document.getElementById('cPL7'); if (el) donut(el, t.rows, k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), T('protocols', 'протоколів')]); });
    return `<div class="chart" id="cPL7" style="height:200px"></div><div class="dl">${t.rows.map((r, i) => `<i class="idot" style="background:${PAL[i % PAL.length]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(dv(r.k))}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div>`; });
}
// "show all" / "top 10" link in a panel header; hidden when there is nothing more to show
function moreToggle(id, key, all, hasMore){
  const b = document.getElementById(id); if (!b) return;
  b.hidden = !all && !hasMore; b.textContent = all ? T('Show top 10', 'Показати топ-10') : T('Show all', 'Показати всі');
  b.onclick = () => { state[key] = !all; render(); };
}
function vApps(){
  const v = document.getElementById('view'), all = !!state.appsAll;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('chart', T('Services over time', 'Сервіси в часі'), T('the service comes from the destination ASN and port', 'сервіс визначається за ASN адреси призначення та портом'))}<div class="chart" id="cApps"></div></section>
    <section class="glass panel s8">${ph('grid', T('Services', 'Сервіси'), T('click to filter by service', 'клік — фільтр за сервісом'), '<button class="lnk" id="aMore"></button>')}<div id="aBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', T('Protocols', 'Протоколи'), T('L7 by port', 'L7 за портом'))}<div id="pBox" class="loading"></div></section></div>`;
  api('series', {by:'service', top:7}).then(s => { const el = document.getElementById('cApps'); if (el) stackChart(el, s, k => k, k => addFilter('service', k)); }).catch(e => fill('cApps', errBox(e)));
  section('aBox', async () => { const t = await api('top', {dim:'service', limit:all ? 100 : 11}), rows = all ? t.rows : t.rows.slice(0, 10);
    moreToggle('aMore', 'appsAll', all, t.rows.length > 10);
    return `<div class="tw"><table><thead><tr><th>${T('Service', 'Сервіс')}</th><th>${T('Protocol', 'Протокол')}</th><th class="num">↓</th><th class="num">↑</th><th class="num">${T('Total', 'Разом')}</th><th class="num">%</th><th class="num">${T('Hosts', 'Хостів')}</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="service" data-v="${esc(r.k)}"><td><button class="link" data-f="service" data-v="${esc(r.k)}">${svcBadge(r.k)}</button></td><td class="ipl">${esc(dv(r.l7))}</td><td class="num d mono">${fmtB(r.dn)}</td><td class="num u mono">${fmtB(r.up)}</td><td class="num mono"><b>${fmtB(tot(r))}</b></td><td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${r.hosts}</td></tr>`).join('')}</tbody></table></div>`; });
  section('pBox', async () => { const t = await api('top', {dim:'l7', limit:10});
    setTimeout(() => { const el = document.getElementById('cL7'); if (el) donut(el, t.rows.slice(0, 8), k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), T('protocols', 'протоколів')]); });
    return `<div class="chart" id="cL7" style="height:220px"></div><div class="dl">${t.rows.slice(0, 8).map((r, i) => `<i class="idot" style="background:${PAL[i % PAL.length]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(dv(r.k))}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div>`; });
}
function vGeo(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s8">${ph('globe', T('Connection map', 'Карта з’єднань'), T('destination GeoIP · a line appears when a new flow arrives · colour = direction', 'GeoIP призначення · лінія з’являється, коли надходить новий flow · колір = напрямок'),
      `<span class="legend"><span><i class="bar" style="background:${C.down}"></i>download</span><span><i class="bar" style="background:${C.up}"></i>upload</span><span><i style="background:${C.int}"></i>${T('sites', 'майданчики')}</span><span><i style="background:${C.ext}"></i>${T('destinations', 'призначення')}</span></span>`)}<div class="chart map" id="cMap"></div></section>
    <section class="glass panel s4">${ph('pulse', T('Live connections', 'З’єднання наживо'), T('new flows with geolocation', 'нові flow із геолокацією'))}<div class="ticker" id="ticker"><div class="empty">${T('Waiting for new records (exporters send about once a minute)…', 'Чекаю на нові записи (експорт іде раз на ~хвилину)…')}</div></div></section>
    <section class="glass panel s4">${ph('globe', T('Countries', 'Країни'), T('by destination address', 'за адресою призначення'))}<div id="ccBox" class="loading"></div></section>
    <section class="glass panel s8">${ph('nodes', T('Autonomous systems', 'Автономні системи'), T('who actually serves the traffic', 'хто насправді обслуговує трафік'))}<div id="asBox" class="loading"></div></section></div>`;
  const tk = document.getElementById('ticker');
  api('geo').then(g => { const el = document.getElementById('cMap'); if (!el) return; flatMap(el, g, r => {
    if (tk.querySelector('.empty')) tk.innerHTML = '';
    const up = r.dir === 'up', site = siteCity(r.exporter), place = r.city || ccName(r.country);
    const d = document.createElement('div'); d.className = 'tick';
    d.innerHTML = `<span class="mono" style="color:var(--ink3)">${hms(r.t)}</span><span><b class="${up ? 'u' : 'd'}">${up ? '↑' : '↓'}</b> ${esc(up ? site : place)} → ${esc(up ? place : site)}<br><span class="nat ipl">${esc(r.name || r.int_ip)} ${up ? '→' : '←'} ${esc(r.ext_ip)}:${r.ext_port} · ${esc(r.service)}</span></span><span class="mono">${fmtB(r.bytes)}</span>`;
    tk.prepend(d); while (tk.children.length > 14) tk.lastChild.remove(); }); }).catch(e => fill('cMap', errBox(e)));
  section('ccBox', async () => { const t = await api('top', {dim:'country', limit:20}); const max = t.rows.length ? tot(t.rows[0]) : 1;
    return `<div class="blist">${t.rows.map(r => `<button class="brow" data-f="country" data-v="${esc(r.k)}"><span class="n"><span class="tag mono">${esc(r.k || '—')}</span>&nbsp; ${esc(r.k ? ccName(r.k) : T('Local / unknown', 'Локальні / невідомі'))}</span><span class="t">${fmtB(tot(r))}</span><span class="p">${pct(tot(r), t.total)}</span>
      <span class="bar2" style="width:${(100 * tot(r) / max).toFixed(1)}%"><i class="u" style="width:${(100 * r.up / (tot(r) || 1)).toFixed(1)}%"></i><i class="d" style="flex:1"></i></span></button>`).join('')}</div>`; });
  section('asBox', async () => { const t = await api('top', {dim:'asn', limit:25});
    return `<div class="tw"><table><thead><tr><th>ASN</th><th>${T('Country', 'Країна')}</th><th class="num">↓</th><th class="num">↑</th><th class="num">${T('Total', 'Разом')}</th><th class="num">%</th></tr></thead><tbody>
      ${t.rows.map(r => `<tr><td>${r.k !== '0' ? `<button class="link" data-f="asn" data-v="${esc(r.k)}">AS${esc(r.k)} ${esc(r.as_org)}</button>` : T('local addresses', 'локальні адреси')}</td><td><span class="tag mono">${esc(r.country || '—')}</span></td><td class="num d mono">${fmtB(r.dn)}</td><td class="num u mono">${fmtB(r.up)}</td><td class="num mono"><b>${fmtB(tot(r))}</b></td><td class="num mono">${pct(tot(r), t.total)}</td></tr>`).join('')}</tbody></table></div>`; });
}
function vThreats(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s8">${ph('shield', T('Events and anomalies', 'Події та аномалії'), T('computed from the flows of the last day', 'обчислюються з потоків за останню добу'))}<div id="alBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('search', T('What is watched', 'Що відстежується'))}<div class="kv">
      <div><span>${T('Sustained upload', 'Тривале вивантаження')}</span><b>${T('&gt;5 Mbit/s · 45 min out of 3 h', '&gt;5 Мбіт/с · 45 хв із 3 год')}</b></div><div><span>${T('Bursts', 'Сплески')}</span><b>${T('×8 the host median', '×8 від медіани хоста')}</b></div><div><span>${T('New countries', 'Нові країни')}</span><b>${T('first contact this week', 'перший контакт за тиждень')}</b></div>
      <div><span>${T('Export health', 'Здоров’я експорту')}</span><b>${T('sequence gaps', 'пропуски sequence')}</b></div></div><p class="note">${T('Port scans, IP reputation and Telegram notifications are next.', 'Сканування портів, репутація IP і сповіщення в Telegram — наступні кроки.')}</p></section></div>`;
  section('alBox', async () => { const a = (await api('alerts')).alerts;
    if (!a.length) return `<div class="empty">${T('No events — all quiet', 'Подій немає — усе спокійно')}</div>`;
    return '<div class="alerts">' + a.map(x => `<div class="alert ${x.sev}"><span class="sev">${x.sev === 'info' ? 'i' : '!'}</span><div class="body"><b>${esc(x.title)}</b><p>${esc(x.text)}</p></div>
      <div class="meta"><span class="pill ${x.sev}">${{warn:T('warning', 'увага'), crit:T('anomaly', 'аномалія'), info:T('info', 'інфо')}[x.sev]}</span><span class="mono">${esc(String(x.when).slice(11, 16) || x.when)}</span>${x.ip ? `<button class="btn" data-f="ip" data-v="${esc(x.ip)}">${T('Filter', 'Фільтр')}</button>` : ''}</div></div>`).join('') + '</div>'; });
}
const VENDORS = {
  Fortinet:(ip, port) => `config system netflow\n    set active-flow-timeout 60\n    config collectors\n        edit 1\n            set collector-ip ${ip}\n            set collector-port ${port}\n        next\n    end\nend\n# ${T('WAN + internal interfaces (not Wi-Fi SSIDs)', 'WAN + внутрішні інтерфейси (крім Wi-Fi SSID)')}\nconfig system interface\n    edit "wan1"\n        set netflow-sampler both\n    next\n    edit "internal"\n        set netflow-sampler both\n    next\nend`,
  Cisco:(ip, port) => `flow record FT-REC\n match ipv4 source address\n match ipv4 destination address\n match ipv4 protocol\n match transport source-port\n match transport destination-port\n match interface input\n match flow direction\n collect interface output\n collect counter bytes long\n collect counter packets long\n collect timestamp sys-uptime first\n collect timestamp sys-uptime last\nflow exporter FLOWTRACK\n destination ${ip}\n transport udp ${port}\n template data timeout 60\nflow monitor FT-MON\n exporter FLOWTRACK\n record FT-REC\n cache timeout active 60\n! ${T('on every interface to watch (WAN and LAN)', 'на кожному інтерфейсі для спостереження (WAN і LAN)')}\ninterface GigabitEthernet0/0/0\n ip flow monitor FT-MON input\n ip flow monitor FT-MON output`,
  MikroTik:(ip, port) => `/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m\n/ip traffic-flow target add dst-address=${ip} port=${port} version=9`,
  Juniper:(ip, port) => `set services flow-monitoring version-ipfix template FT ipv4-template\nset forwarding-options sampling instance FT input rate 1\nset forwarding-options sampling instance FT family inet output flow-server ${ip} port ${port}\nset forwarding-options sampling instance FT family inet output flow-server ${ip} version-ipfix template FT`,
  'Linux / pmacct':(ip, port) => `# /etc/pmacct/pmacctd.conf\nplugins: nfprobe\nnfprobe_receiver: ${ip}:${port}\nnfprobe_version: 10\npcap_interface: eth0`,
};
// SNMP on the device, from the values in the form (stored secrets are not sent to the browser: placeholders then)
const SNMP_AUTH = ['MD5', 'SHA', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'], SNMP_PRIV = ['DES', 'AES', 'AES-192', 'AES-256'];
const SNMP_LEVELS = {noAuthNoPriv:T('no authentication, no privacy', 'без автентифікації та шифрування'), authNoPriv:T('authentication only', 'лише автентифікація'), authPriv:T('authentication + privacy', 'автентифікація + шифрування')};
const snmpVal = (s, k, ph) => s[k] || `<${ph}>`;
// the protocols each vendor's SNMP agent accepts: the form offers only these (FlowTrack itself takes all)
const SNMP_SUPPORT = {MikroTik:{auth:['MD5', 'SHA'], priv:['DES', 'AES']}, Cisco:{auth:['MD5', 'SHA', 'SHA-256', 'SHA-384', 'SHA-512'], priv:['DES', 'AES']},
  Fortinet:{priv:['DES', 'AES', 'AES-256']}, Juniper:{priv:['DES', 'AES']}};
const snmpChoices = (vendor, k) => ((SNMP_SUPPORT[vendor] || {})[k]) || (k === 'auth' ? SNMP_AUTH : SNMP_PRIV);
const SNMP_LABEL = {SHA:'SHA1', AES:'AES-128'};
// the strongest pair each vendor takes (used until the user picks a protocol)
const snmpDefaults = vendor => ({Fortinet:['SHA-256', 'AES-256'], MikroTik:['SHA', 'AES']}[vendor] || ['SHA-256', 'AES']);
// a protocol the vendor does not take moves to its strongest one
const snmpFit = (vendor, s) => { for (const [k, f] of [['auth', 'auth_proto'], ['priv', 'priv_proto']]) { const c = snmpChoices(vendor, k); if (!c.includes(s[f])) s[f] = c[c.length - 1]; } };
const SNMP_VENDORS = {
  Fortinet:(ip, s) => (s.version === '3'
    ? `config system snmp sysinfo\n    set status enable\nend\nconfig system snmp user\n    edit "${snmpVal(s, 'user', 'user')}"\n        set trap-status disable\n        # ${T('FortiOS answers SNMPv3 queries only from these hosts', 'FortiOS відповідає на запити SNMPv3 лише цим хостам')}\n        set notify-hosts ${ip}\n        set queries enable\n        set query-port ${s.port || 161}\n        set security-level ${{noAuthNoPriv:'no-auth-no-priv', authNoPriv:'auth-no-priv', authPriv:'auth-priv'}[s.level]}${s.level !== 'noAuthNoPriv' ? `\n        set auth-proto ${{MD5:'md5', SHA:'sha', 'SHA-224':'sha224', 'SHA-256':'sha256', 'SHA-384':'sha384', 'SHA-512':'sha512'}[s.auth_proto]}\n        set auth-pwd ${snmpVal(s, 'auth_pass', 'auth-password')}` : ''}${s.level === 'authPriv' ? `\n        set priv-proto ${{DES:'des', AES:'aes', 'AES-192':'aes', 'AES-256':'aes256'}[s.priv_proto]}\n        set priv-pwd ${snmpVal(s, 'priv_pass', 'priv-password')}` : ''}\n    next\nend\n# ${T('SNMP access on the interface FlowTrack reaches the device through', 'доступ SNMP на інтерфейсі, через який FlowTrack звертається до пристрою')}\nconfig system interface\n    edit "internal"\n        append allowaccess snmp\n    next\nend\n# ${T('No answer after this? Restart the SNMP agent once', 'Немає відповіді після цього? Один раз перезапустіть агент SNMP')}:\n# diagnose test application snmpd 99`
    : `config system snmp sysinfo\n    set status enable\nend\nconfig system snmp community\n    edit 1\n        set name "${snmpVal(s, 'community', 'community')}"\n        config hosts\n            edit 1\n                set ip ${ip} 255.255.255.255\n            next\n        end\n        set query-v1-status disable\n        set query-v2c-port ${s.port || 161}\n        set trap-v1-status disable\n        set trap-v2c-status disable\n    next\nend\n# ${T('SNMP access on the interface FlowTrack reaches the device through', 'доступ SNMP на інтерфейсі, через який FlowTrack звертається до пристрою')}\nconfig system interface\n    edit "internal"\n        append allowaccess snmp\n    next\nend\n# ${T('No answer after this? Restart the SNMP agent once', 'Немає відповіді після цього? Один раз перезапустіть агент SNMP')}:\n# diagnose test application snmpd 99`),
  Cisco:(ip, s) => `ip access-list standard FLOWTRACK-SNMP\n permit ${ip}\nsnmp-server ifindex persist\n` + (s.version === '3'
    ? `snmp-server group FLOWTRACK v3 ${{noAuthNoPriv:'noauth', authNoPriv:'auth', authPriv:'priv'}[s.level]} access FLOWTRACK-SNMP\nsnmp-server user ${snmpVal(s, 'user', 'user')} FLOWTRACK v3${s.level !== 'noAuthNoPriv' ? ` auth ${s.auth_proto === 'MD5' ? 'md5' : s.auth_proto === 'SHA' ? 'sha' : 'sha-2 ' + s.auth_proto.slice(4)} ${snmpVal(s, 'auth_pass', 'auth-password')}` : ''}${s.level === 'authPriv' ? ` priv ${s.priv_proto === 'DES' ? 'des' : 'aes 128'} ${snmpVal(s, 'priv_pass', 'priv-password')}` : ''}`
    : `snmp-server community ${snmpVal(s, 'community', 'community')} RO FLOWTRACK-SNMP`),
  MikroTik:(ip, s) => (s.version === '3'
    ? `/snmp community add name=${snmpVal(s, 'user', 'user')} addresses=${ip}/32 read-access=yes security=${{noAuthNoPriv:'none', authNoPriv:'authorized', authPriv:'private'}[s.level]}${s.level !== 'noAuthNoPriv' ? ` authentication-protocol=${s.auth_proto === 'SHA' ? 'SHA1' : s.auth_proto} authentication-password="${snmpVal(s, 'auth_pass', 'auth-password')}"` : ''}${s.level === 'authPriv' ? ` encryption-protocol=${s.priv_proto} encryption-password="${snmpVal(s, 'priv_pass', 'priv-password')}"` : ''}`
    : `/snmp community add name="${snmpVal(s, 'community', 'community')}" addresses=${ip}/32 read-access=yes`) + `\n/snmp set enabled=yes\n# ${T('The default firewall drops input from interfaces outside the LAN list (tunnels, WAN): let FlowTrack in', 'Стандартний фаєрвол відкидає вхідні з інтерфейсів поза списком LAN (тунелі, WAN): пропустіть FlowTrack')}\n/ip firewall filter add chain=input protocol=udp dst-port=161 src-address=${ip} action=accept place-before=0 comment=FlowTrack-SNMP`,
  Juniper:(ip, s) => (s.version === '3'
    ? `set snmp v3 usm local-engine user ${snmpVal(s, 'user', 'user')} ${s.level === 'noAuthNoPriv' ? 'authentication-none' : `authentication-${s.auth_proto.toLowerCase().replace('-', '')} authentication-password "${snmpVal(s, 'auth_pass', 'auth-password')}"`}${s.level === 'authPriv' ? `\nset snmp v3 usm local-engine user ${snmpVal(s, 'user', 'user')} privacy-${s.priv_proto === 'DES' ? 'des' : 'aes128'} privacy-password "${snmpVal(s, 'priv_pass', 'priv-password')}"` : ''}\nset snmp v3 vacm security-to-group security-model usm security-name ${snmpVal(s, 'user', 'user')} group flowtrack\nset snmp v3 vacm access group flowtrack default-context-prefix security-model usm security-level ${{noAuthNoPriv:'none', authNoPriv:'authentication', authPriv:'privacy'}[s.level]} read-view all\nset snmp view all oid .1 include`
    : `set snmp community "${snmpVal(s, 'community', 'community')}" authorization read-only\nset snmp community "${snmpVal(s, 'community', 'community')}" clients ${ip}/32`),
  'Linux / pmacct':(ip, s) => s.version === '3'
    ? `# /etc/snmp/snmpd.conf\nagentAddress udp:${s.port || 161}\nrouser ${snmpVal(s, 'user', 'user')} ${{noAuthNoPriv:'noauth', authNoPriv:'auth', authPriv:'priv'}[s.level]}\n# ${T('stop snmpd, add the user, start snmpd', 'зупиніть snmpd, додайте користувача, запустіть snmpd')}:\n# net-snmp-create-v3-user -ro${s.level !== 'noAuthNoPriv' ? ` -a ${s.auth_proto} -A '${snmpVal(s, 'auth_pass', 'auth-password')}'` : ''}${s.level === 'authPriv' ? ` -x ${s.priv_proto} -X '${snmpVal(s, 'priv_pass', 'priv-password')}'` : ''} ${snmpVal(s, 'user', 'user')}`
    : `# /etc/snmp/snmpd.conf\nagentAddress udp:${s.port || 161}\nrocommunity ${snmpVal(s, 'community', 'community')} ${ip}`,
};
const snmpTag = x => !x.snmp || !x.snmp.enabled ? '' : x.snmp.ok === false
  ? ` <span class="pill warn" title="${esc(x.snmp.error_text || '')}">${T('SNMP error', 'помилка SNMP')}</span>`
  : ` <span class="tag" title="${x.snmp.polled ? esc(T(`SNMP: ${x.snmp.interfaces} interfaces, ${x.snmp.addresses} addresses`, `SNMP: інтерфейсів ${x.snmp.interfaces}, адрес ${x.snmp.addresses}`)) : T('SNMP: waiting for the first poll', 'SNMP: чекаю на перше опитування')}">SNMP</span>`;
// ---- edition: limits in effect and the license key (admin)
const fmtInt = n => (+n || 0).toLocaleString(LOC);
const LIC_BAD = ['invalid', 'other_instance', 'returned', 'clock', 'expired'];
function copyText(text, btn){
  const done = () => { const t = btn.textContent; btn.textContent = T('Copied', 'Скопійовано'); setTimeout(() => btn.textContent = t, 1500); };
  if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done); return; }
  const ta = Object.assign(document.createElement('textarea'), {value:text}); document.body.appendChild(ta); ta.select();   // plain-HTTP installs
  try { document.execCommand('copy'); done(); } finally { ta.remove(); }
}
function saveText(name, text){
  const a = Object.assign(document.createElement('a'), {href:URL.createObjectURL(new Blob([text], {type:'text/plain'})), download:name});
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); });
}
async function editionPanel(returned){
  const box = document.getElementById('edBox'); if (!box) return;
  let ed; try { ed = await api('edition'); } catch (e) { box.innerHTML = errBox(e); box.classList.remove('loading'); return; }
  if (!box.isConnected) return;
  const pro = ed.status === 'active', lic = ed.license || {};
  const name = pro ? 'FlowTrack Pro' : 'FlowTrack Community';
  const status = {community:T('free edition', 'безкоштовна редакція'), active:T('license active', 'ліцензія активна'),
    invalid:T('the license is not valid', 'ліцензія недійсна'), other_instance:T('license of another server', 'ліцензія іншого сервера'),
    returned:T('license deactivated', 'ліцензію деактивовано'), clock:T('the clock is wrong', 'неправильний годинник'),
    expired:T('license expired — Community limits apply', 'ліцензія закінчилась — діють ліміти Community'),
    unconfirmed:T('not confirmed by the license server — Community limits apply', 'не підтверджено сервером ліцензій — діють ліміти Community')}[ed.status] || ed.status;
  const fmtDay = t => new Date(t * 1000).toLocaleDateString(LOC, {day:'numeric', month:'long', year:'numeric'});
  const chk = ed.last_checkin, online = ed.online ? `<div class="lic-online"><span class="nat">${
    ed.lease_until ? T(`Online license · confirmed by the license server until ${fmtDay(ed.lease_until)}`, `Онлайн-ліцензія · підтверджена сервером ліцензій до ${fmtDay(ed.lease_until)}`)
                   : T('Online license · not confirmed by the license server', 'Онлайн-ліцензія · не підтверджена сервером ліцензій')}${
    chk ? ' · ' + (chk.ok ? T('last check ', 'остання перевірка ') + new Date(chk.ts * 1000).toLocaleString(LOC) : T('last check failed: ', 'остання перевірка не вдалась: ') + esc(chk.error)) : ''}</span>${
    isAdmin() ? `<button class="btn" id="licCheck">${T('Check now', 'Перевірити зараз')}</button>` : ''}</div>`
    // an offline (or expired) license never contacts the server by itself: ask on request whether the vendor renewed it
    : lic.customer && isAdmin() ? `<div class="lic-online"><span class="nat">${T('Offline license · FlowTrack does not contact the license server by itself', 'Офлайн-ліцензія · FlowTrack сам не звертається до сервера ліцензій')}</span><button class="btn" id="licCheck">${T('Check for renewal', 'Перевірити оновлення')}</button></div>` : '';
  const note = window.__licNote; window.__licNote = null;
  const noteHtml = note ? `<p class="note" role="status" style="color:${note.renewed ? 'var(--ok)' : note.error ? 'var(--crit)' : 'inherit'}">${esc(note.note)}</p>` : '';
  const soon = pro && lic.days_left != null && lic.days_left < 30;
  const until = lic.expires ? new Date(lic.expires * 1000).toLocaleDateString(LOC, {day:'numeric', month:'long', year:'numeric', timeZone:'UTC'}) : '';   // licenses end at 23:59 UTC of their last day
  box.innerHTML = `<div class="edition">
    <div class="ed-name"><b>${name}</b><span class="pill ${pro ? 'ok' : ed.status === 'community' ? 'info' : 'crit'}">${esc(status)}</span>${soon ? `<span class="pill warn">${T(`ends in ${lic.days_left} day${lic.days_left === 1 ? '' : 's'}`, `закінчується через ${lic.days_left} дн.`)}</span>` : ''}${ed.message ? `<span class="nat">${esc(ed.message)}</span>` : ''}</div>
    <div class="ed-lim">
      <div><span>${T('Records per second', 'Записів за секунду')}</span><b>${ed.rps ? T('up to ', 'до ') + fmtInt(ed.rps) : T('no limit', 'без обмежень')}</b></div>
      <div title="${T(`New records are kept this long. Records already stored keep their own term and are never shortened; without a license only the last ${ed.community_days || 30} days are shown, older records show again with a license.`, `Нові записи зберігаються стільки днів. Уже збережені записи мають свій строк, і він ніколи не скорочується; без ліцензії видно лише останні ${ed.community_days || 30} днів, старіші записи знову видно з ліцензією.`)}"><span>${T('Flow details kept', 'Деталі потоків зберігаються')}</span><b>${ed.retention_days} ${T('days', 'днів')}${ed.view_days > ed.retention_days ? ` <small>${T(`(earlier records: the last ${ed.view_days} days shown)`, `(видно записи за останні ${ed.view_days} днів)`)}</small>` : ''}</b></div>
      <div><span>${T('Not stored over the limit, 24 h', 'Не збережено понад ліміт, 24 год')}</span><b class="${ed.license_drops_24h ? 'warnc' : ''}">${fmtInt(ed.license_drops_24h)}</b></div>
      ${lic.customer ? `<div><span>${T('Licensed to', 'Ліцензіат')}</span><b>${esc(lic.customer)}</b></div><div><span>${pro ? T('Valid until', 'Діє до') : ed.status === 'expired' ? T('Expired on', 'Закінчилась') : T('Term', 'Термін')}</span><b class="${soon || !pro ? 'warnc' : ''}">${until}</b></div>` : ''}
    </div>${online}${noteHtml}
  </div>`;
  box.classList.remove('loading');
  const lc = document.getElementById('licCheck'); if (lc) lc.onclick = async () => { lc.disabled = true; lc.textContent = T('Checking…', 'Перевіряю…');
    try { window.__licNote = (await apiPost('license/checkin', {})).checked; } catch (e) { window.__licNote = {error:true, note:e.message}; }
    META = await fetch('api/meta').then(r => r.json()); editionBadge(); editionPanel(); };
  const act = document.getElementById('actBox'); if (!act || !isAdmin()) return;
  // activation: this server's identity and request on the left, the license from the vendor on the right
  act.innerHTML = `<div class="lic-grid">
    <div class="lic-col">
      <div class="lic-step"><span class="lic-n">1</span><div><b>${T('Send the activation request', 'Надішліть запит на активацію')}</b>
        <p class="note">${T('Not needed with a license key. Without internet access, send it to your FlowTrack vendor — by e-mail, or read it out by phone from a closed network. The license will work on this server only.', 'З ліцензійним ключем не потрібен. Без доступу до інтернету надішліть його постачальнику FlowTrack — поштою або продиктуйте телефоном із закритої мережі. Ліцензія діятиме лише на цьому сервері.')}</p></div></div>
      <div class="lic-field"><span>${T('Instance ID', 'ID інсталяції')}</span><code class="mono" id="licInst">${esc(ed.instance || '')}</code></div>
      <div class="lic-field"><span>${T('Activation request', 'Запит на активацію')}</span><code class="mono lic-code" id="licReq">${esc(ed.request || '')}</code></div>
      <div class="acts"><button class="btn" id="reqCopy">${T('Copy', 'Копіювати')}</button><button class="btn" id="reqSave">${T('Download', 'Завантажити')}</button></div>
    </div>
    <div class="lic-col">
      <div class="lic-step"><span class="lic-n">2</span><div><b>${pro ? T('Enter a renewed license', 'Введіть подовжену ліцензію') : T('Enter the license', 'Введіть ліцензію')}</b>
        <p class="note">${T('Paste the license key (FTK-…): FlowTrack activates it online. Or load the .lic file (or paste the FTL-… code) from your vendor: it works at once and is then confirmed by the license server daily — only an offline license never needs the internet.', 'Вставте ліцензійний ключ (FTK-…) — FlowTrack активує його онлайн. Або завантажте файл .lic (чи вставте код FTL-…) від постачальника: він діє одразу, а далі його щодня підтверджує сервер ліцензій — інтернет не потрібен лише для офлайн-ліцензії.')}</p></div></div>
      <textarea id="edKey" rows="4" spellcheck="false" autocomplete="off" placeholder="FTK-XXXXX-… / FTL-XXXXX-…" aria-label="${T('License key or code', 'Ліцензійний ключ або код')}"></textarea>
      <div class="acts"><span class="nat" id="edMsg" role="status"></span><input type="file" id="licFile" accept=".lic,.txt,text/plain" hidden>
        <button class="btn" id="licLoad">${T('Load file…', 'Завантажити файл…')}</button><button class="btn primary" id="edSave">${T('Activate', 'Активувати')}</button></div>
    </div>
  </div>
  ${returned === 'released' ? `<div class="lic-return" role="alert"><b>${T('The license was deactivated on this server', 'Ліцензію на цьому сервері деактивовано')}</b>
    <p class="note">${T('The license key is free again: enter it on the other server.', 'Ліцензійний ключ знову вільний: введіть його на іншому сервері.')}</p></div>` : ''}
  ${returned && returned !== 'released' ? `<div class="lic-return" role="alert"><b>${T('The license was deactivated on this server', 'Ліцензію на цьому сервері деактивовано')}</b>
    <p class="note">${T('Send this return code to your vendor to get the license for another server. This server will not accept that license again.', 'Надішліть цей код повернення постачальнику, щоб отримати ліцензію для іншого сервера. Цей сервер більше не прийме цю ліцензію.')}</p>
    <div class="lic-field"><code class="mono lic-code" id="retCode">${esc(returned)}</code></div><div class="acts"><button class="btn" id="retCopy">${T('Copy', 'Копіювати')}</button></div></div>` : ''}
  ${ed.status !== 'community' ? `<div class="lic-move"><div><b>${T('Move the license to another server', 'Перенести ліцензію на інший сервер')}</b>
    <p class="note">${ed.online ? T('Deactivation removes the license from this server and frees the license key for another one. Community limits apply here again; stored data is kept.', 'Деактивація знімає ліцензію з цього сервера і звільняє ліцензійний ключ для іншого. Тут знову діятимуть ліміти Community; збережені дані лишаться.')
      : T('Deactivation removes the license from this server and gives a return code for the vendor. Community limits apply here again; stored data is kept.', 'Деактивація знімає ліцензію з цього сервера і дає код повернення для постачальника. Тут знову діятимуть ліміти Community; збережені дані лишаться.')}</p></div>
    <button class="btn danger" id="licOff">${ed.status === 'active' ? T('Deactivate…', 'Деактивувати…') : T('Remove…', 'Видалити…')}</button></div>` : ''}`;
  const say = (t, c) => { const m = document.getElementById('edMsg'); m.textContent = t; m.style.color = c || ''; };
  const refresh = async ret => { META = await fetch('api/meta').then(r => r.json()); editionBadge(); editionPanel(ret); };
  document.getElementById('reqCopy').onclick = e => copyText(ed.request, e.currentTarget);
  document.getElementById('reqSave').onclick = () => saveText(`flowtrack-request-${(ed.instance || '').replace(/-/g, '')}.txt`,
    `# FlowTrack activation request\n# Instance ID: ${ed.instance}\n# FlowTrack ${META.version || ''}, ${new Date().toISOString().slice(0, 10)}\n${ed.request}\n`);
  const file = document.getElementById('licFile');
  document.getElementById('licLoad').onclick = () => file.click();
  file.onchange = async () => { const f = file.files[0]; if (!f) return; document.getElementById('edKey').value = (await f.text()).trim(); file.value = ''; say(f.name); };
  document.getElementById('edSave').onclick = async () => { const k = document.getElementById('edKey').value.trim();
    if (!k) return say(T('Paste the license key or code first', 'Спершу вставте ліцензійний ключ або код'), 'var(--crit)');
    say(/^\s*ftk/i.test(k) ? T('Activating at the license server…', 'Активую на сервері ліцензій…') : T('Checking…', 'Перевіряю…'));
    try { await apiPost('license', {key:k}); await refresh(); } catch (e) { say(e.message, 'var(--crit)'); } };
  const rc = document.getElementById('retCopy'); if (rc) rc.onclick = e => copyText(returned, e.currentTarget);
  const off = document.getElementById('licOff'); if (off) off.onclick = async () => {
    if (ed.status !== 'active') {           // a license that does not work here: just remove it
      if (!confirm(T('Remove the license from this server?', 'Видалити ліцензію з цього сервера?'))) return;
      try { await apiPost('license', {key:''}); await refresh(); } catch (e) { alert(e.message); } return; }
    if (!confirm(T('Deactivate the license on this server? Community limits apply here again, and this server will not accept this license again. You get a return code to move the license to another server.',
      'Деактивувати ліцензію на цьому сервері? Тут знову діятимуть ліміти Community, і цей сервер більше не прийме цю ліцензію. Ви отримаєте код повернення, щоб перенести ліцензію на інший сервер.'))) return;
    try { const r = await apiPost('license/deactivate', {}); await refresh(r.released ? 'released' : r.return_code); } catch (e) { alert(e.message); } };
}
// edition badge under the logo: Community / Pro, coloured when a license ends soon or has ended; opens the license panel
function editionBadge(){
  const b = document.getElementById('edBadge'), ed = META.edition; if (!b || !ed) return;
  const pro = ed.status === 'active', left = ed.days_left;
  b.textContent = pro ? 'Pro' : 'Community';
  b.className = 'edbadge' + (pro ? ' pro' : '') + (pro && left != null && left < 30 ? ' warn' : '') + (LIC_BAD.includes(ed.status) ? ' crit' : '');
  b.title = (pro ? 'FlowTrack Pro' + (left != null ? T(` · ${left} days left`, ` · лишилось днів: ${left}`) : '') : `FlowTrack Community · ${T('up to', 'до')} ${fmtInt(ed.rps)} ${T('records/s', 'записів/с')}`)
    + (ed.status === 'expired' ? T(' · license expired', ' · ліцензія закінчилась') : LIC_BAD.includes(ed.status) ? T(' · the license does not work here', ' · ліцензія тут не діє') : '') + ' — ' + T('edition and license', 'редакція і ліцензія');
  b.hidden = false;
  b.onclick = () => { state.view = 'settings'; state.setTab = 'license'; render(); };
}
// ===================== settings: one page, tabs on top =====================
const SET_TABS = () => [['general', T('General', 'Загальні'), ICO.grid], ['devices', T('Devices', 'Пристрої'), DEV_ICON],
  ...(isAdmin() ? [['users', T('Users', 'Користувачі'), USER_ICON]] : []), ['license', T('License', 'Ліцензія'), ICO.shield]];
function vSettings(){
  const tabs = SET_TABS(); if (!tabs.some(t => t[0] === state.setTab)) state.setTab = 'general';
  document.getElementById('view').innerHTML = `<nav class="settabs glass" role="tablist" aria-label="${T('Settings', 'Налаштування')}">${tabs.map(([k, l, ic]) =>
    `<button role="tab" data-tab="${k}" aria-selected="${k === state.setTab}" ${k === state.setTab ? '' : 'tabindex="-1"'}>${icon(ic, 16)}${l}</button>`).join('')}</nav><div id="setBody"></div>`;
  const bar = document.querySelector('.settabs');
  bar.querySelectorAll('button').forEach(b => b.onclick = () => { if (b.dataset.tab === state.setTab) return;
    if (state.ifEdit && !confirm(T('Discard unsaved interface changes?', 'Скасувати незбережені зміни інтерфейсів?'))) return;
    state.setTab = b.dataset.tab; render(); });
  bar.addEventListener('keydown', e => { if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;   // arrow keys move between tabs
    const i = tabs.findIndex(t => t[0] === state.setTab), n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length][0];
    state.setTab = n; render(); setTimeout(() => { const b = document.querySelector(`.settabs [data-tab="${n}"]`); if (b) b.focus(); }); });
  ({general:vGeneral, devices:vDevices, users:vUsers, license:vLicense})[state.setTab]();
}
function vGeneral(){
  const ed = META.edition || {};
  document.getElementById('setBody').innerHTML = `<div class="grid top">
    <section class="glass panel s6">${ph('globe', T('Language', 'Мова'), T('of this browser · other users keep their own', 'цього браузера · інші користувачі мають свою'))}
      <div class="seg" id="langSeg" role="group">${[['en', 'English'], ['uk', 'Українська']].map(([v, l]) => `<button data-v="${v}" aria-pressed="${LANG === v}">${l}</button>`).join('')}</div></section>
    <section class="glass panel s6">${ph('list', T('About', 'Про програму'), T('version and edition', 'версія і редакція'))}
      <div class="about">
        <div><span>${T('Version', 'Версія')}</span><b class="mono">FlowTrack ${esc(META.version || '—')}</b></div>
        <div><span>${T('Edition', 'Редакція')}</span><b>${ed.status === 'active' ? 'Pro' : 'Community'}</b><button class="lnk" id="toLic">${T('License', 'Ліцензія')} →</button></div>
        <div><span>${T('Source code', 'Код')}</span><a href="https://github.com/henzelis/flowtrack" target="_blank" rel="noopener">github.com/henzelis/flowtrack</a></div>
        <div><span>${T('Account', 'Обліковий запис')}</span><b class="mono">${esc(ME.name)}</b><button class="lnk" id="myPass">${T('Change my password', 'Змінити мій пароль')}</button></div>
      </div></section></div>`;
  document.querySelectorAll('#langSeg button').forEach(b => b.onclick = () => { if (b.dataset.v !== LANG) setLang(b.dataset.v); });
  document.getElementById('toLic').onclick = () => { state.setTab = 'license'; render(); };
  document.getElementById('myPass').onclick = openPassword;
}
function vLicense(){
  document.getElementById('setBody').innerHTML = `<div class="grid"><section class="glass panel s12">${ph('shield', T('Edition and license', 'Редакція і ліцензія'), T('limits in effect · a FlowTrack Pro license raises them', 'чинні ліміти · ліцензія FlowTrack Pro їх знімає'))}<div id="edBox" class="loading"></div></section>
    ${isAdmin() ? `<section class="glass panel s12">${ph('key', T('Activation', 'Активація'), T('the license is bound to this server · a key or a license file', 'ліцензія прив’язується до цього сервера · ключ або файл ліцензії'))}<div id="actBox"></div></section>` : ''}</div>`;
  editionPanel();
}
function vDevices(){
  const v = document.getElementById('setBody'); state.ifEdit = null;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('dev', T('Exporter devices', 'Пристрої-експортери'), T('NetFlow v5/v9 and IPFIX from any vendor · statistics for 15 min', 'NetFlow v5/v9 та IPFIX від будь-якого виробника · статистика за 15 хв'), isAdmin() ? `<button class="btn primary" id="addDev">${T('+ Connect a device', '+ Підключити пристрій')}</button>` : `<span class="nat">${T('an administrator can add devices', 'додавати пристрої може адміністратор')}</span>`)}<div id="dBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('ip', T('Interfaces', 'Інтерфейси'), T('indexes the collector saw in 24 h · the WAN role defines what is upload and download', 'індекси, які колектор бачив за 24 год · роль WAN визначає, що таке upload і download'))}<div id="ifBox" class="loading"></div></section>
</div>`;
  if (isAdmin()) document.getElementById('addDev').onclick = () => openDevice(null);
  section('dBox', async () => { const res = await api('devices'), d = res.devices; window.__devs = d; window.__snmpTools = res.snmp_tools;
    // the interfaces panel shows one device: the one picked in the table, else the global device filter, else the first
    const df = state.filters.find(f => f.k === 'device' && !f.neg);
    if (!d.some(x => x.ip === state.ifDev)) state.ifDev = (d.find(x => df && x.ip === df.v) || d.find(x => x.interfaces.length) || d[0] || {}).ip;
    setTimeout(() => {
      showIfaces(d);
      document.querySelectorAll('#dBox tr[data-pick]').forEach(tr => tr.onclick = () => { if (tr.dataset.pick === state.ifDev) return; if (state.ifEdit && !confirm(T('Discard unsaved interface changes?', 'Скасувати незбережені зміни інтерфейсів?'))) return; state.ifEdit = null; state.ifDev = tr.dataset.pick; showIfaces(d); });
      document.querySelectorAll('[data-edit]').forEach(b => b.onclick = e => { e.stopPropagation(); openDevice(d.find(x => x.ip === b.dataset.edit)); });
    });
    return `<div class="tw"><table><thead><tr><th>${T('Status', 'Стан')}</th><th>${T('Device', 'Пристрій')}</th><th>${T('Vendor / model', 'Виробник / модель')}</th><th>${T('Protocol', 'Протокол')}</th><th>${T('Site', 'Майданчик')}</th><th>${T('Export IP', 'IP експорту')}</th><th class="num">${T('Records/s', 'Записів/с')}</th><th class="num">${T('Templates', 'Шаблони')}</th><th>${T('Sampling', 'Вибірка')}</th><th class="num">${T('Loss', 'Втрати')}</th><th class="num">${T('No template', 'Без шаблону')}</th>${isAdmin() ? '<th></th>' : ''}</tr></thead><tbody>
      ${d.map(x => { const never = !x.last, stale = Date.now() / 1000 - x.last > 180, st = never ? 'warn' : stale ? 'crit' : x.loss_pct > 0.5 ? 'warn' : '';
        return `<tr class="click" data-pick="${esc(x.ip)}"><td><span class="dot ${st}" title="${never ? T('has not sent data yet', 'ще не надсилав даних') : stale ? T('no data for over 3 min', 'немає даних понад 3 хв') : T('online', 'онлайн')}"></span></td><td><b class="mono">${esc(x.name)}</b>${x.configured ? '' : ` <span class="tag">${T('not described', 'не описаний')}</span>`}${snmpTag(x)}${dupPill(x)}${repeatPill(x)}</td><td>${esc(x.vendor || '—')}<br><span class="nat">${esc(x.model)}</span></td><td><span class="tag">${never ? T('waiting', 'очікую') : esc(x.proto)}</span></td><td>${esc(x.site || '—')}</td><td class="ipl">${esc(x.ip)}</td>
          <td class="num mono">${x.rps}</td><td class="num mono">${x.templates}</td><td class="mono">${esc(x.sampling)}</td><td class="num mono" style="color:${x.loss_pct ? 'var(--warn)' : 'inherit'}">${x.loss_pct}%</td><td class="num mono">${x.no_template}</td>
          ${isAdmin() ? `<td><button class="btn" data-edit="${esc(x.ip)}">${T('Edit', 'Змінити')}</button></td>` : ''}</tr>`; }).join('') || `<tr><td colspan="12"><div class="empty">${T('No device has sent data yet', 'Ще жоден пристрій не надіслав дані')}</div></td></tr>`}</tbody></table></div>${collectorBar(res.collector, res.listen)}<p class="note">${T('Click a row to see the device’s interfaces below. To filter by device, use the device list at the top.', 'Клік по рядку показує інтерфейси пристрою нижче. Фільтр за пристроєм — у списку пристроїв угорі.')}${isAdmin() ? T(' The collector picks up description changes within a minute.', ' Зміни опису колектор підхоплює протягом хвилини.') : ''}</p>`; });
}
// duplicates: removed ones (direction field present) or a warning when the exporter reports flows twice
const dupPill = x => x.dup_pct >= 2
  ? ` <span class="pill warn" title="${T(`${x.dup_pct}% of the records in 15 min arrive twice. The device monitors both directions on several interfaces but sends no direction field, so the copies cannot be told apart: add the flow direction field to the exported record, or monitor ingress only.`, `${x.dup_pct}% записів за 15 хв приходять двічі. Пристрій стежить за обома напрямками на кількох інтерфейсах, але не передає поле напрямку, тож копії не відрізнити: додайте поле напрямку в запис експорту або залиште лише вхідний напрямок.`)}">${T(`duplicates ${x.dup_pct}%`, `дублікати ${x.dup_pct}%`)}</span>`
  : x.dup_dropped ? ` <span class="pill info" title="${T('Copies of flows seen on ingress and again on egress, removed by the collector (15 min)', 'Копії потоків, побачених на вході й ще раз на виході, які колектор відкинув (за 15 хв)')}">${T(`${fmtN(x.dup_dropped)} duplicates removed`, `відкинуто дублікатів: ${fmtN(x.dup_dropped)}`)}</span>` : '';
// whole packets the exporter sent more than once (same content, own sequence counter): dropped by the receiver
const repeatPill = x => x.dup_packets ? ` <span class="pill warn" title="${T(`The device sent ${fmtN(x.dup_packets)} packets in 15 min a second time with the same content. FlowTrack dropped the copies, so traffic and loss are not affected. The device's export is misbehaving: check its NetFlow targets or restart its flow export.`, `Пристрій за 15 хв надіслав ${fmtN(x.dup_packets)} пакетів повторно з тим самим вмістом. FlowTrack відкинув копії, тож трафік і втрати не спотворені. Експорт на пристрої працює неправильно: перевірте цілі NetFlow або перезапустіть експорт.`)}">${T(`${fmtN(x.dup_packets)} repeated packets dropped`, `відкинуто повторних пакетів: ${fmtN(x.dup_packets)}`)}</span>` : '';
// where devices must send NetFlow: the collector's own interface address when it listens on specific interfaces
// (the web UI may be on another one), otherwise the address this page was opened with
function collectorTarget(){
  const nf = (META.listen || {}).netflow, addrs = nf ? nf.listen.flatMap(x => x.addrs) : [];
  return [addrs.find(a => !a.includes(':')) || addrs[0] || location.hostname, nf ? nf.port : 2055];
}
const listenText = l => !l ? '—' : l.listen.map(x => x.iface ? x.iface + (x.addrs.length ? ` (${x.addrs.join(', ')})` : '') : x.addrs.join(', ') || T('all interfaces', 'усі інтерфейси')).join('; ');
// receiver health: workers, socket buffer and every place a packet can be lost on the way to the database
function collectorBar(c, listen){
  const nf = listen && listen.netflow, web = listen && listen.web;
  const where = (nf || web) ? `<div class="collbar-where">${nf ? `<span>${T('NetFlow/IPFIX received on', 'Прийом NetFlow/IPFIX')}: <b class="mono">UDP ${nf.port} · ${esc(listenText(nf))}</b></span>` : ''}${web ? `<span>${T('Web interface', 'Вебінтерфейс')}: <b class="mono">TCP ${web.port} · ${esc(listenText(web))}</b></span>` : ''}</div>` : '';
  if (!c) return where ? `<div class="collbar">${where}</div>` : '';
  const lost = c.socket_drops + c.queue_drops, pct = 100 * lost / Math.max(1, c.packets + lost), fill = c.rcvbuf ? Math.round(100 * c.rx_queue_peak / c.rcvbuf) : 0;
  const cell = (k, v, tip, bad) => `<div title="${esc(tip)}"><span>${k}</span><b class="mono"${bad ? ' style="color:var(--warn)"' : ''}>${v}</b></div>`;
  return `<div class="collbar"><div class="collbar-h"><b>${T('Collector', 'Колектор')}</b><span class="nat">${T(`last ${c.minutes} min`, `за ${c.minutes} хв`)}</span></div>
    ${cell(T('Workers', 'Воркери'), c.workers, T('Processes that decode packets (FT_WORKERS in /etc/flowtrack/env)', 'Процеси, що декодують пакети (FT_WORKERS у /etc/flowtrack/env)'), !c.workers)}
    ${cell(T('Packets received', 'Пакетів прийнято'), c.packets.toLocaleString(LOC), T('Datagrams read from the socket', 'Датаграми, прочитані із сокета'))}
    ${cell(T('Dropped by socket', 'Відкинуто сокетом'), c.socket_drops.toLocaleString(LOC), T('The kernel dropped packets: the socket buffer was full (the collector fell behind or a burst exceeded the buffer)', 'Ядро відкинуло пакети: буфер сокета був повний (колектор не встигав або сплеск більший за буфер)'), c.socket_drops)}
    ${cell(T('Dropped by queue', 'Відкинуто чергою'), c.queue_drops.toLocaleString(LOC), T('The workers could not take packets in time', 'Воркери не встигали забирати пакети'), c.queue_drops)}
    ${cell(T('Records lost', 'Втрачено записів'), c.dropped_rows.toLocaleString(LOC), T('Records that could not be stored: ClickHouse was unavailable for too long', 'Записи, які не вдалося зберегти: ClickHouse був недоступний занадто довго'), c.dropped_rows)}
    ${cell(T('Socket buffer', 'Буфер сокета'), T(`${fmtB(c.rcvbuf)} · peak ${fill}%`, `${fmtB(c.rcvbuf)} · пік ${fill}%`), T('Receive buffer size and its highest fill (net.core.rmem_max limits the size)', 'Розмір буфера прийому і найбільше його заповнення (net.core.rmem_max обмежує розмір)'), fill > 50)}
    ${cell(T('Loss', 'Втрати'), (lost ? pct.toFixed(pct < 0.01 ? 3 : 2) : '0') + '%', T('Share of packets the collector did not process', 'Частка пакетів, які колектор не обробив'), lost)}${where}</div>`;
}
// generic centered dialog; returns {root, close}
const ROLE_UI = {lan:'LAN', wan:T('WAN (internet)', 'WAN (інтернет)'), local:T('The device itself', 'Сам пристрій')};
function showIfaces(devices){
  document.querySelectorAll('#dBox tr[data-pick]').forEach(tr => tr.classList.toggle('picked', tr.dataset.pick === state.ifDev));
  const x = devices.find(d => d.ip === state.ifDev), box = document.getElementById('ifBox'); if (!box) return;
  box.classList.remove('loading');
  if (!x) { box.innerHTML = `<div class="empty">${T('No device has sent data yet', 'Ще жоден пристрій не надіслав дані')}</div>`; return; }
  box.innerHTML = ifaceTable(x, state.ifEdit === x.ip);
  wireIfaces(box, x, devices);
}
const addrHtml = i => {
  const sa = i.addrs.length ? [] : (i.snmp_addrs || []), known = [...i.addrs, ...sa];
  const own = [...i.addrs.map(a => `<b class="mono">${esc(a)}</b>`), ...sa.map(a => `<span class="mono" title="SNMP">${esc(a)}</span>`)];
  const seen = known.length ? [] : i.seen_addrs;
  const auto = seen.map(a => `<span class="mono nat" title="${a.includes('/') ? T('network that sends traffic into this interface (24 h)', 'мережа, з якої приходить трафік у цей інтерфейс (за 24 год)') : T('NAT address traffic leaves this interface with (24 h)', 'адреса NAT, з якою трафік виходить через цей інтерфейс (за 24 год)')}">${esc(a)}</span>`);
  return [...own, ...auto].join('<br>') || '<span class="nat">—</span>';
};
function ifaceTable(x, edit){
  const admin = isAdmin(), total = x.interfaces.reduce((a, i) => a + i.bytes, 0) || 1;
  // suggest the interface that clearly carries the most internet-facing traffic
  const ranked = [...x.interfaces].filter(i => i.bytes > 0.02 * total).sort((a, b) => b.ext_share - a.ext_share);
  const best = ranked[0] && ranked[0].ext_share >= 0.3 && ranked[0].ext_share >= 3 * ((ranked[1] || {}).ext_share || 0) ? ranked[0].index : null;
  const rows = x.interfaces.map(i => {
    const hint = i.index === best && i.role !== 'wan' ? `<span class="pill info" title="${T(`${Math.round(i.ext_share * 100)}% of this interface’s traffic is from/to public addresses; much less on the others`, `${Math.round(i.ext_share * 100)}% трафіку цього інтерфейсу — з/до публічних адрес; у решти значно менше`)}">${T('looks like WAN', 'схоже на WAN')}</span>` : '';
    const name = edit ? `<input class="ifname" data-idx="${i.index}" value="${esc(i.custom_name)}" placeholder="${esc(i.snmp_name || (i.role === 'local' ? 'local' : 'if ' + i.index))}" maxlength="32" aria-label="${T(`Interface ${i.index} name`, `Назва інтерфейсу ${i.index}`)}">`
                      : `<b class="ipl"${i.snmp_alias ? ` title="${esc(i.snmp_alias)}"` : ''}>${esc(i.name)}</b>${i.snmp_up === false ? ` <span class="tag" title="ifOperStatus">${T('down', 'вимкнено')}</span>` : ''}${i.snmp_alias && i.snmp_alias !== i.name ? `<div class="nat">${esc(i.snmp_alias)}</div>` : ''}`;
    const role = edit ? `<select class="ifrole" data-idx="${i.index}" aria-label="${T(`Interface ${i.index} role`, `Роль інтерфейсу ${i.index}`)}">${Object.entries(ROLE_UI).map(([k, l]) => `<option value="${k}"${k === i.role ? ' selected' : ''}>${l}</option>`).join('')}</select>`
                      : (i.role === 'wan' ? '<span class="pill warn">WAN</span>' : i.role === 'local' ? `<span class="tag">${T('the device itself', 'сам пристрій')}</span>` : '<span class="tag">LAN</span>');
    const addrs = edit ? `<input class="ifaddr" data-idx="${i.index}" value="${esc(i.addrs.join(', '))}" placeholder="${esc((i.snmp_addrs || []).join(', ') || T('IP or IP/mask, comma-separated', 'IP або IP/маска, через кому'))}" aria-label="${T(`Interface ${i.index} IP addresses`, `IP-адреси інтерфейсу ${i.index}`)}">${i.seen_addrs.length ? `<div class="nat ifseen">${T('in the data', 'у даних')}: ${i.seen_addrs.map(esc).join(', ')}</div>` : ''}`
                       : addrHtml(i);
    const unseen = i.unseen ? ` <span class="pill warn" title="${T('The index is in the settings but did not appear in the data for 24 h — it may be wrong', 'Індекс є в налаштуваннях, але в даних за 24 год не траплявся — можливо, його вказано помилково')}">${T('not seen in 24 h', 'не бачили за 24 год')}</span>` : '';
    return `<tr${i.unseen ? ' class="unseen"' : ''}><td class="num mono">${i.index}</td><td>${name}</td><td>${addrs}</td><td>${role} ${hint}${unseen}</td><td class="num mono">${i.unseen ? '—' : fmtB(i.bytes)}</td><td class="num mono">${i.unseen ? '—' : Math.round(i.ext_share * 100) + '%'}</td></tr>`;
  }).join('');
  const sn = x.snmp || {}, when = t => new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'});
  const snmpLine = !sn.enabled ? '' : `<div class="ifsnmp">${sn.polled ? (sn.ok ? `<span class="pill ok">SNMP</span> <span class="nat">${esc(sn.sys && sn.sys.name || '')}${sn.sys && sn.sys.name ? ' · ' : ''}${T(`${sn.interfaces} interfaces, ${sn.addresses} addresses · polled ${when(sn.polled)}`, `інтерфейсів ${sn.interfaces}, адрес ${sn.addresses} · опитано ${when(sn.polled)}`)}</span>`
      : `<span class="pill warn" title="${esc(sn.detail || '')}">${T('SNMP error', 'помилка SNMP')}</span> <span class="nat">${esc(sn.error_text || '')}${sn.last_ok ? ' · ' + T(`last good poll ${when(sn.last_ok)}`, `останнє вдале опитування ${when(sn.last_ok)}`) : ''}</span>`)
      : `<span class="pill info">SNMP</span> <span class="nat">${T('waiting for the first poll', 'чекаю на перше опитування')}</span>`}${admin && !edit ? ` <button class="btn snmppoll">${T('Poll now', 'Оновити зараз')}</button>` : ''}</div>`;
  const btns = !admin || !x.interfaces.length ? '' : edit ? `<span class="nat ifmsg"></span><button class="btn ifcancel">${T('Cancel', 'Скасувати')}</button><button class="btn primary ifsave" disabled>${T('Save', 'Зберегти')}</button>`
                                                           : `<span class="nat ifmsg"></span><button class="btn ifedit">${T('Edit', 'Змінити')}</button>`;
  return `<div class="ifdev${edit ? ' editing' : ''}" data-dev="${esc(x.ip)}"><div class="ifdev-h"><h4 class="mono">${esc(x.name)} <span class="nat">${esc(x.ip)}${x.vendor ? ' · ' + esc(x.vendor) : ''}</span></h4>${btns}</div>${snmpLine}
    ${x.interfaces.length ? `<div class="tw"><table class="compact"><thead><tr><th class="num">${T('Index', 'Індекс')}</th><th>${T('Name', 'Назва')}</th><th>${T('IP addresses', 'IP-адреси')}</th><th>${T('Role', 'Роль')}</th><th class="num">${T('Traffic, 24 h', 'Трафік за 24 год')}</th><th class="num" title="${T('Share of traffic with outside addresses', 'Частка трафіку із зовнішніми адресами')}">${T('Ext.', 'Зовн.')}</th></tr></thead><tbody>${rows}</tbody></table></div>
    <p class="note">${T('Bold: addresses entered by hand; plain: read over SNMP; grey (when neither is known): what the flows of the last 24 h show — the NAT address traffic leaves to the internet with (this is how a WAN usually looks) and the networks that send traffic into the interface. Names and addresses entered by hand take priority over SNMP.', 'Жирним — адреси, вказані вручну; звичайним — отримані по SNMP; сірим (коли інших немає) — те, що видно з потоків за 24 год: адреса NAT, з якою трафік виходить в інтернет (так зазвичай виглядає WAN), і мережі, з яких трафік приходить в інтерфейс. Назви й адреси, вписані вручну, мають перевагу над SNMP.')}</p>`
      : `<div class="empty">${T('The collector has not seen interfaces of this device yet (24 h)', 'Колектор ще не бачив інтерфейсів цього пристрою (за 24 год)')}</div>`}</div>`;
}
function wireIfaces(box, x, devices){
  const card = box.querySelector('.ifdev'), msg = card.querySelector('.ifmsg');
  const say = (t, color) => { if (msg) { msg.textContent = t; msg.style.color = color || ''; } };
  const poll = card.querySelector('.snmppoll');
  if (poll) poll.onclick = async () => { poll.disabled = true; poll.textContent = T('Polling…', 'Опитую…');
    try { await apiPost('devices/snmp_poll', {ip:x.ip}); const fresh = (await api('devices')).devices, i = devices.findIndex(d => d.ip === x.ip), nx = fresh.find(d => d.ip === x.ip);
      if (i >= 0 && nx) devices[i] = nx; META = await fetch('api/meta').then(r => r.json()); showIfaces(devices);
    } catch (e) { poll.disabled = false; poll.textContent = T('Poll now', 'Оновити зараз'); say(e.message, 'var(--crit)'); } };
  const edit = card.querySelector('.ifedit'); if (edit) edit.onclick = () => { state.ifEdit = x.ip; showIfaces(devices); const f = box.querySelector('.ifname'); if (f) f.focus(); };
  const cancel = card.querySelector('.ifcancel'); if (cancel) cancel.onclick = () => { state.ifEdit = null; showIfaces(devices); };
  const save = card.querySelector('.ifsave'); if (!save) return;
  card.querySelectorAll('input,select').forEach(el => el.addEventListener('input', () => { save.disabled = false; say(T('unsaved changes', 'є незбережені зміни'), 'var(--warn)'); }));
  card.addEventListener('keydown', e => { if (e.key === 'Escape') cancel.click(); else if (e.key === 'Enter' && e.target.matches('input') && !save.disabled) save.click(); });
  save.onclick = async () => {
    const roles = [...card.querySelectorAll('.ifrole')], val = (cls, idx) => card.querySelector(`.${cls}[data-idx="${idx}"]`).value.trim();
    if (roles.filter(r => r.value === 'local').length > 1) { say(T('Only one interface can have the role «The device itself»', 'Роль «Сам пристрій» може мати лише один інтерфейс'), 'var(--crit)'); return; }
    const interfaces = roles.map(r => ({index:+r.dataset.idx, role:r.value, name:val('ifname', r.dataset.idx), addrs:val('ifaddr', r.dataset.idx).split(/[\s,;]+/).filter(Boolean)}));
    save.disabled = true; say(T('Saving…', 'Зберігаю…'));
    try {
      await apiPost('devices/interfaces', {ip:x.ip, interfaces});
      META = await fetch('api/meta').then(r => r.json());
      const fresh = (await api('devices')).devices, i = devices.findIndex(d => d.ip === x.ip), nx = fresh.find(d => d.ip === x.ip);
      if (i >= 0 && nx) devices[i] = nx;
      state.ifEdit = null; showIfaces(devices);
      const m = document.querySelector('#ifBox .ifmsg'); if (m) { m.textContent = T('Saved · the collector applies roles within a minute', 'Збережено · колектор застосує ролі протягом хвилини'); m.style.color = 'var(--ok)'; }
    } catch (e) { save.disabled = false; say(e.message, 'var(--crit)'); }
  };
}
function openModal(title, sub, body, wide){
  const root = document.getElementById('drawerRoot');
  root.innerHTML = `<div class="scrim" id="scrim"></div><div class="modal glass${wide ? '' : ' narrow'}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <header><div><h3>${esc(title)}</h3>${sub ? `<span class="nat">${sub}</span>` : ''}</div><button class="btn x" id="dx">${T('Close', 'Закрити')}</button></header>${body}</div>`;
  const close = () => { root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  document.getElementById('scrim').onclick = close; document.getElementById('dx').onclick = close;
  return {root, close};
}
const formErr = (id, msg) => { const el = document.getElementById(id); if (el) { el.textContent = msg || ''; el.hidden = !msg; } };
function openDevice(dev){
  const c = dev ? dev.config || {} : {}, editing = !!dev, st = (dev && dev.snmp) || {};
  let vendor = c.vendor && VENDORS[c.vendor] ? c.vendor : (c.vendor || 'Fortinet');
  const [me, nfPort] = collectorTarget();
  // SNMP in the form; the secrets the server keeps never come back (has_* says one is stored: empty = keep it)
  const sn = {enabled:!!st.enabled, version:st.version || '2c', host:st.host || '', port:st.port || 161, community:'', user:st.user || '', level:st.level || 'authPriv',
              auth_proto:st.auth_proto || snmpDefaults(vendor)[0], auth_pass:'', priv_proto:st.priv_proto || snmpDefaults(vendor)[1], priv_pass:''};
  let picked = !!st.auth_proto;           // stored or chosen by hand: a vendor tab no longer resets the protocols
  const SN_IDS = {sHost:'host', sPort:'port', sComm:'community', sUser:'user', sAuthP:'auth_pass', sPrivP:'priv_pass', sVer:'version', sLevel:'level', sAuth:'auth_proto', sPriv:'priv_proto'};
  const syncSn = () => { const on = document.getElementById('sOn'); if (!on) return; sn.enabled = on.checked;
    Object.entries(SN_IDS).forEach(([id, k]) => { const el = document.getElementById(id); if (el) sn[k] = k.endsWith('pass') || k === 'community' ? el.value : el.value.trim(); }); };
  const code = () => { const v = VENDORS[vendor] ? vendor : 'Fortinet', rem = v === 'Cisco' ? '!' : '#';
    return VENDORS[v](me, nfPort) + (sn.enabled ? `\n\n${rem} ---- SNMP ${sn.version === '3' ? 'v3' : 'v2c'} ----\n` + SNMP_VENDORS[v](me, sn) : ''); };
  const opt = (list, cur) => list.map(([k, l]) => `<option value="${esc(k)}"${k === cur ? ' selected' : ''}>${esc(l)}</option>`).join('');
  const kept = T('stored — leave empty to keep', 'збережено — залиште порожнім, щоб не змінювати');
  const pw = (id, k, label) => `<label>${label}<input id="${id}" type="password" autocomplete="new-password" value="${esc(sn[k])}" placeholder="${st['has_' + k] ? kept : ''}"></label>`;
  const snmpBox = () => `
      <div class="two"><label>${T('Version', 'Версія')}<select id="sVer">${opt([['2c', 'v2c'], ['3', 'v3']], sn.version)}</select></label><label>${T('UDP port', 'UDP-порт')}<input id="sPort" value="${esc(String(sn.port))}" inputmode="numeric"></label></div>
      <label>${T('Address to poll (empty = the export IP)', 'Адреса для опитування (порожньо = IP експорту)')}<input id="sHost" value="${esc(sn.host)}" placeholder="${esc(editing ? dev.ip : T('the export IP', 'IP експорту'))}"></label>
      ${sn.version === '3' ? `<div class="two"><label>${T('User', 'Користувач')}<input id="sUser" value="${esc(sn.user)}" autocomplete="off"></label><label>${T('Security level', 'Рівень безпеки')}<select id="sLevel">${opt(Object.entries(SNMP_LEVELS), sn.level)}</select></label></div>
        ${sn.level !== 'noAuthNoPriv' ? `<div class="two"><label>${T('Authentication', 'Автентифікація')}<select id="sAuth">${opt(snmpChoices(vendor, 'auth').map(x => [x, SNMP_LABEL[x] || x]), sn.auth_proto)}</select></label>${pw('sAuthP', 'auth_pass', T('Authentication password', 'Пароль автентифікації'))}</div>` : ''}
        ${sn.level === 'authPriv' ? `<div class="two"><label>${T('Privacy', 'Шифрування')}<select id="sPriv">${opt(snmpChoices(vendor, 'priv').map(x => [x, SNMP_LABEL[x] || x]), sn.priv_proto)}</select></label>${pw('sPrivP', 'priv_pass', T('Privacy password', 'Пароль шифрування'))}</div>` : ''}`
        : pw('sComm', 'community', 'Community')}
      <div class="snmptest"><button class="btn" type="button" id="sTest">${T('Test SNMP', 'Перевірити SNMP')}</button><span class="nat" id="sMsg" role="status"></span></div>
      ${window.__snmpTools === false ? `<p class="err">${T('The server has no net-snmp tools (package snmp) yet: run sudo flowtrack upgrade.', 'На сервері ще немає утиліт net-snmp (пакет snmp): виконайте sudo flowtrack upgrade.')}</p>` : ''}
      <p class="note">${T('FlowTrack polls the device when you save and then every hour. Names and addresses entered by hand under Interfaces take priority.', 'FlowTrack опитує пристрій під час збереження і далі щогодини. Назви й адреси, вписані вручну в «Інтерфейсах», мають перевагу.')}</p>`;
  const draw = () => {
    if (!picked) [sn.auth_proto, sn.priv_proto] = snmpDefaults(VENDORS[vendor] ? vendor : 'Fortinet');
    snmpFit(VENDORS[vendor] ? vendor : 'Fortinet', sn);
    const m = openModal(editing ? T(`Device ${dev.name}`, `Пристрій ${dev.name}`) : T('Connect a device', 'Підключити пристрій'), editing ? esc(dev.ip) : T('Set up export on the device and describe it here', 'Налаштуйте експорт на пристрої та опишіть його тут'), `
      <div class="vendors" role="group">${Object.keys(VENDORS).map(k => `<button type="button" data-v="${esc(k)}" aria-pressed="${k === vendor}">${esc(k)}</button>`).join('')}</div>
      <div class="cols"><div><h4>${T('1. Configuration on the device', '1. Конфігурація на пристрої')}</h4><pre class="codebox" id="devCode">${esc(code())}</pre></div>
      <form class="form" id="devForm" autocomplete="off"><h4 style="margin:0">${T('2. Description for FlowTrack', '2. Опис для FlowTrack')}</h4>
        <div class="two"><label>${T('IP the export comes from', 'IP, з якого йде експорт')}<input id="fIp" required value="${esc(editing ? dev.ip : '')}" ${editing ? 'readonly' : ''} placeholder="192.0.2.1"></label><label>${T('Name', 'Назва')}<input id="fName" value="${esc(c.name || '')}" placeholder="branch-fw01"></label></div>
        <div class="two"><label>${T('Model', 'Модель')}<input id="fModel" value="${esc(c.model || '')}" placeholder="FortiGate 60F"></label><label>${T('Sampling', 'Вибірка (sampling)')}<input id="fSamp" value="${esc(c.sampling || '1:1')}"></label></div>
        <div class="two"><label>${T('snmp-index of WAN interfaces (comma-separated)', 'snmp-index WAN-інтерфейсів (через кому)')}<input id="fWan" value="${esc((c.wan_ifs || []).join(', '))}" placeholder="1"></label><label>${T('Index of «the device itself» (FortiOS: 0)', 'Індекс «сам пристрій» (FortiOS: 0)')}<input id="fLocal" value="${c.local_if ?? ''}" placeholder="0"></label></div>
        <label>${T('Public IPs of the device (comma-separated)', 'Публічні IP пристрою (через кому)')}<input id="fPub" value="${esc((c.public_ips || []).join(', '))}" placeholder="198.51.100.10"></label>
        <div class="two"><label>${T('City', 'Місто')}<input id="fCity" value="${esc(c.city || '')}" placeholder="Amsterdam"></label><label>${T('Country code', 'Код країни')}<input id="fCc" value="${esc(c.country || '')}" maxlength="2" placeholder="NL"></label></div>
        <div class="two"><label>${T('Latitude', 'Широта')}<input id="fLat" value="${c.lat ?? ''}" placeholder="52.37"></label><label>${T('Longitude', 'Довгота')}<input id="fLon" value="${c.lon ?? ''}" placeholder="4.90"></label></div>
        <label class="chk"><input type="checkbox" id="sOn"${sn.enabled ? ' checked' : ''}> ${T('Read interface names and IP addresses over SNMP', 'Отримувати назви та IP-адреси інтерфейсів по SNMP')}</label>
        <div class="snmpbox" id="sBox"${sn.enabled ? '' : ' hidden'}>${snmpBox()}</div>
        <p class="err" id="fErr" hidden></p>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${editing ? T('Save', 'Зберегти') : T('Add device', 'Додати пристрій')}</button>${editing && dev.configured ? `<button class="btn" type="button" id="fDel">${T('Delete description', 'Видалити опис')}</button>` : ''}<span class="nat" id="fDelAsk" hidden>${T('Really delete?', 'Точно видалити?')} <button class="btn" type="button" id="fDelYes">${T('Yes, delete', 'Так, видалити')}</button></span></div></form></div>`, true);
    m.root.querySelectorAll('.vendors button').forEach(b => b.onclick = () => { vendor = b.dataset.v; keep(); draw(); restore(); });
    const list = id => document.getElementById(id).value.split(',').map(x => x.trim()).filter(Boolean);
    // SNMP: the version, level and checkbox change the fields; every change updates the device configuration
    const box = document.getElementById('sBox'), redraw = () => { document.getElementById('devCode').textContent = code(); };
    const wireSnmp = () => {
      box.querySelectorAll('select').forEach(el => el.onchange = () => { if (el.id === 'sAuth' || el.id === 'sPriv') picked = true; syncSn(); box.innerHTML = snmpBox(); wireSnmp(); redraw(); });
      box.querySelectorAll('input').forEach(el => el.oninput = () => { syncSn(); redraw(); });
      document.getElementById('sTest').onclick = async () => { syncSn(); const msg = document.getElementById('sMsg'), ip = document.getElementById('fIp').value.trim();
        if (!ip) { msg.textContent = T('Enter the export IP first', 'Спершу вкажіть IP експорту'); msg.style.color = 'var(--crit)'; return; }
        msg.textContent = T('Polling…', 'Опитую…'); msg.style.color = '';
        try { const r = await apiPost('devices/snmp_test', {ip, snmp:sn});
          if (r.ok) { msg.textContent = `✓ ${r.sys.name || ''} · ${T(`${r.interfaces} interfaces, ${r.addresses} addresses`, `інтерфейсів ${r.interfaces}, адрес ${r.addresses}`)}`; msg.style.color = 'var(--ok)'; msg.title = r.sys.descr || ''; }
          else { msg.textContent = r.error_text; msg.style.color = 'var(--crit)'; msg.title = r.detail || ''; }
        } catch (err) { msg.textContent = err.message; msg.style.color = 'var(--crit)'; } };
    };
    wireSnmp();
    document.getElementById('sOn').onchange = e => { syncSn(); box.hidden = !e.target.checked; redraw(); };
    document.getElementById('devForm').addEventListener('submit', async e => { e.preventDefault(); formErr('fErr'); syncSn();
      try {
        await apiPost('devices/save', {ip:document.getElementById('fIp').value.trim(), name:document.getElementById('fName').value, vendor, model:document.getElementById('fModel').value,
          sampling:document.getElementById('fSamp').value, wan_ifs:list('fWan'), local_if:document.getElementById('fLocal').value.trim(), public_ips:list('fPub'),
          city:document.getElementById('fCity').value, country:document.getElementById('fCc').value, lat:document.getElementById('fLat').value.trim(), lon:document.getElementById('fLon').value.trim(),
          snmp:sn});
        m.close(); META = await fetch('api/meta').then(r => r.json()); render();
      } catch (err) { formErr('fErr', err.message); } });
    const del = document.getElementById('fDel');
    if (del) { del.onclick = () => { document.getElementById('fDelAsk').hidden = false; del.hidden = true; };
      document.getElementById('fDelYes').onclick = async () => { try { await apiPost('devices/delete', {ip:dev.ip}); m.close(); render(); } catch (err) { formErr('fErr', err.message); } }; }
  };
  // keep typed values when switching vendor tabs (the SNMP fields live in `sn`)
  let saved = null;
  const ids = ['fIp', 'fName', 'fModel', 'fSamp', 'fWan', 'fLocal', 'fPub', 'fCity', 'fCc', 'fLat', 'fLon'];
  const keep = () => { syncSn(); saved = Object.fromEntries(ids.map(id => [id, (document.getElementById(id) || {}).value])); };
  const restore = () => { if (saved) ids.forEach(id => { const el = document.getElementById(id); if (el && saved[id] != null) el.value = saved[id]; }); };
  draw();
}

// ===================== users (admin) =====================
const ROLE_LABEL = {admin:T('Administrator', 'Адміністратор'), viewer:T('Viewer', 'Перегляд')};
function vUsers(){
  const v = document.getElementById('setBody');
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('users', T('Users', 'Користувачі'), T('an administrator manages everything; «Viewer» is read-only, no changes to devices or users', 'адміністратор керує всім; «Перегляд» — лише читання, без змін пристроїв і користувачів'), `<button class="btn primary" id="addUser">${T('+ New user', '+ Новий користувач')}</button>`)}<div id="uBox" class="loading"></div></section></div>`;
  document.getElementById('addUser').onclick = () => openUser(null);
  section('uBox', async () => { const r = await fetch('api/users'); if (!r.ok) throw new Error((await r.json()).error || r.status); const users = (await r.json()).users;
    setTimeout(() => document.querySelectorAll('[data-user]').forEach(b => b.onclick = () => openUser(users.find(u => u.name === b.dataset.user))));
    const when = t => t ? new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}) : T('never signed in', 'ще не входив');
    return `<div class="tw"><table><thead><tr><th>${T('Username', 'Логін')}</th><th>${T('Role', 'Роль')}</th><th>${T('Created', 'Створено')}</th><th>${T('Last sign-in', 'Останній вхід')}</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td><b class="mono">${esc(u.name)}</b>${u.name === ME.name ? ` <span class="tag">${T('you', 'це ви')}</span>` : ''}${u.default_password ? ` <span class="pill warn">${T('default password', 'стандартний пароль')}</span>` : ''}</td><td>${u.role === 'admin' ? `<span class="pill info">${T('Administrator', 'Адміністратор')}</span>` : `<span class="tag">${T('Viewer', 'Перегляд')}</span>`}</td>
        <td class="nat">${when(u.created)}</td><td class="nat">${when(u.last_login)}</td><td><button class="btn" data-user="${esc(u.name)}">${T('Edit', 'Змінити')}</button></td></tr>`).join('')}</tbody></table></div>`; });
}
function genPassword(){ const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const b = new Uint32Array(14); crypto.getRandomValues(b); return [...b].map(x => a[x % a.length]).join(''); }
function openUser(u){
  const editing = !!u, self = editing && u.name === ME.name;
  const m = openModal(editing ? T(`User ${u.name}`, `Користувач ${u.name}`) : T('New user', 'Новий користувач'), '', `<form class="form" id="uForm">
    <label>${T('Username', 'Логін')}<input id="uName" ${editing ? `value="${esc(u.name)}" readonly` : 'required placeholder="olena"'} autocomplete="off"></label>
    <label>${T('Role', 'Роль')}<select id="uRole" ${self ? 'disabled' : ''}><option value="viewer">${T('Viewer — read-only', 'Перегляд — лише читання')}</option><option value="admin">${T('Administrator — full access', 'Адміністратор — повний доступ')}</option></select></label>
    <label>${editing ? T('New password (leave empty to keep it)', 'Новий пароль (залиште порожнім, щоб не змінювати)') : T('Password', 'Пароль')}<input id="uPass" type="text" autocomplete="new-password" ${editing ? '' : 'required'} minlength="8" placeholder="${T('at least 8 characters', 'щонайменше 8 символів')}"></label>
    <button class="lnk" type="button" id="uGen" style="justify-self:start">${T('Generate a password', 'Згенерувати пароль')}</button>
    <p class="err" id="uErr" hidden></p>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${editing ? T('Save', 'Зберегти') : T('Create', 'Створити')}</button>${editing && !self ? `<button class="btn" type="button" id="uDel">${T('Delete user', 'Видалити користувача')}</button><span class="nat" id="uDelAsk" hidden>${T('Sure?', 'Точно?')} <button class="btn" type="button" id="uDelYes">${T('Yes, delete', 'Так, видалити')}</button></span>` : ''}</div>
    ${self ? `<p class="note" style="margin:0">${T('Change your own password in the user menu — it asks for the current password.', 'Власний пароль зручніше змінити в меню користувача — там потрібен поточний пароль.')}</p>` : ''}</form>`);
  document.getElementById('uRole').value = editing ? u.role : 'viewer';
  document.getElementById('uGen').onclick = () => { document.getElementById('uPass').value = genPassword(); };
  document.getElementById('uForm').addEventListener('submit', async e => { e.preventDefault(); formErr('uErr');
    const pass = document.getElementById('uPass').value, role = document.getElementById('uRole').value;
    try {
      if (editing) await apiPost('users/update', {name:u.name, role:self ? undefined : role, password:pass || undefined});
      else await apiPost('users', {name:document.getElementById('uName').value.trim(), role, password:pass});
      m.close(); render();
    } catch (err) { formErr('uErr', err.message); } });
  const del = document.getElementById('uDel');
  if (del) { del.onclick = () => { document.getElementById('uDelAsk').hidden = false; del.hidden = true; };
    document.getElementById('uDelYes').onclick = async () => { try { await apiPost('users/delete', {name:u.name}); m.close(); render(); } catch (err) { formErr('uErr', err.message); } }; }
}

// ===================== session: login, user menu, password =====================
function renderUser(){
  const w = document.getElementById('userWrap'); if (!w || !ME) return;
  w.innerHTML = `${ME.default_password ? `<button class="pill warn" id="pwWarn" style="border:0;cursor:pointer" title="${T('Change the default password', 'Змініть стандартний пароль')}">${T('change password', 'змініть пароль')}</button>` : ''}
    <button class="user" id="userBtn" aria-haspopup="menu" aria-expanded="false"><span class="avatar">${esc(ME.name[0].toUpperCase())}</span><span class="who"><b>${esc(ME.name)}</b><small>${ROLE_LABEL[ME.role]}</small></span></button>
    <div class="menu glass" id="userMenu" role="menu" hidden><button role="menuitem" id="miPass">${T('Change password', 'Змінити пароль')}</button>${isAdmin() ? `<button role="menuitem" id="miUsers">${T('Users', 'Користувачі')}</button>` : ''}<button role="menuitem" id="miLang" lang="${T('uk', 'en')}">${T('Українська', 'English')}</button><button role="menuitem" id="miOut">${T('Sign out', 'Вийти')}</button></div>`;
  const btn = document.getElementById('userBtn'), menu = document.getElementById('userMenu');
  btn.onclick = e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden)); };
  menu.addEventListener('click', () => closeUserMenu());
  document.getElementById('miPass').onclick = openPassword;
  document.getElementById('miLang').onclick = () => setLang(T('uk', 'en'));
  const pw = document.getElementById('pwWarn'); if (pw) pw.onclick = openPassword;
  const mu = document.getElementById('miUsers'); if (mu) mu.onclick = () => { state.view = 'settings'; state.setTab = 'users'; render(); };
  document.getElementById('miOut').onclick = async () => { try { await apiPost('logout', {}); } catch (e) {} ME = null; showLogin(); };
}
function closeUserMenu(){ const m = document.getElementById('userMenu'), b = document.getElementById('userBtn'); if (m) m.hidden = true; if (b) b.setAttribute('aria-expanded', 'false'); }
// one global listener: any click outside the user menu, or Esc, closes it
document.addEventListener('click', e => { if (!e.target.closest || !e.target.closest('#userWrap')) closeUserMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeUserMenu(); });
function openPassword(){
  const m = openModal(T('Change password', 'Змінити пароль'), ME.default_password ? T('The default password is in use now', 'Зараз використовується стандартний пароль') : '', `<form class="form" id="pForm">
    <label>${T('Current password', 'Поточний пароль')}<input id="pCur" type="password" required autocomplete="current-password"></label>
    <label>${T('New password', 'Новий пароль')}<input id="pNew" type="password" required minlength="8" autocomplete="new-password" placeholder="${T('at least 8 characters', 'щонайменше 8 символів')}"></label>
    <label>${T('Repeat the new password', 'Повторіть новий пароль')}<input id="pNew2" type="password" required minlength="8" autocomplete="new-password"></label>
    <p class="err" id="pErr" hidden></p><p class="note" id="pOk" hidden style="color:var(--ok)">${T('Password changed. Other sessions of this user were signed out.', 'Пароль змінено. Інші сесії цього користувача завершено.')}</p>
    <div><button class="btn primary" type="submit">${T('Change password', 'Змінити пароль')}</button></div></form>`);
  document.getElementById('pCur').focus();
  document.getElementById('pForm').addEventListener('submit', async e => { e.preventDefault(); formErr('pErr');
    const n1 = document.getElementById('pNew').value, n2 = document.getElementById('pNew2').value;
    if (n1 !== n2) return formErr('pErr', T('The new passwords do not match', 'Нові паролі не збігаються'));
    try { ME = await apiPost('me/password', {current:document.getElementById('pCur').value, new:n1}); document.getElementById('pOk').hidden = false; renderUser(); setTimeout(m.close, 1400); }
    catch (err) { formErr('pErr', err.message); } });
}
let loginShown = false;
function showLogin(msg){
  if (loginShown) return; loginShown = true;
  cleanup(); document.getElementById('drawerRoot').innerHTML = '';
  document.querySelector('.app').hidden = true;
  const box = document.createElement('div'); box.className = 'login-wrap'; box.id = 'loginWrap';
  box.innerHTML = `<form class="glass login" id="loginForm">
    <div class="brand" style="padding:0"><svg width="40" height="34" viewBox="0 0 40 34" aria-hidden="true"><path d="M3 10c6-6 11-6 17 0s11 6 17 0" fill="none" stroke="#27D3F5" stroke-width="4.5" stroke-linecap="round"/><path d="M3 22c6-6 11-6 17 0s11 6 17 0" fill="none" stroke="#2F7BFF" stroke-width="4.5" stroke-linecap="round"/></svg><div><b>FlowTrack</b><small>${T('Sign in', 'Вхід до панелі')}</small></div></div>
    ${msg ? `<p class="note" style="margin:0">${esc(msg)}</p>` : ''}
    <label>${T('Username', 'Логін')}<input id="lUser" required autocomplete="username" autofocus></label>
    <label>${T('Password', 'Пароль')}<input id="lPass" type="password" required autocomplete="current-password"></label>
    <p class="err" id="lErr" hidden></p>
    <button class="btn primary" type="submit" style="justify-self:stretch;text-align:center;padding:9px">${T('Sign in', 'Увійти')}</button></form>`;
  document.body.appendChild(box);
  document.getElementById('lUser').focus();
  document.getElementById('loginForm').addEventListener('submit', async e => { e.preventDefault(); formErr('lErr');
    try {
      ME = await apiPost('login', {username:document.getElementById('lUser').value.trim(), password:document.getElementById('lPass').value});
      box.remove(); loginShown = false; document.querySelector('.app').hidden = false;
      META = await fetch('api/meta').then(r => r.json()); render(); health();
    } catch (err) { formErr('lErr', err.message); document.getElementById('lPass').select(); } });
}

async function openHost(ip){
  const root = document.getElementById('drawerRoot');
  root.innerHTML = `<div class="scrim" id="scrim"></div><aside class="drawer glass" role="dialog" aria-modal="true" aria-label="${T('Host', 'Хост')} ${esc(ip)}"><div class="loading" style="min-height:200px"></div></aside>`;
  const close = () => { if (hc) { hc.dispose(); const i = charts.indexOf(hc); if (i >= 0) charts.splice(i, 1); } root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  let hc = null; document.addEventListener('keydown', onKey); document.getElementById('scrim').onclick = close;
  let d; try { d = await api('host', {ip}); } catch (e) { root.querySelector('.drawer').innerHTML = errBox(e); return; }
  const s = d.summary;
  root.querySelector('.drawer').innerHTML = `<header><div><h3>${esc(d.host.name || ip)}</h3><div class="ipl" style="color:var(--ink2)">${esc(ip)} · ${d.host.private ? T('inside address', 'внутрішня адреса') : T('public address', 'публічна адреса')}</div></div><button class="btn x" id="dx">${T('Close', 'Закрити')}</button></header>
    <div class="dk"><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4>${T('Traffic', 'Трафік')} · ${rangeLabel()}</h4><div class="chart short" id="cHost"></div></div>
    <div><h4>${T('Services', 'Сервіси')}</h4><div class="tagrow">${d.services.rows.map(g => `<span class="tag">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>${T('Protocols', 'Протоколи')}</h4><div class="tagrow">${d.ports.rows.map(g => `<span class="tag mono">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>${T('Where it goes', 'Куди ходить')}</h4><div class="blist">${d.dests.rows.map(g => `<div class="brow" style="cursor:default"><span class="n"><span class="idot ext"></span>${esc(g.k)} <span class="nat">${esc([g.service, g.city || ccName(g.country)].filter(Boolean).join(' · '))}</span></span><span class="t">${fmtB(tot(g))}</span><span class="p"></span></div>`).join('')}</div></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" id="dfilter">${T('Filter everything by this host', 'Фільтрувати все за цим хостом')}</button></div>`;
  const before = charts.length; trendChart(document.getElementById('cHost'), d.series, true); hc = charts[before];
  document.getElementById('dx').onclick = close;
  document.getElementById('dfilter').onclick = () => { close(); addFilter('ip', ip); };
  document.getElementById('dx').focus();
}

// ===================== shell =====================
const VIEWS = {overview:vOverview, flows:vFlows, paths:vPaths, network:vNetwork, talkers:vTalkers, apps:vApps, ports:vPorts, geo:vGeo, threats:vThreats, settings:vSettings};
function renderShell(){
  document.getElementById('nav').innerHTML = NAV.filter(n => n[3] !== 'admin' || isAdmin()).map(([k, l, d]) => `<button data-view="${k}" ${state.view === k ? 'aria-current="page"' : ''}>${icon(d)}${l}</button>`).join('');
  document.querySelectorAll('#nav button').forEach(b => b.onclick = () => { state.view = b.dataset.view; state.sel = null; state.openFlow = null; render(); });
  // on narrow screens the menu is a scrolling row: keep the current page in sight
  const cur = document.querySelector('#nav [aria-current="page"]'), navEl = document.getElementById('nav');
  if (cur && navEl.scrollWidth > navEl.clientWidth) navEl.scrollLeft += cur.getBoundingClientRect().left - navEl.getBoundingClientRect().left - (navEl.clientWidth - cur.offsetWidth) / 2;
  document.getElementById('chips').innerHTML = (isCustom() ? `<span class="fchip period"><span class="k">${T('period', 'період')}:</span><button class="lnk" id="periodEdit" title="${T('Change the period', 'Змінити період')}">${esc(rangeLabel())}</button><button aria-label="${T('Back to', 'Повернутися до')} ${esc(presetLabel(state.prevRange))}" title="${T('Back to', 'Повернутися до')}: ${esc(presetLabel(state.prevRange))}" id="periodX">×</button></span>` : '') + state.filters.map((f, i) => `<span class="fchip ${f.neg ? 'neg' : ''}"><span class="k">${FILTER_LABEL[f.k] || f.k}${f.neg ? ' ≠' : ':'}</span>${esc(f.k === 'device' ? devName(f.v) : (f.k === 'in_if' || f.k === 'out_if' || f.k === 'iface') ? (ifLabel(pathDevice(), +f.v) === String(f.v) ? 'if ' + f.v : ifLabel(pathDevice(), +f.v)) : f.v)}<button aria-label="${T('Remove filter', 'Прибрати фільтр')}" data-i="${i}">×</button></span>`).join('')
    + (state.filters.length ? `<button class="lnk" id="clearF">${T('Clear all', 'Скинути всі')}</button>` : '');
  document.querySelectorAll('#chips button[data-i]').forEach(b => b.onclick = () => { state.filters.splice(+b.dataset.i, 1); render(); });
  const cf = document.getElementById('clearF'); if (cf) cf.onclick = () => { state.filters = []; render(); };
  const px = document.getElementById('periodX'); if (px) px.onclick = () => { state.range = state.prevRange || '24h'; render(); };
  const pe = document.getElementById('periodEdit'); if (pe) pe.onclick = openPeriod;
  const ds = document.getElementById('devSel'), df = state.filters.find(f => f.k === 'device' && !f.neg);
  ds.innerHTML = `<option value="">${T(`All devices (${META.devices.length})`, `Усі пристрої (${META.devices.length})`)}</option>` + META.devices.map(d => `<option value="${esc(d.ip)}">${esc(d.name)}${d.vendor ? ' · ' + esc(d.vendor) : ''}</option>`).join('');
  ds.value = df ? df.v : '';
  editionBadge();
  const fv = document.getElementById('ftVer'); if (fv && META.version) fv.textContent = 'FlowTrack ' + META.version;
  const rs = document.getElementById('rangeSel');
  rs.querySelectorAll('option[data-x]').forEach(o => o.remove());
  if (isCustom()) rs.insertAdjacentHTML('beforeend', `<option data-x value="custom">${esc(rangeLabel())}</option>`);
  rs.insertAdjacentHTML('beforeend', `<option data-x value="pick">${T('Custom period…', 'Свій період…')}</option>`);
  rs.value = state.range;
  document.getElementById('trafSel').value = state.traffic;
}
function saveUrl(){ const p = new URLSearchParams({v:state.view, r:state.range}); if (state.view === 'settings') p.set('tab', state.setTab || 'general'); if (isCustom()) { p.set('from', state.from); p.set('to', state.to); } if (state.traffic !== 'internet') p.set('t', state.traffic); if (state.filters.length) p.set('f', JSON.stringify(state.filters)); history.replaceState(null, '', '#' + p); }
function loadUrl(){ try { const p = new URLSearchParams(location.hash.slice(1)); if (p.get('v') === 'devices' || p.get('v') === 'users') { state.view = 'settings'; state.setTab = p.get('v'); } else if (p.get('v') && VIEWS[p.get('v')]) state.view = p.get('v'); if (p.get('tab')) state.setTab = p.get('tab'); if (p.get('r') === 'custom') { const a = +p.get('from'), b = +p.get('to'); if (a > 0 && b - a >= 60) Object.assign(state, {range:'custom', from:a, to:b}); } else if (p.get('r')) state.range = p.get('r'); if (['internet', 'internal', 'all'].includes(p.get('t'))) state.traffic = p.get('t'); if (p.get('f')) { state.filters = []; JSON.parse(p.get('f')).forEach(putFilter); } } catch (e) {} }
function render(){ if (state.view === 'devices' || state.view === 'users') { state.setTab = state.view; state.view = 'settings'; } renderSeq++; cleanup(); renderShell(); renderUser(); saveUrl(); VIEWS[state.view](); }

document.getElementById('devSel').onchange = e => { state.filters = state.filters.filter(f => f.k !== 'device'); if (e.target.value) putFilter({k:'device', v:e.target.value, neg:false}); render(); };
document.getElementById('rangeSel').onchange = e => { const v = e.target.value; if (v === 'pick') { e.target.value = state.range; openPeriod(); return; } if (v !== 'custom') { state.range = v; render(); } };
const presetLabel = r => ({'1h':T('Last hour','Остання година'), '6h':T('Last 6 hours','Останні 6 годин'), '24h':T('Last 24 hours','Останні 24 години'), '7d':T('Last 7 days','Останні 7 днів'), '30d':T('Last 30 days','Останні 30 днів')})[r] || r;
// the custom period dialog: from / to to the minute, within the 30 days of detailed data
function openPeriod(){
  closePeriod();
  const now = Math.floor(Date.now() / 1000), t1 = isCustom() ? state.to : now, t0 = isCustom() ? state.from : now - rangeSecs();
  const loc = t => { const d = new Date(t * 1000 - new Date(t * 1000).getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); };
  const keep = (META.edition || {}).view_days || (META.edition || {}).retention_days || 30, min = loc(now - keep * 86400), max = loc(now + 60);
  const el = document.createElement('div'); el.className = 'glass period-pop'; el.id = 'periodPop'; el.setAttribute('role', 'dialog'); el.setAttribute('aria-label', T('Custom period', 'Свій період'));
  el.innerHTML = `<h3>${T('Custom period', 'Свій період')}</h3>
    <label>${T('From', 'Від')}<input type="datetime-local" id="pFrom" step="60" min="${min}" max="${max}" value="${loc(t0)}"></label>
    <label>${T('To', 'До')}<input type="datetime-local" id="pTo" step="60" min="${min}" max="${max}" value="${loc(t1)}"></label>
    <div class="quick">${[[15, T('15 min', '15 хв')], [60, T('1 hour', '1 год')], [240, T('4 hours', '4 год')]].map(([m, l]) => `<button class="btn" data-m="${m}" title="${T('this long, ending at «To»', 'стільки, до «До»')}">${l}</button>`).join('')}</div>
    <p class="note" id="pErr" role="alert"></p>
    <p class="note">${T(`Detailed data is kept for ${keep} days. Tip: drag across any traffic chart to zoom in.`, `Детальні дані зберігаються ${keep} днів. Порада: виділіть мишею проміжок на будь-якому графіку трафіку.`)}</p>
    <div class="acts"><button class="btn" id="pCancel">${T('Cancel', 'Скасувати')}</button><button class="btn primary" id="pApply">${T('Show', 'Показати')}</button></div>`;
  document.body.appendChild(el);
  const r = document.getElementById('rangeLbl').getBoundingClientRect();
  el.style.top = (r.bottom + 8) + 'px'; el.style.left = Math.max(8, Math.min(r.left, innerWidth - el.offsetWidth - 8)) + 'px';
  const val = id => { const v = document.getElementById(id).value; return v ? Math.floor(new Date(v).getTime() / 1000) : NaN; };
  el.querySelectorAll('[data-m]').forEach(b => b.onclick = () => { const e1 = val('pTo'); if (!isNaN(e1)) document.getElementById('pFrom').value = loc(e1 - b.dataset.m * 60); });
  document.getElementById('pCancel').onclick = closePeriod;
  document.getElementById('pApply').onclick = () => {
    const a = val('pFrom'), b = val('pTo'), err = document.getElementById('pErr');
    if (isNaN(a) || isNaN(b)) { err.textContent = T('Enter both dates.', 'Вкажіть обидві дати.'); return; }
    if (b - a < 60) { err.textContent = T('«To» must be at least a minute after «From».', '«До» має бути щонайменше на хвилину пізніше за «Від».'); return; }
    if (b - a > (keep + 1) * 86400) { err.textContent = T(`The period can be at most ${keep + 1} days long.`, `Період може бути не довшим за ${keep + 1} днів.`); return; }
    closePeriod(); setPeriod(a, Math.min(b, now + 60));
  };
  el.addEventListener('keydown', e => { if (e.key === 'Escape') closePeriod(); if (e.key === 'Enter') document.getElementById('pApply').click(); });
  setTimeout(() => document.addEventListener('mousedown', periodOutside), 0);
  document.getElementById('pFrom').focus();
}
function periodOutside(e){ const el = document.getElementById('periodPop'); if (el && !el.contains(e.target)) closePeriod(); }
function closePeriod(){ const el = document.getElementById('periodPop'); if (el) el.remove(); document.removeEventListener('mousedown', periodOutside); }
document.getElementById('trafSel').onchange = e => { state.traffic = e.target.value; state.sel = null; render(); };
const q = document.getElementById('q');
q.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    for (let t of q.value.trim().split(/\s+/).filter(Boolean)) {
      const neg = t.startsWith('-'); if (neg) t = t.slice(1); const i = t.indexOf(':');
      if (i > 0 && FILTER_KEYS.includes(t.slice(0, i).toLowerCase()) && t.slice(i + 1)) putFilter({k:t.slice(0, i).toLowerCase(), v:t.slice(i + 1), neg});
      else if (/^[\d.]+$/.test(t) && t.split('.').length === 4) putFilter({k:/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(t) ? 'ip' : 'dst', v:t, neg});
      else if (/^AS\d+$/i.test(t)) putFilter({k:'asn', v:t, neg});
      else if (/^[A-Za-z]{2}$/.test(t)) putFilter({k:'country', v:t.toUpperCase(), neg});
      else if (t) putFilter({k:'service', v:t, neg});
    }
    q.value = ''; render();
  } else if (e.key === 'Backspace' && !q.value && state.filters.length) { state.filters.pop(); render(); }
});
document.addEventListener('keydown', e => { if (e.key === '/' && document.activeElement !== q && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); q.focus(); } });
document.getElementById('bell').onclick = () => { state.view = 'threats'; render(); };

// sidebar health: real collector ingest rate
const ingHist = [];
async function health(){
  if (!ME) return;
  try {
    const d = (await fetch('api/devices').then(r => r.json())).devices || [];
    const rps = d.reduce((s, x) => s + x.rps, 0), online = d.filter(x => Date.now() / 1000 - x.last < 180).length;
    document.getElementById('collState').textContent = d.length ? (online ? T('Collector online', 'Колектор онлайн') : T('No data', 'Немає даних')) : T('Waiting for export', 'Чекаю на експорт');
    document.getElementById('collDot').className = 'dot' + (online ? '' : ' crit');
    document.getElementById('expCount').textContent = T(`${online}/${d.length} exporter${d.length === 1 ? '' : 's'}`, `${online}/${d.length} експортер${d.length === 1 ? '' : 'и'}`);
    ingHist.push(rps); if (ingHist.length > 40) ingHist.shift();
    document.getElementById('ingV').innerHTML = T(`${rps.toFixed(1)} <small>rec/s</small>`, `${rps.toFixed(1)} <small>записів/с</small>`);
    document.getElementById('ingM').style.width = Math.max(2, Math.min(100, 100 * rps / 2000)).toFixed(1) + '%';
    const max = Math.max(...ingHist, 1); document.getElementById('ingS').innerHTML = `<polyline points="${ingHist.map((x, i) => `${(i / 39 * 200).toFixed(1)},${(28 - x / max * 24).toFixed(1)}`).join(' ')}" fill="none" stroke="${C.down}" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
    const al = (await fetch('api/alerts').then(r => r.json())).alerts || [];
    document.getElementById('bellBadge').hidden = !al.some(a => a.sev !== 'info');
  } catch (e) { document.getElementById('collState').textContent = T('API unavailable', 'API недоступне'); document.getElementById('collDot').className = 'dot crit'; }
}

(async () => {
  loadUrl();
  const r = await fetch('api/me').catch(() => null);
  if (!r || r.status === 401) { showLogin(); setInterval(() => ME && health(), 60000); return; }
  ME = await r.json();
  try { META = await fetch('api/meta').then(x => x.json()); } catch (e) {}
  render(); health(); setInterval(() => ME && health(), 60000);
})();
