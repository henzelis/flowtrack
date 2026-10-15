'use strict';
// FlowTrack web UI — talks to /api/* (see api.py). No build step.

// ===================== language =====================
// The code holds English only: T('English text'). Other languages are dictionaries web/i18n/<lang>.json
// ("English text": "translation"), loaded by index.html before this file; a text missing there stays English.
// {name} placeholders take their values from the second argument: T('Ignore {addr}?', {addr}).
// The same English text that needs different translations gets a context prefix: T('button::Sign in').
// The choice is kept in localStorage and in the ft_lang cookie (the API answers errors and events in it).
const LANG = window.FT_LANG || 'en', DICT = window.FT_DICT || {};
const CTX = /^[a-z]+::/;
const T = (en, a) => {
  const s = Object.hasOwn(DICT, en) ? DICT[en] : en.replace(CTX, '');
  return a ? s.replace(/\{(\w+)\}/g, (m, k) => Object.hasOwn(a, k) ? String(a[k]) : m) : s;
};
// a text with a number: English has one and other ('{n} day', '{n} days', the latter is the dictionary key); a dictionary
// gives the forms of its language by Intl.PluralRules ({"one": …, "few": …, "many": …, "other": …}) or one text for all
const PLURAL = (() => { try { return new Intl.PluralRules(LANG); } catch (e) { return new Intl.PluralRules('en'); } })();
const Tn = (n, one, other, a) => {
  const t = Object.hasOwn(DICT, other) ? DICT[other] : n === 1 ? one : other;
  const s = typeof t === 'string' ? t : t[PLURAL.select(n)] ?? t.other ?? other;
  return s.replace(/\{(\w+)\}/g, (m, k) => k === 'n' ? String(n) : a && Object.hasOwn(a, k) ? String(a[k]) : m);
};
const LOC = DICT['@locale'] || 'en-GB';
document.documentElement.lang = LANG;
document.cookie = `ft_lang=${LANG}; path=/; max-age=31536000; SameSite=Lax`;
// the languages there are dictionaries for, by the server: [[code, own name], …]
const langs = () => META.langs || [['en', 'English']];
function setLang(l){ try { localStorage.setItem('ft-lang', l); } catch (e) {} document.cookie = `ft_lang=${l}; path=/; max-age=31536000; SameSite=Lax`; location.reload(); }
// texts of index.html in the chosen language (the HTML itself is English): data-t translates the element's text,
// data-t-attr the attributes it names
document.querySelectorAll('[data-t]').forEach(el => { el.textContent = T(el.textContent); });
document.querySelectorAll('[data-t-attr]').forEach(el => el.dataset.tAttr.split(' ').forEach(at => el.setAttribute(at, T(el.getAttribute(at)))));

// ===================== state, api =====================
const state = {view:'overview', range:'24h', filters:[], heroMode:'map', heroLive:true, metric:'flows', scale:'sqrt', flowLive:true, sel:null, sort:{col:'tot', dir:-1}, openFlow:null, ifDev:null, ifEdit:null, traffic:'internet'};
let META = {devices:[]}, ME = null;
const isAdmin = () => ME && ME.role === 'admin';
const isInternal = () => state.traffic === 'internal';
// a record whose packets went to int_ip: from the internet, or a server's answer to an inside client
const isBack = f => f.dir === 'down' || f.dir === 'internal_back';
const FILTER_KEYS = ['ip', 'dst', 'service', 'l7', 'country', 'city', 'port', 'device', 'asn', 'dir', 'proto', 'in_if', 'out_if', 'iface'];
const FILTER_LABEL = {iface:T('interface'), in_if:T('in via'), out_if:T('out via'), ip:T('host'), dst:T('ext. IP'), service:T('service'), l7:T('protocol'), country:T('country'), city:T('city'), port:T('port'), device:T('device'), asn:'ASN', dir:T('direction'), proto:'L4'};
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
// the server tags the queries of a page with this browser tab and this view of the page: when the tab moves on to
// another page (or other filters), what the old one still runs is cancelled instead of holding up the new one
const TAB_ID = (() => { try { const v = sessionStorage.getItem('ft-tab') || Math.random().toString(36).slice(2, 12); sessionStorage.setItem('ft-tab', v); return v; } catch (e) { return Math.random().toString(36).slice(2, 12); } })();
let PAGE_ID = Math.random().toString(36).slice(2, 12), PAGE_AC = new AbortController();
// a request of a page that is gone never answers it: its widgets were replaced (maybe by ones with the same ids)
const NEVER = () => new Promise(() => {});
async function apiFetch(url){
  let r;
  try { r = await fetch(url, {headers:{'X-FT-Tab':TAB_ID, 'X-FT-Page':PAGE_ID}, signal:PAGE_AC.signal}); }
  catch (e) { if (e.name === 'AbortError') return NEVER(); throw e; }
  if (r.status === 401) { showLogin(T('Session ended — sign in again')); throw new Error(T('login required')); }
  const body = await r.json().catch(() => ({}));
  if (r.status === 409) return NEVER();          // cancelled by the server: the page changed
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
async function apiPost(path, body){
  API_SHARED.clear();                    // a change: answers shared before it are stale (the server clears its cache too)
  const r = await fetch(`api/${path}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body || {})});
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== 'login') { showLogin(T('Session ended — sign in again')); throw new Error(T('login required')); }
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
const fmtR = bps => { bps = +bps || 0; const u = [T('bit/s'), T('kbit/s'), T('Mbit/s'), T('Gbit/s')]; let i = 0; while (bps >= 1000 && i < 3) { bps /= 1000; i++; } return bps.toFixed(bps < 10 && i > 0 ? 1 : 0) + ' ' + u[i]; };
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
const rangeLabel = () => isCustom() ? periodText(state.from, state.to) : ({'1h':T('inline::Last hour'), '6h':T('inline::Last 6 hours'), '24h':T('inline::Last 24 hours'), '7d':T('inline::Last 7 days'), '30d':T('inline::Last 30 days')})[state.range];
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
    series:order.map(k => { const col = k === '__other' ? C.other : keyColor(k); return {name:k === '__other' ? T('Others') : label(k), id:k, type:'line', stack:'a', smooth:.25, showSymbol:false,
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
const metricFmt = v => state.metric === 'bytes' ? fmtB(v) : state.metric === 'packets' ? fmtN(v) + T(' pkt') : fmtN(v) + ' flows';
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
    if (side === 'L') { if (k === '__other') return [isInternal() ? T('Other clients') : T('Other inside'), T('Remaining addresses')]; const h = info.L.get(k) || {ip:k}; return [h.name || k, h.name ? k : (h.private ? T('Inside') : T('Public (self)'))]; }
    if (k === '__other') return [isInternal() ? T('Other servers') : T('Other outside'), T('Remaining addresses')]; const r = info.R.get(k) || {};
    if (isInternal()) return [r.name || k, r.name ? k : T('Inside')];
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
    ctx.textAlign = 'left'; ctx.fillText(isInternal() ? T('Clients (who connects)') : T('Inside addresses'), 2, L.headH / 2 - 2); ctx.textAlign = 'right'; ctx.fillText(isInternal() ? T('Servers (connected to)') : T('Outside addresses'), W - 2, L.headH / 2 - 2);
    if (!left.length) { ctx.textAlign = 'center'; ctx.fillStyle = C.ink3; ctx.fillText(data.live ? T('No traffic under this filter in the last {min} min — Period shows the whole range', {min: Math.round(data.window / 60)}) : T('No traffic under this filter for the selected period'), W / 2, H / 2); return; }
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
      html = `<b class="mono">${esc(l1)} ⇄ ${esc(r1)}</b><br><span style="color:${C.ink2}">${esc(r2)}</span><br><span style="color:${C.up}">↑ upload ${metricFmt(v.up)}${rate(v.up)}</span><br><span style="color:${C.down}">↓ download ${metricFmt(v.dn)}${rate(v.dn)}</span><br><span style="color:${C.ink3}">${T('Click to select')}</span>`;
    } else {
      const [a, b] = nodeLabel(h.side, h.k), c = cards.find(x => x.side === h.side && x.k === h.k);
      html = `<b class="mono">${esc(a)}</b><br><span style="color:${C.ink2}">${esc(b)}</span><br>${metricFmt(c ? c.val : 0)}<br><span style="color:${C.ink3}">${T('Click to highlight links · Shift+click to filter')}</span>`;
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
// lines on the map and the globe: the biggest places only (the rows come sorted by volume) — more are neither
// readable nor drawable on a busy network; the regions and the city marks keep every place
const MAP_LINES = 20;
function flatMap(el, geo, onConn, arcs = !isCustom()){
  if (!echarts.getMap('world')) { el.innerHTML = '<div class="empty">' + T('Failed to load world map outlines') + '</div>'; return; }
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
      {id:'agg', data:rows.slice(0, MAP_LINES).map(r => { const s = siteGeo(r.exporter); return s && {coords:[s, [r.lo, r.la]], lineStyle:{width:.6 + 3.4 * tot(r) / rmax, opacity:.22, color:r.up > r.dn ? C.up : C.down}}; }).filter(Boolean)},
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
  const poll = async () => { try { const r = await api('live', {since}); since = r.upto || since; queue.push(...r.rows); if (queue.length > 120) queue = queue.slice(-120); } catch (e) {} };
  const tick = () => {
    const now = performance.now(); live = live.filter(e => now - e.born < 4500);
    const n = Math.min(queue.length, Math.max(1, Math.ceil(queue.length / 4)), Math.max(0, MAP_LINES - live.length));
    for (const r of queue.splice(0, n)) {
      // a line needs the device's location (Settings → Devices); Live connections lists the flow without it too
      const s = siteGeo(r.exporter), up = r.dir === 'up';
      if (s && (s[0] !== r.lon || s[1] !== r.lat)) live.push({coords:up ? [s, [r.lon, r.lat]] : [[r.lon, r.lat], s], color:up ? C.up : C.down, born:now});
      if (onConn) onConn(r);
    }
    if (n || live.length !== lastLen) c.setOption({series:[{id:'live', data:live.map(e => ({coords:e.coords, lineStyle:{color:e.color}}))}]});
    lastLen = live.length;
  };
  let lastLen = -1;
  if (arcs && !isCustom()) { poll(); every(4000, poll); every(reduceMotion ? 3000 : 1000, tick); }    // a past period: no live arcs
  return geo => { if (!c.isDisposed()) c.setOption(dataOpt(geo)); };
}
function globe(el, geo){
  if (!echarts.getMap('world') || !window['echarts-gl']) { el.innerHTML = '<div class="empty">' + T('3D mode is not available in this browser') + '</div>'; return; }
  try {
    const tex = echarts.init(document.createElement('canvas'), null, {width:2048, height:1024});
    tex.setOption({backgroundColor:'#071431', animation:false, geo:{map:'world', silent:true, left:0, top:0, right:0, bottom:0, boundingCoords:[[-180, 90], [180, -90]], itemStyle:{areaColor:'#123072', borderColor:'#4C93FF', borderWidth:1.2}}});
    const c = mkChart(el); onCleanup(() => tex.dispose());
    const arcs = geo => geo.rows.slice(0, MAP_LINES).map(r => { const s = siteGeo(r.exporter); if (!s) return null; const up = r.up > r.dn; return {coords:up ? [s, [r.lo, r.la]] : [[r.lo, r.la], s], lineStyle:{color:up ? C.up : C.down}}; }).filter(Boolean);
    const places = geo => { const m = new Map(); for (const r of geo.rows.slice(0, 10)) m.set(r.city, {name:r.city || ccName(r.country), value:[r.lo, r.la, 0]}); return [...m.values()]; };
    const devs = [...new Map(META.devices.filter(d => d.lat != null).map(d => [d.city || d.name, {name:d.city || d.name, lon:d.lon, lat:d.lat}])).values()];   // one label per site
    c.setOption({globe:{baseTexture:tex, shading:'lambert', environment:'none', globeRadius:100, light:{ambient:{intensity:.55}, main:{intensity:1.1, alpha:30, beta:40}},
        atmosphere:{show:true, color:'#2F7BFF', glowPower:5, innerGlowPower:2}, viewControl:{autoRotate:!reduceMotion, autoRotateSpeed:4, autoRotateAfterStill:3, animation:false, distance:180, minDistance:60, maxDistance:260, alpha:45, beta:115}},
      series:[
        {id:'arcs', type:'lines3D', coordinateSystem:'globe', blendMode:'lighter', effect:{show:!reduceMotion, trailWidth:2.5, trailLength:.22, trailOpacity:1, constantSpeed:28}, lineStyle:{width:1.2, opacity:.35}, data:arcs(geo)},
        {type:'scatter3D', coordinateSystem:'globe', blendMode:'lighter', symbolSize:10, itemStyle:{color:C.int}, label:{show:false}, data:devs.map(d => ({name:d.name, value:[d.lon, d.lat, 0]}))},
        {id:'places', type:'scatter3D', coordinateSystem:'globe', blendMode:'lighter', symbolSize:7, itemStyle:{color:C.ext}, label:{show:false}, data:places(geo)},
      ]});
    // the wheel scrolls the page, not the globe (zooming it stopped the rotation); Ctrl/⌘ + wheel still zooms
    el.addEventListener('wheel', e => { if (!e.ctrlKey && !e.metaKey) e.stopPropagation(); }, {capture:true});
    // city names: an HTML layer placed from the globe's camera every frame — only on the near side, fading towards the
    // rim, never cut by the globe's surface (labels drawn inside the 3D scene sank into it as it turned)
    if (getComputedStyle(el).position === 'static') el.style.position = 'relative';
    const lay = el.appendChild(Object.assign(document.createElement('div'), {className:'globe-labels'}));
    let marks = [];
    const setMarks = list => { lay.innerHTML = list.map(m => `<span class="gl-lbl${m.dev ? ' dev' : ''}">${esc(m.name)}</span>`).join('');
      marks = list.map((m, k) => ({...m, el:lay.children[k], w:lay.children[k].offsetWidth, h:lay.children[k].offsetHeight})); };
    const markList = geo => [...devs.map(d => ({...d, dev:true})), ...places(geo).filter(p => !devs.some(d => d.name === p.name)).map(p => ({name:p.name, lon:p.value[0], lat:p.value[1]}))];
    setMarks(markList(geo));
    let raf = 0;
    const frame = () => {
      raf = requestAnimationFrame(frame);
      const g = !c.isDisposed() && c.getModel().getComponent('globe'), cs = g && g.coordinateSystem;
      if (!cs || !cs.viewGL || !cs.viewGL.camera) return;
      const cam = cs.viewGL.camera, vp = cs.viewGL.viewport, V = cam.viewMatrix.array, P = cam.projectionMatrix.array, w = cam.worldTransform.array;
      const R = cs.radius, cd = Math.hypot(w[12], w[13], w[14]) || 1, taken = [];
      // devices first, then places by traffic: a label that would cover one already placed waits until it is clear
      for (const m of marks) {
        const q = cs.dataToPoint([m.lon, m.lat, 0]);
        const face = (q[0] * w[12] + q[1] * w[13] + q[2] * w[14]) / (R * cd) - R / cd;     // > 0: in front of the horizon
        if (face <= 0) { m.el.style.opacity = '0'; continue; }
        const v = k => V[k] * q[0] + V[k + 4] * q[1] + V[k + 8] * q[2] + V[k + 12], vx = v(0), vy = v(1), vz = v(2), vw = v(3);
        const p = k => P[k] * vx + P[k + 4] * vy + P[k + 8] * vz + P[k + 12] * vw, cw = p(3);
        const sx = vp.x + (p(0) / cw * .5 + .5) * vp.width, sy = vp.y + (.5 - p(1) / cw * .5) * vp.height;
        const x0 = sx - m.w / 2, y0 = sy - 7 - m.h;
        if (taken.some(t => x0 < t[2] && x0 + m.w > t[0] && y0 < t[3] && y0 + m.h > t[1])) { m.el.style.opacity = '0'; continue; }
        taken.push([x0 - 2, y0 - 2, x0 + m.w + 2, y0 + m.h + 2]);
        m.el.style.opacity = String(Math.min(1, face / .15));
        m.el.style.transform = `translate(${sx.toFixed(1)}px, ${sy.toFixed(1)}px) translate(-50%, calc(-100% - 7px))`;
      }
    };
    raf = requestAnimationFrame(frame); onCleanup(() => cancelAnimationFrame(raf));
    return geo => { if (c.isDisposed()) return; c.setOption({series:[{id:'arcs', data:arcs(geo)}, {id:'places', data:places(geo)}]}); setMarks(markList(geo)); };
  } catch (e) { el.innerHTML = '<div class="empty">' + T('3D mode is not available: ') + esc(e.message) + '</div>'; }
}

// ===================== shared UI =====================
const NAV = [
  ['overview',T('Overview'),'M3 9.5L9 4l6 5.5V15H3z'], ['flows',T('Flows'),'M2 6c4 0 5 6 9 6h5M2 12c4 0 5-6 9-6h5'], ['paths',T('Through device'),'M2 4h4M2 9h4M2 14h4M12 4h4M12 9h4M12 14h4M6 4c3 0 3 5 6 5M6 14c3 0 3-10 6-10M6 9h6'], ['network',T('Path analysis'),'M9 2.5a2 2 0 1 0 0 .01M3.5 13a2 2 0 1 0 0 .01M14.5 13a2 2 0 1 0 0 .01M8 4.5L4.5 11M10 4.5l3.5 6.5M5.5 13h7'], ['talkers',T('Top hosts'),'M6 7a2.5 2.5 0 1 0 0-.01M2 15c0-2.5 2-4 4-4s4 1.5 4 4M13 8a2 2 0 1 0 0-.01M11.5 15c.3-2 1.3-3 3-3'],
  ['apps',T('Services'),'M3 3h5v5H3zM10 3h5v5h-5zM3 10h5v5H3zM10 10h5v5h-5z'], ['ports',T('Ports'),'M6 2v4M12 2v4M4 6h10v3a5 5 0 0 1-10 0zM9 14v3'], ['geo',T('Geolocation'),'M9 16s5-4.5 5-8.5A5 5 0 0 0 4 7.5C4 11.5 9 16 9 16zM9 9a1.6 1.6 0 1 0 0-.01'],
  ['threats',T('Events'),'M9 2l6 2.5V9c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V4.5z'],
  ['settings',T('Settings'),'M9 6.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5zM9 1.5v2M9 14.5v2M1.5 9h2M14.5 9h2M3.7 3.7l1.4 1.4M12.9 12.9l1.4 1.4M3.7 14.3l1.4-1.4M12.9 5.1l1.4-1.4'],
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
const lockLive = id => { if (!isCustom()) return; const b = document.querySelector(`#${id} button[data-v="live"]`); if (b) { b.disabled = true; b.title = T('Live shows the last minutes — choose a preset period to use it'); } };
const wireSeg = (id, fn) => document.querySelectorAll(`#${id} button`).forEach(b => b.onclick = () => fn(b.dataset.v));
const hostCell = (ip, name) => `<span class="idot int"></span><b class="mono">${esc(name || ip)}</b>${name ? ` <span class="nat">${esc(ip)}</span>` : ''}`;
// values stored in English (service / protocol names made by the collector) shown in the UI language
// names the server gives to groups of values
const dv = v => v === 'Local network' ? T('Local network') : v === 'Unknown' ? T('Unknown')
  : / other$/.test(String(v || '')) ? T('{name} other', {name: String(v).slice(0, -6)}) : v;
const svcBadge = name => { const c = keyColor(name); return `<span class="app-b"><i style="background:${hexA(c, .85)};box-shadow:0 0 8px ${hexA(c, .6)}">${esc((dv(name) || '?')[0])}</i>${esc(dv(name))}</span>`; };
const fill = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; return el; };
const errBox = e => `<div class="err">${T('Failed to load: ')}${esc(e.message)}</div>`;
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
  : `<div class="empty">${T('No traffic under this filter')}</div>`;

// ===================== views =====================
async function kpiCards(){
  const [s, ser] = await Promise.all([api('summary'), api('series')]);
  // trend vs the previous equal period; until enough history exists, say since when data is collected and when the comparison appears
  const since = s.oldest ? (Date.now() / 1000 - s.oldest > 86400 ? dmy(s.oldest) + ' ' : '') + hhmm(s.oldest) : '';
  const ready = s.oldest && !s.custom ? s.oldest + 2 * s.range : 0, readyTxt = ready ? new Date(ready * 1000).toLocaleString(LOC, {day:'numeric', month:'long', hour:'2-digit', minute:'2-digit'}) : '';
  const noPrev = `<span class="tr nodata" style="color:var(--ink3)" title="${T('Comparison with the previous equal period will appear once twice as much data is collected')}${readyTxt ? T(' — approx. ') + readyTxt : ''}">${since ? T('data since ') + since : T('no data')}</span>`;
  const trend = (a, b) => !s.has_prev || !b ? noPrev : `<span class="tr ${a < b ? 'dn' : ''}" title="${T('compared to the previous equal period')}">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
  const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]);
  const card = (ic, k, v, tr, sp, col) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sparkSvg(sp, col)}</div>`;
  return card('pulse', T('Total traffic'), fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
    + card('nodes', T('Flows processed'), fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext)
    + card('ip', T('Unique IPs'), fmtN(s.ips), trend(s.ips, s.p_ips), fl.map(Math.sqrt), '#4C93FF')
    + card('grid', T('Top service'), esc(s.top_service || '—'), s.top_service ? `<span class="tr" style="color:var(--ink2)">${pct(s.top_service_bytes, s.bytes)}</span>` : '', vals.map(Math.sqrt), C.int);
}
let heroScope = null;
function mountHero(){
  if (heroScope) heroScope.dispose();
  heroScope = childScope();
  const g = state.heroMode === 'graph' || isInternal();     // no geography for inside <-> inside traffic
  const live = heroLive();
  // one Live / Period switch for Map, Graph and 3D: live = the last 2 minutes of data, period = the whole range
  const sub = live ? (g ? T('live · 2 min · updating…') : T('live · the last 2 min'))
    : (g ? rangeLabel() : T('the selected period'));
  fill('heroSec', `${ph('flow', T('Network traffic'), `<span id="heroLbl" class="tnum">${sub}</span>`,
      (isInternal() ? `<span class="legend"><span><i class="bar" style="background:${C.up}"></i>${T('client → server (what it sends)')}</span><span><i class="bar" style="background:${C.down}"></i>${T('server → client (the answer)')}</span></span>`
        : `<span class="legend"><span><i class="bar" style="background:${C.down}"></i>download</span><span><i class="bar" style="background:${C.up}"></i>upload</span>${g ? '' : `<span><i style="background:${C.int}"></i>${T('inside')}</span><span><i style="background:${C.ext}"></i>${T('outside')}</span>`}</span>`)
      + (g ? seg('scaleSeg', [['sqrt', T('Compressed'), T('Width ∝ √volume — small flows stand out next to large ones')], ['lin', T('Linear'), T('Width proportional to volume')]], state.scale) : '')
      + seg('heroLiveSeg', [['live', T('Live'), T('The last 2 minutes of data, updated as it arrives')], ['period', T('toggle::Period'), T('The whole selected period')]], live ? 'live' : 'period')
      + (isInternal() ? '' : seg('heroSeg', [['map', 'Map'], ['graph', 'Graph'], ['3d', '3D']], state.heroMode)))}
    <div id="heroBody" class="${g ? 'river' : 'chart hero-h'}"></div><div id="heroNote" class="heronote" hidden></div><div id="heroOvl"></div>`);
  lockLive('heroLiveSeg');
  wireSeg('heroSeg', m => { if (m === state.heroMode) return; state.heroMode = m; mountHero(); });
  wireSeg('heroLiveSeg', m => { const l = m === 'live'; if (l === !!state.heroLive) return; state.heroLive = l; mountHero(); });
  wireSeg('scaleSeg', m => { state.scale = m; setPressed('scaleSeg', m); RIVERS.forEach(k => k()); });
  const hb = document.getElementById('heroBody'), myScope = heroScope;
  heroScope.run(() => {
    if (g) createRiver(hb, {compact:true, refreshMs:live ? 10000 : 0, fetchData:() => api('river', {top:8, live:live ? 1 : 0, win:120, metric:state.metric}),
      onData:() => fill('heroLbl', live ? `${T('live · 2 min · updated {time}', {time: hms(Math.floor(Date.now() / 1000))})}${scaleNote()}` : rangeLabel() + scaleNote())});
  });
  if (!g) {
    // an empty map or globe says so, like the graph: nothing under this filter in the window
    const note = geo => { const n = document.getElementById('heroNote'); if (!n || heroScope !== myScope) return; n.hidden = !!geo.rows.length;
      n.textContent = geo.live ? T('No traffic with a location under this filter in the last {min} min — “Period” shows the whole range', {min: Math.round(geo.window / 60)})
        : T('No traffic with a location under this filter for the selected period'); };
    const load = () => api('geo', {live:live ? 1 : 0, win:120});
    load().then(geo => { if (!hb.isConnected || heroScope !== myScope) return; note(geo);
      myScope.run(() => { const update = state.heroMode === 'map' ? flatMap(hb, geo, null, live) : globe(hb, geo);
        if (live && update) every(15000, () => load().then(d => { if (heroScope === myScope) { note(d); update(d); } }).catch(() => {})); }); }).catch(e => fill('heroBody', errBox(e)));
    section('heroOvl', async () => {
      const [h, d, s] = await Promise.all([api('top', {dim:'int_ip', limit:5}), api('top', {dim:'ext_ip', limit:1}), api('top', {dim:'service', limit:5})]);   // the same requests as the top lists beside it
      if (heroScope !== myScope) return null;
      const a = h.rows[0], b = d.rows[0], c = s.rows[0];
      return `<div class="overlay"><div class="ovl">
        <div><span class="ico">${icon(ICO.users, 15)}</span><span>${T('Top source')}</span><b>${esc(a ? a.name || a.k : '—')}</b><small>${a ? fmtB(tot(a)) : ''}</small></div>
        <div><span class="ico">${icon(ICO.globe, 15)}</span><span>${T('Top destination')}</span><b>${esc(b ? b.k : '—')}</b><small>${b ? [b.city, fmtB(tot(b))].filter(Boolean).join(' · ') : ''}</small></div>
        <div><span class="ico">${icon(ICO.grid, 15)}</span><span>${T('Top service')}</span><b>${esc(c ? c.k : '—')}</b><small>${c ? pct(tot(c), s.total) : ''}</small></div></div>
        ${!live ? '' : `<div class="livebadge"><b>${T('Live')}</b>${T('new connections')}</div>`}</div>`;
    });
  }
}
function vOverview(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><div id="kpis" class="s12 grid" style="grid-column:span 12"><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div></div>
    <section class="glass panel s8 hero" id="heroSec"></section>
    <div class="col s4">
      <section class="glass panel">${ph('pie', T('Top services'), T('by traffic volume'))}<div id="svcBox" class="loading"></div></section>
      <section class="glass panel">${ph('users', T('Top hosts'), T('inside addresses'))}<div id="hostBox" class="loading"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', T('Traffic trend'), rangeLabel())}<div class="chart" id="cTrend"></div></section>
    <section class="glass panel s4">${ph('conv', T('Top conversations'), (isInternal() ? T('client → server') : T('inside → outside address')))}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('list', T('Recent flows'), T('new network activity'), `<button class="lnk" id="toFlows">${T('All')}</button>`)}<div id="recentBox" class="loading"></div></section></div>`;
  document.getElementById('toFlows').onclick = () => { state.view = 'flows'; render(); };
  section('kpis', kpiCards);
  mountHero();
  section('svcBox', async () => {
    const t = await api('top', {dim:'service', limit:5}); const rest = t.total - t.rows.reduce((s, r) => s + tot(r), 0);
    const rows = [...t.rows, ...(rest > 0 ? [{k:T('Others'), up:rest, dn:0}] : [])];
    setTimeout(() => { const el = document.getElementById('cDonut'); if (el) donut(el, rows, k => k === T('Others') ? C.other : keyColor(k), [fmtB(t.total), T('total traffic')]); });
    return `<div class="donut-wrap"><div class="chart donut" id="cDonut"></div><div class="dl">${rows.map(r => `<i class="idot" style="background:${r.k === T('Others') ? C.other : keyColor(r.k)}"></i>${r.k === T('Others') ? `<span>${T('Others')}</span>` : `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.k)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div></div>`;
  });
  section('hostBox', async () => { const t = await api('top', {dim:'int_ip', limit:5});
    return `<div class="tw"><table class="compact"><thead><tr><th>#</th><th>${T('Host')}</th><th class="num">${T('Traffic')}</th><th class="num">%</th><th></th></tr></thead><tbody>${t.rows.map((r, i) => `<tr class="click" data-host="${esc(r.k)}"><td class="mono">${i + 1}</td><td><div class="two-line"><b class="mono">${esc(r.name || r.k)}</b>${r.name ? `<span class="nat">${esc(r.k)}</span>` : ''}</div></td><td class="num mono">${fmtB(tot(r))}</td><td class="num mono">${pct(tot(r), t.total)}</td><td class="chev">›</td></tr>`).join('')}</tbody></table></div>`; });
  api('series').then(s => { const el = document.getElementById('cTrend'); if (el) trendChart(el, s); }).catch(e => fill('cTrend', errBox(e)));
  section('convBox', async () => { const t = await api('top', {dim:'conv', limit:5}); return convRows(t.rows, t.total); });
  section('recentBox', async () => { const t = await api('flows', {limit:7});
    return `<div class="tw"><table class="compact"><thead><tr><th>${T('Time')}</th><th>${isInternal() ? T('Client → server · service') : T('Inside → outside · service')}</th><th class="num">${T('Volume')}</th></tr></thead><tbody>${t.rows.map(f => `<tr><td class="mono">${hms(f.t)}</td><td><div class="two-line"><span class="ipl">${esc(f.name || f.int_ip)} <span class="${isBack(f) ? 'd' : 'u'}">${isBack(f) ? '←' : '→'}</span> ${esc(f.ext_ip)}</span><span class="nat">${esc(dv(f.service))}${f.l7 ? ' · ' + esc(f.l7) : ''}</span></div></td><td class="num mono">${fmtB(f.bytes)}</td></tr>`).join('') || `<tr><td colspan="4"><div class="empty">${T('No records')}</div></td></tr>`}</tbody></table></div>`; });
}

// filters that describe a river selection (a host, an outside address, or a conversation band); none for «Others»
function selFilters(sel){
  if (!sel) return [];
  const isOther = k => k === '__other', out = [];
  if (sel.type === 'band') { if (!isOther(sel.l)) out.push({k:'ip', v:sel.l}); if (!isOther(sel.r)) out.push({k:'dst', v:sel.r}); }
  else if (!isOther(sel.k)) out.push({k:sel.side === 'L' ? 'ip' : 'dst', v:sel.k});
  return out;
}
async function inspectorHtml(sel){
  if (!sel) return `<p class="note" style="margin:0">${T('Hover a ribbon or node to see the volume. A click highlights its links and shows the details here; Shift+click on a node adds it to the filters.')}</p>`;
  const extra = selFilters(sel);
  let title, subtitle = '';
  const isOther = k => k === '__other';
  if (sel.type === 'band') { title = `${isOther(sel.l) ? T('Others') : sel.l} ⇄ ${isOther(sel.r) ? T('Others') : sel.r}`; subtitle = T('conversation'); }
  else if (sel.side === 'L') title = isOther(sel.k) ? T('Other inside') : sel.k;
  else title = isOther(sel.k) ? T('Other outside') : sel.k;
  if (!extra.length) return `<div class="insp"><div class="who"><b>${esc(title)}</b></div><p class="note" style="margin:0">${T('A collapsed group — pick a specific address.')}</p></div>`;
  const [s, svc, l7, ext] = await Promise.all([api('summary', {}, extra), api('top', {dim:'service', limit:4}, extra), api('top', {dim:'l7', limit:4}, extra), api('top', {dim:'ext_ip', limit:1}, extra)]);
  const e0 = ext.rows[0];
  if (sel.type !== 'band' && sel.side === 'R' && e0) subtitle = [e0.as_org && `AS${e0.asn} ${e0.as_org}`, [e0.city, ccName(e0.country)].filter(Boolean).join(', ')].filter(Boolean).join(' · ');
  return `<div class="insp"><div class="who"><b>${esc(title)}</b><span>${esc(subtitle)}</span></div>
    <div class="dk"><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">${T('Services')}</h4><div class="tagrow">${svc.rows.map(g => `<span class="tag">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">${T('Protocols')}</h4><div class="tagrow">${l7.rows.map(g => `<span class="tag mono">${esc(dv(g.k))}</span>`).join('') || '—'}</div></div>
    <div class="chart" id="cInsp" style="height:120px" data-extra="${esc(JSON.stringify(extra))}"></div></div>`;
}
function vFlows(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid">
    <section class="glass panel s9">${ph('flow', isInternal() ? T('Exchange between inside addresses') : T('Exchange between inside and outside addresses'), isInternal() ? T('who connects to whom: clients on the left, the servers they connect to on the right · colour = direction · width = volume (the compressed scale shows small flows too) · top 10 on each side, the rest in «Others»') : T('Colour = direction · width = volume (the compressed scale shows small flows too) · top 10 on each side, the rest in «Others»'),
      seg('metricSeg', [['bytes', T('Bytes')], ['packets', T('Packets')], ['flows', 'Flows']], state.metric) + seg('scaleSeg', [['sqrt', T('Compressed'), T('Width ∝ √volume — small flows stay visible next to big ones')], ['lin', T('Linear'), T('Width proportional to volume')]], state.scale) + seg('liveSeg', [['live', T('Live')], ['period', T('toggle::Period')]], flowLive() ? 'live' : 'period'), true)}
      <div class="legend" style="margin:-6px 0 10px">${isInternal() ? `<span><i class="bar" style="background:${C.up}"></i>${T('client → server (what it sends)')}</span><span><i class="bar" style="background:${C.down}"></i>${T('server → client (the answer)')}</span><span><i style="background:${C.int}"></i>${T('inside address')}</span>` : `<span><i class="bar" style="background:${C.down}"></i>${T('download (outside → inside)')}</span><span><i class="bar" style="background:${C.up}"></i>${T('upload (inside → outside)')}</span><span><i style="background:${C.int}"></i>${T('inside address')}</span><span><i style="background:${C.ext}"></i>${T('outside address')}</span>`}<span id="winLbl" class="mono" style="margin-left:auto"></span></div>
      <div class="river big" id="river"></div></section>
    <div class="col s3">
      <section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO.pulse, 22)}</span><span class="k">${T('Total traffic')}</span><span class="v" id="kTot">—</span></section>
      <section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO.nodes, 22)}</span><span class="k">${T('Flow records')}</span><span class="v" id="kFl">—</span></section>
      <section class="glass panel">${ph('search', T('Inspector'), T('details of the selection'))}<div id="insp"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', T('Traffic volume'), 'download / upload')}<div class="chart" id="cVol"></div></section>
    <section class="glass panel s4">${ph('conv', T('Top conversations'), T('with the service'))}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', T('Protocols'), T('L7 by port'))}<div id="protoBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('list', T('Flow records'), T('raw records, one per session direction · click to expand'))}<div id="recBox" class="loading"></div></section></div>`;
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
  const winLbl = d => { const el = document.getElementById('winLbl'); if (el) el.textContent = (d.live && d.window_end ? T('2-min window to {end} · updated {time}', {end: hms(d.window_end), time: hms(Math.floor(Date.now() / 1000))}) : rangeLabel()) + scaleNote(); };
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
    return `<div class="tw"><table class="compact"><thead><tr><th>${isInternal() ? T('Client') : T('col::Inside')}</th><th>${isInternal() ? T('Server') : T('Outside')}</th><th>${T('Service')}</th><th class="num">${T('Volume')}</th></tr></thead><tbody>${t.rows.map(x => `<tr class="click" data-conv="${esc(x.int_ip)}|${esc(x.ext_ip)}" title="${T('Filter by this conversation')}"><td class="ipl">${esc(x.name || x.int_ip)}</td><td class="ipl">${esc(x.ext_ip)}</td><td>${svcBadge(x.service)}</td><td class="num mono">${isInternal() ? `<div class="two-line"><b>${fmtB(tot(x))}</b><span class="nat"><span class="u" title="${T('the client sent')}">↑ ${fmtB(x.up)}</span> <span class="d" title="${T('the server answered')}">↓ ${fmtB(x.dn)}</span></span></div>` : fmtB(tot(x))}</td></tr>`).join('')}</tbody></table></div>`; });
  document.getElementById('convBox').addEventListener('click', e => { const tr = e.target.closest('tr[data-conv]'); if (!tr) return;
    const [ip, dst] = tr.dataset.conv.split('|'); putFilter({k:'ip', v:ip, neg:false}); putFilter({k:'dst', v:dst, neg:false}); state.sel = null; render(); });
  section('protoBox', async () => { const t = await api('top', {dim:'l7', limit:6});
    setTimeout(() => { const el = document.getElementById('cProto'); if (el) donut(el, t.rows, k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), T('protocols')]); });
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
    if (!paths.length) { ctx.font = '600 13px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.textAlign = 'center'; ctx.fillText(data.live ? T('No traffic through this device under these filters in the last {min} min — Period shows the whole range', {min: Math.round(data.window / 60)}) : T('No traffic through this device for the selected filters'), W / 2, H / 2); return; }
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
        tip:`<b>${esc(nameOf(L.p.in_if))} → ${esc(nameOf(L.p.out_if))}</b><br>${fmtV(L.p.v)} · ${T('hosts')}: ${L.p.hosts}${(L.p.services || []).length ? '<br>' + esc(L.p.services.map(dv).join(', ')) : ''}`});
    }
    // core
    if (paths.some(p => sideOf(p.in_if) === 'C' || sideOf(p.out_if) === 'C')) {
      const cp = new Path2D(); cp.arc(core.x, core.y, core.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(12,22,52,.96)'; ctx.fill(cp); ctx.strokeStyle = '#8A96B4'; ctx.lineWidth = 1.4; ctx.stroke(cp);
      ctx.textAlign = 'center'; ctx.font = '600 10.5px Manrope, sans-serif'; ctx.fillStyle = C.ink2; ctx.fillText(T('device itself'), core.x, core.y + core.r + 11);
      const li = paths.find(p => sideOf(p.in_if) === 'C' || sideOf(p.out_if) === 'C'), idx = sideOf(li.in_if) === 'C' ? li.in_if : li.out_if;
      shapes.push({kind:'port', path:cp, i:idx, tip:`<b>${T('The device itself')}</b> (${idx})`});
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
        const l1 = c.other ? T('Others') : side === 'L' ? (c.h.name || c.h.host) : c.h.host;
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
      shapes.push({kind:'port', path:hit, i:D.i, tip:`<b>${esc(nameOf(D.i))}</b> (${D.i}) · ${role === 'wan' ? 'WAN' : 'LAN'}<br>${esc(addrOf(D.i))}<br>${T('enters the device')}: ${fmtV(enter.get(D.i) || 0)}<br>${T('leaves the device')}: ${fmtV(leave.get(D.i) || 0)}`});
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
    <section class="glass panel s9">${ph('nodes', T('Traffic through the device'), T('input interface → device → output interface · width = volume · click a ribbon or an interface to filter'),
      `<span id="pDevSeg"></span>` + seg('pMetricSeg', [['bytes', T('Bytes')], ['packets', T('Packets')], ['flows', 'Flows']], state.metric) + seg('pColorSeg', [['dir', T('Direction')], ['service', T('Service')]], state.ringColor || 'dir') + seg('pScaleSeg', [['sqrt', T('Compressed'), T('Width ∝ √volume — small paths stay visible next to big ones')], ['lin', T('Linear')]], state.scale) + seg('pLiveSeg', [['live', T('Live')], ['period', T('toggle::Period')]], live ? 'live' : 'period'), true)}
      <div class="legend" id="pLegend" style="margin:-6px 0 10px"></div>
      <div class="river devmap" id="cPaths"></div>
      <p class="note">${T('Follows the traffic selector at the top: Internet, Internal or All traffic (everything that passed the device). Wi-Fi SSID (VAP) interfaces of FortiGate are not sampled: traffic between two SSIDs does not appear.')}</p></section>
    <div class="col s3">
      <div id="pKpi" class="col"></div>
      <section class="glass panel">${ph('search', T('Path'), T('the selected input → output'))}<div id="pInsp"></div></section>
    </div>
    <section class="glass panel s7">${ph('conv', T('Paths'), T('input → output interface · click to filter'))}<div id="pTable" class="loading"></div></section>
    <section class="glass panel s5">${ph('ip', T('Interfaces'), T('traffic entering and leaving each interface'))}<div id="pIfs" class="loading"></div></section></div>`;
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
    fill('pDevSeg', `<label class="sel glass" title="${T('Device')}">${icon(ICO.dev, 16)}<select id="pDevSel" aria-label="${T('Device')}">${opts}</select></label>`);
    const ds = document.getElementById('pDevSel');
    if (ds) ds.onchange = () => { state.pathDev = ds.value;
      state.filters = state.filters.filter(f => !['in_if', 'out_if', 'iface'].includes(f.k));
      if (df) { state.filters = state.filters.filter(f => f.k !== 'device'); putFilter({k:'device', v:ds.value, neg:false}); }
      render(); };
    if (!dev) { fill('cPaths', `<div class="empty">${T('No device has sent data yet')}</div>`); return; }
    const ifs = new Map(dev.interfaces.map(i => [i.index, i]));
    const extra = df ? [] : [{k:'device', v:ip}];
    const load = () => api('paths', {t:state.traffic, metric:state.metric, live:live ? 1 : 0, win:120}, extra);
    const color = new Map();
    // a fixed colour per interface (role colour for WAN / the device itself, else by its place among the device's interfaces)
    const plain = [...ifs.values()].filter(i => !ROLE_COLOR[i.role]).map(i => i.index).sort((a, b) => a - b);
    const ifColor = idx => { if (!color.has(idx)) { const r = (ifs.get(idx) || {}).role; const pos = plain.indexOf(idx);
      color.set(idx, ROLE_COLOR[r] || IFPAL[(pos >= 0 ? pos : plain.length + color.size) % IFPAL.length]); } return color.get(idx); };
    const ifName = idx => { const i = ifs.get(idx); return i ? (i.custom_name || i.name) : (idx === 0 ? 'local' : `if ${idx}`); };
    // an address or network that identifies the interface: entered by hand, else what the flows show
    const ifAddr = idx => { const i = ifs.get(idx); return i ? (ifAddrs(i)[0] || '') : ''; };
    const ifNamed = idx => { const i = ifs.get(idx); return !!(i && (i.custom_name || i.snmp_name)) || idx === 0; };
    const ifRole = idx => { const r = (ifs.get(idx) || {}).role || 'lan'; return r === 'wan' ? 'WAN' : r === 'local' ? T('device itself') : 'LAN'; };
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
          + `<span class="nat">${T('colour = main service of the path')}</span>`);
      } else
      fill('pLegend', `<span><i style="background:${C.int}"></i>${T('inside hosts · inside interfaces')}</span><span><i class="bar" style="background:${C.up}"></i>${T('to the internet')}</span><span><i class="bar" style="background:${C.down}"></i>${T('from the internet')}</span><span><i class="bar" style="background:${C.int}"></i>${T('between inside networks (arc)')}</span><span><i class="bar" style="background:#6E7FA6"></i>${T('to / from the device itself')}</span><span style="margin-left:auto"><i style="background:${C.ext}"></i>${T('WAN · internet hosts')}</span>` + (d.live && d.window_end ? `<span class="mono">${T('2-min window to {end}', {end: hms(d.window_end)})}</span>` : `<span class="mono">${rangeLabel()}</span>`));
      // KPIs, tables
      const by = f => rows.reduce((a, r) => a + (f(r) ? r.b : 0), 0), totB = by(() => true);
      const isWan = i => (ifs.get(i) || {}).role === 'wan', isLocal = i => (ifs.get(i) || {}).role === 'local';
      const kc = (ic, k, val, sub) => `<section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span class="v">${val}</span>${sub ? `<span class="nat" style="grid-column:2">${sub}</span>` : ''}</section>`;
      fill('pKpi', kc('pulse', T('Through the device'), fmtB(totB), `${rows.length} ${T('paths')}`)
        + kc('globe', T('Internet'), fmtB(by(r => isWan(r.in_if) || isWan(r.out_if))), `${pct(by(r => isWan(r.in_if) || isWan(r.out_if)), totB)}`)
        + kc('nodes', T('Between inside networks'), fmtB(by(r => !isWan(r.in_if) && !isWan(r.out_if) && !isLocal(r.in_if) && !isLocal(r.out_if))), '')
        + kc('dev', T('To / from the device itself'), fmtB(by(r => isLocal(r.in_if) || isLocal(r.out_if))), ''));
      const pill = i => `<span class="idot" style="background:${ifColor(i)};box-shadow:0 0 8px ${ifColor(i)}"></span><b class="mono">${esc(ifName(i))}</b>${ifNamed(i) ? ` <span class="nat">${i}</span>` : ''}`;
      const max = rows.length ? rows[0].v : 1;
      const tb = fill('pTable', `<div class="tw"><table class="compact"><thead><tr><th>${T('Input')}</th><th></th><th>${T('Output')}</th><th style="width:26%">${T('Volume')}</th><th class="num">%</th><th class="num">Flows</th><th class="num">${T('Hosts')}</th><th>${T('Main services')}</th></tr></thead><tbody>
        ${rows.slice(0, 15).map(r => `<tr class="click" data-path="${r.in_if}|${r.out_if}"><td>${pill(r.in_if)}</td><td class="nat">→</td><td>${pill(r.out_if)}</td>
          <td><b class="mono">${unit(r.v)}</b><div class="vbar"><i style="width:${(100 * r.v / max).toFixed(1)}%;background:linear-gradient(90deg,${ifColor(r.in_if)},${ifColor(r.out_if)})"></i></div></td>
          <td class="num mono">${pct(r.v, total)}</td><td class="num mono">${fmtN(r.fl)}</td><td class="num mono">${r.hosts}</td><td class="nat">${esc(r.services.map(dv).join(', '))}</td></tr>`).join('')}</tbody></table></div>`);
      if (tb) { tb.classList.remove('loading'); tb.querySelectorAll('tr[data-path]').forEach(tr => tr.onclick = () => { const [a, b] = tr.dataset.path.split('|');
        putFilter({k:'in_if', v:a, neg:false}); putFilter({k:'out_if', v:b, neg:false}); if (!df) putFilter({k:'device', v:ip, neg:false}); render(); }); }
      const allIf = [...new Set([...ins.keys(), ...outs.keys()])].sort((a, b) => (outs.get(b) || 0) + (ins.get(b) || 0) - (outs.get(a) || 0) - (ins.get(a) || 0));
      const ib = fill('pIfs', `<div class="tw"><table class="compact"><thead><tr><th>${T('Interface')}</th><th>${T('Role')}</th><th class="num">${T('Entering')}</th><th class="num">${T('Leaving')}</th><th>${T('Addresses')}</th></tr></thead><tbody>
        ${allIf.map(i => { const x = ifs.get(i) || {addrs:[], seen_addrs:[]};
          return `<tr><td>${pill(i)}</td><td><span class="tag">${ifRole(i)}</span></td><td class="num mono">${unit(ins.get(i) || 0)}</td><td class="num mono">${unit(outs.get(i) || 0)}</td><td class="nat mono">${esc(ifAddrs(x).slice(0, 2).join(', ') || '—')}</td></tr>`; }).join('')}</tbody></table></div>`);
      if (ib) ib.classList.remove('loading');
    };
    // inspector of the selected path (interface filters)
    const fi = state.filters.find(f => f.k === 'in_if' && !f.neg), fo = state.filters.find(f => f.k === 'out_if' && !f.neg);
    if (fi || fo) {
      const [hosts, svc, dst] = await Promise.all([api('top', {dim:'int_ip', limit:5, t:state.traffic}, extra), api('top', {dim:'service', limit:5, t:state.traffic}, extra), api('top', {dim:'ext_ip', limit:5, t:state.traffic}, extra)]);
      if (seq !== renderSeq) return;
      const list = (rows, name) => rows.map(r => `<div class="brow" style="cursor:default"><span class="n">${esc(name(r))}</span><span class="t">${fmtB(tot(r))}</span><span class="p"></span></div>`).join('') || '—';
      fill('pInsp', `<div class="insp"><div class="who"><b>${esc(fi ? ifName(+fi.v) : '*')} → ${esc(fo ? ifName(+fo.v) : '*')}</b><span>${esc(dev.name)}</span></div>
        <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">${T('Hosts')}</h4><div class="blist">${list(hosts.rows, r => r.name || r.k)}</div></div>
        <div><h4 style="margin:6px 0;font-size:12.5px;color:var(--ink2)">${T('Services')}</h4><div class="blist">${list(svc.rows, r => dv(r.k))}</div></div>
        <div><h4 style="margin:6px 0;font-size:12.5px;color:var(--ink2)">${T('Destinations')}</h4><div class="blist">${list(dst.rows, r => r.k)}</div></div></div>`);
    } else fill('pInsp', `<p class="note" style="margin:0">${T('Click a ribbon to see who and what uses that path. The path then filters every page.')}</p>`);
    const pickMap = sh => {
      if (sh.kind === 'path') { putFilter({k:'in_if', v:String(sh.in_if), neg:false}); putFilter({k:'out_if', v:String(sh.out_if), neg:false}); }
      else if (sh.kind === 'port') putFilter({k:'iface', v:String(sh.i), neg:false});
      else if (sh.kind === 'host') putFilter({k:sh.side === 'L' ? 'ip' : 'dst', v:sh.ip, neg:false});
      if (!df) putFilter({k:'device', v:ip, neg:false});
      render(); };
    const mapEl = document.getElementById('cPaths');
    if (mapEl) createDevMap(mapEl, {ifs, dev, refreshMs:live ? 10000 : 0, onPick:pickMap,
      fetchData:() => api('devmap', {t:state.traffic, metric:state.metric, live:live ? 1 : 0, win:120, top:6}, extra)});
    try { draw(await load()); } catch (e) { fill('pTable', errBox(e)); }
    if (live) every(10000, () => load().then(d => { if (seq === renderSeq) draw(d); }).catch(() => {}));
  })().catch(e => fill('cPaths', errBox(e)));
}
// ===================== path analysis: layer-3 neighbours of a device and the path of traffic across devices =====================
const LINK_STATE = {
  observed:[T('Observed'), T('traffic recorded by both ends')],
  gap:[T('Gap'), T('one end sent much more than the other received')],
  unobserved:[T('No observation'), T('the other end sends no NetFlow')],
  one_sided:[T('One side'), T('the interface of the other end towards this one is not known')],
  adjacent:[T('No traffic'), T('neighbours by addressing, no traffic in the period')]};
const HOP_STATE = {observed:T('recorded'), gap:T('recorded nothing — gap'), unobserved:T('sends no NetFlow'),
  internet:T('the internet'), branch:T('on another exit'), unplaced:T('recorded it, place on the path unknown')};
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
    if (!data.nodes.length) { ctx.font = '600 13px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.textAlign = 'center'; ctx.fillText(T('No device has sent data yet'), W / 2, H / 2); return; }
    const node = new Map(data.nodes.map(n => [n.ip, n])), onPath = opts.pathSet ? opts.pathSet() : null;
    const v = x => state.scale === 'lin' ? x : Math.sqrt(x);
    const vmax = Math.max(1e-9, ...data.links.map(l => v(Math.max(l.a_out, l.b_in) + Math.max(l.b_out, l.a_in))));
    const lw = x => x > 0 ? 2 + 14 * v(x) / vmax : 0;
    const nm = d => esc(d === 'internet' ? T('Internet') : (node.get(d) || {}).name || d);
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
    const stateLook = l => l.state === 'adjacent' ? ['rgba(170,190,230,.55)', T('no traffic')] : l.state === 'gap' || l.state === 'unobserved' ? [RED, '⨯ ' + LINK_STATE[l.state][0]] : null;
    const tipOf = l => `<b>${nm(l.a)} ${esc(l.a_name)} ↔ ${nm(l.b)} ${esc(l.b_name)}</b>${l.net ? ` <span class="nat">${esc(l.net)}</span>` : ''}<div style="color:${l.state === 'observed' ? C.ext : l.state === 'adjacent' || l.state === 'one_sided' ? C.ink2 : RED}">${LINK_STATE[l.state][0]} — ${LINK_STATE[l.state][1]}</div>`
      + (l.b === 'internet' ? `<div>${T('to the internet')}: <b class="mono">${fmtB(l.a_out)}</b> · ${T('from it')}: <b class="mono">${fmtB(l.a_in)}</b></div>`
        : [[l.a, l.b, l.a_out, l.b_in], [l.b, l.a, l.b_out, l.a_in]].map(([f, t, s, g]) => `<div>${nm(f)} → ${nm(t)}: <b class="mono">${fmtB(s)}</b> ${T('sent')} · <b class="mono">${fmtB(g)}</b> ${T('received')}</div>`).join(''));
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
      ctx.textAlign = 'left'; ctx.font = '700 14px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(T('Internet'), cloud.x - 20, cloud.y + 12);
      ctx.globalAlpha = 1;
      shapes.push({path:cp, cloud:true, tip:`<b>${T('Internet')}</b>` + wl.map(l => `<div>${nm(l.a)} <span class="mono">${esc(l.a_name)}</span>: ↗ <b class="mono">${fmtB(l.a_out)}</b> · ↘ <b class="mono">${fmtB(l.a_in)}</b></div>`).join('')});
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
      ctx.textAlign = 'left'; ctx.font = '700 13px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(clip(n.ip === 'internet' ? T('Internet') : n.name || n.ip, ctx.font, p.w - 52), x + 36, y + 22);
      ctx.font = '500 11px Manrope, sans-serif'; ctx.fillStyle = C.ink3;
      ctx.fillText(clip(n.ip === 'internet' ? T('beyond the WAN') : [n.vendor, n.model].filter(Boolean).join(' ') || T('device'), ctx.font, p.w - 24), x + 12, y + 44);
      ctx.font = '600 11px JetBrains Mono, monospace'; ctx.fillStyle = C.ink2; if (n.ip !== 'internet') ctx.fillText(n.ip, x + 12, y + 60);
      if (n.ip !== 'internet') { ctx.beginPath(); ctx.arc(x + p.w - 13, y + 14, 4, 0, 7); ctx.fillStyle = n.exporting ? C.ext : C.ink3; ctx.fill(); }
      if (n.more) { const bx = x + p.w - 34, by = y + p.h - 22; ctx.fillStyle = 'rgba(47,123,255,.35)'; ctx.fill(rr(bx, by, 26, 16, 8)); ctx.font = '700 10.5px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.textAlign = 'center'; ctx.fillText('+' + n.more, bx + 13, by + 8.5); }
      const k = onPath && opts.hopNo ? opts.hopNo(n.ip) : 0;
      if (k) { ctx.beginPath(); ctx.arc(x + 2, y + 2, 10, 0, 7); ctx.fillStyle = '#27D3F5'; ctx.fill(); ctx.font = '800 11px Manrope, sans-serif'; ctx.fillStyle = '#04102A'; ctx.textAlign = 'center'; ctx.fillText(k, x + 2, y + 2.5); }
      ctx.globalAlpha = 1;
      shapes.push({path:card, n, tip:`<b>${nm(n.ip)}</b>${n.ip !== 'internet' ? ` <span class="nat">${esc(n.ip)}</span><div>${n.exporting ? T('sends NetFlow') : T('sent no NetFlow in this period')}</div>` : ''}${n.more ? `<div>${Tn(n.more, '{n} more neighbour beyond', '{n} more neighbours beyond')}</div>` : ''}${n.ip !== data.pov && n.ip !== 'internet' ? `<div class="nat">${T('Click: look from this device')}</div>` : ''}`});
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
    <section class="glass panel s9">${ph('nodes', T('Path analysis'), T('layer-3 neighbours of the Point of View · width = volume · click a device to look from it'),
      `<span id="nPovSeg"></span>` + seg('nDepthSeg', [['1', '1'], ['2', '2'], ['3', '3']].map(([k, l]) => [k, l, Tn(+k, 'Neighbours up to {n} hop away', 'Neighbours up to {n} hops away')]), String(depth))
      + seg('nScaleSeg', [['sqrt', T('Compressed'), T('Width ∝ √volume — small links stay visible next to big ones')], ['lin', T('Linear')]], state.scale)
      + seg('nLiveSeg', [['live', T('Live')], ['period', T('toggle::Period')]], live ? 'live' : 'period'))}
      <div class="legend" style="margin:-6px 0 10px"><span><i class="bar" style="background:${C.down}"></i>${T('from the internet')}</span><span><i class="bar" style="background:${C.up}"></i>${T('to the internet')}</span><span><i class="bar" style="background:${C.int}"></i>${T('internal')}</span><span><i class="bar dash" style="border-color:${RED}"></i>${T('no observation / gap')}</span><span><i class="bar dash" style="border-color:#AABEE6"></i>${T('L3 adjacency, no traffic')}</span></div>
      <div class="river netmap" id="cNet"></div>
      <p class="note">${T('Devices are neighbours when their interfaces share a subnet (Settings → Devices → Interfaces) or when one records the other’s addresses on an interface. The volumes on the links follow the selector at the top (Internet, Internal or All traffic); neighbours, gaps and the path search always use all traffic, and the device filter does not apply — choose the Point of View instead.')}</p></section>
    <div class="col s3">
      <div id="nKpi" class="col"></div>
      <section class="glass panel">${ph('search', T('Path'), T('the hops from a source to a destination'))}
        <form class="form trace" id="nTrace" autocomplete="off"><label>${T('Source')}<input id="nSrc" class="mono" placeholder="10.20.0.21 ${T('or')} 10.20.0.0/24" value="${esc(state.netSrc || '')}"></label>
          <label>${T('Destination')}<input id="nDst" class="mono" placeholder="8.8.8.8 ${T('or')} 0.0.0.0/0" value="${esc(state.netDst || '')}"></label>
          <div class="acts"><button type="button" class="btn" id="nSwap" title="${T('Swap: the reply direction')}">⇄</button><button class="btn primary" id="nGo">${T('Trace')}</button>${state.netPath ? `<button type="button" class="btn" id="nClear">${T('Clear')}</button>` : ''}</div></form>
        <div id="nPath"></div></section>
    </div>
    <section class="glass panel s12">${ph('conv', T('Links'), T('what each end of a link sent and the other received'))}<div id="nLinks" class="loading"></div></section></div>`;
  wireSeg('nDepthSeg', m => { if (+m === depth) return; state.netDepth = +m; render(); });
  wireSeg('nScaleSeg', m => { if (m === state.scale) return; state.scale = m; render(); });
  lockLive('nLiveSeg');
  wireSeg('nLiveSeg', m => { const l = m === 'live'; if (l === !!state.netLive) return; state.netLive = l; render(); });
  const seq = renderSeq, P = () => ({t:state.traffic, live:live ? 1 : 0, win:120});
  let topo = null, path = null;
  const hopIndex = () => { const m = new Map(); if (path) path.hops.forEach((h, k) => { if (!m.has(h.device) && h.state !== 'unplaced' && h.state !== 'branch') m.set(h.device, k + 1); }); return m; };
  const map = createTopoMap(document.getElementById('cNet'), {onNode:n => { if (n.ip === 'internet' || n.ip === state.netPov) return; state.netPov = n.ip; if (n.more) state.netDepth = Math.max(depth, 1); render(); },
    pathSet:() => path && path.hops.length ? new Set(path.hops.filter(h => h.state !== 'unplaced').map(h => h.device)) : null, hopNo:ip => hopIndex().get(ip)});
  const nm = ip => ip === 'internet' ? T('Internet') : ((topo && topo.devices.find(d => d.ip === ip)) || {}).name || ip;
  const drawSide = () => {
    const ls = topo.links, cnt = s => ls.filter(l => l.state === s).length;
    const kc = (ic, k, val, sub, col) => `<section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span>${sub ? `<span class="nat" style="grid-column:2">${sub}</span>` : ''}</section>`;
    const pv = topo.devices.find(d => d.ip === topo.pov);
    fill('nKpi', kc('dev', T('Point of View'), esc(pv ? pv.name : '—'), pv ? Tn(pv.neighbours, '{n} L3 neighbour', '{n} L3 neighbours') : '')
      + kc('nodes', T('Links shown'), ls.length, `${cnt('observed')} ${T('observed')}`)
      + kc('shield', T('Gaps · not observed'), `${cnt('gap')} · ${cnt('unobserved')}`, T('links to check'), cnt('gap') + cnt('unobserved') ? RED : ''));
    const row = (d, name, addr, seen) => `<b>${esc(nm(d))}</b> <span class="mono">${esc(name)}</span>${addr ? ` <span class="nat mono"${seen ? ` title="${T('seen in the records of 24 h (the interface has no address from the settings or SNMP)')}"` : ''}>${esc(addr)}</span>` : ''}`;
    const sr = (sent, got, inet) => inet ? `<b class="mono">${fmtB(sent)}</b>` : `<b class="mono">${fmtB(sent)}</b> <span class="nat">/ ${fmtB(got)}</span>`;
    const tb = fill('nLinks', ls.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('End A')}</th><th></th><th>${T('End B')}</th><th>${T('State')}</th><th class="num">${T('A → B sent / received')}</th><th class="num">${T('B → A sent / received')}</th><th>${T('Found by')}</th></tr></thead><tbody>
      ${ls.map(l => { const inet = l.b === 'internet', bad = l.state === 'gap' || l.state === 'unobserved';
        return `<tr><td>${row(l.a, l.a_name, l.a_addr, l.a_seen)}</td><td class="nat">↔</td><td>${inet ? `<b>${T('Internet')}</b>` : row(l.b, l.b_name, l.b_addr, l.b_seen)}</td>
          <td><span class="tag" title="${esc(LINK_STATE[l.state][1])}"${bad ? ` style="color:${RED};border-color:${hexA(RED, .5)}"` : ''}>${LINK_STATE[l.state][0]}</span></td>
          <td class="num">${sr(l.a_out, l.b_in, inet)}</td><td class="num">${inet ? `<b class="mono">${fmtB(l.a_in)}</b>` : sr(l.b_out, l.a_in)}</td>
          <td class="nat">${l.evidence === 'subnet' ? T('subnet') + ' ' + esc(l.net) : l.evidence === 'wan' ? T('WAN interface') : T('addresses in the records')}</td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty">${T('This device has no layer-3 neighbours among the devices: set interface addresses in Settings → Devices → Interfaces, or wait for traffic between the devices.')}</div>`);
    if (tb) tb.classList.remove('loading');
  };
  const drawPath = () => {
    if (!path) { fill('nPath', `<p class="note" style="margin:8px 0 0">${T('Enter an address or a network on each side. Each device on the way shows the interfaces the traffic used; a device that should have seen it but recorded nothing marks a gap.')}</p>`); return; }
    const hs = path.hops, real = hs.filter(h => !['internet', 'unplaced', 'branch'].includes(h.state)), obs = real.filter(h => h.state === 'observed').length, gaps = real.length - obs;
    if (!hs.length) { fill('nPath', `<div class="empty">${T('No device recorded traffic from this source to this destination in the period.')}</div>`); return; }
    const total = Math.max(0, ...hs.map(h => h.bytes));
    const el = fill('nPath', `<div class="pstats"><div><span>${T('Hops')}</span><b>${real.length}</b></div><div><span>${T('Observed')}</span><b>${obs} / ${real.length}</b></div><div><span>${T('Gaps')}</span><b${gaps ? ` style="color:${RED}"` : ''}>${gaps}${gaps ? ' ⚠' : ''}</b></div><div><span>${T('Traffic')}</span><b>${fmtB(total)}</b></div></div>
      <ol class="hops">${hs.map((h, k) => { const bad = h.state === 'gap' || h.state === 'unobserved';
        return `<li class="hop ${h.state}" data-dev="${esc(h.device)}"><span class="no">${h.state === 'unplaced' ? '?' : h.state === 'branch' ? '↳' : k + 1}</span><div><b>${esc(h.state === 'internet' ? T('Internet') : h.name)}</b>
          ${h.state === 'observed' || h.state === 'unplaced' || h.state === 'branch' ? `<div class="mono">${esc(h.in_name)} → ${esc(h.out_name)}</div><div class="nat">${fmtB(h.bytes)} · ${fmtN(h.convs)} ${T('conversations')}${h.share < 1 ? ` · ${Math.round(100 * h.share)}% ${T('of the busiest hop')}` : ''}</div>
            <div class="vbar"><i style="width:${(100 * h.share).toFixed(1)}%;background:linear-gradient(90deg,${hexA(C.down, .6)},${C.down})"></i></div>` : ''}
          ${h.nat && h.nat.length ? `<div class="nat">NAT → <span class="mono">${esc(h.nat.join(', '))}</span></div>` : ''}
          ${(h.other_exits || []).map(e => `<div class="nat">${T('also leaves via')} <span class="mono">${esc(e.out_name)}</span>${e.next ? ` → ${esc(nm(e.next))}` : ''}: ${fmtB(e.bytes)}</div>`).join('')}
          <div class="st"${bad ? ` style="color:${RED}"` : ''}>${HOP_STATE[h.state]}${h.state === 'branch' ? ` ${T('of hop')} ${h.via_hop + 1}` : ''}</div></div></li>`; }).join('')}</ol>
      <p class="note" style="margin:6px 0 0">${path.complete ? T('Every device on the way recorded the traffic.') : T('The path is not seen whole: see the marked hops.')}</p>`);
    if (el) el.querySelectorAll('li[data-dev]').forEach(li => li.onclick = () => { const d = li.dataset.dev; if (d === 'internet' || d === state.netPov) return; state.netPov = d; render(); });
  };
  const load = () => api('topology', {...P(), pov:state.netPov || '', depth});
  const show = d => { if (seq !== renderSeq) return; topo = d; state.netPov = d.pov;
    const opts = d.devices.slice().sort((a, b) => a.name.localeCompare(b.name)).map(x => `<option value="${esc(x.ip)}"${x.ip === d.pov ? ' selected' : ''}${!x.neighbours ? ' disabled' : ''}>${esc(x.name)} (${esc(x.ip)})${!x.neighbours ? ' — ' + T('no L3 neighbours') : ''}</option>`).join('');
    fill('nPovSeg', `<label class="sel glass" title="${T('Point of View')}">${icon(ICO.dev, 16)}<select id="nPovSel" aria-label="${T('Point of View')}">${opts}</select></label>`);
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
// the top hosts as CSV: [header, rows]; inside traffic adds how many inside hosts each one connected to / was connected from
function hostsCsv(rows, secs){
  const head = ['rank', 'ip', 'name', 'bytes', 'upload', 'download', 'percent', 'flows', 'avg_bps', ...(isInternal() ? ['connects_to', 'connected_from'] : [])];
  return [head, rows.map((r, i) => [i + 1, r.k, r.name || '', tot(r), r.up, r.dn, (100 * tot(r) / (window.__tTotal || 1)).toFixed(2), r.fl, Math.round(tot(r) * 8 / secs),
    ...(isInternal() ? [r.calls || 0, r.callers || 0] : [])])];
}
function recTable(rows){
  return `<div class="tw"><table><thead><tr><th>${T('Time')}</th><th>${T('Exporter')}</th><th>${T('Inside address')}</th><th></th><th>${T('Outside address')}</th><th>${T('Protocol')}</th><th>${T('Service')}</th><th>${T('Country')}</th><th class="num">${T('Bytes')}</th><th class="num">${T('Packets')}</th><th class="num">${T('Dur.')}</th></tr></thead><tbody>
    ${rows.map((f, i) => `<tr class="click" data-rec="${i}"><td class="mono">${hms(f.t)}</td><td class="ipl">${esc(devName(f.exporter))}</td>
      <td class="ipl"><button class="link" data-f="ip" data-v="${esc(f.int_ip)}">${esc(f.name || f.int_ip)}</button> <span class="nat">:${f.int_port}</span></td><td class="${isBack(f) ? 'd' : 'u'}">${isBack(f) ? '←' : f.dir === 'transit' ? '↔' : '→'}</td>
      <td class="ipl"><button class="link" data-f="dst" data-v="${esc(f.ext_ip)}">${esc(f.ext_ip)}</button> <span class="nat">:${f.ext_port}</span></td><td><span class="tag">${esc(dv(f.l7))}</span></td><td>${svcBadge(f.service)}</td>
      <td>${f.country ? `<button class="link" data-f="country" data-v="${esc(f.country)}">${esc(f.country)}</button>` : '—'}</td><td class="num mono">${fmtB(f.bytes)}</td><td class="num mono">${fmtN(f.packets)}</td><td class="num mono">${Math.max(0, f.t - f.t0).toFixed(0)} ${T('s')}</td></tr>
      ${state.openFlow === i ? `<tr class="detail"><td colspan="11"><div class="kv"><div><span>${T('Host')}</span><b>${esc(f.name || '—')} · ${esc(f.int_ip)}</b></div><div><span>${T('NAT (after translation)')}</span><b>${f.nat_ip ? esc(f.nat_ip) + ':' + f.nat_port : '—'}</b></div>
        <div><span>ASN</span><b>${f.asn ? 'AS' + f.asn + ' ' + esc(f.as_org) : '—'}</b></div><div><span>${T('City')}</span><b>${esc([f.city, ccName(f.country)].filter(Boolean).join(', ') || '—')}</b></div>
        <div><span>${T('Interfaces')}</span><b>${esc(ifLabel(f.exporter, f.in_if))} → ${esc(ifLabel(f.exporter, f.out_if))}</b></div><div><span>${T('Sampling')}</span><b>${f.sampling > 1 ? '1:' + f.sampling + T(' (volume scaled up)') : T('1:1 (not sampled)')}</b></div><div><span>L4</span><b>${({1:'ICMP', 6:'TCP', 17:'UDP', 50:'ESP', 47:'GRE'})[f.proto] || f.proto}</b></div></div></td></tr>` : ''}`).join('') || `<tr><td colspan="11"><div class="empty">${T('No records for this filter')}</div></td></tr>`}
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
      <section class="glass panel">${ph('users', T('Top hosts'), T('by total volume · click a row to add the host to the filters'), '<button class="lnk" id="tMore"></button>')}<div id="tBox" class="loading"></div></section>
      <section class="glass panel grow">${ph('chart', T('Top hosts trend'), T('top 5 and the rest'))}<div class="chart" id="cTop5"></div></section>
    </div>
    <div class="col s4">
      <section class="glass panel">${ph('pie', T('Top hosts traffic'), T('share of the total volume'))}<div id="tDonut" class="loading"></div></section>
      <section class="glass panel">${ph('grid', T('By service'), T('share of traffic · click to filter'))}<div id="tSvc" class="loading"></div></section>
      <section class="glass panel">${ph('globe', T('Where the traffic goes'), T('destination countries'))}<div id="tGeo" class="loading"></div></section>
      <section class="glass panel">${ph('search', T('Quick actions'), '<span id="qaFor">—</span>')}<div class="qa" id="qa"></div></section>
    </div>
    <section class="glass panel s12">${ph('list', T('Top hosts in detail'), T('main service and protocol of each · click to filter'), `<button class="lnk" id="toFlows2">${T('Flows →')}</button>`)}<div id="tDetail" class="loading"></div></section></div>`;
  document.getElementById('toFlows2').onclick = () => { state.view = 'flows'; render(); };
  const limit = state.talkersAll ? 50 : 10, secs = rangeSecs();
  fill('tMore', state.talkersAll ? T('Show top 10') : T('Show top 50'));
  document.getElementById('tMore').onclick = () => { state.talkersAll = !state.talkersAll; render(); };
  const colorOf = new Map();
  let selected = null, topRows = [];
  const drawQa = () => {
    const h = selected; fill('qaFor', h ? T('for {name}', {name: esc(h.name || h.k)}) : T('no data'));
    const box = fill('qa', h ? [
      ['flow', T('Flow details'), T('the Flows page with a filter'), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'flows'; render(); }],
      ['users', T('Host card'), T('services, protocols, destinations'), () => openHost(h.k)],
      ['globe', T('Geolocation'), T('connection map of this host'), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'geo'; render(); }],
      ['list', T('Export CSV'), T('the top hosts table'), () => downloadCsv(`flowtrack-top-hosts-${isCustom() ? state.from + '-' + state.to : state.range}.csv`, ...hostsCsv(topRows, secs))],
    ].map(([ic, t, sub], i) => `<button class="qa-btn" data-qa="${i}"><span class="ico">${icon(ICO[ic], 18)}</span><span><b>${t}</b><small>${sub}</small></span></button>`).join('') : '');
    if (box && h) { const acts = [() => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'flows'; render(); }, () => openHost(h.k), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'geo'; render(); },
      () => downloadCsv(`flowtrack-top-hosts-${isCustom() ? state.from + '-' + state.to : state.range}.csv`, ...hostsCsv(topRows, secs))];
      box.querySelectorAll('[data-qa]').forEach(b => b.onclick = acts[+b.dataset.qa]); }
  };
  section('tKpi', async () => {
    const [s, ser, t] = await Promise.all([api('summary'), api('series'), api('top', {dim:'int_ip', limit:1})]);
    const trend = (a, b) => !s.has_prev || !b ? `<span class="tr nodata" style="color:var(--ink3)">${T('data since {time}', {time: hhmm(s.oldest)})}</span>` : `<span class="tr ${a < b ? 'dn' : ''}">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
    const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]), top = t.rows[0];
    const card = (ic, k, v, tr, sp, col, sub) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sub ? `<span class="s" style="grid-column:2/-1;font-size:12.5px;color:var(--ink2)">${sub}</span>` : ''}${sp ? sparkSvg(sp, col) : ''}</div>`;
    return card('pulse', T('Total traffic'), fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
      + card('ip', T('Top host (by volume)'), esc(top ? top.name || top.k : '—'), '', null, '', top ? `${esc(top.name ? top.k + ' · ' : '')}${fmtB(tot(top))} (${pct(tot(top), t.total)})` : '')
      + card('users', T('Unique hosts'), fmtN(s.hosts), trend(s.hosts, s.p_hosts), fl.map(Math.sqrt), C.int)
      + card('nodes', T('Total flows'), fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext);
  });
  Promise.all([api('top', {dim:'int_ip', limit}), api('series', {by:'int_ip', top:Math.min(limit, 20)})]).then(([t, ser]) => {
    topRows = t.rows; window.__tTotal = t.total;
    t.rows.forEach((r, i) => colorOf.set(r.k, HOSTPAL[i % HOSTPAL.length]));
    const fip = (state.filters.find(f => f.k === 'ip' && !f.neg) || {}).v;
    selected = t.rows.find(r => r.k === fip) || t.rows[0] || null; drawQa();
    const sp = new Map(); for (const [ts, k, b] of ser.rows) { if (!sp.has(k)) sp.set(k, new Map()); sp.get(k).set(ts, b); }
    const {ts} = grid(ser), max = t.rows.length ? tot(t.rows[0]) : 1;
    const box = fill('tBox', `<div class="tw"><table class="talkers"><thead><tr><th>#</th><th>${T('Host / IP')}</th><th style="width:26%">${T('Volume')}</th>${isInternal() ? `<th class="num" title="${T('→ inside hosts it connected to · ← inside hosts that connected to it')}">${T('Connections')}</th>` : ''}<th class="num">%</th><th class="num">Flows</th><th class="num">${T('Avg rate')}</th><th>${T('Trend')}</th><th></th></tr></thead><tbody>
      ${t.rows.map((r, i) => { const c = colorOf.get(r.k);
        return `<tr class="click${r.k === fip ? ' is-picked' : ''}" data-pick="${esc(r.k)}" title="${T('Add to filters')}"><td class="mono">${i + 1}</td><td><div class="hcell"><span class="hbar" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="htxt"><b class="mono">${esc(r.k)}</b><span class="nat">${esc(r.name || (r.k.startsWith('10.') || r.k.startsWith('192.168.') || r.k.startsWith('172.') ? T('no name') : T('public address')))}</span></span></div></td>
          <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .55)},${c});box-shadow:0 0 8px ${hexA(c, .6)}"></i></div>${isInternal() ? `<span class="nat mono"><span class="u" title="${T('sent')}">↑ ${fmtB(r.up)}</span> <span class="d" title="${T('received')}">↓ ${fmtB(r.dn)}</span></span>` : ''}</td>
          ${isInternal() ? `<td class="num mono"><span class="u" title="${T('inside hosts it connected to')}">→ ${fmtN(r.calls || 0)}</span> · <span class="d" title="${T('inside hosts that connected to it')}">← ${fmtN(r.callers || 0)}</span></td>` : ''}<td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${fmtN(r.fl)}</td><td class="num mono">${fmtR(tot(r) * 8 / secs)}</td>
          <td style="width:120px">${sp.has(r.k) ? sparkSvg(ts.map(x => sp.get(r.k).get(x) || 0), c, 120, 26) : ''}</td><td><button class="btn" data-open="${esc(r.k)}" title="${T('Host card')}">›</button></td></tr>`; }).join('') || `<tr><td colspan="${isInternal() ? 9 : 8}"><div class="empty">${T('No data')}</div></td></tr>`}</tbody></table></div>`);
    if (box) { box.classList.remove('loading');
      box.querySelectorAll('tr[data-pick]').forEach(tr => tr.onclick = () => addFilter('ip', tr.dataset.pick));
      box.querySelectorAll('[data-open]').forEach(b => b.onclick = e => { e.stopPropagation(); openHost(b.dataset.open); }); }
    // donut: top 5 + rest, same colours as the table
    const top5 = t.rows.slice(0, 5), rest = t.total - top5.reduce((a, r) => a + tot(r), 0);
    const drows = [...top5.map(r => ({k:r.k, label:r.name || r.k, up:r.up, dn:r.dn})), ...(rest > 0 ? [{k:'__other', label:T('Others'), up:rest, dn:0}] : [])];
    const db = fill('tDonut', `<div class="donut-wrap"><div class="chart donut" id="cTDonut"></div><div class="dl">${drows.map(r => `<i class="idot" style="background:${r.k === '__other' ? C.other : colorOf.get(r.k)}"></i>${r.k === '__other' ? `<span>${T('Others')}</span>` : `<button class="link mono" data-f="ip" data-v="${esc(r.k)}">${esc(r.label)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t"></span>`).join('')}</div></div>`);
    if (db) { db.classList.remove('loading'); wireFilters(db); donut(document.getElementById('cTDonut'), drows.map(r => ({...r, k:r.label})), k => { const r = drows.find(x => x.label === k); return r.k === '__other' ? C.other : colorOf.get(r.k); }, [fmtB(t.total), T('all traffic')]); }
    // stacked trend: top 5 + others, same colours
    api('series', {by:'int_ip', top:5}).then(s5 => { const el = document.getElementById('cTop5'); if (!el) return;
      const {ts: t5, step} = grid(s5), keys = new Map(); for (const [x, k, b] of s5.rows) { if (!keys.has(k)) keys.set(k, new Map()); keys.get(k).set(x, b); }
      const order = [...keys.keys()].sort((a, b) => (a === '__other') - (b === '__other'));
      const c = mkChart(el);
      c.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true}, legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
        tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(t5), yAxis:axisY(v => fmtR(v)),
        series:order.map(k => { const col = k === '__other' ? C.other : (colorOf.get(k) || C.other), r = t.rows.find(x => x.k === k);
          return {name:k === '__other' ? T('others') : (r && r.name) || k, type:'line', stack:'a', smooth:.3, showSymbol:false, lineStyle:{width:1.6, color:col}, itemStyle:{color:col},
            areaStyle:{color:new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset:0, color:hexA(col, .45)}, {offset:1, color:hexA(col, .05)}])}, data:t5.map(x => [x * 1000, (keys.get(k).get(x) || 0) * 8 / step])}; })});
      zoomable(c);
    }).catch(e => fill('cTop5', errBox(e)));
  }).catch(e => fill('tBox', errBox(e)));
  section('tSvc', async () => { const p = await api('top', {dim:'service', limit:6}); const rows = p.rows.slice(0, 5), rest = p.total - rows.reduce((a, r) => a + tot(r), 0);
    const all = [...rows.map(r => ({label:r.k, v:tot(r), k:r.k})), ...(rest > 0 ? [{label:T('Others'), v:rest}] : [])];
    return `<div class="pbars">${all.map(r => { const c = r.k ? keyColor(r.k) : C.other;
      return `<span>${r.k ? `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.label)}</button>` : r.label}</span><div class="vbar"><i style="width:${Math.max(1, 100 * r.v / (p.total || 1)).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .6)},${c})"></i></div><b class="mono">${pct(r.v, p.total)}</b>`; }).join('') || `<div class="empty">${T('No data')}</div>`}</div>`; });
  section('tGeo', async () => { const [cc, city] = await Promise.all([api('top', {dim:'country', limit:5}), api('top', {dim:'city', limit:25})]);
    const rest = cc.total - cc.rows.reduce((a, r) => a + tot(r), 0), cols = ['#27D3F5', '#2F7BFF', '#2EE59D', '#8B5CFF', '#FFB547'];
    setTimeout(() => { const el = document.getElementById('cMini'); if (!el || !echarts.getMap('world')) return; const c = mkChart(el), cmax = city.rows.length ? tot(city.rows[0]) : 1;
      c.setOption({animation:false, geo:{map:'world', silent:true, roam:false, left:0, right:0, top:0, bottom:0, itemStyle:{areaColor:'rgba(30,56,120,.45)', borderColor:'rgba(110,160,255,.25)', borderWidth:.4}},
        series:[{type:'scatter', coordinateSystem:'geo', symbolSize:d => 4 + 10 * Math.sqrt(d[2] / cmax), itemStyle:{color:'#27D3F5', shadowBlur:10, shadowColor:'#27D3F5'},
          data:city.rows.filter(r => r.la || r.lo).map(r => [r.lo, r.la, tot(r)])}]}); });
    return `<div class="geomini"><div class="chart" id="cMini" style="height:120px"></div><div class="dl">${cc.rows.map((r, i) => `<i class="idot" style="background:${cols[i]}"></i><button class="link" data-f="country" data-v="${esc(r.k)}">${esc(r.k ? ccName(r.k) : T('Local'))}</button><span class="p">${pct(tot(r), cc.total)}</span><span class="t"></span>`).join('')}${rest > 0 ? `<i class="idot" style="background:${C.other}"></i><span>${T('Others')}</span><span class="p">${pct(rest, cc.total)}</span><span class="t"></span>` : ''}</div></div>`; });
  section('tDetail', async () => { const d = await api('top', {dim:'host_svc', limit:6});
    return `<div class="tw"><table class="compact"><thead><tr><th>${T('Host')}</th><th>${T('Main service')}</th><th>${T('Protocol')}</th><th class="num">${T('Volume')}</th></tr></thead><tbody>${d.rows.map((r, i) => { const c = HOSTPAL[i % HOSTPAL.length];
      return `<tr class="click" data-f="ip" data-v="${esc(r.k)}"><td><span class="idot" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="mono">${esc(r.name || r.k)}</span></td><td>${svcBadge(r.service)}</td><td><span class="tag">${L4[r.proto] || r.proto} · ${esc(dv(r.l7))}</span></td><td class="num mono">${fmtB(tot(r))}</td></tr>`; }).join('')}</tbody></table></div>`; });
}
function vPorts(){
  const v = document.getElementById('view'), all = !!state.portsAll;
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12">${ph('chart', T('Ports over time'), T('top 7 · click a line to filter by port'))}<div class="chart" id="cPorts"></div></section>
    <section class="glass panel s8">${ph('list', T('Top ports'), T('click to filter by port'), '<button class="lnk" id="pMore"></button>')}<div id="pTbl" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', T('L7 protocols'), T('by port'))}<div id="pL7" class="loading"></div></section></div>`;
  api('series', {by:'ext_port', top:7}).then(s => { const el = document.getElementById('cPorts'); if (el) stackChart(el, s, k => ':' + k, k => addFilter('port', k)); }).catch(e => fill('cPorts', errBox(e)));
  section('pTbl', async () => { const t = await api('top', {dim:'ext_port', limit:all ? 100 : 11}), rows = all ? t.rows : t.rows.slice(0, 10), max = rows.length ? tot(rows[0]) : 1;
    moreToggle('pMore', 'portsAll', all, t.rows.length > 10);
    return `<div class="tw"><table><thead><tr><th>${T('Port')}</th><th>${T('Protocol')}</th><th>${T('Typical service')}</th><th style="width:24%">${T('Volume')}</th><th class="num">%</th><th class="num">${T('Hosts')}</th><th class="num">${T('col::Outside addresses')}</th><th class="num">Flows</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="port" data-v="${esc(r.k)}"><td><b class="mono">${esc(r.k)}</b></td><td><span class="tag">${L4[r.proto_n] || r.proto_n} · ${esc(dv(r.l7))}</span></td><td>${svcBadge(r.service)}</td>
        <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,#1aa7d6,#27D3F5)"></i></div></td><td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${r.hosts}</td><td class="num mono">${fmtN(r.peers)}</td><td class="num mono">${fmtN(r.fl)}</td></tr>`).join('') || `<tr><td colspan="8"><div class="empty">${T('No data')}</div></td></tr>`}</tbody></table></div>`; });
  section('pL7', async () => { const t = await api('top', {dim:'l7', limit:8});
    setTimeout(() => { const el = document.getElementById('cPL7'); if (el) donut(el, t.rows, k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), T('protocols')]); });
    return `<div class="chart" id="cPL7" style="height:200px"></div><div class="dl">${t.rows.map((r, i) => `<i class="idot" style="background:${PAL[i % PAL.length]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(dv(r.k))}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div>`; });
}
// "show all" / "top 10" link in a panel header; hidden when there is nothing more to show
function moreToggle(id, key, all, hasMore){
  const b = document.getElementById(id); if (!b) return;
  b.hidden = !all && !hasMore; b.textContent = all ? T('Show top 10') : T('Show all');
  b.onclick = () => { state[key] = !all; render(); };
}
function vApps(){
  const v = document.getElementById('view'), all = !!state.appsAll;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('chart', T('Services over time'), T('the service comes from the destination ASN and port'))}<div class="chart" id="cApps"></div></section>
    <section class="glass panel s8">${ph('grid', T('Services'), T('click to filter by service'), '<button class="lnk" id="aMore"></button>')}<div id="aBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', T('Protocols'), T('L7 by port'))}<div id="pBox" class="loading"></div></section></div>`;
  api('series', {by:'service', top:7}).then(s => { const el = document.getElementById('cApps'); if (el) stackChart(el, s, k => k, k => addFilter('service', k)); }).catch(e => fill('cApps', errBox(e)));
  section('aBox', async () => { const t = await api('top', {dim:'service', limit:all ? 100 : 11}), rows = all ? t.rows : t.rows.slice(0, 10);
    moreToggle('aMore', 'appsAll', all, t.rows.length > 10);
    return `<div class="tw"><table><thead><tr><th>${T('Service')}</th><th>${T('Protocol')}</th><th class="num">↓</th><th class="num">↑</th><th class="num">${T('Total')}</th><th class="num">%</th><th class="num">${T('Hosts')}</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="service" data-v="${esc(r.k)}"><td><button class="link" data-f="service" data-v="${esc(r.k)}">${svcBadge(r.k)}</button></td><td class="ipl">${esc(dv(r.l7))}</td><td class="num d mono">${fmtB(r.dn)}</td><td class="num u mono">${fmtB(r.up)}</td><td class="num mono"><b>${fmtB(tot(r))}</b></td><td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${r.hosts}</td></tr>`).join('')}</tbody></table></div>`; });
  section('pBox', async () => { const t = await api('top', {dim:'l7', limit:10});
    setTimeout(() => { const el = document.getElementById('cL7'); if (el) donut(el, t.rows.slice(0, 8), k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), T('protocols')]); });
    return `<div class="chart" id="cL7" style="height:220px"></div><div class="dl">${t.rows.slice(0, 8).map((r, i) => `<i class="idot" style="background:${PAL[i % PAL.length]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(dv(r.k))}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div>`; });
}
// devices without a location: the map draws no lines from them — say so and where to set it
const noSite = () => { const n = META.devices.filter(d => d.lat == null || d.lon == null).map(d => d.name || d.ip);
  return n.length ? `<p class="note warn">${T('No lines from devices without a location — set Latitude and Longitude in Settings → Devices')}: ${esc(n.join(', '))}</p>` : ''; };
function vGeo(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s8">${ph('globe', T('Connection map'), T('destination GeoIP · a line appears when a new flow arrives · colour = direction'),
      `<span class="legend"><span><i class="bar" style="background:${C.down}"></i>download</span><span><i class="bar" style="background:${C.up}"></i>upload</span><span><i style="background:${C.int}"></i>${T('sites')}</span><span><i style="background:${C.ext}"></i>${T('destinations')}</span></span>`)}<div class="chart map" id="cMap"></div>${noSite()}</section>
    <section class="glass panel s4">${ph('pulse', T('Live connections'), T('new flows with geolocation'))}<div class="ticker" id="ticker"><div class="empty">${T('Waiting for new records (exporters send about once a minute)…')}</div></div></section>
    <section class="glass panel s4">${ph('globe', T('Countries'), T('by destination address'))}<div id="ccBox" class="loading"></div></section>
    <section class="glass panel s8">${ph('nodes', T('Autonomous systems'), T('who actually serves the traffic'))}<div id="asBox" class="loading"></div></section></div>`;
  const tk = document.getElementById('ticker');
  api('geo').then(g => { const el = document.getElementById('cMap'); if (!el) return; flatMap(el, g, r => {
    if (tk.querySelector('.empty')) tk.innerHTML = '';
    const up = r.dir === 'up', site = siteCity(r.exporter), place = r.city || ccName(r.country);
    const d = document.createElement('div'); d.className = 'tick';
    d.innerHTML = `<span class="mono" style="color:var(--ink3)">${hms(r.t)}</span><span class="mid"><span class="ipl"><b class="${up ? 'u' : 'd'}">${up ? '↑' : '↓'}</b> ${esc(up ? site : place)} → ${esc(up ? place : site)}</span><span class="nat ipl">${esc(r.name || r.int_ip)} ${up ? '→' : '←'} ${esc(r.ext_ip)}:${r.ext_port} · ${esc(r.service)}</span></span><span class="mono">${fmtB(r.bytes)}</span>`;
    tk.prepend(d); while (tk.children.length > 14) tk.lastChild.remove(); }); }).catch(e => fill('cMap', errBox(e)));
  section('ccBox', async () => { const t = await api('top', {dim:'country', limit:20}); const max = t.rows.length ? tot(t.rows[0]) : 1;
    return `<div class="blist">${t.rows.map(r => `<button class="brow" data-f="country" data-v="${esc(r.k)}"><span class="n"><span class="tag mono">${esc(r.k || '—')}</span>&nbsp; ${esc(r.k ? ccName(r.k) : T('Local / unknown'))}</span><span class="t">${fmtB(tot(r))}</span><span class="p">${pct(tot(r), t.total)}</span>
      <span class="bar2" style="width:${(100 * tot(r) / max).toFixed(1)}%"><i class="u" style="width:${(100 * r.up / (tot(r) || 1)).toFixed(1)}%"></i><i class="d" style="flex:1"></i></span></button>`).join('')}</div>`; });
  section('asBox', async () => { const t = await api('top', {dim:'asn', limit:25});
    return `<div class="tw"><table><thead><tr><th>ASN</th><th>${T('Country')}</th><th class="num">↓</th><th class="num">↑</th><th class="num">${T('Total')}</th><th class="num">%</th></tr></thead><tbody>
      ${t.rows.map(r => `<tr><td>${r.k !== '0' ? `<button class="link" data-f="asn" data-v="${esc(r.k)}">AS${esc(r.k)} ${esc(r.as_org)}</button>` : T('local addresses')}</td><td><span class="tag mono">${esc(r.country || '—')}</span></td><td class="num d mono">${fmtB(r.dn)}</td><td class="num u mono">${fmtB(r.up)}</td><td class="num mono"><b>${fmtB(tot(r))}</b></td><td class="num mono">${pct(tot(r), t.total)}</td></tr>`).join('')}</tbody></table></div>`; });
}
// detections and anomalies: name, what triggers it, its thresholds (keys as in detect.KINDS)
const EV_KINDS = () => ({
  port_scan:[T('Port scan'), T('one outside address calls many ports of ours, several of our management services, or one port on many of our addresses — within 10 min'),
    {ports:T('ports'), services:T('services'), hosts:T('addresses')}],
  brute_force:[T('Password guessing'), T('one address opens many sessions to a sensitive service (SSH, RDP, management) within 10 min'), {sessions:T('sessions / 10 min')}],
  probes:[T('Probes of management services'), T('one summary a day per sensitive service: how many outside addresses called it'), {}],
  heavy_client:[T('Aggressive client'), T('one address opens very many sessions to a public service (web) within 10 min'), {sessions:T('sessions / 10 min')}],
  ddos:[T('DDoS / flood'), T('minutes far above the usual peak (99th percentile of the week) and above a floor: new sessions to a service, inbound traffic, UDP reflection'),
    {factor:T('× usual peak'), min_sessions:T('sessions/min at least'), min_mbps:T('Mbit/s at least'), refl_mbps:T('reflection, Mbit/s'), minutes:T('minutes of 10')}],
  inside_scan:[T('Inside host scans the internet'), T('a host of ours calls many addresses on one port, or many ports of one address, mostly without answer — a sign of malware'),
    {hosts:T('addresses'), hosts_busy:T('on web / DNS / NTP'), ports:T('ports')}],
  lateral_scan:[T('Scan inside the network'), T('a host calls many hosts or ports of the local network without answer'), {hosts:T('hosts'), ports:T('ports')}],
  malware_contact:[T('Contact with malware infrastructure'), T('a host of ours opens a connection to a botnet controller or a malware host (abuse.ch lists)'), {}],
  listed_contact:[T('Contact with a listed address'), T('a host of ours opens a connection to an address on another enabled reputation list'), {}],
  listed_inbound:[T('Listed addresses calling us'), T('one summary a day: how many listed addresses called our services, by list'), {}],
  sustained_upload:[T('Sustained upload'), T('more than 5 Mbit/s to one address for 45 min out of 3 h'), {}],
  burst:[T('Traffic burst'), T('5 minutes ×8 above the host’s daily median'), {}],
  new_country:[T('New destination'), T('a host contacts a country for the first time this week'), {}],
});
const SEV = () => ({crit:T('critical'), warn:T('warning'), info:T('info')});
// stored times are UTC 'YYYY-MM-DD hh:mm:ss': local time, with the day when not today
function evTime(s){
  if (!/^\d{4}-\d\d-\d\d \d\d:\d\d/.test(String(s))) return String(s);
  const d = new Date(String(s).replace(' ', 'T') + 'Z'), today = new Date().toDateString() === d.toDateString();
  return d.toLocaleString(LOC, today ? {hour:'2-digit', minute:'2-digit'} : {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'});
}
// a stored event's span: the day once when both ends are on it
function evRange(a, b){
  const d = s => new Date(String(s).replace(' ', 'T') + 'Z');
  if (!/^\d{4}-/.test(String(a)) || d(a).toDateString() !== d(b).toDateString()) return `${evTime(a)} – ${evTime(b)}`;
  return `${evTime(a)} – ${d(b).toLocaleTimeString(LOC, {hour:'2-digit', minute:'2-digit'})}`;
}
// the filter an event's button sets: the server names it for stored events (an outside attacker is an outside
// address), the anomalies computed from flows are about an inside host or a device
const evFilter = x => x.fk && x.fv ? [x.fk, x.fv] : x.ip ? ['ip', x.ip] : x.device ? ['device', x.device] : null;
function vThreats(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s8">${ph('shield', T('Events and anomalies'), T('in the chosen period and filters · scans, password guessing and floods are checked every 10 minutes'))}<div id="alBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('search', T('What is watched'), '', isAdmin() ? `<button class="btn" id="evCfg">${T('Configure')}</button>` : '')}<div id="watchBox" class="loading"></div></section></div>`;
  if (isAdmin()) document.getElementById('evCfg').onclick = () => { state.view = 'settings'; state.setTab = 'events'; render(); };
  const sevs = SEV(), kinds = EV_KINDS();
  section('alBox', async () => { const res = await api('alerts'), all = res.alerts, cur = state.evSev || 'all';
    const W = document.getElementById('watchBox');
    if (W) { W.classList.remove('loading'); W.innerHTML = `<div class="watch">${Object.entries(kinds).map(([k, [name, desc]]) => { const c = (res.watch || {})[k] || {};
      return `<div class="${c.on === false ? 'off' : ''}"><b>${name}</b><span class="pill ${c.on === false ? '' : c.sev}">${c.on === false ? T('off') : sevs[c.sev] || ''}</span><p>${desc}</p></div>`; }).join('')}
      <div><b>${T('Export and collector health')}</b><span class="pill warn">${sevs.warn}</span><p>${T('lost packets, a collector falling behind, the edition limit, the license')}</p></div></div>`; }
    const skip = (res.unfiltered || []).map(k => FILTER_LABEL[k] || k), note = skip.length ? `<p class="note evskip">${T('Not applied to events')}: ${esc(skip.join(', '))}</p>` : '';
    if (!all.length) return note + `<div class="empty">${state.filters.length ? T('No events for these filters in this period') : T('No events — all quiet')}</div>`;
    const n = s => all.filter(x => x.sev === s).length, a = cur === 'all' ? all : all.filter(x => x.sev === cur);
    setTimeout(() => {
      document.querySelectorAll('#evSeg button').forEach(b => b.onclick = () => { state.evSev = b.dataset.v; vThreats(); });
      document.querySelectorAll('[data-ign]').forEach(b => b.onclick = async () => {
        if (!confirm(T('Ignore {addr}? Its events will no longer be recorded or shown. You can undo it in Settings → Events.', {addr: b.dataset.ign}))) return;
        try { await apiPost('events/ignore', {value:b.dataset.ign}); vThreats(); } catch (e) { alert(e.message); } });
    });
    return `<div class="seg evseg" id="evSeg" role="group">${[['all', T('All'), all.length], ['crit', sevs.crit, n('crit')], ['warn', sevs.warn, n('warn')], ['info', sevs.info, n('info')]].map(([k, l, c]) =>
      `<button data-v="${k}" aria-pressed="${cur === k}">${l} <span class="mono">${c}</span></button>`).join('')}</div>` + note +
      (a.length ? '<div class="alerts">' + a.map(x => `<div class="alert ${x.sev}"><span class="sev">${x.sev === 'info' ? 'i' : '!'}</span><div class="body"><b>${esc(x.title)}</b><p>${esc(x.text)}</p></div>
      <div class="meta"><span class="pill ${x.sev}">${sevs[x.sev] || x.sev}</span><span class="mono">${x.stored && x.first !== x.last ? esc(evRange(x.first, x.last)) : esc(evTime(x.when))}</span>
        <span class="acts">${evFilter(x) ? `<button class="btn" data-f="${evFilter(x)[0]}" data-v="${esc(evFilter(x)[1])}" title="${esc(`${FILTER_LABEL[evFilter(x)[0]] || evFilter(x)[0]}: ${evFilter(x)[1]}`)}">${T('Filter')}</button>` : ''}${x.stored && x.src && isAdmin() ? `<button class="btn" data-ign="${esc(x.src)}" title="${T('Do not record or show events of this address')}">${T('Ignore')}</button>` : ''}</span></div></div>`).join('') + '</div>'
        : `<div class="empty">${T('No events of this priority')}</div>`); });
}
// Settings → Events (administrators): detections on/off, priority, thresholds; roles of our services; exceptions
function vEventsCfg(){
  const v = document.getElementById('setBody');
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('shield', T('Detections'), T('on or off, the priority each event gets, and when it triggers'))}<div id="evkBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('M2 9l14-6-5 14-2-6zM9 11l7-8', T('Notifications'), T('a new event goes out once · what continues is not sent again'))}<div id="evtBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('globe', T('IP reputation'), T('public lists of malicious addresses · downloaded once a day by this server from their publishers · checked every 10 minutes, not per record'))}<div id="evrBox" class="loading"></div></section>
    <section class="glass panel s7">${ph('dev', T('Services on our side'), T('learned from the last day: what outside addresses call'))}<div id="evsBox" class="loading"></div></section>
    <section class="glass panel s5">${ph('list', T('Exceptions and ports'))}<div id="evxBox" class="loading"></div></section>
    <section class="glass panel s12 evsave"><div><button class="btn primary" id="evSave">${T('Save')}</button> <button class="btn" id="evDef">${T('Restore defaults')}</button></div><p class="err" id="evErr"></p><p class="note" id="evOk" hidden>${T('Saved. The next 10-minute check uses the new settings.')}</p></section></div>`;
  const get = async u => { const r = await fetch(u); if (!r.ok) throw new Error((await r.json()).error || r.status); return r.json(); };
  const load = async () => { const [ev, nt] = await Promise.all([get('api/events/config'), get('api/notify')]); return {...ev, notify:nt}; };
  const show = res => {
    const cfg = res.config, kinds = EV_KINDS(), sevs = SEV();
    const box = (id, html) => { const el = document.getElementById(id); el.classList.remove('loading'); el.innerHTML = html; };
    box('evkBox', `<div class="tw form"><table class="evk"><thead><tr><th>${T('On')}</th><th>${T('Event')}</th><th>${T('Priority')}</th><th title="${T('Send this kind to Telegram')}">Telegram</th><th title="${T('Send this kind by e-mail')}">E-mail</th><th>${T('Triggers at')}</th></tr></thead><tbody>
      ${Object.entries(kinds).map(([k, [name, desc, thr]]) => { const c = cfg.kinds[k] || {};
        return `<tr data-k="${k}"><td><label class="chk"><input type="checkbox" data-x="on" ${c.on ? 'checked' : ''} aria-label="${esc(name)}"></label></td><td class="wrap"><b>${name}</b><p class="note">${desc}</p></td>
        <td><select data-x="sev">${['info', 'warn', 'crit'].map(s => `<option value="${s}" ${c.sev === s ? 'selected' : ''}>${sevs[s]}</option>`).join('')}</select></td>
        <td><label class="chk"><input type="checkbox" data-n="${k}" ${res.notify.kinds[k] !== false ? 'checked' : ''} aria-label="Telegram: ${esc(name)}"></label></td>
        <td><label class="chk"><input type="checkbox" data-m="${k}" ${res.notify.email_kinds[k] !== false ? 'checked' : ''} aria-label="E-mail: ${esc(name)}"></label></td>
        <td class="thr"><div>${Object.entries(thr).map(([t, l]) => `<label><input type="number" min="1" data-x="${t}" value="${esc(c[t])}">${l}</label>`).join('') || '<span class="note">—</span>'}</div></td></tr>`; }).join('')}</tbody></table></div>`);
    const tg = res.notify.telegram, ml = res.notify.email, sevSel = (id, v) => `<select id="${id}">${['info', 'warn', 'crit'].map(s => `<option value="${s}" ${v === s ? 'selected' : ''}>${sevs[s]}</option>`).join('')}</select>`;
    const langSel = (id, v) => `<select id="${id}">${langs().map(([c, l]) => `<option value="${c}" lang="${c}" ${v === c ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
    const on = ch => res.notify[ch].on ? ` <span class="pill ok">${T('on')}</span>` : '';
    const ntTab = state.ntTab || 'telegram';
    box('evtBox', `<div class="seg ntseg" id="ntSeg" role="tablist">${[['telegram', 'Telegram'], ['email', 'E-mail']].map(([v, l]) =>
        `<button type="button" role="tab" data-v="${v}" aria-pressed="${v === ntTab}" aria-selected="${v === ntTab}">${l}${on(v)}</button>`).join('')}</div>
      <div class="form tgform" id="ntTelegram" ${ntTab === 'telegram' ? '' : 'hidden'}>
      <p class="note" style="margin:0">${T('1) In Telegram open <b>@BotFather</b>, send /newbot and copy the token. 2) Write any message to your new bot (or add it to a group). 3) Paste the token, press <b>Find chat</b>, pick the chat, Save, and Send a test.')}</p>
      <label class="chk"><input type="checkbox" id="tgOn" ${tg.on ? 'checked' : ''}>${T('Send new events to Telegram')}</label>
      <div class="two"><label>${T('Bot token')}<input id="tgTok" type="password" autocomplete="off" placeholder="${tg.token_set ? T('saved — leave empty to keep') : '123456789:AA…'}"></label>
        <label>${T('Chat ID')}<span class="tgchat"><input id="tgChat" value="${esc(tg.chat)}" placeholder="123456789 / -100… / @channel"><button class="btn" type="button" id="tgFind">${T('Find chat')}</button></span></label></div>
      <div id="tgChats" class="tgchats"></div>
      <div class="two"><label>${T('Send from priority')}${sevSel('tgSev', tg.min_sev)}</label>
        <label>${T('Language of the messages')}${langSel('tgLang', tg.lang)}</label></div>
      <div><button class="btn" type="button" id="tgTest">${T('Send a test')}</button> <span class="note" id="tgSay"></span></div></div>
      <div class="form tgform" id="ntEmail" ${ntTab === 'email' ? '' : 'hidden'}>
      <p class="note" style="margin:0">${T('Any mail server or service that takes SMTP: your own, Gmail or Microsoft 365 (with an app password), a relay of your provider. One letter per 10-minute check, to all recipients.')}</p>
      <label class="chk"><input type="checkbox" id="mlOn" ${ml.on ? 'checked' : ''}>${T('Send new events by e-mail')}</label>
      <div class="two"><label>${T('Mail server (SMTP)')}<input id="mlHost" value="${esc(ml.host)}" placeholder="smtp.example.com" autocomplete="off"></label>
        <div class="two"><label>${T('Port')}<input id="mlPort" type="number" min="1" max="65535" value="${esc(ml.port)}"></label>
          <label>${T('Encryption')}<select id="mlSec">${[['starttls', 'STARTTLS'], ['ssl', 'SSL/TLS'], ['none', T('none')]].map(([v, l]) => `<option value="${v}" ${ml.security === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div></div>
      <label class="chk"><input type="checkbox" id="mlVerify" ${ml.verify ? 'checked' : ''}>${T('Verify the certificate of the server')}</label>
      <div class="two"><label>${T('Login (empty: without a login)')}<input id="mlUser" value="${esc(ml.user)}" autocomplete="off"></label>
        <label>${T('Password')}<input id="mlPass" type="password" autocomplete="new-password" placeholder="${ml.password_set ? T('saved — leave empty to keep') : ''}"></label></div>
      <div class="two"><label>${T('From')}<input id="mlFrom" value="${esc(ml.sender)}" placeholder="flowtrack@example.com"></label>
        <label>${T('To (several: comma-separated)')}<input id="mlTo" value="${esc(ml.to.join(', '))}" placeholder="admin@example.com, noc@example.com"></label></div>
      <div class="two"><label>${T('Send from priority')}${sevSel('mlSev', ml.min_sev)}</label>
        <label>${T('Language of the messages')}${langSel('mlLang', ml.lang)}</label></div>
      <div><button class="btn" type="button" id="mlTest">${T('Send a test')}</button> <span class="note" id="mlSay"></span></div></div>
      <div class="form tgform ntshared"><div class="two"><label>${T('FlowTrack address for the link in messages (optional)')}<input id="tgLink" value="${esc(res.notify.link)}" placeholder="${esc(location.origin)}"></label>
        <label>${T('At most messages an hour, per channel')}<input id="tgHour" type="number" min="1" max="600" value="${esc(res.notify.per_hour)}"></label></div></div>`);
    document.querySelectorAll('#ntSeg [data-v]').forEach(b => b.onclick = () => { state.ntTab = b.dataset.v;
      document.querySelectorAll('#ntSeg [data-v]').forEach(x => { x.setAttribute('aria-pressed', String(x === b)); x.setAttribute('aria-selected', String(x === b)); });
      document.getElementById('ntTelegram').hidden = b.dataset.v !== 'telegram'; document.getElementById('ntEmail').hidden = b.dataset.v !== 'email'; });
    const mlTls = () => { document.getElementById('mlVerify').disabled = document.getElementById('mlSec').value === 'none'; };
    document.getElementById('mlSec').onchange = mlTls; mlTls();
    const msay = (m, bad) => { const e = document.getElementById('mlSay'); e.textContent = m; e.style.color = bad ? 'var(--crit)' : 'var(--ok)'; };
    document.getElementById('mlTest').onclick = async () => { msay(T('Sending…'));
      try { await apiPost('notify/test', {...collectNotify(), channel:'email'}); msay(T('Sent — check the mailbox (and the spam folder).')); } catch (e) { msay(e.message, true); } };
    const say = (m, bad) => { const e = document.getElementById('tgSay'); e.textContent = m; e.style.color = bad ? 'var(--crit)' : 'var(--ok)'; };
    document.getElementById('tgFind').onclick = async () => { say(T('Asking Telegram…'));
      try { const r = await apiPost('notify/chats', collectNotify()); const box2 = document.getElementById('tgChats');
        const kind = t => ({private:T('private chat'), group:T('group'), supergroup:T('group'), channel:T('channel')})[t] || t;
        const others = r.chats.filter(c => !r.checked || c.id !== r.checked.id);
        if (r.checked) say(T('✓ {name} · {kind} — the chat ID is right.', {name:r.checked.name || r.checked.id, kind:kind(r.checked.type)}));
        else if (r.check_error) say(r.check_error, true);
        else if (!others.length) say(T('No chats in the last 24 hours (Telegram keeps the messages to a bot that long): write any message to the bot (or add it to a group) and press again.'), true);
        else say('');
        box2.innerHTML = others.map(c => `<button class="btn" type="button" data-chat="${esc(c.id)}">${esc(c.name || c.id)} <span class="mono">${esc(c.id)}</span> · ${esc(kind(c.type))}</button>`).join(' ');
        box2.querySelectorAll('[data-chat]').forEach(b => b.onclick = () => { document.getElementById('tgChat').value = b.dataset.chat; box2.innerHTML = ''; });
      } catch (e) { say(e.message, true); } };
    document.getElementById('tgTest').onclick = async () => { say(T('Sending…'));
      try { await apiPost('notify/test', collectNotify()); say(T('Sent — check the chat.')); } catch (e) { say(e.message, true); } };
    const cats = {malware:T('malware: botnet controllers, malware hosts'), drop:T('criminal netblocks'), attack:T('hosts seen attacking'), anon:T('Tor exit relays')};
    const when = t => t ? new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}) : '';
    box('evrBox', `<div class="tw form"><table class="evr"><thead><tr><th>${T('On')}</th><th>${T('List')}</th><th>${T('What it holds')}</th><th class="num">${T('Entries')}</th><th>${T('Updated')}</th></tr></thead><tbody>
      ${res.lists.map(l => `<tr><td><label class="chk"><input type="checkbox" data-list="${esc(l.name)}" ${l.on ? 'checked' : ''} aria-label="${esc(l.title)}"></label></td>
        <td><a href="${esc(l.link)}" target="_blank" rel="noopener">${esc(l.title)}</a></td><td class="note">${cats[l.category] || ''}</td><td class="num mono">${l.count ? l.count.toLocaleString(LOC) : '—'}</td>
        <td>${l.error ? `<span class="pill crit" title="${esc(l.error)}">${T('failed')}</span> ` : ''}<span class="note">${l.updated ? when(l.updated) : l.on ? T('not yet — within 10 min') : ''}</span></td></tr>`).join('')}</tbody></table></div>
      <div class="form evown"><label>${T('Own list — addresses and networks you consider malicious (one per line)')}<textarea id="evOwn" rows="3" placeholder="203.0.113.66&#10;198.51.100.0/24">${esc((cfg.own_list || []).join('\n'))}</textarea></label></div>`);
    const roles = {'':T('auto'), public:T('public — floods only'), sensitive:T('sensitive — guessing, probes'), normal:T('ordinary — scans only')};
    box('evsBox', res.services.length ? `<div class="tw form"><table class="evs"><thead><tr><th>${T('Service')}</th><th class="num">${T('Callers / day')}</th><th>${T('Role')}</th></tr></thead><tbody>
      ${res.services.map(s => `<tr><td class="mono">${esc(s.ep.replace('/6', ' TCP').replace('/17', ' UDP'))}</td><td class="num mono">${s.peers.toLocaleString(LOC)}</td>
        <td><select data-ep="${esc(s.ep)}">${Object.entries(roles).map(([r, l]) => `<option value="${r}" ${(s.set ? s.role : '') === r ? 'selected' : ''}>${r ? l : `${l}: ${roles[s.role].split(' — ')[0]}`}</option>`).join('')}</select></td></tr>`).join('')}</tbody></table></div>
      <p class="note">${T('Public services (web sites) get many visitors: only floods and aggressive clients count there. Sensitive ones (SSH, management, VPN) also get password guessing and the daily probe summary.')}</p>`
      : `<div class="empty">${T('Nothing learned yet — services show up within an hour of traffic.')}</div>`);
    box('evxBox', `<div class="form">
      <label>${T('Ignore — addresses, networks, ASNs (one per line)')}<textarea id="evIgn" rows="6" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;AS40934">${esc(cfg.ignore.join('\n'))}</textarea></label>
      <label>${T('Sensitive ports')}<input id="evSens" value="${esc(cfg.sensitive.join(', '))}"></label>
      <label>${T('Public ports')}<input id="evPub" value="${esc(cfg.public.join(', '))}"></label>
      <p class="note">${T('The role of a service listed on the left wins over these ports.')}</p></div>`);
  };
  const collect = () => {
    const kinds = {};
    document.querySelectorAll('table.evk tr[data-k]').forEach(tr => { const k = {};
      tr.querySelectorAll('[data-x]').forEach(i => { k[i.dataset.x] = i.type === 'checkbox' ? i.checked : i.type === 'number' ? Number(i.value) : i.value; });
      kinds[tr.dataset.k] = k; });
    const roles = {}; document.querySelectorAll('table.evs select[data-ep]').forEach(s => { if (s.value) roles[s.dataset.ep] = s.value; });
    const lists = {}; document.querySelectorAll('table.evr [data-list]').forEach(i => { lists[i.dataset.list] = i.checked; });
    return {kinds, roles, lists, own_list:document.getElementById('evOwn').value.split(/[\s,]+/).filter(Boolean), ignore:document.getElementById('evIgn').value.split(/[\s,]+/).filter(Boolean),
      sensitive:document.getElementById('evSens').value, public:document.getElementById('evPub').value};
  };
  const collectNotify = () => { const kinds = {}, email_kinds = {}, v = id => document.getElementById(id);
    document.querySelectorAll('table.evk [data-n]').forEach(i => { kinds[i.dataset.n] = i.checked; });
    document.querySelectorAll('table.evk [data-m]').forEach(i => { email_kinds[i.dataset.m] = i.checked; });
    return {telegram:{on:v('tgOn').checked, token:v('tgTok').value.trim(), chat:v('tgChat').value.trim(), min_sev:v('tgSev').value, lang:v('tgLang').value},
      email:{on:v('mlOn').checked, host:v('mlHost').value.trim(), port:Number(v('mlPort').value), security:v('mlSec').value, verify:v('mlVerify').checked,
        user:v('mlUser').value.trim(), password:v('mlPass').value, sender:v('mlFrom').value.trim(), to:v('mlTo').value, min_sev:v('mlSev').value, lang:v('mlLang').value},
      kinds, email_kinds, link:v('tgLink').value.trim(), per_hour:Number(v('tgHour').value)}; };
  const err = document.getElementById('evErr'), ok = document.getElementById('evOk');
  load().then(show).catch(e => { err.textContent = e.message; });
  document.getElementById('evSave').onclick = async () => { err.textContent = ''; ok.hidden = true;
    try { const nt = await apiPost('notify', collectNotify()); show({...await apiPost('events/config', collect()), notify:nt}); ok.hidden = false; } catch (e) { err.textContent = e.message; } };
  document.getElementById('evDef').onclick = async () => { if (!confirm(T('Restore the default settings of all events? Exceptions and service roles are cleared too.'))) return;
    err.textContent = ''; ok.hidden = true;
    try { show({...await apiPost('events/config', {}), notify:await get('api/notify')}); ok.hidden = false; } catch (e) { err.textContent = e.message; } };
}
// How each vendor exports flows: the protocols it can send, in the order offered (the first is the recommended one),
// each with the configuration for the device. FlowTrack recognises the protocol of every packet by itself; the choice
// picks the instructions and lets the Devices page warn when something else arrives.
const PROTO_NAME = {netflow5:'NetFlow v5', netflow9:'NetFlow v9', ipfix:'IPFIX', sflow:'sFlow v5'};
const PROTO_READY = ['netflow5', 'netflow9', 'ipfix', 'sflow'];      // what the collector decodes
// the sampling of the form (1:N): the snippets that set a rate on the device are marked rated(); for the others the
// configuration says to set the same rate there (FlowTrack scales records that carry no rate by it)
const sampleRate = v => { const n = parseInt(String(v || '').split(':').pop(), 10); return n >= 1 ? n : 1; };
const sfRate = (o, d) => o.rate > 1 ? o.rate : d;        // sFlow: the vendor's usual rate until one is entered
const rated = f => Object.assign(f, {rated:true});
// the interfaces of the form (chosen from SNMP or typed): the snippets that name interfaces are marked named() and use
// these instead of their examples; for the others the configuration lists them
const named = f => Object.assign(f, {named:true});
const mtIfs = o => o.ifs.length ? o.ifs.join(',') : 'all';     // RouterOS: a list or all
// RouterOS samples sampling-interval packets in a row, then skips sampling-space: 1 of N = 1 and N - 1
const mtSamp = o => o.rate > 1 ? ` packet-sampling=yes sampling-interval=1 sampling-space=${o.rate - 1}` : '';
const each = (o, examples, fn) => (o.ifs.length ? o.ifs : examples).map(fn).join('');
const ciscoFnf = proto => named(rated((ip, port, o) => `${o.rate > 1 ? `sampler FT-SAMP\n mode random 1 out-of ${o.rate}\n` : ''}flow record FT-REC\n match ipv4 source address\n match ipv4 destination address\n match ipv4 protocol\n match transport source-port\n match transport destination-port\n match interface input\n match flow direction\n collect interface output\n collect counter bytes long\n collect counter packets long\n collect timestamp sys-uptime first\n collect timestamp sys-uptime last\nflow exporter FLOWTRACK\n destination ${ip}\n transport udp ${port}\n export-protocol ${proto}\n template data timeout 60\nflow monitor FT-MON\n exporter FLOWTRACK\n record FT-REC\n cache timeout active 60\n! ${T('on every interface to watch (WAN and LAN)')}${each(o, ['GigabitEthernet0/0/0'], n => `\ninterface ${n}\n ip flow monitor FT-MON${o.rate > 1 ? ' sampler FT-SAMP' : ''} input\n ip flow monitor FT-MON${o.rate > 1 ? ' sampler FT-SAMP' : ''} output`)}`));
const juniper = (tpl, kw) => named(rated((ip, port, o) => `set services flow-monitoring ${tpl} template FT ipv4-template\nset forwarding-options sampling instance FT input rate ${o.rate}\nset forwarding-options sampling instance FT family inet output flow-server ${ip} port ${port}\nset forwarding-options sampling instance FT family inet output flow-server ${ip} ${kw} template FT\n# ${T('on every interface to watch (WAN and LAN)')}${each(o, ['ge-0/0/0.0'], n => { const [ifd, unit = '0'] = n.split('.');
    return `\nset interfaces ${ifd} unit ${unit} family inet sampling input\nset interfaces ${ifd} unit ${unit} family inet sampling output`; })}`));
const vyos = v => named(rated((ip, port, o) => `set system flow-accounting netflow version ${v}\nset system flow-accounting netflow server ${ip} port ${port}\n${o.rate > 1 ? `set system flow-accounting netflow sampling-rate ${o.rate}\n` : ''}set system flow-accounting netflow timeout expiry-interval 60\n${each(o, ['eth0'], n => `set system flow-accounting interface ${n}\n`)}# ${T('VyOS 1.4 and newer: set system flow-accounting netflow interface eth0')}\ncommit; save`));
const huawei = v => named(rated((ip, port, o) => `ip netstream timeout active 1\nip netstream export version ${v}\n${o.rate > 1 ? `ip netstream sampler fix-packets ${o.rate} inbound\nip netstream sampler fix-packets ${o.rate} outbound\nip netstream export template option sampler\n` : ''}ip netstream export source <${T('address of this device')}>\nip netstream export host ${ip} ${port}\n# ${T('on every interface to watch (WAN and LAN)')}${each(o, ['GigabitEthernet0/0/1'], n => `\ninterface ${n}\n ip netstream inbound\n ip netstream outbound`)}`));
const steps = list => (ip, port, o) => list(ip, port, o).map((x, i) => `${i + 1}. ${x}`).join('\n');
// sFlow: a switch samples what comes IN on every port (both directions everywhere counts traffic twice); a router or
// firewall doing NAT samples its LAN side in both directions — on the WAN the packets carry its public address, not the host's
const SFLOW_NOTE = () => T('switches: sample incoming traffic (ingress) on every port — both directions everywhere counts the traffic twice; a router or firewall doing NAT: sample the LAN-side interfaces in both directions and not the WAN, where packets carry the public address instead of the inside host');
const VENDORS = {
  Fortinet:{netflow9:named(rated((ip, port, o) => `config system netflow\n    set active-flow-timeout 60\n    config collectors\n        edit 1\n            set collector-ip ${ip}\n            set collector-port ${port}\n        next\n    end\nend\n# ${T('WAN + internal interfaces (not Wi-Fi SSIDs)')}${o.rate > 1 ? `\n# ${T('netflow-sample-rate: FortiOS 7.6 and newer; FortiOS 7.4 and older sends every session — set 1:1 in FlowTrack there and leave the line out')}` : ''}\nconfig system interface${each(o, ['wan1', 'internal'], n => `\n    edit "${n}"\n        set netflow-sampler both${o.rate > 1 ? `\n        set netflow-sample-rate ${o.rate}` : ''}\n    next`)}\nend`)),
    sflow:named(rated((ip, port, o) => `config system sflow\n    config collectors\n        edit 1\n            set collector-ip ${ip}\n            set collector-port ${port}\n        next\n    end\nend\n# ${T('FortiOS 7.0 and older: set collector-ip / set collector-port directly under config system sflow')}\n# ${T('the LAN-side interfaces in both directions, not the WAN: on the WAN sFlow sees the public address instead of the inside host (FortiOS samples before NAT)')}\n# ${T('Wi-Fi through FortiAPs in tunnel mode shows as the access point\'s CAPWAP traffic (UDP 5247), not as its clients; for per-host traffic use NetFlow v9')}\nconfig system interface${each(o, ['internal'], n => `\n    edit "${n}"\n        set sflow-sampler enable\n        set sample-rate ${sfRate(o, 1000)}\n        set sample-direction both\n        set polling-interval 20\n    next`)}\nend`))},
  Cisco:{netflow9:ciscoFnf('netflow-v9'), ipfix:ciscoFnf('ipfix'),
    sflow:named(rated((ip, port, o) => `! ${T('Cisco Nexus (NX-OS); IOS routers export NetFlow / IPFIX')}\nfeature sflow\nsflow sampling-rate ${sfRate(o, 1024)}\nsflow counter-poll-interval 20\nsflow collector-ip ${ip} vrf default\nsflow collector-port ${port}\nsflow agent-ip <${T('address of this device')}>\n! ${SFLOW_NOTE()}${each(o, ['ethernet 1/1'], n => `\nsflow data-source interface ${n}`)}`)),
    netflow5:named(rated((ip, port, o) => `! ${T('classic NetFlow (older IOS): IPv4 only')}\n${o.rate > 1 ? `flow-sampler-map FT-SAMP\n mode random one-out-of ${o.rate}\n` : ''}ip flow-export version 5\nip flow-export destination ${ip} ${port}\nip flow-cache timeout active 1\n! ${T('on every interface to watch (WAN and LAN)')}${each(o, ['GigabitEthernet0/0/0'], n => o.rate > 1 ? `\ninterface ${n}\n flow-sampler FT-SAMP` : `\ninterface ${n}\n ip flow ingress\n ip flow egress`)}${o.rate > 1 ? `\n! ${T('a sampler counts the traffic coming in: no ip flow ingress / egress on these interfaces (full NetFlow would override it)')}` : ''}`))},
  MikroTik:{netflow9:named(rated((ip, port, o) => `/ip traffic-flow set enabled=yes interfaces=${mtIfs(o)} active-flow-timeout=1m${mtSamp(o)}\n/ip traffic-flow target add dst-address=${ip} port=${port} version=9`)),
    ipfix:named(rated((ip, port, o) => `/ip traffic-flow set enabled=yes interfaces=${mtIfs(o)} active-flow-timeout=1m${mtSamp(o)}\n/ip traffic-flow target add dst-address=${ip} port=${port} version=ipfix`)),
    netflow5:named(rated((ip, port, o) => `/ip traffic-flow set enabled=yes interfaces=${mtIfs(o)} active-flow-timeout=1m${mtSamp(o)}\n/ip traffic-flow target add dst-address=${ip} port=${port} version=5`))},
  Juniper:{ipfix:juniper('version-ipfix', 'version-ipfix'), netflow9:juniper('version9', 'version9'),
    sflow:named(rated((ip, port, o) => `# ${T('EX / QFX switches')}\nset protocols sflow collector ${ip} udp-port ${port}\nset protocols sflow sample-rate ingress ${sfRate(o, 1000)}\nset protocols sflow polling-interval 20\n# ${SFLOW_NOTE()}${each(o, ['ge-0/0/0'], n => `\nset protocols sflow interfaces ${n}`)}`))},
  'Palo Alto':{netflow9:steps((ip, port) => [T('Device → Server Profiles → NetFlow → Add: name FlowTrack, active timeout 1 min, template refresh 1 min.'),
    T('Servers → Add: address {ip}, port {port}.', {ip, port}), T('Network → Interfaces → each interface to watch → Advanced → NetFlow Profile: FlowTrack.'), T('Commit.')])},
  'Check Point':{netflow9:(ip, port) => `# Gaia clish\nadd netflow collector ip ${ip} port ${port} export-format Netflow_V9\nsave config`,
    netflow5:(ip, port) => `# Gaia clish\nadd netflow collector ip ${ip} port ${port} export-format Netflow_V5\nsave config`},
  SonicWall:Object.fromEntries([['ipfix', 'IPFIX'], ['netflow9', 'NetFlow version-9'], ['netflow5', 'NetFlow version-5']].map(([k, l]) => [k, steps((ip, port) => [
    T('Device → AppFlow → Flow Reporting (older SonicOS: Log → Flow Reporting).'), T('Send flows to an external collector: on; protocol: {proto}.', {proto: l}),
    T('External collector: {ip}, port {port}.', {ip, port}), T('Report on the interfaces to watch (WAN and LAN), then Accept.')])])),
  Huawei:{netflow9:huawei(9), netflow5:huawei(5),
    sflow:named(rated((ip, port, o) => `sflow agent ip <${T('address of this device')}>\nsflow collector 1 ip ${ip} udp-port ${port}\n# ${SFLOW_NOTE()}${each(o, ['GigabitEthernet0/0/1'], n => `\ninterface ${n}\n sflow flow-sampling collector 1\n sflow flow-sampling rate ${sfRate(o, 1000)}\n sflow flow-sampling inbound\n sflow counter-sampling collector 1\n sflow counter-sampling interval 20`)}`))},
  Arista:{sflow:rated((ip, port, o) => `sflow sample ${sfRate(o, 1024)}\nsflow polling-interval 20\nsflow destination ${ip} ${port}\nsflow source-interface Management1\nsflow run`),
    ipfix:named(rated((ip, port, o) => `flow tracking sampled\n   sample ${sfRate(o, 1024)}\n   tracker FT\n      exporter FT\n         collector ${ip} port ${port}\n         local interface Management1\n   no shutdown\n! ${T('on every interface to watch (WAN and LAN)')}${each(o, ['Ethernet1'], n => `\ninterface ${n}\n   flow tracker sampled FT`)}`))},
  'VyOS / EdgeOS':{netflow9:vyos(9), ipfix:vyos(10), netflow5:vyos(5),
    sflow:named(rated((ip, port, o) => `# VyOS 1.4+\nset system sflow server ${ip} port ${port}\nset system sflow sampling-rate ${sfRate(o, 1000)}\n${each(o, ['eth0'], n => `set system sflow interface ${n}\n`)}# ${T('EdgeOS: set system flow-accounting sflow server {ip} port {port}; set system flow-accounting interface eth0', {ip, port})}\ncommit; save`))},
  'pfSense / OPNsense':Object.fromEntries([['netflow9', 'v9', '9'], ['ipfix', null, '10'], ['netflow5', 'v5', '5']].map(([k, opn, pf]) => [k, steps((ip, port) => [
    ...(opn ? [T('OPNsense: Reporting → NetFlow: listening interfaces (WAN and LAN), version {v}, destination {ip}:{port}, Apply.', {v: opn, ip, port})] : []),
    T('pfSense: install the softflowd package; Services → softflowd: interfaces (WAN and LAN), host {ip}, port {port}, NetFlow version {v}, Save.', {ip, port, v: pf})])])),
  'Linux / pmacct':Object.fromEntries([['ipfix', 10], ['netflow9', 9], ['netflow5', 5]].map(([k, v]) => [k, named(rated((ip, port, o) =>
    `# /etc/pmacct/pmacctd.conf\nplugins: nfprobe\nnfprobe_receiver: ${ip}:${port}\nnfprobe_version: ${v}\n${o.rate > 1 ? `sampling_rate: ${o.rate}\n` : ''}pcap_interface: ${(o.ifs[0] || 'eth0')}\n# ${T('or softflowd')}: softflowd -i ${(o.ifs[0] || 'eth0')} -n ${ip}:${port} -v ${v} -t maxlife=60${o.rate > 1 ? ` -s ${o.rate}` : ''}${o.ifs.length > 1 ? `\n# ${T('one interface per process: run one more for each of {names}', {names: o.ifs.slice(1).join(', ')})}` : ''}`))]).concat([['sflow',
    named(rated((ip, port, o) => `# /etc/hsflowd.conf (host-sflow)\nsflow {\n  collector { ip = ${ip} udpport = ${port} }\n  sampling = ${sfRate(o, 1000)}\n  polling = 20\n${each(o, ['eth0'], n => `  pcap { dev = ${n} }\n`)}}\n# ${T('or pmacct')}: plugins: sfprobe · sfprobe_receiver: ${ip}:${port} · sampling_rate: ${sfRate(o, 1000)}`))]])),
  Other:Object.fromEntries(['netflow9', 'ipfix', 'netflow5'].map(k => [k, rated(steps((ip, port, o) => [
    T('Flow export ({proto}) to {ip}, UDP port {port}.', {proto: PROTO_NAME[k], ip, port}), T('Active timeout 60 s, inactive timeout 15 s; templates resent at least every minute.'),
    T('On every interface to watch (WAN and LAN), ingress — or ingress and egress when the record carries the flow direction.'),
    T('Fields: addresses, ports, protocol, input and output interface, bytes, packets, first and last time.'),
    ...(o.rate > 1 ? [T('Packet sampling 1 of {n} — or, if the device cannot sample, none and 1:1 in FlowTrack.', {n: o.rate})] : [])]))]).concat([['sflow', rated(steps((ip, port, o) => [
    T('sFlow version 5 to {ip}, UDP port {port}.', {ip, port}), o.rate > 1 ? T('Sampling 1 of {n} packets, counter polling every 20 s.', {n: o.rate}) : T('Sampling 1 of 1000 packets on fast links (1 of 100–500 on slower ones), counter polling every 20 s.'),
    SFLOW_NOTE()]))]])),
  'HPE Aruba':{sflow:named(rated((ip, port, o) => `! AOS-CX\nsflow\nsflow collector ${ip} port ${port}\nsflow sampling ${sfRate(o, 1024)}\nsflow polling 20\n! ${SFLOW_NOTE()}${each(o, ['1/1/1'], n => `\ninterface ${n}\n    sflow`)}\n! ${T('AOS-S (ProCurve): sflow 1 destination {ip} {port} · interface 1-24 sflow 1 sampling {rate} · sflow 1 polling 1-24 20', {ip, port, rate: sfRate(o, 1024)})}`))},
};
// the protocols FlowTrack takes from this vendor now, recommended first; vendors with none are not offered yet
const vendorProtos = v => Object.keys(VENDORS[v] || {}).filter(p => PROTO_READY.includes(p) && VENDORS[v][p]);
const VENDOR_LIST = () => Object.keys(VENDORS).filter(v => vendorProtos(v).length);
const vendorLabel = v => v === 'Other' ? T('Other') : v;
// SNMP on the device, from the values in the form (stored secrets are not sent to the browser: placeholders then)
const SNMP_AUTH = ['MD5', 'SHA', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'], SNMP_PRIV = ['DES', 'AES', 'AES-192', 'AES-256'];
const SNMP_LEVELS = {noAuthNoPriv:T('no authentication, no privacy'), authNoPriv:T('authentication only'), authPriv:T('authentication + privacy')};
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
    ? `config system snmp sysinfo\n    set status enable\nend\nconfig system snmp user\n    edit "${snmpVal(s, 'user', 'user')}"\n        set trap-status disable\n        # ${T('FortiOS answers SNMPv3 queries only from these hosts')}\n        set notify-hosts ${ip}\n        set queries enable\n        set query-port ${s.port || 161}\n        set security-level ${{noAuthNoPriv:'no-auth-no-priv', authNoPriv:'auth-no-priv', authPriv:'auth-priv'}[s.level]}${s.level !== 'noAuthNoPriv' ? `\n        set auth-proto ${{MD5:'md5', SHA:'sha', 'SHA-224':'sha224', 'SHA-256':'sha256', 'SHA-384':'sha384', 'SHA-512':'sha512'}[s.auth_proto]}\n        set auth-pwd ${snmpVal(s, 'auth_pass', 'auth-password')}` : ''}${s.level === 'authPriv' ? `\n        set priv-proto ${{DES:'des', AES:'aes', 'AES-192':'aes', 'AES-256':'aes256'}[s.priv_proto]}\n        set priv-pwd ${snmpVal(s, 'priv_pass', 'priv-password')}` : ''}\n    next\nend\n# ${T('SNMP access on the interface FlowTrack reaches the device through')}\nconfig system interface\n    edit "internal"\n        append allowaccess snmp\n    next\nend\n# ${T('No answer after this? Restart the SNMP agent once')}:\n# diagnose test application snmpd 99`
    : `config system snmp sysinfo\n    set status enable\nend\nconfig system snmp community\n    edit 1\n        set name "${snmpVal(s, 'community', 'community')}"\n        config hosts\n            edit 1\n                set ip ${ip} 255.255.255.255\n            next\n        end\n        set query-v1-status disable\n        set query-v2c-port ${s.port || 161}\n        set trap-v1-status disable\n        set trap-v2c-status disable\n    next\nend\n# ${T('SNMP access on the interface FlowTrack reaches the device through')}\nconfig system interface\n    edit "internal"\n        append allowaccess snmp\n    next\nend\n# ${T('No answer after this? Restart the SNMP agent once')}:\n# diagnose test application snmpd 99`),
  Cisco:(ip, s) => `ip access-list standard FLOWTRACK-SNMP\n permit ${ip}\nsnmp-server ifindex persist\n` + (s.version === '3'
    ? `snmp-server group FLOWTRACK v3 ${{noAuthNoPriv:'noauth', authNoPriv:'auth', authPriv:'priv'}[s.level]} access FLOWTRACK-SNMP\nsnmp-server user ${snmpVal(s, 'user', 'user')} FLOWTRACK v3${s.level !== 'noAuthNoPriv' ? ` auth ${s.auth_proto === 'MD5' ? 'md5' : s.auth_proto === 'SHA' ? 'sha' : 'sha-2 ' + s.auth_proto.slice(4)} ${snmpVal(s, 'auth_pass', 'auth-password')}` : ''}${s.level === 'authPriv' ? ` priv ${s.priv_proto === 'DES' ? 'des' : 'aes 128'} ${snmpVal(s, 'priv_pass', 'priv-password')}` : ''}`
    : `snmp-server community ${snmpVal(s, 'community', 'community')} RO FLOWTRACK-SNMP`),
  MikroTik:(ip, s) => (s.version === '3'
    ? `/snmp community add name=${snmpVal(s, 'user', 'user')} addresses=${ip}/32 read-access=yes security=${{noAuthNoPriv:'none', authNoPriv:'authorized', authPriv:'private'}[s.level]}${s.level !== 'noAuthNoPriv' ? ` authentication-protocol=${s.auth_proto === 'SHA' ? 'SHA1' : s.auth_proto} authentication-password="${snmpVal(s, 'auth_pass', 'auth-password')}"` : ''}${s.level === 'authPriv' ? ` encryption-protocol=${s.priv_proto} encryption-password="${snmpVal(s, 'priv_pass', 'priv-password')}"` : ''}`
    : `/snmp community add name="${snmpVal(s, 'community', 'community')}" addresses=${ip}/32 read-access=yes`) + `\n/snmp set enabled=yes\n# ${T('The default firewall drops input from interfaces outside the LAN list (tunnels, WAN): let FlowTrack in')}\n/ip firewall filter add chain=input protocol=udp dst-port=161 src-address=${ip} action=accept place-before=0 comment=FlowTrack-SNMP`,
  Juniper:(ip, s) => (s.version === '3'
    ? `set snmp v3 usm local-engine user ${snmpVal(s, 'user', 'user')} ${s.level === 'noAuthNoPriv' ? 'authentication-none' : `authentication-${s.auth_proto.toLowerCase().replace('-', '')} authentication-password "${snmpVal(s, 'auth_pass', 'auth-password')}"`}${s.level === 'authPriv' ? `\nset snmp v3 usm local-engine user ${snmpVal(s, 'user', 'user')} privacy-${s.priv_proto === 'DES' ? 'des' : 'aes128'} privacy-password "${snmpVal(s, 'priv_pass', 'priv-password')}"` : ''}\nset snmp v3 vacm security-to-group security-model usm security-name ${snmpVal(s, 'user', 'user')} group flowtrack\nset snmp v3 vacm access group flowtrack default-context-prefix security-model usm security-level ${{noAuthNoPriv:'none', authNoPriv:'authentication', authPriv:'privacy'}[s.level]} read-view all\nset snmp view all oid .1 include`
    : `set snmp community "${snmpVal(s, 'community', 'community')}" authorization read-only\nset snmp community "${snmpVal(s, 'community', 'community')}" clients ${ip}/32`),
  Other:(ip, s) => s.version === '3'
    ? `# ${T('SNMPv3, read-only, from {ip}: user {user}, level {level}', {ip, user: snmpVal(s, 'user', 'user'), level: s.level})}` + (s.level !== 'noAuthNoPriv' ? `\n# ${T('authentication')} ${s.auth_proto}` : '') + (s.level === 'authPriv' ? `, ${T('privacy')} ${s.priv_proto}` : '')
    : `# ${T('SNMP v2c, read-only, from {ip}: community {community}', {ip, community: snmpVal(s, 'community', 'community')})}`,
  'Linux / pmacct':(ip, s) => s.version === '3'
    ? `# /etc/snmp/snmpd.conf\nagentAddress udp:${s.port || 161}\nrouser ${snmpVal(s, 'user', 'user')} ${{noAuthNoPriv:'noauth', authNoPriv:'auth', authPriv:'priv'}[s.level]}\n# ${T('stop snmpd, add the user, start snmpd')}:\n# net-snmp-create-v3-user -ro${s.level !== 'noAuthNoPriv' ? ` -a ${s.auth_proto} -A '${snmpVal(s, 'auth_pass', 'auth-password')}'` : ''}${s.level === 'authPriv' ? ` -x ${s.priv_proto} -X '${snmpVal(s, 'priv_pass', 'priv-password')}'` : ''} ${snmpVal(s, 'user', 'user')}`
    : `# /etc/snmp/snmpd.conf\nagentAddress udp:${s.port || 161}\nrocommunity ${snmpVal(s, 'community', 'community')} ${ip}`,
};
const snmpTag = x => !x.snmp || !x.snmp.enabled ? '' : x.snmp.ok === false
  ? ` <span class="pill warn" title="${esc(x.snmp.error_text || '')}">${T('SNMP error')}</span>`
  : ` <span class="tag" title="${x.snmp.polled ? esc(T('SNMP: {ifs} interfaces, {addrs} addresses', {ifs: x.snmp.interfaces, addrs: x.snmp.addresses})) : T('SNMP: waiting for the first poll')}">SNMP</span>`;
// ---- edition: limits in effect and the license key (admin)
const fmtInt = n => (+n || 0).toLocaleString(LOC);
const LIC_BAD = ['invalid', 'other_instance', 'returned', 'clock', 'expired'];
function copyText(text, btn){
  const done = () => { const t = btn.textContent; btn.textContent = T('Copied'); setTimeout(() => btn.textContent = t, 1500); };
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
  const status = {community:T('free edition'), active:T('license active'),
    invalid:T('the license is not valid'), other_instance:T('license of another server'),
    returned:T('license deactivated'), clock:T('the clock is wrong'),
    expired:T('license expired — Community limits apply'),
    unconfirmed:T('not confirmed by the license server — Community limits apply')}[ed.status] || ed.status;
  const fmtDay = t => new Date(t * 1000).toLocaleDateString(LOC, {day:'numeric', month:'long', year:'numeric'});
  const chk = ed.last_checkin, online = ed.online ? `<div class="lic-online"><span class="nat">${
    ed.lease_until ? T('Online license · confirmed by the license server until {date}', {date: fmtDay(ed.lease_until)})
                   : T('Online license · not confirmed by the license server')}${
    chk ? ' · ' + (chk.ok ? T('last check ') + new Date(chk.ts * 1000).toLocaleString(LOC) : T('last check failed: ') + esc(chk.error)) : ''}</span>${
    isAdmin() ? `<button class="btn" id="licCheck">${T('Check now')}</button>` : ''}</div>`
    // an offline (or expired) license never contacts the server by itself: ask on request whether the vendor renewed it
    : lic.customer && isAdmin() ? `<div class="lic-online"><span class="nat">${T('Offline license · FlowTrack does not contact the license server by itself')}</span><button class="btn" id="licCheck">${T('Check for renewal')}</button></div>` : '';
  const note = window.__licNote; window.__licNote = null;
  const noteHtml = note ? `<p class="note" role="status" style="color:${note.renewed ? 'var(--ok)' : note.error ? 'var(--crit)' : 'inherit'}">${esc(note.note)}</p>` : '';
  const soon = pro && lic.days_left != null && lic.days_left < 30;
  const until = lic.expires ? new Date(lic.expires * 1000).toLocaleDateString(LOC, {day:'numeric', month:'long', year:'numeric', timeZone:'UTC'}) : '';   // licenses end at 23:59 UTC of their last day
  box.innerHTML = `<div class="edition">
    <div class="ed-name"><b>${name}</b><span class="pill ${pro ? 'ok' : ed.status === 'community' ? 'info' : 'crit'}">${esc(status)}</span>${soon ? `<span class="pill warn">${Tn(lic.days_left, 'ends in {n} day', 'ends in {n} days')}</span>` : ''}${ed.message ? `<span class="nat">${esc(ed.message)}</span>` : ''}</div>
    <div class="ed-lim">
      <div><span>${T('Records per second')}</span><b>${ed.rps ? T('up to ') + fmtInt(ed.rps) : T('no limit')}</b></div>
      <div title="${T('New records are kept this long. Records already stored keep their own term and are never shortened; without a license only the last {days} days are shown, older records show again with a license.', {days: ed.community_days || 30})}"><span>${T('Flow details kept')}</span><b>${ed.retention_days} ${T('days')}${ed.view_days > ed.retention_days ? ` <small>${T('(earlier records: the last {days} days shown)', {days: ed.view_days})}</small>` : ''}</b></div>
      <div><span>${T('Not stored over the limit, 24 h')}</span><b class="${ed.license_drops_24h ? 'warnc' : ''}">${fmtInt(ed.license_drops_24h)}</b></div>
      ${lic.customer ? `<div><span>${T('Licensed to')}</span><b>${esc(lic.customer)}</b></div><div><span>${pro ? T('Valid until') : ed.status === 'expired' ? T('Expired on') : T('Term')}</span><b class="${soon || !pro ? 'warnc' : ''}">${until}</b></div>` : ''}
    </div>${online}${noteHtml}
  </div>`;
  box.classList.remove('loading');
  const lc = document.getElementById('licCheck'); if (lc) lc.onclick = async () => { lc.disabled = true; lc.textContent = T('Checking…');
    try { window.__licNote = (await apiPost('license/checkin', {})).checked; } catch (e) { window.__licNote = {error:true, note:e.message}; }
    META = await fetch('api/meta').then(r => r.json()); editionBadge(); editionPanel(); };
  const act = document.getElementById('actBox'); if (!act || !isAdmin()) return;
  // activation: this server's identity and request on the left, the license from the vendor on the right
  act.innerHTML = `<div class="lic-grid">
    <div class="lic-col">
      <div class="lic-step"><span class="lic-n">1</span><div><b>${T('Send the activation request')}</b>
        <p class="note">${T('Not needed with a license key. Without internet access, send it to your FlowTrack vendor — by e-mail, or read it out by phone from a closed network. The license will work on this server only.')}</p></div></div>
      <div class="lic-field"><span>${T('Instance ID')}</span><code class="mono" id="licInst">${esc(ed.instance || '')}</code></div>
      <div class="lic-field"><span>${T('Activation request')}</span><code class="mono lic-code" id="licReq">${esc(ed.request || '')}</code></div>
      <div class="acts"><button class="btn" id="reqCopy">${T('Copy')}</button><button class="btn" id="reqSave">${T('Download')}</button></div>
    </div>
    <div class="lic-col">
      <div class="lic-step"><span class="lic-n">2</span><div><b>${pro ? T('Enter a renewed license') : T('Enter the license')}</b>
        <p class="note">${T('Paste the license key (FTK-…): FlowTrack activates it online. Or load the .lic file (or paste the FTL-… code) from your vendor: it works at once and is then confirmed by the license server daily — only an offline license never needs the internet.')}</p></div></div>
      <textarea id="edKey" rows="4" spellcheck="false" autocomplete="off" placeholder="FTK-XXXXX-… / FTL-XXXXX-…" aria-label="${T('License key or code')}"></textarea>
      <div class="acts"><span class="nat" id="edMsg" role="status"></span><input type="file" id="licFile" accept=".lic,.txt,text/plain" hidden>
        <button class="btn" id="licLoad">${T('Load file…')}</button><button class="btn primary" id="edSave">${T('Activate')}</button></div>
    </div>
  </div>
  ${returned === 'released' ? `<div class="lic-return" role="alert"><b>${T('The license was deactivated on this server')}</b>
    <p class="note">${T('The license key is free again: enter it on the other server.')}</p></div>` : ''}
  ${returned && returned !== 'released' ? `<div class="lic-return" role="alert"><b>${T('The license was deactivated on this server')}</b>
    <p class="note">${T('Send this return code to your vendor to get the license for another server. This server will not accept that license again.')}</p>
    <div class="lic-field"><code class="mono lic-code" id="retCode">${esc(returned)}</code></div><div class="acts"><button class="btn" id="retCopy">${T('Copy')}</button></div></div>` : ''}
  ${ed.status !== 'community' ? `<div class="lic-move"><div><b>${T('Move the license to another server')}</b>
    <p class="note">${ed.online ? T('Deactivation removes the license from this server and frees the license key for another one. Community limits apply here again; stored data is kept.')
      : T('Deactivation removes the license from this server and gives a return code for the vendor. Community limits apply here again; stored data is kept.')}</p></div>
    <button class="btn danger" id="licOff">${ed.status === 'active' ? T('Deactivate…') : T('Remove…')}</button></div>` : ''}`;
  const say = (t, c) => { const m = document.getElementById('edMsg'); m.textContent = t; m.style.color = c || ''; };
  const refresh = async ret => { META = await fetch('api/meta').then(r => r.json()); editionBadge(); editionPanel(ret); };
  document.getElementById('reqCopy').onclick = e => copyText(ed.request, e.currentTarget);
  document.getElementById('reqSave').onclick = () => saveText(`flowtrack-request-${(ed.instance || '').replace(/-/g, '')}.txt`,
    `# FlowTrack activation request\n# Instance ID: ${ed.instance}\n# FlowTrack ${META.version || ''}, ${new Date().toISOString().slice(0, 10)}\n${ed.request}\n`);
  const file = document.getElementById('licFile');
  document.getElementById('licLoad').onclick = () => file.click();
  file.onchange = async () => { const f = file.files[0]; if (!f) return; document.getElementById('edKey').value = (await f.text()).trim(); file.value = ''; say(f.name); };
  document.getElementById('edSave').onclick = async () => { const k = document.getElementById('edKey').value.trim();
    if (!k) return say(T('Paste the license key or code first'), 'var(--crit)');
    say(/^\s*ftk/i.test(k) ? T('Activating at the license server…') : T('Checking…'));
    try { await apiPost('license', {key:k}); await refresh(); } catch (e) { say(e.message, 'var(--crit)'); } };
  const rc = document.getElementById('retCopy'); if (rc) rc.onclick = e => copyText(returned, e.currentTarget);
  const off = document.getElementById('licOff'); if (off) off.onclick = async () => {
    if (ed.status !== 'active') {           // a license that does not work here: just remove it
      if (!confirm(T('Remove the license from this server?'))) return;
      try { await apiPost('license', {key:''}); await refresh(); } catch (e) { alert(e.message); } return; }
    if (!confirm(T('Deactivate the license on this server? Community limits apply here again, and this server will not accept this license again. You get a return code to move the license to another server.'))) return;
    try { const r = await apiPost('license/deactivate', {}); await refresh(r.released ? 'released' : r.return_code); } catch (e) { alert(e.message); } };
}
// edition badge under the logo: Community / Pro, coloured when a license ends soon or has ended; opens the license panel
function editionBadge(){
  const b = document.getElementById('edBadge'), ed = META.edition; if (!b || !ed) return;
  const pro = ed.status === 'active', left = ed.days_left;
  b.textContent = pro ? 'Pro' : 'Community';
  b.className = 'edbadge' + (pro ? ' pro' : '') + (pro && left != null && left < 30 ? ' warn' : '') + (LIC_BAD.includes(ed.status) ? ' crit' : '');
  b.title = (pro ? 'FlowTrack Pro' + (left != null ? Tn(left, ' · {n} day left', ' · {n} days left') : '') : `FlowTrack Community · ${T('up to')} ${fmtInt(ed.rps)} ${T('records/s')}`)
    + (ed.status === 'expired' ? T(' · license expired') : LIC_BAD.includes(ed.status) ? T(' · the license does not work here') : '') + ' — ' + T('edition and license');
  b.hidden = false;
  b.onclick = () => { state.view = 'settings'; state.setTab = 'license'; render(); };
}
// ===================== settings: one page, tabs on top =====================
const SET_TABS = () => [['general', T('General'), ICO.grid], ['devices', T('Devices'), DEV_ICON],
  ...(isAdmin() ? [['users', T('Users'), USER_ICON], ['events', T('Events'), ICO.pulse], ['backups', T('Backups'), BK_ICON]] : []), ['license', T('License'), ICO.shield]];
function vSettings(){
  const tabs = SET_TABS(); if (!tabs.some(t => t[0] === state.setTab)) state.setTab = 'general';
  document.getElementById('view').innerHTML = `<nav class="settabs glass" role="tablist" aria-label="${T('Settings')}">${tabs.map(([k, l, ic]) =>
    `<button role="tab" data-tab="${k}" aria-selected="${k === state.setTab}" ${k === state.setTab ? '' : 'tabindex="-1"'}>${icon(ic, 16)}${l}</button>`).join('')}</nav><div id="setBody"></div>`;
  const bar = document.querySelector('.settabs');
  bar.querySelectorAll('button').forEach(b => b.onclick = () => { if (b.dataset.tab === state.setTab) return;
    if (state.ifEdit && !confirm(T('Discard unsaved interface changes?'))) return;
    state.setTab = b.dataset.tab; render(); });
  bar.addEventListener('keydown', e => { if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;   // arrow keys move between tabs
    const i = tabs.findIndex(t => t[0] === state.setTab), n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length][0];
    state.setTab = n; render(); setTimeout(() => { const b = document.querySelector(`.settabs [data-tab="${n}"]`); if (b) b.focus(); }); });
  ({general:vGeneral, devices:vDevices, users:vUsers, events:vEventsCfg, backups:vBackups, license:vLicense})[state.setTab]();
}
function vGeneral(){
  const ed = META.edition || {};
  document.getElementById('setBody').innerHTML = `<div class="grid top">
    <section class="glass panel s6">${ph('globe', T('Language'), T('of this browser · other users keep their own'))}
      <label class="sel glass">${icon(ICO.globe, 16)}<select id="langSel" aria-label="${T('Language')}">${langs().map(([v, l]) => `<option value="${v}" lang="${v}" ${LANG === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label></section>
    <section class="glass panel s6">${ph('list', T('About'), T('version and edition'))}
      <div class="about">
        <div><span>${T('Version')}</span><b class="mono">FlowTrack ${esc(META.version || '—')}</b></div>
        <div><span>${T('Edition')}</span><b>${ed.status === 'active' ? 'Pro' : 'Community'}</b><button class="lnk" id="toLic">${T('License')} →</button></div>
        <div><span>${T('Source code')}</span><a href="https://github.com/henzelis/flowtrack" target="_blank" rel="noopener">github.com/henzelis/flowtrack</a></div>
        <div><span>${T('Account')}</span><b class="mono">${esc(ME.name)}</b><button class="lnk" id="myPass">${T('Change my password')}</button></div>
      </div></section></div>`;
  document.getElementById('langSel').onchange = e => { if (e.target.value !== LANG) setLang(e.target.value); };
  document.getElementById('toLic').onclick = () => { state.setTab = 'license'; render(); };
  document.getElementById('myPass').onclick = openPassword;
}
// ===================== backups: data + settings, on a schedule, here and off the server (backup.py runs them as root) =====================
const BK_ICON = 'M2 4h14v3H2zM3 7v8h12V7M7 10h4';
const BK_DESTS = [['s3', 'S3'], ['sftp', 'SFTP'], ['ftp', 'FTP']];
function vBackups(){
  const v = document.getElementById('setBody'), seq = renderSeq;
  v.innerHTML = `<div class="grid"><div id="bkKpi" style="display:contents"></div>
    <section class="glass panel s12">${ph(BK_ICON, T('Backups'), T('the flow data and every setting · a full one weekly, the changes since it on the other days · newest first'),
      `<label class="chk" title="${T('A full backup does not depend on older ones')}"><input type="checkbox" id="bkFull">${T('full')}</label> <button class="btn primary" id="bkNow">${T('Back up now')}</button>`)}<div id="bkList" class="loading"></div></section>
    <section class="glass panel s6">${ph('chart', T('Schedule and keeping'), T('runs on this server, also when nobody is logged in'))}<div id="bkSched" class="form"></div></section>
    <section class="glass panel s6">${ph('key', T('Encryption'), T('of the copies off the server (S3, SFTP, FTP)'))}<div id="bkEnc" class="form"></div></section>
    <section class="glass panel s12">${ph('globe', T('Where to keep'), T('a folder on this server always · copies to S3, SFTP or FTP: a backup survives the loss of the server'))}<div id="bkDest" class="loading"></div></section>
    <section class="glass panel s12 evsave"><div><button class="btn primary" id="bkSave">${T('Save')}</button></div><p class="err" id="bkErr" hidden></p><p class="note" id="bkOk" hidden>${T('Saved.')}</p></section></div>`;
  let d = null, fp = '', checking = null, asked = 0;
  const box = (id, html) => { const el = document.getElementById(id); if (!el) return null; el.classList.remove('loading'); el.innerHTML = html; return el; };
  const ago = t => { const s = Math.floor(Date.now() / 1000) - t; return s < 3600 ? T('{n} min ago', {n:Math.max(1, Math.round(s / 60))}) : s < 86400 ? T('{n} h ago', {n:Math.round(s / 3600)}) : T('{n} d ago', {n:Math.round(s / 86400)}); };
  const when = t => new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'});
  const busy = () => !!(d && (d.running || d.pending));
  const load = async () => { const r = await fetch('api/backups'); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.status); return j; };
  // ---- what changes while a backup runs: the cards, the list, the button
  const draw = () => {
    const c = d.config, last = d.last, newest = d.backups[0];
    const kc = (ic, k, val, sub, col) => `<section class="glass panel kcard s3" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic] || ic, 22)}</span><span class="k">${k}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span>${sub ? `<span class="nat" style="grid-column:2">${sub}</span>` : ''}</section>`;
    const lastSub = !last ? T('none yet') : !last.ok ? `<span class="pill ${newest && newest.id === last.id ? 'warn' : 'crit'}">${newest && newest.id === last.id ? T('a copy failed') : T('failed')}</span> <span title="${esc(last.error)}">${esc(last.error.slice(0, 90))}</span>`
      : newest ? `<span class="pill ok">OK</span> ${newest.kind === 'full' ? T('Full') : T('Changes')} · ${fmtB(newest.size)}` : '';
    box('bkKpi', kc(BK_ICON, T('Last backup'), last ? ago(last.t) : '—', lastSub)
      + kc('pulse', T('Next backup'), d.next ? `${dmy(d.next)} ${hhmm(d.next)}` : T('off'), d.next ? (c.schedule.full === 'week' ? T('full every week, the changes every day') : T('full every day'))
          + (d.tz_offset !== -new Date(d.next * 1000).getTimezoneOffset() * 60 ? ` · ${T('{t} on the server', {t:new Date((d.next + d.tz_offset) * 1000).toLocaleTimeString(LOC, {hour:'2-digit', minute:'2-digit', timeZone:'UTC'})})}` : '') : T('only by hand'))
      + kc('list', T('Kept'), `${d.backups.length}`, `${fmtB(d.used)} · ${T('{free} free on the disk', {free:fmtB(d.free)})}`)
      + kc('shield', T('Encryption'), c.encrypt.on ? T('on') : T('off'), c.encrypt.on ? T('copies: AES-256-GCM') : BK_DESTS.some(([k]) => c[k].on) ? T('the copies hold passwords and tokens') : T('no copies off the server'), c.encrypt.on ? 'var(--ok)' : BK_DESTS.some(([k]) => c[k].on) ? 'var(--warn)' : ''));
    const on = BK_DESTS.filter(([k]) => c[k].on);
    const place = (m, k, l) => { const s = (m.places || {})[k];
      if (s === 'ok') return `<span class="pill ok" title="${T('stored')}">${l}</span>`;
      if (s === 'error') return `<span class="pill crit" title="${esc((m.errors || {})[k] || T('failed'))}">${l} ✕</span>`;
      return c[k].on ? `<span class="pill" style="opacity:.6" title="${T('not copied yet — with the next backup')}">${l} …</span>` : ''; };
    const vf = m => { const x = m.verified; if (checking === m.id) return T('Checking…');
      return x ? (x.ok ? `✓ ${T('intact')}` : `✕ ${T('damaged')}`) : T('Check'); };
    const rows = d.backups.slice(0, state.bkAll ? 999 : 8);
    const el = box('bkList', d.backups.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('Time')}</th><th>${T('Type')}</th><th class="num">${T('Size')}</th><th>${T('Version')}</th><th>${T('Where')}</th><th></th><th></th></tr></thead><tbody>
      ${rows.map(m => `<tr data-id="${esc(m.id)}"><td class="mono">${when(m.t)}<div class="nat">${ago(m.t)}</div></td><td>${m.kind === 'full' ? `<b>${T('Full')}</b>` : T('Changes')}${m.encrypted ? ` <span title="${T('the copies are encrypted')}">🔒</span>` : ''}</td>
        <td class="num mono">${fmtB(m.size)}</td><td class="mono">${esc(m.version)}</td><td>${[`<span class="pill ok">${T('here')}</span>`, ...on.map(([k, l]) => place(m, k, l))].join(' ')}</td>
        <td class="nat">${Math.round(m.took)} s</td><td style="white-space:nowrap"><button class="btn" data-a="restore">${T('Restore…')}</button> <button class="btn" data-a="verify" ${busy() ? 'disabled' : ''} title="${esc(m.verified && !m.verified.ok ? m.verified.problems.join('\n') : m.verified ? T('checked {when}', {when:when(m.verified.t)}) : T('Check that every file of the backup is in place'))}">${vf(m)}</button></td></tr>`).join('')}</tbody></table></div>
      ${d.backups.length > 8 ? `<p style="margin:8px 0 0"><button class="btn" id="bkMore">${state.bkAll ? T('Show the last 8') : T('Show all ({n})', {n:d.backups.length})}</button></p>` : ''}
      <p class="note">${T('A backup of the changes needs the full one before it; the keeping rule deletes a full backup together with the changes after it. A failed copy is tried again with the next backup.')}</p>`
      : `<div class="empty">${d.next ? T('No backups yet — the first one runs {when}, or press Back up now.', {when:when(d.next)}) : T('No backups yet — press Back up now.')}</div>`);
    if (!el) return;
    const more = document.getElementById('bkMore'); if (more) more.onclick = () => { state.bkAll = !state.bkAll; draw(); };
    el.querySelectorAll('button[data-a="restore"]').forEach(b => b.onclick = () => openRestore(d.backups.find(x => x.id === b.closest('tr').dataset.id)));
    el.querySelectorAll('button[data-a="verify"]').forEach(b => b.onclick = async () => { const id = b.closest('tr').dataset.id;
      try { await apiPost('backups/verify', {id}); checking = id; asked = Math.floor(Date.now() / 1000); draw(); poll(); } catch (e) { formErr('bkErr', e.message); } });
    const nb = document.getElementById('bkNow'), r = d.running;
    nb.disabled = busy();
    nb.textContent = !r ? (d.pending ? T('Starting…') : T('Back up now'))
      : r.stage === 'data' ? T('Backing up the flow data…') : r.stage === 'settings' ? T('Saving the settings…')
      : T('Copying to {where}… {pct} %', {where:r.stage.toUpperCase(), pct:r.total ? Math.min(99, Math.floor(100 * r.done / r.total)) : 0});
  };
  const openRestore = m => openModal(T('Restore a backup'), when(m.t), `<div class="form" style="padding:4px 2px">
      <p class="note" style="margin:0">${T('Restoring stops collecting and the web interface for a few minutes, replaces the flow data and the settings with the backup, and starts them again. Records that arrive meanwhile are lost. The current data is set aside until the backup is in place and comes back if the restore fails.')}</p>
      <p class="note" style="margin:0">${T('Run on the server:')}</p>
      <pre class="mono" style="margin:0;padding:10px 12px;border-radius:10px;background:rgba(0,0,0,.35);white-space:pre-wrap">sudo flowtrack restore ${esc(m.id)}</pre>
      <p class="note" style="margin:0">${T('Options: --only-settings (keep the flow data), --only-data (keep the settings), --with-license (also the license files — only on the same server). On a new server: install FlowTrack, set the same place here (S3, SFTP or FTP), then run sudo flowtrack restore --from s3 (or sftp, ftp, a folder) and pick the backup.')}</p>
      ${m.encrypted ? `<p class="note" style="margin:0;color:var(--warn)">${T('The copies of this backup are encrypted: a restore from them asks for the passphrase.')}</p>` : ''}</div>`);
  // ---- the forms: drawn once, so a refresh while a backup runs never clears what is being typed
  const forms = () => {
    const c = d.config, s = c.schedule, days = [T('Sunday'), T('Monday'), T('Tuesday'), T('Wednesday'), T('Thursday'), T('Friday'), T('Saturday')];
    const fulls = d.backups.filter(m => m.kind === 'full'), diffs = d.backups.filter(m => m.kind !== 'full');
    const fullSz = fulls.length ? fulls[0].size : 0, daySz = diffs.length ? diffs.reduce((a, m) => a + m.size, 0) / diffs.length : 0;
    box('bkSched', `<label class="chk"><input type="checkbox" id="bkOn" ${s.on ? 'checked' : ''}>${T('Back up every day')}</label>
      <div class="two"><label>${T('At (server time)')}<input id="bkTime" type="time" value="${esc(s.time)}"></label>
        <label>${T('Full backup')}<select id="bkFullSel"><option value="week" ${s.full === 'week' ? 'selected' : ''}>${T('once a week, the changes on the other days')}</option><option value="day" ${s.full === 'day' ? 'selected' : ''}>${T('every day')}</option></select></label></div>
      <div class="two"><label>${T('Full backup on')}<select id="bkDay">${days.map((n, i) => `<option value="${i}" ${s.weekday === i ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
        <label>${T('Keep full backups (with their changes)')}<input id="bkKeep" type="number" min="1" max="60" value="${esc(c.keep_full)}"></label></div>
      <p class="note" style="margin:0" id="bkEst"></p>`);
    const est = () => { const n = +document.getElementById('bkKeep').value || 1, wk = document.getElementById('bkFullSel').value === 'week';
      document.getElementById('bkEst').textContent = fullSz ? T('About {size} with these settings: a full backup ≈ {full}, a day of changes ≈ {day}.', {size:fmtB(n * (wk ? fullSz + 6 * daySz : fullSz)), full:fmtB(fullSz), day:fmtB(daySz)}) : ''; };
    box('bkEnc', `<label class="chk"><input type="checkbox" id="bkEncOn" ${c.encrypt.on ? 'checked' : ''}>${T('Encrypt the copies with a passphrase')}</label>
      <div class="two"><label>${T('Passphrase')}<input id="bkPass" type="password" autocomplete="new-password" placeholder="${c.encrypt.set ? T('saved — leave empty to keep') : T('at least 10 characters')}"></label>
        <label>${T('Repeat')}<input id="bkPass2" type="password" autocomplete="new-password"></label></div>
      <p class="note" style="margin:0;color:var(--warn)">${T('Keep the passphrase somewhere else too (a password manager). Without it an encrypted copy cannot be restored — nobody, us included, can recover it.')}</p>
      <p class="note" style="margin:0">${T('The folder on this server is not encrypted: only root can read it, and the next backup of the changes needs it as it is. The backups hold the users, SNMP and Telegram / e-mail secrets.')}</p>`);
    const dTab = state.bkTab || 'local', pill = k => c[k].on ? ` <span class="pill ok">${T('on')}</span>` : '';
    const sec = (id, set) => `<input id="${id}" type="password" autocomplete="new-password" placeholder="${set ? T('saved — leave empty to keep') : ''}">`;
    const testRow = k => `<div><button class="btn" type="button" data-test="${k}">${T('Test')}</button> <span class="note" data-say="${k}"></span></div>`;
    const x3 = c.s3, sf = c.sftp, ft = c.ftp;
    fp = sf.fingerprint || '';
    box('bkDest', `<div class="seg ntseg" id="bkSeg" role="tablist">${[['local', T('Folder here')], ...BK_DESTS].map(([k, l]) => `<button type="button" role="tab" data-v="${k}" aria-pressed="${k === dTab}" aria-selected="${k === dTab}">${l}${k === 'local' ? '' : pill(k)}</button>`).join('')}</div>
      <div class="form tgform" data-p="local" ${dTab === 'local' ? '' : 'hidden'}>
        <label>${T('Folder')}<input value="${esc(d.dir)}" readonly></label>
        <p class="note" style="margin:0">${T('Always used: the newest backups stay here for a quick restore. {free} free.', {free:fmtB(d.free)})} ${T('Another folder (e.g. a disk mounted from a NAS) is set when installing or upgrading:')} <span class="mono">sudo flowtrack upgrade --force --backup-dir /mnt/nas/flowtrack</span></p></div>
      <div class="form tgform" data-p="s3" ${dTab === 's3' ? '' : 'hidden'}>
        <p class="note" style="margin:0">${T('Amazon S3 or any storage that speaks S3: MinIO, Backblaze B2, Wasabi, Cloudflare R2, Hetzner. Give FlowTrack a key that may only write and read this bucket.')}</p>
        <label class="chk"><input type="checkbox" id="s3On" ${x3.on ? 'checked' : ''}>${T('Copy every backup to S3')}</label>
        <div class="two"><label>${T('Endpoint (empty: Amazon S3)')}<input id="s3Ep" value="${esc(x3.endpoint)}" placeholder="https://s3.eu-central-1.amazonaws.com"></label><label>${T('Region')}<input id="s3Reg" value="${esc(x3.region)}" placeholder="eu-central-1"></label></div>
        <div class="two"><label>${T('Bucket')}<input id="s3Bk" value="${esc(x3.bucket)}"></label><label>${T('Folder in the bucket (optional)')}<input id="s3Pre" value="${esc(x3.prefix)}" placeholder="flowtrack/"></label></div>
        <div class="two"><label>${T('Access key ID')}<input id="s3Key" value="${esc(x3.key_id)}" autocomplete="off"></label><label>${T('Secret access key')}${sec('s3Sec', x3.secret_set)}</label></div>
        ${testRow('s3')}</div>
      <div class="form tgform" data-p="sftp" ${dTab === 'sftp' ? '' : 'hidden'}>
        <p class="note" style="margin:0">${T('Any server with SSH: a NAS (Synology, QNAP, TrueNAS), a Linux box, a hosting account. A key is safer than a password.')}</p>
        <label class="chk"><input type="checkbox" id="sfOn" ${sf.on ? 'checked' : ''}>${T('Copy every backup over SFTP')}</label>
        <div class="two"><label>${T('Server')}<input id="sfHost" value="${esc(sf.host)}" placeholder="backup.example.net"></label><div class="two"><label>${T('Port')}<input id="sfPort" type="number" min="1" max="65535" value="${esc(sf.port)}"></label><label>${T('User')}<input id="sfUser" value="${esc(sf.user)}" autocomplete="off"></label></div></div>
        <div class="two"><label>${T('Sign in with')}<select id="sfAuth"><option value="key" ${sf.auth === 'key' ? 'selected' : ''}>${T('a private key')}</option><option value="password" ${sf.auth === 'password' ? 'selected' : ''}>${T('a password')}</option></select></label>
          <label>${T('Folder on the server')}<input id="sfPath" value="${esc(sf.path)}" placeholder="/backups/flowtrack"></label></div>
        <label data-auth="key">${T('Private key (OpenSSH, without a passphrase)')}<textarea id="sfKey" rows="3" class="mono" placeholder="${sf.key_set ? T('saved — leave empty to keep') : '-----BEGIN OPENSSH PRIVATE KEY-----'}" style="border:1px solid var(--edge);border-radius:10px;padding:8px 12px;background:rgba(0,0,0,.3);color:var(--ink)"></textarea></label>
        <label data-auth="password" hidden>${T('Password')}${sec('sfPass', sf.password_set)}</label>
        <p class="note" style="margin:0" id="sfFp"></p>
        ${testRow('sftp')}</div>
      <div class="form tgform" data-p="ftp" ${dTab === 'ftp' ? '' : 'hidden'}>
        <p class="note" style="margin:0">${T('An FTP server: a NAS, a router with a disk, a hosting account. With TLS (FTPS) the password and the files are encrypted on the way; plain FTP sends them as they are — use it only inside a trusted network.')}</p>
        <label class="chk"><input type="checkbox" id="ftOn" ${ft.on ? 'checked' : ''}>${T('Copy every backup over FTP')}</label>
        <div class="two"><label>${T('Server')}<input id="ftHost" value="${esc(ft.host)}" placeholder="nas.example.lan"></label><div class="two"><label>${T('Port')}<input id="ftPort" type="number" min="1" max="65535" value="${esc(ft.port)}"></label><label>${T('Encryption')}<select id="ftTls"><option value="tls" ${ft.tls ? 'selected' : ''}>${T('TLS (FTPS, explicit)')}</option><option value="none" ${ft.tls ? '' : 'selected'}>${T('none (plain FTP)')}</option></select></label></div></div>
        <label class="chk"><input type="checkbox" id="ftVerify" ${ft.verify ? 'checked' : ''}>${T('Verify the certificate of the server')}</label>
        <div class="two"><label>${T('User')}<input id="ftUser" value="${esc(ft.user)}" autocomplete="off"></label><label>${T('Password')}${sec('ftPass', ft.password_set)}</label></div>
        <label>${T('Folder on the server')}<input id="ftPath" value="${esc(ft.path)}" placeholder="/backups/flowtrack"></label>
        <p class="note" id="ftWarn" style="margin:0;color:var(--warn)" hidden>${T('Plain FTP: anyone on the way sees the login, the password and — without encryption of the copies — the secrets inside them.')}</p>
        ${testRow('ftp')}</div>`);
    const $ = id => document.getElementById(id);
    document.querySelectorAll('#bkSeg [data-v]').forEach(b => b.onclick = () => { state.bkTab = b.dataset.v;
      document.querySelectorAll('#bkSeg [data-v]').forEach(x => { x.setAttribute('aria-pressed', String(x === b)); x.setAttribute('aria-selected', String(x === b)); });
      document.querySelectorAll('#bkDest [data-p]').forEach(p => { p.hidden = p.dataset.p !== b.dataset.v; }); });
    const auth = () => { const a = $('sfAuth').value; document.querySelectorAll('#bkDest [data-auth]').forEach(l => { l.hidden = l.dataset.auth !== a; }); };
    $('sfAuth').onchange = auth; auth();
    const fpNote = () => { $('sfFp').innerHTML = fp ? T('Server key trusted: {fp}. If it changes, copies stop until you test and accept the new one.', {fp:`<span class="mono">${esc(fp)}</span>`}) : T('The first Test shows the key of the server to accept.'); };
    fpNote();
    ['sfHost', 'sfPort'].forEach(id => { $(id).oninput = () => { if ($('sfHost').value.trim() !== sf.host || +$('sfPort').value !== +sf.port) { fp = ''; fpNote(); } else { fp = sf.fingerprint || ''; fpNote(); } }; });
    const sched = () => { const off = !$('bkOn').checked; ['bkTime', 'bkFullSel', 'bkDay'].forEach(id => { $(id).disabled = off; });
      if (!off) $('bkDay').disabled = $('bkFullSel').value !== 'week'; est(); };
    ['bkOn', 'bkFullSel'].forEach(id => { $(id).onchange = sched; }); $('bkKeep').oninput = est; sched();
    const enc = () => { const off = !$('bkEncOn').checked; ['bkPass', 'bkPass2'].forEach(id => { $(id).disabled = off; }); };
    $('bkEncOn').onchange = enc; enc();
    const ftls = () => { const plain = $('ftTls').value === 'none'; $('ftVerify').disabled = plain; $('ftWarn').hidden = !plain; };
    $('ftTls').onchange = ftls; ftls();
    document.querySelectorAll('#bkDest [data-test]').forEach(b => b.onclick = async () => { const k = b.dataset.test, say = document.querySelector(`#bkDest [data-say="${k}"]`);
      const form = collect(); say.textContent = T('Testing…'); say.style.color = ''; b.disabled = true;
      try { const r = await apiPost('backups/test', {kind:k, [k]:form[k]});
        say.style.color = r.ok ? 'var(--ok)' : 'var(--crit)'; say.textContent = r.message;
        if (r.ok && r.fingerprint) { const a = document.createElement('button'); a.className = 'btn'; a.type = 'button'; a.textContent = T('Accept this key');
          a.onclick = () => { fp = r.fingerprint; fpNote(); say.style.color = 'var(--ok)'; say.textContent = T('Accepted — Test again, then Save.'); };
          say.append(' ', a); }
      } catch (e) { say.style.color = 'var(--crit)'; say.textContent = e.message; } finally { b.disabled = false; } });
  };
  const collect = () => { const $ = id => document.getElementById(id), val = id => $(id).value.trim();
    return {schedule:{on:$('bkOn').checked, time:$('bkTime').value || '03:00', full:$('bkFullSel').value, weekday:+$('bkDay').value}, keep_full:+$('bkKeep').value,
      encrypt:{on:$('bkEncOn').checked, passphrase:$('bkPass').value},
      s3:{on:$('s3On').checked, endpoint:val('s3Ep'), region:val('s3Reg'), bucket:val('s3Bk'), prefix:val('s3Pre'), key_id:val('s3Key'), secret:$('s3Sec').value},
      sftp:{on:$('sfOn').checked, host:val('sfHost'), port:+$('sfPort').value || 22, user:val('sfUser'), auth:$('sfAuth').value, path:val('sfPath'), key:$('sfKey').value.trim(), password:$('sfPass').value, fingerprint:fp},
      ftp:{on:$('ftOn').checked, host:val('ftHost'), port:+$('ftPort').value || 21, tls:$('ftTls').value === 'tls', verify:$('ftVerify').checked, user:val('ftUser'), password:$('ftPass').value, path:val('ftPath')}}; };
  document.getElementById('bkSave').onclick = async () => { const a = document.getElementById('bkPass').value, b2 = document.getElementById('bkPass2').value;
    document.getElementById('bkOk').hidden = true;
    if (a !== b2) return formErr('bkErr', T('The passphrases differ'));
    formErr('bkErr', '');
    try { const r = await apiPost('backups/config', collect()); d.config = r.config; d.next = r.next;
      ['bkPass', 'bkPass2', 's3Sec', 'sfKey', 'sfPass', 'ftPass'].forEach(id => { document.getElementById(id).value = ''; });
      forms(); draw(); document.getElementById('bkOk').hidden = false;
    } catch (e) { formErr('bkErr', e.message); } };
  document.getElementById('bkNow').onclick = async () => { formErr('bkErr', '');
    try { await apiPost('backups/run', {full:document.getElementById('bkFull').checked}); d.pending = true; asked = Math.floor(Date.now() / 1000); draw(); poll(); }
    catch (e) { formErr('bkErr', e.message); } };
  // ---- while a backup or a check runs: ask every 2 s; it ends when the service has written its result
  let polling = false;
  const poll = () => { if (polling) return; polling = true;
    const tick = async () => { if (seq !== renderSeq) { polling = false; return; }
      try { const n = await load();
        if (checking) { const v = (n.backups.find(m => m.id === checking) || {}).verified;
          if ((v && v.t >= asked) || Date.now() / 1000 - asked > 900) checking = null; }
        d = {...n, config:d.config}; draw();
        if (n.running || n.pending || checking) { setTimeout(tick, 2000); return; }
      } catch (e) { setTimeout(tick, 5000); return; }
      polling = false; };
    setTimeout(tick, 1500); };
  load().then(n => { if (seq !== renderSeq) return; d = n; forms(); draw(); if (busy()) poll(); })
    .catch(e => { box('bkList', errBox(e)); box('bkDest', ''); });
  every(30000, () => { if (!polling && d) load().then(n => { if (seq === renderSeq) { d = {...n, config:d.config}; draw(); if (busy()) poll(); } }).catch(() => {}); });
}
function vLicense(){
  document.getElementById('setBody').innerHTML = `<div class="grid"><section class="glass panel s12">${ph('shield', T('Edition and license'), T('limits in effect · a FlowTrack Pro license raises them'))}<div id="edBox" class="loading"></div></section>
    ${isAdmin() ? `<section class="glass panel s12">${ph('key', T('Activation'), T('the license is bound to this server · a key or a license file'))}<div id="actBox"></div></section>` : ''}</div>`;
  editionPanel();
}
function vDevices(){
  const v = document.getElementById('setBody'); state.ifEdit = null;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('dev', T('Exporter devices'), T('NetFlow v5/v9 and IPFIX from any vendor · statistics for 15 min'), isAdmin() ? `<button class="btn primary" id="addDev">${T('+ Connect a device')}</button>` : `<span class="nat">${T('an administrator can add devices')}</span>`)}<div id="dBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('ip', T('Interfaces'), T('indexes the collector saw in 24 h · the WAN role defines what is upload and download'))}<div id="ifBox" class="loading"></div></section>
</div>`;
  if (isAdmin()) document.getElementById('addDev').onclick = () => openDevice(null);
  section('dBox', async () => { const res = await api('devices'), d = res.devices; window.__devs = d; window.__snmpTools = res.snmp_tools;
    // the interfaces panel shows one device: the one picked in the table, else the global device filter, else the first
    const df = state.filters.find(f => f.k === 'device' && !f.neg);
    if (!d.some(x => x.ip === state.ifDev)) state.ifDev = (d.find(x => df && x.ip === df.v) || d.find(x => x.interfaces.length) || d[0] || {}).ip;
    setTimeout(() => {
      showIfaces(d);
      document.querySelectorAll('#dBox tr[data-pick]').forEach(tr => tr.onclick = () => { if (tr.dataset.pick === state.ifDev) return; if (state.ifEdit && !confirm(T('Discard unsaved interface changes?'))) return; state.ifEdit = null; state.ifDev = tr.dataset.pick; showIfaces(d); });
      document.querySelectorAll('[data-edit]').forEach(b => b.onclick = e => { e.stopPropagation(); openDevice(d.find(x => x.ip === b.dataset.edit)); });
    });
    return `<div class="tw"><table><thead><tr><th>${T('Status')}</th><th>${T('Device')}</th><th>${T('Vendor / model')}</th><th>${T('Protocol')}</th><th>${T('Site')}</th><th>${T('Export IP')}</th><th class="num">${T('Records/s')}</th><th class="num">${T('Templates')}</th><th>${T('Sampling')}</th><th class="num">${T('Loss')}</th><th class="num">${T('No template')}</th>${isAdmin() ? '<th></th>' : ''}</tr></thead><tbody>
      ${d.map(x => { const never = !x.last, stale = Date.now() / 1000 - x.last > 180, st = never ? 'warn' : stale ? 'crit' : x.loss_pct > 0.5 ? 'warn' : '';
        return `<tr class="click" data-pick="${esc(x.ip)}"><td><span class="dot ${st}" title="${never ? T('has not sent data yet') : stale ? T('no data for over 3 min') : T('online')}"></span></td><td><b class="mono">${esc(x.name)}</b>${x.configured ? '' : ` <span class="tag">${T('not described')}</span>`}${protoPill(x)}${snmpTag(x)}${dupPill(x)}${repeatPill(x)}</td><td>${esc(x.vendor || '—')}<br><span class="nat">${esc(x.model)}</span></td><td><span class="tag">${never ? T('waiting') : esc(x.proto)}</span></td><td>${esc(x.site || '—')}</td><td class="ipl">${esc(x.ip)}</td>
          <td class="num mono">${x.rps}</td><td class="num mono">${x.templates}</td><td class="mono">${esc(x.sampling)}</td><td class="num mono" style="color:${x.loss_pct ? 'var(--warn)' : 'inherit'}">${x.loss_pct}%</td><td class="num mono">${x.no_template}</td>
          ${isAdmin() ? `<td><button class="btn" data-edit="${esc(x.ip)}">${T('Edit')}</button></td>` : ''}</tr>`; }).join('') || `<tr><td colspan="12"><div class="empty">${T('No device has sent data yet')}</div></td></tr>`}</tbody></table></div>${collectorBar(res.collector, res.listen)}<p class="note">${T('Click a row to see the device’s interfaces below. To filter by device, use the device list at the top.')}${isAdmin() ? T(' The collector picks up description changes within a minute.') : ''}</p>`; });
}
// the protocol chosen in the description and the one that arrives differ
const protoPill = x => x.config && x.config.protocol && x.detected && x.config.protocol !== x.detected
  ? ` <span class="pill warn" title="${T('The device sends {got}, while {want} is chosen in its description: change the export on the device, or the protocol in the description.', {got: PROTO_NAME[x.detected] || x.detected, want: PROTO_NAME[x.config.protocol] || x.config.protocol})}">${T('expected {proto}', {proto: PROTO_NAME[x.config.protocol] || x.config.protocol})}</span>` : '';
// duplicates: removed ones (direction field present) or a warning when the exporter reports flows twice
const dupPill = x => x.dup_pct >= 2
  ? ` <span class="pill warn" title="${T('{pct}% of the records in 15 min arrive twice. The device monitors both directions on several interfaces but sends no direction field, so the copies cannot be told apart: add the flow direction field to the exported record, or monitor ingress only.', {pct: x.dup_pct})}">${T('duplicates {pct}%', {pct: x.dup_pct})}</span>`
  : x.dup_dropped ? ` <span class="pill info" title="${T('Copies of flows seen on ingress and again on egress, removed by the collector (15 min)')}">${T('{n} duplicates removed', {n: fmtN(x.dup_dropped)})}</span>` : '';
// whole packets the exporter sent more than once (same content, own sequence counter): dropped by the receiver
const repeatPill = x => x.dup_packets ? ` <span class="pill warn" title="${T('The device sent {n} packets in 15 min a second time with the same content. FlowTrack dropped the copies, so traffic and loss are not affected. The device\'s export is misbehaving: check its NetFlow targets or restart its flow export.', {n: fmtN(x.dup_packets)})}">${T('{n} repeated packets dropped', {n: fmtN(x.dup_packets)})}</span>` : '';
// where devices must send NetFlow: the collector's own interface address when it listens on specific interfaces
// (the web UI may be on another one), otherwise the address this page was opened with
function collectorTarget(){
  const nf = (META.listen || {}).netflow, addrs = nf ? nf.listen.flatMap(x => x.addrs) : [];
  return [addrs.find(a => !a.includes(':')) || addrs[0] || location.hostname, nf ? nf.port : 2055, nf ? nf.sflow_port || nf.port : 6343];
}
const listenText = l => !l ? '—' : l.listen.map(x => x.iface ? x.iface + (x.addrs.length ? ` (${x.addrs.join(', ')})` : '') : x.addrs.join(', ') || T('all interfaces')).join('; ');
// receiver health: workers, socket buffer and every place a packet can be lost on the way to the database
function collectorBar(c, listen){
  const nf = listen && listen.netflow, web = listen && listen.web;
  const where = (nf || web) ? `<div class="collbar-where">${nf ? `<span>${T('NetFlow/IPFIX received on')}: <b class="mono">UDP ${nf.port}${nf.sflow_port ? `, sFlow UDP ${nf.sflow_port}` : ''} · ${esc(listenText(nf))}</b></span>` : ''}${web ? `<span>${T('Web interface')}: <b class="mono">TCP ${web.port} · ${esc(listenText(web))}</b></span>` : ''}</div>` : '';
  if (!c) return where ? `<div class="collbar">${where}</div>` : '';
  const lost = c.socket_drops + c.queue_drops, pct = 100 * lost / Math.max(1, c.packets + lost), fill = c.rcvbuf ? Math.round(100 * c.rx_queue_peak / c.rcvbuf) : 0;
  const cell = (k, v, tip, bad) => `<div title="${esc(tip)}"><span>${k}</span><b class="mono"${bad ? ' style="color:var(--warn)"' : ''}>${v}</b></div>`;
  return `<div class="collbar"><div class="collbar-h"><b>${T('Collector')}</b><span class="nat">${T('last {min} min', {min: c.minutes})}</span></div>
    ${cell(T('Workers'), c.workers, T('Processes that decode packets (FT_WORKERS in /etc/flowtrack/env)'), !c.workers)}
    ${cell(T('Packets received'), c.packets.toLocaleString(LOC), T('Datagrams read from the socket'))}
    ${cell(T('Dropped by socket'), c.socket_drops.toLocaleString(LOC), T('The kernel dropped packets: the socket buffer was full (the collector fell behind or a burst exceeded the buffer)'), c.socket_drops)}
    ${cell(T('Dropped by queue'), c.queue_drops.toLocaleString(LOC), T('The workers could not take packets in time'), c.queue_drops)}
    ${cell(T('Records lost'), c.dropped_rows.toLocaleString(LOC), T('Records that could not be stored: ClickHouse was unavailable for too long'), c.dropped_rows)}
    ${cell(T('Socket buffer'), T('{size} · peak {fill}%', {size: fmtB(c.rcvbuf), fill}), T('Receive buffer size and its highest fill (net.core.rmem_max limits the size)'), fill > 50)}
    ${cell(T('Loss'), (lost ? pct.toFixed(pct < 0.01 ? 3 : 2) : '0') + '%', T('Share of packets the collector did not process'), lost)}${where}</div>`;
}
// generic centered dialog; returns {root, close}
const ROLE_UI = {lan:'LAN', wan:T('WAN (internet)'), local:T('The device itself')};
function showIfaces(devices){
  document.querySelectorAll('#dBox tr[data-pick]').forEach(tr => tr.classList.toggle('picked', tr.dataset.pick === state.ifDev));
  const x = devices.find(d => d.ip === state.ifDev), box = document.getElementById('ifBox'); if (!box) return;
  box.classList.remove('loading');
  if (!x) { box.innerHTML = `<div class="empty">${T('No device has sent data yet')}</div>`; return; }
  box.innerHTML = ifaceTable(x, state.ifEdit === x.ip);
  wireIfaces(box, x, devices);
}
const addrHtml = i => {
  const sa = i.addrs.length ? [] : (i.snmp_addrs || []), known = [...i.addrs, ...sa];
  const own = [...i.addrs.map(a => `<b class="mono">${esc(a)}</b>`), ...sa.map(a => `<span class="mono" title="SNMP">${esc(a)}</span>`)];
  const seen = known.length ? [] : i.seen_addrs;
  const auto = seen.map(a => `<span class="mono nat" title="${a.includes('/') ? T('network that sends traffic into this interface (24 h)') : T('NAT address traffic leaves this interface with (24 h)')}">${esc(a)}</span>`);
  return [...own, ...auto].join('<br>') || '<span class="nat">—</span>';
};
// what the sFlow interface counters of the last minutes say: in / out bit/s (share of the speed), speed, state, errors
const ifCounters = c => { if (!c) return '<span class="nat">—</span>';
  const rate = v => v == null ? '—' : fmtR(v) + (c.speed ? ` <span class="nat">${(100 * v / c.speed).toFixed(v < 0.1 * c.speed ? 1 : 0)}%</span>` : '');
  return `${c.up ? '' : `<span class="tag" title="ifOperStatus">${T('down')}</span> `}<span class="mono" title="${T('average of the last {min} min', {min: c.minutes})}">↓ ${rate(c.in_bps)}<br>↑ ${rate(c.out_bps)}</span>`
    + (c.speed ? `<div class="nat">${T('speed {speed}', {speed: fmtR(c.speed)})}</div>` : '')
    + (c.errors || c.discards ? `<span class="pill warn" title="${T('in the last {min} min, both directions', {min: c.minutes})}">${T('errors {e} · discards {d}', {e: fmtInt(c.errors), d: fmtInt(c.discards)})}</span>` : ''); };
function ifaceTable(x, edit){
  const admin = isAdmin(), total = x.interfaces.reduce((a, i) => a + i.bytes, 0) || 1, counted = x.interfaces.some(i => i.counters);
  // suggest the interface that clearly carries the most internet-facing traffic
  const ranked = [...x.interfaces].filter(i => i.bytes > 0.02 * total).sort((a, b) => b.ext_share - a.ext_share);
  const best = ranked[0] && ranked[0].ext_share >= 0.3 && ranked[0].ext_share >= 3 * ((ranked[1] || {}).ext_share || 0) ? ranked[0].index : null;
  const rows = x.interfaces.map(i => {
    const hint = i.index === best && i.role !== 'wan' ? `<span class="pill info" title="${T('{pct}% of this interface’s traffic is from/to public addresses; much less on the others', {pct: Math.round(i.ext_share * 100)})}">${T('looks like WAN')}</span>` : '';
    const name = edit ? `<input class="ifname" data-idx="${i.index}" value="${esc(i.custom_name)}" placeholder="${esc(i.snmp_name || (i.role === 'local' ? 'local' : 'if ' + i.index))}" maxlength="32" aria-label="${T('Interface {idx} name', {idx: i.index})}">`
                      : `<b class="ipl"${i.snmp_alias ? ` title="${esc(i.snmp_alias)}"` : ''}>${esc(i.name)}</b>${i.snmp_up === false ? ` <span class="tag" title="ifOperStatus">${T('down')}</span>` : ''}${i.snmp_alias && i.snmp_alias !== i.name ? `<div class="nat">${esc(i.snmp_alias)}</div>` : ''}`;
    const role = edit ? `<select class="ifrole" data-idx="${i.index}" aria-label="${T('Interface {idx} role', {idx: i.index})}">${Object.entries(ROLE_UI).map(([k, l]) => `<option value="${k}"${k === i.role ? ' selected' : ''}>${l}</option>`).join('')}</select>`
                      : (i.role === 'wan' ? '<span class="pill warn">WAN</span>' : i.role === 'local' ? `<span class="tag">${T('the device itself')}</span>` : '<span class="tag">LAN</span>');
    const addrs = edit ? `<input class="ifaddr" data-idx="${i.index}" value="${esc(i.addrs.join(', '))}" placeholder="${esc((i.snmp_addrs || []).join(', ') || T('IP or IP/mask, comma-separated'))}" aria-label="${T('Interface {idx} IP addresses', {idx: i.index})}">${i.seen_addrs.length ? `<div class="nat ifseen">${T('in the data')}: ${i.seen_addrs.map(esc).join(', ')}</div>` : ''}`
                       : addrHtml(i);
    const unseen = i.unseen ? ` <span class="pill warn" title="${T('The index is in the settings but did not appear in the data for 24 h — it may be wrong')}">${T('not seen in 24 h')}</span>` : '';
    return `<tr${i.unseen ? ' class="unseen"' : ''}><td class="num mono">${i.index}</td><td>${name}</td><td>${addrs}</td><td>${role} ${hint}${unseen}</td><td class="num mono">${i.unseen ? '—' : fmtB(i.bytes)}</td><td class="num mono">${i.unseen ? '—' : Math.round(i.ext_share * 100) + '%'}</td>${counted ? `<td class="ifcnt">${ifCounters(i.counters)}</td>` : ''}</tr>`;
  }).join('');
  const sn = x.snmp || {}, when = t => new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'});
  const snmpLine = !sn.enabled ? '' : `<div class="ifsnmp">${sn.polled ? (sn.ok ? `<span class="pill ok">SNMP</span> <span class="nat">${esc(sn.sys && sn.sys.name || '')}${sn.sys && sn.sys.name ? ' · ' : ''}${T('{ifs} interfaces, {addrs} addresses · polled {when}', {ifs: sn.interfaces, addrs: sn.addresses, when: when(sn.polled)})}</span>`
      : `<span class="pill warn" title="${esc(sn.detail || '')}">${T('SNMP error')}</span> <span class="nat">${esc(sn.error_text || '')}${sn.last_ok ? ' · ' + T('last good poll {when}', {when: when(sn.last_ok)}) : ''}</span>`)
      : `<span class="pill info">SNMP</span> <span class="nat">${T('waiting for the first poll')}</span>`}${admin && !edit ? ` <button class="btn snmppoll">${T('Poll now')}</button>` : ''}</div>`;
  const btns = !admin || !x.interfaces.length ? '' : edit ? `<span class="nat ifmsg"></span><button class="btn ifcancel">${T('Cancel')}</button><button class="btn primary ifsave" disabled>${T('Save')}</button>`
                                                           : `<span class="nat ifmsg"></span><button class="btn ifedit">${T('Edit')}</button>`;
  return `<div class="ifdev${edit ? ' editing' : ''}" data-dev="${esc(x.ip)}"><div class="ifdev-h"><h4 class="mono">${esc(x.name)} <span class="nat">${esc(x.ip)}${x.vendor ? ' · ' + esc(x.vendor) : ''}</span></h4>${btns}</div>${snmpLine}
    ${x.interfaces.length ? `<div class="tw"><table class="compact"><thead><tr><th class="num">${T('Index')}</th><th>${T('Name')}</th><th>${T('IP addresses')}</th><th>${T('Role')}</th><th class="num">${T('Traffic, 24 h')}</th><th class="num" title="${T('Share of traffic with outside addresses')}">${T('Ext.')}</th>${counted ? `<th title="${T('From the interface counters the device sends with sFlow')}">${T('Load (sFlow counters)')}</th>` : ''}</tr></thead><tbody>${rows}</tbody></table></div>
    <p class="note">${T('Bold: addresses entered by hand; plain: read over SNMP; grey (when neither is known): what the flows of the last 24 h show — the NAT address traffic leaves to the internet with (this is how a WAN usually looks) and the networks that send traffic into the interface. Names and addresses entered by hand take priority over SNMP.')}</p>`
      : `<div class="empty">${T('The collector has not seen interfaces of this device yet (24 h)')}</div>`}</div>`;
}
function wireIfaces(box, x, devices){
  const card = box.querySelector('.ifdev'), msg = card.querySelector('.ifmsg');
  const say = (t, color) => { if (msg) { msg.textContent = t; msg.style.color = color || ''; } };
  const poll = card.querySelector('.snmppoll');
  if (poll) poll.onclick = async () => { poll.disabled = true; poll.textContent = T('Polling…');
    try { await apiPost('devices/snmp_poll', {ip:x.ip}); const fresh = (await api('devices')).devices, i = devices.findIndex(d => d.ip === x.ip), nx = fresh.find(d => d.ip === x.ip);
      if (i >= 0 && nx) devices[i] = nx; META = await fetch('api/meta').then(r => r.json()); showIfaces(devices);
    } catch (e) { poll.disabled = false; poll.textContent = T('Poll now'); say(e.message, 'var(--crit)'); } };
  const edit = card.querySelector('.ifedit'); if (edit) edit.onclick = () => { state.ifEdit = x.ip; showIfaces(devices); const f = box.querySelector('.ifname'); if (f) f.focus(); };
  const cancel = card.querySelector('.ifcancel'); if (cancel) cancel.onclick = () => { state.ifEdit = null; showIfaces(devices); };
  const save = card.querySelector('.ifsave'); if (!save) return;
  card.querySelectorAll('input,select').forEach(el => el.addEventListener('input', () => { save.disabled = false; say(T('unsaved changes'), 'var(--warn)'); }));
  card.addEventListener('keydown', e => { if (e.key === 'Escape') cancel.click(); else if (e.key === 'Enter' && e.target.matches('input') && !save.disabled) save.click(); });
  save.onclick = async () => {
    const roles = [...card.querySelectorAll('.ifrole')], val = (cls, idx) => card.querySelector(`.${cls}[data-idx="${idx}"]`).value.trim();
    if (roles.filter(r => r.value === 'local').length > 1) { say(T('Only one interface can have the role «The device itself»'), 'var(--crit)'); return; }
    const interfaces = roles.map(r => ({index:+r.dataset.idx, role:r.value, name:val('ifname', r.dataset.idx), addrs:val('ifaddr', r.dataset.idx).split(/[\s,;]+/).filter(Boolean)}));
    save.disabled = true; say(T('Saving…'));
    try {
      await apiPost('devices/interfaces', {ip:x.ip, interfaces});
      META = await fetch('api/meta').then(r => r.json());
      const fresh = (await api('devices')).devices, i = devices.findIndex(d => d.ip === x.ip), nx = fresh.find(d => d.ip === x.ip);
      if (i >= 0 && nx) devices[i] = nx;
      state.ifEdit = null; showIfaces(devices);
      const m = document.querySelector('#ifBox .ifmsg'); if (m) { m.textContent = T('Saved · the collector applies roles within a minute'); m.style.color = 'var(--ok)'; }
    } catch (e) { save.disabled = false; say(e.message, 'var(--crit)'); }
  };
}
function openModal(title, sub, body, wide){
  const root = document.getElementById('drawerRoot');
  root.innerHTML = `<div class="scrim" id="scrim"></div><div class="modal glass${wide ? '' : ' narrow'}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <header><div><h3>${esc(title)}</h3>${sub ? `<span class="nat">${sub}</span>` : ''}</div><button class="btn x" id="dx">${T('Close')}</button></header>${body}</div>`;
  const close = () => { root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  document.getElementById('scrim').onclick = close; document.getElementById('dx').onclick = close;
  return {root, close};
}
const formErr = (id, msg) => { const el = document.getElementById(id); if (el) { el.textContent = msg || ''; el.hidden = !msg; } };
function openDevice(dev){
  const c = dev ? dev.config || {} : {}, editing = !!dev, st = (dev && dev.snmp) || {};
  let vendor = VENDOR_LIST().includes(c.vendor) ? c.vendor : c.vendor ? 'Other' : 'Fortinet';
  // the protocol: as described, else what the device sends now, else the vendor's recommended one
  const fitProto = p => vendorProtos(vendor).includes(p) ? p : vendorProtos(vendor)[0];
  let proto = fitProto(c.protocol || (dev && dev.detected) || '');
  const [me, nfPort, sfPort] = collectorTarget();
  // SNMP in the form; the secrets the server keeps never come back (has_* says one is stored: empty = keep it)
  const sn = {enabled:!!st.enabled, version:st.version || '2c', host:st.host || '', port:st.port || 161, community:'', user:st.user || '', level:st.level || 'authPriv',
              auth_proto:st.auth_proto || snmpDefaults(vendor)[0], auth_pass:'', priv_proto:st.priv_proto || snmpDefaults(vendor)[1], priv_pass:''};
  let picked = !!st.auth_proto;           // stored or chosen by hand: a vendor tab no longer resets the protocols
  // the interfaces the device configuration names: ticked from what SNMP found (with SNMP on), else typed by hand
  let ifSel = [...(c.export_ifs || [])], snIfs = st.ok && st.ifs ? st.ifs : null;
  const exportIfs = () => ifSel;
  const pickIfs = () => { if (!ifSel.length && snIfs) ifSel = snIfs.filter(i => i.up && i.addrs.length && !/^(lo|loopback)/i.test(i.name)).map(i => i.name); };
  pickIfs();
  const wanIdx = () => new Set(String((document.getElementById('fWan') || {}).value ?? (c.wan_ifs || []).join(',')).split(',').map(x => parseInt(x, 10)));
  const IF_EXAMPLE = {Fortinet:'wan1, internal', Cisco:'GigabitEthernet0/0/0', MikroTik:'ether1, bridge', Juniper:'ge-0/0/0.0', Huawei:'GigabitEthernet0/0/1',
                      Arista:'Ethernet1', 'HPE Aruba':'1/1/1'};
  const ifBox = () => {
    const list = sn.enabled && snIfs && snIfs.length ? snIfs : null;
    if (!list) return `<label>${T('Interfaces in the configuration (names on the device, comma-separated)')}<input id="fIfsTxt" value="${esc(ifSel.join(', '))}" placeholder="${esc(IF_EXAMPLE[vendor] || 'eth0')}"></label>`
      + (sn.enabled ? `<p class="note">${T('Test SNMP to choose from the interfaces of the device.')}</p>` : '');
    const wan = wanIdx(), have = new Set(list.map(i => i.name));
    const row = (n, i) => `<label class="chk"><input type="checkbox" data-n="${esc(n)}"${ifSel.includes(n) ? ' checked' : ''}> <b class="mono">${esc(n)}</b>`
      + (i && wan.has(i.index) ? ' <span class="tag">WAN</span>' : '') + `<span class="nat"> ${esc(i ? [i.alias, ...i.addrs].filter(Boolean).join(' · ') : T('not on the device'))}${i && !i.up ? ' · ' + T('down') : ''}</span></label>`;
    return `<span class="lbl">${T('Interfaces in the configuration (from SNMP)')}</span><div class="iflist">${list.map(i => row(i.name, i)).join('')}${ifSel.filter(n => !have.has(n)).map(n => row(n, null)).join('')}</div>`;
  };
  const SN_IDS = {sHost:'host', sPort:'port', sComm:'community', sUser:'user', sAuthP:'auth_pass', sPrivP:'priv_pass', sVer:'version', sLevel:'level', sAuth:'auth_proto', sPriv:'priv_proto'};
  const syncSn = () => { const on = document.getElementById('sOn'); if (!on) return; sn.enabled = on.checked;
    Object.entries(SN_IDS).forEach(([id, k]) => { const el = document.getElementById(id); if (el) sn[k] = k.endsWith('pass') || k === 'community' ? el.value : el.value.trim(); }); };
  const code = () => { const rem = ['Cisco', 'Arista', 'HPE Aruba'].includes(vendor) ? '!' : '#';
    const el = document.getElementById('fSamp'), o = {rate: sampleRate(el ? el.value : c.sampling), ifs: exportIfs()}, f = VENDORS[vendor][proto];
    return f(me, proto === 'sflow' ? sfPort : nfPort, o)
      + (o.ifs.length && !f.named ? `\n${rem} ${T('interfaces to watch: {names}', {names: o.ifs.join(', ')})}` : '')
      + (sn.enabled ? `\n\n${rem} ---- SNMP ${sn.version === '3' ? 'v3' : 'v2c'} ----\n` + (SNMP_VENDORS[vendor] || SNMP_VENDORS.Other)(me, sn) : ''); };
  const protoNote = () => !editing || !dev.detected ? '' : dev.detected === proto ? `<span class="nat">${T('the device sends it now')}</span>`
    : `<span class="pill warn">${T('the device sends {proto} now', {proto: PROTO_NAME[dev.detected] || dev.detected})}</span>`;
  const protoSeg = () => `<div class="protos"><span class="nat">${T('Export protocol')}</span><div class="seg" id="protoSeg" role="group">${vendorProtos(vendor).map((p, i) =>
    `<button type="button" data-v="${p}" aria-pressed="${p === proto}"${i ? '' : ` title="${T('recommended for this vendor')}"`}>${PROTO_NAME[p]}${i ? '' : ' ★'}</button>`).join('')}</div> <span id="protoNote">${protoNote()}</span></div>`;
  const opt = (list, cur) => list.map(([k, l]) => `<option value="${esc(k)}"${k === cur ? ' selected' : ''}>${esc(l)}</option>`).join('');
  const kept = T('stored — leave empty to keep');
  const pw = (id, k, label) => `<label>${label}<input id="${id}" type="password" autocomplete="new-password" value="${esc(sn[k])}" placeholder="${st['has_' + k] ? kept : ''}"></label>`;
  const snmpBox = () => `
      <div class="two"><label>${T('Version')}<select id="sVer">${opt([['2c', 'v2c'], ['3', 'v3']], sn.version)}</select></label><label>${T('UDP port')}<input id="sPort" value="${esc(String(sn.port))}" inputmode="numeric"></label></div>
      <label>${T('Address to poll (empty = the export IP)')}<input id="sHost" value="${esc(sn.host)}" placeholder="${esc(editing ? dev.ip : T('the export IP'))}"></label>
      ${sn.version === '3' ? `<div class="two"><label>${T('User')}<input id="sUser" value="${esc(sn.user)}" autocomplete="off"></label><label>${T('Security level')}<select id="sLevel">${opt(Object.entries(SNMP_LEVELS), sn.level)}</select></label></div>
        ${sn.level !== 'noAuthNoPriv' ? `<div class="two"><label>${T('Authentication')}<select id="sAuth">${opt(snmpChoices(vendor, 'auth').map(x => [x, SNMP_LABEL[x] || x]), sn.auth_proto)}</select></label>${pw('sAuthP', 'auth_pass', T('Authentication password'))}</div>` : ''}
        ${sn.level === 'authPriv' ? `<div class="two"><label>${T('Privacy')}<select id="sPriv">${opt(snmpChoices(vendor, 'priv').map(x => [x, SNMP_LABEL[x] || x]), sn.priv_proto)}</select></label>${pw('sPrivP', 'priv_pass', T('Privacy password'))}</div>` : ''}`
        : pw('sComm', 'community', 'Community')}
      <div class="snmptest"><button class="btn" type="button" id="sTest">${T('Test SNMP')}</button><span class="nat" id="sMsg" role="status"></span></div>
      ${window.__snmpTools === false ? `<p class="err">${T('The server has no net-snmp tools (package snmp) yet: run sudo flowtrack upgrade.')}</p>` : ''}
      <p class="note">${T('FlowTrack polls the device when you save and then every hour. Names and addresses entered by hand under Interfaces take priority.')}</p>`;
  let drawIfs = () => {};
  const draw = () => {
    if (!picked) [sn.auth_proto, sn.priv_proto] = snmpDefaults(VENDORS[vendor] ? vendor : 'Fortinet');
    snmpFit(VENDORS[vendor] ? vendor : 'Fortinet', sn);
    const m = openModal(editing ? T('Device {name}', {name: dev.name}) : T('Connect a device'), editing ? esc(dev.ip) : T('Set up export on the device and describe it here'), `
      <div class="vendors" role="group">${VENDOR_LIST().map(k => `<button type="button" data-v="${esc(k)}" aria-pressed="${k === vendor}">${esc(vendorLabel(k))}</button>`).join('')}</div>
      ${protoSeg()}
      <div class="cols"><div><h4>${T('1. Configuration on the device')}</h4><pre class="codebox" id="devCode">${esc(code())}</pre></div>
      <form class="form" id="devForm" autocomplete="off"><h4 style="margin:0">${T('2. Description for FlowTrack')}</h4>
        <div class="two"><label>${T('IP the export comes from')}<input id="fIp" required value="${esc(editing ? dev.ip : '')}" ${editing ? 'readonly' : ''} placeholder="192.0.2.1"></label><label>${T('Name')}<input id="fName" value="${esc(c.name || '')}" placeholder="branch-fw01"></label></div>
        <div class="two"><label>${T('Model')}<input id="fModel" value="${esc(c.model || '')}" placeholder="FortiGate 60F"></label><label>${T('form::Sampling')}<input id="fSamp" value="${esc(c.sampling || '1:1')}"></label></div>
        <p class="note warn" id="fSampNote" hidden></p>
        <div class="two"><label>${T('snmp-index of WAN interfaces (comma-separated)')}<input id="fWan" value="${esc((c.wan_ifs || []).join(', '))}" placeholder="1"></label><label>${T('Index of «the device itself» (FortiOS: 0)')}<input id="fLocal" value="${c.local_if ?? ''}" placeholder="0"></label></div>
        <div id="fIfs">${ifBox()}</div>
        <label>${T('Public IPs of the device (comma-separated)')}<input id="fPub" value="${esc((c.public_ips || []).join(', '))}" placeholder="198.51.100.10"></label>
        <div class="two"><label>${T('City')}<input id="fCity" value="${esc(c.city || '')}" placeholder="Amsterdam"></label><label>${T('Country code')}<input id="fCc" value="${esc(c.country || '')}" maxlength="2" placeholder="NL"></label></div>
        <div class="two"><label>${T('Latitude')}<input id="fLat" value="${c.lat ?? ''}" placeholder="52.37"></label><label>${T('Longitude')}<input id="fLon" value="${c.lon ?? ''}" placeholder="4.90"></label></div>
        <label class="chk"><input type="checkbox" id="sOn"${sn.enabled ? ' checked' : ''}> ${T('Read interface names and IP addresses over SNMP')}</label>
        <div class="snmpbox" id="sBox"${sn.enabled ? '' : ' hidden'}>${snmpBox()}</div>
        <p class="err" id="fErr" hidden></p>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${editing ? T('Save') : T('Add device')}</button>${editing && dev.configured ? `<button class="btn" type="button" id="fDel">${T('Delete description')}</button>` : ''}<span class="nat" id="fDelAsk" hidden>${T('Really delete?')} <button class="btn" type="button" id="fDelYes">${T('Yes, delete')}</button></span></div></form></div>`, true);
    m.root.querySelectorAll('.vendors button').forEach(b => b.onclick = () => { vendor = b.dataset.v; proto = fitProto(proto); keep(); draw(); restore(); redraw(); });
    m.root.querySelectorAll('#protoSeg button').forEach(b => b.onclick = () => { proto = b.dataset.v;
      m.root.querySelectorAll('#protoSeg button').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
      document.getElementById('protoNote').innerHTML = protoNote(); redraw(); });
    const list = id => document.getElementById(id).value.split(',').map(x => x.trim()).filter(Boolean);
    // SNMP: the version, level and checkbox change the fields; every change updates the device configuration
    // a device whose configuration sets no sampling sends every flow: a rate here would multiply its volumes
    const sampNote = () => { const el = document.getElementById('fSampNote'), n = sampleRate(document.getElementById('fSamp').value);
      const show = n > 1 && !VENDORS[vendor][proto].rated; el.hidden = !show;
      el.textContent = show ? T('{vendor} ({proto}) has no sampling setting: it sends every flow. Set 1:1 here — with 1:{n} FlowTrack would multiply its volumes by {n}.', {vendor: vendorLabel(vendor), proto: PROTO_NAME[proto], n}) : ''; };
    const box = document.getElementById('sBox'), redraw = () => { document.getElementById('devCode').textContent = code(); sampNote(); };
    sampNote();
    const wireSnmp = () => {
      box.querySelectorAll('select').forEach(el => el.onchange = () => { if (el.id === 'sAuth' || el.id === 'sPriv') picked = true; syncSn(); box.innerHTML = snmpBox(); wireSnmp(); redraw(); });
      box.querySelectorAll('input').forEach(el => el.oninput = () => { syncSn(); redraw(); });
      document.getElementById('sTest').onclick = async () => { syncSn(); const msg = document.getElementById('sMsg'), ip = document.getElementById('fIp').value.trim();
        if (!ip) { msg.textContent = T('Enter the export IP first'); msg.style.color = 'var(--crit)'; return; }
        msg.textContent = T('Polling…'); msg.style.color = '';
        try { const r = await apiPost('devices/snmp_test', {ip, snmp:sn});
          if (r.ok) { snIfs = r.ifs || []; pickIfs(); drawIfs(); redraw(); msg.textContent = `✓ ${r.sys.name || ''} · ${T('{ifs} interfaces, {addrs} addresses', {ifs: r.interfaces, addrs: r.addresses})}`; msg.style.color = 'var(--ok)'; msg.title = r.sys.descr || ''; }
          else { msg.textContent = r.error_text; msg.style.color = 'var(--crit)'; msg.title = r.detail || ''; }
        } catch (err) { msg.textContent = err.message; msg.style.color = 'var(--crit)'; } };
    };
    const wireIfs = () => { const b = document.getElementById('fIfs');
      b.querySelectorAll('input[type=checkbox]').forEach(el => el.onchange = () => { ifSel = [...b.querySelectorAll('input[type=checkbox]:checked')].map(x => x.dataset.n); redraw(); });
      const t = document.getElementById('fIfsTxt'); if (t) t.oninput = () => { ifSel = t.value.split(',').map(x => x.trim()).filter(Boolean); redraw(); }; };
    drawIfs = () => { document.getElementById('fIfs').innerHTML = ifBox(); wireIfs(); };
    wireSnmp(); wireIfs();
    document.getElementById('fSamp').oninput = redraw;
    document.getElementById('fWan').addEventListener('input', () => drawIfs());
    document.getElementById('sOn').onchange = e => { syncSn(); box.hidden = !e.target.checked; drawIfs(); redraw(); };
    document.getElementById('devForm').addEventListener('submit', async e => { e.preventDefault(); formErr('fErr'); syncSn();
      try {
        await apiPost('devices/save', {ip:document.getElementById('fIp').value.trim(), name:document.getElementById('fName').value, vendor, protocol:proto, model:document.getElementById('fModel').value,
          sampling:document.getElementById('fSamp').value, export_ifs:ifSel, wan_ifs:list('fWan'), local_if:document.getElementById('fLocal').value.trim(), public_ips:list('fPub'),
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
const ROLE_LABEL = {admin:T('Administrator'), viewer:T('Viewer')};
function vUsers(){
  const v = document.getElementById('setBody');
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('users', T('Users'), T('an administrator manages everything; «Viewer» is read-only, no changes to devices or users'), `<button class="btn primary" id="addUser">${T('+ New user')}</button>`)}<div id="uBox" class="loading"></div></section></div>`;
  document.getElementById('addUser').onclick = () => openUser(null);
  section('uBox', async () => { const r = await fetch('api/users'); if (!r.ok) throw new Error((await r.json()).error || r.status); const users = (await r.json()).users;
    setTimeout(() => document.querySelectorAll('[data-user]').forEach(b => b.onclick = () => openUser(users.find(u => u.name === b.dataset.user))));
    const when = t => t ? new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}) : T('never signed in');
    return `<div class="tw"><table><thead><tr><th>${T('Username')}</th><th>${T('Role')}</th><th>${T('Created')}</th><th>${T('Last sign-in')}</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td><b class="mono">${esc(u.name)}</b>${u.name === ME.name ? ` <span class="tag">${T('you')}</span>` : ''}${u.default_password ? ` <span class="pill warn">${T('default password')}</span>` : ''}</td><td>${u.role === 'admin' ? `<span class="pill info">${T('Administrator')}</span>` : `<span class="tag">${T('Viewer')}</span>`}</td>
        <td class="nat">${when(u.created)}</td><td class="nat">${when(u.last_login)}</td><td><button class="btn" data-user="${esc(u.name)}">${T('Edit')}</button></td></tr>`).join('')}</tbody></table></div>`; });
}
function genPassword(){ const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const b = new Uint32Array(14); crypto.getRandomValues(b); return [...b].map(x => a[x % a.length]).join(''); }
function openUser(u){
  const editing = !!u, self = editing && u.name === ME.name;
  const m = openModal(editing ? T('User {name}', {name: u.name}) : T('New user'), '', `<form class="form" id="uForm">
    <label>${T('Username')}<input id="uName" ${editing ? `value="${esc(u.name)}" readonly` : 'required placeholder="olena"'} autocomplete="off"></label>
    <label>${T('Role')}<select id="uRole" ${self ? 'disabled' : ''}><option value="viewer">${T('Viewer — read-only')}</option><option value="admin">${T('Administrator — full access')}</option></select></label>
    <label>${editing ? T('New password (leave empty to keep it)') : T('Password')}<input id="uPass" type="text" autocomplete="new-password" ${editing ? '' : 'required'} minlength="8" placeholder="${T('at least 8 characters')}"></label>
    <button class="lnk" type="button" id="uGen" style="justify-self:start">${T('Generate a password')}</button>
    <p class="err" id="uErr" hidden></p>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${editing ? T('Save') : T('Create')}</button>${editing && !self ? `<button class="btn" type="button" id="uDel">${T('Delete user')}</button><span class="nat" id="uDelAsk" hidden>${T('Sure?')} <button class="btn" type="button" id="uDelYes">${T('Yes, delete')}</button></span>` : ''}</div>
    ${self ? `<p class="note" style="margin:0">${T('Change your own password in the user menu — it asks for the current password.')}</p>` : ''}</form>`);
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
  w.innerHTML = `${ME.default_password ? `<button class="pill warn" id="pwWarn" style="border:0;cursor:pointer" title="${T('Change the default password')}">${T('change password')}</button>` : ''}
    <button class="user" id="userBtn" aria-haspopup="menu" aria-expanded="false"><span class="avatar">${esc(ME.name[0].toUpperCase())}</span><span class="who"><b>${esc(ME.name)}</b><small>${ROLE_LABEL[ME.role]}</small></span></button>
    <div class="menu glass" id="userMenu" role="menu" hidden><button role="menuitem" id="miPass">${T('Change password')}</button>${isAdmin() ? `<button role="menuitem" id="miUsers">${T('Users')}</button>` : ''}<button role="menuitem" id="miOut">${T('Sign out')}</button></div>`;
  const btn = document.getElementById('userBtn'), menu = document.getElementById('userMenu');
  btn.onclick = e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden)); };
  menu.addEventListener('click', () => closeUserMenu());
  document.getElementById('miPass').onclick = openPassword;
  const pw = document.getElementById('pwWarn'); if (pw) pw.onclick = openPassword;
  const mu = document.getElementById('miUsers'); if (mu) mu.onclick = () => { state.view = 'settings'; state.setTab = 'users'; render(); };
  document.getElementById('miOut').onclick = async () => { try { await apiPost('logout', {}); } catch (e) {} ME = null; showLogin(); };
}
function closeUserMenu(){ const m = document.getElementById('userMenu'), b = document.getElementById('userBtn'); if (m) m.hidden = true; if (b) b.setAttribute('aria-expanded', 'false'); }
// one global listener: any click outside the user menu, or Esc, closes it
document.addEventListener('click', e => { if (!e.target.closest || !e.target.closest('#userWrap')) closeUserMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeUserMenu(); });
function openPassword(){
  const m = openModal(T('Change password'), ME.default_password ? T('The default password is in use now') : '', `<form class="form" id="pForm">
    <label>${T('Current password')}<input id="pCur" type="password" required autocomplete="current-password"></label>
    <label>${T('New password')}<input id="pNew" type="password" required minlength="8" autocomplete="new-password" placeholder="${T('at least 8 characters')}"></label>
    <label>${T('Repeat the new password')}<input id="pNew2" type="password" required minlength="8" autocomplete="new-password"></label>
    <p class="err" id="pErr" hidden></p><p class="note" id="pOk" hidden style="color:var(--ok)">${T('Password changed. Other sessions of this user were signed out.')}</p>
    <div><button class="btn primary" type="submit">${T('Change password')}</button></div></form>`);
  document.getElementById('pCur').focus();
  document.getElementById('pForm').addEventListener('submit', async e => { e.preventDefault(); formErr('pErr');
    const n1 = document.getElementById('pNew').value, n2 = document.getElementById('pNew2').value;
    if (n1 !== n2) return formErr('pErr', T('The new passwords do not match'));
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
    <div class="brand" style="padding:0"><svg width="40" height="34" viewBox="0 0 40 34" aria-hidden="true"><path d="M3 10c6-6 11-6 17 0s11 6 17 0" fill="none" stroke="#27D3F5" stroke-width="4.5" stroke-linecap="round"/><path d="M3 22c6-6 11-6 17 0s11 6 17 0" fill="none" stroke="#2F7BFF" stroke-width="4.5" stroke-linecap="round"/></svg><div><b>FlowTrack</b><small>${T('Sign in')}</small></div></div>
    ${msg ? `<p class="note" style="margin:0">${esc(msg)}</p>` : ''}
    <label>${T('Username')}<input id="lUser" required autocomplete="username" autofocus></label>
    <label>${T('Password')}<input id="lPass" type="password" required autocomplete="current-password"></label>
    <p class="err" id="lErr" hidden></p>
    <button class="btn primary" type="submit" style="justify-self:stretch;text-align:center;padding:9px">${T('button::Sign in')}</button></form>`;
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
  root.innerHTML = `<div class="scrim" id="scrim"></div><aside class="drawer glass" role="dialog" aria-modal="true" aria-label="${T('Host')} ${esc(ip)}"><div class="loading" style="min-height:200px"></div></aside>`;
  const close = () => { if (hc) { hc.dispose(); const i = charts.indexOf(hc); if (i >= 0) charts.splice(i, 1); } root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  let hc = null; document.addEventListener('keydown', onKey); document.getElementById('scrim').onclick = close;
  let d; try { d = await api('host', {ip}); } catch (e) { root.querySelector('.drawer').innerHTML = errBox(e); return; }
  const s = d.summary;
  root.querySelector('.drawer').innerHTML = `<header><div><h3>${esc(d.host.name || ip)}</h3><div class="ipl" style="color:var(--ink2)">${esc(ip)} · ${d.host.private ? T('inside address') : T('public address')}</div></div><button class="btn x" id="dx">${T('Close')}</button></header>
    <div class="dk"><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4>${T('Traffic')} · ${rangeLabel()}</h4><div class="chart short" id="cHost"></div></div>
    <div><h4>${T('Services')}</h4><div class="tagrow">${d.services.rows.map(g => `<span class="tag">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>${T('Protocols')}</h4><div class="tagrow">${d.ports.rows.map(g => `<span class="tag mono">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>${T('Where it goes')}</h4><div class="blist">${d.dests.rows.map(g => `<div class="brow" style="cursor:default"><span class="n"><span class="idot ext"></span>${esc(g.k)} <span class="nat">${esc([g.service, g.city || ccName(g.country)].filter(Boolean).join(' · '))}</span></span><span class="t">${fmtB(tot(g))}</span><span class="p"></span></div>`).join('')}</div></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" id="dfilter">${T('Filter everything by this host')}</button></div>`;
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
  document.getElementById('chips').innerHTML = (isCustom() ? `<span class="fchip period"><span class="k">${T('period')}:</span><button class="lnk" id="periodEdit" title="${T('Change the period')}">${esc(rangeLabel())}</button><button aria-label="${T('Back to')} ${esc(presetLabel(state.prevRange))}" title="${T('Back to')}: ${esc(presetLabel(state.prevRange))}" id="periodX">×</button></span>` : '') + state.filters.map((f, i) => `<span class="fchip ${f.neg ? 'neg' : ''}"><span class="k">${FILTER_LABEL[f.k] || f.k}${f.neg ? ' ≠' : ':'}</span>${esc(f.k === 'device' ? devName(f.v) : (f.k === 'in_if' || f.k === 'out_if' || f.k === 'iface') ? (ifLabel(pathDevice(), +f.v) === String(f.v) ? 'if ' + f.v : ifLabel(pathDevice(), +f.v)) : f.v)}<button aria-label="${T('Remove filter')}" data-i="${i}">×</button></span>`).join('')
    + (state.filters.length ? `<button class="lnk" id="clearF">${T('Clear all')}</button>` : '');
  document.querySelectorAll('#chips button[data-i]').forEach(b => b.onclick = () => { state.filters.splice(+b.dataset.i, 1); render(); });
  const cf = document.getElementById('clearF'); if (cf) cf.onclick = () => { state.filters = []; render(); };
  const px = document.getElementById('periodX'); if (px) px.onclick = () => { state.range = state.prevRange || '24h'; render(); };
  const pe = document.getElementById('periodEdit'); if (pe) pe.onclick = openPeriod;
  const ds = document.getElementById('devSel'), df = state.filters.find(f => f.k === 'device' && !f.neg);
  ds.innerHTML = `<option value="">${T('All devices ({n})', {n: META.devices.length})}</option>` + META.devices.map(d => `<option value="${esc(d.ip)}">${esc(d.name)}${d.vendor ? ' · ' + esc(d.vendor) : ''}</option>`).join('');
  ds.value = df ? df.v : '';
  editionBadge();
  const fv = document.getElementById('ftVer'); if (fv && META.version) fv.textContent = 'FlowTrack ' + META.version;
  const rs = document.getElementById('rangeSel');
  rs.querySelectorAll('option[data-x]').forEach(o => o.remove());
  if (isCustom()) rs.insertAdjacentHTML('beforeend', `<option data-x value="custom">${esc(rangeLabel())}</option>`);
  rs.insertAdjacentHTML('beforeend', `<option data-x value="pick">${T('Custom period…')}</option>`);
  rs.value = state.range;
  document.getElementById('trafSel').value = state.traffic;
}
function saveUrl(){ const p = new URLSearchParams({v:state.view, r:state.range}); if (state.view === 'settings') p.set('tab', state.setTab || 'general'); if (isCustom()) { p.set('from', state.from); p.set('to', state.to); } if (state.traffic !== 'internet') p.set('t', state.traffic); if (state.filters.length) p.set('f', JSON.stringify(state.filters)); history.replaceState(null, '', '#' + p); }
function loadUrl(){ try { const p = new URLSearchParams(location.hash.slice(1)); if (p.get('v') === 'devices' || p.get('v') === 'users') { state.view = 'settings'; state.setTab = p.get('v'); } else if (p.get('v') && VIEWS[p.get('v')]) state.view = p.get('v'); if (p.get('tab')) state.setTab = p.get('tab'); if (p.get('r') === 'custom') { const a = +p.get('from'), b = +p.get('to'); if (a > 0 && b - a >= 60) Object.assign(state, {range:'custom', from:a, to:b}); } else if (p.get('r')) state.range = p.get('r'); if (['internet', 'internal', 'all'].includes(p.get('t'))) state.traffic = p.get('t'); if (p.get('f')) { state.filters = []; JSON.parse(p.get('f')).forEach(putFilter); } } catch (e) {} }
function render(){ if (state.view === 'devices' || state.view === 'users') { state.setTab = state.view; state.view = 'settings'; } renderSeq++;
  PAGE_ID = Math.random().toString(36).slice(2, 12);     // a new view: the server cancels what the old one still runs
  PAGE_AC.abort(); PAGE_AC = new AbortController();       // and the browser stops waiting for it
  for (const [k, v] of API_SHARED) if (!v.done) API_SHARED.delete(k);     // nor is a cancelled answer shared with it
  cleanup(); renderShell(); renderUser(); saveUrl(); VIEWS[state.view](); }

document.getElementById('devSel').onchange = e => { state.filters = state.filters.filter(f => f.k !== 'device'); if (e.target.value) putFilter({k:'device', v:e.target.value, neg:false}); render(); };
document.getElementById('rangeSel').onchange = e => { const v = e.target.value; if (v === 'pick') { e.target.value = state.range; openPeriod(); return; } if (v !== 'custom') { state.range = v; render(); } };
const presetLabel = r => ({'1h':T('Last hour'), '6h':T('Last 6 hours'), '24h':T('Last 24 hours'), '7d':T('Last 7 days'), '30d':T('Last 30 days')})[r] || r;
// the custom period dialog: from / to to the minute, within the 30 days of detailed data
function openPeriod(){
  closePeriod();
  const now = Math.floor(Date.now() / 1000), t1 = isCustom() ? state.to : now, t0 = isCustom() ? state.from : now - rangeSecs();
  const loc = t => { const d = new Date(t * 1000 - new Date(t * 1000).getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); };
  const keep = (META.edition || {}).view_days || (META.edition || {}).retention_days || 30, min = loc(now - keep * 86400), max = loc(now + 60);
  const el = document.createElement('div'); el.className = 'glass period-pop'; el.id = 'periodPop'; el.setAttribute('role', 'dialog'); el.setAttribute('aria-label', T('Custom period'));
  el.innerHTML = `<h3>${T('Custom period')}</h3>
    <label>${T('From')}<input type="datetime-local" id="pFrom" step="60" min="${min}" max="${max}" value="${loc(t0)}"></label>
    <label>${T('To')}<input type="datetime-local" id="pTo" step="60" min="${min}" max="${max}" value="${loc(t1)}"></label>
    <div class="quick">${[[15, T('15 min')], [60, T('1 hour')], [240, T('4 hours')]].map(([m, l]) => `<button class="btn" data-m="${m}" title="${T('this long, ending at «To»')}">${l}</button>`).join('')}</div>
    <p class="note" id="pErr" role="alert"></p>
    <p class="note">${T('Detailed data is kept for {keep} days. Tip: drag across any traffic chart to zoom in.', {keep})}</p>
    <div class="acts"><button class="btn" id="pCancel">${T('Cancel')}</button><button class="btn primary" id="pApply">${T('Show')}</button></div>`;
  document.body.appendChild(el);
  const r = document.getElementById('rangeLbl').getBoundingClientRect();
  el.style.top = (r.bottom + 8) + 'px'; el.style.left = Math.max(8, Math.min(r.left, innerWidth - el.offsetWidth - 8)) + 'px';
  const val = id => { const v = document.getElementById(id).value; return v ? Math.floor(new Date(v).getTime() / 1000) : NaN; };
  el.querySelectorAll('[data-m]').forEach(b => b.onclick = () => { const e1 = val('pTo'); if (!isNaN(e1)) document.getElementById('pFrom').value = loc(e1 - b.dataset.m * 60); });
  document.getElementById('pCancel').onclick = closePeriod;
  document.getElementById('pApply').onclick = () => {
    const a = val('pFrom'), b = val('pTo'), err = document.getElementById('pErr');
    if (isNaN(a) || isNaN(b)) { err.textContent = T('Enter both dates.'); return; }
    if (b - a < 60) { err.textContent = T('«To» must be at least a minute after «From».'); return; }
    if (b - a > (keep + 1) * 86400) { err.textContent = T('The period can be at most {days} days long.', {days: keep + 1}); return; }
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
    document.getElementById('collState').textContent = d.length ? (online ? T('Collector online') : T('No data')) : T('Waiting for export');
    document.getElementById('collDot').className = 'dot' + (online ? '' : ' crit');
    document.getElementById('expCount').textContent = Tn(d.length, '{online}/{n} exporter', '{online}/{n} exporters', {online});
    ingHist.push(rps); if (ingHist.length > 40) ingHist.shift();
    document.getElementById('ingV').innerHTML = T('{rps} <small>rec/s</small>', {rps: rps.toFixed(1)});
    document.getElementById('ingM').style.width = Math.max(2, Math.min(100, 100 * rps / 2000)).toFixed(1) + '%';
    const max = Math.max(...ingHist, 1); document.getElementById('ingS').innerHTML = `<polyline points="${ingHist.map((x, i) => `${(i / 39 * 200).toFixed(1)},${(28 - x / max * 24).toFixed(1)}`).join(' ')}" fill="none" stroke="${C.down}" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
    const al = (await fetch('api/alerts').then(r => r.json())).alerts || [];
    document.getElementById('bellBadge').hidden = !al.some(a => a.sev !== 'info');
  } catch (e) { document.getElementById('collState').textContent = T('API unavailable'); document.getElementById('collDot').className = 'dot crit'; }
}

(async () => {
  loadUrl();
  const r = await fetch('api/me').catch(() => null);
  if (!r || r.status === 401) { showLogin(); setInterval(() => ME && health(), 60000); return; }
  ME = await r.json();
  try { META = await fetch('api/meta').then(x => x.json()); } catch (e) {}
  render(); health(); setInterval(() => ME && health(), 60000);
})();
