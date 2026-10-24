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
const FILTER_KEYS = ['ip', 'net', 'dst', 'service', 'l7', 'country', 'city', 'port', 'device', 'asn', 'dir', 'proto', 'in_if', 'out_if', 'iface', 'dscp'];
const FILTER_LABEL = {net:T('network'), iface:T('interface'), dscp:'DSCP', in_if:T('in via'), out_if:T('out via'), ip:T('host'), dst:T('ext. IP'), service:T('service'), l7:T('protocol'), country:T('country'), city:T('city'), port:T('port'), device:T('device'), asn:'ASN', dir:T('direction'), proto:'L4'};
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
  let r; const page = PAGE_ID; waitBegin(page);
  try { r = await fetch(url, {headers:{'X-FT-Tab':TAB_ID, 'X-FT-Page':PAGE_ID}, signal:PAGE_AC.signal}); }
  catch (e) { if (e.name === 'AbortError') return NEVER(); throw e; }
  finally { waitEnd(page); }
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
// add=true (typed in the search box, 1.8.3): a positive filter joins the others of its key — any of them matches
// (device A or device B); a click on a chart or a table still replaces it
function putFilter(f, add){
  const k = f.k, v = String(f.v), neg = !!f.neg;
  if (!FILTER_KEYS.includes(k) || !v) return;
  state.filters = state.filters.filter(x => !(x.k === k && (x.v === v || (!add && !neg && !x.neg))));
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
  axisLabel:{color:C.ink3, fontFamily:'JetBrains Mono', fontSize:11, hideOverlap:true,
    // (1.16.1) a period of 1–4 days has ticks within a day: the date alone repeated itself (20/10, 20/10 …)
    formatter:v => rangeSecs() > 4 * 86400 ? dmy(v / 1000) : rangeSecs() > 86400 ? `${dmy(v / 1000)} ${hhmm(v / 1000)}` : hhmm(v / 1000)}});
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
  const grow = !!el.closest('.wsettle') && !REDUCED.matches;      // (1.8.7) after a wait the ring fills round once
  c.setOption({animation:grow, animationType:'expansion', animationDuration:900, animationEasing:'cubicOut', tooltip:{...tipBase(), formatter:p => `${esc(p.name)}<br><b>${fmtB(p.value)}</b> · ${p.percent}%`},
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
  const {onSelect, fetchData, refreshMs} = opts;
  // (1.8.9) compact in a panel, full-size cards when its panel is full screen; fitTop(H, compact): as many pairs as the
  // height holds — asked again (debounced) when the size changes the number
  let compact = opts.compact, top = null, refit = 0;
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
    try { data = await fetchData(top); } catch (e) { host.querySelector('.rtip').hidden = true; return; }
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
  if (!opts.fitTop) load();
  if (refreshMs) every(refreshMs, () => { if (top !== null || !opts.fitTop) load(); });
  function size(){ kick(); const r = host.getBoundingClientRect(); W = r.width; H = r.height; dpr = Math.min(2, devicePixelRatio || 1); cv.width = W * dpr; cv.height = H * dpr;
    compact = opts.compact && !host.closest('section.is-max');
    if (opts.fitTop && H > 0) { const want = opts.fitTop(H, compact);
      if (want !== top) { const firstFit = top === null; top = want; clearTimeout(refit); if (firstFit) load(); else refit = setTimeout(load, 300); } } }
  const ro = new ResizeObserver(size); ro.observe(host); size(); onCleanup(() => { ro.disconnect(); clearTimeout(refit); });
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
// (1.16.0) stacked classes
const QOS_ICON = 'M3 14h12M3 10h9M3 6h6M13 4l2 2-2 2';
// (1.15.0) bars of a period
const USAGE_ICON = 'M3 15V9M7 15V5M11 15V8M15 15V3M2 15.5h14';
// (1.13.0) a gauge
const CAP_ICON = 'M2.5 13.5a6.5 6.5 0 1 1 13 0M9 13.5l3.2-4.2M4.6 9.6l.9.6M13.4 9.6l-.9.6M9 7v1';
const NAV = [
  ['overview',T('Overview'),'M3 9.5L9 4l6 5.5V15H3z'], ['flows',T('Flows'),'M2 6c4 0 5 6 9 6h5M2 12c4 0 5-6 9-6h5'], ['paths',T('Through device'),'M2 4h4M2 9h4M2 14h4M12 4h4M12 9h4M12 14h4M6 4c3 0 3 10 6 10M6 14c3 0 3-10 6-10M6 9h6'], ['network',T('Path analysis'),'M6.9 4a2.1 2.1 0 1 0 4.2 0a2.1 2.1 0 1 0 -4.2 0M1.9 14a2.1 2.1 0 1 0 4.2 0a2.1 2.1 0 1 0 -4.2 0M11.9 14a2.1 2.1 0 1 0 4.2 0a2.1 2.1 0 1 0 -4.2 0M7.57 6.86L5.43 11.14M10.43 6.86L12.57 11.14M7.2 14L10.8 14'], ['talkers',T('Top hosts'),'M4 6a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0 -5 0M2 15.5c0-2.8 2-4.5 4.5-4.5s4.5 1.7 4.5 4.5M11 7a2 2 0 1 0 4 0a2 2 0 1 0 -4 0M12.6 11.2c.4-.1.9-.2 1.4-.2 1.9 0 3 1.5 3 4'],
  ['usage',T('Usage'),USAGE_ICON], ['apps',T('Services'),'M3 3h5v5H3zM10 3h5v5h-5zM3 10h5v5H3zM10 10h5v5h-5z'], ['ports',T('Ports'),'M6 2v4M12 2v4M4 6h10v3a5 5 0 0 1-10 0zM9 14v3'], ['geo',T('Geolocation'),'M9 16.2s5.2-4.6 5.2-8.7A5.2 5.2 0 0 0 3.8 7.5c0 4.1 5.2 8.7 5.2 8.7zM7.2 7.4a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0 -3.6 0'],
  ['capacity',T('page::Capacity'),CAP_ICON], ['qos',T('QoS'),QOS_ICON],
  ['threats',T('Events'),'M9 2l6 2.5V9c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V4.5z'],
  ['settings',T('Settings'),'M14.29 7.93L16.15 8.14L16.15 9.86L14.29 10.07L13.5 11.98L14.66 13.45L13.45 14.66L11.98 13.5L10.07 14.29L9.86 16.15L8.14 16.15L7.93 14.29L6.02 13.5L4.55 14.66L3.34 13.45L4.5 11.98L3.71 10.07L1.85 9.86L1.85 8.14L3.71 7.93L4.5 6.02L3.34 4.55L4.55 3.34L6.02 4.5L7.93 3.71L8.14 1.85L9.86 1.85L10.07 3.71L11.98 4.5L13.45 3.34L14.66 4.55L13.5 6.02zM6.7 9a2.3 2.3 0 1 0 4.6 0a2.3 2.3 0 1 0 -4.6 0'],
];
const DEV_ICON = 'M2 5h14v6H2zM5 8h.01M8 8h.01M6 14h6', USER_ICON = 'M4 6.5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0 -5 0M2 15.5c0-2.8 2-4.5 4.5-4.5s4.5 1.7 4.5 4.5M12.5 5h4M14.5 3v4';
const navIcon = k => (NAV.find(n => n[0] === k) || [])[2];
const icon = (d, s = 18) => `<svg width="${s}" height="${s}" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${d}"/></svg>`;
const ICO = {pulse:'M2 9h3l2-5 3 10 2-5h4', nodes:'M6.9 4a2.1 2.1 0 1 0 4.2 0a2.1 2.1 0 1 0 -4.2 0M1.9 14a2.1 2.1 0 1 0 4.2 0a2.1 2.1 0 1 0 -4.2 0M11.9 14a2.1 2.1 0 1 0 4.2 0a2.1 2.1 0 1 0 -4.2 0M7.57 6.86L5.43 11.14M10.43 6.86L12.57 11.14', ip:'M3 5h12v6H3zM6 14h6M7 8h.01M10 8h.01', grid:navIcon('apps'), flow:navIcon('flows'),
  globe:'M9 2a7 7 0 1 0 0 14A7 7 0 0 0 9 2zM2 9h14M9 2c2.5 2.5 2.5 11.5 0 14M9 2c-2.5 2.5-2.5 11.5 0 14', chart:'M2 15l4-6 3 3 5-8 2 2', conv:'M3 5h8l-2-2M15 13H7l2 2', list:'M3 5h12M3 9h12M3 13h8',
  users:navIcon('talkers'), key:'M12 3a3 3 0 1 0 .01 0M9.9 8.1L3 15M5 13l2 2M7 11l2 2', shield:navIcon('threats'), dev:DEV_ICON, pie:'M9 2v7h7A7 7 0 1 1 9 2z', search:'M8 8m-5 0a5 5 0 1 0 10 0a5 5 0 1 0-10 0M12 12l4 4'};
const ph = (ic, title, sub, right = '', big = false, tools = '') => `<div class="ph"><div class="ttl"><span class="ico">${icon(ICO[ic] || ic)}</span><div><h2${big ? ' class="big"' : ''}>${title}${tools}</h2>${sub ? `<span class="sub">${sub}</span>` : ''}</div></div>${right ? `<div class="right">${right}</div>` : ''}</div>`;
// (1.8.8) a panel of the Overview opens full screen: the browser's own (Esc leaves it), or, where a page cannot have
// it (iPhone), over the whole window; the charts and the map follow the size by themselves (ResizeObserver)
const MAX_IN = 'M2 6.5V2h4.5M11.5 2H16v4.5M16 11.5V16h-4.5M6.5 16H2v-4.5', MAX_OUT = 'M6.5 2v4.5H2M16 6.5h-4.5V2M11.5 16v-4.5H16M2 11.5h4.5V16';
const maxBtn = () => `<button type="button" class="maxbtn" data-max title="${T('Full screen')}" aria-label="${T('Full screen')}">${icon(MAX_IN, 14)}</button>`;
function maxMark(){ document.querySelectorAll('[data-max]').forEach(b => { const on = b.closest('section').classList.contains('is-max');
  b.innerHTML = icon(on ? MAX_OUT : MAX_IN, 14); b.title = on ? T('Leave full screen') : T('Full screen'); b.setAttribute('aria-label', b.title); b.setAttribute('aria-pressed', String(on)); }); }
function maxToggle(sec){
  if (sec.classList.contains('is-max')) { sec.classList.remove('is-max'); if (document.fullscreenElement) document.exitFullscreen().catch(() => {}); maxMark(); if (sec._reload) sec._reload(); return; }
  document.querySelectorAll('section.is-max').forEach(x => { x.classList.remove('is-max'); if (x._reload) x._reload(); });
  sec.classList.add('is-max'); maxMark(); if (sec._reload) sec._reload();      // (1.8.9) a list: more rows
  if (sec.requestFullscreen) sec.requestFullscreen().catch(() => {});      // refused: it stays over the window
}
document.addEventListener('click', e => { const b = e.target.closest('[data-max]'); if (b) maxToggle(b.closest('section')); });
function maxLeave(){ const x = document.querySelector('section.is-max'); if (x) maxToggle(x); }
document.addEventListener('fullscreenchange', () => { if (!document.fullscreenElement) { document.querySelectorAll('section.is-max').forEach(x => { x.classList.remove('is-max'); if (x._reload) x._reload(); }); maxMark(); } });
document.addEventListener('keydown', e => { if (e.key !== 'Escape') return; const x = document.querySelector('section.is-max'); if (x) maxToggle(x); });
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
const fill = (id, html) => { const el = document.getElementById(id); if (el) { const was = el.classList.contains('wshow'); el.innerHTML = html; if (was) wSettle(el); } return el; };
// (1.8.7) the answer after a wait fills in as in the waiting mock-up: the rows settle one after another, the bars grow
// to their value, a ring fills round (donut()); once — a later refresh of the same box just replaces it
const W_SETTLE_ROWS = 'tbody tr, .blist > .brow, .pbars > span, .dl > button, .dl > span:not(.p):not(.t), .wleg > div, .rows > *';
function wSettle(el){
  el.classList.remove('wshow', 'wfade'); delete el.dataset.w;
  if (REDUCED.matches) return;
  el.querySelectorAll(W_SETTLE_ROWS).forEach((r, i) => r.style.setProperty('--wi', Math.min(i, 14)));
  el.querySelectorAll('.pbars > .vbar, .pbars > b').forEach(b => { const w = b.previousElementSibling && b.previousElementSibling.style.getPropertyValue('--wi'); if (w) b.style.setProperty('--wi', w); });
  el.classList.add('wsettle'); clearTimeout(el._ws); el._ws = setTimeout(() => el.classList.remove('wsettle'), 1800);
}
// ===================== waiting (1.8.5): what a page shows while the server reads the data =====================
// Tables "decode" (characters cycle until the answer), pie charts spin a ring with the share read, the big maps draw a
// sketch of what is coming (Through device: the device and its interfaces, lines growing; Path analysis: the devices
// and links assembling). A pill at the bottom says how far the database is (rows read of rows to read, from
// system.processes) and cancels. Nothing shows for the first 0.4 s; one 30 fps canvas at most; stops when hidden.
const WAIT = {n:0, since:0, page:null, prog:null, poll:0, tick:0, cancelled:false};
const REDUCED = matchMedia('(prefers-reduced-motion: reduce)');
const RING_IDS = new Set(['svcBox', 'protoBox', 'pBox', 'pL7', 'tDonut']);
function waitBegin(page){ if (page !== PAGE_ID) return; if (!WAIT.n++) { WAIT.since = Date.now(); WAIT.page = page; WAIT.prog = null; WAIT.cancelled = false; } waitKick(); }
function waitEnd(page){ if (page !== WAIT.page) return; WAIT.n = Math.max(0, WAIT.n - 1); if (!WAIT.n) waitPill(); }
function waitReset(){ WAIT.n = 0; WAIT.page = PAGE_ID; WAIT.prog = null; WAIT.cancelled = false; waitPill(); }     // a new page: the old requests no longer count
function waitKick(){
  if (!WAIT.poll) WAIT.poll = setInterval(waitPoll, 700);
  if (!WAIT.tick) WAIT.tick = setInterval(waitTick, 90);
}
async function waitPoll(){
  if (!WAIT.n) { if (!document.querySelector('#view .loading, #view .wbig')) { clearInterval(WAIT.poll); WAIT.poll = 0; } return; }
  if (document.hidden || Date.now() - WAIT.since < 400) return;
  try { const r = await fetch('api/progress', {headers:{'X-FT-Tab':TAB_ID, 'X-FT-Page':PAGE_ID}}); if (r.ok) { const d = await r.json(); if (d.n) WAIT.prog = {...d, t:Date.now()}; } } catch (e) {}
  waitPill();
}
const fmtRows = n => n >= 1e6 ? T('{n} M', {n:(n / 1e6).toLocaleString(LOC, {maximumFractionDigits:1})}) : n.toLocaleString(LOC);
function waitText(){ const p = WAIT.prog; if (!p) return T('Reading the data…');
  if (p.total > p.rows && p.rows > 0) { const left = p.secs * (p.total - p.rows) / p.rows;
    return T('Read {a} of {b} records · {p}%', {a:fmtRows(p.rows), b:fmtRows(p.total), p:Math.floor(100 * p.rows / p.total)}) + (left >= 1 ? ' · ' + T('~{s} s left', {s:Math.ceil(left)}) : ''); }
  return T('Read {a} records · {s} s', {a:fmtRows(p.rows), s:Math.round(p.secs)}); }
const waitShare = () => { const p = WAIT.prog; return p && p.total ? Math.min(1, p.rows / p.total) : 0; };
// the pill: shown while something is read for more than 1.5 s
function waitPill(){
  let el = document.getElementById('waitPill');
  const on = WAIT.n > 0 && Date.now() - WAIT.since > 1500 && !WAIT.cancelled;
  if (WAIT.cancelled) return;                 // the pill says "Cancelled" until the next page
  if (!on) { if (el) el.hidden = true; return; }
  if (!el) { el = document.createElement('div'); el.id = 'waitPill'; el.className = 'glass waitpill'; el.setAttribute('role', 'status');
    el.innerHTML = '<span class="wpbar"><i></i></span><span class="wptxt"></span><button class="btn" type="button"></button>'; document.body.append(el);
    el.querySelector('button').onclick = waitCancel; }
  el.hidden = false; el.querySelector('.wpbar').hidden = false; el.querySelector('.wptxt').textContent = waitText();
  const btn = el.querySelector('button'); btn.textContent = T('Cancel'); btn.onclick = waitCancel;
  const sh = waitShare(); el.querySelector('.wpbar i').style.transform = `scaleX(${sh || 0.04})`; el.classList.toggle('indet', !sh);
}
async function waitCancel(){
  WAIT.cancelled = true;
  try { await fetch('api/cancel', {method:'POST', headers:{'Content-Type':'application/json', 'X-FT-Tab':TAB_ID, 'X-FT-Page':PAGE_ID}, body:'{}'}); } catch (e) {}
  PAGE_AC.abort(); PAGE_AC = new AbortController(); WAIT.n = 0;
  // the boxes say so in a word; the pill explains once and offers to ask again
  const msg = `<div class="empty wcancel">${T('Cancelled')}</div>`;
  document.querySelectorAll('#view .loading').forEach(el => { el.classList.remove('loading', 'wshow'); el.innerHTML = msg; });
  document.querySelectorAll('#view .wbig').forEach(el => { const h = el.parentElement; el.remove(); if (h) h.insertAdjacentHTML('beforeend', `<div class="wover">${msg}</div>`); });
  const el = document.getElementById('waitPill');
  if (el) { el.hidden = false; el.classList.remove('indet'); el.querySelector('.wpbar').hidden = true; el.querySelector('.wptxt').textContent = T('Cancelled. A shorter period or a filter makes it faster.');
    const b = el.querySelector('button'); b.textContent = T('Try again'); b.onclick = () => render(); }
}
// the small panels: a decoding table or a spinning ring, put into each empty .loading box
const W_AZ = 'ABCDEFGHKLMNPQRSTUVWXYZ';
const wScr = tpl => tpl.replace(/[0-9]/g, () => String(Math.floor(Math.random() * 10))).replace(/[A-Za-z]/g, () => W_AZ[Math.floor(Math.random() * W_AZ.length)]);
const W_ROWS = ['443|TCP·HTTPS|106 GB', '61000|UDP·QUIC|84.1 GB', '53|UDP·DNS|43.6 GB', '8443|TCP·MGMT|15.8 GB', '51820|UDP·WG|9.73 GB', '80|TCP·HTTP|8.38 GB'];
function waitFill(el){
  if (el.dataset.w || el.children.length) return;
  el.dataset.w = '1';
  if (RING_IDS.has(el.id)) { el.innerHTML = `<div class="wring" aria-hidden="true"><div class="wr"><b>0%</b></div><div class="wleg">${[0, 1, 2, 3, 4].map(i => `<div><i style="background:${PAL[i]}"></i><span data-s="PROTOCOL"></span><span data-s="00%"></span></div>`).join('')}</div></div>`; return; }
  // a KPI tile: one number; any other box is a table to come (an empty box is low, so its height says nothing)
  if (el.classList.contains('kcard')) { el.innerHTML = `<div class="wdec wone" aria-hidden="true"><span class="wval" data-s="${['128.4 GB', '2 417', '96.1 Mbit/s', '35 812'][Math.floor(Math.random() * 4)]}"></span></div>`; return; }   // a KPI tile: one number
  const hgt = el.getBoundingClientRect().height, n = hgt > 200 ? Math.min(8, Math.floor(hgt / 30)) : 6;
  el.innerHTML = `<div class="wdec" aria-hidden="true"><i class="wscan"></i>${W_ROWS.concat(W_ROWS).slice(0, n).map((r, i) => { const [a, b, c] = r.split('|');
    return `<div class="wrow"><span data-s="${a}"></span><span class="tag" data-s="${b}"></span><span class="vb"><i style="transform:scaleX(${(0.9 - i * 0.12).toFixed(2)})"></i></span><span class="num" data-s="${c}"></span></div>`; }).join('')}</div>`;
}
function waitTick(){
  const boxes = document.querySelectorAll('#view .loading');
  if (!boxes.length && !document.querySelector('#view .wbig')) { clearInterval(WAIT.tick); WAIT.tick = 0; return; }
  if (document.hidden) return;
  const shown = Date.now() - WAIT.since > 400 || !WAIT.n;
  boxes.forEach(el => { waitFill(el); el.classList.toggle('wshow', shown); });
  if (REDUCED.matches) return;
  document.querySelectorAll('#view .loading [data-s]').forEach(x => { x.textContent = wScr(x.dataset.s); });
  document.querySelectorAll('#view .loading .vb i').forEach(x => { if (Math.random() < 0.1) x.style.transform = `scaleX(${(0.15 + Math.random() * 0.8).toFixed(2)})`; });
  const pc = Math.round(100 * waitShare()) + '%'; document.querySelectorAll('#view .wring .wr b').forEach(b => { b.textContent = pc; });
  waitPill();
}
// the big maps: a canvas sketch over the map box until its first answer; stop() takes it away
function waitBig(host, kind, sketch){
  const box = document.createElement('div'); box.className = 'wbig'; box.innerHTML = '<canvas aria-hidden="true"></canvas>'; host.append(box);
  const cv = box.querySelector('canvas'); let ctx = cv.getContext('2d'), W = 0, H = 0, DPR = 1, raf = 0, last = 0, t0 = performance.now(), S = null, alive = true;
  const C2 = {blue:'#4C93FF', down:C.down, up:C.up, int:C.int, ext:C.ext, ink2:'#A9B7D9'};
  const spr = {}; const sprite = col => { if (spr[col]) return spr[col]; const c = document.createElement('canvas'), n = 32; c.width = c.height = n; const g = c.getContext('2d');
    const gr = g.createRadialGradient(n / 2, n / 2, 0, n / 2, n / 2, n / 2); gr.addColorStop(0, '#ffffff'); gr.addColorStop(0.18, col); gr.addColorStop(0.45, col + '55'); gr.addColorStop(1, col + '00');
    g.fillStyle = gr; g.fillRect(0, 0, n, n); return (spr[col] = c); };
  const glow = (x, y, r, col, a) => { ctx.globalAlpha = a; const d = r * 5; ctx.drawImage(sprite(col), x - d / 2, y - d / 2, d, d); };
  const bez = (p0, p1, p2, p3, t) => { const u = 1 - t; return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3; };
  const ease = t => t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2;
  const part = (l, t) => { const mx = (l.x0 + l.x1) / 2, P = [[l.x0, l.y0], [mx, l.y0], [mx, l.y1], [l.x1, l.y1]], L = (a, b) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
    const p01 = L(P[0], P[1]), p12 = L(P[1], P[2]), p23 = L(P[2], P[3]), p012 = L(p01, p12), p123 = L(p12, p23), e = L(p012, p123);
    ctx.beginPath(); ctx.moveTo(l.x0, l.y0); ctx.bezierCurveTo(p01[0], p01[1], p012[0], p012[1], e[0], e[1]); ctx.stroke(); return e; };
  const along = (pts, t) => { const n = pts.length / 2 - 1, f = Math.min(n - 1e-6, t * n), i = Math.floor(f), u = f - i, x0 = pts[i * 2], y0 = pts[i * 2 + 1], x1 = pts[i * 2 + 2], y1 = pts[i * 2 + 3], mx = (x0 + x1) / 2;
    return [bez(x0, mx, mx, x1, u), bez(y0, y0, y1, y1, u)]; };
  function size(){ const r = box.getBoundingClientRect(); if (!r.width) return; DPR = Math.min(1.5, devicePixelRatio || 1); W = r.width; H = r.height;
    cv.width = Math.round(W * DPR); cv.height = Math.round(H * DPR); ctx.setTransform(DPR, 0, 0, DPR, 0, 0); S = sketch.layout(W, H); S.bg = null; S.lines.forEach(l => { l.t0 = 0; l.k = 0; }); S.t0 = performance.now(); }
  const ro = new ResizeObserver(() => { size(); go(); }); ro.observe(box);
  function frame(now){
    raf = 0; if (!alive || !S) return;
    if (now - last >= 32) { last = now;
      const T0 = now / 1000, dt = 1 / 30, P = Math.max(Math.min(1, (now - S.t0) / 9000), waitShare());     // the share read, or a slow clock when the server has no estimate
      let done = 0;
      S.lines.forEach(l => { if (!l.t0 && P >= l.at) l.t0 = T0; l.k = l.t0 ? (REDUCED.matches ? 1 : ease(Math.min(1, (T0 - l.t0) / 0.8))) : 0; if (l.k >= 1) done++; });
      if (!S.bg || S.bgKey !== done) { const c = S.bg || document.createElement('canvas'); c.width = cv.width; c.height = cv.height; const g = c.getContext('2d'); g.setTransform(DPR, 0, 0, DPR, 0, 0);
        const real = ctx; ctx = g; sketch.still(ctx, S, (l) => { ctx.globalAlpha = l.a; part(l, 1); }); ctx = real; S.bg = c; S.bgKey = done; }
      ctx.clearRect(0, 0, W, H); ctx.globalAlpha = 1; ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.drawImage(S.bg, 0, 0); ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      ctx.lineWidth = 1.4; ctx.lineCap = 'round'; ctx.strokeStyle = C2.blue;
      S.lines.forEach(l => { if (!l.k || l.k >= 1) return; ctx.globalAlpha = l.a + 0.15; const e = part(l, l.k); ctx.globalCompositeOperation = 'lighter'; glow(e[0], e[1], 2.4, C2.blue, 0.9); ctx.globalCompositeOperation = 'source-over'; });
      // packets on finished routes
      const routes = S.routes.filter(r => r.lines.every(l => l.k >= 1));
      ctx.globalCompositeOperation = 'lighter';
      S.pk.forEach(q => { if (!q.r) { if (!routes.length) return; q.r = routes[Math.floor(Math.random() * routes.length)]; q.s = -Math.random() * 0.5; q.up = Math.random() < 0.55; }
        q.s += REDUCED.matches ? 0 : q.v * dt; if (q.s >= 1) { q.r = null; return; } if (q.s < 0) return;
        const pts = q.up ? q.r.pts : q.r.back, [x, y] = along(pts, q.s); glow(x, y, 2.3, q.up ? C2.up : C2.down, 0.95); });
      ctx.globalCompositeOperation = 'source-over'; ctx.globalAlpha = 1;
    }
    if (!REDUCED.matches) go();       // reduced motion: one still picture
  }
  function go(){ if (alive && !raf && !document.hidden) raf = requestAnimationFrame(frame); }
  setTimeout(() => { if (alive) box.classList.add('wshow'); }, 400);
  const vis = () => go(); document.addEventListener('visibilitychange', vis);
  const stop = () => { if (!alive) return; alive = false; ro.disconnect(); document.removeEventListener('visibilitychange', vis); cancelAnimationFrame(raf);
    box.classList.add('wgone'); setTimeout(() => box.remove(), 350); };
  onCleanup(stop);
  return {stop};
}
// Through device: the device and its interfaces are known before the answer; the hosts are dots; lines grow host ->
// interface -> through the device -> interface -> address
function sketchDevice(dev, ifs){
  const named = [...ifs.values()].filter(i => i.role !== 'local').slice(0, 12);
  const wan = named.filter(i => i.role === 'wan'), lan = named.filter(i => i.role !== 'wan');
  const L = (lan.length ? lan : named.slice(0, Math.ceil(named.length / 2))).slice(0, 6), R = (wan.length ? wan : named.slice(L.length)).slice(0, 6);
  const nm = i => i.custom_name || i.name || `if ${i.index}`;
  return {
    layout(W, H){
      const bx = W * 0.36, bw = W * 0.28, by = H * 0.1, bh = H * 0.8;
      const ports = [...(L.length ? L : [{name:'LAN'}]).map((x, k, a) => ({n:nm(x), side:'L', x:bx, y:by + bh * (k + 1) / (a.length + 1)})),
        ...(R.length ? R : [{name:'WAN'}]).map((x, k, a) => ({n:nm(x), side:'R', x:bx + bw, y:by + bh * (k + 1) / (a.length + 1)}))];
      const nl = ports.filter(p => p.side === 'L'), nr = ports.filter(p => p.side === 'R');
      const hosts = (side, list) => Array.from({length:7}, (_, k) => ({x:side === 'L' ? W * 0.06 : W * 0.94, y:H * (0.1 + 0.8 * k / 6), p:list[Math.floor(k / 7 * list.length)]}));
      const hl = hosts('L', nl), hr = hosts('R', nr), lines = [];
      hl.forEach((h, k) => { h.line = {x0:h.x, y0:h.y, x1:h.p.x, y1:h.p.y, a:0.24, at:0.02 + k * 0.04}; lines.push(h.line); });
      const links = []; nl.forEach((a, k) => { const b = nr[k % nr.length]; links.push({a, b}); if (nr.length > 1 && k < 2) links.push({a, b:nr[(k + 1) % nr.length]}); });
      links.forEach((l, k) => { l.line = {x0:l.a.x, y0:l.a.y, x1:l.b.x, y1:l.b.y, a:0.45, at:0.3 + k * 0.05}; lines.push(l.line); });
      hr.forEach((h, k) => { h.line = {x0:h.p.x, y0:h.p.y, x1:h.x, y1:h.y, a:0.24, at:0.55 + k * 0.04}; lines.push(h.line); });
      const routes = [];
      links.forEach(l => hl.filter(h => h.p === l.a).forEach(a => hr.filter(h => h.p === l.b).forEach(b => { const pts = [a.x, a.y, l.a.x, l.a.y, l.b.x, l.b.y, b.x, b.y];
        routes.push({lines:[a.line, l.line, b.line], pts, back:[b.x, b.y, l.b.x, l.b.y, l.a.x, l.a.y, a.x, a.y]}); })));
      return {box:{bx, bw, by, bh}, ports, hosts:[...hl, ...hr], lines, routes, pk:Array.from({length:22}, () => ({r:null, s:0, v:0.18 + Math.random() * 0.14}))};
    },
    still(ctx, S, line){
      const B = S.box;
      ctx.globalAlpha = 0.9; ctx.fillStyle = '#0B1736'; ctx.strokeStyle = 'rgba(130,175,255,.45)'; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.roundRect(B.bx, B.by, B.bw, B.bh, 14); ctx.fill(); ctx.stroke();
      ctx.globalAlpha = 0.8; ctx.fillStyle = '#A9B7D9'; ctx.font = '600 12.5px Manrope, sans-serif'; ctx.textAlign = 'center'; ctx.fillText(dev.name, B.bx + B.bw / 2, B.by + 22);
      ctx.lineWidth = 1.4; ctx.lineCap = 'round'; ctx.strokeStyle = '#4C93FF'; S.lines.forEach(l => { if (l.k >= 1) line(l); });
      S.hosts.forEach(h => { ctx.globalAlpha = 0.9; ctx.fillStyle = h.x < B.bx ? C.int : C.ext; ctx.beginPath(); ctx.arc(h.x, h.y, 3.5, 0, 6.2832); ctx.fill(); });
      S.ports.forEach(p => { ctx.globalAlpha = 1; ctx.fillStyle = '#081127'; ctx.strokeStyle = '#4C93FF'; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(p.x, p.y, 5, 0, 6.2832); ctx.fill(); ctx.stroke();
        ctx.fillStyle = '#A9B7D9'; ctx.font = '11px "JetBrains Mono", monospace'; ctx.textAlign = p.side === 'L' ? 'left' : 'right'; ctx.fillText(p.n.length > 16 ? p.n.slice(0, 15) + '…' : p.n, p.x + (p.side === 'L' ? 9 : -9), p.y + 18); });
      ctx.globalAlpha = 1; ctx.textAlign = 'left'; ctx.lineCap = 'butt';
    }};
}
// Path analysis: the devices (known before the answer) in columns, the internet on the right; links assemble
function sketchGraph(devs){
  const list = devs.slice(0, 9);
  return {
    layout(W, H){
      const cols = list.length <= 3 ? [list] : [list.slice(0, Math.ceil(list.length / 3)), list.slice(Math.ceil(list.length / 3), Math.ceil(2 * list.length / 3)), list.slice(Math.ceil(2 * list.length / 3))];
      const nodes = [];
      cols.forEach((c, ci) => c.forEach((d, k) => nodes.push({name:d.name, c:ci, x:W * (0.12 + ci * (0.6 / Math.max(1, cols.length - 1 || 1))), y:H * ((k + 1) / (c.length + 1))})));
      const inet = {name:T('Internet'), c:cols.length, x:W * 0.9, y:H / 2, inet:true}; nodes.push(inet);
      const lines = [], routes = [];
      const link = (a, b, at) => { const l = {x0:a.x + (a.inet ? 0 : 50), y0:a.y, x1:b.x - (b.inet ? 30 : 50), y1:b.y, a:0.38, at}; lines.push(l); routes.push({lines:[l], pts:[l.x0, l.y0, l.x1, l.y1], back:[l.x1, l.y1, l.x0, l.y0]}); };
      let k = 0; const n = nodes.length;
      nodes.forEach(a => { const next = nodes.filter(b => b.c === a.c + 1); if (!next.length) return;
        next.forEach((b, j) => { if (j === nodes.indexOf(a) % next.length || Math.random() < 0.35 || b.inet) link(a, b, 0.05 + (k++) * 0.75 / Math.max(1, n * 1.4)); }); });
      if (!lines.length && nodes.length > 1) link(nodes[0], inet, 0.1);
      return {nodes, lines, routes, pk:Array.from({length:24}, () => ({r:null, s:0, v:0.3 + Math.random() * 0.2}))};
    },
    still(ctx, S, line){
      ctx.lineWidth = 1.4; ctx.lineCap = 'round'; ctx.strokeStyle = '#4C93FF'; S.lines.forEach(l => { if (l.k >= 1) line(l); });
      S.nodes.forEach(nd => { ctx.globalAlpha = 0.95; ctx.fillStyle = '#0B1736'; ctx.strokeStyle = nd.inet ? C.ext : '#4C93FF'; ctx.lineWidth = 1.5;
        const w = nd.inet ? 60 : 100, h = nd.inet ? 34 : 30; ctx.beginPath(); ctx.roundRect(nd.x - w / 2, nd.y - h / 2, w, h, nd.inet ? 17 : 8); ctx.fill(); ctx.stroke();
        ctx.fillStyle = '#A9B7D9'; ctx.font = '600 11.5px Manrope, sans-serif'; ctx.textAlign = 'center'; const t = nd.name.length > 14 ? nd.name.slice(0, 13) + '…' : nd.name; ctx.fillText(t, nd.x, nd.y + 4); });
      ctx.globalAlpha = 1; ctx.textAlign = 'left'; ctx.lineCap = 'butt';
    }};
}
const errBox = e => `<div class="err">${T('Failed to load: ')}${esc(e.message)}</div>`;
function wireFilters(root){
  root.querySelectorAll('[data-f]').forEach(b => b.addEventListener('click', e => { e.stopPropagation(); addFilter(b.dataset.f, b.dataset.v, e.shiftKey); }));
  root.querySelectorAll('[data-host]').forEach(tr => tr.addEventListener('click', () => openHost(tr.dataset.host)));
}
// run an async section; ignore results if the user navigated away meanwhile
async function section(id, fn){
  const seq = renderSeq;
  try { const html = await fn(); if (seq === renderSeq && html != null) { const el = fill(id, html); if (el) { el.classList.remove('loading', 'wshow'); delete el.dataset.w; wireFilters(el); } } }
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
      + (isInternal() ? '' : seg('heroSeg', [['map', 'Map'], ['graph', 'Graph'], ['3d', '3D']], state.heroMode)), false, maxBtn())}
    <div id="heroBody" class="${g ? 'river' : 'chart hero-h'}"></div><div id="heroNote" class="heronote" hidden></div><div id="heroOvl"></div>`);
  lockLive('heroLiveSeg'); maxMark();
  wireSeg('heroSeg', m => { if (m === state.heroMode) return; state.heroMode = m; mountHero(); });
  wireSeg('heroLiveSeg', m => { const l = m === 'live'; if (l === !!state.heroLive) return; state.heroLive = l; mountHero(); });
  wireSeg('scaleSeg', m => { state.scale = m; setPressed('scaleSeg', m); RIVERS.forEach(k => k()); });
  const hb = document.getElementById('heroBody'), myScope = heroScope;
  heroScope.run(() => {
    if (g) createRiver(hb, {compact:true, refreshMs:live ? 10000 : 0, fetchData:top => api('river', {top, live:live ? 1 : 0, win:120, metric:state.metric}),
      fitTop:(h, cpt) => Math.max(3, Math.min(20, Math.floor((h - (cpt ? 22 : 30) + (cpt ? 6 : 8)) / (cpt ? 46 : 58)))),     // a card 40 / 50 px + the gap
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
      <section class="glass panel">${ph('pie', T('Top services'), T('by traffic volume'), '', false, maxBtn())}<div id="svcBox" class="loading"></div></section>
      <section class="glass panel">${ph('users', T('Top hosts'), T('inside addresses'), '', false, maxBtn())}<div id="hostBox" class="loading"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', T('Traffic trend'), rangeLabel(), '', false, maxBtn())}<div class="chart" id="cTrend"></div></section>
    <section class="glass panel s4">${ph('conv', T('Top conversations'), (isInternal() ? T('client → server') : T('inside → outside address')), '', false, maxBtn())}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('list', T('Recent flows'), T('new network activity'), `<button class="lnk" id="toFlows">${T('All')}</button>`, false, maxBtn())}<div id="recentBox" class="loading"></div></section></div>`;
  document.getElementById('toFlows').onclick = () => { state.view = 'flows'; render(); };
  section('kpis', kpiCards);
  mountHero();
  // (1.8.9) full screen: the lists show more rows (a panel's _reload loads it again when it opens or closes)
  const big = id => { const el = document.getElementById(id); return !!(el && el.closest('section.is-max')); };
  const loaders = {
  svcBox:() => section('svcBox', async () => {
    const t = await api('top', {dim:'service', limit:big('svcBox') ? 12 : 5}); const rest = t.total - t.rows.reduce((s, r) => s + tot(r), 0);
    const rows = [...t.rows, ...(rest > 0 ? [{k:T('Others'), up:rest, dn:0}] : [])];
    setTimeout(() => { const el = document.getElementById('cDonut'); if (el) donut(el, rows, k => k === T('Others') ? C.other : keyColor(k), [fmtB(t.total), T('total traffic')]); });
    return `<div class="donut-wrap"><div class="chart donut" id="cDonut"></div><div class="dl">${rows.map(r => `<i class="idot" style="background:${r.k === T('Others') ? C.other : keyColor(r.k)}"></i>${r.k === T('Others') ? `<span>${T('Others')}</span>` : `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.k)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div></div>`;
  }),
  hostBox:() => section('hostBox', async () => { const t = await api('top', {dim:'int_ip', limit:big('hostBox') ? 20 : 5});
    return `<div class="tw"><table class="compact"><thead><tr><th>#</th><th>${T('Host')}</th><th class="num">${T('Traffic')}</th><th class="num">%</th><th></th></tr></thead><tbody>${t.rows.map((r, i) => `<tr class="click" data-host="${esc(r.k)}"><td class="mono">${i + 1}</td><td><div class="two-line"><b class="mono">${esc(r.name || r.k)}</b>${r.name ? `<span class="nat">${esc(r.k)}</span>` : ''}</div></td><td class="num mono">${fmtB(tot(r))}</td><td class="num mono">${pct(tot(r), t.total)}</td><td class="chev">›</td></tr>`).join('')}</tbody></table></div>`; }),
  convBox:() => section('convBox', async () => { const t = await api('top', {dim:'conv', limit:big('convBox') ? 20 : 5}); return convRows(t.rows, t.total); }),
  recentBox:() => section('recentBox', async () => { const t = await api('flows', {limit:big('recentBox') ? 20 : 7});
    return `<div class="tw"><table class="compact"><thead><tr><th>${T('Time')}</th><th>${isInternal() ? T('Client → server · service') : T('Inside → outside · service')}</th><th class="num">${T('Volume')}</th></tr></thead><tbody>${t.rows.map(f => `<tr><td class="mono">${hms(f.t)}</td><td><div class="two-line"><span class="ipl">${esc(f.name || f.int_ip)} <span class="${isBack(f) ? 'd' : 'u'}">${isBack(f) ? '←' : '→'}</span> ${esc(f.ext_ip)}</span><span class="nat">${esc(dv(f.service))}${f.l7 ? ' · ' + esc(f.l7) : ''}</span></div></td><td class="num mono">${fmtB(f.bytes)}</td></tr>`).join('') || `<tr><td colspan="4"><div class="empty">${T('No records')}</div></td></tr>`}</tbody></table></div>`; })
  };
  Object.values(loaders).forEach(f => f());
  Object.entries(loaders).forEach(([id, f]) => { const sec = document.getElementById(id).closest('section'); if (sec) sec._reload = f; });
  api('series').then(s => { const el = document.getElementById('cTrend'); if (el) trendChart(el, s); }).catch(e => fill('cTrend', errBox(e)));
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
// (1.12.0) the load of each interface of the device: average / 95th percentile / peak in and out, as Mbit/s and as a
// share of the capacity (own figures or the port's speed), with the busiest 5 minutes over the period as a small chart
const loadColor = pct => pct == null ? 'var(--ink3)' : pct >= 90 ? 'var(--crit)' : pct >= 70 ? 'var(--warn)' : 'var(--ok)';
async function ifLoadPanel(ip, seq){
  const put = (id, html) => { const el = fill(id, html); if (el) el.classList.remove('loading'); return el; };     // the box stops "loading"
  let d;
  try { d = await api('ifload', {device:ip}); } catch (e) { put('pLoad', `<p class="err">${esc(e.message)}</p>`); return; }
  if (seq !== renderSeq) return;
  if (!d.interfaces.length) { put('pLoad', `<div class="empty">${T('No interface traffic in this period')}</div>`); return; }
  const bar = (pct, rate) => `<div class="ldbar" title="${esc(fmtR(rate))}${pct == null ? '' : ' · ' + pct + '%'}"><i style="width:${Math.min(100, pct || 0)}%;background:${loadColor(pct)}"></i></div>`;
  const cell = (x, cap) => `<td class="ld"><div class="ldtop"><b class="mono" style="color:${loadColor(x.peak_pct)}">${x.peak_pct == null ? '—' : x.peak_pct + '%'}</b><span class="nat mono">${fmtR(x.peak)}</span></div>
    ${bar(x.peak_pct, x.peak)}<div class="nat mono ldsub">${T('avg')} ${fmtR(x.avg)}${x.avg_pct == null ? '' : ` (${x.avg_pct}%)`} · p95 ${fmtR(x.p95)}${x.p95_pct == null ? '' : ` (${x.p95_pct}%)`}</div></td>`;
  const spark = i => { const w = 220, h = 34, top = Math.max(i.cap_in * 1e6, i.cap_out * 1e6, ...i.series.map(r => Math.max(r[1], r[2])), 1);
    const line = (k, color) => `<polyline points="${i.series.map((r, n) => `${(n / Math.max(1, i.series.length - 1) * w).toFixed(1)},${(h - 2 - r[k] / top * (h - 4)).toFixed(1)}`).join(' ')}" fill="none" stroke="${color}" stroke-width="1.3" vector-effect="non-scaling-stroke"/>`;
    const capY = c => (h - 2 - c * 1e6 / top * (h - 4)).toFixed(1);
    return `<svg class="ldspark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">${i.cap_in ? `<line x1="0" x2="${w}" y1="${capY(i.cap_in)}" y2="${capY(i.cap_in)}" stroke="var(--ink3)" stroke-dasharray="3 3" stroke-width="1" vector-effect="non-scaling-stroke"/>` : ''}${line(1, '#27D3F5')}${line(2, '#FF9F43')}</svg>`; };
  const capTxt = i => !i.cap_in && !i.cap_out ? `<span class="nat" title="${T('Unknown: set it in Settings → Devices → Interfaces')}">${T('unknown')}</span>`
    : `<span class="mono">${i.cap_in === i.cap_out ? fmtR(i.cap_in * 1e6) : `${fmtR(i.cap_in * 1e6)} ↓ / ${fmtR(i.cap_out * 1e6)} ↑`}</span><div class="nat">${i.cap_own ? T('your figures') : T('port speed')}</div>`;
  put('pLoad', `<div class="tw"><table class="compact ldtable"><thead><tr><th>${T('Interface')}</th><th>${T('Capacity')}</th><th>${T('In (peak)')}</th><th>${T('Out (peak)')}</th><th>${T('Over the period')} <span class="nat" style="font-weight:500"><span style="color:#27D3F5">— ${T('in')}</span> <span style="color:#FF9F43">— ${T('out')}</span></span></th></tr></thead><tbody>
    ${d.interfaces.map(i => `<tr><td><b>${esc(i.name)}</b> ${i.role === 'wan' ? '<span class="pill warn">WAN</span>' : ''}<div class="nat mono">${T('index {idx}', {idx:i.index})}</div></td><td>${capTxt(i)}</td>
      ${cell(i.in, i.cap_in)}${cell(i.out, i.cap_out)}<td>${spark(i)}</td></tr>`).join('')}</tbody></table></div>
    <p class="note">${T('In = traffic entering the device through the interface, out = leaving through it; every traffic type, whatever the selector at the top. 5-minute averages: a burst of seconds is smoothed. The capacity is the port speed unless you set your own (e.g. your ISP contract) in Settings → Devices → Interfaces.')}
    ${isAdmin() ? ` <button class="lnk" id="ldCaps">${T('Set capacities')} →</button>` : ''}</p>`);
  const b = document.getElementById('ldCaps');
  if (b) b.onclick = () => { state.view = 'settings'; state.setTab = 'devices'; state.ifDev = ip; render(); };
}
// ===================== (1.13.0) Capacity: how full each link is day by day and where it is heading =====================
// /api/capacity (every interface of every device over whole local days, the fullest first) and /api/capacity/iface
// (one link: weekday × hour, what drives it). Its own period (7 – 365 days, as far as the edition shows); every traffic
// type, whatever the selector and the filters at the top.
const CAP_IN = '#27D3F5', CAP_OUT = '#FF9F43';
const CAP_STATUS = () => ({over:[T('Over the limit'), 'crit'], full:[T('Near full'), 'crit'], soon:[T('Will fill'), 'warn'], watch:[T('Worth watching'), 'warn'], ok:[T('Fine'), 'ok'], unknown:[T('Capacity unknown'), '']});
const capTz = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } };
const capApi = (path, params = {}) => apiFetch(`api/${path}?${new URLSearchParams({days:state.capDays || 30, tz:capTz(), f:JSON.stringify(state.filters), ...params})}`);
// (1.13.1) growth a month as shown: beyond ±100 % only "over" (a link that just started carrying traffic)
const capGrowth = g => Math.abs(g) > 100 ? (g > 0 ? T('over +100%') : T('over −100%')) : `${g > 0 ? '+' : ''}${g.toLocaleString(LOC, {maximumFractionDigits:1})}%`;
const dMon = t => new Date(t * 1000).toLocaleDateString(LOC, {day:'numeric', month:'short'});
const capDir = d => d === 'in' ? T('incoming traffic') : T('outgoing traffic');
const capOf = (x, d) => (d === 'in' ? x.cap_in : x.cap_out) * 1e6;
// "85 % around 12 Nov" / "not within 58 days" / "now"
function capWhen(fc, key, lastDay){
  if (!fc) return '';
  if (fc[key] === 0) return T('already');
  if (fc[key] == null) return fc.direction === 'up' && fc.busy_pct != null ? T('not within {n} days', {n:fc.horizon}) : '—';
  return dMon(lastDay + fc[key] * 86400 + 43200);          // midday: a DST change between does not move the date
}
// one sentence about a link, for the detail and the reports' spirit
function capSentence(x){
  const d = x.worst, s = x[d], fc = s.forecast, cap = capOf(x, d), who = `${esc(x.device_name)} · ${esc(x.name)}`;
  const sp = x.seen_pct && x.seen_pct[d], cov = sp == null ? '' : ' ' + (sp < 80 ? T('The flows see only {pct}% of what the interface counted: the rest is not exported (check the sampler on this interface).', {pct:sp})
    : sp > 125 ? T('The flows count {pct}% of what the interface counted: some traffic may be exported twice.', {pct:sp}) : T('The flows see {pct}% of what the interface counted.', {pct:sp}));
  if (!cap) return T('{who}: the capacity is unknown — set it (e.g. your ISP contract) in Settings → Devices → Interfaces to see shares and a forecast.', {who}) + cov;
  const ctr = x.source && x.source !== 'flows';      // (1.14.0) the interface's own counters: the peak is one minute
  const ba = {who, dir:capDir(d), p95:fmtR(s.p95), cap:fmtR(cap), pct:s.p95_pct, peak:fmtR(s.peak)};
  const base = ctr ? T('{who}, {dir}: the busy hours reach {p95} of {cap} (95th percentile, {pct}%), the busiest minute {peak} (the interface\'s own counters).', ba)
    : T('{who}, {dir}: the busy hours reach {p95} of {cap} (95th percentile, {pct}%), the busiest 5 minutes {peak}.', ba);
  if (!fc) return base + ' ' + T('A forecast needs {n} days of history.', {n:CAP.forecast_days}) + cov;
  if (fc.over_in === 0) return base + ' ' + T('Busy days already fill it — time for more capacity.') + cov;
  const g = Math.abs(fc.growth_pct_month).toLocaleString(LOC, {maximumFractionDigits:1});
  if (!fc.clear) return base + ' ' + T('The days differ too much for a trend; it shows once there is more history.') + cov;
  if (fc.direction === 'stable') return base + ' ' + T('The load is stable.') + cov;
  if (fc.direction === 'down') return base + ' ' + T('The load is falling, about {g}% a month.', {g}) + cov;
  const last = s.trend.last_day;
  return base + ' ' + (fc.full_in === 0 ? T('Growing about {g}% a month; already above {full}% on busy days, the limit around {over}.', {g, full:CAP.full_pct, over:capWhen(fc, 'over_in', last)})
    : fc.full_in != null ? T('Growing about {g}% a month: {full}% around {date}, the limit {over}.', {g, full:CAP.full_pct, date:capWhen(fc, 'full_in', last), over:fc.over_in != null ? T('around {date}', {date:capWhen(fc, 'over_in', last)}) : T('not within {n} days', {n:fc.horizon})})
    : T('Growing about {g}% a month; {full}% not within {n} days.', {g, full:CAP.full_pct, n:fc.horizon})) + cov;
}
let CAP = null;
function vCapacity(){
  const v = document.getElementById('view');
  const days = state.capDays || 30;
  // (1.13.2) visual first (Yegor's rule for every page): the cards, the chart of one link, when it is busy and what
  // drives it; the table of all links last — a row of it picks the link above
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12 caphead">${ph(CAP_ICON, T('page::Capacity'), T('how full each link is on its busy days and where it is heading · all its traffic · whole days · the device and interface filters apply'), '<span id="capDaysBox"></span>', true)}</section>
    <div id="capKpi" style="display:contents"></div>
    <section class="glass panel s8" id="capDetailS">${ph('chart', `<span id="capDetT">${T('Trend and forecast')}</span>`, `<span id="capDetSub">${T('daily 95th percentile, the trend of the busy days and where it meets the capacity')}</span>`, '<span id="capPickBox"></span><span id="capDirBox"></span>')}<div id="capChart" class="loading"></div><p class="capsay" id="capSay"></p></section>
    <section class="glass panel s4">${ph('pulse', T('When it is busy'), T('busiest 5 minutes of each hour, averaged over the weeks'))}<div id="capHeat" class="loading"></div></section>
    <section class="glass panel s6">${ph('users', T('Hosts on this link'), `<span id="capHalfH">${T('recent half of the period against the earlier one')}</span>`)}<div id="capHosts" class="loading"></div></section>
    <section class="glass panel s6">${ph('grid', T('Services on this link'), `<span id="capHalfS">${T('recent half of the period against the earlier one')}</span>`)}<div id="capSvcs" class="loading"></div></section>
    <section class="glass panel s12">${ph('list', T('All links'), T('the fullest first · click a row to see it above'))}<div id="capTable" class="loading"></div></section></div>`;
  const seq = renderSeq;
  const done = (id, html) => { const el = fill(id, html); if (el) el.classList.remove('loading'); return el; };
  (async () => {
    let d;
    try { d = await capApi('capacity'); } catch (e) { done('capTable', errBox(e)); return; }
    if (seq !== renderSeq) return;
    CAP = d;
    fill('capDaysBox', seg('capDays', [7, 30, 90, 180, 365].map(n => [String(n), T('{n} d', {n}), n > d.max_days ? T('Your edition shows {n} days', {n:d.max_days}) : '']), String(d.days)));
    document.querySelectorAll('#capDays button').forEach(b => { if (+b.dataset.v > d.max_days) b.disabled = true; });
    wireSeg('capDays', n => { if (+n === d.days || +n > d.max_days) return; state.capDays = +n; render(); });
    const all = d.interfaces, st = CAP_STATUS();
    const skip = (d.unfiltered || []).map(k => FILTER_LABEL[k] || k), skipNote = skip.length ? `<p class="note evskip">${T('Not applied here')}: ${esc(skip.join(', '))}</p>` : '';
    if (!all.length) { done('capTable', skipNote + `<div class="empty">${state.filters.some(f => f.k === 'device' || f.k === 'iface') ? T('No link matches these filters') : T('No interface traffic in this period')}</div>`); ['capChart', 'capHeat', 'capHosts', 'capSvcs'].forEach(id => done(id, '')); return; }
    // the cards
    const kc = (ic, k, val, sub, col) => `<section class="glass panel kcard s3" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic] || ic, 22)}</span><span class="k">${k}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span><span class="nat" style="grid-column:2">${sub}</span></section>`;
    const near = all.filter(x => x.status === 'over' || x.status === 'full'), soon = all.filter(x => x.status === 'soon');
    const dated = all.map(x => ({x, fc:x[x.worst].forecast, last:(x[x.worst].trend || {}).last_day})).filter(o => o.fc && o.fc.full_in != null && o.fc.full_in > 0).sort((a, b) => a.fc.full_in - b.fc.full_in);
    const grow = all.filter(x => capOf(x, x.worst) && x[x.worst].forecast && x[x.worst].forecast.direction === 'up' && x[x.worst].forecast.clear).sort((a, b) => b[b.worst].forecast.growth_pct_month - a[a.worst].forecast.growth_pct_month);
    const known = all.filter(x => x.status !== 'unknown');
    const nm = x => `${esc(x.name)} <span class="nat">${esc(x.device_name)}</span>`;
    fill('capKpi', kc('shield', T('Near full'), String(near.length), near.length ? near.slice(0, 2).map(nm).join(', ') : T('no link at {pct}% on busy days', {pct:d.full_pct}), near.length ? 'var(--crit)' : 'var(--ok)')
      + kc('chart', T('Will fill'), dated.length ? capWhen(dated[0].fc, 'full_in', dated[0].last) : '—', dated.length ? T('{name} reaches {pct}% first', {name:nm(dated[0].x), pct:d.full_pct}) + (soon.length > 1 ? ` · ${Tn(soon.length - 1, '{n} more link', '{n} more links')}` : '') : T('no link reaches {pct}% within the forecast', {pct:d.full_pct}), dated.length ? 'var(--warn)' : '')
      + kc('pulse', T('Fastest growth'), grow.length ? capGrowth(grow[0][grow[0].worst].forecast.growth_pct_month) : '—', grow.length ? `${nm(grow[0])} · ${T('a month')}` : T('a forecast needs {n} days of history', {n:d.forecast_days}))
      + (() => {      // (1.14.0) with interface counters: how much of the links the flows see, the worst first
        const cov = all.flatMap(x => ['in', 'out'].filter(k => x.seen_pct && x.seen_pct[k] != null).map(k => ({x, k, v:x.seen_pct[k]}))).sort((a, b) => a.v - b.v);
        const cnt = all.filter(x => x.counters).length;
        if (!cov.length && cnt) return kc('ip', T('Flows see'), '…', T('{n} links with counters since {date}: the comparison shows after 3 hours', {n:cnt, date:dMon(Math.min(...all.filter(x => x.counters_since).map(x => x.counters_since)))}));
        if (!cov.length) return kc('ip', T('Links measured'), `${known.length} / ${all.length}`, known.length < all.length ? T('{n} without a known capacity', {n:all.length - known.length}) : T('every link has a capacity'));
        const w = cov[0], low = w.v < 80;
        return kc('ip', T('Flows see'), `${Math.round(w.v)}%`, low ? T('{name}, {dir}: the rest of its traffic is not exported', {name:nm(w.x), dir:capDir(w.k)}) : T('of what the interfaces counted, at least · {n} links by their own counters', {n:all.filter(x => x.source && x.source !== 'flows').length}), low ? 'var(--warn)' : 'var(--ok)'); })());
    // the table
    const bar = (pct, c) => `<div class="ldbar"><i style="width:${Math.min(100, pct || 0)}%;background:${loadColor(pct)}"></i></div>`;
    const dirCell = (x, k) => { const s = x[k]; return `<td class="ld"><div class="ldtop"><b class="mono" style="color:${loadColor(s.p95_pct)}">${s.p95_pct == null ? '—' : s.p95_pct + '%'}</b><span class="nat mono">${fmtR(s.p95)}</span></div>${bar(s.p95_pct)}<div class="nat mono ldsub">${T('peak')} ${fmtR(s.peak)}${s.peak_pct == null ? '' : ` (${s.peak_pct}%)`}</div></td>`; };
    const trendCell = x => { const fc = x[x.worst].forecast; if (!fc) return `<td><span class="nat" title="${T('A forecast needs {n} days of history.', {n:d.forecast_days})}">${T('collecting')}</span></td>`;
      if (!fc.clear) return `<td><b class="mono" style="color:var(--ink2)">≈</b><div class="nat" title="${T('The days differ too much for a trend; it shows once there is more history.')}">${T('unsteady')}</div></td>`;
      const a = fc.direction === 'up' ? '↗' : fc.direction === 'down' ? '↘' : '→', col = fc.direction === 'up' ? (capOf(x, x.worst) ? 'var(--warn)' : 'var(--ink2)') : fc.direction === 'down' ? 'var(--ok)' : 'var(--ink2)';
      return `<td><b class="mono" style="color:${col}">${a} ${capGrowth(fc.growth_pct_month)}</b><div class="nat">${T('a month')}</div></td>`; };
    const whenCell = x => { const s = x[x.worst], fc = s.forecast; if (!capOf(x, x.worst)) return '<td><span class="nat">—</span></td>';
      if (!fc) return `<td><span class="nat">—</span></td>`;
      const w = capWhen(fc, 'full_in', s.trend.last_day), hot = fc.full_in != null;
      return `<td><b class="mono" style="color:${fc.full_in === 0 ? 'var(--crit)' : hot ? 'var(--warn)' : 'var(--ink2)'}">${w}</b>${fc.over_in != null && fc.over_in > 0 ? `<div class="nat">${T('limit {date}', {date:capWhen(fc, 'over_in', s.trend.last_day)})}</div>` : ''}</td>`; };
    // (1.14.0) how much of what the interface counted the flows see (in / out): below 80 % the export misses traffic
    const seenCell = x => { const v = x.seen_pct; if (!v || (v.in == null && v.out == null)) return x.counters ? `<td><span class="nat" title="${T('After 3 hours of counters')}">${T('collecting')}</span></td>` : `<td><span class="nat" title="${T('Switch SNMP on for the device to compare the flows with the interface\'s counters')}">—</span></td>`;
      const one = (k, a) => v[k] == null ? '' : `<div class="mono" style="color:${v[k] < 80 ? 'var(--warn)' : v[k] > 125 ? 'var(--warn)' : 'var(--ink2)'}">${a} ${Math.round(v[k])}%</div>`;
      return `<td>${one('in', '↓')}${one('out', '↑')}</td>`; };
    const spark = x => { const w = 200, h = 34, rows = x.days, top = Math.max(capOf(x, 'in'), capOf(x, 'out'), ...rows.map(r => Math.max(r[1], r[2])), 1);
      const line = (k, color) => `<polyline points="${rows.map((r, n) => `${(n / Math.max(1, rows.length - 1) * w).toFixed(1)},${(h - 2 - r[k] / top * (h - 4)).toFixed(1)}`).join(' ')}" fill="none" stroke="${color}" stroke-width="1.4" vector-effect="non-scaling-stroke"/>`;
      const cy = capOf(x, x.worst) ? (h - 2 - capOf(x, x.worst) / top * (h - 4)).toFixed(1) : null;
      return `<svg class="ldspark capspark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">${cy ? `<line x1="0" x2="${w}" y1="${cy}" y2="${cy}" stroke="var(--ink3)" stroke-dasharray="3 3" stroke-width="1" vector-effect="non-scaling-stroke"/>` : ''}${line(1, CAP_IN)}${line(2, CAP_OUT)}</svg>`; };
    const capTxt = x => !x.cap_in && !x.cap_out ? `<span class="nat">${T('unknown')}</span>` : `<span class="mono">${x.cap_in === x.cap_out ? fmtR(x.cap_in * 1e6) : `${fmtR(x.cap_in * 1e6)} ↓<br>${fmtR(x.cap_out * 1e6)} ↑`}</span><div class="nat">${x.cap_own ? T('your figures') : T('port speed')}</div>`;
    const key = x => `${x.device}|${x.index}`;
    if (!all.some(x => key(x) === state.capSel)) state.capSel = key(all[0]);
    done('capTable', skipNote + `<div class="tw"><table class="compact ldtable captable"><thead><tr><th>${T('Status')}</th><th>${T('Interface')}</th><th>${T('Capacity')}</th><th>${T('In (95th percentile)')}</th><th>${T('Out (95th percentile)')}</th><th>${T('Trend')}</th><th>${T('Reaches {pct}%', {pct:d.full_pct})}</th><th title="${T('Bytes in the flows against the interface\'s own counters, the days both have')}">${T('Flows see')}</th><th>${T('Day by day')} <span class="nat" style="font-weight:500"><span style="color:${CAP_IN}">— ${T('in')}</span> <span style="color:${CAP_OUT}">— ${T('out')}</span></span></th></tr></thead><tbody>
      ${all.map(x => `<tr class="caprow" data-k="${esc(key(x))}" tabindex="0" aria-selected="${key(x) === state.capSel}"><td><span class="pill ${st[x.status][1]}">${st[x.status][0]}</span></td>
        <td><b>${esc(x.name)}</b> ${x.role === 'wan' ? '<span class="pill warn">WAN</span>' : ''}<div class="nat">${esc(x.device_name)}${x.counters ? ` · <span class="capsrc${x.source === 'flows' ? ' soon' : ''}" title="${x.source === 'flows' ? T('Counters read since {date}: the days take their figures once the counters cover most of the period; what the flows see shows after 3 hours.', {date:dMon(x.counters_since)}) : T('The interface\'s own counters: every octet, the busiest minute')}">${x.counters === 'snmp' ? T('SNMP counters') : T('sFlow counters')}${x.source === 'flows' && x.counters_since ? ' ' + T('since {date}', {date:dMon(x.counters_since)}) : ''}</span>` : ''}</div></td><td>${capTxt(x)}</td>${dirCell(x, 'in')}${dirCell(x, 'out')}${trendCell(x)}${whenCell(x)}${seenCell(x)}<td>${spark(x)}</td></tr>`).join('')}</tbody></table></div>
      <p class="note">${T('95th percentile = the load of the busy hours: only 5% of the 5-minute periods were busier. The trend compares days a whole number of weeks apart, so quiet weekends are no decline, and a forecast never reaches further than twice the history it rests on. In = entering the device through the interface, out = leaving through it.')}
      ${isAdmin() ? ` <button class="lnk" id="capCaps">${T('Set capacities')} →</button>` : ''}</p>`);
    const cb = document.getElementById('capCaps');
    if (cb) cb.onclick = () => { const x = all.find(y => key(y) === state.capSel) || all[0]; state.view = 'settings'; state.setTab = 'devices'; state.ifDev = x.device; render(); };
    const pickLink = (k, scroll) => { state.capSel = k; state.capDir = null;
      document.querySelectorAll('.caprow').forEach(o => o.setAttribute('aria-selected', String(o.dataset.k === k)));
      const ps = document.getElementById('capPick'); if (ps) ps.value = k;
      capDetail(all.find(x => key(x) === k), seq);
      if (scroll) { const el = document.getElementById('capDetailS'); if (el) el.scrollIntoView({behavior:'smooth', block:'start'}); } };
    document.querySelectorAll('.caprow').forEach(r => { r.onclick = () => pickLink(r.dataset.k, true);
      r.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pickLink(r.dataset.k, true); } }; });
    fill('capPickBox', `<label class="sel glass" title="${T('Link')}">${icon(ICO.ip, 16)}<select id="capPick" aria-label="${T('Link')}">${all.map(x => `<option value="${esc(key(x))}"${key(x) === state.capSel ? ' selected' : ''}>${esc(x.name)} · ${esc(x.device_name)}</option>`).join('')}</select></label>`);
    document.getElementById('capPick').onchange = e => pickLink(e.target.value, false);
    pickLink(state.capSel, false);
  })();
}
// the trend chart: daily 95th percentile (dots) and peak (faint), the busy days' trend line carried on dashed into the
// future, the capacity and the "near full" line, and where they meet
function capChart(x, d){
  const s = x[d], cap = capOf(x, d), rows = x.days, k = d === 'in' ? 1 : 2, color = d === 'in' ? CAP_IN : CAP_OUT;
  const tr = s.trend, fc = s.forecast, today = CAP.today;
  const t0 = rows.length ? rows[0][0] : today, lastT = tr ? tr.last_day : rows.length ? rows[rows.length - 1][0] : today;
  const ahead = fc && cap ? Math.min(fc.horizon, Math.max(14, (fc.over_in != null ? fc.over_in : fc.full_in != null ? fc.full_in : 0) + 7)) : 0;
  const t1 = Math.max(today, lastT + ahead * 86400);
  const W = 900, H = 280, L = 86, R = 16, Tp = 14, B = 30;
  const busyAt = t => tr ? tr.busy + tr.slope * (t - lastT) / 86400 : 0;
  const top = Math.max(1, cap || 0, ...rows.map(r => r[k + 2]), tr ? busyAt(t1) : 0) * 1.08;
  const X = t => L + (t - t0) / Math.max(86400, t1 - t0) * (W - L - R), Y = v => Tp + (1 - v / top) * (H - Tp - B);
  const ticks = [...Array(5)].map((_, i) => top / 1.08 * i / 4);
  let g = ticks.map(v => `<line x1="${L}" x2="${W - R}" y1="${Y(v).toFixed(1)}" y2="${Y(v).toFixed(1)}" class="cgrid"/><text x="${L - 8}" y="${(Y(v) + 4).toFixed(1)}" class="caxis" text-anchor="end">${esc(fmtR(v))}</text>`).join('');
  const nT = Math.min(6, Math.max(2, Math.round((t1 - t0) / 86400 / 7)));
  for (let i = 0; i <= nT; i++) { const t = t0 + (t1 - t0) * i / nT; g += `<text x="${X(t).toFixed(1)}" y="${H - 8}" class="caxis" text-anchor="${i === 0 ? 'start' : i === nT ? 'end' : 'middle'}">${esc(dMon(t))}</text>`; }
  if (t1 > today) g += `<rect x="${X(today + 86400).toFixed(1)}" y="${Tp}" width="${(X(t1) - X(today + 86400)).toFixed(1)}" height="${H - Tp - B}" class="cfuture"/><text x="${(X(today + 86400) + 6).toFixed(1)}" y="${Tp + 14}" class="caxis">${T('forecast')}</text>`;
  if (cap) g += `<line x1="${L}" x2="${W - R}" y1="${Y(cap).toFixed(1)}" y2="${Y(cap).toFixed(1)}" class="ccap"/><text x="${L + 6}" y="${(Y(cap) - 6).toFixed(1)}" class="caxis ccapt">${T('capacity')} ${esc(fmtR(cap))}</text>`
    + `<line x1="${L}" x2="${W - R}" y1="${Y(cap * CAP.full_pct / 100).toFixed(1)}" y2="${Y(cap * CAP.full_pct / 100).toFixed(1)}" class="cfull"/><text x="${L + 6}" y="${(Y(cap * CAP.full_pct / 100) - 6).toFixed(1)}" class="caxis cfullt">${CAP.full_pct}%</text>`;
  g += `<polyline points="${rows.map(r => `${X(r[0] + 43200).toFixed(1)},${Y(r[k + 2]).toFixed(1)}`).join(' ')}" fill="none" stroke="${color}" stroke-opacity=".35" stroke-width="1.3"/>`;
  g += rows.map(r => `<circle cx="${X(r[0] + 43200).toFixed(1)}" cy="${Y(r[k]).toFixed(1)}" r="3.2" fill="${color}"${r[0] >= today ? ' fill-opacity=".45"' : ''}><title>${esc(dMon(r[0]))}: p95 ${esc(fmtR(r[k]))} · ${T('peak')} ${esc(fmtR(r[k + 2]))}</title></circle>`).join('');
  if (tr) {
    const a = t0 + 43200, b = lastT + 43200, clip = v => Math.max(0, Math.min(top, v));
    g += `<line x1="${X(a).toFixed(1)}" y1="${Y(clip(busyAt(a))).toFixed(1)}" x2="${X(b).toFixed(1)}" y2="${Y(clip(busyAt(b))).toFixed(1)}" class="ctrend"/>`;
    if (t1 > b) g += `<line x1="${X(b).toFixed(1)}" y1="${Y(clip(busyAt(b))).toFixed(1)}" x2="${X(t1).toFixed(1)}" y2="${Y(clip(busyAt(t1))).toFixed(1)}" class="ctrend cdash"/>`;
    for (const [key2, cls, lbl] of [['full_in', 'cfullt', `${CAP.full_pct}%`], ['over_in', 'ccapt', '100%']]) {
      const n = fc && fc[key2]; if (!n) continue;
      const t = lastT + n * 86400 + 43200; if (t > t1) continue;
      g += `<line x1="${X(t).toFixed(1)}" x2="${X(t).toFixed(1)}" y1="${Tp}" y2="${H - B}" class="cmark"/><circle cx="${X(t).toFixed(1)}" cy="${Y(busyAt(t)).toFixed(1)}" r="5" class="cmarkd"/>`
        + `<text x="${(X(t) - 6).toFixed(1)}" y="${(Y(busyAt(t)) - 10).toFixed(1)}" class="caxis ${cls}" text-anchor="end">${lbl} ≈ ${esc(dMon(t))}</text>`;
    }
  }
  return `<svg class="capchart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${T('Trend and forecast')}">${g}</svg>
    <div class="legend caplegend"><span><i style="background:${color}"></i>${T('95th percentile of the day')}</span><span><i style="background:${color};opacity:.4"></i>${x.source && x.source !== 'flows' ? T('busiest minute of the day') : T('busiest 5 minutes of the day')}</span>${tr ? `<span><i class="lt"></i>${T('trend of the busy days')}</span>` : ''}${cap ? `<span><i class="lc"></i>${T('capacity')}</span>` : ''}</div>`;
}
async function capDetail(x, seq){
  if (!x) return;
  const d = state.capDir && x[state.capDir] ? state.capDir : x.worst;
  fill('capDetT', T('Trend and forecast'));
  fill('capDirBox', seg('capDir', [['in', T('In')], ['out', T('Out')]], d));
  wireSeg('capDir', v => { state.capDir = v; capDetail(x, seq); });
  const ch = fill('capChart', capChart(x, d)); if (ch) ch.classList.remove('loading');
  fill('capSay', capSentence({...x, worst:d}).replace(/\.\.( |$)/g, '.$1'));         // an abbreviation with a dot at the end of a sentence
  ['capHeat', 'capHosts', 'capSvcs'].forEach(id => { const el = document.getElementById(id); if (el) el.classList.add('loading'); });
  let r;
  try { r = await capApi('capacity/iface', {device:x.device, if:x.index}); } catch (e) { ['capHeat', 'capHosts', 'capSvcs'].forEach(id => { const el = fill(id, errBox(e)); if (el) el.classList.remove('loading'); }); return; }
  if (seq !== renderSeq || state.capSel !== `${x.device}|${x.index}`) return;
  // weekday × hour: share of the capacity when known, else of the busiest hour
  const grid = r.heat[d], cap = capOf(x, d), max = Math.max(1, ...grid.flat()), wd = WDAYS(), wds = [...Array(7)].map((_, i) => new Date(Date.UTC(2026, 0, 5 + i)).toLocaleDateString(LOC, {weekday:'short', timeZone:'UTC'}));
  // brightness against the busiest hour (the rhythm shows on a quiet link too), the colour by the share of the capacity
  const col = v => { const a = (.12 + .83 * v / max).toFixed(2), p = cap ? v / cap : 0;
    return v <= 0 ? 'rgba(120,160,255,.06)' : p >= CAP.full_pct / 100 ? `rgba(255,92,122,${a})` : p >= .7 ? `rgba(255,195,77,${a})` : `rgba(39,211,245,${a})`; };
  const heat = `<div class="capheat"><span></span>${[...Array(24)].map((_, h) => `<span class="hh">${h % 3 ? '' : h}</span>`).join('')}
    ${grid.map((row, w) => `<span class="wd">${esc(wds[w])}</span>${row.map((v, h) => `<i style="background:${col(v)}" title="${esc(wd[w])} ${String(h).padStart(2, '0')}:00 · ${esc(fmtR(v))}${cap ? ` · ${Math.round(100 * v / cap)}%` : ''}"></i>`).join('')}`).join('')}</div>
    <p class="note">${cap ? T('Brighter = busier; colour = share of the capacity: blue below 70%, amber above, red above {pct}%.', {pct:CAP.full_pct}) : T('Brighter = busier (the capacity is unknown).')} ${T('Direction: {dir}.', {dir:capDir(d)})}</p>`;
  const h = fill('capHeat', heat); if (h) h.classList.remove('loading');
  const half = `${dMon(r.from)} – ${dMon(r.mid)} → ${dMon(r.mid)} – ${dMon(r.to)}`;
  fill('capHalfH', half); fill('capHalfS', half);
  const list = (rows, kind) => { if (!rows.length) return `<div class="empty">${T('No traffic under this filter')}</div>`;
    const top = Math.max(...rows.map(o => o.recent + o.earlier), 1);
    return '<div class="blist">' + rows.map(o => { const ch = o.earlier ? Math.round(100 * (o.recent - o.earlier) / o.earlier) : null;
      return `<button class="brow" ${kind === 'hosts' ? 'data-host' : 'data-svc'}="${esc(o.k)}"><span class="n">${esc(o.name || o.k)}${o.name ? ` <span class="nat mono">${esc(o.k)}</span>` : ''}</span><span class="t">${fmtB(o.recent + o.earlier)}</span>
        <span class="p" style="color:${ch == null ? 'var(--warn)' : ch > 15 ? 'var(--warn)' : ch < -15 ? 'var(--ok)' : 'var(--ink2)'}">${ch == null ? T('new') : ch > 300 ? `×${Math.round(o.recent / o.earlier).toLocaleString(LOC)}` : `${ch > 0 ? '+' : ''}${ch}%`}</span>
        <span class="bar2" style="width:${(100 * (o.recent + o.earlier) / top).toFixed(1)}%"><i class="u" style="width:${(100 * o.earlier / ((o.recent + o.earlier) || 1)).toFixed(1)}%;background:rgba(120,160,255,.45)"></i><i class="d" style="flex:1;background:${d === 'in' ? CAP_IN : CAP_OUT}"></i></span></button>`; }).join('') + '</div>'
      + `<p class="note">${kind === 'hosts' ? T('Bar: the earlier half (grey) and the recent one (colour); the change is recent against earlier. Click a host for its details.') : T('Bar: the earlier half (grey) and the recent one (colour); the change is recent against earlier. Click a service to open it on the Services page.')}</p>`; };
  for (const [id, kind] of [['capHosts', 'hosts'], ['capSvcs', 'services']]) { const el = fill(id, list(r[kind], kind)); if (el) { el.classList.remove('loading'); wireFilters(el);
    el.querySelectorAll('[data-svc]').forEach(b => b.onclick = () => { putFilter({k:'service', v:b.dataset.svc, neg:false}); state.view = 'apps'; render(); }); } }
}
// ===================== (1.15.0) Usage: what each inside host downloaded and uploaded over a period =====================
// /api/usage — this month, last month or the last 7 – 365 days (as far as the edition keeps data), against the same
// length of time before it; visual first (Yegor's rule): cards, the days, who uses most and who changed, the table last.
const USAGE_PER = () => [['month', T('This month')], ['prev_month', T('Last month')], ['7', T('{n} d', {n:7})], ['30', T('{n} d', {n:30})], ['90', T('{n} d', {n:90})], ['180', T('{n} d', {n:180})], ['365', T('{n} d', {n:365})]];
const usageChange = (cur, prev) => prev ? Math.round(100 * (cur - prev) / prev) : null;
function usageDelta(cur, prev, big){        // ↑ 12% against the period before; new / — when there is nothing to compare with
  if (prev == null) return '';
  const ch = usageChange(cur, prev);
  if (ch == null) return cur ? `<span class="udelta up">${T('new')}</span>` : '';
  const col = Math.abs(ch) < 5 ? 'var(--ink2)' : ch > 0 ? 'var(--warn)' : 'var(--ok)';
  return `<span class="udelta${big ? ' big' : ''}" style="color:${col}">${ch > 0 ? '↑' : ch < 0 ? '↓' : '='} ${ch > 300 ? '×' + Math.round(cur / prev).toLocaleString(LOC) : Math.abs(ch) + '%'}</span>`;
}
function vUsage(){
  const v = document.getElementById('view'), per = state.usagePer || '30';
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12 caphead">${ph(USAGE_ICON, T('Usage'), T('what each inside host downloaded and uploaded · the filters and the traffic selector at the top apply'), '<span id="uPerBox"></span>', true)}</section>
    <div id="uKpi" style="display:contents"></div>
    <section class="glass panel s8">${ph('chart', T('Day by day'), `<span id="uChartSub">${T('downloaded and uploaded')}</span>`)}<div id="uChart" class="loading" style="height:420px"></div><p class="note" id="uNote"></p></section>
    <section class="glass panel s4">${ph('users', T('Who uses most'), T('the 10 busiest hosts · click for details'))}<div id="uTop" class="loading"></div></section>
    <section class="glass panel s6">${ph('pulse', T('Biggest changes'), `<span id="uMovSub">${T('against the period before')}</span>`)}<div id="uMov" class="loading"></div></section>
    <section class="glass panel s6">${ph('grid', T('By network'), T('your named networks · Settings → Flow configuration'))}<div id="uNets" class="loading"></div></section>
    <section class="glass panel s12">${ph('list', T('All hosts'), `<span id="uAllSub"></span>`, `<a class="btn" id="uCsv" href="#" download>${T('Download CSV')}</a>`)}<div id="uTable" class="loading"></div></section></div>`;
  const seq = renderSeq, done = (id, html) => { const el = fill(id, html); if (el) el.classList.remove('loading'); return el; };
  (async () => {
    let d;
    const qs = {period:per, tz:capTz(), t:state.traffic, f:JSON.stringify(state.filters)};
    try { d = await apiFetch(`api/usage?${new URLSearchParams(qs)}`); } catch (e) { done('uChart', errBox(e)); return; }
    if (seq !== renderSeq) return;
    if (d.error) { done('uChart', `<p class="err">${esc(d.error)}</p>`); return; }
    fill('uPerBox', seg('uPer', USAGE_PER().map(([k, l]) => [k, l, /^\d+$/.test(k) && +k > d.max_days ? T('Your edition shows {n} days', {n:d.max_days}) : '']), d.period));
    document.querySelectorAll('#uPer button').forEach(b => { if (/^\d+$/.test(b.dataset.v) && +b.dataset.v > d.max_days) b.disabled = true; });
    wireSeg('uPer', k => { if (k === d.period) return; state.usagePer = k; render(); });
    const tot = d.total, prev = d.prev, all = tot.up + tot.dn, hs = d.hosts;
    const dateR = (a, b) => `${new Date(a * 1000).toLocaleDateString(LOC, {day:'numeric', month:'short'})} – ${new Date((b - 1) * 1000).toLocaleDateString(LOC, {day:'numeric', month:'short', year:'numeric'})}`;
    // the cards
    const kc = (ic, k, val, sub, col) => `<section class="glass panel kcard s3" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic] || ic, 22)}</span><span class="k">${k}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span><span class="nat" style="grid-column:2">${sub}</span></section>`;
    const noPrev = d.since && d.since > d.prev_from ? T('no period before to compare with: data since {date}', {date:new Date(d.since * 1000).toLocaleDateString(LOC, {day:'numeric', month:'short'})}) : T('no period before to compare with: the edition keeps {n} days', {n:d.max_days});
    const vs = prev ? T('against {range}', {range:dateR(d.prev_from, d.prev_to)}) : noPrev;
    const top10 = hs.slice(0, 10).reduce((a, h) => a + h.up + h.dn, 0);
    fill('uKpi', kc('pulse', T('Downloaded'), `${fmtB(tot.dn)} ${usageDelta(tot.dn, prev && prev.dn, true)}`, vs, C.down)
      + kc('pulse', T('Uploaded'), `${fmtB(tot.up)} ${usageDelta(tot.up, prev && prev.up, true)}`, vs, C.up)
      + kc('users', T('Active hosts'), `${tot.hosts.toLocaleString(LOC)} ${usageDelta(tot.hosts, prev && prev.hosts, true)}`, dateR(d.from, d.to))
      + kc('pie', T('The 10 busiest'), all ? Math.round(100 * top10 / all) + '%' : '—', all ? T('of all traffic — {n} hosts in all', {n:tot.hosts.toLocaleString(LOC)}) : T('No traffic under this filter')));
    // day by day (month by month): stacked bars, bytes
    const el = done('uChart', '');
    if (el && d.series.length) {
      const c = mkChart(el), lab = t => new Date(t * 1000).toLocaleDateString(LOC, d.bucket === 'day' ? {day:'numeric', month:'short'} : {month:'short', year:'numeric'});
      c.setOption({animation:false, grid:{left:14, right:10, top:30, bottom:4, containLabel:true},
        legend:{top:0, right:0, icon:'roundRect', itemWidth:14, itemHeight:6, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
        tooltip:{...tipBase(), trigger:'axis', valueFormatter:v => fmtB(v)},
        xAxis:{type:'category', data:d.series.map(r => lab(r[0])), axisLine:{lineStyle:{color:C.hair}}, axisLabel:{color:C.ink3, fontFamily:'JetBrains Mono', fontSize:11}},
        yAxis:axisY(v => fmtB(v)),
        series:[{name:'↓ ' + T('Downloaded'), type:'bar', stack:'u', barMaxWidth:28, itemStyle:{color:C.down, borderRadius:[0, 0, 2, 2]}, data:d.series.map(r => r[2])},
                {name:'↑ ' + T('Uploaded'), type:'bar', stack:'u', barMaxWidth:28, itemStyle:{color:C.up, borderRadius:[3, 3, 0, 0]}, data:d.series.map(r => r[1])}]});
      fill('uChartSub', d.bucket === 'day' ? T('downloaded and uploaded, day by day') : T('downloaded and uploaded, month by month'));
    } else if (el) el.innerHTML = `<div class="empty">${T('No traffic under this filter')}</div>`;
    fill('uNote', d.cut ? T('The period starts {date}: older data is not kept by your edition ({n} days).', {date:new Date(d.from * 1000).toLocaleDateString(LOC), n:d.max_days}) : '');
    // who uses most: bars split in download / upload
    const bars = (rows, extra) => !rows.length ? `<div class="empty">${T('No traffic under this filter')}</div>` : '<div class="blist">' + rows.map(h => { const t = h.up + h.dn, mx = rows[0].up + rows[0].dn || 1;
      return `<button class="brow" data-host="${esc(h.k)}"><span class="n">${esc(h.name || h.k)}${h.name ? ` <span class="nat mono">${esc(h.k)}</span>` : ''}</span><span class="t">${fmtB(t)}</span><span class="p">${extra ? extra(h) : pct(t, all)}</span>
        <span class="bar2" style="width:${(100 * t / mx).toFixed(1)}%"><i class="d" style="width:${(100 * h.dn / (t || 1)).toFixed(1)}%;background:${C.down}"></i><i class="u" style="flex:1;background:${C.up}"></i></span></button>`; }).join('') + '</div>';
    const put = (id, html) => { const e = done(id, html); if (e) wireFilters(e); };
    put('uTop', bars(hs.slice(0, 10)));
    // biggest changes: the largest growth (and new hosts), then the largest drops
    if (!prev) { done('uMov', `<div class="empty">${noPrev}</div>`); }
    else {
      const ch = hs.map(h => ({...h, diff:(h.up + h.dn) - (h.prev_up + h.prev_dn)})).filter(h => Math.abs(h.diff) > 0);
      const grow = [...ch].sort((a, b) => b.diff - a.diff).filter(h => h.diff > 0).slice(0, 5), drop = [...ch].sort((a, b) => a.diff - b.diff).filter(h => h.diff < 0).slice(0, 3);
      fill('uMovSub', T('against {range}', {range:dateR(d.prev_from, d.prev_to)}));
      put('uMov', grow.length || drop.length ? bars([...grow, ...drop].sort((a, b) => (b.up + b.dn) - (a.up + a.dn)), h => usageDelta(h.up + h.dn, h.prev_up + h.prev_dn)) : `<div class="empty">${T('No changes worth showing')}</div>`);
    }
    // by named network
    const nets = new Map();
    for (const h of hs) { const k = h.net || ''; const e = nets.get(k) || {k, up:0, dn:0, n:0}; e.up += h.up; e.dn += h.dn; e.n++; nets.set(k, e); }
    const nl = [...nets.values()].filter(x => x.k).sort((a, b) => (b.up + b.dn) - (a.up + a.dn));
    done('uNets', !nl.length ? `<div class="empty">${T('Name your networks in Settings → Flow configuration to see the traffic of each one.')}</div>`
      : '<div class="blist">' + nl.map(x => `<button class="brow" data-f="net" data-v="${esc(x.k)}"><span class="n">${esc(x.k)} <span class="nat">${Tn(x.n, '{n} host', '{n} hosts')}</span></span><span class="t">${fmtB(x.up + x.dn)}</span><span class="p">${pct(x.up + x.dn, all)}</span>
          <span class="bar2" style="width:${(100 * (x.up + x.dn) / (nl[0].up + nl[0].dn || 1)).toFixed(1)}%"><i class="d" style="width:${(100 * x.dn / ((x.up + x.dn) || 1)).toFixed(1)}%;background:${C.down}"></i><i class="u" style="flex:1;background:${C.up}"></i></span></button>`).join('') + '</div>');
    wireFilters(document.getElementById('uNets'));
    // the table, last
    fill('uAllSub', d.more ? T('the {n} busiest of {all} · all of them: Download CSV', {n:hs.length.toLocaleString(LOC), all:tot.hosts.toLocaleString(LOC)}) : T('{n} hosts, the busiest first', {n:hs.length.toLocaleString(LOC)}));
    const csv = document.getElementById('uCsv');
    csv.href = `api/top?${new URLSearchParams({dim:'int_ip', limit:'all', format:'csv', from:d.from, to:d.to, t:state.traffic, f:JSON.stringify(state.filters)})}`;
    done('uTable', !hs.length ? `<div class="empty">${T('No traffic under this filter')}</div>` : `<div class="tw"><table class="compact utable"><thead><tr><th>${T('Host')}</th><th>${T('Network')}</th><th class="num">↓ ${T('Downloaded')}</th><th class="num">↑ ${T('Uploaded')}</th><th class="num">${T('Total')}</th><th class="num">${T('Share')}</th>${prev ? `<th class="num">${T('column::Change')}</th>` : ''}<th class="num">${T('Active days')}</th></tr></thead><tbody>
      ${hs.map(h => `<tr data-host="${esc(h.k)}"><td><b>${esc(h.name || h.k)}</b>${h.name ? `<div class="nat mono">${esc(h.k)}</div>` : ''}</td><td>${esc(h.net || '—')}</td><td class="num mono">${fmtB(h.dn)}</td><td class="num mono">${fmtB(h.up)}</td><td class="num mono"><b>${fmtB(h.up + h.dn)}</b></td><td class="num mono">${pct(h.up + h.dn, all)}</td>${prev ? `<td class="num mono">${usageDelta(h.up + h.dn, h.prev_up + h.prev_dn)}</td>` : ''}<td class="num mono">${h.days}</td></tr>`).join('')}</tbody></table></div>`);
    wireFilters(document.getElementById('uTable'));
  })();
}
// ===================== (1.16.0) QoS: the DSCP marking of the traffic =====================
// /api/qos under the period and the filters at the top — visual first: cards, the classes over time and their shares,
// the class mix of each interface, what the devices re-mark, the services of each class; the table of classes last.
// A class opens the other pages filtered by it (dscp:EF).
const DSCP_INFO = () => ({0:[T('Best effort'), '#6E7FA6'], 8:[T('Low-priority data'), '#4C5A7A'], 10:[T('High-throughput data'), '#2F7BFF'], 12:[T('High-throughput data'), '#2F7BFF'], 14:[T('High-throughput data'), '#2F7BFF'],
  16:[T('Network management'), '#5AC8FA'], 18:[T('Low-latency data'), '#27D3F5'], 20:[T('Low-latency data'), '#27D3F5'], 22:[T('Low-latency data'), '#27D3F5'],
  24:[T('Broadcast video / call signalling'), '#8B5CFF'], 26:[T('Multimedia streaming'), '#A879FF'], 28:[T('Multimedia streaming'), '#A879FF'], 30:[T('Multimedia streaming'), '#A879FF'],
  32:[T('Real-time interactive'), '#FF4FA0'], 34:[T('Video calls'), '#FFD166'], 36:[T('Video calls'), '#FFD166'], 38:[T('Video calls'), '#FFD166'],
  40:[T('Signalling'), '#FF9F43'], 44:[T('Voice (admitted)'), '#FF5C7A'], 46:[T('Voice'), '#FF5C7A'], 48:[T('Network control'), '#2EE59D'], 56:[T('Network control'), '#2EE59D'], 255:[T('Not reported by the device'), '#2A3550']});
const dscpName = (names, k) => names[String(k)] || ('DSCP ' + k);
const dscpInfo = k => DSCP_INFO()[k] || [T('Non-standard marking'), '#B0B8CC'];
const dscpLabel = (names, k) => k === 255 ? T('not reported') : dscpName(names, k);
function vQos(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12 caphead">${ph(QOS_ICON, T('QoS'), T('how the traffic is marked (DSCP) as it enters each device · the period and the filters at the top apply · click a class to filter by it'), '', true)}</section>
    <div id="qKpi" style="display:contents"></div>
    <section class="glass panel s8">${ph('chart', T('Classes over time'), T('traffic of each class'))}<div id="qChart" class="loading" style="height:340px"></div></section>
    <section class="glass panel s4">${ph('pie', T('Share of each class'), T('of the traffic in the period'))}<div id="qDonut" class="loading" style="height:340px"></div></section>
    <section class="glass panel s6">${ph('ip', T('Interfaces'), T('the class mix of what enters each interface'))}<div id="qIfs" class="loading"></div></section>
    <section class="glass panel s6">${ph('pulse', T('Re-marked by the devices'), T('class on the way in → class on the way out'))}<div id="qRemark" class="loading"></div></section>
    <section class="glass panel s12">${ph('grid', T('Services in each class'), T('the 5 biggest of each'))}<div id="qSvc" class="loading"></div></section>
    <section class="glass panel s12">${ph('list', T('Classes'), T('click to filter every page by the class'))}<div id="qTable" class="loading"></div></section></div>`;
  const seq = renderSeq, done = (id, html) => { const el = fill(id, html); if (el) el.classList.remove('loading'); return el; };
  (async () => {
    let d;
    try { d = await api('qos'); } catch (e) { done('qChart', errBox(e)); return; }
    if (seq !== renderSeq) return;
    const N = d.names, cls = d.classes, all = cls.reduce((a, c) => a + c.bytes, 0);
    const known = cls.filter(c => c.k !== 255), kb = known.reduce((a, c) => a + c.bytes, 0), unk = all - kb;
    const marked = known.filter(c => c.k !== 0).reduce((a, c) => a + c.bytes, 0);
    const rt = known.filter(c => [46, 44, 40, 34, 36, 38, 32].includes(c.k)).reduce((a, c) => a + c.bytes, 0);
    const rem = d.remarked.reduce((a, r) => a + r.bytes, 0);
    const kc = (ic, k, val, sub, col) => `<section class="glass panel kcard s3" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic] || ic, 22)}</span><span class="k">${k}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span><span class="nat" style="grid-column:2">${sub}</span></section>`;
    fill('qKpi', kc('shield', T('Marked'), kb ? pct(marked, kb) : '—', kb ? T('of the traffic carries a class other than best effort') : T('No device reports the marking yet'), kb ? '' : 'var(--ink3)')
      + kc('pulse', T('Voice and video'), fmtB(rt), kb ? T('EF, signalling and video-call classes · {pct} of the marked traffic', {pct:pct(rt, marked || 1)}) : '—', rt ? '#FF5C7A' : '')
      + kc('conv', T('Re-marked'), d.both_known ? pct(rem, d.both_known) : '—', d.both_known ? T('of the traffic leaves a device in another class') : T('the devices do not report the class on the way out'), rem ? 'var(--warn)' : '')
      + kc('ip', T('Not reported'), all ? pct(unk, all) : '—', unk ? T('traffic of devices (or of times) without the marking in their export') : T('every device reports the marking'), unk ? 'var(--ink2)' : 'var(--ok)'));
    if (!all) { ['qChart', 'qDonut', 'qIfs', 'qRemark', 'qSvc', 'qTable'].forEach(id => done(id, `<div class="empty">${T('No traffic under this filter')}</div>`)); return; }
    // classes over time: stacked areas, the class colours
    const order = cls.map(c => c.k), ts = [...new Set(d.series.map(r => r[0]))].sort((a, b) => a - b), m = new Map(d.series.map(r => [r[0] + ':' + r[1], r[2]]));
    const ch = zoomable(mkChart(done('qChart', '')));     // (1.16.1) drag across it for that stretch of time, as on Ports / Services
    ch.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true},
      legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}, type:'scroll'},
      tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(ts), yAxis:axisY(v => fmtR(v)),
      series:order.map(k => ({name:dscpLabel(N, k), type:'line', stack:'q', smooth:.25, showSymbol:false, lineStyle:{width:1.2, color:dscpInfo(k)[1]},
        itemStyle:{color:dscpInfo(k)[1]}, areaStyle:{opacity:k === 255 ? .25 : .45}, data:ts.map(t => [t * 1000, (m.get(t + ':' + k) || 0) * 8 / d.step])}))});
    donut(done('qDonut', ''), cls.map(c => ({k:dscpLabel(N, c.k), up:c.bytes, dn:0})), k => dscpInfo(cls.find(c => dscpLabel(N, c.k) === k).k)[1], [kb ? pct(marked, kb) : '—', T('marked')]);
    // interfaces: one bar each, split by class
    const ifs = d.interfaces.slice(0, 12), top = Math.max(1, ...ifs.map(x => x.bytes));
    done('qIfs', !ifs.length ? `<div class="empty">${T('No traffic under this filter')}</div>` : '<div class="qifs">' + ifs.map(x => `<div class="qif"><div class="qifh"><b>${esc(x.name)}</b> <span class="nat">${esc(x.device_name)}</span><span class="mono nat">${fmtB(x.bytes)}</span></div>
      <div class="qbar" style="width:${(100 * x.bytes / top).toFixed(1)}%">${Object.entries(x.classes).sort((a, b) => b[1] - a[1]).map(([k, b]) => `<i style="width:${(100 * b / x.bytes).toFixed(2)}%;background:${dscpInfo(+k)[1]}" title="${esc(dscpLabel(N, +k))}: ${esc(fmtB(b))} · ${pct(b, x.bytes)}"></i>`).join('')}</div></div>`).join('') + '</div>');
    // re-marking
    done('qRemark', d.remarked.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('Device')}</th><th>${T('In')}</th><th></th><th>${T('Out')}</th><th class="num">${T('Traffic')}</th></tr></thead><tbody>
      ${d.remarked.map(r => `<tr><td>${esc(r.device_name)}</td><td><span class="dscp" style="--c:${dscpInfo(r.from)[1]}">${esc(dscpName(N, r.from))}</span></td><td>→</td><td><span class="dscp" style="--c:${dscpInfo(r.to)[1]}">${esc(dscpName(N, r.to))}</span></td><td class="num mono">${fmtB(r.bytes)}</td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${d.both_known ? T('No device changed the class of the traffic in this period.') : T('The devices do not report the class on the way out (FortiGate does), so re-marking cannot be seen.')}</div>`);
    // services of each class
    const byK = new Map(); for (const sv of d.services) { if (!byK.has(sv.k)) byK.set(sv.k, []); byK.get(sv.k).push(sv); }
    done('qSvc', '<div class="qsvc">' + cls.filter(c => byK.has(c.k)).slice(0, 8).map(c => `<div><h5><span class="dscp" style="--c:${dscpInfo(c.k)[1]}">${esc(dscpLabel(N, c.k))}</span> <span class="nat">${esc(dscpInfo(c.k)[0])}</span></h5>
      <div class="blist">${byK.get(c.k).map(sv => `<button class="brow" data-f="service" data-v="${esc(sv.service)}"><span class="n">${esc(sv.service)}</span><span class="t">${fmtB(sv.bytes)}</span><span class="p">${pct(sv.bytes, c.bytes)}</span>
        <span class="bar2" style="width:${(100 * sv.bytes / (byK.get(c.k)[0].bytes || 1)).toFixed(1)}%"><i class="d" style="flex:1;background:${dscpInfo(c.k)[1]}"></i></span></button>`).join('')}</div></div>`).join('') + '</div>');
    wireFilters(document.getElementById('qSvc'));
    // the classes, last
    done('qTable', `<div class="tw"><table class="compact"><thead><tr><th>${T('Class')}</th><th class="num">DSCP</th><th>${T('Meant for')}</th><th class="num">${T('Traffic')}</th><th class="num">${T('Share')}</th><th class="num">${T('Packets')}</th><th class="num">${T('Flows')}</th></tr></thead><tbody>
      ${cls.map(c => `<tr data-f="dscp" data-v="${c.k === 255 ? '255' : esc(dscpName(N, c.k))}" style="cursor:pointer"><td><span class="dscp" style="--c:${dscpInfo(c.k)[1]}">${esc(dscpLabel(N, c.k))}</span></td><td class="num mono">${c.k === 255 ? '—' : c.k}</td><td>${esc(dscpInfo(c.k)[0])}</td>
        <td class="num mono">${fmtB(c.bytes)}</td><td class="num mono">${pct(c.bytes, all)}</td><td class="num mono">${fmtN(c.packets)}</td><td class="num mono">${fmtN(c.flows)}</td></tr>`).join('')}</tbody></table></div>
      <p class="note">${T('DSCP is the class a sender or a device puts on each packet so the network can give it priority (voice before downloads). FortiGate reports the class on the way in and on the way out (re-marking shows); MikroTik on the way in. «Not reported»: traffic from before FlowTrack 1.16 or from devices that do not export it.')}</p>`);
    wireFilters(document.getElementById('qTable'));
  })();
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
    <section class="glass panel s5">${ph('ip', T('Interfaces'), T('traffic entering and leaving each interface'))}<div id="pIfs" class="loading"></div></section>
    <section class="glass panel s12">${ph('pulse', T('Interface load'), T('all traffic through each interface against its capacity · 5-minute averages · the fullest first'))}<div id="pLoad" class="loading"></div></section></div>`;
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
    if (!dev) { fill('cPaths', `<div class="empty">${T('No device has sent data yet')}</div>`); const pl = fill('pLoad', ''); if (pl) pl.classList.remove('loading'); return; }
    ifLoadPanel(ip, seq);
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
    const mapEl = document.getElementById('cPaths'); let wb = null;
    if (mapEl) createDevMap(mapEl, {ifs, dev, refreshMs:live ? 10000 : 0, onPick:pickMap, onData:() => { if (wb) wb.stop(); },
      fetchData:() => api('devmap', {t:state.traffic, metric:state.metric, live:live ? 1 : 0, win:120, top:6}, extra)});
    if (mapEl && mapEl.querySelector('canvas')) wb = waitBig(mapEl, 'device', sketchDevice(dev, ifs));   // (1.8.5) a sketch until the first answer
    try { draw(await load()); } catch (e) { fill('pTable', errBox(e)); }
    if (live) every(10000, () => load().then(d => { if (seq === renderSeq) draw(d); }).catch(() => {}));
  })().catch(e => fill('cPaths', errBox(e)));
}
// ===================== path analysis: layer-3 neighbours of a device and the path of traffic across devices =====================
const LINK_STATE = {
  observed:[T('Observed'), T('traffic recorded by both ends')],
  gap:[T('Gap'), T('one end sends traffic towards the other and gets nothing back; the other end records nothing at all')],
  silent:[T('One end silent'), T('the link works (traffic comes back), but one end records nothing on its interface: NetFlow is probably off there')],
  unobserved:[T('No observation'), T('the other end sends no NetFlow')],
  one_sided:[T('One side'), T('the interface of the other end towards this one is not known')],
  adjacent:[T('No traffic'), T('neighbours by addressing, no traffic in the period')]};
const HOP_STATE = {observed:T('recorded'), gap:T('recorded nothing on that interface — gap'), not_seen:T('not seen here — another route?'), silent:T('its interface records nothing — NetFlow off?'), unobserved:T('sends no NetFlow'),
  internet:T('the internet'), branch:T('on another exit'), unplaced:T('recorded it, place on the path unknown')};
const RED = '#FF5C7A', AMBER = '#FFC34D';
// (1.9.2) why the two ends of a link do not agree, in words: a working network differs a lot (sampling, timing,
// asymmetric routes, tunnels, a big download one way); a gap is only real traffic towards a silent interface
function linkHints(l, nmOf, live){
  if (l.b === 'internet' || l.state === 'adjacent' || l.state === 'unobserved' || l.state === 'one_sided') return [];
  l = {...l, ...(l.all || {})};          // all the traffic, as the state was found (the selector narrows only the drawing)
  const out = [], A = nmOf(l.a), B = nmOf(l.b);
  if (l.state === 'silent') {
    const silentB = !(l.b_out + l.b_in), [S, Sif, R, back] = silentB ? [B, l.b_name, A, l.a_in] : [A, l.a_name, B, l.b_in];
    out.push(T('{s} records nothing on {iface}, but {r} received {bytes} from it: the link works.', {s:S, iface:`<span class="mono">${esc(Sif || '?')}</span>`, r:R, bytes:fmtB(back)}));
    out.push(T('NetFlow is probably off on that interface (FortiGate: set netflow-sampler both; tunnel interfaces need it too). Until then FlowTrack sees this link from one end only.'));
    return out;
  }
  if (l.state === 'gap') {
    const silentB = !(l.b_out + l.b_in), [S, Sif, R, sent] = silentB ? [B, l.b_name, A, l.a_out] : [A, l.a_name, B, l.b_out];
    out.push(T('{s} recorded nothing on {iface} — no packets either way — while {r} sent {bytes} towards it and got nothing back.', {s:S, iface:`<span class="mono">${esc(Sif || '?')}</span>`, r:R, bytes:fmtB(sent)}));
    out.push(T('Check that NetFlow is on for that interface (FortiGate: set netflow-sampler both), that its number matches in Settings → Devices, and that the link is up.'));
    if (live) out.push(T('Over 2 minutes a quiet end may not have reported its sessions yet: see the Period view.'));
    return out;
  }
  for (const [f, t, sent, got] of [[A, B, l.a_out, l.b_in], [B, A, l.b_out, l.a_in]])
    if (sent >= 100e3 && got < sent * .9) out.push(T('{t} recorded {p}% of what {f} sent towards it.', {t, f, p:Math.round(100 * got / sent)}));
  if (out.length) out.push(T('Usual in a working network: sampled exports, sessions reported at different times, traffic coming back another way, tunnels (the inner traffic is recorded on the tunnel interface), traffic to the device itself, policy drops.'));
  return out;
}
const hopHint = (h, prevName) => h.state === 'silent' ? T('{d} records nothing on its interface towards {p}, although the link works: NetFlow is probably off on that interface.', {d:esc(h.name), p:prevName})
  : h.state === 'not_seen' ? T('{d} carried other traffic on its interface towards {p}, but not this: it probably went another way (asymmetric routing, another exit) or through a tunnel.', {d:esc(h.name), p:prevName})
  : h.state === 'gap' ? T('{d} recorded nothing at all on its interface towards {p}: check that NetFlow is on for it.', {d:esc(h.name), p:prevName}) : '';
const devIcon = n => n.ip === 'internet' ? ICO.globe : DEV_ICON;
function createTopoMap(host, opts){
  host.innerHTML = '<div class="netin"><canvas></canvas><div class="rtip" hidden></div></div>';
  const box = host.firstChild, cv = box.querySelector('canvas'), tip = box.querySelector('.rtip'), main = cv.getContext('2d');
  let ctx = main;          // (1.9.0) the live views draw their still part into a hidden canvas (ctx), then move over it
  const mode = () => (opts.mode ? opts.mode() : 'classic'), thin = () => mode() !== 'classic';
  let W = 0, H = 0, dpr = 1, data = null, hover = null, shapes = [], centred = null, GAP = 184;
  const CW = 136, CH = 74;                // card size; GAP: room between columns for the interface labels
  const BASE0 = host.getBoundingClientRect().height || 560;     // the map grows taller than this when the cards need it
  // (1.9.2) full screen: the map is as tall as the panel gives it (drawn again for it, never stretched)
  const maxed = () => !!host.closest('section.is-max');
  let BASE = BASE0;
  // ribbon width by volume; one link end on a card side takes a slot: its label (name over address) above its ribbon
  const v = x => state.scale === 'lin' ? x : Math.sqrt(x), vol2 = l => Math.max(l.a_out, l.b_in) + Math.max(l.b_out, l.a_in);
  let vmax = 1; const lw = x => x > 0 && !thin() ? 2 + 14 * v(x) / vmax : 0, slot = l => 40 + lw(vol2(l)), WAN_PAD = 40;
  const CLW = 132, CLH = 36, UP = 84;     // (1.8.10) the internet as in the waiting sketch: a pill on top; UP: room under it for the WAN ribbons and their labels
  function size(){ BASE = maxed() ? Math.max(BASE0, Math.floor(host.parentElement.getBoundingClientRect().bottom - host.getBoundingClientRect().top - 22)) : BASE0;
    const r = host.getBoundingClientRect(); H = r.height; dpr = Math.min(2, devicePixelRatio || 1); draw(); }
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
    const wan = data.links.filter(l => l.b === 'internet' && col.has(l.a)), hasWan = new Set(wan.map(l => l.a));
    const top = wan.length ? 12 + CLH + UP : 12;            // devices start under the cloud
    // a card is as tall as the slots of its busier side; a card with a WAN link keeps room above it for that label
    const sides = new Map(), sameCol = new Set();
    for (const l of data.links) { if (l.b === 'internet' || !col.has(l.a) || !col.has(l.b)) continue;
      if (col.get(l.a) === col.get(l.b)) { sameCol.add(col.get(l.a)); continue; }      // drawn down the column, no slot
      for (const [me, other] of [[l.a, l.b], [l.b, l.a]]) { const k = me + (col.get(other) > col.get(me) ? '>R' : '>L'); sides.set(k, (sides.get(k) || 0) + slot(l)); } }
    const hOf = n => Math.max(CH, ...['>L', '>R'].map(k => (sides.get(n + k) || 0) + 16)), padOf = n => hasWan.has(n) ? WAN_PAD : 0;
    const gOf = c => sameCol.has(c) ? 44 : 24;     // room for a link between two cards of one column and its state
    const colH = c => { const list = [...col.keys()].filter(n => col.get(n) === c); return list.reduce((s, n) => s + padOf(n) + hOf(n), 0) + gOf(c) * (list.length - 1); };
    H = Math.max(BASE, top + Math.max(...cols.map(colH)) + 12);
    const pos = new Map();
    // the middle column first, then outwards: each column ordered by its parents' height, then centred on them
    for (const c of [...cols].sort((a, b) => Math.abs(a) - Math.abs(b) || b - a)) {
      const list = [...col.keys()].filter(n => col.get(n) === c).sort((a, b) => ((pos.get(parent.get(a)) || {}).y || 0) - ((pos.get(parent.get(b)) || {}).y || 0));
      const room = H - top - 12, total = list.reduce((s, n) => s + padOf(n) + hOf(n), 0), gap = Math.min(56, Math.max(gOf(c), (room - total) / Math.max(1, list.length)));
      let y = top + Math.max(0, (room - total - gap * (list.length - 1)) / 2);
      const ys = list.map(n => { y += padOf(n); const m = y + hOf(n) / 2; y += hOf(n) + gap; return m; });
      if (c !== 0 && list.length) {
        const want = list.reduce((s, n) => s + ((pos.get(parent.get(n)) || {y:(top + H) / 2}).y), 0) / list.length, cur = ys.reduce((s, v) => s + v, 0) / ys.length;
        const f = list[0], e = list[list.length - 1];
        const d = Math.max(top + padOf(f) + hOf(f) / 2 - ys[0], Math.min(H - 12 - hOf(e) / 2 - ys[ys.length - 1], want - cur));
        ys.forEach((v, k) => ys[k] = v + d);
      }
      list.forEach((n, k) => pos.set(n, {x:xs(c), y:ys[k], w:CW, h:hOf(n), c}));
    }
    // the cloud over the devices that reach the internet
    const wx = wan.map(l => pos.get(l.a).x), cx = wx.length ? Math.max(14 + CLW / 2, Math.min(W - 14 - CLW / 2, (Math.min(...wx) + Math.max(...wx)) / 2)) : W / 2;
    return {pos, cloud:wan.length ? {x:cx, y:12 + CLH / 2, w:CLW, h:CLH} : null};
  }
  // the internet: a rounded pill, as in the waiting sketch (it was a big cloud)
  const cloudPath = ({x, y, w, h}) => rr(x - w / 2, y - h / 2, w, h, h / 2);
  // (1.9.0) shared by every view: names, tooltips
  const nmOf = d => esc(d === 'internet' ? T('Internet') : ((data && data.nodes.find(n => n.ip === d)) || {}).name || d);
  const linkTip = l => `<b>${nmOf(l.a)} ${esc(l.a_name)} ↔ ${nmOf(l.b)} ${esc(l.b_name)}</b>${l.net ? ` <span class="nat">${esc(l.net)}</span>` : ''}<div style="color:${l.state === 'observed' ? C.ext : l.state === 'adjacent' || l.state === 'one_sided' ? C.ink2 : RED}">${LINK_STATE[l.state][0]} — ${LINK_STATE[l.state][1]}</div>`
      + (l.b === 'internet' ? `<div>${T('to the internet')}: <b class="mono">${fmtB(l.a_out)}</b> · ${T('from it')}: <b class="mono">${fmtB(l.a_in)}</b></div>`
        : [[l.a, l.b, l.a_out, l.b_in], [l.b, l.a, l.b_out, l.a_in]].map(([f, t, s, g]) => `<div>${nmOf(f)} → ${nmOf(t)}: <b class="mono">${fmtB(s)}</b> ${T('sent')} · <b class="mono">${fmtB(g)}</b> ${T('received')}</div>`).join('')) + linkHints(l, nmOf, !!(data && data.live)).map(x => `<div class="lhint">${x}</div>`).join('');
  const nodeTip = n => `<b>${nmOf(n.ip)}</b>${n.ip !== 'internet' ? ` <span class="nat">${esc(n.ip)}</span><div>${n.exporting ? T('sends NetFlow') : T('sent no NetFlow in this period')}</div>` : ''}${n.more ? `<div>${Tn(n.more, '{n} more neighbour beyond', '{n} more neighbours beyond')}</div>` : ''}${n.ip !== data.pov && n.ip !== 'internet' ? `<div class="nat">${T('Click: look from this device')}</div>` : ''}`;
  const inetTip = () => `<b>${T('Internet')}</b>` + data.links.filter(l => l.b === 'internet').map(l => `<div>${nmOf(l.a)} <span class="mono">${esc(l.a_name)}</span>: ↗ <b class="mono">${fmtB(l.a_out)}</b> · ↘ <b class="mono">${fmtB(l.a_in)}</b></div>`).join('');
  function drawClassic(){
    if (!H) return;
    if (!data) { W = host.clientWidth; return; }
    vmax = Math.max(1e-9, ...data.links.map(l => v(vol2(l))));
    const {pos, cloud} = data.nodes.length ? layout() : {pos:new Map(), cloud:null};
    if (!data.nodes.length) { W = host.clientWidth; H = BASE; }
    const hs = H > BASE || maxed() ? H + 'px' : '';
    if (host.style.height !== hs) host.style.height = hs;     // the ResizeObserver draws again at the new height
    box.style.width = W + 'px'; cv.width = W * dpr; cv.height = H * dpr; cv.style.width = W + 'px'; cv.style.height = H + 'px'; sizeBg();
    if (centred !== data.pov && pos.has(data.pov)) { centred = data.pov; host.scrollLeft = Math.max(0, pos.get(data.pov).x - host.clientWidth / 2); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H); shapes = [];
    ctx.textBaseline = 'middle'; ctx.lineCap = 'round';
    if (!data.nodes.length) { ctx.font = '600 13px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.textAlign = 'center'; ctx.fillText(T('No device has sent data yet'), W / 2, H / 2); return; }
    const node = new Map(data.nodes.map(n => [n.ip, n])), onPath = opts.pathSet ? opts.pathSet() : null;
    const nm = nmOf;
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
    const stateLook = l => l.state === 'adjacent' ? ['rgba(170,190,230,.55)', T('no traffic')] : l.state === 'silent' ? [AMBER, '◌ ' + LINK_STATE.silent[0]] : l.state === 'gap' || l.state === 'unobserved' ? [RED, '⨯ ' + LINK_STATE[l.state][0]] : null;
    const tipOf = linkTip;
    // where each link meets a card: the links on one side of a card get a slot each down its height, ordered by the
    // far end; the ribbon leaves at the bottom of its slot, its label sits above it
    const ends = new Map(), anchor = new Map();
    for (const l of data.links) { const A = pos.get(l.a), B = pos.get(l.b); if (!A || !B) continue;
      if (A.c === B.c) continue;
      for (const [me, other, P, Q] of [[l.a, l.b, A, B], [l.b, l.a, B, A]]) { const k = me + (Q.c > P.c ? '>R' : '>L'); if (!ends.has(k)) ends.set(k, []); ends.get(k).push({l, me, y:Q.y}); } }
    for (const list of ends.values()) { list.sort((a, b) => a.y - b.y); const n = list.length;
      let y = -list.reduce((s, e) => s + slot(e.l), 0) / 2;
      list.forEach((e, k) => { const dy = n === 1 ? 0 : y + 34 + lw(vol2(e.l)) / 2; y += slot(e.l);
        anchor.set(e.l, {...anchor.get(e.l), [e.me === e.l.a ? 'a' : 'b']:{dy, first:k === 0, last:k === n - 1, n}}); }); }
    // the WAN ribbons: spread along the card top (several WANs) and along the cloud bottom (ordered by device)
    const up = new Map();
    if (cloud) {
      const wl = data.links.filter(l => l.b === 'internet' && pos.has(l.a)), per = new Map();
      wl.forEach(l => { if (!per.has(l.a)) per.set(l.a, []); per.get(l.a).push(l); });
      for (const list of per.values()) list.forEach((l, k) => up.set(l, {dx:list.length === 1 ? 0 : -24 + 48 * k / (list.length - 1)}));
      const order = [...wl].sort((a, b) => pos.get(a.a).x + up.get(a).dx - pos.get(b.a).x - up.get(b).dx), span = Math.min(cloud.w * .7, 22 * (order.length - 1));
      order.forEach((l, k) => { up.get(l).cx = cloud.x + (order.length === 1 ? 0 : -span / 2 + span * k / (order.length - 1)); });
    }
    const labels = [], pills = [], sameK = new Map();
    for (const l of data.links) {
      const A = pos.get(l.a), B = pos.get(l.b);
      const dim = onPath && !(onPath.has(l.a) && onPath.has(l.b));    // a WAN ribbon stays lit only on a path to / from the internet
      const w = lw(Math.max(l.a_out, l.b_in) + Math.max(l.b_out, l.a_in)), look = stateLook(l);
      ctx.globalAlpha = dim ? .15 : 1;
      if (l.b === 'internet') {
        // up from the top of the card into the cloud; the WAN interface (name over address) beside the ribbon
        const e = up.get(l); if (!A || !e) { ctx.globalAlpha = 1; continue; }
        const rw = Math.min(w, 14), xd = A.x + e.dx, yd = A.y - A.h / 2, xc = e.cx, yc = cloud.y + cloud.h / 2 - 1, ym = (yd + yc) / 2;
        const curve = off => { const p = new Path2D(); p.moveTo(xd + off, yd); p.bezierCurveTo(xd + off, ym, xc + off, ym, xc + off, yc); return p; };
        if (thin()) { thinLine(curve(0), l); geoms.set(l, mkGeo(cubicPts([xd, yd], [xd, ym], [xc, ym], [xc, yc]), false)); }
        if (w && l.state !== 'adjacent') ribbon(curve, l, rw, false);
        if (look) { ctx.setLineDash([5, 5]); ctx.strokeStyle = look[0]; ctx.lineWidth = 1.6; ctx.stroke(curve(w ? rw / 2 + 4 : 0)); ctx.setLineDash([]); }
        const inward = xc >= xd;                  // the label on the cloud's side of the ribbon: it stays inside the map
        labels.push({parts:[l.a_name, l.a_addr], x:inward ? xd + rw / 2 + 8 : xd - rw / 2 - 8, top:yd - 36, align:inward ? 'left' : 'right', room:GAP / 2 + CW / 2 - 12, dim});
        ctx.globalAlpha = 1;
        const hit = new Path2D(); hit.moveTo(xd, yd); hit.bezierCurveTo(xd, ym, xc, ym, xc, yc); shapes.push({stroke:hit, sw:Math.max(12, rw + 6), l, tip:tipOf(l)});
        continue;
      }
      if (!A || !B) { ctx.globalAlpha = 1; continue; }
      if (A.c === B.c) {
        // two devices of one column: from the bottom of the upper card to the top of the lower one, bowed outwards
        // when a card lies between them; the interfaces are in the tooltip and the table
        const U = A.y < B.y ? A : B, D = U === A ? B : A, k = (sameK.get(U.c) || 0); sameK.set(U.c, k + 1);
        const xu = U.x + U.w / 2 - 22 - 16 * (k % 3), yu = U.y + U.h / 2, yd2 = D.y - D.h / 2, rw = Math.min(w, 10);
        const out = (U.c < 0 ? -1 : 1) * ([...pos.values()].some(P => P.c === U.c && P.y > U.y && P.y < D.y) ? U.w / 2 + 40 : 0);
        const curve = off => { const p = new Path2D(); p.moveTo(xu + off, yu); p.bezierCurveTo(xu + off + out, yu + 30, xu + off + out, yd2 - 30, xu + off, yd2); return p; };
        if (thin()) { thinLine(curve(0), l); geoms.set(l, mkGeo(cubicPts([xu, yu], [xu + out, yu + 30], [xu + out, yd2 - 30], [xu, yd2]), U !== A)); }
        if (w && l.state !== 'adjacent') ribbon(curve, l, rw, false);
        if (look) { ctx.setLineDash([5, 5]); ctx.strokeStyle = look[0]; ctx.lineWidth = 1.6; ctx.stroke(curve(w ? rw / 2 + 4 : 0)); ctx.setLineDash([]); }
        if (look) pills.push([look[1], xu + out * .75, (yu + yd2) / 2, look[0], dim]);
        ctx.globalAlpha = 1;
        shapes.push({stroke:curve(0), sw:Math.max(12, rw + 6), l, tip:tipOf(l)});
        continue;
      }
      const L = A.x <= B.x ? A : B, R = L === A ? B : A, flip = L !== A, an = anchor.get(l) || {}, ea = (flip ? an.b : an.a) || {dy:0, n:1}, eb = (flip ? an.a : an.b) || {dy:0, n:1};
      const xa = L.x + L.w / 2, xb = R.x - R.w / 2, ya = L.y + ea.dy, yb = R.y + eb.dy, xm = (xa + xb) / 2;
      const curve = off => { const p = new Path2D(); p.moveTo(xa, ya + off); p.bezierCurveTo(xm, ya + off, xm, yb + off, xb, yb + off); return p; };
      if (thin()) { thinLine(curve(0), l); geoms.set(l, mkGeo(cubicPts([xa, ya], [xm, ya], [xm, yb], [xb, yb]), flip)); }
      if (w && l.state !== 'adjacent') ribbon(curve, l, w, true);
      if (look) { ctx.setLineDash([5, 5]); ctx.strokeStyle = look[0]; ctx.lineWidth = 1.6; ctx.stroke(curve(w ? w / 2 + 4 : 0)); ctx.setLineDash([]); }
      // interface · address at each end, on the side the ribbon bends away from (two lines when one does not fit)
      const la = flip ? [l.b_name, l.b_addr] : [l.a_name, l.a_addr], lb = flip ? [l.a_name, l.a_addr] : [l.b_name, l.b_addr], room = (xb - xa) / 2 - (look ? 44 : 12);     // half the gap each: the state sits in the middle
      // several links on a card side: each label in its slot above its ribbon; a lone link: the side its ribbon bends away from
      const sideOf = (e, bendsUp) => e.n > 1 ? -1 : bendsUp ? 1 : -1;
      labels.push({parts:la, x:xa + 7, y:ya, align:'left', side:sideOf(ea, yb < ya - 2), w, room, dim});
      if (l.b !== 'internet') labels.push({parts:lb, x:xb - 7, y:yb, align:'right', side:eb.n > 1 ? sideOf(eb, false) : (ya > yb + 2 ? -1 : 1), w, room, dim});
      if (look) pills.push([look[1], xm, (ya + yb) / 2, look[0], dim]);
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
    for (const [t, x, y, c, d] of pills) { ctx.globalAlpha = d ? .15 : 1; pill(t, x, y, c); }     // the link states over the labels
    ctx.globalAlpha = 1;
    if (cloud) {
      const cp = cloudPath(cloud), wl = data.links.filter(l => l.b === 'internet' && pos.has(l.a));
      const dim = onPath && !onPath.has('internet'), on = hover && hover.cloud;
      ctx.globalAlpha = dim ? .35 : 1;
      ctx.fillStyle = 'rgba(14,30,66,.97)'; ctx.fill(cp);
      ctx.strokeStyle = on ? 'rgba(46,229,157,.95)' : 'rgba(46,229,157,.6)'; ctx.lineWidth = 1.4; ctx.shadowColor = 'rgba(46,229,157,.45)'; ctx.shadowBlur = on ? 18 : 10; ctx.stroke(cp); ctx.shadowBlur = 0;
      ctx.font = '700 13px Manrope, sans-serif'; const tw = ctx.measureText(T('Internet')).width, gx = cloud.x - (tw + 24) / 2;      // the globe and the word, centred
      ctx.save(); ctx.translate(gx, cloud.y - 8); ctx.scale(.9, .9); ctx.strokeStyle = C.ext; ctx.lineWidth = 1.5; ctx.stroke(new Path2D(ICO.globe)); ctx.restore();
      ctx.textAlign = 'left'; ctx.fillStyle = C.ink; ctx.fillText(T('Internet'), gx + 24, cloud.y + .5);
      ctx.globalAlpha = 1;
      shapes.push({path:cp, cloud:true, tip:inetTip()}); void wl;
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
      shapes.push({path:card, n, tip:nodeTip(n)});
    }
  }
  // ===================== (1.9.0) live views: Lines, Stars, Metro, River =====================
  // The still part (lines, devices, labels) is drawn once into a hidden canvas and copied each frame; over it the
  // traffic moves: light particles along each link in the direction it really goes, as many and as fast as its rate
  // (Mbit/s over the window: the last 2 min live, else the period's average), coloured by direction — from the
  // internet, to the internet, inside. 30 fps at most, nothing moves when the tab is hidden or motion is reduced.
  const geoms = new Map(), bands = new Map();
  let bgCv = null, parts = [], acc = new Map(), raf = 0, lastT = 0, dist = new Map(), placed = [];
  // (1.9.2) a link is known by its ends and interface, not by the object of one answer: a refresh (every 10 s live)
  // keeps the particles flying and eases the rates to the new values instead of starting over
  const lkey = l => l.a + '|' + l.b + '|' + (l.a_name || '');
  const geoByKey = new Map(), linkByKey = new Map(), eased = new Map(), phase = new Map();
  const sizeBg = () => { if (ctx !== main && bgCv) { bgCv.width = cv.width; bgCv.height = cv.height; } };
  const cubicPts = (p0, p1, p2, p3, n = 40) => Array.from({length:n + 1}, (_, i) => { const t = i / n, u = 1 - t;
    return [u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0], u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1]]; });
  function mkGeo(pts, rev){
    const cum = [0]; for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
    const len = cum[cum.length - 1] || 1, path = new Path2D(); path.moveTo(pts[0][0], pts[0][1]); for (let i = 1; i < pts.length; i++) path.lineTo(pts[i][0], pts[i][1]);
    const at = t => { const d = Math.max(0, Math.min(1, t)) * len; let lo = 0, hi = cum.length - 1;
      while (hi - lo > 1) { const m = (lo + hi) >> 1; if (cum[m] < d) lo = m; else hi = m; }
      const k = (d - cum[lo]) / ((cum[hi] - cum[lo]) || 1), a = pts[lo], b = pts[hi];
      return [a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k, Math.atan2(b[1] - a[1], b[0] - a[0])]; };
    return {pts, len, path, at, rev};
  }
  // straight, 45°, straight, with rounded corners (Metro)
  function roundPoly(P, R = 16){
    const out = [P[0]];
    for (let i = 1; i < P.length - 1; i++) { const p = P[i], u = P[i - 1], w = P[i + 1], d1 = Math.hypot(p[0] - u[0], p[1] - u[1]), d2 = Math.hypot(w[0] - p[0], w[1] - p[1]);
      if (d1 < .5 || d2 < .5) continue; const r = Math.min(R, d1 / 2, d2 / 2);
      const s = [p[0] + (u[0] - p[0]) * r / d1, p[1] + (u[1] - p[1]) * r / d1], e = [p[0] + (w[0] - p[0]) * r / d2, p[1] + (w[1] - p[1]) * r / d2];
      out.push(s); for (let k = 1; k <= 8; k++) { const t = k / 8, q = 1 - t; out.push([q * q * s[0] + 2 * q * t * p[0] + t * t * e[0], q * q * s[1] + 2 * q * t * p[1] + t * t * e[1]]); } }
    out.push(P[P.length - 1]);
    const dense = [out[0]]; for (let i = 1; i < out.length; i++) { const a = out[i - 1], b = out[i], n = Math.max(1, Math.round(Math.hypot(b[0] - a[0], b[1] - a[1]) / 12));
      for (let k = 1; k <= n; k++) dense.push([a[0] + (b[0] - a[0]) * k / n, a[1] + (b[1] - a[1]) * k / n]); }
    return dense;
  }
  function octo(a, b, first){
    const dx = b[0] - a[0], dy = b[1] - a[1], ax = Math.abs(dx), ay = Math.abs(dy), sx = Math.sign(dx) || 1, sy = Math.sign(dy) || 1;
    const mid = (first || (ax >= ay ? 'h' : 'v')) === 'h' ? (ax >= ay ? [[a[0] + sx * (ax - ay) / 2, a[1]], [b[0] - sx * (ax - ay) / 2, b[1]]] : [[a[0], a[1]], [a[0], a[1]]])
      : (ay >= ax ? [[a[0], a[1] + sy * (ay - ax) / 2], [b[0], b[1] - sy * (ay - ax) / 2]] : [[a[0] + sx * (ax - ay) / 2, a[1]], [b[0] - sx * (ax - ay) / 2, b[1]]]);
    return roundPoly([a, ...mid, b]);
  }
  const thinLine = (p, l) => { if (l.state === 'adjacent') return; ctx.lineWidth = hover && hover.l === l ? 2 : 1.3;
    ctx.strokeStyle = l.b === 'internet' ? 'rgba(46,229,157,.55)' : 'rgba(120,160,255,.55)'; ctx.stroke(p); };
  const winSecs = () => Math.max(1, data.window || data.range || 120);
  const mbit = bytes => bytes * 8 / winSecs() / 1e6;
  const dirsOf = l => { const a = l.a_dir || {}, b = l.b_dir || {}; return (a.up || 0) + (a.down || 0) + (a.internal || 0) >= (b.up || 0) + (b.down || 0) + (b.internal || 0) ? a : b; };
  // hops from the internet (WAN links first): the end nearer to it sends the traffic that comes from the internet
  function hopsFromInternet(){
    const m = new Map([['internet', 0]]), q = ['internet'];
    while (q.length) { const c = q.shift(); for (const l of data.links) { const o = l.a === c ? l.b : l.b === c ? l.a : null; if (o && !m.has(o)) { m.set(o, m.get(c) + 1); q.push(o); } } }
    return m;
  }
  function colourPick(l, fwd){
    const d = dirsOf(l), nearA = (dist.get(l.a) ?? 99) <= (dist.get(l.b) ?? 99), inward = fwd ? nearA : !nearA;
    const w = inward ? [[d.down || 0, C.down], [d.internal || 0, C.int]] : [[d.up || 0, C.up], [d.internal || 0, C.int]];
    const sum = w[0][0] + w[1][0]; if (!sum) return l.b === 'internet' ? (fwd ? C.up : C.down) : '#4C93FF';
    let r = Math.random() * sum; for (const [x, c] of w) { if ((r -= x) <= 0) return c; } return w[1][1];
  }
  const SPR = {};
  const sprite = col => { if (SPR[col]) return SPR[col]; const c = document.createElement('canvas'), n = 32; c.width = c.height = n; const g = c.getContext('2d');
    const gr = g.createRadialGradient(n / 2, n / 2, 0, n / 2, n / 2, n / 2); gr.addColorStop(0, '#ffffff'); gr.addColorStop(.2, col); gr.addColorStop(.5, col + '55'); gr.addColorStop(1, col + '00');
    g.fillStyle = gr; g.fillRect(0, 0, n, n); return (SPR[col] = c); };
  const dimOf = l => { const onPath = opts.pathSet ? opts.pathSet() : null; if (onPath && !(onPath.has(l.a) && onPath.has(l.b))) return .1;
    if (hover && hover.l) return hover.l === l ? 1 : .3; if (hover && hover.n) return l.a === hover.n.ip || l.b === hover.n.ip ? 1 : .3; return 1; };
  // (1.9.1) density and speed relative to the busiest link on the map (by the square root of the share): the busiest
  // one is always lively, the others in proportion — a small network or a long period's average looks alive too
  const dirMbit = (l, fwd) => mbit(fwd ? Math.max(l.a_out || 0, l.b_in || 0) : Math.max(l.b_out || 0, l.a_in || 0));
  // the rate a link shows: eased towards the latest answer (about 4 s to settle), never a jump
  const easeRate = (key, target, dt) => { const cur = eased.has(key) ? eased.get(key) : target, k = 1 - Math.exp(-dt / 1.5), v = cur + (target - cur) * k; eased.set(key, v); return v; };
  function spawn(dt){
    const top = {river:4, metro:9, stars:10}[mode()] || 13, speedK = mode() === 'stars' ? .75 : mode() === 'metro' ? .85 : 1;
    const rates = []; let mmax = 0;
    for (const [l, g] of geoms) for (const fwd of [true, false]) {
      const key = (fwd ? '>' : '<') + lkey(l), m = easeRate(key, l.state === 'adjacent' ? 0 : dirMbit(l, fwd), dt);
      rates.push([l, g, fwd, key, m]); mmax = Math.max(mmax, m); }
    mmax = easeRate('__max', mmax, dt);
    if (mmax <= 0) return;
    for (const [l, g, fwd, key, m] of rates) {
      if (m <= mmax * 1e-4) continue;
      const share = Math.min(1, Math.sqrt(m / mmax)); let a = (acc.get(key) ?? Math.random()) + Math.max(.25, top * share) * dt;
      while (a >= 1) { a -= 1; parts.push({k:lkey(l), l, g, fwd, s:0, v:(60 + 80 * share) * speedK / g.len, col:colourPick(l, fwd), size:1.5 + 1.3 * share}); }
      acc.set(key, a);
    }
    if (parts.length > 700) parts.splice(0, parts.length - 700);
  }
  // a strand's dash phase grows by its eased speed: a new speed changes the pace, not the place
  const phaseOf = (key, speed, dt) => { const sp = easeRate('~' + key, speed, dt), ph = (phase.get(key) || 0) + sp * dt; phase.set(key, ph % 1e6); return ph; };
  function paint(dt, t){
    main.setTransform(1, 0, 0, 1, 0, 0); main.clearRect(0, 0, cv.width, cv.height); if (bgCv) main.drawImage(bgCv, 0, 0); main.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (mode() === 'river') for (const [l, b] of bands) {          // the liquid: strands per direction, thin streaks flowing in them
      let off = -b.w / 2; const dim = dimOf(l);
      for (const [sw, col, dir, val] of b.strands) {
        main.save(); main.translate(0, off + sw / 2); main.globalAlpha = .26 * dim; main.lineWidth = sw * .92; main.strokeStyle = col; main.stroke(b.g.path);
        if (!REDUCED.matches) { main.globalAlpha = .85 * dim; main.lineWidth = Math.min(1.6, sw * .4); main.lineCap = 'round';
          for (const [kk, len, gap] of [[0, 14, 26], [1, 8, 34]]) { if (sw < 5 && kk) continue;
            main.save(); main.translate(0, sw * (kk ? .22 : -.18)); main.setLineDash([len, gap]); main.lineDashOffset = -(phaseOf(lkey(l) + col + kk, 38 + Math.sqrt(val) * 2.4, dt) + kk * 20) * dir; main.stroke(b.g.path); main.restore(); }
          main.setLineDash([]); main.lineCap = 'butt'; }
        main.restore(); off += sw; } }
    main.globalAlpha = 1;
    if (REDUCED.matches) return;
    main.globalCompositeOperation = 'lighter';
    for (let i = parts.length - 1; i >= 0; i--) { const p = parts[i]; p.s += p.v * dt;
      const g = geoByKey.get(p.k); if (g && g !== p.g) { p.v *= p.g.len / g.len; p.g = g; p.l = linkByKey.get(p.k); }      // a refresh: same link, new curve
      if (p.s >= 1 || !g) { parts.splice(i, 1); continue; }
      const u = p.fwd !== !!p.g.rev ? p.s : 1 - p.s, [x, y, ang] = p.g.at(u), a = dimOf(p.l) * .95 * Math.min(1, p.s * 6, (1 - p.s) * 6);
      if (mode() === 'metro') { main.save(); main.translate(x, y); main.rotate(ang); main.globalAlpha = a; main.fillStyle = p.col; main.fill(rr(-6, -2.2, 12, 4.4, 2.2)); main.restore(); }
      else if (mode() === 'stars') for (let k = 2; k >= 0; k--) { const [tx, ty] = k ? p.g.at(u + (p.fwd !== !!p.g.rev ? -1 : 1) * k * .014) : [x, y]; main.globalAlpha = a * (k ? .42 - k * .14 : 1); const d = p.size * (k ? 1 - k * .3 : 1) * 5; main.drawImage(sprite(p.col), tx - d / 2, ty - d / 2, d, d); }
      else { main.globalAlpha = a; const d = p.size * 5; main.drawImage(sprite(p.col), x - d / 2, y - d / 2, d, d); } }
    main.globalCompositeOperation = 'source-over'; main.globalAlpha = 1;
  }
  function tickLive(now){
    raf = 0; if (!cv.isConnected || mode() === 'classic' || document.hidden) return;
    if (now - lastT >= 32) { const dt = Math.min(.1, (now - lastT) / 1000); lastT = now; spawn(dt); paint(dt, now / 1000); }
    if (!REDUCED.matches) raf = requestAnimationFrame(tickLive);
  }
  const kickLive = () => { if (!raf && !REDUCED.matches) { lastT = performance.now(); raf = requestAnimationFrame(tickLive); } };
  const stopLive = () => { cancelAnimationFrame(raf); raf = 0; parts = []; };
  const onVis = () => { if (!document.hidden && mode() !== 'classic') kickLive(); };
  document.addEventListener('visibilitychange', onVis); onCleanup(() => { stopLive(); document.removeEventListener('visibilitychange', onVis); });

  // labels: an interface name over its address on a dark plate, put where it overlaps nothing drawn yet
  const reg = (x, y, w, h) => placed.push([x - 3, y - 3, w + 6, h + 6]);
  const free = (x, y, w, h) => x >= 2 && y >= 2 && x + w <= W - 2 && y + h <= H - 2 && !placed.some(([a, b, c, d]) => x < a + c && a < x + w && y < b + d && b < y + h);
  const NAME_FL = '700 11px JetBrains Mono, monospace', ADDR_FL = '500 10px JetBrains Mono, monospace';
  function endLabel(g, atStart, name, addr, gap, alpha){
    if (!name && !addr) return;
    ctx.font = NAME_FL; const w1 = ctx.measureText(name || '').width; ctx.font = ADDR_FL; const w2 = addr ? ctx.measureText(addr).width : 0;
    const bw = Math.max(w1, w2) + 10, bh = addr ? 30 : 17, dir = atStart === !g.rev ? 1 : -1;
    let best = null, room = false;
    outer: for (const extra of [0, 18]) for (const step of [.07, .14, .22, .3, .4, .5]) for (const flip of [1, -1]) {
      const t = atStart === !g.rev ? step : 1 - step, [x, y, ang] = g.at(t), tx = Math.cos(ang) * dir, ty = Math.sin(ang) * dir;
      let nx = -ty, ny = tx; if (ny > 0 || (Math.abs(ny) < .2 && nx < 0)) { nx = -nx; ny = -ny; } nx *= flip; ny *= flip;
      const gp = gap + extra, vertical = Math.abs(ty) > .85, cx = x + nx * (gp + (vertical ? 0 : bh / 2 - 6)), cy = y + ny * (gp + bh / 2 - 4);
      const x0 = vertical ? (nx >= 0 ? cx : cx - bw) : cx - bw / 2, c = {x0, y0:cy - bh / 2};
      if (free(c.x0, c.y0, bw, bh)) { best = c; room = true; break outer; } }
    if (!room) return;                // no free place near this end: the interface stays in the tooltip and the table
    reg(best.x0, best.y0, bw, bh);
    ctx.globalAlpha = alpha; ctx.fillStyle = 'rgba(6,13,34,.86)'; ctx.fill(rr(best.x0, best.y0, bw, bh, 6));
    ctx.textAlign = 'left'; ctx.textBaseline = 'middle'; ctx.font = NAME_FL; ctx.fillStyle = C.ink; ctx.fillText(name || '', best.x0 + 5, addr ? best.y0 + 8 : best.y0 + bh / 2 + .5);
    if (addr) { ctx.font = ADDR_FL; ctx.fillStyle = C.ink2; ctx.fillText(addr, best.x0 + 5, best.y0 + 22); } ctx.globalAlpha = 1;
  }
  const linkAlpha = l => { const onPath = opts.pathSet ? opts.pathSet() : null; return onPath && !(onPath.has(l.a) && onPath.has(l.b)) ? .15 : 1; };
  const nodeAlpha = ip => { const onPath = opts.pathSet ? opts.pathSet() : null; return onPath && !onPath.has(ip) ? .3 : 1; };
  const devices = () => data.nodes.filter(n => n.ip !== 'internet');
  const nodeVol = ip => data.links.filter(l => l.a === ip || l.b === ip).reduce((s, l) => s + vol2(l), 0);
  // the canvas as tall as the view needs (never narrower than the panel)
  function sizeTo(w, h){ W = w; H = Math.max(BASE, h); const hs = H > BASE || maxed() ? H + 'px' : ''; if (host.style.height !== hs) host.style.height = hs;
    box.style.width = W + 'px'; cv.width = W * dpr; cv.height = H * dpr; cv.style.width = W + 'px'; cv.style.height = H + 'px'; sizeBg(); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
    shapes = []; placed = []; ctx.textBaseline = 'middle'; ctx.lineCap = 'round'; }
  const stateDash = (p, l) => { if (l.state === 'adjacent') { ctx.setLineDash([4, 5]); ctx.strokeStyle = 'rgba(170,190,230,.55)'; ctx.lineWidth = 1.4; ctx.stroke(p); ctx.setLineDash([]); return true; }
    if (l.state === 'gap' || l.state === 'unobserved') { ctx.setLineDash([5, 5]); ctx.strokeStyle = RED; ctx.lineWidth = 1.6; ctx.stroke(p); ctx.setLineDash([]); return true; }
    if (l.state === 'silent') { ctx.setLineDash([2, 6]); ctx.lineCap = 'round'; ctx.strokeStyle = AMBER; ctx.lineWidth = 1.6; ctx.stroke(p); ctx.setLineDash([]); return false; } return false; };
  function inetPill(x, y, w, h){
    const p = rr(x - w / 2, y - h / 2, w, h, h / 2); ctx.globalAlpha = nodeAlpha('internet'); ctx.fillStyle = 'rgba(11,23,54,.97)'; ctx.fill(p);
    ctx.strokeStyle = hover && hover.cloud ? 'rgba(46,229,157,.95)' : 'rgba(46,229,157,.65)'; ctx.lineWidth = 1.6; ctx.stroke(p);
    ctx.font = '700 13px Manrope, sans-serif'; const tw = ctx.measureText(T('Internet')).width, gx = x - (tw + 24) / 2;
    ctx.save(); ctx.translate(gx, y - 8); ctx.scale(.9, .9); ctx.strokeStyle = C.ext; ctx.lineWidth = 1.5; ctx.stroke(new Path2D(ICO.globe)); ctx.restore();
    ctx.textAlign = 'left'; ctx.fillStyle = C.ink; ctx.fillText(T('Internet'), gx + 24, y + .5); ctx.globalAlpha = 1;
    reg(x - w / 2, y - h / 2, w, h); shapes.push({path:p, cloud:true, tip:inetTip()});
  }

  // ---- Metro: the classic places, stations, lines at 0 / 45 / 90 degrees
  function drawMetro(){
    if (!H || !data) return; vmax = Math.max(1e-9, ...data.links.map(l => v(vol2(l))));
    if (!devices().length) { sizeTo(host.clientWidth, BASE); return noDevices(); }
    const {pos, cloud} = layout(); sizeTo(W, H);
    const pt = ip => pos.get(ip), wan = data.links.filter(l => l.b === 'internet' && pos.has(l.a));
    const ix = cloud ? cloud.x : W / 2, iy = cloud ? cloud.y : 24, iw = 128;
    wan.sort((a, b) => pt(a.a).x - pt(b.a).x);
    const sameCol = new Map();
    for (const l of data.links) { const A = pt(l.a); if (!A) continue; let pts;
      if (l.b === 'internet') { const k = wan.indexOf(l), xs = ix + (wan.length === 1 ? 0 : -Math.min(iw * .7, 18 * (wan.length - 1)) / 2 + Math.min(iw * .7, 18 * (wan.length - 1)) * k / (wan.length - 1));
        pts = octo([A.x + (wan.filter(x => x.a === l.a).indexOf(l) - (wan.filter(x => x.a === l.a).length - 1) / 2) * 10, A.y], [xs, iy + 15], 'v'); }
      else { const B = pt(l.b); if (!B) continue;
        if (A.c === B.c) { const U = A.y < B.y ? A : B, D = U === A ? B : A, k = sameCol.get(U.c) || 0; sameCol.set(U.c, k + 1);
          const between = [...pos.values()].some(P => P.c === U.c && P.y > U.y && P.y < D.y), off = (U.c < 0 ? -1 : 1) * (between ? 48 + 12 * k : 0);
          pts = between ? roundPoly([[U.x, U.y], [U.x + off, U.y + Math.abs(off)], [U.x + off, D.y - Math.abs(off)], [D.x, D.y]]) : octo([U.x, U.y], [D.x, D.y], 'v');
          if (U !== A) pts.reverse(); }
        else pts = octo([A.x, A.y], [B.x, B.y], 'h'); }
      const g = mkGeo(pts, false); geoms.set(l, g);
      ctx.globalAlpha = linkAlpha(l); ctx.lineJoin = 'round';
      if (!stateDash(g.path, l)) { const on = hover && hover.l === l; ctx.lineWidth = 7; ctx.strokeStyle = on ? '#2F5FC0' : '#21386F'; ctx.stroke(g.path); ctx.lineWidth = 2; ctx.strokeStyle = l.b === 'internet' ? (on ? '#7DF2C4' : '#3FB98C') : (on ? '#9DB9FF' : '#5577C8'); ctx.stroke(g.path); }
      ctx.globalAlpha = 1; shapes.push({stroke:g.path, sw:12, l, tip:linkTip(l)}); }
    if (cloud) inetPill(ix, iy, iw, 30);
    // stations and their names, where no line runs
    for (const n of devices()) { const p = pt(n.ip); if (!p) continue; const pov = n.ip === data.pov, a = nodeAlpha(n.ip); ctx.globalAlpha = a;
      const sh = pov ? rr(p.x - 26, p.y - 12, 52, 24, 12) : (() => { const c = new Path2D(); c.arc(p.x, p.y, 9, 0, 6.2832); return c; })();
      ctx.fillStyle = '#EAF0FF'; ctx.fill(sh); ctx.lineWidth = pov ? 3.5 : 3; ctx.strokeStyle = pov ? '#27D3F5' : hover && hover.n === n ? '#9DB9FF' : '#3B5FB0'; ctx.stroke(sh);
      if (!n.exporting) { ctx.fillStyle = C.ink3; ctx.beginPath(); ctx.arc(p.x, p.y, 3, 0, 6.2832); ctx.fill(); }
      reg(p.x - 28, p.y - 14, 56, 28); shapes.push({path:sh, n, tip:nodeTip(n)});
      const t1 = n.name || n.ip, t2 = [n.model || n.vendor, n.ip].filter(Boolean).join(' · '), half = pov ? 26 : 9;
      ctx.font = '800 13.5px Manrope, sans-serif'; const w1 = ctx.measureText(t1).width; ctx.font = '500 11px Manrope, sans-serif'; const w2 = ctx.measureText(t2).width, w = Math.max(w1, w2), hh = 32;
      // below, left, right, above the station: the first place where nothing is drawn; [anchor x, top, align]
      const cands = [[p.x, p.y + 17, 'center'], [p.x - half - 10, p.y - hh / 2, 'right'], [p.x + half + 10, p.y - hh / 2, 'left'], [p.x, p.y - 17 - hh, 'center']];
      const box0 = ([x, y, al]) => [al === 'center' ? x - w / 2 : al === 'right' ? x - w : x, y];
      const pick0 = cands.find(c => { const [x0, y0] = box0(c); return free(x0, y0, w, hh); }) || cands[0], [bx, by] = box0(pick0); reg(bx, by, w, hh);
      ctx.textAlign = pick0[2]; ctx.font = '800 13.5px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(t1, pick0[0], by + 8);
      ctx.font = '500 11px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.fillText(t2, pick0[0], by + 24);
      ctx.globalAlpha = 1; }
    for (const l of data.links) { const g = geoms.get(l); if (!g) continue; const a = linkAlpha(l) < 1 ? .18 : 1;
      endLabel(g, true, l.a_name, l.a_addr, 14, a); if (l.b !== 'internet') endLabel(g, false, l.b_name, l.b_addr, 14, a); }
  }

  // ---- Stars: the Point of View in the middle, neighbours on rings by hops, the internet above
  function drawStars(){
    if (!H || !data) return; vmax = Math.max(1e-9, ...data.links.map(l => v(vol2(l))));
    if (!devices().length) { sizeTo(host.clientWidth, BASE); return noDevices(); }
    const L0 = layout(), hop = new Map([[data.pov, 0]]), q = [data.pov];
    while (q.length) { const c = q.shift(); for (const l of data.links) { if (l.b === 'internet') continue; const o = l.a === c ? l.b : l.b === c ? l.a : null; if (o && !hop.has(o)) { hop.set(o, hop.get(c) + 1); q.push(o); } } }
    const maxHop = Math.max(1, ...[...hop.values()]), ringN = new Map(); devices().forEach(n => { if (!hop.has(n.ip)) hop.set(n.ip, maxHop); });
    // (1.9.3) the rings fill the room they get (the whole screen in wall mode); the neighbours spread evenly round the
    // Point of View — all but the top, where the internet is — and a farther device sits near the one it is reached by
    const w0 = host.clientWidth, hh = Math.max(BASE, 560 + 60 * (maxHop - 1)), RIGHT0 = -55, ARC = 290;
    const R0 = Math.max(150, Math.min((w0 / 2 - 125) / 1.15, (hh - 200) / 2 / .82));
    sizeTo(w0, hh); const Ry = R0 * .82, cx = W / 2, cy = Math.min(H - Ry - 60, 150 + Ry), R = h => maxHop < 2 ? R0 : R0 * (.6 + .4 * (h - 1) / (maxHop - 1));
    const P = new Map([['internet', {x:cx, y:Math.max(42, cy - Ry - 95), r:26}]]), ang = new Map();
    const at = (n, h, deg) => { ang.set(n.ip, deg); const a = deg * Math.PI / 180; P.set(n.ip, {x:cx + Math.cos(a) * R(h) * 1.15, y:cy + Math.sin(a) * R(h) * .82, r:22}); };
    const side = n => ((L0.pos.get(n.ip) || {}).c || 0), yOf = n => ((L0.pos.get(n.ip) || {}).y || 0);
    for (let h = 1; h <= maxHop; h++) {
      const ring = devices().filter(n => n.ip !== data.pov && hop.get(n.ip) === h);
      if (h === 1) {        // right side top to bottom, then left side bottom to top: neighbours keep the classic sides
        ring.sort((a, b) => (side(b) > 0) - (side(a) > 0) || (side(a) > 0 ? yOf(a) - yOf(b) : yOf(b) - yOf(a)));
        ring.forEach((n, i) => at(n, h, RIGHT0 + ARC * (i + .5) / ring.length));
      } else {              // near the device it is reached through, fanned out a little
        const by = new Map(); ring.forEach(n => { const par = data.links.map(l => l.a === n.ip ? l.b : l.b === n.ip ? l.a : null).find(o => o && hop.get(o) === h - 1);
          const k = ang.has(par) ? par : '_'; if (!by.has(k)) by.set(k, []); by.get(k).push(n); });
        let free = 0; for (const [par, list] of by) list.forEach((n, i) => at(n, h, par !== '_' ? ang.get(par) + (i - (list.length - 1) / 2) * 16 : RIGHT0 + ARC * ((free++) + .5) / ring.length));
      }
      ringN.set(h, ring.length); }
    P.set(data.pov, {x:cx, y:cy, r:30});
    // a faint sky: rings and still stars
    ctx.strokeStyle = 'rgba(120,160,255,.07)'; ctx.lineWidth = 1;
    for (let h = 1; h <= maxHop; h++) { ctx.beginPath(); ctx.ellipse(cx, cy, R(h) * 1.15, R(h) * .82, 0, 0, 6.2832); ctx.stroke(); }
    let sd = 7; const rnd = () => (sd = (sd * 9301 + 49297) % 233280) / 233280;
    for (let i = 0; i < 110; i++) { ctx.globalAlpha = .1 + rnd() * .28; ctx.fillStyle = '#9fb8ff'; ctx.fillRect(rnd() * W, rnd() * H, 1.2, 1.2); } ctx.globalAlpha = 1;
    const wanBy = new Map(); data.links.filter(l => l.b === 'internet').forEach(l => { wanBy.set(l.a, (wanBy.get(l.a) || 0) + 1); });
    const seen = new Map();
    for (const l of data.links) { const A = P.get(l.a), B = P.get(l.b); if (!A || !B) continue;
      const k = seen.get(l.a + l.b) || 0; seen.set(l.a + l.b, k + 1); const n = l.b === 'internet' ? wanBy.get(l.a) : 1, bend = (n > 1 ? (k - (n - 1) / 2) * .28 : .1) + (n > 1 ? 0 : (A.x < cx ? -.06 : .06));
      const dx = B.x - A.x, dy = B.y - A.y, d = Math.hypot(dx, dy) || 1, ux = dx / d, uy = dy / d, s = [A.x + ux * (A.r + 7), A.y + uy * (A.r + 7)], e = [B.x - ux * (B.r + 7), B.y - uy * (B.r + 7)], nx = -uy * d * bend, ny = ux * d * bend;
      const g = mkGeo(cubicPts(s, [s[0] + dx * .3 + nx, s[1] + dy * .3 + ny], [e[0] - dx * .3 + nx, e[1] - dy * .3 + ny], e), false); geoms.set(l, g);
      ctx.globalAlpha = linkAlpha(l);
      if (!stateDash(g.path, l)) { ctx.lineWidth = hover && hover.l === l ? 1.8 : 1.1; ctx.strokeStyle = l.b === 'internet' ? 'rgba(46,229,157,.42)' : 'rgba(150,180,255,.36)'; ctx.setLineDash([1, 5]); ctx.stroke(g.path); ctx.setLineDash([]); }
      ctx.globalAlpha = 1; shapes.push({stroke:g.path, sw:12, l, tip:linkTip(l)}); }
    // the internet and the devices: a circle with the share of the busiest device's traffic around it
    { const I = P.get('internet'), c = new Path2D(); c.arc(I.x, I.y, I.r, 0, 6.2832); ctx.globalAlpha = nodeAlpha('internet'); ctx.fillStyle = 'rgba(8,24,40,.96)'; ctx.fill(c); ctx.lineWidth = 1.5;
      ctx.strokeStyle = hover && hover.cloud ? C.ext : 'rgba(46,229,157,.7)'; ctx.stroke(c); ctx.save(); ctx.translate(I.x - 8, I.y - 8); ctx.strokeStyle = C.ext; ctx.stroke(new Path2D(ICO.globe)); ctx.restore();
      ctx.font = '700 12.5px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.textAlign = 'center'; ctx.fillText(T('Internet'), I.x, I.y + I.r + 13); ctx.globalAlpha = 1;
      reg(I.x - 40, I.y - I.r - 4, 80, 2 * I.r + 26); if (data.links.some(l => l.b === 'internet')) shapes.push({path:c, cloud:true, tip:inetTip()}); }
    const top = Math.max(1, ...devices().map(n => nodeVol(n.ip)));
    for (const n of devices()) { const p = P.get(n.ip); if (!p) continue; const pov = n.ip === data.pov, share = nodeVol(n.ip) / top, c = new Path2D(); c.arc(p.x, p.y, p.r, 0, 6.2832);
      ctx.globalAlpha = nodeAlpha(n.ip); ctx.fillStyle = pov ? 'rgba(18,44,86,.97)' : 'rgba(9,20,48,.96)'; ctx.fill(c); ctx.lineWidth = pov ? 2 : 1.3;
      ctx.strokeStyle = pov ? '#27D3F5' : hover && hover.n === n ? 'rgba(170,200,255,.95)' : 'rgba(130,175,255,.6)'; ctx.stroke(c);
      ctx.lineWidth = 3; ctx.strokeStyle = 'rgba(255,255,255,.07)'; ctx.beginPath(); ctx.arc(p.x, p.y, p.r + 6, 0, 6.2832); ctx.stroke();
      const gr = ctx.createLinearGradient(p.x - p.r, p.y, p.x + p.r, p.y); gr.addColorStop(0, C.down); gr.addColorStop(1, '#4C93FF');
      ctx.strokeStyle = gr; ctx.beginPath(); ctx.arc(p.x, p.y, p.r + 6, -Math.PI / 2, -Math.PI / 2 + share * 6.2832); ctx.stroke(); ctx.lineCap = 'round';
      ctx.font = '700 11px JetBrains Mono, monospace'; ctx.fillStyle = C.ink2; ctx.textAlign = 'center'; ctx.fillText(Math.round(share * 100) + '%', p.x, p.y + .5);
      const t2 = [n.model || n.vendor, n.ip].filter(Boolean).join(' · ');
      ctx.font = '700 13px Manrope, sans-serif'; ctx.fillStyle = C.ink; ctx.fillText(n.name || n.ip, p.x, p.y + p.r + 18); ctx.font = '500 11px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.fillText(t2, p.x, p.y + p.r + 34);
      ctx.font = '700 13px Manrope, sans-serif'; const w = Math.max(ctx.measureText(n.name || n.ip).width, ctx.measureText(t2).width * .9);
      reg(p.x - p.r - 8, p.y - p.r - 8, 2 * p.r + 16, 2 * p.r + 16); reg(p.x - w / 2, p.y + p.r + 8, w, 34);
      if (!n.exporting) { ctx.fillStyle = C.ink3; ctx.beginPath(); ctx.arc(p.x + p.r * .7, p.y - p.r * .7, 3.5, 0, 6.2832); ctx.fill(); }
      ctx.globalAlpha = 1; shapes.push({path:c, n, tip:nodeTip(n)}); }
    for (const l of data.links) { const g = geoms.get(l); if (!g) continue; const a = linkAlpha(l) < 1 ? .18 : 1;
      endLabel(g, true, l.a_name, l.a_addr, 12, a); if (l.b !== 'internet') endLabel(g, false, l.b_name, l.b_addr, 12, a); }
    void ringN;
  }

  // ---- River: columns by hops from the internet, bands as wide as their traffic, strands flowing by direction
  function drawRiver(){
    if (!H || !data) return; bands.clear();
    if (!devices().length) { sizeTo(host.clientWidth, BASE); return noDevices(); }
    dist = hopsFromInternet(); const L0 = layout();
    const ids = ['internet', ...devices().map(n => n.ip)], maxD = Math.max(1, ...devices().map(n => dist.get(n.ip) ?? 0));
    const depth = ip => ip === 'internet' ? 0 : (dist.get(ip) ?? maxD + 1), D = Math.max(...ids.map(depth));
    const vmaxR = Math.max(1, ...data.links.map(vol2)), bw = l => 2 + 30 * Math.sqrt(vol2(l) / vmaxR);
    const left = (l, ip) => (l.a === ip ? depth(l.b) : depth(l.a)) < depth(ip);       // the link enters ip from the internet's side
    const sideH = (ip, lft) => { const ls = data.links.filter(l => (l.a === ip || l.b === ip) && left(l, ip) === lft); return ls.reduce((s, l) => s + bw(l), 0) + 4 * Math.max(0, ls.length - 1); };
    const hOf = ip => Math.max(26, sideH(ip, true), sideH(ip, false));
    const cols = []; ids.forEach(ip => { (cols[depth(ip)] = cols[depth(ip)] || []).push(ip); });
    const w0 = host.clientWidth, pad = 30, nameRoom = 120, colX = c => pad + 6 + (w0 - 2 * pad - 12 - nameRoom) * c / Math.max(1, D);
    const yOf = new Map(), gapY = 46;
    const tall = Math.max(...cols.filter(Boolean).map(c => c.reduce((s, ip) => s + hOf(ip), 0) + gapY * (c.length - 1)));
    sizeTo(w0, tall + 120);
    cols.forEach((c, k) => { if (!c) return;
      c.sort((x, y) => { const up = ip => { const ls = data.links.filter(l => (l.a === ip || l.b === ip) && left(l, ip)); return ls.length ? ls.reduce((s, l) => s + (yOf.get(l.a === ip ? l.b : l.a) || 0), 0) / ls.length : ((L0.pos.get(ip) || {}).y || 0); }; return up(x) - up(y); });
      const total = c.reduce((s, ip) => s + hOf(ip), 0) + gapY * (c.length - 1); let y = (H - total) / 2 + 20;
      c.forEach(ip => { yOf.set(ip, y + hOf(ip) / 2); y += hOf(ip) + gapY; }); void k; });
    const X = ip => colX(depth(ip)), off = new Map();
    for (const ip of ids) for (const lft of [true, false]) {
      const ls = data.links.filter(l => (l.a === ip || l.b === ip) && left(l, ip) === lft).sort((p, q) => yOf.get(p.a === ip ? p.b : p.a) - yOf.get(q.a === ip ? q.b : q.a));
      let y = yOf.get(ip) - sideH(ip, lft) / 2; for (const l of ls) { off.set(l.a + l.b + l.a_name + (l.a === ip ? 'A' : 'B'), y + bw(l) / 2); y += bw(l) + 4; } }
    for (const l of data.links) {
      const inA = depth(l.a) <= depth(l.b), U = inA ? l.a : l.b, V = inA ? l.b : l.a, same = depth(l.a) === depth(l.b);
      const yu = off.get(l.a + l.b + l.a_name + (U === l.a ? 'A' : 'B')), yv = off.get(l.a + l.b + l.a_name + (V === l.a ? 'A' : 'B')), xu = X(U) + 6, xv = same ? X(V) + 6 : X(V) - 6;
      const pts = same ? cubicPts([xu, yu], [xu + 90, yu], [xv + 90, yv], [xv, yv], 60) : cubicPts([xu, yu], [(xu + xv) / 2, yu], [(xu + xv) / 2, yv], [xv, yv], 60);
      const g = mkGeo(pts, U !== l.a), w = bw(l); geoms.set(l, g);
      ctx.globalAlpha = linkAlpha(l); ctx.lineWidth = w; ctx.strokeStyle = hover && hover.l === l ? 'rgba(76,147,255,.3)' : 'rgba(76,147,255,.14)'; ctx.stroke(g.path); stateDash(g.path, l); ctx.globalAlpha = 1;
      // strands: from the internet (towards V), to it (towards U), inside (the busier way), their widths by share
      const d = dirsOf(l), tsum = (d.down || 0) + (d.up || 0) + (d.internal || 0) || 1, ab = Math.max(l.a_out || 0, l.b_in || 0) >= Math.max(l.b_out || 0, l.a_in || 0);
      const mb = mbit(vol2(l));
      bands.set(l, {g, w, strands:[[w * (d.down || 0) / tsum, C.down, 1], [w * (d.up || 0) / tsum, C.up, -1], [w * (d.internal || 0) / tsum, C.int, (ab === (U === l.a)) ? 1 : -1]].filter(x => x[0] > .4).map(x => [Math.max(1, x[0]), x[1], x[2], mb])});
      shapes.push({stroke:g.path, sw:Math.max(10, w + 4), l, tip:linkTip(l)}); }
    for (const ip of ids) { const x = X(ip), y = yOf.get(ip), h = hOf(ip), isI = ip === 'internet', n = data.nodes.find(z => z.ip === ip) || {ip};
      const p = rr(x - 6, y - h / 2, 12, h, 5), gr = ctx.createLinearGradient(x, y - h / 2, x, y + h / 2);
      gr.addColorStop(0, isI ? '#2EE59D' : ip === data.pov ? '#27D3F5' : '#4C93FF'); gr.addColorStop(1, isI ? '#1aa97a' : ip === data.pov ? '#1aa7d6' : '#2F7BFF');
      ctx.globalAlpha = nodeAlpha(ip); ctx.fillStyle = gr; ctx.fill(p); if (hover && (hover.n === n || (isI && hover.cloud))) { ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.2; ctx.stroke(p); }
      const last = depth(ip) === D && D > 0, t1 = isI ? T('Internet') : n.name || ip, t2 = isI ? '' : [n.model || n.vendor, n.ip].filter(Boolean).join(' · ');
      ctx.textAlign = last ? 'right' : 'left'; ctx.font = '700 13px Manrope, sans-serif'; ctx.fillStyle = C.ink; const tx = last ? x + 4 : x - 4;
      ctx.fillText(t1, tx, y - h / 2 - (t2 ? 26 : 12)); if (t2) { ctx.font = '500 10.5px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.fillText(t2, tx, y - h / 2 - 11); }
      ctx.font = '700 13px Manrope, sans-serif'; const tw = Math.max(ctx.measureText(t1).width, t2 ? ctx.measureText(t2).width * .85 : 0);
      reg(last ? tx - tw : tx, y - h / 2 - 36, tw, 32); reg(x - 8, y - h / 2, 16, h); ctx.globalAlpha = 1;
      shapes.push(isI ? {path:p, cloud:true, tip:inetTip()} : {path:p, n, tip:nodeTip(n)}); }
    for (const l of data.links) { const b = bands.get(l); if (!b) continue; const a = linkAlpha(l) < 1 ? .18 : 1, gap = b.w / 2 + 8;
      endLabel(b.g, true, l.a_name, l.a_addr, gap, a); if (l.b !== 'internet') endLabel(b.g, false, l.b_name, l.b_addr, gap, a); }
  }
  function noDevices(){ ctx.font = '600 13px Manrope, sans-serif'; ctx.fillStyle = C.ink3; ctx.textAlign = 'center'; ctx.fillText(T('No device has sent data yet'), W / 2, H / 2); }

  function draw(){
    const m = mode(); geoms.clear(); bands.clear();
    if (m !== 'classic') { if (!bgCv) bgCv = document.createElement('canvas'); ctx = bgCv.getContext('2d'); }
    try { if (data) dist = hopsFromInternet(); (m === 'metro' ? drawMetro : m === 'stars' ? drawStars : m === 'river' ? drawRiver : drawClassic)(); }
    finally { ctx = main; }
    geoByKey.clear(); linkByKey.clear(); for (const [l, g] of geoms) { geoByKey.set(lkey(l), g); linkByKey.set(lkey(l), l); }
    if (m !== 'classic' && data) { if (m !== 'river') bands.clear(); main.setTransform(dpr, 0, 0, dpr, 0, 0); paint(0, performance.now() / 1000); kickLive(); }
    else stopLive();
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
  return {set:d => { data = d; draw(); }, redraw:draw, resize:() => { host.style.height = ''; requestAnimationFrame(size); }};
}
function vNetwork(){
  const v = document.getElementById('view'), live = !!state.netLive && !isCustom(), depth = state.netDepth || 1;
  v.innerHTML = `<div class="grid">
    <section class="glass panel s9" id="netSec">${ph('nodes', T('Path analysis'), T('layer-3 neighbours of the Point of View · width = volume · click a device to look from it'),
      `<span id="nPovSeg"></span>` + seg('nDepthSeg', [['1', '1'], ['2', '2'], ['3', '3']].map(([k, l]) => [k, l, Tn(+k, 'Neighbours up to {n} hop away', 'Neighbours up to {n} hops away')]), String(depth))
      + seg('nScaleSeg', [['sqrt', T('Compressed'), T('Width ∝ √volume — small links stay visible next to big ones')], ['lin', T('Linear')]], state.scale)
      + seg('nLiveSeg', [['live', T('Live')], ['period', T('toggle::Period')]], live ? 'live' : 'period'), false, maxBtn())}
      <div class="netviews" id="netViews" role="group" aria-label="${T('Map view')}"></div>
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
  // (1.9.0) the map view: each user's own default (the lamp), switched here for now
  const NET_VIEWS = () => [['classic', T('Classic')], ['lines', T('Lines')], ['stars', T('Stars')], ['metro', T('Metro')], ['river', T('River')]];
  const defView = () => ((ME && ME.prefs) || {}).path_view || 'classic', curView = () => state.netView || defView();
  const LAMP = 'M9 2.2a5 5 0 0 0-3 9c.6.5.9 1.1.9 1.8h4.2c0-.7.3-1.3.9-1.8a5 5 0 0 0-3-9M7 15.2h4M7.6 17h2.8';
  const drawViews = () => { const box = document.getElementById('netViews'); if (!box) return; const cur = curView(), def = defView();
    box.innerHTML = `<span class="nat">${T('View')}</span><div class="seg">${NET_VIEWS().map(([k, l]) => `<button type="button" data-nv="${k}" aria-pressed="${k === cur}"${k === def ? ` title="${T('Your default view')}"` : ''}>${k === def ? `<span class="lamp on" aria-hidden="true">${icon(LAMP, 13)}</span>` : ''}${l}</button>`).join('')}</div>
      <button type="button" class="btn lampbtn" id="nvDef" ${cur === def ? 'disabled' : ''}><span class="lamp${cur === def ? ' on' : ''}" aria-hidden="true">${icon(LAMP, 14)}</span>${cur === def ? T('Your default view') : T('Make it my default')}</button>`;
    box.querySelectorAll('[data-nv]').forEach(b => b.onclick = () => { if (b.dataset.nv === curView()) return; state.netView = b.dataset.nv; drawViews(); map.redraw(); });
    document.getElementById('nvDef').onclick = async () => { const b = document.getElementById('nvDef'); b.disabled = true;
      try { ME = await apiPost('me/prefs', {prefs:{path_view:curView()}}); } catch (e) { b.disabled = false; alert(e.message); return; } drawViews(); }; };
  const map = createTopoMap(document.getElementById('cNet'), {mode:curView, onNode:n => { if (n.ip === 'internet' || n.ip === state.netPov) return; state.netPov = n.ip; if (n.more) state.netDepth = Math.max(depth, 1); render(); },
    pathSet:() => path && path.hops.length ? new Set(path.hops.filter(h => h.state !== 'unplaced').map(h => h.device)) : null, hopNo:ip => hopIndex().get(ip)});
  drawViews();
  document.getElementById('netSec')._reload = () => map.resize();       // (1.9.2) full screen and back: drawn again at the new size
  let wb = waitBig(document.getElementById('cNet'), 'graph', sketchGraph((META.devices || []).slice().sort((a, b) => a.name.localeCompare(b.name))));   // (1.8.5) a sketch until the first answer
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
          <td><span class="tag" title="${esc(LINK_STATE[l.state][1])}"${bad ? ` style="color:${RED};border-color:${hexA(RED, .5)}"` : l.state === 'silent' ? ` style="color:${AMBER};border-color:${hexA(AMBER, .5)}"` : ''}>${LINK_STATE[l.state][0]}</span>${(h => h.length ? `<details class="lhints"><summary>${l.state === 'gap' || l.state === 'silent' ? T('what to check') : T('why the ends differ')}</summary>${h.map(x => `<p>${x}</p>`).join('')}</details>` : '')(linkHints(l, d => esc(nm(d)), !!topo.live))}</td>
          <td class="num">${sr(l.a_out, l.b_in, inet)}</td><td class="num">${inet ? `<b class="mono">${fmtB(l.a_in)}</b>` : sr(l.b_out, l.a_in)}</td>
          <td class="nat">${l.evidence === 'subnet' ? T('subnet') + ' ' + esc(l.net) : l.evidence === 'wan' ? T('WAN interface') : T('addresses in the records')}</td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty">${T('This device has no layer-3 neighbours among the devices: set interface addresses in Settings → Devices → Interfaces, or wait for traffic between the devices.')}</div>`);
    if (tb) tb.classList.remove('loading');
  };
  const drawPath = () => {
    if (!path) { fill('nPath', `<p class="note" style="margin:8px 0 0">${T('Enter an address or a network on each side. Each device on the way shows the interfaces the traffic used; a device whose interface on the way recorded nothing at all marks a gap.')}</p>`); return; }
    const hs = path.hops, real = hs.filter(h => !['internet', 'unplaced', 'branch'].includes(h.state)), obs = real.filter(h => h.state === 'observed').length, gaps = real.filter(h => h.state === 'gap' || h.state === 'unobserved').length;
    if (!hs.length) { fill('nPath', `<div class="empty">${T('No device recorded traffic from this source to this destination in the period.')}</div>`); return; }
    const total = Math.max(0, ...hs.map(h => h.bytes));
    const el = fill('nPath', `<div class="pstats"><div><span>${T('Hops')}</span><b>${real.length}</b></div><div><span>${T('Observed')}</span><b>${obs} / ${real.length}</b></div><div><span>${T('Gaps')}</span><b${gaps ? ` style="color:${RED}"` : ''}>${gaps}${gaps ? ' ⚠' : ''}</b></div><div><span>${T('Traffic')}</span><b>${fmtB(total)}</b></div></div>
      <ol class="hops">${hs.map((h, k) => { const bad = h.state === 'gap' || h.state === 'unobserved', warn = h.state === 'not_seen' || h.state === 'silent', hint = hopHint(h, esc(nm((hs[k - 1] || hs[k + 1] || {}).device || '')));
        return `<li class="hop ${h.state}" data-dev="${esc(h.device)}"><span class="no">${h.state === 'unplaced' ? '?' : h.state === 'branch' ? '↳' : k + 1}</span><div><b>${esc(h.state === 'internet' ? T('Internet') : h.name)}</b>
          ${h.state === 'observed' || h.state === 'unplaced' || h.state === 'branch' ? `<div class="mono">${esc(h.in_name)} → ${esc(h.out_name)}</div><div class="nat">${fmtB(h.bytes)} · ${fmtN(h.convs)} ${T('conversations')}${h.share < 1 ? ` · ${Math.round(100 * h.share)}% ${T('of the busiest hop')}` : ''}</div>
            <div class="vbar"><i style="width:${(100 * h.share).toFixed(1)}%;background:linear-gradient(90deg,${hexA(C.down, .6)},${C.down})"></i></div>` : ''}
          ${h.nat && h.nat.length ? `<div class="nat">NAT → <span class="mono">${esc(h.nat.join(', '))}</span></div>` : ''}
          ${(h.other_exits || []).map(e => `<div class="nat">${T('also leaves via')} <span class="mono">${esc(e.out_name)}</span>${e.next ? ` → ${esc(nm(e.next))}` : ''}: ${fmtB(e.bytes)}</div>`).join('')}
          <div class="st"${bad ? ` style="color:${RED}"` : warn ? ` style="color:${AMBER}"` : ''}>${HOP_STATE[h.state]}${h.state === 'branch' ? ` ${T('of hop')} ${h.via_hop + 1}` : ''}</div>${hint ? `<div class="nat lhint">${hint}</div>` : ''}</div></li>`; }).join('')}</ol>
      <p class="note" style="margin:6px 0 0">${path.complete ? T('Every device on the way recorded the traffic.') : T('The path is not seen whole: see the marked hops.')}</p>`);
    if (el) el.querySelectorAll('li[data-dev]').forEach(li => li.onclick = () => { const d = li.dataset.dev; if (d === 'internet' || d === state.netPov) return; state.netPov = d; render(); });
  };
  const load = () => api('topology', {...P(), pov:state.netPov || '', depth});
  const show = d => { if (seq !== renderSeq) return; topo = d; state.netPov = d.pov;
    const opts = d.devices.slice().sort((a, b) => a.name.localeCompare(b.name)).map(x => `<option value="${esc(x.ip)}"${x.ip === d.pov ? ' selected' : ''}${!x.neighbours ? ' disabled' : ''}>${esc(x.name)} (${esc(x.ip)})${!x.neighbours ? ' — ' + T('no L3 neighbours') : ''}</option>`).join('');
    fill('nPovSeg', `<label class="sel glass" title="${T('Point of View')}">${icon(ICO.dev, 16)}<select id="nPovSel" aria-label="${T('Point of View')}">${opts}</select></label>`);
    const ps = document.getElementById('nPovSel'); if (ps) ps.onchange = () => { state.netPov = ps.value; render(); };
    if (wb) { wb.stop(); wb = null; } map.set(d); drawSide(); };
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
  load().then(d => { show(d); if (state.netPath && state.netSrc && state.netDst) trace(); }).catch(e => { if (wb) { wb.stop(); wb = null; } if (seq === renderSeq) { fill('cNet', errBox(e)); fill('nLinks', ''); } });
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
        <div><span>${T('Interfaces')}</span><b>${esc(ifLabel(f.exporter, f.in_if))} → ${esc(ifLabel(f.exporter, f.out_if))}</b></div><div><span>DSCP</span><b>${f.dscp == null || f.dscp === 255 ? T('not reported') : esc(DSCP_NAME(f.dscp)) + (f.dscp_out != null && f.dscp_out !== 255 && f.dscp_out !== f.dscp ? ' → ' + esc(DSCP_NAME(f.dscp_out)) + ' ' + T('(re-marked)') : '')}</b></div><div><span>${T('Sampling')}</span><b>${f.sampling > 1 ? '1:' + f.sampling + T(' (volume scaled up)') : T('1:1 (not sampled)')}</b></div><div><span>L4</span><b>${({1:'ICMP', 6:'TCP', 17:'UDP', 50:'ESP', 47:'GRE'})[f.proto] || f.proto}</b></div></div></td></tr>` : ''}`).join('') || `<tr><td colspan="11"><div class="empty">${T('No records for this filter')}</div></td></tr>`}
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
// (1.8.7) the user's named networks: the label of a group ('' = addresses in none of them) and its networks in short
const netLabel = k => k || T('no network');
const netsText = (nets, k) => !k ? T('addresses in none of the named networks') : nets.length > 2 ? `${nets.slice(0, 2).join(', ')} +${nets.length - 2}` : nets.join(', ');
function netsCsv(rows, secs){
  return [['rank', 'network', 'networks', 'hosts', 'bytes', 'upload', 'download', 'percent', 'flows', 'avg_bps'],
    rows.map((r, i) => [i + 1, netLabel(r.k), (r.nets || []).join(' '), r.hosts || 0, tot(r), r.up, r.dn, (100 * tot(r) / (window.__tTotal || 1)).toFixed(2), r.fl, Math.round(tot(r) * 8 / secs)])];
}
function vTalkers(){
  const v = document.getElementById('view');
  // Hosts | Networks (1.8.7): the same panels, grouped by inside host or by the user's named network
  const byNet = state.talkersBy === 'net', fk = byNet ? 'net' : 'ip', dim = byNet ? 'net' : 'int_ip', noNets = byNet && !(META.networks || []).length;
  v.innerHTML = `<div class="grid">
    <div id="tKpi" class="s12 grid" style="grid-column:span 12"><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div></div>
    <div class="col s8 fillcol">
      <section class="glass panel">${ph('users', byNet ? T('Top networks') : T('Top hosts'), byNet ? T('your named networks by total volume · click a row to add the network to the filters') : T('by total volume · click a row to add the host to the filters'),
        seg('tBySeg', [['ip', T('Hosts')], ['net', T('Networks'), T('Grouped by the networks named in Settings → Flow configuration')]], fk) + '<button class="lnk" id="tMore"></button>')}<div id="tBox" class="loading"></div></section>
      <section class="glass panel grow">${ph('chart', byNet ? T('Top networks trend') : T('Top hosts trend'), T('top 5 and the rest'))}<div class="chart" id="cTop5"></div></section>
    </div>
    <div class="col s4">
      <section class="glass panel">${ph('pie', byNet ? T('Top networks traffic') : T('Top hosts traffic'), T('share of the total volume'))}<div id="tDonut" class="loading"></div></section>
      <section class="glass panel">${ph('grid', T('By service'), T('share of traffic · click to filter'))}<div id="tSvc" class="loading"></div></section>
      <section class="glass panel">${ph('globe', T('Where the traffic goes'), T('destination countries'))}<div id="tGeo" class="loading"></div></section>
      <section class="glass panel">${ph('search', T('Quick actions'), '<span id="qaFor">—</span>')}<div class="qa" id="qa"></div></section>
    </div>
    <section class="glass panel s12">${ph('list', byNet ? T('Top networks in detail') : T('Top hosts in detail'), T('main service and protocol of each · click to filter'), `<button class="lnk" id="toFlows2">${T('Flows →')}</button>`)}<div id="tDetail" class="loading"></div></section></div>`;
  document.getElementById('toFlows2').onclick = () => { state.view = 'flows'; render(); };
  wireSeg('tBySeg', x => { if (x === fk) return; state.talkersBy = x === 'net' ? 'net' : null; render(); });
  const limit = state.talkersAll ? 50 : 10, secs = rangeSecs();
  fill('tMore', state.talkersAll ? T('Show top 10') : T('Show top 50'));
  document.getElementById('tMore').onclick = () => { state.talkersAll = !state.talkersAll; render(); };
  const colorOf = new Map();
  let selected = null, topRows = [];
  const csvName = `flowtrack-top-${byNet ? 'networks' : 'hosts'}-${isCustom() ? state.from + '-' + state.to : state.range}.csv`;
  const withF = (view, extra) => () => { putFilter({k:fk, v:selected.k, neg:false}); if (extra) extra(); state.view = view; render(); };
  const drawQa = () => {
    const h = selected; fill('qaFor', h ? T('for {name}', {name: esc(byNet ? h.k : h.name || h.k)}) : T('no data'));
    const acts = !h ? [] : [
      ['flow', T('Flow details'), T('the Flows page with a filter'), withF('flows')],
      byNet ? ['users', T('Hosts of the network'), T('its top hosts'), withF('talkers', () => { state.talkersBy = null; })] : ['users', T('Host card'), T('services, protocols, destinations'), () => openHost(h.k)],
      ['globe', T('Geolocation'), byNet ? T('connection map of this network') : T('connection map of this host'), withF('geo')],
      ['list', T('Export CSV'), byNet ? T('the top networks table') : T('the top hosts table'), () => downloadCsv(csvName, ...(byNet ? netsCsv : hostsCsv)(topRows, secs))]];
    const box = fill('qa', acts.map(([ic, t, sub], i) => `<button class="qa-btn" data-qa="${i}"><span class="ico">${icon(ICO[ic], 18)}</span><span><b>${t}</b><small>${sub}</small></span></button>`).join(''));
    if (box) box.querySelectorAll('[data-qa]').forEach(b => b.onclick = acts[+b.dataset.qa][3]);
  };
  section('tKpi', async () => {
    const [s, ser, t] = await Promise.all([api('summary'), api('series'), noNets ? {rows:[], total:0} : api('top', {dim, limit:byNet ? 2 : 1})]);
    const trend = (a, b) => !s.has_prev || !b ? `<span class="tr nodata" style="color:var(--ink3)">${T('data since {time}', {time: hhmm(s.oldest)})}</span>` : `<span class="tr ${a < b ? 'dn' : ''}">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
    const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]), top = byNet ? t.rows.find(r => r.k) : t.rows[0];
    const card = (ic, k, v, tr, sp, col, sub) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sub ? `<span class="s" style="grid-column:2/-1;font-size:12.5px;color:var(--ink2)">${sub}</span>` : ''}${sp ? sparkSvg(sp, col) : ''}</div>`;
    return card('pulse', T('Total traffic'), fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
      + (byNet ? card('ip', T('Top network (by volume)'), esc(top ? top.k : '—'), '', null, '', top ? `${esc(netsText(top.nets || [], top.k))} · ${fmtB(tot(top))} (${pct(tot(top), t.total)})` : '')
        : card('ip', T('Top host (by volume)'), esc(top ? top.name || top.k : '—'), '', null, '', top ? `${esc(top.name ? top.k + ' · ' : '')}${fmtB(tot(top))} (${pct(tot(top), t.total)})` : ''))
      + card('users', T('Unique hosts'), fmtN(s.hosts), trend(s.hosts, s.p_hosts), fl.map(Math.sqrt), C.int)
      + card('nodes', T('Total flows'), fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext);
  });
  if (noNets) {          // nothing named yet: say where networks get their names
    const box = fill('tBox', `<div class="empty">${T('No named networks yet. Give your networks names in Settings → Flow configuration (e.g. 172.16.0.0/24 → Office), and their traffic shows here.')}
      <div style="margin-top:10px"><button class="btn primary" id="toNets">${T('Name networks')}</button></div></div>`);
    if (box) { box.classList.remove('loading'); document.getElementById('toNets').onclick = () => { state.view = 'settings'; state.setTab = 'flowcfg'; render(); }; }
    ['tDonut', 'tDetail', 'cTop5'].forEach(id => { const el = fill(id, `<div class="empty">${T('No data')}</div>`); if (el) el.classList.remove('loading'); });
    drawQa();
  } else Promise.all([api('top', {dim, limit}), api('series', {by:dim, top:Math.min(limit, 20)})]).then(([t, ser]) => {
    topRows = t.rows; window.__tTotal = t.total;
    t.rows.forEach((r, i) => colorOf.set(r.k, byNet && !r.k ? C.other : HOSTPAL[i % HOSTPAL.length]));
    const fip = (state.filters.find(f => f.k === fk && !f.neg) || {}).v;
    selected = t.rows.find(r => r.k === fip) || t.rows.find(r => r.k) || null; drawQa();
    const sp = new Map(); for (const [ts, k, b] of ser.rows) { if (!sp.has(k)) sp.set(k, new Map()); sp.get(k).set(ts, b); }
    const {ts} = grid(ser), max = t.rows.length ? tot(t.rows[0]) : 1, conn = isInternal() && !byNet, cols = 8 + (conn || byNet ? 1 : 0);
    const label = r => byNet ? netLabel(r.k) : r.name || r.k;
    const who = (r, c) => byNet
      ? `<div class="hcell"><span class="hbar" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="htxt"><b>${esc(netLabel(r.k))}</b><span class="nat mono" title="${esc((r.nets || []).join(', '))}">${esc(netsText(r.nets || [], r.k))}</span></span></div>`
      : `<div class="hcell"><span class="hbar" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="htxt"><b class="mono">${esc(r.k)}</b><span class="nat">${esc(r.name || (r.k.startsWith('10.') || r.k.startsWith('192.168.') || r.k.startsWith('172.') ? T('no name') : T('public address')))}</span></span></div>`;
    const pick = r => !byNet || r.k ? ` data-pick="${esc(r.k)}" title="${T('Add to filters')}"` : '';
    const box = fill('tBox', `<div class="tw"><table class="talkers"><thead><tr><th>#</th><th>${byNet ? T('Network') : T('Host / IP')}</th><th style="width:26%">${T('Volume')}</th>${conn ? `<th class="num" title="${T('→ inside hosts it connected to · ← inside hosts that connected to it')}">${T('Connections')}</th>` : byNet ? `<th class="num">${T('Hosts')}</th>` : ''}<th class="num">%</th><th class="num">Flows</th><th class="num">${T('Avg rate')}</th><th>${T('Trend')}</th><th></th></tr></thead><tbody>
      ${t.rows.map((r, i) => { const c = colorOf.get(r.k);
        return `<tr class="${pick(r) ? 'click' : ''}${r.k === fip ? ' is-picked' : ''}"${pick(r)}><td class="mono">${i + 1}</td><td>${who(r, c)}</td>
          <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .55)},${c});box-shadow:0 0 8px ${hexA(c, .6)}"></i></div>${isInternal() ? `<span class="nat mono"><span class="u" title="${T('sent')}">↑ ${fmtB(r.up)}</span> <span class="d" title="${T('received')}">↓ ${fmtB(r.dn)}</span></span>` : ''}</td>
          ${conn ? `<td class="num mono"><span class="u" title="${T('inside hosts it connected to')}">→ ${fmtN(r.calls || 0)}</span> · <span class="d" title="${T('inside hosts that connected to it')}">← ${fmtN(r.callers || 0)}</span></td>` : byNet ? `<td class="num mono">${fmtN(r.hosts || 0)}</td>` : ''}<td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${fmtN(r.fl)}</td><td class="num mono">${fmtR(tot(r) * 8 / secs)}</td>
          <td style="width:120px">${sp.has(r.k) ? sparkSvg(ts.map(x => sp.get(r.k).get(x) || 0), c, 120, 26) : ''}</td><td>${!byNet ? `<button class="btn" data-open="${esc(r.k)}" title="${T('Host card')}">›</button>` : r.k ? `<button class="btn" data-open="${esc(r.k)}" title="${T('Hosts of the network')}">›</button>` : ''}</td></tr>`; }).join('') || `<tr><td colspan="${cols}"><div class="empty">${T('No data')}</div></td></tr>`}</tbody></table></div>`);
    if (box) { box.classList.remove('loading');
      box.querySelectorAll('tr[data-pick]').forEach(tr => tr.onclick = () => addFilter(fk, tr.dataset.pick));
      box.querySelectorAll('[data-open]').forEach(b => b.onclick = e => { e.stopPropagation();
        if (byNet) { putFilter({k:'net', v:b.dataset.open, neg:false}); state.talkersBy = null; state.sel = null; render(); } else openHost(b.dataset.open); }); }
    // donut: top 5 + rest, same colours as the table
    const top5 = t.rows.slice(0, 5), rest = t.total - top5.reduce((a, r) => a + tot(r), 0);
    const drows = [...top5.map(r => ({k:r.k, label:label(r), up:r.up, dn:r.dn})), ...(rest > 0 ? [{k:'__other', label:T('Others'), up:rest, dn:0}] : [])];
    const db = fill('tDonut', `<div class="donut-wrap"><div class="chart donut" id="cTDonut"></div><div class="dl">${drows.map(r => `<i class="idot" style="background:${r.k === '__other' ? C.other : colorOf.get(r.k)}"></i>${r.k === '__other' ? `<span>${T('Others')}</span>` : byNet && !r.k ? `<span>${esc(r.label)}</span>` : `<button class="link${byNet ? '' : ' mono'}" data-f="${fk}" data-v="${esc(r.k)}">${esc(r.label)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t"></span>`).join('')}</div></div>`);
    if (db) { db.classList.remove('loading'); wireFilters(db); donut(document.getElementById('cTDonut'), drows.map(r => ({...r, k:r.label})), k => { const r = drows.find(x => x.label === k); return r.k === '__other' ? C.other : colorOf.get(r.k); }, [fmtB(t.total), T('all traffic')]); }
    // stacked trend: top 5 + others, same colours
    api('series', {by:dim, top:5}).then(s5 => { const el = document.getElementById('cTop5'); if (!el) return;
      const {ts: t5, step} = grid(s5), keys = new Map(); for (const [x, k, b] of s5.rows) { if (!keys.has(k)) keys.set(k, new Map()); keys.get(k).set(x, b); }
      const order = [...keys.keys()].sort((a, b) => (a === '__other') - (b === '__other'));
      const c = mkChart(el);
      c.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true}, legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
        tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(t5), yAxis:axisY(v => fmtR(v)),
        series:order.map(k => { const col = k === '__other' ? C.other : (colorOf.get(k) || C.other), r = t.rows.find(x => x.k === k);
          return {name:k === '__other' ? T('others') : byNet ? netLabel(k) : (r && r.name) || k, type:'line', stack:'a', smooth:.3, showSymbol:false, lineStyle:{width:1.6, color:col}, itemStyle:{color:col},
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
  if (!noNets) section('tDetail', async () => { const d = await api('top', {dim:byNet ? 'net_svc' : 'host_svc', limit:6});
    return `<div class="tw"><table class="compact"><thead><tr><th>${byNet ? T('Network') : T('Host')}</th><th>${T('Main service')}</th><th>${T('Protocol')}</th><th class="num">${T('Volume')}</th></tr></thead><tbody>${d.rows.map((r, i) => { const c = byNet && !r.k ? C.other : HOSTPAL[i % HOSTPAL.length];
      return `<tr${byNet && !r.k ? '' : ` class="click" data-f="${fk}" data-v="${esc(r.k)}"`}><td><span class="idot" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="${byNet ? '' : 'mono'}">${esc(byNet ? netLabel(r.k) : r.name || r.k)}</span></td><td>${svcBadge(r.service)}</td><td><span class="tag">${L4[r.proto] || r.proto} · ${esc(dv(r.l7))}</span></td><td class="num mono">${fmtB(tot(r))}</td></tr>`; }).join('')}</tbody></table></div>`; });
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
    setTimeout(() => document.querySelectorAll('#pTbl [data-pname]').forEach(b => b.onclick = e => { e.stopPropagation(); const [pr, po] = b.dataset.pname.split('/'); openPortName(pr, +po); }));
    return `<div class="tw"><table><thead><tr><th>${T('Port')}</th><th>${T('Protocol')}</th><th>${T('Typical service')}</th><th style="width:24%">${T('Volume')}</th><th class="num">%</th><th class="num">${T('Hosts')}</th><th class="num">${T('col::Outside addresses')}</th><th class="num">Flows</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="port" data-v="${esc(r.k)}"><td><b class="mono">${esc(r.k)}</b></td><td><span class="tag">${L4[r.proto_n] || r.proto_n} · ${esc(dv(r.l7))}</span>${isAdmin() && (+r.proto_n === 6 || +r.proto_n === 17) && +r.k > 0 ? ` <button class="btn tiny" data-pname="${+r.proto_n === 17 ? 'udp' : 'tcp'}/${esc(r.k)}" title="${T('Give this port a name of yours')}" aria-label="${T('Give this port a name of yours')}">✎</button>` : ''}</td><td>${svcBadge(r.service)}</td>
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
  link_load:[T('Link near capacity'), T('an interface stays above this share of its capacity — your figures in Settings → Devices → Interfaces, else its speed — in every 5 minutes of the span, incoming or outgoing'),
    {pct:T('% of capacity'), span:T('minutes')}],
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
// an exclusion rule as people read it: "↑ 10.0.0.5 → 203.0.113.7:443", "↓ any → 10.0.0.9:8443"
const exText = r => `${({up:'↑', down:'↓'})[r.dir] || '⇅'} ${r.src || T('any')} → ${r.dst ? (r.dst.includes(':') && !r.dst.includes('/') && r.port ? `[${r.dst}]` : r.dst) : T('any')}${r.port ? ':' + r.port : ''}`;
// the rule the Exclude button of an event proposes: this source -> this target:port, in the event's direction
const UPLOAD_KINDS = ['sustained_upload', 'inside_scan', 'lateral_scan', 'malware_contact', 'listed_contact', 'new_country', 'burst'];
const exOf = x => (x.src || x.ip) && (x.dst || x.port) ? {dir:UPLOAD_KINDS.includes(x.kind) ? 'up' : 'down', src:x.src || x.ip, dst:x.dst || '', port:x.port || 0} : null;
const evFilter = x => x.fk && x.fv ? [x.fk, x.fv] : x.ip ? ['ip', x.ip] : x.device ? ['device', x.device] : null;
// (1.17.0) one colour per kind, the same on the page and in the PDF reports (reports.EV_COLORS); the collector's
// health, the license and the reports share the grey
const EV_COLOR = {port_scan:'#FF9F43', brute_force:'#FF5C7A', probes:'#6E9BFF', heavy_client:'#FFD166', ddos:'#E8384F', inside_scan:'#C77DFF',
  lateral_scan:'#8B5CFF', link_load:'#27D3F5', malware_contact:'#FF4FA0', listed_contact:'#F7A1C4', listed_inbound:'#2F7BFF',
  sustained_upload:'#2EE59D', burst:'#3FC8B4', new_country:'#A3E635'};
const evColor = k => EV_COLOR[k] || C.other;
const cap1 = s => String(s).charAt(0).toUpperCase() + String(s).slice(1);
// one event as a card: what happened, priority, when, and its buttons (Filter / Exclude / Ignore)
function evRow(x, sevs){
  return `<div class="alert ${x.sev}"><span class="sev">${x.sev === 'info' ? 'i' : '!'}</span><div class="body"><b>${esc(x.title)}</b> <span class="evkind" style="--c:${evColor(x.kind)}"></span><p>${esc(x.text)}</p></div>
      <div class="meta"><span class="pill ${x.sev}">${sevs[x.sev] || x.sev}</span><span class="mono">${x.stored && x.first !== x.last ? esc(evRange(x.first, x.last)) : esc(evTime(x.when))}</span>
        <span class="acts">${evFilter(x) ? `<button class="btn" data-f="${evFilter(x)[0]}" data-v="${esc(evFilter(x)[1])}" title="${esc(`${FILTER_LABEL[evFilter(x)[0]] || evFilter(x)[0]}: ${evFilter(x)[1]}`)}">${T('Filter')}</button>` : ''}${exOf(x) && isAdmin() ? `<button class="btn" data-exc="${esc(JSON.stringify(exOf(x)))}" title="${esc(T('Do not show events of this connection in this direction') + ': ' + exText(exOf(x)))}">${T('Exclude')}</button>` : ''}${x.stored && x.src && isAdmin() ? `<button class="btn" data-ign="${esc(x.src)}" title="${T('Do not record or show events of this address')}">${T('Ignore')}</button>` : ''}</span></div></div>`;
}
// the Exclude / Ignore buttons of a list; `again` shows the page anew after a change
function wireEvActs(root, again){
  root.querySelectorAll('[data-exc]').forEach(b => b.onclick = async () => { const r = JSON.parse(b.dataset.exc);
    if (!confirm(T('Exclude {rule}? Such events will no longer be shown or notified. You can change it in Settings → Events.', {rule: exText(r)}))) return;
    try { await apiPost('events/exclude', r); again(); } catch (e) { alert(e.message); } });
  root.querySelectorAll('[data-ign]').forEach(b => b.onclick = async () => {
    if (!confirm(T('Ignore {addr}? Its events will no longer be recorded or shown. You can undo it in Settings → Events.', {addr: b.dataset.ign}))) return;
    try { await apiPost('events/ignore', {value:b.dataset.ign}); again(); } catch (e) { alert(e.message); } });
}
// the page's own choice of priority / kind (not a filter of the other pages): what the list and «All events» show
const evQuery = (extra = {}) => ({tz:capTz(), ...(state.evSev && state.evSev !== 'all' ? {sev:state.evSev} : {}), ...(state.evKind ? {kind:state.evKind} : {}), ...extra});
const evSkip = res => { const skip = (res.unfiltered || []).map(k => FILTER_LABEL[k] || k); return skip.length ? `<p class="note evskip">${T('Not applied to events')}: ${esc(skip.join(', '))}</p>` : ''; };
const evCut = res => res.stats.truncated ? T('The period has more events than are read at once ({n}): the oldest are left out — choose a shorter period.', {n:fmtN(res.stats.total)}) : '';
// (1.17.0) Events: visual first — cards, how the number changes over time by kind, the share of each kind; then the
// newest 30 and «All events» for the rest. A period that ends now refreshes every minute.
function vThreats(){
  const v = document.getElementById('view'), sevs = SEV(), kinds = EV_KINDS();
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12 caphead">${ph('shield', T('Events and anomalies'), T('in the chosen period and filters · scans, password guessing and floods are checked every 10 minutes'), `<button class="btn" id="evAllTop">${T('All events')} →</button>`, true)}</section>
    <div id="evKpi" style="display:contents"></div>
    <section class="glass panel s8 evfill">${ph('chart', T('Events over time'), `<span id="evChartSub">${T('how many began, by kind · click a kind to show only it')}</span>`)}<div id="evChart" class="loading" style="height:320px"></div><p class="note" id="evChartNote" hidden></p></section>
    <section class="glass panel s4">${ph('pie', T('By kind'), `<span id="evPieSub">${T('of the events in the period')}</span>`)}<div id="evPie" class="loading"></div></section>
    <section class="glass panel s8">${ph('list', T('Latest events'), `<span id="evListSub">${T('the newest 30')}</span>`)}<div id="alBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('search', T('What is watched'), '', isAdmin() ? `<button class="btn" id="evCfg">${T('Configure')}</button>` : '')}<div id="watchBox" class="loading"></div></section></div>`;
  if (isAdmin()) document.getElementById('evCfg').onclick = () => { state.view = 'settings'; state.setTab = 'events'; render(); };
  document.getElementById('evAllTop').onclick = () => { state.view = 'events'; state.evPage = 0; render(); };
  const seq = renderSeq, done = (id, html) => { const el = fill(id, html); if (el) el.classList.remove('loading'); return el; };
  let chart = null, pie = null, first = true;
  // (1.16.1) the kind under the pointer is brought forward after a short pause and the others fade over 0.3 s — the
  // built-in focus of ECharts darkened the whole chart at once on every segment the pointer crossed
  // (ECharts does not animate a changed opacity, so the fade is stepped here, frame by frame)
  let curOrder = [], hoverK = '', hoverT = 0, fadeF = 0, shown = {};
  const evOp = k => !hoverK || hoverK === k ? 1 : .35;
  const fade = () => { cancelAnimationFrame(fadeF); if (!chart || chart.isDisposed()) return;
    const from = {...shown}, t0 = performance.now(), D = REDUCED.matches ? 0 : 300;
    const step = now => { if (chart.isDisposed()) return; const u = D ? Math.min(1, (now - t0) / D) : 1, e = 1 - Math.pow(1 - u, 3);
      chart.setOption({series:curOrder.map(([id]) => { const a = from[id] ?? 1, v = a + (evOp(id) - a) * e; shown[id] = v; return {id, itemStyle:{opacity:v}}; })}, {lazyUpdate:false, silent:true});
      if (u < 1) fadeF = requestAnimationFrame(step); };
    fadeF = requestAnimationFrame(step); };
  const focusTo = k => { clearTimeout(hoverT); hoverT = setTimeout(() => { if (hoverK === k) return; hoverK = k; fade(); }, k ? 140 : 240); };
  onCleanup(() => { clearTimeout(hoverT); cancelAnimationFrame(fadeF); });
  const draw = res => {
    const st = res.stats, all = st.total, cur = state.evSev || 'all';
    let kind = state.evKind && st.kinds[state.evKind] ? state.evKind : '';
    if (first) { first = false; const W = document.getElementById('watchBox');
      if (W) { W.classList.remove('loading'); W.innerHTML = `<div class="watch">${Object.entries(kinds).map(([k, [name, desc]]) => { const c = (res.watch || {})[k] || {};
        return `<div class="${c.on === false ? 'off' : ''}"><b><i class="evkind" style="--c:${evColor(k)}"></i>${name}</b><span class="pill ${c.on === false ? '' : c.sev}">${c.on === false ? T('off') : sevs[c.sev] || ''}</span><p>${desc}</p></div>`; }).join('')}
        <div><b>${T('Export and collector health')}</b><span class="pill warn">${sevs.warn}</span><p>${T('lost packets, a collector falling behind, the edition limit, the license')}</p></div></div>`; } }
    // the cards: all, then each priority — a card is also the priority switch of the list
    const order = Object.entries(st.kinds).sort((a, b) => b[1].n - a[1].n), most = order[0];
    const kc = (k, ic, label, val, sub, col) => `<button class="glass panel kcard s3 evcard${cur === k ? ' on' : ''}" data-sev="${k}" aria-pressed="${cur === k}" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO[ic] || ic, 22)}</span><span class="k">${label}</span><span class="v"${col ? ` style="color:${col}"` : ''}>${val}</span><span class="nat" style="grid-column:2">${sub}</span></button>`;
    fill('evKpi', kc('all', 'shield', T('Events'), fmtN(all), all ? (most ? T('most often: {kind}', {kind:esc(most[1].title)}) : '') : T('No events — all quiet'), all ? '' : 'var(--ok)')
      + kc('crit', 'pulse', cap1(sevs.crit), fmtN(st.sev.crit || 0), T('need attention now'), st.sev.crit ? 'var(--crit)' : 'var(--ink3)')
      + kc('warn', 'search', cap1(sevs.warn), fmtN(st.sev.warn || 0), T('worth a look'), st.sev.warn ? 'var(--warn)' : 'var(--ink3)')
      + kc('info', 'list', cap1(sevs.info), fmtN(st.sev.info || 0), T('for the record'), st.sev.info ? 'var(--down)' : 'var(--ink3)'));
    document.querySelectorAll('#evKpi [data-sev]').forEach(b => b.onclick = () => { state.evSev = b.dataset.sev; reload(); });
    // over time: stacked bars of the events that began in each step, a colour per kind
    const s = st.series, ts = []; for (let t = s.from; t < s.to; t += s.step) ts.push(t);
    const m = new Map(s.rows.map(r => [r[0] + ':' + r[1], r[2]]));
    const cel = document.getElementById('evChart'); cel.classList.remove('loading');
    if (!chart) { chart = mkChart(cel); zoomable(chart);
      chart.on('click', p => { if (p.seriesId) setTimeout(() => { state.evKind = state.evKind === p.seriesId ? '' : p.seriesId; reload(); }); });
      chart.on('mouseover', p => { if (p.componentType === 'series') focusTo(p.seriesId); });
      chart.on('mouseout', p => { if (p.componentType === 'series') focusTo(''); });
      chart.on('globalout', () => focusTo(''));
      chart.on('legendselectchanged', p => { chart.dispatchAction({type:'legendSelect', name:p.name}); const k = curOrder.find(o => o[1].title === p.name);
        if (k) setTimeout(() => { state.evKind = state.evKind === k[0] ? '' : k[0]; reload(); }); }); }
    const stepTxt = s.step >= 86400 ? T('a day') : s.step >= 3600 ? Tn(s.step / 3600, '{n} hour', '{n} hours') : Tn(s.step / 60, '{n} minute', '{n} minutes');
    // (1.16.1) the chosen priority and kind apply to the chart too: a priority keeps the kinds that have it (a kind has
    // one priority, set in Settings → Events), a kind only its own bars; the ring offers the kinds of the priority
    const pri = cur === 'all' ? order : order.filter(([, o]) => o.sev === cur), priN = pri.reduce((a, [, o]) => a + o.n, 0);
    if (kind && !pri.some(([k]) => k === kind)) { kind = ''; state.evKind = ''; }
    const vis = kind ? pri.filter(([k]) => k === kind) : pri, chosen = kind ? st.kinds[kind].title : cur !== 'all' ? cap1(sevs[cur]) : '';
    curOrder = vis; cancelAnimationFrame(fadeF); hoverK = ''; shown = Object.fromEntries(vis.map(([k]) => [k, 1]));
    chart.setOption({animation:!REDUCED.matches, animationDuration:450, animationEasing:'cubicOut', animationDurationUpdate:320, animationEasingUpdate:'cubicOut',
      grid:{left:30, right:10, top:36, bottom:4, containLabel:true},     // room for the first time label (date + time)
      legend:{top:0, left:0, type:'scroll', icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}, pageTextStyle:{color:C.ink2}, pageIconColor:C.ink2},
      tooltip:{...tipBase(), trigger:'axis', axisPointer:{type:'shadow', shadowStyle:{color:'rgba(120,160,255,.07)'}}, order:'valueDesc', transitionDuration:.25,
        formatter:ps => { const n = ps.reduce((a, p) => a + (p.value[1] || 0), 0); if (!n) return '';      // an empty step: no box
          const t0 = ps[0].value[0] / 1000 - s.step / 2, lbl = s.step >= 86400 ? new Date(t0 * 1000).toLocaleDateString(LOC, {day:'numeric', month:'short'}) : `${s.to - s.from > 86400 ? dmy(t0) + ' ' : ''}${hhmm(t0)} – ${hhmm(t0 + s.step)}`;
          return `${esc(lbl)} · <b>${Tn(n, '{n} event', '{n} events')}</b><br>` + ps.filter(p => p.value[1]).map(p => `${p.marker}${esc(p.seriesName)} <b>${p.value[1]}</b>`).join('<br>'); }},
      xAxis:{...axisX(ts), min:s.from * 1000, max:(ts.length ? ts[ts.length - 1] + s.step : s.to) * 1000},
      yAxis:{...axisY(v => fmtN(v)), minInterval:1},
      graphic:[{id:'evNone', type:'text', left:'center', top:'middle', silent:true, style:{text:all && !priN ? T('No events of this priority') : '', fill:C.ink3, font:'13px Manrope'}}],
      series:vis.map(([k, o]) => ({id:k, name:o.title, type:'bar', stack:'e', barMaxWidth:26, barCategoryGap:'22%', itemStyle:{color:evColor(k), opacity:evOp(k), borderRadius:0},
        emphasis:{focus:'none', itemStyle:{shadowBlur:14, shadowColor:evColor(k)}}, data:ts.map(t => [(t + s.step / 2) * 1000, m.get(t + ':' + k) || 0])}))},
      {replaceMerge:['series']});        // a refresh moves the bars to their new heights instead of drawing them anew
    fill('evChartSub', `${T('how many began, by kind · one bar = {step} · click a kind to show only it', {step:stepTxt})}${chosen ? ` · <b class="evwhat">${esc(chosen)}</b>` : ''}`);
    const cn = document.getElementById('evChartNote'), cnt = [st.before ? Tn(st.before, '{n} event began before the period and is not drawn here.', '{n} events began before the period and are not drawn here.') : '', evCut(res)].filter(Boolean);
    cn.hidden = !cnt.length; cn.innerHTML = cnt.join(' ');
    // the share of each kind
    const pel = document.getElementById('evPie'); pel.classList.remove('loading');
    fill('evPieSub', T('of the events in the period') + (chosen && !kind ? ` · <b class="evwhat">${esc(chosen)}</b>` : ''));
    if (!priN) { if (pie && !pie.isDisposed()) pie.dispose(); pie = null; pel.innerHTML = `<div class="empty evnone">${all ? T('No events of this priority') : state.filters.length ? T('No events for these filters in this period') : T('No events — all quiet')}</div>`; }
    else {
      if (!pie || !pel.querySelector('.evpie')) { pel.innerHTML = `<div class="chart evpie" style="height:230px"></div><div class="dl evleg"></div>`; pie = mkChart(pel.querySelector('.evpie'));
        pie.on('click', p => setTimeout(() => { state.evKind = state.evKind === p.data.id ? '' : p.data.id; reload(); })); }
      pie.setOption({animation:false, tooltip:{...tipBase(), formatter:p => `${esc(p.name)}<br><b>${Tn(p.value, '{n} event', '{n} events')}</b> · ${p.percent}%`},
        title:{text:fmtN(kind ? st.kinds[kind].n : priN), subtext:chosen || T('events'), left:'center', top:'38%', textStyle:{color:C.ink, fontFamily:'JetBrains Mono', fontSize:18, fontWeight:700}, subtextStyle:{color:C.ink2, fontFamily:'Manrope', fontSize:11.5, width:120, overflow:'truncate'}},
        series:[{type:'pie', radius:['64%', '86%'], padAngle:2, itemStyle:{borderRadius:5}, label:{show:false}, emphasis:{scale:true, scaleSize:4},
          data:pri.map(([k, o]) => ({id:k, name:o.title, value:o.n, itemStyle:{color:evColor(k), opacity:kind && kind !== k ? .25 : 1, shadowBlur:12, shadowColor:evColor(k)}}))}]}, {notMerge:true});
      pel.querySelector('.evleg').innerHTML = pri.map(([k, o]) => `<i class="idot" style="background:${evColor(k)}"></i><button class="link${kind === k ? ' on' : ''}" data-kind="${k}">${esc(o.title)}</button><span class="p">${pct(o.n, priN)}</span><span class="t">${fmtN(o.n)}</span>`).join('');
      pel.querySelectorAll('[data-kind]').forEach(b => b.onclick = () => { state.evKind = state.evKind === b.dataset.kind ? '' : b.dataset.kind; reload(); });
    }
    // the newest events of the chosen priority / kind
    const what = [cur !== 'all' ? sevs[cur] : '', kind ? st.kinds[kind].title : ''].filter(Boolean);
    fill('evListSub', (res.matched > res.alerts.length ? T('the newest {n} of {all}', {n:res.alerts.length, all:fmtN(res.matched)}) : Tn(res.matched, '{n} event', '{n} events'))
      + (what.length ? ` · <span class="fchip evsel"><span>${esc(what.join(' · '))}</span><button id="evSelX" aria-label="${T('Show all')}" title="${T('Show all')}">×</button></span>` : ''));
    const x = document.getElementById('evSelX'); if (x) x.onclick = () => { state.evSev = 'all'; state.evKind = ''; reload(); };
    const box = done('alBox', evSkip(res) + (!all ? `<div class="empty">${state.filters.length ? T('No events for these filters in this period') : T('No events — all quiet')}</div>`
      : !res.alerts.length ? `<div class="empty">${T('No events of this priority')}</div>`
      : '<div class="alerts dense">' + res.alerts.map(e => evRow(e, sevs)).join('') + '</div>'
        + (res.matched > res.alerts.length ? `<div class="evmore"><button class="btn primary" id="evAll">${T('All events ({n})', {n:fmtN(res.matched)})} →</button></div>` : '')));
    if (box) { wireFilters(box); wireEvActs(box, reload); const b = document.getElementById('evAll'); if (b) b.onclick = () => { state.view = 'events'; state.evPage = 0; render(); }; }
  };
  const load = () => api('alerts', evQuery({limit:30}));
  const reload = () => load().then(r => { if (seq === renderSeq) draw(r); }).catch(e => fill('alBox', errBox(e)));
  load().then(r => { if (seq === renderSeq) draw(r); }).catch(e => { ['evChart', 'evPie', 'alBox'].forEach(id => done(id, errBox(e))); });
  if (!isCustom()) every(60000, reload);
}
// (1.17.0) every event of the period, a page of 50 at a time: priority, kind, a text search; the newest first
const EV_PAGE = 50;
function vEvents(){
  const v = document.getElementById('view'), sevs = SEV(), cur = state.evSev || 'all';
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('list', T('All events'), T('in the chosen period and filters · the newest first'), `<button class="btn" id="evBack">← ${T('Events')}</button>`, true)}
    <div class="evbar"><div id="evSevBox"></div><select id="evKindSel" aria-label="${T('Kind')}"><option value="">${T('All kinds')}</option></select>
      <input id="evQ" type="search" placeholder="${T('Search: address, text …')}" value="${esc(state.evQ || '')}" autocomplete="off"><span class="note" id="evCount"></span></div>
    <div id="evNote" hidden></div><div id="evList" class="loading"></div><div class="evpager" id="evPager"></div></section></div>`;
  document.getElementById('evBack').onclick = () => { state.view = 'threats'; render(); };
  const seq = renderSeq;
  const load = () => {
    const page = state.evPage || 0;
    return api('alerts', evQuery({limit:EV_PAGE, offset:page * EV_PAGE, ...(state.evQ ? {q:state.evQ} : {})})).then(res => { if (seq !== renderSeq) return;
      const st = res.stats, kinds = Object.entries(st.kinds).sort((a, b) => b[1].n - a[1].n);
      fill('evSevBox', seg('evSev', [['all', `${T('All')} <span class="mono">${st.total}</span>`], ...['crit', 'warn', 'info'].map(k => [k, `${cap1(sevs[k])} <span class="mono">${st.sev[k] || 0}</span>`])], cur));
      wireSeg('evSev', k => { state.evSev = k; state.evPage = 0; render(); });
      const ks = document.getElementById('evKindSel');
      ks.innerHTML = `<option value="">${T('All kinds')}</option>` + kinds.map(([k, o]) => `<option value="${k}">${esc(o.title)} (${o.n})</option>`).join('');
      ks.value = state.evKind && st.kinds[state.evKind] ? state.evKind : '';
      const nb = document.getElementById('evNote'), notes = evSkip(res) + (evCut(res) ? `<p class="note">${evCut(res)}</p>` : ''); nb.hidden = !notes; nb.innerHTML = notes;
      const n = res.matched, a = res.offset + 1, b = res.offset + res.alerts.length;
      fill('evCount', n ? T('{a}–{b} of {n}', {a, b, n:fmtN(n)}) : '');
      const box = fill('evList', n ? '<div class="alerts dense">' + res.alerts.map(e => evRow(e, sevs)).join('') + '</div>'
        : `<div class="empty">${st.total ? T('No events match') : state.filters.length ? T('No events for these filters in this period') : T('No events — all quiet')}</div>`);
      if (box) { box.classList.remove('loading'); wireFilters(box); wireEvActs(box, load); }
      const pages = Math.ceil(n / EV_PAGE);
      fill('evPager', pages > 1 ? `<button class="btn" data-p="${page - 1}" ${page ? '' : 'disabled'}>← ${T('Newer')}</button><span class="mono">${T('page {p} of {n}', {p:page + 1, n:pages})}</span><button class="btn" data-p="${page + 1}" ${page + 1 < pages ? '' : 'disabled'}>${T('Older')} →</button>` : '');
      document.querySelectorAll('#evPager [data-p]').forEach(x => x.onclick = () => { state.evPage = +x.dataset.p; load().then(() => document.getElementById('view').scrollIntoView({block:'start'})); });
    }).catch(e => { const el = fill('evList', errBox(e)); if (el) el.classList.remove('loading'); });
  };
  document.getElementById('evKindSel').onchange = e => { state.evKind = e.target.value; state.evPage = 0; load(); };
  let qt = 0; document.getElementById('evQ').oninput = e => { clearTimeout(qt); qt = setTimeout(() => { state.evQ = e.target.value.trim(); state.evPage = 0; load(); }, 300); };
  load();
  if (!isCustom()) every(60000, () => { if (!(state.evPage || 0)) load(); });      // a later page stays still while read
}
// Settings → Events (administrators): detections on/off, priority, thresholds; roles of our services; exceptions
function vEventsCfg(){
  const v = document.getElementById('setBody');
  // (1.8.4) four parts, one shown at a time; Detections, Notifications and IP reputation share Save, the exceptions
  // are saved row by row
  const SUBS = [['det', T('Detections')], ['notify', T('Notifications')], ['rep', T('IP reputation')], ['exc', T('Exceptions')]];
  const sub = SUBS.some(x => x[0] === state.evSub) ? state.evSub : 'det';
  v.innerHTML = `<div class="seg evsub" id="evSub" role="tablist" aria-label="${T('Events')}">${SUBS.map(([k, l]) => `<button type="button" role="tab" data-sub="${k}" aria-selected="${k === sub}" aria-pressed="${k === sub}">${l}</button>`).join('')}</div>
    <div class="grid"><section class="glass panel s12" data-part="det">${ph('shield', T('Detections'), T('on or off, the priority each event gets, and when it triggers'))}<div id="evkBox" class="loading"></div></section>
    <section class="glass panel s12" data-part="notify">${ph('M2 9l14-6-5 14-2-6zM9 11l7-8', T('Notifications'), T('a new event goes out once · what continues is not sent again'))}<div id="evtBox" class="loading"></div></section>
    <section class="glass panel s12" data-part="rep">${ph('globe', T('IP reputation'), T('public lists of malicious addresses · downloaded once a day by this server from their publishers · checked every 10 minutes, not per record'))}<div id="evrBox" class="loading"></div></section>
    <section class="glass panel s12" data-part="exc">${ph('M4 9h10M9 4v10', T('Exclude connections'), T('the events of a connection in one direction are neither shown nor notified — e.g. a nightly backup to a server of yours'))}<div id="excBox" class="loading"></div></section>
    <section class="glass panel s12" data-part="exc">${ph('list', T('Ignore addresses'), T('no events at all about these addresses, networks or ASNs'), `<button class="lnk" id="toFlowCfg">${T('Roles of our services')} →</button>`)}<div id="ignBox" class="loading"></div></section>
    <section class="glass panel s12 evsave" data-part="det notify rep"><div><button class="btn primary" id="evSave">${T('Save')}</button> <button class="btn" id="evDef">${T('Restore defaults')}</button></div><p class="err" id="evErr"></p><p class="note" id="evOk" hidden>${T('Saved. The next 10-minute check uses the new settings.')}</p></section></div>`;
  const get = async u => { const r = await fetch(u); if (!r.ok) throw new Error((await r.json()).error || r.status); return r.json(); };
  const load = async () => { const [ev, nt] = await Promise.all([get('api/events/config'), get('api/notify')]); return {...ev, notify:nt}; };
  const show = res => {
    const cfg = res.config, kinds = EV_KINDS(), sevs = SEV();
    const box = (id, html) => { const el = document.getElementById(id); el.classList.remove('loading'); el.innerHTML = html; };
    box('evkBox', `<div class="tw form"><table class="evk"><thead><tr><th>${T('On')}</th><th>${T('Event')}</th><th>${T('Priority')}</th><th title="${T('Send this kind to Telegram')}">Telegram</th><th title="${T('Send this kind by e-mail')}">E-mail</th><th title="${T('Send this kind to the webhook')}">${T('Webhook')}</th><th title="${T('Send this kind to the SIEM')}">SIEM</th><th>${T('Triggers at')}</th></tr></thead><tbody>
      ${Object.entries(kinds).map(([k, [name, desc, thr]]) => { const c = cfg.kinds[k] || {};
        return `<tr data-k="${k}"><td><label class="chk"><input type="checkbox" data-x="on" ${c.on ? 'checked' : ''} aria-label="${esc(name)}"></label></td><td class="wrap"><b>${name}</b><p class="note">${desc}</p></td>
        <td><select data-x="sev">${['info', 'warn', 'crit'].map(s => `<option value="${s}" ${c.sev === s ? 'selected' : ''}>${sevs[s]}</option>`).join('')}</select></td>
        <td><label class="chk"><input type="checkbox" data-n="${k}" ${res.notify.kinds[k] !== false ? 'checked' : ''} aria-label="Telegram: ${esc(name)}"></label></td>
        <td><label class="chk"><input type="checkbox" data-m="${k}" ${res.notify.email_kinds[k] !== false ? 'checked' : ''} aria-label="E-mail: ${esc(name)}"></label></td>
        <td><label class="chk"><input type="checkbox" data-w="${k}" ${(res.notify.webhook_kinds || {})[k] !== false ? 'checked' : ''} aria-label="${T('Webhook')}: ${esc(name)}"></label></td>
        <td><label class="chk"><input type="checkbox" data-s="${k}" ${(res.notify.siem_kinds || {})[k] !== false ? 'checked' : ''} aria-label="SIEM: ${esc(name)}"></label></td>
        <td class="thr"><div>${Object.entries(thr).map(([t, l]) => `<label><input type="number" min="1" data-x="${t}" value="${esc(c[t])}">${l}</label>`).join('') || '<span class="note">—</span>'}</div></td></tr>`; }).join('')}</tbody></table></div>`);
    const tg = res.notify.telegram, ml = res.notify.email, wh = res.notify.webhook || {}, sm = res.notify.siem || {}, sevSel = (id, v) => `<select id="${id}">${['info', 'warn', 'crit'].map(s => `<option value="${s}" ${v === s ? 'selected' : ''}>${sevs[s]}</option>`).join('')}</select>`;
    const langSel = (id, v) => `<select id="${id}">${langs().map(([c, l]) => `<option value="${c}" lang="${c}" ${v === c ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
    const on = ch => res.notify[ch].on ? ` <span class="pill ok">${T('on')}</span>` : '';
    const ntTab = state.ntTab || 'telegram';
    box('evtBox', `<div class="seg ntseg" id="ntSeg" role="tablist">${[['telegram', 'Telegram'], ['email', 'E-mail'], ['webhook', T('Webhook')], ['siem', 'Syslog / SIEM']].map(([v, l]) =>
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
      <p class="note" style="margin:0">${T('New events by e-mail: one letter per 10-minute check, to all recipients.')}</p>
      <label class="chk"><input type="checkbox" id="mlOn" ${ml.on ? 'checked' : ''}>${T('Send new events by e-mail')}</label>
      <div id="mlSrv">${mailLine(ml)}</div>
      <label>${T('To (several: comma-separated)')}<input id="mlTo" value="${esc(ml.to.join(', '))}" placeholder="admin@example.com, noc@example.com"></label>
      <div class="two"><label>${T('Send from priority')}${sevSel('mlSev', ml.min_sev)}</label>
        <label>${T('Language of the messages')}${langSel('mlLang', ml.lang)}</label></div>
      <div><button class="btn" type="button" id="mlTest">${T('Send a test')}</button> <span class="note" id="mlSay"></span></div></div>
      <div class="form tgform" id="ntWebhook" ${ntTab === 'webhook' ? '' : 'hidden'}>
      <p class="note" style="margin:0">${T('New events as an HTTP POST: to your own system (FlowTrack JSON), or a message to Slack, Mattermost, Rocket.Chat or Discord (their incoming webhook address).')}</p>
      <label class="chk"><input type="checkbox" id="whOn" ${wh.on ? 'checked' : ''}>${T('Send new events to the webhook')}</label>
      <div class="two"><label>${T('Webhook address')}<input id="whUrl" value="${esc(wh.url)}" placeholder="https://hooks.example.com/flowtrack" autocomplete="off"></label>
        <label>${T('Format')}<select id="whFmt">${[['json', T('FlowTrack JSON')], ['slack', 'Slack / Mattermost / Rocket.Chat'], ['discord', 'Discord']].map(([v, l]) => `<option value="${v}" ${wh.format === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div>
      <div class="two"><label>${T('Secret for the signature (optional)')}<input id="whSec" type="password" autocomplete="new-password" placeholder="${wh.secret_set ? T('saved — leave empty to keep') : T('e.g. a long random string')}"></label>
        <label>${T('Extra header (optional)')}<input id="whHdr" autocomplete="off" placeholder="${wh.header_set ? esc(wh.header) + ': ' + T('saved — leave empty to keep') : 'Authorization: Bearer abc123'}"></label></div>
      ${wh.secret_set || wh.header_set ? `<div style="display:flex;gap:14px;flex-wrap:wrap">${wh.secret_set ? `<label class="chk"><input type="checkbox" id="whSecX">${T('Remove the saved secret')}</label>` : ''}${wh.header_set ? `<label class="chk"><input type="checkbox" id="whHdrX">${T('Remove the saved header')}</label>` : ''}</div>` : ''}
      <label class="chk"><input type="checkbox" id="whVerify" ${wh.verify ? 'checked' : ''}>${T('Verify the certificate of the server')}</label>
      <div class="two"><label>${T('Send from priority')}${sevSel('whSev', wh.min_sev)}</label>
        <label>${T('Language of the messages')}${langSel('whLang', wh.lang)}</label></div>
      <details class="note"><summary>${T('How to check the signature')}</summary><p style="margin:6px 0 0">${T('With a secret every request carries X-FlowTrack-Timestamp and X-FlowTrack-Signature: sha256=HMAC-SHA256(secret, timestamp + "." + body). Compute it over the raw body and compare; refuse timestamps older than 5 minutes.')}</p></details>
      <div><button class="btn" type="button" id="whTest">${T('Send a test')}</button> <span class="note" id="whSay"></span></div></div>
      <div class="form tgform" id="ntSiem" ${ntTab === 'siem' ? '' : 'hidden'}>
      <p class="note" style="margin:0">${T('Every new event as its own syslog message (RFC 5424) to your SIEM or log server — Splunk, QRadar, ArcSight, Microsoft Sentinel, Elastic, Graylog, Wazuh, rsyslog. The hourly limit does not apply.')}</p>
      <label class="chk"><input type="checkbox" id="smOn" ${sm.on ? 'checked' : ''}>${T('Send new events to the SIEM')}</label>
      <div class="two"><label>${T('Server')}<input id="smHost" value="${esc(sm.host || '')}" placeholder="siem.example.com" autocomplete="off"></label>
        <div class="two"><label>${T('Port')}<input id="smPort" type="number" min="1" max="65535" value="${esc(sm.port || 514)}"></label>
          <label>${T('Transport')}<select id="smTr">${[['udp', 'UDP'], ['tcp', 'TCP'], ['tls', 'TLS']].map(([v, l]) => `<option value="${v}" ${sm.transport === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div></div>
      <div class="two"><label>${T('Format')}<select id="smFmt">${[['cef', T('CEF — ArcSight, QRadar, Splunk, Sentinel')], ['json', T('JSON — Elastic, Graylog, Splunk, Wazuh')]].map(([v, l]) => `<option value="${v}" ${sm.format === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label>${T('Facility')}<select id="smFac">${[...Array(8)].map((_, i) => `<option value="${16 + i}" ${+sm.facility === 16 + i ? 'selected' : ''}>local${i}</option>`).join('')}</select></label></div>
      <label class="chk"><input type="checkbox" id="smVerify" ${sm.verify !== false ? 'checked' : ''}>${T('Verify the certificate of the server')}</label>
      <div class="two"><label>${T('Send from priority')}${sevSel('smSev', sm.min_sev || 'info')}</label>
        <label>${T('Language of the messages')}${langSel('smLang', sm.lang || 'en')}</label></div>
      <div><button class="btn" type="button" id="smTest">${T('Send a test')}</button> <span class="note" id="smSay"></span></div></div>
      <div class="form tgform ntshared"><div class="two"><label>${T('FlowTrack address for the link in messages (optional)')}<input id="tgLink" value="${esc(res.notify.link)}" placeholder="${esc(location.origin)}"></label>
        <label>${T('At most messages an hour, per channel')}<input id="tgHour" type="number" min="1" max="600" value="${esc(res.notify.per_hour)}"></label></div></div>`);
    document.querySelectorAll('#ntSeg [data-v]').forEach(b => b.onclick = () => { state.ntTab = b.dataset.v;
      document.querySelectorAll('#ntSeg [data-v]').forEach(x => { x.setAttribute('aria-pressed', String(x === b)); x.setAttribute('aria-selected', String(x === b)); });
      document.getElementById('ntTelegram').hidden = b.dataset.v !== 'telegram'; document.getElementById('ntEmail').hidden = b.dataset.v !== 'email';
      document.getElementById('ntWebhook').hidden = b.dataset.v !== 'webhook'; document.getElementById('ntSiem').hidden = b.dataset.v !== 'siem'; });
    const smTls = () => { document.getElementById('smVerify').disabled = document.getElementById('smTr').value !== 'tls';
      const p = document.getElementById('smPort'); if (['514', '6514'].includes(p.value)) p.value = document.getElementById('smTr').value === 'tls' ? '6514' : '514'; };
    document.getElementById('smTr').onchange = smTls; document.getElementById('smVerify').disabled = document.getElementById('smTr').value !== 'tls';
    const ssay = (m, bad) => { const e = document.getElementById('smSay'); e.textContent = m; e.style.color = bad ? 'var(--crit)' : 'var(--ok)'; };
    document.getElementById('smTest').onclick = async () => { ssay(T('Sending…'));
      try { await apiPost('notify/test', {...collectNotify(), channel:'siem'}); ssay(document.getElementById('smTr').value === 'udp' ? T('Sent over UDP — check that it arrived in the SIEM (UDP has no answer).') : T('Sent — the server took it.')); }
      catch (e) { ssay(e.message, true); } };
    const whTls = () => { const u = document.getElementById('whUrl').value; document.getElementById('whVerify').disabled = /^http:/i.test(u); };
    document.getElementById('whUrl').oninput = whTls; whTls();
    const wsay = (m, bad) => { const e = document.getElementById('whSay'); e.textContent = m; e.style.color = bad ? 'var(--crit)' : 'var(--ok)'; };
    document.getElementById('whTest').onclick = async () => { wsay(T('Sending…'));
      try { await apiPost('notify/test', {...collectNotify(), channel:'webhook'}); wsay(T('Sent — the webhook answered OK.')); } catch (e) { wsay(e.message, true); } };
    wireMailLine(document.getElementById('mlSrv'));
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
    // (1.16.2) a key per list (a publisher may ask for one: abuse.ch ThreatFox since 2025); the saved key never comes back
    const noKey = l => l.key_need && !l.key_set;
    const keyCell = l => `<td class="evkey"><input type="password" autocomplete="new-password" data-key="${esc(l.name)}" aria-label="${esc(T('Key for {list}', {list:l.title}))}"
        placeholder="${l.key_set ? T('saved — leave empty to keep') : l.key_need ? T('needed — paste the key') : T('only if the publisher asks')}">
        ${l.key_set ? `<label class="chk"><input type="checkbox" data-keyx="${esc(l.name)}">${T('Remove')}</label>` : ''}
        ${noKey(l) && l.key_link ? `<div class="note"><a href="${esc(l.key_link)}" target="_blank" rel="noopener">${T('Get a free key')}</a></div>` : ''}</td>`;
    const state = l => l.error === 'needs a key' ? `<span class="pill warn">${T('needs a key')}</span>`
      : l.error === 'the key was refused' ? `<span class="pill crit">${T('the key was refused')}</span> `
      : l.error ? `<span class="pill crit" title="${esc(l.error)}">${T('failed')}</span> ` : '';
    box('evrBox', `<div class="tw form"><table class="evr"><thead><tr><th>${T('On')}</th><th>${T('List')}</th><th>${T('What it holds')}</th><th class="num">${T('Entries')}</th><th>${T('Updated')}</th><th>${T('Key (Auth-Key)')}</th></tr></thead><tbody>
      ${res.lists.map(l => `<tr><td><label class="chk"><input type="checkbox" data-list="${esc(l.name)}" ${l.on ? 'checked' : ''} aria-label="${esc(l.title)}"></label></td>
        <td><a href="${esc(l.link)}" target="_blank" rel="noopener">${esc(l.title)}</a></td><td class="note">${cats[l.category] || ''}</td><td class="num mono">${l.count ? l.count.toLocaleString(LOC) : '—'}</td>
        <td>${state(l)}<span class="note">${l.updated ? when(l.updated) : l.on && !noKey(l) ? T('not yet — within 10 min') : ''}</span></td>${keyCell(l)}</tr>`).join('')}</tbody></table></div>
      <div class="form evown"><label>${T('Own list — addresses and networks you consider malicious (one per line)')}<textarea id="evOwn" rows="3" placeholder="203.0.113.66&#10;198.51.100.0/24">${esc((cfg.own_list || []).join('\n'))}</textarea></label></div>`);
    excTables(cfg);
    mark();
  };
  const collect = () => {
    const kinds = {};
    document.querySelectorAll('table.evk tr[data-k]').forEach(tr => { const k = {};
      tr.querySelectorAll('[data-x]').forEach(i => { k[i.dataset.x] = i.type === 'checkbox' ? i.checked : i.type === 'number' ? Number(i.value) : i.value; });
      kinds[tr.dataset.k] = k; });
    const lists = {}; document.querySelectorAll('table.evr [data-list]').forEach(i => { lists[i.dataset.list] = i.checked; });
    const list_keys = {}; document.querySelectorAll('table.evr [data-key]').forEach(i => { if (i.value.trim()) list_keys[i.dataset.key] = i.value.trim(); });
    const clear_keys = [...document.querySelectorAll('table.evr [data-keyx]:checked')].map(i => i.dataset.keyx);
    return {kinds, lists, list_keys, clear_keys, own_list:document.getElementById('evOwn').value.split(/[\s,]+/).filter(Boolean)};
  };
  const collectNotify = () => { const kinds = {}, email_kinds = {}, webhook_kinds = {}, siem_kinds = {}, v = id => document.getElementById(id);
    document.querySelectorAll('table.evk [data-s]').forEach(i => { siem_kinds[i.dataset.s] = i.checked; });
    document.querySelectorAll('table.evk [data-w]').forEach(i => { webhook_kinds[i.dataset.w] = i.checked; });
    document.querySelectorAll('table.evk [data-n]').forEach(i => { kinds[i.dataset.n] = i.checked; });
    document.querySelectorAll('table.evk [data-m]').forEach(i => { email_kinds[i.dataset.m] = i.checked; });
    return {telegram:{on:v('tgOn').checked, token:v('tgTok').value.trim(), chat:v('tgChat').value.trim(), min_sev:v('tgSev').value, lang:v('tgLang').value},
      email:{on:v('mlOn').checked, to:v('mlTo').value, min_sev:v('mlSev').value, lang:v('mlLang').value},
      webhook:{on:v('whOn').checked, url:v('whUrl').value.trim(), format:v('whFmt').value, secret:v('whSec').value, header:v('whHdr').value.trim(),
        clear_secret:!!(v('whSecX') && v('whSecX').checked), clear_header:!!(v('whHdrX') && v('whHdrX').checked), verify:v('whVerify').checked,
        min_sev:v('whSev').value, lang:v('whLang').value},
      siem:{on:v('smOn').checked, host:v('smHost').value.trim(), port:Number(v('smPort').value), transport:v('smTr').value, format:v('smFmt').value,
        facility:Number(v('smFac').value), verify:v('smVerify').checked, min_sev:v('smSev').value, lang:v('smLang').value},
      kinds, email_kinds, webhook_kinds, siem_kinds, link:v('tgLink').value.trim(), per_hour:Number(v('tgHour').value)}; };
  // the parts: one at a time, remembered for the session
  const part = k => { state.evSub = k;
    document.querySelectorAll('#evSub [data-sub]').forEach(b => { const on = b.dataset.sub === k; b.setAttribute('aria-selected', String(on)); b.setAttribute('aria-pressed', String(on)); });
    document.querySelectorAll('[data-part]').forEach(x => { x.hidden = !x.dataset.part.split(' ').includes(k); }); };
  document.querySelectorAll('#evSub [data-sub]').forEach(b => b.onclick = () => part(b.dataset.sub)); part(sub);
  // the exceptions: connections excluded in one direction, addresses ignored — tables, saved at once
  let exc = null, ign = null;
  const DIRS = [['up', T('Outgoing — we send or call out')], ['down', T('Incoming — arrives to us')], ['any', T('Both directions')]];
  const dirShort = {up:'↑ ' + T('outgoing'), down:'↓ ' + T('incoming'), any:'⇅ ' + T('both')};
  const anyCell = v => v ? `<span class="mono">${esc(v)}</span>` : `<span class="note">${T('any')}</span>`;
  const excTables = cfg => {
    const rows = (cfg.exclude || []).map(x => ({dir:x.dir, src:x.src || '', dst:x.dst || '', port:x.port ? String(x.port) : ''}));
    let cur = rows;
    const same = (a, b) => a.dir === b.dir && a.src === b.src && a.dst === b.dst && (+a.port || 0) === (+b.port || 0);
    exc = rowTable(document.getElementById('excBox'), {id:'ex', admin:true, items:rows, cols:'minmax(0,1.3fr) minmax(0,1fr) minmax(0,1fr) 100px auto',
      fields:[{k:'dir', label:T('Direction'), opts:DIRS}, {k:'src', label:T('Source (who opens it)'), ph:T('any'), mono:true, max:50},
        {k:'dst', label:T('Target'), ph:T('any'), mono:true, max:50}, {k:'port', label:T('Target port'), ph:T('any'), mono:true, num:true, max:5}],
      hint:T('A source or a target is needed: an address or a network (10.0.0.0/24); an empty field means any. Outgoing = what we send or call out (uploads, contacts, scans from inside); incoming = what arrives (scans, guessing, floods).'),
      check:(r, at) => { const bad = [];
        if (r.src && !addrOk(r.src, true, false)) bad.push('src');
        if (r.dst && !addrOk(r.dst, true, false)) bad.push('dst');
        if (r.port && !(+r.port >= 1 && +r.port <= 65535)) bad.push('port');
        if (bad.length) return {bad, err:bad.includes('port') ? T('A port is a number from 1 to 65535.') : T('Not an address or network: {v}', {v:r[bad[0]]})};
        if (!r.src && !r.dst) return {bad:['src', 'dst'], err:T('Give a source or a target address.')};
        if (cur.some((x, i) => i !== at && same(x, r))) return {err:T('This rule is already in the list.')};
        return {hint:T('Events of this connection will no longer be shown or notified.')}; },
      show:(it, k) => k === 'dir' ? `<span class="tag">${dirShort[it.dir]}</span>` : k === 'port' ? anyCell(it.port) : anyCell(it[k]),
      save:async list => { const r = await apiPost('events/exceptions', {exclude:list.map(x => ({dir:x.dir, src:x.src, dst:x.dst, port:+x.port || 0}))});
        cur = r.exclude.map(x => ({dir:x.dir, src:x.src || '', dst:x.dst || '', port:x.port ? String(x.port) : ''})); return cur; },
      delAsk:it => T('Delete the rule {rule}? Such events are shown and notified again.', {rule:exText({...it, port:+it.port || 0})}),
      empty:T('No excluded connections. The Exclude button of an event adds its rule here.')});
    let curI = (cfg.ignore || []).map(v => ({v}));
    const kind = v => /^AS\d/i.test(v) ? T('ASN') : v.includes('/') ? T('network') : T('address');
    ign = rowTable(document.getElementById('ignBox'), {id:'ig', admin:true, items:curI, cols:'minmax(0,1fr) auto',
      fields:[{k:'v', label:T('Address, network or ASN'), ph:'203.0.113.7 · 198.51.100.0/24 · AS40934', mono:true, max:50}],
      extraHead:T('Kind'), extra:it => kind(it.v),
      hint:T('Their events are neither recorded nor shown — use it for your own scanners, monitoring, partners.'),
      check:(r, at) => !addrOk(r.v, true, true) ? {bad:['v'], err:T('Not an address, network or ASN: {v}', {v:r.v})}
        : curI.some((x, i) => i !== at && x.v.toLowerCase() === r.v.toLowerCase()) ? {err:T('Already in the list.')} : {hint:kind(r.v)},
      show:it => `<span class="mono">${esc(it.v)}</span>`,
      save:async list => { const r = await apiPost('events/exceptions', {ignore:list.map(x => x.v)}); curI = r.ignore.map(v => ({v})); return curI; },
      delAsk:it => T('Stop ignoring {addr}? Its events are recorded again.', {addr:it.v}),
      empty:T('Nothing ignored. The Ignore button of an event adds its address here.')});
  };
  const mark = dirtyGuard(() => { if (!document.getElementById('evOwn')) throw new Error('not drawn'); return [collect(), collectNotify()]; }), cfgDirty = state.dirty;
  state.dirty = () => cfgDirty() || !!(exc && exc.dirty()) || !!(ign && ign.dirty());
  const err = document.getElementById('evErr'), ok = document.getElementById('evOk');
  document.getElementById('toFlowCfg').onclick = () => { state.setTab = 'flowcfg'; render(); };
  load().then(show).catch(e => { err.textContent = e.message; });
  document.getElementById('evSave').onclick = async () => { err.textContent = ''; ok.hidden = true;
    try { const cfg = collect(), nt = await apiPost('notify', collectNotify()); show({...await apiPost('events/config', cfg), notify:nt}); ok.hidden = false; } catch (e) { err.textContent = e.message; } };
  document.getElementById('evDef').onclick = async () => { if (!confirm(T('Restore the default settings of all events? Exceptions are cleared too.'))) return;
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
// (1.8.8) a ready-made text (device configuration, a command) with a Copy button over it; the button copies what the
// box shows at the moment (the configuration follows the form)
const codeBox = (text, id = '', cls = 'codebox', style = '') => `<div class="codewrap"><pre class="${cls}"${id ? ` id="${id}"` : ''}${style ? ` style="${style}"` : ''}>${esc(text)}</pre><button type="button" class="btn copybtn" data-copy>${T('Copy')}</button></div>`;
document.addEventListener('click', e => { const b = e.target.closest('[data-copy]'); if (b) copyText(b.parentElement.querySelector('pre').textContent, b); });
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
const SET_TABS = () => [['general', T('General'), ICO.grid], ['devices', T('Devices'), DEV_ICON], ['flowcfg', T('Flow configuration'), ICO.flow],
  ...(isAdmin() ? [['users', T('Users'), USER_ICON], ['events', T('Events'), ICO.pulse], ['backups', T('Backups'), BK_ICON], ['reports', T('Reports'), REP_ICON], ['api', T('API'), API_ICON]] : []), ['license', T('License'), ICO.shield]];
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
  ({general:vGeneral, devices:vDevices, flowcfg:vFlowCfg, users:vUsers, events:vEventsCfg, backups:vBackups, reports:vReports, api:vApi, license:vLicense})[state.setTab]();
}
// (1.10.0) scheduled reports: a PDF of the last day / week / month e-mailed at its hour; Download and Send now any time
const REP_ICON = 'M4 2h7l3 3v11H4zM11 2v3h3M6.5 9h5M6.5 12h5';
const REP_EVERY = () => [['day', T('Daily')], ['week', T('Weekly')], ['month', T('Monthly')]];
const REP_SECTIONS = () => ({summary:T('Totals'), chart:T('Traffic over time'), hosts:T('Busiest inside hosts'), outside:T('Outside networks (AS)'),
  services:T('Services'), countries:T('Countries'), networks:T('Your networks'), capacity:T('Link capacity'), events:T('Security events'), devices:T('Devices')});
const REP_TRAFFIC = () => [['internet', T('Internet traffic')], ['internal', T('Traffic between inside hosts')], ['all', T('All traffic')]];
// weekday names in the language of the page (0 = Monday, as on the server); 5 Jan 2026 was a Monday
const WDAYS = () => [...Array(7)].map((_, i) => new Date(Date.UTC(2026, 0, 5 + i)).toLocaleDateString(LOC, {weekday:'long', timeZone:'UTC'}));
const repWhen = r => r.every === 'day' ? T('daily at {t}', {t:r.at}) : r.every === 'week' ? T('weekly: {day}, {t}', {day:WDAYS()[r.wday || 0], t:r.at})
  : T('monthly: day {n}, {t}', {n:r.mday || 1, t:r.at});
// the next sending and the days it covers, as the server works them out (reports.period): dates only, no clock
function repNext(r){
  const d0 = new Date(), today = new Date(d0.getFullYear(), d0.getMonth(), d0.getDate()), [h, m] = (r.at || '07:00').split(':').map(Number);
  const day = (y, mo, dd) => new Date(y, mo, dd), wd = x => (x.getDay() + 6) % 7;
  let send = new Date(today), start;
  const past = x => x < today || (+x === +today && (d0.getHours() * 60 + d0.getMinutes()) >= h * 60 + m);
  if (r.every === 'day') { if (past(send)) send = day(send.getFullYear(), send.getMonth(), send.getDate() + 1); start = day(send.getFullYear(), send.getMonth(), send.getDate() - 1); }
  else if (r.every === 'week') { send = day(today.getFullYear(), today.getMonth(), today.getDate() + ((r.wday || 0) - wd(today) + 7) % 7);
    if (past(send)) send = day(send.getFullYear(), send.getMonth(), send.getDate() + 7); start = day(send.getFullYear(), send.getMonth(), send.getDate() - 7); }
  else { const n = r.mday || 1; send = day(today.getFullYear(), today.getMonth(), n); if (past(send)) send = day(send.getFullYear(), send.getMonth() + 1, n);
    start = day(send.getFullYear(), send.getMonth() - 1, n); }
  const end = day(send.getFullYear(), send.getMonth(), send.getDate() - 1), f = x => x.toLocaleDateString(LOC, {day:'numeric', month:'short'});
  return T('Next: {when}, covering {from} — {to}', {when:`${send.toLocaleDateString(LOC, {weekday:'short', day:'numeric', month:'short'})} ${r.at}`,
    from:f(start), to:f(end)});
}
// browsers still name some zones by their old names (Chromium: Europe/Kiev); the server's list has the new ones
const TZ_RENAMED = {'Europe/Kiev':'Europe/Kyiv', 'Europe/Uzhgorod':'Europe/Kyiv', 'Europe/Zaporozhye':'Europe/Kyiv', 'Asia/Calcutta':'Asia/Kolkata',
  'Asia/Saigon':'Asia/Ho_Chi_Minh', 'Asia/Katmandu':'Asia/Kathmandu', 'Asia/Rangoon':'Asia/Yangon', 'Atlantic/Faeroe':'Atlantic/Faroe',
  'America/Buenos_Aires':'America/Argentina/Buenos_Aires', 'Pacific/Truk':'Pacific/Chuuk', 'Etc/UTC':'UTC'};
// filters back as the words of the box: a device by its name, a named network with _ for its spaces (1.11.1)
const repFilters = f => (f || []).map(x => (x.neg ? '-' : '') + x.k + ':' + (x.k === 'device' ? ((META.devices || []).find(d => d.ip === x.v) || {}).name || x.v
  : x.k === 'net' ? netTyped(x.v) : x.v)).join(' ');
async function repDownload(q, btn, path = 'reports/pdf'){
  const old = btn.textContent; btn.disabled = true; btn.textContent = T('Making the PDF…');
  try {
    const r = await fetch(`api/${path}?` + new URLSearchParams(q));
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || r.status); }
    const name = (/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '') || [])[1] || 'flowtrack-report.pdf';
    const a = document.createElement('a'); a.href = URL.createObjectURL(await r.blob()); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    return '';
  } catch (e) { return e.message; } finally { btn.disabled = false; btn.textContent = old; }
}
// (1.10.0) the mail server (SMTP) of Settings → General: the reports and the e-mail notifications send through it.
// A summary when it is set up, the form when it is not (or on Change); a test letter goes to any address.
const MAIL_ICON = 'M2 4h14v10H2zM2 4l7 6 7-6';
const mailReady = m => !!(m && m.host && m.sender);
// one line for the pages that send mail: where it goes through, or that it is not set up — with the way to General
const mailLine = m => mailReady(m)
  ? `<p class="note" style="margin:0 0 10px">${T('Mail goes through {server}', {server:`<span class="mono">${esc(m.host)}:${esc(m.port)}</span>`})} · <button class="lnk" data-go="mail">${T('Change in General')} →</button></p>`
  : `<p class="note" style="margin:0 0 10px;padding:8px 12px;border-radius:10px;background:rgba(255,195,77,.10);border:1px solid rgba(255,195,77,.35);color:var(--warn)">${T('The mail server is not set up: nothing is sent by e-mail.')} <button class="lnk" data-go="mail">${T('Set up the mail server')} →</button></p>`;
const wireMailLine = root => root.querySelectorAll('[data-go="mail"]').forEach(b => b.onclick = () => { state.setTab = 'general'; state.goMail = true; render(); });
function mailPanel(el, d){
  let open = false;
  const $ = id => document.getElementById(id);
  const draw = () => {
    if (!el.isConnected) return;
    el.classList.remove('loading');
    const m = d.mail, sec = {starttls:'STARTTLS', ssl:'SSL/TLS', none:T('none')};
    if (m.ready && !open) {
      el.innerHTML = `<div class="about"><div><span>${T('Server')}</span><b class="mono">${esc(m.host)}:${esc(m.port)}</b><span class="nat">${m.security === 'none' ? T('no encryption') : esc(sec[m.security])}${m.user ? ' · ' + esc(m.user) : ''}</span></div>
        <div><span>${T('From')}</span><b class="mono">${esc(m.sender)}</b><button class="lnk" id="rmChange">${T('Change')}</button></div></div>
        <div style="margin-top:10px"><button class="btn danger" type="button" id="rmDel">${T('Delete the mail server')}</button></div>`;
      $('rmChange').onclick = () => { open = true; draw(); };
      // (1.12.1) deleting it: asked for in a window of its own that says what stops working
      $('rmDel').onclick = () => {
        const md = openModal(T('Delete the mail server?'), esc(`${m.host}:${m.port}`), `<div class="form" style="padding:4px 2px">
          <p class="note" style="margin:0">${T('FlowTrack forgets the server, the login and the password. Until you set up another one:')}</p>
          <ul class="note" style="margin:0;padding-left:18px"><li>${T('scheduled reports are not sent (they stay, marked «not sent»);')}</li>
            <li>${T('e-mail notifications are switched off (their recipients are kept);')}</li><li>${T('Telegram, webhooks and the SIEM go on as before.')}</li></ul>
          <p class="err" id="rmDelErr" hidden></p>
          <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn danger" type="button" id="rmDelYes">${T('Delete')}</button><button class="btn" type="button" id="rmDelNo">${T('Cancel')}</button></div></div>`);
        document.getElementById('rmDelNo').onclick = md.close;
        document.getElementById('rmDelYes').onclick = async () => {
          try { d = await apiPost('mail/delete', {}); md.close(); open = false; draw(); }
          catch (x) { formErr('rmDelErr', x.message); } };
      };
      return;
    }
    el.innerHTML = `${m.ready ? '' : `<p class="note" style="color:var(--warn);margin:0 0 10px"><b>${T('Not set up yet: nothing is sent by e-mail.')}</b> ${T('Enter the SMTP server you send mail through — your own, Gmail or Microsoft 365 (with an app password), or a relay of your provider. FlowTrack only sends: no POP3 or IMAP is needed.')}</p>`}
      <form class="form" id="rmForm" novalidate>
      <div class="two"><label>${T('Mail server (SMTP)')}<input id="rmHost" value="${esc(m.host)}" placeholder="smtp.example.com" autocomplete="off"></label>
        <div class="two"><label>${T('Port')}<input id="rmPort" type="number" min="1" max="65535" value="${esc(m.port)}"></label>
          <label>${T('Encryption')}<select id="rmSec">${Object.entries(sec).map(([k, l]) => `<option value="${k}" ${m.security === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label></div></div>
      <label class="chk"><input type="checkbox" id="rmVerify" ${m.verify ? 'checked' : ''}>${T('Verify the certificate of the server')}</label>
      <div class="two"><label>${T('Login (empty: without a login)')}<input id="rmUser" value="${esc(m.user)}" autocomplete="off"></label>
        <label>${T('Password')}<input id="rmPass" type="password" autocomplete="new-password" placeholder="${m.password_set ? T('saved — leave empty to keep') : ''}"></label></div>
      <div class="two"><label>${T('From')}<input id="rmFrom" value="${esc(m.sender)}" placeholder="flowtrack@example.com"></label>
        <label>${T('Send a test letter to')}<input id="rmTo" value="${esc((d.to || [])[0] || '')}" placeholder="admin@example.com"></label></div>
      <p class="err" id="rmErr" hidden></p><p class="note" id="rmOk" hidden></p>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${T('Save')}</button><button class="btn" type="button" id="rmTest">${T('Send a test')}</button>${m.ready ? `<button class="btn" type="button" id="rmNo">${T('Cancel')}</button>` : ''}</div></form>`;
    const tls = () => { $('rmVerify').disabled = $('rmSec').value === 'none'; }; $('rmSec').onchange = tls; tls();
    const body = () => ({host:$('rmHost').value.trim(), port:Number($('rmPort').value), security:$('rmSec').value, verify:$('rmVerify').checked,
      user:$('rmUser').value.trim(), password:$('rmPass').value, sender:$('rmFrom').value.trim()});
    const say = (ok, msg) => { formErr('rmErr', ok ? '' : msg); const n = $('rmOk'); n.textContent = ok ? msg : ''; n.hidden = !ok; };
    if ($('rmNo')) $('rmNo').onclick = () => { open = false; draw(); };
    $('rmTest').onclick = async e => { const b = e.target, old = b.textContent; b.disabled = true; b.textContent = T('Sending…'); say(true, '');
      try { await apiPost('mail/test', Object.assign(body(), {to:$('rmTo').value.trim(), lang:LANG})); say(true, T('Sent — check the mailbox (and the spam folder).')); }
      catch (x) { say(false, x.message); } finally { b.disabled = false; b.textContent = old; } };
    $('rmForm').onsubmit = async e => { e.preventDefault(); say(true, '');
      try { d = await apiPost('mail', body()); open = false; draw(); } catch (x) { say(false, x.message); } };
  };
  draw();
}
// (1.10.0) a report of any period, made now — an attack or an outage the engineer has zoomed into: the period and the
// filters of the page come along; Download PDF for anyone, Send by e-mail for administrators
const dtLocal = t => { const d = new Date(t * 1000); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
async function openPeriodReport(){
  const now = Math.floor(Date.now() / 1000), t1 = isCustom() ? Math.min(state.to, now) : now, t0 = isCustom() ? state.from : now - rangeSecs();
  let mail = null; if (isAdmin()) { try { mail = (await (await fetch('api/mail')).json()).mail; } catch (e) {} }
  let tz = 'UTC'; try { const b = Intl.DateTimeFormat().resolvedOptions().timeZone; tz = TZ_RENAMED[b] || b; } catch (e) {}
  const secs = REP_SECTIONS();
  const md = openModal(T('Report for a period'), T('a PDF of any period, made now — e.g. an attack or an outage'), `<form class="form" id="opForm" novalidate style="padding:4px 2px">
    <label>${T('Name')}<input id="opName" maxlength="80" value="${esc(T('Report for a period'))}"></label>
    <div class="two"><label>${T('From')}<input id="opFrom" type="datetime-local" value="${dtLocal(t0)}"></label><label>${T('To')}<input id="opTo" type="datetime-local" value="${dtLocal(t1)}"></label></div>
    <p class="note" id="opLen" style="margin:0"></p>
    <div class="cols" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">
      <label>${T('Traffic')}<select id="opT">${REP_TRAFFIC().map(([k, l]) => `<option value="${k}" ${state.traffic === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <label>${T('Language')}<select id="opLang">${langs().map(([k, l]) => `<option value="${k}" ${LANG === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label></div>
    <div><label for="opF">${T('Filters')} <span class="nat">${T('— as in the search box; empty: all traffic')}</span></label><input id="opF" class="mono" value="${esc(repFilters(state.filters))}" placeholder="net:Office ip:10.0.0.5 -service:Telegram"></div>
    <fieldset style="border:0;padding:0;margin:0"><legend class="nat" style="margin-bottom:6px">${T('What the report holds')}</legend>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:4px 12px">${Object.entries(secs).map(([k, l]) =>
        `<label class="chk"><input type="checkbox" data-sec="${k}" checked>${l}</label>`).join('')}</div></fieldset>
    ${isAdmin() ? `<label>${T('Send by e-mail to (optional)')}<textarea id="opTo2" rows="2" ${mailReady(mail) ? '' : 'disabled'} placeholder="${mailReady(mail) ? 'noc@example.com, boss@example.com' : esc(T('The mail server is not set up: nothing is sent by e-mail.'))}"></textarea></label>` : ''}
    <p class="err" id="opErr" hidden></p><p class="note" id="opOk" hidden></p>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${T('Download PDF')}</button>${isAdmin() ? `<button class="btn" type="button" id="opSend" ${mailReady(mail) ? '' : 'disabled'}>${T('Send')}</button>` : ''}<button class="btn" type="button" id="opNo">${T('Cancel')}</button></div></form>`, true);
  const $ = id => document.getElementById(id);
  const span = () => { const a = new Date($('opFrom').value).getTime() / 1000, b = new Date($('opTo').value).getTime() / 1000; return [Math.round(a), Math.round(b)]; };
  const len = () => { const [a, b] = span(), m = Math.round((b - a) / 60);
    $('opLen').textContent = !(b > a) ? T('The end must be after the start.') : m < 120 ? T('{n} min', {n:m}) : m < 2880 ? T('{n} h', {n:Math.round(m / 6) / 10}) : T('{n} d', {n:Math.round(m / 144) / 10}); };
  $('opFrom').oninput = len; $('opTo').oninput = len; len();
  filterGuide($('opF'));
  const body = () => { const f = [];
    for (const t of $('opF').value.trim().split(/\s+/).filter(Boolean)) { const p = qParse(t); if (p.err) throw new Error(p.err); if (!p.f) throw new Error(T('Not a filter: {v}', {v:t})); f.push(p.f); }
    const [a, b] = span(); if (!(b > a)) throw new Error(T('The end must be after the start.'));
    return {from:a, to:b, form:{name:$('opName').value.trim(), t:$('opT').value, f, lang:$('opLang').value, tz, to:$('opTo2') ? $('opTo2').value : '',
      sections:[...document.querySelectorAll('#opForm [data-sec]:checked')].map(c => c.dataset.sec)}}; };
  const say = (ok, msg) => { formErr('opErr', ok ? '' : msg); const n = $('opOk'); n.textContent = ok ? msg : ''; n.hidden = !ok; };
  $('opNo').onclick = md.close;
  $('opForm').onsubmit = async e => { e.preventDefault(); say(true, ''); let b; try { b = body(); } catch (x) { return say(false, x.message); }
    const err = await repDownload({from:b.from, to:b.to, form:JSON.stringify(b.form)}, e.submitter || $('opForm').querySelector('button[type=submit]'), 'report/pdf');
    if (err) say(false, err); };
  if ($('opSend')) $('opSend').onclick = async e => { say(true, ''); let b; try { b = body(); } catch (x) { return say(false, x.message); }
    const btn = e.target, old = btn.textContent; btn.disabled = true; btn.textContent = T('Sending…');
    try { const x = await apiPost('reports/send_once', b); say(true, '✓ ' + Tn(x.sent, 'sent to {n} recipient', 'sent to {n} recipients', {n:x.sent}) + ' · ' + x.period); }
    catch (x) { say(false, x.message); } finally { btn.disabled = false; btn.textContent = old; } };
}
// (1.11.0) API tokens for scripts, monitoring and integrations: created here, shown once, revoked here
const API_ICON = 'M6 5L2 9l4 4M12 5l4 4-4 4M10 3L8 15';
const TOKEN_SCOPES = () => ({read:[T('Read only'), T('what a viewer sees: every page’s data, events, devices')],
  write:[T('Read and change'), T('also what an administrator changes — devices, names, networks, events, reports — except users, tokens, the license and deleting backups')]});
function vApi(){
  const v = document.getElementById('setBody'), seq = renderSeq;
  const ex = `curl -k -H "Authorization: Bearer ftapi_…" \\\n  "${location.origin}/api/summary?range=24h&f=[]"`;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph(API_ICON, T('API tokens'), T('for scripts, monitoring and integrations · sent as Authorization: Bearer …'),
    `<button class="btn primary" id="tkNew">${T('New token')}</button>`)}<div id="tkList" class="loading"></div><p class="err" id="tkErr" hidden></p></section>
    <section class="glass panel s12">${ph('list', T('How to use'), T('the same JSON the pages use · every filter of the search box works'))}
      ${codeBox(ex, 'tkEx')}
      <div class="tw" style="margin-top:12px"><table class="compact"><tbody>${[['/api/summary?range=24h&f=[]', T('totals, against the period before')], ['/api/top?dim=int_ip&limit=10&range=24h&f=[]', T('busiest inside hosts (dim: ext_ip, service, country, asn, net…)')],
        ['/api/series?range=24h&f=[]', T('traffic over time')], ['/api/alerts?range=24h&f=[]', T('security events')], ['/api/devices', T('devices and their export health')]].map(([u, d]) =>
        `<tr><td class="mono" style="white-space:nowrap;font-size:12.5px">GET ${esc(u)}</td><td class="nat">${esc(d)}</td></tr>`).join('')}</tbody></table></div>
      <p class="note" style="margin:10px 0 0">${T('Periods: range=1h|6h|24h|7d|30d, or from/to in unix seconds; filters: f=[{"k":"net","v":"Office"}].')} <a href="https://github.com/henzelis/flowtrack/blob/main/docs/api.md" target="_blank" rel="noopener">${T('All endpoints')} ↗</a></p></section></div>`;
  let d = null;
  const $ = id => document.getElementById(id);
  const when = t => new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit'});
  const draw = () => {
    const el = $('tkList'); if (!el || seq !== renderSeq) return;
    el.classList.remove('loading');
    const now = Date.now() / 1000, sc = TOKEN_SCOPES();
    el.innerHTML = d.tokens.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('Name')}</th><th>${T('Access')}</th><th>${T('Token')}</th><th>${T('Created')}</th><th>${T('Last used')}</th><th>${T('Valid until')}</th><th></th></tr></thead><tbody>
      ${d.tokens.map(t => { const ended = t.expires && t.expires < now;
        return `<tr data-id="${esc(t.id)}"><td><b>${esc(t.name)}</b></td><td><span class="pill ${t.scope === 'write' ? 'warn' : ''}" title="${esc(sc[t.scope][1])}">${esc(sc[t.scope][0])}</span></td>
        <td class="mono">${esc(t.hint)}</td><td>${when(t.created)}<div class="nat">${esc(t.by || '')}</div></td>
        <td>${t.last_used ? `${when(t.last_used)}<div class="nat mono">${esc(t.last_ip)}</div>` : `<span class="nat">${T('never')}</span>`}</td>
        <td>${!t.expires ? `<span class="nat">${T('no end date')}</span>` : ended ? `<span class="pill crit">${T('ended')}</span> <span class="nat">${when(t.expires)}</span>` : when(t.expires)}</td>
        <td style="text-align:right"><button class="btn" data-a="del">${T('Revoke')}</button></td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty">${T('No tokens yet. A token lets a script or a monitoring system (Zabbix, Grafana, your own) read FlowTrack without a password: press New token.')}</div>`;
    el.querySelectorAll('[data-a="del"]').forEach(b => b.onclick = async () => { const t = d.tokens.find(x => x.id === b.closest('tr').dataset.id);
      if (!confirm(T('Revoke the token {name}? Scripts that use it stop working at once.', {name:t.name}))) return;
      try { d = await apiPost('tokens/delete', {id:t.id}); draw(); } catch (e) { formErr('tkErr', e.message); } });
  };
  const openNew = () => {
    const sc = TOKEN_SCOPES();
    const md = openModal(T('New token'), T('shown once — keep it like a password'), `<form class="form" id="tkForm" novalidate style="padding:4px 2px">
      <label>${T('Name')}<input id="tkName" maxlength="48" placeholder="${T('e.g. Zabbix, Grafana, backup script')}"></label>
      <fieldset style="border:0;padding:0;margin:0"><legend class="nat" style="margin-bottom:6px">${T('Access')}</legend>${Object.entries(sc).map(([k, [l, dsc]]) =>
        `<label class="chk" style="align-items:flex-start;margin-bottom:6px"><input type="radio" name="tkScope" value="${k}" ${k === 'read' ? 'checked' : ''}><span><b>${l}</b><br><span class="nat">${dsc}</span></span></label>`).join('')}</fieldset>
      <label>${T('Valid')}<select id="tkDays">${[[0, T('no end date')], [30, T('30 days')], [90, T('90 days')], [365, T('1 year')]].map(([k, l]) => `<option value="${k}" ${k === 365 ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <p class="err" id="tkFErr" hidden></p>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${T('Create the token')}</button><button class="btn" type="button" id="tkNo">${T('Cancel')}</button></div></form>`);
    $('tkNo').onclick = md.close; $('tkName').focus();
    $('tkForm').onsubmit = async e => { e.preventDefault(); formErr('tkFErr', '');
      try { const r = await apiPost('tokens', {name:$('tkName').value.trim(), scope:document.querySelector('[name="tkScope"]:checked').value, days:Number($('tkDays').value)});
        d = {tokens:r.tokens}; draw();
        md.root.querySelector('.modal').lastElementChild.outerHTML = `<div class="form" style="padding:4px 2px">
          <p class="note" style="margin:0;color:var(--warn)"><b>${T('Copy the token now: FlowTrack keeps only its fingerprint and cannot show it again.')}</b></p>
          ${codeBox(r.token, 'tkTok', 'mono', 'margin:0;padding:10px 104px 10px 12px;border-radius:10px;background:rgba(0,0,0,.35);white-space:pre-wrap;word-break:break-all')}
          ${codeBox(`curl -k -H "Authorization: Bearer ${r.token}" \\\n  "${location.origin}/api/summary?range=24h&f=[]"`, '', 'mono', 'margin:0;padding:10px 104px 10px 12px;border-radius:10px;background:rgba(0,0,0,.35);white-space:pre-wrap;word-break:break-all;font-size:12px')}
          <div><button class="btn primary" type="button" id="tkDone">${T('Done')}</button></div></div>`;
        $('tkDone').onclick = md.close; }
      catch (x) { formErr('tkFErr', x.message); } };
  };
  $('tkNew').onclick = openNew;
  (async () => { try { const r = await fetch('api/tokens'); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); d = j; draw(); }
    catch (e) { const el = $('tkList'); if (el) { el.classList.remove('loading'); el.innerHTML = `<p class="err">${esc(e.message)}</p>`; } } })();
}
function vReports(){
  const v = document.getElementById('setBody'), seq = renderSeq;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph(REP_ICON, T('Reports'), T('a PDF of the last day, week or month, e-mailed at its hour · the same numbers as the pages'),
    `<button class="btn" id="repOnce">${T('Report for a period')}</button> <button class="btn primary" id="repNew">${T('New report')}</button>`)}<div id="repMail"></div><div id="repList" class="loading"></div><p class="err" id="repErr" hidden></p></section></div>`;
  let d = null;
  const $ = id => document.getElementById(id);
  const when = t => new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'});
  const draw = () => {
    const el = $('repList'); if (!el || seq !== renderSeq) return;
    el.classList.remove('loading');
    $('repMail').innerHTML = mailLine(d.mail); wireMailLine($('repMail'));
    el.innerHTML = d.reports.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('Report')}</th><th>${T('When')}</th><th>${T('Recipients')}</th><th>${T('Last sent')}</th><th>${T('Next')}</th><th></th></tr></thead><tbody>
      ${d.reports.map(r => { const s = d.status[r.id] || {}, to = r.to.length ? r.to : d.mail_to;
        const last = s.error && s.error_at > (s.sent || 0) ? `<span class="pill crit" title="${esc(s.error)}">${T('failed')}</span> <span class="nat" title="${esc(s.error)}">${esc(s.error.slice(0, 70))}</span>`
          : s.sent ? `${when(s.sent)}<div class="nat">${esc(s.sent_period)} · ${Tn(s.to, '{n} recipient', '{n} recipients', {n:s.to})}</div>` : `<span class="nat">${T('not yet')}</span>`;
        const next = !r.on ? '—' : s.blocked ? `<span class="pill warn">${T('not sent')}</span><div class="nat" style="font-family:var(--f-body)">${esc(s.blocked)}</div>` : s.next ? when(s.next) : '—';
        return `<tr data-id="${esc(r.id)}"><td><b>${esc(r.name)}</b>${r.on ? '' : ` <span class="pill">${T('off')}</span>`}<div class="nat">${esc(REP_TRAFFIC().find(x => x[0] === r.t)[1])}${r.f.length ? ' · <span class="mono">' + esc(repFilters(r.f)) + '</span>' : ''}</div></td>
          <td>${esc(repWhen(r))}<div class="nat">${esc(r.tz)} · ${esc((langs().find(x => x[0] === r.lang) || [, r.lang])[1])}</div></td>
          <td>${to.length ? esc(to.slice(0, 2).join(', ')) + (to.length > 2 ? ` +${to.length - 2}` : '') : `<span class="nat">${T('none')}</span>`}${r.to.length ? '' : `<div class="nat">${T('those of the notifications')}</div>`}</td>
          <td>${last}</td><td class="mono">${next}</td>
          <td style="white-space:nowrap;text-align:right"><button class="btn" data-a="pdf" title="${T('Download PDF')} · ${T('The last period, made now')}">PDF ↓</button> <button class="btn" data-a="send" ${s.blocked ? `disabled title="${esc(s.blocked)}"` : ''}>${T('Send now')}</button> <button class="btn" data-a="edit">${T('Edit')}</button> <button class="btn" data-a="del" title="${T('Delete')}" aria-label="${T('Delete')}">✕</button></td></tr>`; }).join('')}
      </tbody></table></div>` : `<div class="empty">${T('No reports yet. A weekly report for the management or a daily one for the duty engineer: press New report.')}</div>`;
    el.querySelectorAll('button[data-a]').forEach(b => b.onclick = async () => {
      const r = d.reports.find(x => x.id === b.closest('tr').dataset.id); formErr('repErr', '');
      if (b.dataset.a === 'edit') return openReport(r);
      if (b.dataset.a === 'pdf') return formErr('repErr', await repDownload({id:r.id}, b));
      if (b.dataset.a === 'del') { if (!confirm(T('Delete the report {name}?', {name:r.name}))) return;
        try { d = await apiPost('reports/delete', {id:r.id}); draw(); } catch (e) { formErr('repErr', e.message); } return; }
      const old = b.textContent; b.disabled = true; b.textContent = T('Sending…');
      try { const x = await apiPost('reports/send', {id:r.id}); b.textContent = '✓ ' + Tn(x.sent, 'sent to {n} recipient', 'sent to {n} recipients', {n:x.sent});
        setTimeout(async () => { try { d = await (await fetch('api/reports')).json(); draw(); } catch (e) { b.textContent = old; b.disabled = false; } }, 2500); }
      catch (e) { b.textContent = old; b.disabled = false; formErr('repErr', e.message); }
    });
  };
  // ---- the form of a new or a changed report (a modal): Download PDF tries it before it is saved
  const openReport = r => {
    const x = Object.assign({}, d.blank, r || {name:'', to:[]}), secs = REP_SECTIONS();
    let tz = x.tz; if (!r) { try { const b = Intl.DateTimeFormat().resolvedOptions().timeZone, n = TZ_RENAMED[b] || b; if (d.timezones.includes(n)) tz = n; } catch (e) {} }
    if (!r) x.lang = LANG;
    const md = openModal(r ? T('Edit the report') : T('New report'), r ? esc(r.name) : T('sent by e-mail as a PDF'), `<form class="form" id="rpForm" novalidate style="padding:4px 2px">
      ${d.mail_ready ? '' : `<p class="note" id="rpNoMail" style="margin:0;padding:8px 12px;border-radius:10px;background:rgba(255,195,77,.10);border:1px solid rgba(255,195,77,.35);color:var(--warn)">${T('The mail server is not set up: the report can be saved and downloaded, but it is not sent until you set up the mail server in Settings → General.')}</p>`}
      <label>${T('Name')}<input id="rpName" maxlength="80" value="${esc(x.name)}" placeholder="${T('e.g. Weekly traffic report')}"></label>
      <div class="cols" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px">
        <label>${T('How often')}<select id="rpEvery">${REP_EVERY().map(([k, l]) => `<option value="${k}" ${x.every === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label id="rpWdayL">${T('Day of the week')}<select id="rpWday">${WDAYS().map((l, i) => `<option value="${i}" ${+x.wday === i ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
        <label id="rpMdayL">${T('Day of the month')}<select id="rpMday">${[...Array(28)].map((_, i) => `<option value="${i + 1}" ${+x.mday === i + 1 ? 'selected' : ''}>${i + 1}</option>`).join('')}</select></label>
        <label>${T('At')}<input id="rpAt" type="time" value="${esc(x.at)}"></label>
        <label>${T('Language')}<select id="rpLang">${langs().map(([k, l]) => `<option value="${k}" ${x.lang === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label></div>
      <p class="note" id="rpWhen" style="margin:0"></p>
      <label>${T('Time zone')}<select id="rpTz">${d.timezones.map(z => `<option ${z === tz ? 'selected' : ''}>${esc(z)}</option>`).join('')}</select></label>
      <label>${T('Recipients')}<textarea id="rpTo" rows="2" placeholder="${esc(d.mail_to.length ? T('empty: those of the notifications ({to})', {to:d.mail_to.join(', ')}) : 'noc@example.com, boss@example.com')}">${esc(x.to.join(', '))}</textarea></label>
      <label>${T('Traffic')}<select id="rpT">${REP_TRAFFIC().map(([k, l]) => `<option value="${k}" ${x.t === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <div><label for="rpF">${T('Filters')} <span class="nat">${T('— as in the search box; empty: all traffic')}</span></label><input id="rpF" class="mono" value="${esc(repFilters(x.f))}" placeholder="net:Office device:fw-main -service:Telegram"></div>
      <fieldset style="border:0;padding:0;margin:0"><legend class="nat" style="margin-bottom:6px">${T('What the report holds')}</legend>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:4px 12px">${Object.entries(secs).map(([k, l]) =>
          `<label class="chk"><input type="checkbox" data-sec="${k}" ${x.sections.includes(k) ? 'checked' : ''}>${l}</label>`).join('')}</div></fieldset>
      <label class="chk"><input type="checkbox" id="rpOn" ${x.on ? 'checked' : ''}>${T('Send on schedule')}</label>
      <p class="err" id="rpErr" hidden></p>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${T('Save')}</button><button class="btn" type="button" id="rpPdf">${T('Download PDF')}</button><button class="btn" type="button" id="rpNo">${T('Cancel')}</button></div></form>`, true);
    const sched = () => ({every:$('rpEvery').value, wday:Number($('rpWday').value), mday:Number($('rpMday').value), at:$('rpAt').value || '07:00'});
    const hint = () => { const s = sched(); $('rpWdayL').hidden = s.every !== 'week'; $('rpMdayL').hidden = s.every !== 'month';
      $('rpWhen').textContent = repWhen(s) + ' · ' + repNext(s); };
    ['rpEvery', 'rpWday', 'rpMday'].forEach(id => $(id).onchange = hint); $('rpAt').oninput = hint; hint();
    filterGuide($('rpF'));
    const form = () => { const f = [];
      for (const t of $('rpF').value.trim().split(/\s+/).filter(Boolean)) { const p = qParse(t); if (p.err) throw new Error(p.err); if (!p.f) throw new Error(T('Not a filter: {v}', {v:t})); f.push(p.f); }
      return Object.assign(sched(), {id:r ? r.id : '', name:$('rpName').value.trim(), lang:$('rpLang').value, tz:$('rpTz').value, to:$('rpTo').value, t:$('rpT').value, f,
        sections:[...document.querySelectorAll('#rpForm [data-sec]:checked')].map(c => c.dataset.sec), on:$('rpOn').checked}); };
    $('rpNo').onclick = md.close;
    $('rpPdf').onclick = async e => { let f; try { f = form(); } catch (x) { return formErr('rpErr', x.message); }
      formErr('rpErr', await repDownload({form:JSON.stringify(Object.assign(f, {name:f.name || T('Report')}))}, e.target)); };
    $('rpForm').onsubmit = async e => { e.preventDefault(); formErr('rpErr', '');
      try { d = await apiPost('reports/save', form()); md.close(); draw(); } catch (x) { formErr('rpErr', x.message); } };
    $('rpName').focus();
  };
  $('repNew').onclick = () => d && openReport(null);
  $('repOnce').onclick = openPeriodReport;
  (async () => { try { const r = await fetch('api/reports'); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); d = j; draw(); }
    catch (e) { const el = $('repList'); if (el) { el.classList.remove('loading'); el.innerHTML = `<p class="err">${esc(e.message)}</p>`; } } })();
}
function vGeneral(){
  const ed = META.edition || {};
  // (1.10.0) one even row of four cards (as on Backups), the mail server under it: no panel shorter than its neighbour
  const card = (ic, k, v, sub) => `<section class="glass panel kcard gcard s3"><span class="ico">${icon(ICO[ic] || ic, 22)}</span><span class="k">${k}</span><span class="v">${v}</span><span class="nat">${sub}</span></section>`;
  document.getElementById('setBody').innerHTML = `<div class="grid">
    ${card('list', T('Version'), `FlowTrack ${esc(META.version || '—')}`, `<a href="https://github.com/henzelis/flowtrack" target="_blank" rel="noopener">${T('Source code')} ↗</a>`)}
    ${card('shield', T('Edition'), ed.status === 'active' ? 'Pro' : 'Community', `<button class="lnk" id="toLic">${T('License')} →</button>`)}
    ${card('globe', T('Language'), `<select id="langSel" aria-label="${T('Language')}">${langs().map(([v, l]) => `<option value="${v}" lang="${v}" ${LANG === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`,
      T('only in this browser'))}
    ${card(USER_ICON, T('Account'), esc(ME.display || ME.name), `${ME.role === 'admin' ? T('Administrator') : T('Viewer')}${ME.source === 'ldap' ? ` · ${T('directory account')}` : ` · <button class="lnk" id="myPass">${T('Change my password')}</button>`}`)}
    ${isAdmin() ? `<section class="glass panel s12" id="mailBox">${ph(MAIL_ICON, T('Mail server'), T('e-mail (SMTP) for the reports and the e-mail notifications'))}<div id="mailBody" class="loading"></div></section>` : ''}</div>`;
  if (isAdmin()) (async () => { const el = document.getElementById('mailBody');
    try { const r = await fetch('api/mail'); const j = await r.json(); if (!r.ok) throw new Error(j.error || r.status); mailPanel(el, j);
      if (state.goMail) { state.goMail = false; document.getElementById('mailBox').scrollIntoView({block:'start', behavior:'smooth'}); const h = document.getElementById('rmHost'); if (h) h.focus({preventScroll:true}); } }
    catch (e) { el.classList.remove('loading'); el.innerHTML = `<p class="err">${esc(e.message)}</p>`; } })();
  document.getElementById('langSel').onchange = e => { if (e.target.value !== LANG) setLang(e.target.value); };
  document.getElementById('toLic').onclick = () => { state.setTab = 'license'; render(); };
  const mp = document.getElementById('myPass'); if (mp) mp.onclick = openPassword;
}
// (1.8.4) a table of settings rows: each added with a checked form, changed or deleted in its row, saved at once.
// o: {id, admin, fields:[{k, label, opts:[[v, label]], ph, max, mono, num, def}], cols (grid of the form), items,
//     check(row, index of the row being changed or -1) -> {err, bad:[keys], hint, warn}, show(item, key) -> html,
//     extraHead / extra(item) for more columns, save(list) -> Promise of the new items, delAsk(item) -> text, empty, hint}
function rowTable(el, o){
  let items = o.items.slice(), edit = null;
  const F = o.fields, ID = o.id;
  const ctl = (f, v, id) => f.opts
    ? `<select id="${id}" aria-label="${esc(f.label)}">${f.opts.map(([k, l]) => `<option value="${esc(k)}" ${String(v) === String(k) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`
    : `<input id="${id}" class="${f.mono ? 'mono' : ''}" ${f.num ? 'inputmode="numeric"' : ''} maxlength="${f.max || 64}" placeholder="${esc(f.ph || '')}" value="${esc(v == null ? '' : v)}" autocomplete="off" aria-label="${esc(f.label)}">`;
  const read = pre => Object.fromEntries(F.map((f, i) => { const x = document.getElementById(pre + i); if (!x) return [f.k, ''];
    if (f.num && x.value !== x.value.replace(/\D/g, '')) x.value = x.value.replace(/\D/g, ''); return [f.k, x.value.trim()]; }));
  const cell = (it, f) => o.show ? o.show(it, f.k) : esc(it[f.k]);
  const fail = e => { const x = el.querySelector('.rterr'); if (x) { x.textContent = e ? e.message || e : ''; x.hidden = !e; } };
  const save = async list => { fail(''); try { items = await o.save(list); edit = null; draw(); return true; } catch (e) { fail(e); return false; } };
  const draw = () => {
    el.classList.remove('loading');
    el.innerHTML = `${o.admin ? `<form class="form pnadd rtadd" id="${ID}Add" novalidate style="grid-template-columns:${o.cols}">
        ${F.map((f, i) => `<label>${esc(f.label)}${ctl(f, f.def == null ? '' : f.def, ID + 'A' + i)}</label>`).join('')}
        <button class="btn primary" type="submit" id="${ID}Go">${T('Add')}</button><p class="note pnhint" id="${ID}Hint"></p></form>` : ''}
      ${items.length ? `<div class="tw"><table class="pntbl"><thead><tr>${F.map(f => `<th>${esc(f.label)}</th>`).join('')}${o.extraHead ? `<th>${o.extraHead}</th>` : ''}${o.admin ? '<th></th>' : ''}</tr></thead><tbody>
        ${items.map((it, i) => i === edit
          ? `<tr class="pnedit">${F.map((f, j) => `<td>${ctl(f, it[f.k], ID + 'E' + j)}</td>`).join('')}${o.extraHead ? `<td class="note" id="${ID}EHint"></td>` : ''}
            <td class="acts"><button class="btn primary" id="${ID}EOk">${T('Save')}</button> <button class="btn" id="${ID}ENo">${T('Cancel')}</button></td></tr>`
          : `<tr>${F.map(f => `<td>${cell(it, f)}</td>`).join('')}${o.extraHead ? `<td class="note">${o.extra(it)}</td>` : ''}
            ${o.admin ? `<td class="acts"><button class="btn" data-re="${i}" ${edit !== null ? 'disabled' : ''}>${T('Edit')}</button> <button class="btn danger" data-rd="${i}" ${edit !== null ? 'disabled' : ''}>${T('Delete')}</button></td>` : ''}</tr>`).join('')}
        </tbody></table></div>` : `<div class="empty">${o.empty}</div>`}
      <p class="err rterr" hidden></p>`;
    if (!o.admin) return;
    const go = document.getElementById(ID + 'Go'), hint = document.getElementById(ID + 'Hint');
    const check = () => { const row = read(ID + 'A'), filled = F.some(f => !f.opts && row[f.k]);
      const r = filled ? o.check(row, -1) || {} : {};
      F.forEach((f, i) => document.getElementById(ID + 'A' + i).classList.toggle('bad', (r.bad || []).includes(f.k)));
      go.disabled = !filled || !!r.err || !!(r.bad || []).length;
      hint.classList.toggle('warn', !!r.err || !!r.warn);
      hint.innerHTML = !filled ? o.hint : r.err ? esc(r.err) : (r.hint || ''); };
    F.forEach((f, i) => document.getElementById(ID + 'A' + i).addEventListener('input', check)); check();
    document.getElementById(ID + 'Add').onsubmit = async e => { e.preventDefault(); check(); if (go.disabled) return;
      const row = read(ID + 'A'), r = o.check(row, -1) || {};
      if (await save(r.replace != null ? items.map((x, i) => i === r.replace ? row : x) : [...items, row])) { const f = document.getElementById(ID + 'A' + F.findIndex(x => !x.opts)); if (f) f.focus(); } };
    el.querySelectorAll('[data-re]').forEach(b => b.onclick = () => { edit = +b.dataset.re; draw(); const f = document.getElementById(ID + 'E' + F.findIndex(x => !x.opts)); if (f) { f.focus(); f.select(); } });
    el.querySelectorAll('[data-rd]').forEach(b => b.onclick = async () => { const it = items[+b.dataset.rd];
      if (confirm(o.delAsk(it))) await save(items.filter(x => x !== it)); });
    if (edit !== null) {
      const ok = document.getElementById(ID + 'EOk'), eh = document.getElementById(ID + 'EHint');
      const echk = () => { const row = read(ID + 'E'), r = o.check(row, edit) || {};
        F.forEach((f, i) => document.getElementById(ID + 'E' + i).classList.toggle('bad', (r.bad || []).includes(f.k)));
        ok.disabled = !!r.err || !!(r.bad || []).length; ok.title = r.err || '';
        if (eh) eh.textContent = r.err || ''; };
      F.forEach((f, i) => document.getElementById(ID + 'E' + i).addEventListener('input', echk)); echk();
      const commit = () => { if (!ok.disabled) save(items.map((x, i) => i === edit ? read(ID + 'E') : x)); };
      ok.onclick = commit; document.getElementById(ID + 'ENo').onclick = () => { edit = null; draw(); };
      F.forEach((f, i) => document.getElementById(ID + 'E' + i).addEventListener('keydown', e => { if (e.key === 'Enter') commit(); else if (e.key === 'Escape') { edit = null; draw(); } }));
    } };
  draw();
  // something typed in the add form or a row being changed counts as unsaved
  return {dirty:() => edit !== null || (o.admin && F.some((f, i) => { const x = document.getElementById(ID + 'A' + i); return x && !f.opts && x.value.trim() !== ''; }))};
}
// addresses as people type them: an IPv4 / IPv6 address, a network with net=true, AS<number> with asn=true
function addrOk(v, net, asn){
  if (asn && /^AS\d{1,10}$/i.test(v)) return true;
  const [a, pre, extra] = v.split('/');
  if (extra !== undefined || (pre !== undefined && (!net || !/^\d{1,3}$/.test(pre)))) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) return a.split('.').every(x => +x <= 255) && (pre === undefined || +pre <= 32);
  return a.includes(':') && /^[0-9a-f:.]+$/i.test(a) && (a.match(/::/g) || []).length <= 1 && (pre === undefined || +pre <= 128);
}
// (1.8.4) a name of yours for one port, from the report (Ports page): the same rules as the table in Flow configuration
async function openPortName(proto, port){
  let d; try { d = await api('ports'); } catch (e) { alert(e.message); return; }
  const have = d.items.find(x => x.proto === proto && x.port === port), def = have ? have.default : (d.known[`${proto}/${port}`] || (port < 1024 ? `${proto.toUpperCase()}/${port}` : `${proto.toUpperCase()} other`));
  const m = openModal(T('Name of {p}', {p:`${proto.toUpperCase()} ${port}`}), T('FlowTrack calls it: {name}', {name:esc(def)}), `<form class="form" id="opnForm" novalidate>
    <label>${T('Name')}<input id="opnName" maxlength="40" value="${esc(have ? have.name : '')}" placeholder="${T('HTTPS management')}" autocomplete="off"></label>
    <p class="note" style="margin:0">${T('New records get the name at once; the records of the last 30 days within a minute, the totals of longer periods after the current hour.')} ${T('All names: Settings → Flow configuration.')}</p>
    <p class="err" id="opnErr" hidden></p>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit" id="opnOk">${T('Save')}</button>${have ? `<button class="btn danger" type="button" id="opnDel">${T('Delete the name')}</button>` : ''}</div></form>`);
  const inp = document.getElementById('opnName'), ok = document.getElementById('opnOk');
  const chk = () => { ok.disabled = !inp.value.trim(); }; inp.addEventListener('input', chk); chk(); inp.focus(); inp.select();
  const put = async list => { try { await apiPost('ports', {items:list.map(({proto, port, name}) => ({proto, port, name}))}); m.close(); render(); } catch (e) { formErr('opnErr', e.message); } };
  const rest = d.items.filter(x => !(x.proto === proto && x.port === port));
  document.getElementById('opnForm').onsubmit = e => { e.preventDefault(); if (!ok.disabled) put([...rest, {proto, port, name:inp.value.trim()}]); };
  const del = document.getElementById('opnDel'); if (del) del.onclick = () => put(rest);
}
// ===================== Settings → Flow configuration: how FlowTrack names and treats the traffic =====================
// (1.8.4) own port names (a table, added with a form) and the roles of our services (from the Events tab)
function vFlowCfg(){
  const admin = isAdmin();
  document.getElementById('setBody').innerHTML = `<div class="grid top">
    <section class="glass panel s12">${ph('list', T('Port names'), T('your own names of ports: they replace the protocol FlowTrack names (e.g. TCP other) in every report'))}<div id="pnBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('dev', T('Host names'), T('your own names of the hosts in your network: shown next to their addresses everywhere, over the names from DNS'))}<div id="hnBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('nodes', T('Network names'), T('your own names of networks: filter by them (net:Office) and see the traffic of each on Top hosts → Networks'))}<div id="nnBox" class="loading"></div></section>
    ${admin ? `<section class="glass panel s7">${ph('dev', T('Services on our side'), T('learned from the last day: what outside addresses call · the role decides which events they get'))}<div id="evsBox" class="loading"></div></section>
    <section class="glass panel s5">${ph('shield', T('Port roles'), T('for services not listed on the left'))}<div id="prBox" class="loading"></div></section>
    <section class="glass panel s12 evsave"><div><button class="btn primary" id="svSave">${T('Save')}</button> <button class="btn" id="svDef">${T('Restore defaults')}</button></div><p class="err" id="svErr"></p><p class="note" id="svOk" hidden>${T('Saved. The next 10-minute check uses the new settings.')}</p></section>` : ''}</div>`;
  const PROTOS = [['tcp', 'TCP'], ['udp', 'UDP']], up = p => p.toUpperCase();
  let items = [], known = {}, edit = null;      // edit = index of the row being changed
  const pnDirty = () => edit !== null || ['pnN', 'pnT'].some(id => { const x = document.getElementById(id); return x && x.value.trim() !== ''; });
  const deflt = (pr, port) => known[`${pr}/${port}`] || (port < 1024 ? `${up(pr)}/${port}` : `${up(pr)} other`);
  const portOk = v => /^\d{1,5}$/.test(v) && +v >= 1 && +v <= 65535;
  const save = async list => { const d = await apiPost('ports', {items:list.map(({proto, port, name}) => ({proto, port, name}))}); edit = null; draw(d); return d; };
  const draw = d => { const el = document.getElementById('pnBox'); if (!el) return;
    items = d.items; known = d.known || {}; el.classList.remove('loading');
    const sel = (id, v) => `<select id="${id}" aria-label="${T('Protocol')}">${PROTOS.map(([k, l]) => `<option value="${k}" ${v === k ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
    const row = (it, i) => i === edit
      ? `<tr class="pnedit"><td>${sel('pnEdP', it.proto)}</td><td><input id="pnEdN" class="mono" inputmode="numeric" maxlength="5" value="${it.port}" aria-label="${T('Port')}"></td>
          <td><input id="pnEdT" maxlength="40" value="${esc(it.name)}" aria-label="${T('Name')}"></td><td class="note" id="pnEdD">${esc(deflt(it.proto, it.port))}</td>
          <td class="acts"><button class="btn primary" id="pnEdOk">${T('Save')}</button> <button class="btn" id="pnEdNo">${T('Cancel')}</button></td></tr>`
      : `<tr><td><span class="tag">${up(it.proto)}</span></td><td class="mono">${it.port}</td><td><b>${esc(it.name)}</b></td><td class="note">${esc(it.default)}</td>
          ${admin ? `<td class="acts"><button class="btn" data-pe="${i}" ${edit !== null ? 'disabled' : ''}>${T('Edit')}</button> <button class="btn danger" data-pd="${i}" ${edit !== null ? 'disabled' : ''}>${T('Delete')}</button></td>` : ''}</tr>`;
    el.innerHTML = `${admin ? `<form class="form pnadd" id="pnAdd" novalidate>
        <label>${T('Protocol')}${sel('pnP', 'tcp')}</label>
        <label>${T('Port')}<input id="pnN" class="mono" inputmode="numeric" maxlength="5" placeholder="8443" autocomplete="off"></label>
        <label class="pnname">${T('Name')}<input id="pnT" maxlength="40" placeholder="${T('HTTPS management')}" autocomplete="off"></label>
        <button class="btn primary" type="submit" id="pnGo">${T('Add')}</button>
        <p class="note pnhint" id="pnHint">${T('Pick the protocol, type the port number (1–65535) and the name you want to see in the reports.')}</p></form>` : ''}
      ${items.length ? `<div class="tw"><table class="pntbl"><thead><tr><th>${T('Protocol')}</th><th>${T('Port')}</th><th>${T('Name')}</th><th>${T('Without your name')}</th>${admin ? '<th></th>' : ''}</tr></thead>
        <tbody>${items.map(row).join('')}</tbody></table></div>`
        : `<div class="empty">${T('No own names yet.')}${admin ? ' ' + T('Example: TCP 8443 → HTTPS management.') : ''}</div>`}
      <p class="note">${T('New records get the name at once; the records of the last 30 days within a minute, the totals of longer periods after the current hour.')}${d.applied ? '' : ' <b>' + T('Renaming the totals…') + '</b>'}</p>
      <p class="err" id="pnErr" hidden></p>`;
    const fail = e => { const x = document.getElementById('pnErr'); if (x) { x.textContent = e.message || e; x.hidden = false; } };
    if (!admin) return;
    // the add form: the button only works with a valid port and a name; the hint says what the port is called now
    const P = document.getElementById('pnP'), N = document.getElementById('pnN'), Tt = document.getElementById('pnT'), go = document.getElementById('pnGo'), hint = document.getElementById('pnHint');
    const check = () => { const v = N.value.trim(), pr = P.value; N.value = v.replace(/\D/g, '');
      const ok = portOk(N.value), dup = ok && items.find(it => it.proto === pr && it.port === +N.value);
      N.classList.toggle('bad', !!N.value && !ok);
      go.disabled = !ok || !Tt.value.trim();
      hint.classList.toggle('warn', !!dup || (!!N.value && !ok));
      hint.innerHTML = !N.value ? T('Pick the protocol, type the port number (1–65535) and the name you want to see in the reports.')
        : !ok ? T('A port is a number from 1 to 65535.')
        : dup ? T('{p} already has the name «{name}» — adding replaces it.', {p:`${up(pr)} ${N.value}`, name:esc(dup.name)})
        : T('Now FlowTrack calls it: {name}', {name:`<b>${esc(deflt(pr, +N.value))}</b>`}); };
    [P, N, Tt].forEach(x => x.addEventListener('input', check)); check();
    document.getElementById('pnAdd').onsubmit = async e => { e.preventDefault(); check(); if (go.disabled) return;
      const it = {proto:P.value, port:+N.value, name:Tt.value.trim()};
      try { await save([...items.filter(x => !(x.proto === it.proto && x.port === it.port)), it]); setTimeout(() => { const n = document.getElementById('pnN'); if (n) n.focus(); }); } catch (err) { fail(err); } };
    el.querySelectorAll('[data-pe]').forEach(b => b.onclick = () => { edit = +b.dataset.pe; draw(d); const t = document.getElementById('pnEdT'); t.focus(); t.select(); });
    el.querySelectorAll('[data-pd]').forEach(b => b.onclick = async () => { const it = items[+b.dataset.pd];
      if (!confirm(T('Delete the name «{name}» of {p}? The port gets back the name FlowTrack gives it: {def}.', {name:it.name, p:`${up(it.proto)} ${it.port}`, def:it.default}))) return;
      try { await save(items.filter(x => x !== it)); } catch (err) { fail(err); } });
    if (edit !== null) {
      const eP = document.getElementById('pnEdP'), eN = document.getElementById('pnEdN'), eT = document.getElementById('pnEdT'), ok = document.getElementById('pnEdOk');
      const echk = () => { eN.value = eN.value.replace(/\D/g, ''); const good = portOk(eN.value), clash = good && items.some((x, i) => i !== edit && x.proto === eP.value && x.port === +eN.value);
        eN.classList.toggle('bad', !good || clash); ok.disabled = !good || clash || !eT.value.trim();
        document.getElementById('pnEdD').textContent = clash ? T('already named — edit that row') : good ? deflt(eP.value, +eN.value) : ''; };
      [eP, eN, eT].forEach(x => x.addEventListener('input', echk)); echk();
      const commit = async () => { if (ok.disabled) return; const list = items.slice(); list[edit] = {proto:eP.value, port:+eN.value, name:eT.value.trim()};
        try { await save(list); } catch (err) { fail(err); } };
      ok.onclick = commit; document.getElementById('pnEdNo').onclick = () => { edit = null; draw(d); };
      [eN, eT].forEach(x => x.addEventListener('keydown', e => { if (e.key === 'Enter') commit(); else if (e.key === 'Escape') { edit = null; draw(d); } }));
    } };
  api('ports').then(draw).catch(e => fill('pnBox', errBox(e)));
  // host names: the IP of a host and the name to show
  let hn = null;
  api('hosts/names').then(d => { if (!document.getElementById('hnBox')) return;
    let cur = d.items; const hnItems = () => cur;
    hn = rowTable(document.getElementById('hnBox'), {id:'hn', admin, items:d.items, cols:'minmax(0,220px) minmax(0,1fr) auto',
      fields:[{k:'ip', label:T('IP address'), ph:'10.0.0.15', mono:true, max:45}, {k:'name', label:T('Name'), ph:T('NAS in the office'), max:64}],
      hint:T('Type the address of a host of yours and the name to show for it.'),
      check:(r, at) => { const bad = [], dup = r.ip ? hnItems().findIndex((x, i) => i !== at && x.ip === r.ip) : -1;
        if (r.ip && !addrOk(r.ip, false, false)) return {bad:['ip'], err:T('Not an IP address: {v}', {v:r.ip})};
        if (!r.ip) bad.push('ip'); if (!r.name) bad.push('name');
        if (at >= 0 && dup >= 0) return {bad:['ip'], err:T('This address already has a name — change that row')};
        return {bad, replace:dup >= 0 ? dup : null, warn:dup >= 0, hint:dup >= 0 ? T('{ip} is already named «{name}» — adding replaces it.', {ip:esc(r.ip), name:esc(hnItems()[dup].name)}) : ''}; },
      show:(it, k) => k === 'ip' ? `<span class="mono">${esc(it.ip)}</span>` : `<b>${esc(it.name)}</b>`,
      save:async list => { const r = await apiPost('hosts/names', {items:list}); cur = r.items; return r.items; },
      delAsk:it => T('Delete the name «{name}» of {ip}?', {name:it.name, ip:it.ip}),
      empty:T('No own host names yet.') + (admin ? ' ' + T('Example: 10.0.0.15 → NAS in the office.') : '')});
  }).catch(e => fill('hnBox', errBox(e)));
  // (1.8.7) network names: a network (CIDR) and its name; several networks may share one name
  let nn = null;
  api('networks').then(d => { if (!document.getElementById('nnBox')) return;
    let cur = d.items; const norm = v => { const c = addrCheck(v); return c.ok && c.net ? c.v : null; };
    nn = rowTable(document.getElementById('nnBox'), {id:'nn', admin, items:d.items, cols:'minmax(0,220px) minmax(0,1fr) auto',
      fields:[{k:'net', label:T('Network'), ph:'172.16.0.0/24', mono:true, max:49}, {k:'name', label:T('Name'), ph:T('Office'), max:40}],
      hint:T('Type a network of yours with its mask and the name to show for it. Give several networks one name to count them together.'),
      check:(r, at) => { const bad = [], n = r.net ? norm(r.net) : null, dup = n ? cur.findIndex((x, i) => i !== at && norm(x.net) === n) : -1;
        if (r.net && !n) return {bad:['net'], err:addrCheck(r.net).ok ? T('Write the network with its mask: {v}/24', {v:r.net}) : addrCheck(r.net).msg};
        if (!r.net) bad.push('net'); if (!r.name) bad.push('name');
        if (at >= 0 && dup >= 0) return {bad:['net'], err:T('This network already has a name — change that row')};
        const same = r.name ? cur.filter((x, i) => i !== at && i !== dup && x.name.toLowerCase() === r.name.toLowerCase()).map(x => x.net) : [];
        return {bad, replace:dup >= 0 ? dup : null, warn:dup >= 0, hint:dup >= 0 ? T('{net} is already named «{name}» — adding replaces it.', {net:esc(n), name:esc(cur[dup].name)})
          : same.length ? T('«{name}» also takes in {nets}: their traffic counts together.', {name:esc(r.name), nets:esc(same.join(', '))}) : n && n !== r.net ? T('Saved as {net}', {net:`<b>${esc(n)}</b>`}) : ''}; },
      show:(it, k) => k === 'net' ? `<span class="mono">${esc(it.net)}</span>` : `<b>${esc(it.name)}</b>`,
      save:async list => { const r = await apiPost('networks', {items:list}); cur = r.items; META.networks = r.items; return r.items; },
      delAsk:it => T('Delete the name «{name}» of {net}?', {name:it.name, net:it.net}),
      empty:T('No named networks yet.') + (admin ? ' ' + T('Example: 172.16.0.0/24 → Office.') : '')});
  }).catch(e => fill('nnBox', errBox(e)));
  if (!admin) return;
  // the roles of our services and the port lists (detections read them; saved apart from the rest of the Events tab)
  const get = async u => { const r = await fetch(u); if (!r.ok) throw new Error((await r.json()).error || r.status); return r.json(); };
  const show = res => { const cfg = res.config;
    const box = (id, html) => { const el = document.getElementById(id); if (!el) return; el.classList.remove('loading'); el.innerHTML = html; };
    const roles = {'':T('auto'), public:T('public — floods only'), sensitive:T('sensitive — guessing, probes'), normal:T('ordinary — scans only')};
    // a busy network has hundreds of services: the busiest and the ones with a role of their own first, a search for the rest
    const TOP = 12, many = res.services.length > TOP;
    box('evsBox', res.services.length ? `${many ? `<div class="form svfind"><input id="svQ" type="search" placeholder="${T('Find a service: address or port')}" aria-label="${T('Find a service: address or port')}"></div>` : ''}
      <div class="tw form"><table class="evs"><thead><tr><th>${T('Service')}</th><th class="num">${T('Callers / day')}</th><th>${T('Role')}</th></tr></thead><tbody>
      ${res.services.map((s, i) => `<tr data-q="${esc(s.ep.toLowerCase())}" ${many && i >= TOP && !s.set ? 'hidden data-more' : ''}><td class="mono">${esc(s.ep.replace('/6', ' TCP').replace('/17', ' UDP'))}</td><td class="num mono">${s.peers.toLocaleString(LOC)}</td>
        <td><select data-ep="${esc(s.ep)}">${Object.entries(roles).map(([r, l]) => `<option value="${r}" ${(s.set ? s.role : '') === r ? 'selected' : ''}>${r ? l : `${l}: ${roles[s.role].split(' — ')[0]}`}</option>`).join('')}</select></td></tr>`).join('')}</tbody></table></div>
      ${many ? `<div class="svmore"><button class="lnk" id="svAll">${T('Show all {n} services', {n:res.services.length.toLocaleString(LOC)})}</button><span class="note" id="svNone" hidden>${T('No service matches.')}</span></div>` : ''}
      <p class="note">${T('Public services (web sites) get many visitors: only floods and aggressive clients count there. Sensitive ones (SSH, management, VPN) also get password guessing and the daily probe summary.')}</p>`
      : `<div class="empty">${T('Nothing learned yet — services show up within an hour of traffic.')}</div>`);
    box('prBox', `<div class="form">
      <label>${T('Sensitive ports')}<textarea id="evSens" rows="3" placeholder="22, 3389, 8443">${esc(cfg.sensitive.join(', '))}</textarea></label>
      <label>${T('Public ports')}<textarea id="evPub" rows="2" placeholder="80, 443">${esc(cfg.public.join(', '))}</textarea></label>
      <p class="note">${T('Port numbers, separated by commas.')} ${T('The role of a service listed on the left wins over these ports.')}</p></div>`);
    const q = document.getElementById('svQ'), all = document.getElementById('svAll');
    const filt = () => { const v = q.value.trim().toLowerCase(), showAll = all.dataset.on === '1'; let n = 0;
      document.querySelectorAll('table.evs tbody tr').forEach(tr => { const hit = v ? tr.dataset.q.includes(v) : (showAll || !tr.hasAttribute('data-more')); tr.hidden = !hit; n += hit; });
      document.getElementById('svNone').hidden = n > 0; all.hidden = !!v || showAll; };
    if (q) { q.addEventListener('input', filt); all.onclick = () => { all.dataset.on = '1'; filt(); }; }
    mark(); };
  const svCollect = () => { const roles = {}; document.querySelectorAll('table.evs select[data-ep]').forEach(s => { if (s.value) roles[s.dataset.ep] = s.value; });
    const sens = document.getElementById('evSens'); if (!sens) throw new Error('not drawn');
    return {roles, sensitive:sens.value, public:document.getElementById('evPub').value}; };
  const mark = dirtyGuard(svCollect), svDirty = state.dirty;
  state.dirty = () => svDirty() || pnDirty() || !!(hn && hn.dirty()) || !!(nn && nn.dirty());
  const err = document.getElementById('svErr'), ok = document.getElementById('svOk');
  get('api/events/config').then(show).catch(e => { err.textContent = e.message; });
  document.getElementById('svSave').onclick = async () => { err.textContent = ''; ok.hidden = true;
    try { show(await apiPost('events/services', svCollect())); ok.hidden = false; } catch (e) { err.textContent = e.message; } };
  document.getElementById('svDef').onclick = async () => { if (!confirm(T('Restore the default port roles? The roles set per service are cleared too.'))) return;
    err.textContent = ''; ok.hidden = true;
    try { show(await apiPost('events/services', {reset:true})); ok.hidden = false; } catch (e) { err.textContent = e.message; } };
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
  let d = null, fp = '', checking = null, asked = 0, deleting = 0;
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
      : last.prune_error ? `<span class="pill warn">${T('old backups not deleted')}</span> <span title="${esc(last.prune_error)}">${esc(last.prune_error.slice(0, 90))}</span>`
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
    const el = box('bkList', (d.backups.length ? `<div class="tw"><table class="compact"><thead><tr><th>${T('Time')}</th><th>${T('Type')}</th><th class="num">${T('Size')}</th><th>${T('Version')}</th><th>${T('Where')}</th><th></th><th></th></tr></thead><tbody>
      ${rows.map(m => `<tr data-id="${esc(m.id)}"><td class="mono">${when(m.t)}<div class="nat">${ago(m.t)}</div></td><td>${m.kind === 'full' ? `<b>${T('Full')}</b>` : T('Changes')}${m.encrypted ? ` <span title="${T('the copies are encrypted')}">🔒</span>` : ''}</td>
        <td class="num mono">${fmtB(m.size)}</td><td class="mono">${esc(m.version)}</td><td>${[`<span class="pill ok">${T('here')}</span>`, ...on.map(([k, l]) => place(m, k, l))].join(' ')}</td>
        <td class="nat">${Math.round(m.took)} s</td><td style="white-space:nowrap"><button class="btn" data-a="restore">${T('Restore…')}</button> <button class="btn" data-a="verify" ${busy() ? 'disabled' : ''} title="${esc(m.verified && !m.verified.ok ? m.verified.problems.join('\n') : m.verified ? T('checked {when}', {when:when(m.verified.t)}) : T('Check that every file of the backup is in place'))}">${vf(m)}</button> <button class="btn danger" data-a="del" ${busy() ? 'disabled' : ''}>${T('Delete…')}</button></td></tr>`).join('')}</tbody></table></div>
      ${d.backups.length > 8 ? `<p style="margin:8px 0 0"><button class="btn" id="bkMore">${state.bkAll ? T('Show the last 8') : T('Show all ({n})', {n:d.backups.length})}</button></p>` : ''}
      <p class="note">${T('A backup of the changes needs the full one before it; the keeping rule deletes a full backup together with the changes after it. A failed copy is tried again with the next backup.')}</p>`
      : `<div class="empty">${d.next ? T('No backups yet — the first one runs {when}, or press Back up now.', {when:when(d.next)}) : T('No backups yet — press Back up now.')}</div>`) + delNote());
    if (!el) return;
    const more = document.getElementById('bkMore'); if (more) more.onclick = () => { state.bkAll = !state.bkAll; draw(); };
    el.querySelectorAll('button[data-a="restore"]').forEach(b => b.onclick = () => openRestore(d.backups.find(x => x.id === b.closest('tr').dataset.id)));
    el.querySelectorAll('button[data-a="del"]').forEach(b => b.onclick = () => openDelete(d.backups.find(x => x.id === b.closest('tr').dataset.id)));
    el.querySelectorAll('button[data-a="verify"]').forEach(b => b.onclick = async () => { const id = b.closest('tr').dataset.id;
      try { await apiPost('backups/verify', {id}); checking = id; asked = Math.floor(Date.now() / 1000); draw(); poll(); } catch (e) { formErr('bkErr', e.message); } });
    const nb = document.getElementById('bkNow'), r = d.running;
    nb.disabled = busy();
    nb.textContent = !r ? (d.pending ? T('Starting…') : T('Back up now'))
      : r.stage === 'data' ? T('Backing up the flow data…') : r.stage === 'settings' ? T('Saving the settings…')
      : T('Copying to {where}… {pct} %', {where:r.stage.toUpperCase(), pct:r.total ? Math.min(99, Math.floor(100 * r.done / r.total)) : 0});
  };
  // (1.8.8) deleting by hand: a full backup takes its changes with it; confirmed with the admin's own password
  const delNote = () => { const x = d.deleted; if (!x || x.t < deleting - 5 || !deleting) return '';
    return x.error ? `<p class="err" style="margin:8px 0 0">${esc(x.error)}</p>`
      : `<p class="note" style="margin:8px 0 0;color:var(--ok)">${Tn(x.ids.length, 'Deleted {n} backup.', 'Deleted {n} backups.', {n:x.ids.length})}</p>`; };
  const openDelete = m => {
    const goes = [m, ...(m.kind === 'full' ? d.backups.filter(x => x.base === m.id) : [])].sort((a, b) => a.t - b.t);
    const fullsLeft = d.backups.filter(x => x.kind === 'full' && !goes.includes(x)).length, places = BK_DESTS.filter(([k]) => d.config[k].on);
    const md = openModal(T('Delete a backup'), when(m.t), `<form class="form" id="bdForm" novalidate style="padding:4px 2px">
      <p class="note" style="margin:0">${goes.length > 1 ? T('A backup of the changes cannot be restored without its full one, so these go together:') : T('This backup goes:')}</p>
      <div class="tw"><table class="compact"><tbody>${goes.map(x => `<tr><td class="mono">${when(x.t)}</td><td>${x.kind === 'full' ? `<b>${T('Full')}</b>` : T('Changes')}</td><td class="num mono">${fmtB(x.size)}</td></tr>`).join('')}</tbody></table></div>
      <p class="note" style="margin:0">${T('Frees {size} on this server. It cannot be undone.', {size:`<b>${fmtB(goes.reduce((a, x) => a + (x.size || 0), 0))}</b>`})}</p>
      ${fullsLeft ? '' : `<p class="note" style="margin:0;color:var(--warn)">${T('No full backup is left after it: the next backup will be a full one.')}</p>`}
      ${places.length ? `<label class="chk"><input type="checkbox" id="bdCopies">${T('Also delete their copies on {places}', {places:places.map(([, l]) => l).join(', ')})}</label>` : ''}
      <label>${T('Your password ({user}) to confirm', {user:esc(ME.name)})}<input id="bdPass" type="password" autocomplete="current-password"></label>
      <p class="err" id="bdErr" hidden></p>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn danger" type="submit" id="bdOk" disabled>${Tn(goes.length, 'Delete {n} backup', 'Delete {n} backups', {n:goes.length})}</button><button class="btn" type="button" id="bdNo">${T('Cancel')}</button></div></form>`);
    const pw = document.getElementById('bdPass'), ok = document.getElementById('bdOk');
    pw.addEventListener('input', () => { ok.disabled = !pw.value; }); pw.focus();
    document.getElementById('bdNo').onclick = md.close;
    document.getElementById('bdForm').onsubmit = async e => { e.preventDefault(); if (ok.disabled) return; ok.disabled = true; formErr('bdErr', '');
      const cp = document.getElementById('bdCopies');
      try { await apiPost('backups/delete', {ids:[m.id], password:pw.value, copies:!!(cp && cp.checked)}); md.close();
        deleting = asked = Math.floor(Date.now() / 1000); d.pending = true; draw(); poll(); }
      catch (err) { formErr('bdErr', err.message); pw.select(); ok.disabled = false; } }; };
  const openRestore = m => openModal(T('Restore a backup'), when(m.t), `<div class="form" style="padding:4px 2px">
      <p class="note" style="margin:0">${T('Restoring stops collecting and the web interface for a few minutes, replaces the flow data and the settings with the backup, and starts them again. Records that arrive meanwhile are lost. The current data is set aside until the backup is in place and comes back if the restore fails.')}</p>
      <p class="note" style="margin:0">${T('Run on the server:')}</p>
      ${codeBox(`sudo flowtrack restore ${m.id}`, '', 'mono', 'margin:0;padding:10px 12px;border-radius:10px;background:rgba(0,0,0,.35);white-space:pre-wrap')}
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
  const bkMark = dirtyGuard(collect);
  document.getElementById('bkSave').onclick = async () => { const a = document.getElementById('bkPass').value, b2 = document.getElementById('bkPass2').value;
    document.getElementById('bkOk').hidden = true;
    if (a !== b2) return formErr('bkErr', T('The passphrases differ'));
    formErr('bkErr', '');
    try { const r = await apiPost('backups/config', collect()); d.config = r.config; d.next = r.next;
      ['bkPass', 'bkPass2', 's3Sec', 'sfKey', 'sfPass', 'ftPass'].forEach(id => { document.getElementById(id).value = ''; });
      forms(); bkMark(); draw(); document.getElementById('bkOk').hidden = false;
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
        const delWait = deleting && !(n.deleted && n.deleted.t >= deleting - 5) && Date.now() / 1000 - deleting < 300;
        if (n.running || n.pending || checking || delWait) { setTimeout(tick, 2000); return; }
      } catch (e) { setTimeout(tick, 5000); return; }
      polling = false; };
    setTimeout(tick, 1500); };
  load().then(n => { if (seq !== renderSeq) return; d = n; forms(); bkMark(); draw(); if (busy()) poll(); })
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
        return `<tr class="click" data-pick="${esc(x.ip)}"><td><span class="dot ${st}" title="${never ? T('has not sent data yet') : stale ? T('no data for over 3 min') : T('online')}"></span></td><td><b class="mono">${esc(x.name)}</b>${x.configured ? '' : ` <span class="tag">${T('not described')}</span>`}${protoPill(x)}${snmpTag(x)}${dupPill(x)}${repeatPill(x)}${runningPill(x)}</td><td>${esc(x.vendor || '—')}<br><span class="nat">${esc(x.model)}</span></td><td><span class="tag">${never ? T('waiting') : esc(x.proto)}</span></td><td>${esc(x.site || '—')}</td><td class="ipl">${esc(x.ip)}</td>
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
// an exporter that sends the running totals of long sessions: the collector stores only their growth
const runningPill = x => x.running_totals ? ` <span class="pill info" title="${T('This device sends long sessions again at every export with all their bytes since the start (a running total). FlowTrack stores only what each session grew by since its last export.')}">${T('running totals corrected')}</span>` : '';
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
  const admin = isAdmin(), total = x.interfaces.reduce((a, i) => a + i.bytes, 0) || 1, counted = x.interfaces.some(i => i.counters), csrc = new Set(x.interfaces.filter(i => i.counters).map(i => i.counters.src || 'sflow'));
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
    // (1.12.0) capacity: the port speed, or own figures in / out (an ISP contract)
    const capv = v => v ? (v >= 1000 && v % 1000 === 0 ? `${v / 1000} G` : `${v} M`) : '';
    const cap = edit ? `<span class="ifcap"><input class="ifcapin" data-idx="${i.index}" type="number" min="0" step="any" value="${i.cap_own ? i.cap_in : ''}" placeholder="${i.cap_auto || '—'}" aria-label="${T('Interface {idx} capacity in, Mbit/s', {idx: i.index})}"><span>↓</span><input class="ifcapout" data-idx="${i.index}" type="number" min="0" step="any" value="${i.cap_own ? i.cap_out : ''}" placeholder="${i.cap_auto || '—'}" aria-label="${T('Interface {idx} capacity out, Mbit/s', {idx: i.index})}"><span>↑</span></span>`
      : !i.cap_in && !i.cap_out ? '<span class="nat">—</span>' : `<span class="mono">${i.cap_in === i.cap_out ? capv(i.cap_in) : `${capv(i.cap_in)} ↓ ${capv(i.cap_out)} ↑`}</span>${i.cap_own ? ` <span class="tag" title="${T('your figures')}">${T('own')}</span>` : ''}`;
    return `<tr${i.unseen ? ' class="unseen"' : ''}><td class="num mono">${i.index}</td><td>${name}</td><td>${addrs}</td><td>${role} ${hint}${unseen}</td><td class="nowrap">${cap}</td><td class="num mono">${i.unseen ? '—' : fmtB(i.bytes)}</td><td class="num mono">${i.unseen ? '—' : Math.round(i.ext_share * 100) + '%'}</td>${counted ? `<td class="ifcnt">${ifCounters(i.counters)}</td>` : ''}</tr>`;
  }).join('');
  const sn = x.snmp || {}, when = t => new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'});
  const snmpLine = !sn.enabled ? '' : `<div class="ifsnmp">${sn.polled ? (sn.ok ? `<span class="pill ok">SNMP</span> <span class="nat">${esc(sn.sys && sn.sys.name || '')}${sn.sys && sn.sys.name ? ' · ' : ''}${T('{ifs} interfaces, {addrs} addresses · polled {when}', {ifs: sn.interfaces, addrs: sn.addresses, when: when(sn.polled)})}${sn.counters ? ' · ' + (sn.counters.ok ? T('traffic counters every minute, read {when}', {when: when(sn.counters.t)}) : T('traffic counters not read: {err}', {err: sn.counters.error || '?'})) : ''}</span>`
      : `<span class="pill warn" title="${esc(sn.detail || '')}">${T('SNMP error')}</span> <span class="nat">${esc(sn.error_text || '')}${sn.last_ok ? ' · ' + T('last good poll {when}', {when: when(sn.last_ok)}) : ''}</span>`)
      : `<span class="pill info">SNMP</span> <span class="nat">${T('waiting for the first poll')}</span>`}${admin && !edit ? ` <button class="btn snmppoll">${T('Poll now')}</button>` : ''}</div>`;
  const btns = !admin || !x.interfaces.length ? '' : edit ? `<span class="nat ifmsg"></span><button class="btn ifcancel">${T('Cancel')}</button><button class="btn primary ifsave" disabled>${T('Save')}</button>`
                                                           : `<span class="nat ifmsg"></span><button class="btn ifedit">${T('Edit')}</button>`;
  return `<div class="ifdev${edit ? ' editing' : ''}" data-dev="${esc(x.ip)}"><div class="ifdev-h"><h4 class="mono">${esc(x.name)} <span class="nat">${esc(x.ip)}${x.vendor ? ' · ' + esc(x.vendor) : ''}</span></h4>${btns}</div>${snmpLine}
    ${x.interfaces.length ? `<div class="tw"><table class="compact"><thead><tr><th class="num">${T('Index')}</th><th>${T('Name')}</th><th>${T('IP addresses')}</th><th>${T('Role')}</th><th title="${T('Mbit/s: the port speed, or your own figures in ↓ / out ↑ (e.g. your ISP contract) — empty keeps the port speed')}">${T('Capacity, Mbit/s')}</th><th class="num">${T('Traffic, 24 h')}</th><th class="num" title="${T('Share of traffic with outside addresses')}">${T('Ext.')}</th>${counted ? (csrc.size === 1 && csrc.has('snmp') ? `<th title="${T('From the interface counters read over SNMP every minute')}">${T('Load (SNMP counters)')}</th>`
      : csrc.size === 1 ? `<th title="${T('From the interface counters the device sends with sFlow')}">${T('Load (sFlow counters)')}</th>` : `<th title="${T('From the interface counters: read over SNMP or sent with sFlow')}">${T('Load (interface counters)')}</th>`) : ''}</tr></thead><tbody>${rows}</tbody></table></div>
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
    const interfaces = roles.map(r => ({index:+r.dataset.idx, role:r.value, name:val('ifname', r.dataset.idx), addrs:val('ifaddr', r.dataset.idx).split(/[\s,;]+/).filter(Boolean),
      cap_in:val('ifcapin', r.dataset.idx), cap_out:val('ifcapout', r.dataset.idx)}));
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
  maxLeave();                // a full-screen panel would hide it
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
      <div class="cols"><div><h4>${T('1. Configuration on the device')}</h4>${codeBox(code(), 'devCode')}</div>
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
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('users', T('Users'), T('an administrator manages everything; «Viewer» is read-only, no changes to devices or users'), `<button class="btn primary" id="addUser">${T('+ New user')}</button>`)}<div id="uBox" class="loading"></div></section>
    <section class="glass panel s12" id="ldapBox">${ph('M9 2l6 3v4c0 4-3 6.5-6 7.5C6 15.5 3 13 3 9V5zM6.5 9l2 2 3.5-4', T('Sign-in through the directory'), T('Active Directory or LDAP · the sign-in page then offers «Local account» or the directory'))}<div id="ldapBody" class="loading"></div></section></div>`;
  ldapPanel(document.getElementById('ldapBody'));
  document.getElementById('addUser').onclick = () => openUser(null);
  section('uBox', async () => { const r = await fetch('api/users'); if (!r.ok) throw new Error((await r.json()).error || r.status); const users = (await r.json()).users;
    setTimeout(() => document.querySelectorAll('[data-user]').forEach(b => b.onclick = () => openUser(users.find(u => u.name === b.dataset.user))));
    const when = t => t ? new Date(t * 1000).toLocaleString(LOC, {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}) : T('never signed in');
    return `<div class="tw"><table><thead><tr><th>${T('Username')}</th><th>${T('Role')}</th><th>${T('Created')}</th><th>${T('Last sign-in')}</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td><b class="mono">${esc(u.display || u.name)}</b>${u.source === 'ldap' ? ` <span class="tag" title="${T('signs in through the directory')}">LDAP</span>` : ''}${u.name === ME.name ? ` <span class="tag">${T('you')}</span>` : ''}${u.default_password ? ` <span class="pill warn">${T('default password')}</span>` : ''}</td><td>${u.role === 'admin' ? `<span class="pill info">${T('Administrator')}</span>` : `<span class="tag">${T('Viewer')}</span>`}</td>
        <td class="nat">${when(u.created)}</td><td class="nat">${when(u.last_login)}</td><td><button class="btn" data-user="${esc(u.name)}">${T('Edit')}</button></td></tr>`).join('')}</tbody></table></div>`; });
}
function genPassword(){ const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const b = new Uint32Array(14); crypto.getRandomValues(b); return [...b].map(x => a[x % a.length]).join(''); }
function openUser(u){
  if (u && u.source === 'ldap') return openDirUser(u);
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

// (1.12.0) a directory user: the role comes from the groups at each sign-in, the password from the directory; only
// removing the entry here (it comes back at the next sign-in, while the groups allow it)
function openDirUser(u){
  const self = u.name === ME.name;
  const m = openModal(T('User {name}', {name:u.display || u.name}), T('signs in through the directory'), `<div class="form" style="padding:4px 2px">
    <div class="about"><div><span>${T('Role')}</span><b>${u.role === 'admin' ? T('Administrator') : T('Viewer')}</b><span class="nat">${T('from the directory groups, at each sign-in')}</span></div>
      <div><span>${T('Last sign-in')}</span><b>${u.last_login ? new Date(u.last_login * 1000).toLocaleString(LOC) : T('never signed in')}</b></div></div>
    <p class="note" style="margin:0">${T('To change the role, move the user to another group in the directory; the password is changed in the directory too.')}</p>
    <p class="err" id="duErr" hidden></p>
    <div style="display:flex;gap:8px;flex-wrap:wrap">${self ? '' : `<button class="btn" type="button" id="duDel">${T('Remove from FlowTrack')}</button>`}<button class="btn" type="button" id="duNo">${T('Close')}</button></div></div>`);
  document.getElementById('duNo').onclick = m.close;
  const del = document.getElementById('duDel');
  if (del) del.onclick = async () => { try { await apiPost('users/delete', {name:u.name}); m.close(); render(); } catch (e) { formErr('duErr', e.message); } };
}
// the directory settings + a check that shows what FlowTrack finds for a user (groups, role) before anyone relies on it
function ldapPanel(el){
  let d = null;
  const $ = id => document.getElementById(id);
  const lines = a => (a || []).join('\n');
  const draw = () => {
    el.classList.remove('loading');
    const sec = [['ldaps', T('LDAPS (port 636)')], ['starttls', T('STARTTLS (port 389)')], ['none', T('none — test networks only')]];
    el.innerHTML = `<form class="form" id="ldForm" novalidate>
      <label class="chk"><input type="checkbox" id="ldOn" ${d.on ? 'checked' : ''}>${T('Offer sign-in through the directory')}</label>
      <div class="two"><label>${T('Directory type')}<select id="ldKind"><option value="ad" ${d.kind === 'ad' ? 'selected' : ''}>Active Directory</option><option value="ldap" ${d.kind === 'ldap' ? 'selected' : ''}>${T('LDAP (OpenLDAP, FreeIPA, …)')}</option></select></label>
        <label>${T('Name on the sign-in page')}<input id="ldLabel" maxlength="40" value="${esc(d.label)}" placeholder="${d.kind === 'ad' ? 'CORP' : 'LDAP'}"></label></div>
      <div class="two"><label>${T('Server')}<input id="ldHost" value="${esc(d.host)}" placeholder="dc1.corp.example.com" autocomplete="off"></label>
        <div class="two"><label>${T('Encryption')}<select id="ldSec">${sec.map(([k, l]) => `<option value="${k}" ${d.security === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
          <label>${T('Port')}<input id="ldPort" type="number" min="1" max="65535" value="${esc(d.port)}"></label></div></div>
      <label class="chk"><input type="checkbox" id="ldVerify" ${d.verify ? 'checked' : ''}>${T('Verify the certificate of the server')}</label>
      <label>${T('CA certificate of the directory (optional, PEM)')}<textarea id="ldCa" rows="2" class="mono" placeholder="-----BEGIN CERTIFICATE-----">${esc(d.ca)}</textarea></label>
      <div class="two"><label>${T('Service account (bind DN)')}<input id="ldBind" value="${esc(d.bind_dn)}" placeholder="${d.kind === 'ad' ? 'svc-flowtrack@corp.example.com' : 'cn=flowtrack,ou=services,dc=example,dc=org'}" autocomplete="off"></label>
        <label>${T('Its password')}<input id="ldBindPw" type="password" autocomplete="new-password" placeholder="${d.bind_password_set ? T('saved — leave empty to keep') : ''}"></label></div>
      <div class="two"><label>${T('Where users are (base DN)')}<input id="ldBase" value="${esc(d.base_dn)}" placeholder="${d.kind === 'ad' ? 'DC=corp,DC=example,DC=com' : 'dc=example,dc=org'}"></label>
        <label>${T('User filter (optional)')}<input id="ldFilter" class="mono" value="${esc(d.user_filter)}" placeholder="${esc(d.default_filters[d.kind])}"></label></div>
      <div class="two"><label>${T('Administrator groups (one per line: name or DN)')}<textarea id="ldAdm" rows="2" class="mono" placeholder="FT-Admins">${esc(lines(d.admin_groups))}</textarea></label>
        <label>${T('Viewer groups')}<textarea id="ldView" rows="2" class="mono" placeholder="FT-Viewers">${esc(lines(d.viewer_groups))}</textarea></label></div>
      <label class="chk"><input type="checkbox" id="ldAll" ${d.everyone_viewer ? 'checked' : ''}>${T('Anyone else who signs in through the directory gets the viewer role')}</label>
      <p class="note" style="margin:0">${T('Nested groups count in Active Directory. Local users keep signing in with «Local account»; at least one local administrator always remains — your way in when the directory is unreachable.')}</p>
      <div class="ldtest"><h4 style="margin:4px 0 6px">${T('Check before switching it on')}</h4>
        <div class="two"><label>${T('A user to look up (optional)')}<input id="ldTU" autocomplete="off" placeholder="anna"></label>
          <label>${T('Their password (optional — also checks it)')}<input id="ldTP" type="password" autocomplete="new-password"></label></div>
        <div><button class="btn" type="button" id="ldTest">${T('Check')}</button></div><div id="ldOut"></div></div>
      <p class="err" id="ldErr" hidden></p><p class="note" id="ldOk" hidden></p>
      <div><button class="btn primary" type="submit">${T('Save')}</button></div></form>`;
    const tls = () => { $('ldVerify').disabled = $('ldSec').value === 'none'; $('ldCa').disabled = $('ldSec').value === 'none'; };
    $('ldSec').onchange = () => { const p = $('ldPort'); if (['389', '636'].includes(p.value)) p.value = $('ldSec').value === 'ldaps' ? '636' : '389'; tls(); };
    $('ldKind').onchange = () => { $('ldFilter').placeholder = d.default_filters[$('ldKind').value]; }; tls();
    const body = () => ({on:$('ldOn').checked, kind:$('ldKind').value, label:$('ldLabel').value.trim(), host:$('ldHost').value.trim(), security:$('ldSec').value,
      port:$('ldPort').value, verify:$('ldVerify').checked, ca:$('ldCa').value.trim(), bind_dn:$('ldBind').value.trim(), bind_password:$('ldBindPw').value,
      base_dn:$('ldBase').value.trim(), user_filter:$('ldFilter').value.trim(), admin_groups:$('ldAdm').value, viewer_groups:$('ldView').value, everyone_viewer:$('ldAll').checked});
    const say = (ok, msg) => { formErr('ldErr', ok ? '' : msg); const n = $('ldOk'); n.textContent = ok ? msg : ''; n.hidden = !ok; };
    $('ldTest').onclick = async e => { const b = e.target, old = b.textContent; b.disabled = true; b.textContent = T('Checking…'); say(true, ''); $('ldOut').innerHTML = '';
      try { const r = await apiPost('ldap/test', Object.assign(body(), {test_user:$('ldTU').value.trim(), test_password:$('ldTP').value}));
        const u = r.user, role = x => x === 'admin' ? T('Administrator') : x === 'viewer' ? T('Viewer') : '';
        $('ldOut').innerHTML = `<div class="about" style="margin-top:8px"><div><span>${T('Service account')}</span><b style="color:var(--ok)">✓ ${T('signed in, base DN found')}</b></div>
          ${!u ? '' : !u.found ? `<div><span>${T('User')}</span><b style="color:var(--warn)">${T('not found with this filter')}</b></div>`
          : `<div><span>${T('User')}</span><b class="mono">${esc(u.name)}</b><span class="nat mono" style="word-break:break-all">${esc(u.dn)}</span></div>
             <div><span>${T('Groups')}</span><b class="mono" style="font-weight:500;font-size:12px;white-space:normal">${u.groups.length ? u.groups.map(g => esc(g.split(',')[0].split('=')[1] || g)).join(', ') : '—'}</b></div>
             <div><span>${T('Role in FlowTrack')}</span><b style="color:${u.role ? 'var(--ok)' : 'var(--crit)'}">${u.role ? role(u.role) : T('none — would not get in')}</b>${u.admin_match.length || u.viewer_match.length ? `<span class="nat">${T('by')} ${esc([...u.admin_match, ...u.viewer_match].join(', '))}</span>` : ''}</div>
             ${'password_ok' in u ? `<div><span>${T('Password')}</span><b style="color:${u.password_ok ? 'var(--ok)' : 'var(--crit)'}">${u.password_ok ? '✓ ' + T('right') : '✕ ' + T('wrong')}</b></div>` : ''}`}</div>`; }
      catch (x) { say(false, x.message); } finally { b.disabled = false; b.textContent = old; } };
    $('ldForm').onsubmit = async e => { e.preventDefault(); say(true, '');
      try { d = await apiPost('ldap', body()); draw(); say(true, T('Saved.') + (d.on ? ' ' + T('The sign-in page now offers «{label}».', {label:d.label || (d.kind === 'ad' ? 'Active Directory' : 'LDAP')}) : '')); }
      catch (x) { say(false, x.message); } };
  };
  fetch('api/ldap').then(r => r.json()).then(j => { d = j; draw(); }).catch(e => { el.classList.remove('loading'); el.innerHTML = `<p class="err">${esc(e.message)}</p>`; });
}

// ===================== session: login, user menu, password =====================
function renderUser(){
  const w = document.getElementById('userWrap'); if (!w || !ME) return;
  w.innerHTML = `${ME.default_password ? `<button class="pill warn" id="pwWarn" style="border:0;cursor:pointer" title="${T('Change the default password')}">${T('change password')}</button>` : ''}
    <button class="user" id="userBtn" aria-haspopup="menu" aria-expanded="false"><span class="avatar">${esc((ME.display || ME.name)[0].toUpperCase())}</span><span class="who"><b>${esc(ME.display || ME.name)}</b><small>${ROLE_LABEL[ME.role]}</small></span></button>
    <div class="menu glass" id="userMenu" role="menu" hidden>${ME.source === 'ldap' ? '' : `<button role="menuitem" id="miPass">${T('Change password')}</button>`}${isAdmin() ? `<button role="menuitem" id="miUsers">${T('Users')}</button>` : ''}<button role="menuitem" id="miOut">${T('Sign out')}</button></div>`;
  const btn = document.getElementById('userBtn'), menu = document.getElementById('userMenu');
  btn.onclick = e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden)); };
  menu.addEventListener('click', () => closeUserMenu());
  const mi = document.getElementById('miPass'); if (mi) mi.onclick = openPassword;      // a directory user's password is the directory's
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
    <label id="lMethodL" hidden>${T('Sign in with')}<select id="lMethod"></select></label>
    <p class="err" id="lErr" hidden></p>
    <button class="btn primary" type="submit" style="justify-self:stretch;text-align:center;padding:9px">${T('button::Sign in')}</button></form>`;
  document.body.appendChild(box);
  document.getElementById('lUser').focus();
  // (1.12.0) the directory, when one is set up: the person chooses how to sign in (a local "admin" and the
  // directory's "admin" are two accounts); the browser remembers the last choice
  fetch('api/login/methods').then(r => r.json()).then(j => { const ms = j.methods || []; if (ms.length < 2) return;
    let last = 'ldap'; try { last = localStorage.getItem('ft-login-method') || 'ldap'; } catch (e) {}
    const sel = document.getElementById('lMethod'); if (!sel) return;
    sel.innerHTML = ms.map(m => `<option value="${esc(m.id)}" ${m.id === last ? 'selected' : ''}>${m.id === 'local' ? T('Local account') : esc(m.label)}</option>`).join('');
    document.getElementById('lMethodL').hidden = false; }).catch(() => {});
  document.getElementById('loginForm').addEventListener('submit', async e => { e.preventDefault(); formErr('lErr');
    try {
      const sel = document.getElementById('lMethod'), method = sel && !document.getElementById('lMethodL').hidden ? sel.value : 'local';
      ME = await apiPost('login', {username:document.getElementById('lUser').value.trim(), password:document.getElementById('lPass').value, method});
      try { if (method) localStorage.setItem('ft-login-method', method); } catch (e) {}
      box.remove(); loginShown = false; document.querySelector('.app').hidden = false;
      META = await fetch('api/meta').then(r => r.json()); render(); health();
    } catch (err) { formErr('lErr', err.message); document.getElementById('lPass').select(); } });
}

async function openHost(ip){
  maxLeave();
  const root = document.getElementById('drawerRoot');
  root.innerHTML = `<div class="scrim" id="scrim"></div><aside class="drawer glass" role="dialog" aria-modal="true" aria-label="${T('Host')} ${esc(ip)}"><div class="loading" style="min-height:200px"></div></aside>`;
  const close = () => { if (hc) { hc.dispose(); const i = charts.indexOf(hc); if (i >= 0) charts.splice(i, 1); } root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  let hc = null; document.addEventListener('keydown', onKey); document.getElementById('scrim').onclick = close;
  let d; try { d = await api('host', {ip}); } catch (e) { root.querySelector('.drawer').innerHTML = errBox(e); return; }
  const s = d.summary;
  root.querySelector('.drawer').innerHTML = `<header><div><h3>${esc(d.host.name || ip)}</h3><div class="ipl" style="color:var(--ink2)">${esc(ip)} · ${d.host.private ? T('inside address') : T('public address')}${d.host.net ? ` · ${T('network')} <b>${esc(d.host.net)}</b>` : ''}</div></div><button class="btn x" id="dx">${T('Close')}</button></header>
    <div class="dk"><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4>${T('Traffic')} · ${rangeLabel()}</h4><div class="chart short" id="cHost"></div></div>
    <div><h4>${T('Services')}</h4><div class="tagrow">${d.services.rows.map(g => `<span class="tag">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>${T('Protocols')}</h4><div class="tagrow">${d.ports.rows.map(g => `<span class="tag mono">${esc(dv(g.k))} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>${T('Where it goes')}</h4><div class="blist">${d.dests.rows.map(g => `<div class="brow" style="cursor:default"><span class="n"><span class="idot ext"></span>${esc(g.k)} <span class="nat">${esc([g.service, g.city || ccName(g.country)].filter(Boolean).join(' · '))}</span></span><span class="t">${fmtB(tot(g))}</span><span class="p"></span></div>`).join('')}</div></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" id="dfilter">${T('Filter everything by this host')}</button>${netOf(ip) ? `<button class="btn" id="dnet" title="${esc(netOf(ip))}">${T('The whole network {net}', {net:'/' + netOf(ip).split('/')[1]})}</button>` : ''}${d.host.net ? `<button class="btn" id="dnetn">${T('Network «{name}»', {name:esc(d.host.net)})}</button>` : ''}</div>`;
  const before = charts.length; trendChart(document.getElementById('cHost'), d.series, true); hc = charts[before];
  document.getElementById('dx').onclick = close;
  document.getElementById('dfilter').onclick = () => { close(); addFilter('ip', ip); };
  const dnn = document.getElementById('dnetn'); if (dnn) dnn.onclick = () => { close(); addFilter('net', d.host.net); };
  const dn = document.getElementById('dnet'); if (dn) dn.onclick = () => { close(); addFilter(d.host.private ? 'ip' : 'dst', netOf(ip)); };
  document.getElementById('dx').focus();
}

// ===================== shell =====================
const VIEWS = {overview:vOverview, flows:vFlows, paths:vPaths, network:vNetwork, capacity:vCapacity, usage:vUsage, qos:vQos, talkers:vTalkers, apps:vApps, ports:vPorts, geo:vGeo, threats:vThreats, events:vEvents, settings:vSettings};
function renderShell(){
  document.getElementById('nav').innerHTML = NAV.filter(n => n[3] !== 'admin' || isAdmin()).map(([k, l, d]) => `<button data-view="${k}" ${state.view === k || (k === 'threats' && state.view === 'events') ? 'aria-current="page"' : ''}>${icon(d)}${l}</button>`).join('');
  document.querySelectorAll('#nav button').forEach(b => b.onclick = () => { state.view = b.dataset.view; state.sel = null; state.openFlow = null; render(); });
  // on narrow screens the menu is a scrolling row: keep the current page in sight
  const cur = document.querySelector('#nav [aria-current="page"]'), navEl = document.getElementById('nav');
  if (cur && navEl.scrollWidth > navEl.clientWidth) navEl.scrollLeft += cur.getBoundingClientRect().left - navEl.getBoundingClientRect().left - (navEl.clientWidth - cur.offsetWidth) / 2;
  document.getElementById('chips').innerHTML = (isCustom() ? `<span class="fchip period"><span class="k">${T('period')}:</span><button class="lnk" id="periodEdit" title="${T('Change the period')}">${esc(rangeLabel())}</button><button aria-label="${T('Back to')} ${esc(presetLabel(state.prevRange))}" title="${T('Back to')}: ${esc(presetLabel(state.prevRange))}" id="periodX">×</button></span>` : '') + state.filters.map((f, i) => `<span class="fchip ${f.neg ? 'neg' : ''}"><span class="k">${chipKey(f)}${f.neg ? ' ≠' : ':'}</span>${esc(f.k === 'device' ? devName(f.v) : (f.k === 'in_if' || f.k === 'out_if' || f.k === 'iface') && /^\d+$/.test(f.v) ? (ifLabel(pathDevice(), +f.v) === String(f.v) ? 'if ' + f.v : ifLabel(pathDevice(), +f.v)) : f.v)}<button aria-label="${T('Remove filter')}" data-i="${i}">×</button></span>`).join('')
    + (state.filters.length ? `<button class="lnk" id="clearF">${T('Clear all')}</button>` : '');
  document.querySelectorAll('#chips button[data-i]').forEach(b => b.onclick = () => { state.filters.splice(+b.dataset.i, 1); render(); });
  const cf = document.getElementById('clearF'); if (cf) cf.onclick = () => { state.filters = []; render(); };
  const px = document.getElementById('periodX'); if (px) px.onclick = () => { state.range = state.prevRange || '24h'; render(); };
  const pe = document.getElementById('periodEdit'); if (pe) pe.onclick = openPeriod;
  const ds = document.getElementById('devSel'), dfs = state.filters.filter(f => f.k === 'device' && !f.neg);
  ds.innerHTML = `<option value="">${T('All devices ({n})', {n: META.devices.length})}</option>` + (dfs.length > 1 ? `<option value="*" disabled>${T('{n} devices', {n: dfs.length})}</option>` : '')
    + META.devices.map(d => `<option value="${esc(d.ip)}">${esc(d.name)}${d.vendor ? ' · ' + esc(d.vendor) : ''}</option>`).join('');
  ds.value = dfs.length > 1 ? '*' : dfs.length ? dfs[0].v : '';
  editionBadge();
  const fv = document.getElementById('ftVer'); if (fv && META.version) fv.textContent = 'FlowTrack ' + META.version;
  const rs = document.getElementById('rangeSel');
  rs.querySelectorAll('option[data-x]').forEach(o => o.remove());
  if (isCustom()) rs.insertAdjacentHTML('beforeend', `<option data-x value="custom">${esc(rangeLabel())}</option>`);
  rs.insertAdjacentHTML('beforeend', `<option data-x value="pick">${T('Custom period…')}</option>`);
  rs.value = state.range;
  document.getElementById('trafSel').value = state.traffic;
}
function saveUrl(){ const p = new URLSearchParams({v:state.view, r:state.range}); if (state.view === 'settings') p.set('tab', state.setTab || 'general'); if (isCustom()) { p.set('from', state.from); p.set('to', state.to); } if (state.traffic !== 'internet') p.set('t', state.traffic); if (state.filters.length) p.set('f', JSON.stringify(state.filters)); if (state.view === 'talkers' && state.talkersBy === 'net') p.set('by', 'net'); history.replaceState(null, '', '#' + p); }
function loadUrl(){ try { const p = new URLSearchParams(location.hash.slice(1)); if (p.get('v') === 'devices' || p.get('v') === 'users') { state.view = 'settings'; state.setTab = p.get('v'); } else if (p.get('v') && VIEWS[p.get('v')]) state.view = p.get('v'); if (p.get('tab')) state.setTab = p.get('tab'); if (p.get('r') === 'custom') { const a = +p.get('from'), b = +p.get('to'); if (a > 0 && b - a >= 60) Object.assign(state, {range:'custom', from:a, to:b}); } else if (p.get('r')) state.range = p.get('r'); if (['internet', 'internal', 'all'].includes(p.get('t'))) state.traffic = p.get('t'); if (p.get('by') === 'net') state.talkersBy = 'net'; if (p.get('f')) { state.filters = []; JSON.parse(p.get('f')).forEach(putFilter); } } catch (e) {} }
// (1.8.4) unsaved changes: a settings form sets state.dirty; leaving it (another page, tab, filter …) asks first
const SHOWN_KEYS = ['view', 'setTab', 'filters', 'range', 'from', 'to', 'traffic', 'prevRange'];
let SHOWN = null;
function dirtyGuard(collect){ let snap = null; const now = () => { try { return JSON.stringify(collect()); } catch (e) { return null; } };
  state.dirty = () => snap !== null && now() !== null && now() !== snap;
  return () => { snap = now(); }; }
window.addEventListener('beforeunload', e => { if (state.dirty && state.dirty()) { e.preventDefault(); e.returnValue = ''; } });
function render(){ if (state.view === 'devices' || state.view === 'users') { state.setTab = state.view; state.view = 'settings'; }
  if (state.dirty && SHOWN && state.dirty()) {
    if (!confirm(T('Leave without saving? The changes on this page are lost.'))) { SHOWN_KEYS.forEach(k => { state[k] = SHOWN[k]; }); renderShell(); saveUrl(); return; } }
  state.dirty = null; SHOWN = Object.fromEntries(SHOWN_KEYS.map(k => [k, Array.isArray(state[k]) ? state[k].slice() : state[k]]));
  renderSeq++;
  PAGE_ID = Math.random().toString(36).slice(2, 12);     // a new view: the server cancels what the old one still runs
  waitReset();
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
// ===================== the search box: filters typed, with a guide (1.8.6) =====================
// Typed: key:value (-key:value leaves out), or a bare value whose kind is guessed (an address, a network, AS…, a
// country code, else a service). On focus a panel lists every filter with an example; while typing it suggests what
// the word can be (↑ ↓ to pick, Enter or Tab to take) and says what is wrong with a value before it is applied.
const q = document.getElementById('q');
const DSCP_NAME = n => Object.keys(DSCP_BY_NAME).find(k => DSCP_BY_NAME[k] === n && !['BE', 'DEFAULT'].includes(k)) || `DSCP ${n}`;
const DSCP_BY_NAME = {BE:0, DEFAULT:0, CS0:0, CS1:8, AF11:10, AF12:12, AF13:14, CS2:16, AF21:18, AF22:20, AF23:22, CS3:24, AF31:26, AF32:28, AF33:30, CS4:32, AF41:34, AF42:36, AF43:38, CS5:40, VA:44, EF:46, CS6:48, CS7:56};
const QHELP = () => [
  [T('Who'), [['ip', T('inside host or network'), '10.0.0.5 · 172.16.0.0/24'], ['net', T('named network'), (META.networks || []).slice(0, 2).map(n => netTyped(n.name)).join(' · ') || T('Office')], ['dst', T('outside address or network'), '8.8.8.8 · 203.0.113.0/24'],
    ['asn', T('network owner: AS number or name'), 'AS15169 · Google'], ['country', T('country: two letters'), 'US · UA'], ['city', T('city'), 'Kyiv']]],
  [T('What'), [['service', T('service by address'), 'Telegram · YouTube'], ['l7', T('protocol by port'), 'HTTPS · DNS'], ['port', T('port of the server'), '443 · 3389'],
    ['proto', T('L4 protocol number'), T('6 = TCP · 17 = UDP · 1 = ICMP')], ['dscp', T('QoS class: name or number'), 'EF · AF41 · 46']]],
  [T('Where'), [['device', T('device: name or address'), (META.devices && META.devices[0] || {}).name || 'fw-main'], ['iface', T('interface: name or number, in or out'), 'wan'],
    ['in_if', T('input interface number'), '5'], ['out_if', T('output interface number'), '1'], ['dir', T('direction: up · down · internal'), 'up']]]];
const QKEY_INFO = () => Object.fromEntries(QHELP().flatMap(([, rows]) => rows.map(r => [r[0], r])));
// (1.8.7) a named network as typed: spaces of its name as _ (a word of the box has none), any case
const netTyped = name => name.replace(/ /g, '_');
const netFind = v => { const w = v.toLowerCase(); return (META.networks || []).find(n => n.name.toLowerCase() === w || n.name.toLowerCase() === w.replace(/_/g, ' ')); };
const netNames = () => [...new Set((META.networks || []).map(n => n.name))];
const isPrivate = v => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd][0-9a-f]{2}:)/i.test(v);
// an address or a network as typed -> {ok, v (normalised), net, msg}
function addrCheck(v){
  const [a, pre, more] = v.split('/');
  if (more !== undefined) return {ok:false, msg:T('Not an address or network: {v}', {v})};
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) {
    const o = a.split('.').map(Number); if (o.some(x => x > 255)) return {ok:false, msg:T('Not an address or network: {v}', {v})};
    if (pre === undefined) return {ok:true, v:a};
    if (!/^\d{1,2}$/.test(pre) || +pre > 32) return {ok:false, msg:T('A network mask is /0 … /32: {v}', {v})};
    const n = ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3], m = +pre ? (0xffffffff << (32 - pre)) >>> 0 : 0, b = (n & m) >>> 0;
    const net = [b >>> 24, (b >>> 16) & 255, (b >>> 8) & 255, b & 255].join('.') + '/' + pre;
    return {ok:true, v:net, net:true, size:2 ** (32 - pre)};
  }
  if (a.includes(':') && /^[0-9a-f:.]+$/i.test(a) && (a.match(/::/g) || []).length <= 1) {
    if (pre === undefined) return {ok:true, v:a.toLowerCase()};
    if (!/^\d{1,3}$/.test(pre) || +pre > 128) return {ok:false, msg:T('A network mask is /0 … /128: {v}', {v})};
    return {ok:true, v:a.toLowerCase() + '/' + pre, net:true};
  }
  return {ok:false, msg:T('Not an address or network: {v}', {v})};
}
const netOf = ip => { const c = addrCheck(ip + (ip.includes(':') ? '/64' : '/24')); return c.ok ? c.v : ''; };
const chipKey = f => (f.k === 'ip' || f.k === 'dst') && String(f.v).includes('/') ? (f.k === 'ip' ? T('network') : T('ext. network')) : FILTER_LABEL[f.k] || f.k;
// one typed word -> a filter, or an error to show
function qParse(t){
  const neg = t.startsWith('-'); if (neg) t = t.slice(1); const i = t.indexOf(':');
  const key = i > 0 ? t.slice(0, i).toLowerCase() : '';
  if (key && FILTER_KEYS.includes(key) && t.slice(i + 1)) { let v = t.slice(i + 1);
    if (key === 'device') { const d = (META.devices || []).find(x => x.ip === v || (x.name || '').toLowerCase() === v.toLowerCase()); if (d) v = d.ip; }   // by name too
    if (key === 'ip' || key === 'dst') { const c = addrCheck(v); if (!c.ok) return {err:c.msg}; v = c.v; }
    if (key === 'net') { const n = netFind(v); if (!n) return {err:(META.networks || []).length ? T('No network named {v}: name networks in Settings → Flow configuration', {v}) : T('No named networks yet: name them in Settings → Flow configuration')}; v = n.name; }
    if (['port', 'proto', 'in_if', 'out_if'].includes(key) && !/^\d+$/.test(v)) return {err:T('{key} takes a number: {v}', {key, v})};
    if (key === 'iface' && !/^\d+$/.test(v) && !/^[\w.\/:-]{1,60}$/.test(v)) return {err:T('{key} takes a number or a name: {v}', {key, v})};      // (1.13.0) iface:wan
    if (key === 'dscp') { const n = /^\d+$/.test(v) ? +v : DSCP_BY_NAME[v.toUpperCase()]; if (n == null || (n > 63 && n !== 255)) return {err:T('Not a DSCP class: {v} (EF, AF41, CS1 … or 0–63)', {v})}; v = /^\d+$/.test(v) ? v : v.toUpperCase(); }      // (1.16.0)
    return {f:{k:key, v, neg}}; }
  if (/^[\d.]+(\/\d+)?$/.test(t) && t.split('.').length === 4 || /^[0-9a-f]*:[0-9a-f:.]*(\/\d+)?$/i.test(t) && !FILTER_KEYS.includes(key)) { const c = addrCheck(t); if (!c.ok) return {err:c.msg};
    return {f:{k:isPrivate(c.v) ? 'ip' : 'dst', v:c.v, neg}}; }
  if (/^AS\d+$/i.test(t)) return {f:{k:'asn', v:t, neg}};
  if (!key && netFind(t)) return {f:{k:'net', v:netFind(t).name, neg}};
  if (/^[A-Za-z]{2}$/.test(t)) return {f:{k:'country', v:t.toUpperCase(), neg}};
  return t ? {f:{k:'service', v:t, neg}} : {};
}
function qApply(){
  const bad = []; let n = 0;
  for (const t of q.value.trim().split(/\s+/).filter(Boolean)) { const r = qParse(t); if (r.err) bad.push(t); else if (r.f) { putFilter(r.f, true); n++; } }
  q.value = bad.join(' ');            // what could not be applied stays, with the reason in the guide
  if (n) render();
  if (n && !bad.length) qBox.hidden = true; else qGuide();      // applied: the page shows again; a click or a key brings the guide back
}
// the guide under the search box
let qSel = -1, qItems = [];
const qBox = (() => { const el = document.createElement('div'); el.id = 'qGuide'; el.className = 'qguide'; el.hidden = true; el.setAttribute('role', 'listbox');
  q.closest('.search').append(el); q.setAttribute('aria-controls', 'qGuide'); q.setAttribute('aria-autocomplete', 'list');
  el.addEventListener('mousedown', e => e.preventDefault());        // keep the focus in the box
  el.addEventListener('click', e => { const b = e.target.closest('[data-qi]'); if (b) qTake(qItems[+b.dataset.qi]); });
  return el; })();
function qWord(){ const m = q.value.match(/(\S*)$/); return m ? m[1] : ''; }
function qSuggest(word){
  const neg = word.startsWith('-'), w = neg ? word.slice(1) : word, pre = neg ? '-' : '', info = QKEY_INFO(), out = [];
  const i = w.indexOf(':'), key = i > 0 ? w.slice(0, i).toLowerCase() : '', val = i > 0 ? w.slice(i + 1) : '';
  if (key && info[key]) {                               // key typed: its help and values
    if (key === 'device') (META.devices || []).filter(d => !val || (d.name || '').toLowerCase().includes(val.toLowerCase()) || d.ip.startsWith(val)).slice(0, 6)
      .forEach(d => out.push({text:`${pre}device:${d.name}`, label:d.name, note:d.ip, apply:true}));
    else if (key === 'dir') [['up', T('to the internet')], ['down', T('from the internet')], ['internal', T('between inside hosts')]].filter(([v]) => v.startsWith(val))
      .forEach(([v, l]) => out.push({text:`${pre}dir:${v}`, label:`dir:${v}`, note:l, apply:true}));
    else if (key === 'net') netNames().filter(n => !val || n.toLowerCase().includes(val.replace(/_/g, ' ').toLowerCase())).slice(0, 8)
      .forEach(n => out.push({text:`${pre}net:${netTyped(n)}`, label:`${pre}net:${netTyped(n)}`, note:(META.networks || []).filter(x => x.name === n).map(x => x.net).join(', '), apply:true}));
    if (key === 'net' && !out.length && (val || !netNames().length)) out.push({err:qParse(`net:${val || '?'}`).err});
    else if (key === 'proto') [['6', 'TCP'], ['17', 'UDP'], ['1', 'ICMP'], ['47', 'GRE'], ['50', 'ESP']].filter(([v]) => v.startsWith(val))
      .forEach(([v, l]) => out.push({text:`${pre}proto:${v}`, label:`proto:${v}`, note:l, apply:true}));
    else if (val) { const r = qParse(word); if (r.err) out.push({err:r.err});
      else if (r.f) out.push({text:word, label:`${pre}${key}:${r.f.v}`, note:r.f.v.includes('/') ? T('network') + (addrCheck(r.f.v).size ? ' · ' + T('{n} addresses', {n:addrCheck(r.f.v).size.toLocaleString(LOC)}) : '') : info[key][1], apply:true}); }
    if (!val) out.push({text:'', label:`${key}:`, note:`${info[key][1]} · ${T('e.g.')} ${info[key][2]}`, hint:true});
    return out;
  }
  if (!w) return null;                                  // empty: the whole guide
  Object.keys(info).filter(k => k.startsWith(w.toLowerCase()) && k !== w.toLowerCase()).forEach(k => out.push({text:`${pre}${k}:`, label:`${pre}${k}:`, note:info[k][1], key:true}));
  const r = qParse(word);
  if (r.err) out.push({err:r.err});
  else if (r.f) {
    const addr = r.f.k === 'ip' || r.f.k === 'dst', alt = addr ? (r.f.k === 'ip' ? 'dst' : 'ip') : null;
    const note = f => f.v.includes('/') ? (f.k === 'ip' ? T('inside network') : T('outside network')) : info[f.k][1];
    const tv = r.f.k === 'net' ? netTyped(r.f.v) : r.f.v;
    out.push({text:`${pre}${r.f.k}:${tv}`, label:`${pre}${r.f.k}:${tv}`, note:note(r.f), apply:true});
    if (alt) out.push({text:`${pre}${alt}:${r.f.v}`, label:`${pre}${alt}:${r.f.v}`, note:note({k:alt, v:r.f.v}), apply:true});
    if (r.f.k === 'service') { netNames().filter(n => n.toLowerCase().includes(w.replace(/_/g, ' ').toLowerCase())).slice(0, 3).forEach(n => out.push({text:`${pre}net:${netTyped(n)}`, label:`${pre}net:${netTyped(n)}`, note:T('named network'), apply:true}));
      (META.devices || []).filter(d => (d.name || '').toLowerCase().includes(w.toLowerCase())).slice(0, 3).forEach(d => out.push({text:`${pre}device:${d.name}`, label:`${pre}device:${d.name}`, note:T('device'), apply:true}));
      ['l7', 'city', 'asn'].forEach(k => out.push({text:`${pre}${k}:${w}`, label:`${pre}${k}:${w}`, note:info[k][1], apply:true})); }
  }
  return out;
}
// the guide's HTML for a list of suggestions (null: every key with an example); fills `items` with what can be taken
function guideHtml(list, items, tips){
  if (list === null) return `<div class="qgrid">${QHELP().map(([g, rows]) => `<div><h5>${g}</h5>${rows.map(([k, d, ex]) => { items.push({text:`${k}:`, key:true});
    return `<button type="button" class="qrow" data-qi="${items.length - 1}" role="option"><code>${k}:</code><span>${d}<small>${esc(ex)}</small></span></button>`; }).join('')}</div>`).join('')}</div>
    <p class="qtips">${tips}</p>`;
  return list.map(it => { if (it.err) return `<div class="qerr" role="alert">${esc(it.err)}</div>`;
    items.push(it); return `<button type="button" class="qrow${it.hint ? ' hint' : ''}" data-qi="${items.length - 1}" role="option"><code>${esc(it.label)}</code><span>${esc(it.note || '')}</span></button>`; }).join('');
}
function qGuide(){
  if (document.activeElement !== q) { qBox.hidden = true; return; }
  const word = qWord(), list = qSuggest(word);
  qItems = [];
  if (list && !list.length) { qBox.hidden = true; return; }
  qBox.innerHTML = guideHtml(list, qItems, T('<b>-</b>key:value leaves out · two values of one key: either of them · <b>Enter</b> applies · <b>Backspace</b> in an empty box removes the last filter · <b>/</b> opens the search'));
  qBox.hidden = false; qSel = Math.min(qSel, qItems.length - 1); qMark();
}
// (1.11.1) the same guide for the filter fields of forms (reports): a suggestion completes the word — nothing is
// applied — and a space follows a complete filter, so the next one can be typed; every word's error shows at once.
// It floats over the window (fixed, on <body>: a scrolling modal would cut or stretch it), under the field or above
// it when there is more room there, and follows the field when the window scrolls.
function filterGuide(input){
  const box = document.createElement('div'), items = [];
  let sel = -1;
  box.className = 'qguide float'; box.hidden = true; box.setAttribute('role', 'listbox'); box.id = `${input.id}Guide`;
  input.setAttribute('aria-controls', box.id);
  document.body.append(box);
  const place = () => {
    if (box.hidden) return;
    const r = input.getBoundingClientRect(), below = innerHeight - r.bottom - 12, above = r.top - 12, w = Math.min(Math.max(r.width, 320), innerWidth - 16);
    box.style.left = `${Math.max(8, Math.min(r.left, innerWidth - w - 8))}px`; box.style.width = `${w}px`;
    // down, over what follows the field; up only when there is little room below
    if (below >= 220 || below >= above) { box.style.top = `${r.bottom + 6}px`; box.style.bottom = 'auto'; box.style.maxHeight = `${Math.max(120, below - 6)}px`; }
    else { box.style.top = 'auto'; box.style.bottom = `${innerHeight - r.top + 6}px`; box.style.maxHeight = `${Math.max(120, above - 6)}px`; }
  };
  addEventListener('scroll', place, true); addEventListener('resize', place);
  const gone = new MutationObserver(() => { if (!input.isConnected) { box.remove(); gone.disconnect(); removeEventListener('scroll', place, true); removeEventListener('resize', place); } });
  gone.observe(document.body, {childList:true, subtree:true});
  input.setAttribute('aria-autocomplete', 'list'); input.setAttribute('autocomplete', 'off'); input.spellcheck = false;
  const word = () => (input.value.slice(0, input.selectionStart ?? input.value.length).match(/(\S*)$/) || ['', ''])[1];
  const mark = () => box.querySelectorAll('[data-qi]').forEach(b => { const on = +b.dataset.qi === sel; b.classList.toggle('on', on); b.setAttribute('aria-selected', String(on)); if (on) b.scrollIntoView({block:'nearest'}); });
  const show = () => {
    if (document.activeElement !== input) { box.hidden = true; return; }
    const w = word(), list = qSuggest(w);
    // the words before this one: what is wrong with them, so the form is not refused later without a reason
    const errs = input.value.trim().split(/\s+/).filter(t => t && t !== w).map(t => [t, qParse(t).err]).filter(([, e]) => e);
    items.length = 0;
    const html = errs.map(([t, e]) => `<div class="qerr" role="alert"><code>${esc(t)}</code> — ${esc(e)}</div>`).join('') + (list && !list.length ? '' :
      guideHtml(list, items, T('words separated by spaces · <b>-</b>key:value leaves out · two values of one key: either of them · <b>↑ ↓</b> and <b>Tab</b> take a suggestion')));
    box.innerHTML = html; box.hidden = !html; sel = Math.min(sel, items.length - 1); place(); mark();
  };
  const take = it => {
    if (!it || it.hint) return;
    const at = input.selectionStart ?? input.value.length, before = input.value.slice(0, at).replace(/(\S*)$/, it.text), after = input.value.slice(at).replace(/^\S*/, '');
    const add = it.key ? '' : (after.startsWith(' ') ? '' : ' ');
    input.value = before + add + after; const c = (before + add).length; input.setSelectionRange(c, c);
    sel = -1; input.focus(); show(); input.dispatchEvent(new Event('change'));
  };
  box.addEventListener('mousedown', e => e.preventDefault());
  box.addEventListener('click', e => { const b = e.target.closest('[data-qi]'); if (b) take(items[+b.dataset.qi]); });
  input.addEventListener('focus', () => { sel = -1; show(); });
  input.addEventListener('click', show);
  input.addEventListener('input', () => { sel = -1; show(); });
  input.addEventListener('blur', () => { box.hidden = true; });
  input.addEventListener('keydown', e => {
    if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && !box.hidden && items.length) { e.preventDefault();
      sel = (sel + (e.key === 'ArrowDown' ? 1 : items.length - 1 + (sel < 0 ? 1 : 0))) % items.length; mark(); }
    else if ((e.key === 'Tab' && word() || e.key === 'Enter' && sel >= 0) && !box.hidden && items.length) { e.preventDefault(); take(items[Math.max(0, sel)]); }
    else if (e.key === 'Escape' && !box.hidden) { e.stopPropagation(); box.hidden = true; }      // the guide closes, not the window
  });
}
function qMark(){ qBox.querySelectorAll('[data-qi]').forEach(b => { const on = +b.dataset.qi === qSel; b.classList.toggle('on', on); b.setAttribute('aria-selected', String(on)); if (on) b.scrollIntoView({block:'nearest'}); }); }
function qTake(it){
  if (!it) return;
  if (it.hint) { q.focus(); return; }
  q.value = q.value.replace(/(\S*)$/, it.text); qSel = -1;
  if (it.apply) qApply(); else { q.focus(); qGuide(); }
}
q.addEventListener('focus', () => { qSel = -1; qGuide(); });
q.addEventListener('click', () => { if (qBox.hidden) qGuide(); });
q.addEventListener('blur', () => { qBox.hidden = true; });
q.addEventListener('input', () => { qSel = -1; qGuide(); });
q.addEventListener('keydown', e => {
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { if (qBox.hidden || !qItems.length) return; e.preventDefault();
    qSel = (qSel + (e.key === 'ArrowDown' ? 1 : qItems.length - 1 + (qSel < 0 ? 1 : 0))) % qItems.length; qMark(); }
  else if (e.key === 'Tab' && !qBox.hidden && qItems.length && qWord()) { e.preventDefault(); qTake(qItems[Math.max(0, qSel)]); }
  else if (e.key === 'Enter') { e.preventDefault(); if (qSel >= 0 && !qBox.hidden) qTake(qItems[qSel]); else qApply(); }
  else if (e.key === 'Escape') { qBox.hidden = true; q.blur(); }
  else if (e.key === 'Backspace' && !q.value && state.filters.length) { state.filters.pop(); render(); }
});
document.addEventListener('keydown', e => { if (e.key === '/' && document.activeElement !== q && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); q.focus(); } });
document.getElementById('bell').onclick = () => { state.view = 'threats'; render(); };
document.getElementById('repBtn').onclick = openPeriodReport;      // (1.10.0) a PDF of the period and filters on screen

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
    const sv = ((await fetch('api/alerts?limit=0').then(r => r.json())).stats || {}).sev || {};      // (1.17.0) the counts, not every event
    document.getElementById('bellBadge').hidden = !(sv.crit || sv.warn);
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
