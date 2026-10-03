'use strict';
// FlowTrack web UI — talks to /api/* (see api.py). No build step.

// ===================== state, api =====================
const state = {view:'overview', range:'24h', filters:[], heroMode:'graph', metric:'flows', scale:'sqrt', flowLive:true, sel:null, sort:{col:'tot', dir:-1}, openFlow:null, ifDev:null, ifEdit:null};
let META = {devices:[]}, ME = null;
const isAdmin = () => ME && ME.role === 'admin';
const FILTER_KEYS = ['ip', 'dst', 'service', 'l7', 'country', 'city', 'port', 'device', 'asn', 'dir', 'proto'];
const FILTER_LABEL = {ip:'хост', dst:'зовн. IP', service:'сервіс', l7:'протокол', country:'країна', city:'місто', port:'порт', device:'пристрій', asn:'ASN', dir:'напрямок', proto:'L4'};
let renderSeq = 0;

async function api(path, params = {}, extraFilters = []){
  const qs = new URLSearchParams({range:state.range, f:JSON.stringify([...state.filters, ...extraFilters]), ...params});
  const r = await fetch(`api/${path}?${qs}`);
  if (r.status === 401) { showLogin('Сесія завершилась — увійдіть знову'); throw new Error('потрібен вхід'); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
async function apiPost(path, body){
  const r = await fetch(`api/${path}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body || {})});
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== 'login') { showLogin('Сесія завершилась — увійдіть знову'); throw new Error('потрібен вхід'); }
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
const fmtR = bps => { bps = +bps || 0; const u = ['біт/с','Кбіт/с','Мбіт/с','Гбіт/с']; let i = 0; while (bps >= 1000 && i < 3) { bps /= 1000; i++; } return bps.toFixed(bps < 10 && i > 0 ? 1 : 0) + ' ' + u[i]; };
const fmtN = n => { n = +n || 0; return n >= 1e6 ? (n / 1e6).toFixed(2) + ' M' : n >= 1e4 ? (n / 1e3).toFixed(1) + ' K' : Math.round(n).toLocaleString('uk-UA'); };
const hhmm = t => new Date(t * 1000).toLocaleTimeString('uk-UA', {hour:'2-digit', minute:'2-digit'});
const hms = t => new Date(t * 1000).toLocaleTimeString('uk-UA', {hour:'2-digit', minute:'2-digit', second:'2-digit'});
const dmy = t => new Date(t * 1000).toLocaleDateString('uk-UA', {day:'numeric', month:'2-digit'});
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let regionNames; try { regionNames = new Intl.DisplayNames(['uk'], {type:'region'}); } catch (e) { regionNames = null; }
const ccName = cc => { if (!cc) return '—'; try { return regionNames ? regionNames.of(cc) : cc; } catch (e) { return cc; } };
const PAL = ['#2F7BFF','#FF4FA0','#FF9F43','#27D3F5','#8B5CFF','#2EE59D','#FFD166','#6E7FA6'];
const C = {down:'#27D3F5', up:'#FF9F43', int:'#8B5CFF', ext:'#2EE59D', other:'#6E7FA6', ink:'#EAF0FF', ink2:'#A9B7D9', ink3:'#6E7FA6', hair:'rgba(120,160,255,.12)'};
const hexA = (hex, a) => { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`; };
const pct = (v, all) => all ? (100 * v / all).toFixed(1) + '%' : '—';
const tot = r => (+r.up || 0) + (+r.dn || 0);
const colorCache = new Map();
const keyColor = k => { if (!colorCache.has(k)) colorCache.set(k, PAL[colorCache.size % (PAL.length - 1)]); return colorCache.get(k); };
const rangeSecs = () => ({'1h':3600, '6h':21600, '24h':86400, '7d':604800, '30d':2592000})[state.range];
const rangeLabel = () => ({'1h':'остання година', '6h':'останні 6 годин', '24h':'останні 24 години', '7d':'останні 7 днів', '30d':'останні 30 днів'})[state.range];
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
const axisX = () => ({type:'time', axisLine:{lineStyle:{color:C.hair}}, axisTick:{show:false}, splitLine:{show:false},
  axisLabel:{color:C.ink3, fontFamily:'JetBrains Mono', fontSize:11, hideOverlap:true, formatter:v => rangeSecs() > 86400 ? dmy(v / 1000) : hhmm(v / 1000)}});
const axisY = fmt => ({type:'value', splitLine:{lineStyle:{color:C.hair}}, axisLabel:{color:C.ink3, fontFamily:'JetBrains Mono', fontSize:11, formatter:v => String(fmt(v)).replace(/\.0 /, ' ')}});
const tipBase = () => ({backgroundColor:'rgba(10,20,46,.94)', borderColor:'rgba(130,175,255,.45)', textStyle:{color:C.ink, fontFamily:'Manrope', fontSize:12}, extraCssText:'border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.4)'});
// fill missing buckets with zeros so lines drop to 0 instead of interpolating across gaps
function grid(series){
  const step = series.step, end = Math.floor(Date.now() / 1000 / step) * step, start = end - series.range;
  const ts = []; for (let t = Math.ceil(start / step) * step; t <= end; t += step) ts.push(t);
  return {ts, step};
}
function trendChart(el, series, compact){
  const {ts, step} = grid(series), m = new Map(series.rows.map(r => [r[0], r]));
  const area = c => ({color:new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset:0, color:hexA(c, .35)}, {offset:1, color:hexA(c, .02)}])});
  const c = mkChart(el);
  c.setOption({animation:false, grid:compact ? {left:12, right:8, top:8, bottom:4, containLabel:true} : {left:14, right:10, top:30, bottom:4, containLabel:true},
    legend:{show:!compact, top:0, right:0, icon:'roundRect', itemWidth:14, itemHeight:6, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
    tooltip:{...tipBase(), trigger:'axis', valueFormatter:v => fmtR(v)}, xAxis:axisX(), yAxis:axisY(v => fmtR(v)),
    series:[
      {name:'↓ Download', type:'line', smooth:.35, showSymbol:false, lineStyle:{width:2, color:C.down, shadowBlur:12, shadowColor:C.down}, itemStyle:{color:C.down}, areaStyle:area(C.down), data:ts.map(t => [t * 1000, ((m.get(t) || [])[1] || 0) * 8 / step])},
      {name:'↑ Upload', type:'line', smooth:.35, showSymbol:false, lineStyle:{width:2, color:C.up, shadowBlur:12, shadowColor:C.up}, itemStyle:{color:C.up}, areaStyle:area(C.up), data:ts.map(t => [t * 1000, ((m.get(t) || [])[2] || 0) * 8 / step])}]});
  return c;
}
function stackChart(el, series, label, onPick){
  const {ts, step} = grid(series), keys = new Map();
  for (const [t, k, b] of series.rows) { if (!keys.has(k)) keys.set(k, new Map()); keys.get(k).set(t, b); }
  const order = [...keys.keys()].sort((a, b) => (a === '__other') - (b === '__other'));
  const c = mkChart(el);
  c.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true}, legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
    tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(), yAxis:axisY(v => fmtR(v)),
    series:order.map(k => { const col = k === '__other' ? C.other : keyColor(k); return {name:k === '__other' ? 'інше' : label(k), id:k, type:'line', stack:'a', smooth:.25, showSymbol:false,
      lineStyle:{width:1.4, color:col}, itemStyle:{color:col}, areaStyle:{opacity:k === '__other' ? .2 : .35}, emphasis:{focus:'series'}, data:ts.map(t => [t * 1000, (keys.get(k).get(t) || 0) * 8 / step])}; })});
  c.on('click', p => p.seriesId !== '__other' && onPick && onPick(p.seriesId));
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
const metricFmt = v => state.metric === 'bytes' ? fmtB(v) : state.metric === 'packets' ? fmtN(v) + ' пак.' : fmtN(v) + ' flows';
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
    if (side === 'L') { if (k === '__other') return ['Інші внутрішні', 'решта адрес']; const h = info.L.get(k) || {ip:k}; return [h.name || k, h.name ? k : (h.private ? 'внутрішня' : 'публічна (self)')]; }
    if (k === '__other') return ['Інші зовнішні', 'решта адрес']; const r = info.R.get(k) || {}; return [k, [r.service, r.city || ccName(r.country)].filter(Boolean).join(' · ')];
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
    ctx.textAlign = 'left'; ctx.fillText('Внутрішні адреси', 2, L.headH / 2 - 2); ctx.textAlign = 'right'; ctx.fillText('Зовнішні адреси', W - 2, L.headH / 2 - 2);
    if (!left.length) { ctx.textAlign = 'center'; ctx.fillStyle = C.ink3; ctx.fillText('Немає трафіку під цей фільтр за вибраний період', W / 2, H / 2); return; }
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
      html = `<b class="mono">${esc(l1)} ⇄ ${esc(r1)}</b><br><span style="color:${C.ink2}">${esc(r2)}</span><br><span style="color:${C.up}">↑ upload ${metricFmt(v.up)}${rate(v.up)}</span><br><span style="color:${C.down}">↓ download ${metricFmt(v.dn)}${rate(v.dn)}</span><br><span style="color:${C.ink3}">клік — виділити</span>`;
    } else {
      const [a, b] = nodeLabel(h.side, h.k), c = cards.find(x => x.side === h.side && x.k === h.k);
      html = `<b class="mono">${esc(a)}</b><br><span style="color:${C.ink2}">${esc(b)}</span><br>${metricFmt(c ? c.val : 0)}<br><span style="color:${C.ink3}">клік — виділити зв’язки · Shift+клік — фільтр</span>`;
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
function flatMap(el, geo, onConn){
  if (!echarts.getMap('world')) { el.innerHTML = '<div class="empty">Не вдалося завантажити контури карти світу</div>'; return; }
  const c = mkChart(el);
  const rows = geo.rows, rmax = rows.length ? tot(rows[0]) : 1;
  const byCountry = new Map(); for (const r of rows) byCountry.set(r.country, (byCountry.get(r.country) || 0) + tot(r));
  const cmax = Math.max(1, ...byCountry.values());
  let nameEn; try { nameEn = new Intl.DisplayNames(['en'], {type:'region'}); } catch (e) {}
  const EN_FIX = {'United States':'United States', 'Czechia':'Czech Rep.', 'Bosnia & Herzegovina':'Bosnia and Herz.', 'South Korea':'Korea', 'Dominican Republic':'Dominican Rep.'};
  const regions = [...byCountry].map(([cc, v]) => { let n = nameEn ? nameEn.of(cc) : cc; n = EN_FIX[n] || n; return {name:n, itemStyle:{areaColor:`rgba(47,123,255,${(0.18 + 0.42 * v / cmax).toFixed(2)})`}}; });
  const sites = META.devices.filter(d => d.lat != null).map(d => ({name:d.city || d.name, full:`${d.city || ''}${d.country ? ', ' + ccName(d.country) : ''} · ${d.name}`, value:[d.lon, d.lat, 1]}));
  const lbl = (pos, size) => ({show:true, position:pos, distance:7, color:'#F2F6FF', fontFamily:'Manrope', fontWeight:700, fontSize:size, textBorderColor:'rgba(4,10,28,.95)', textBorderWidth:3.5, formatter:'{b}'});
  const cities = new Map(); for (const r of rows) { const k = r.city + '|' + r.country; const g = cities.get(k) || {name:r.city || ccName(r.country), cc:r.country, lon:r.lo, lat:r.la, v:0}; g.v += tot(r); cities.set(k, g); }
  c.setOption({animation:false, tooltip:{...tipBase(), trigger:'item', formatter:p => p.seriesType === 'lines' ? '' : p.componentType === 'geo' ? esc(p.name) : `${esc(p.data && p.data.full || p.name)}${p.data && p.data.v ? '<br><b>' + fmtB(p.data.v) + '</b>' : ''}`},
    geo:{map:'world', roam:true, zoom:1.25, center:[15, 35], scaleLimit:{min:1, max:10}, label:{show:false},
      itemStyle:{areaColor:'rgba(30,56,120,.38)', borderColor:'rgba(110,160,255,.38)', borderWidth:.5}, emphasis:{label:{show:false}, itemStyle:{areaColor:'rgba(47,123,255,.55)'}}, regions},
    series:[
      {id:'agg', type:'lines', coordinateSystem:'geo', silent:true, zlevel:1, lineStyle:{curveness:.28},
        data:rows.map(r => { const s = siteGeo(r.exporter); return s && {coords:[s, [r.lo, r.la]], lineStyle:{width:.6 + 3.4 * tot(r) / rmax, opacity:.22, color:r.up > r.dn ? C.up : C.down}}; }).filter(Boolean)},
      {id:'live', type:'lines', coordinateSystem:'geo', zlevel:2, silent:true, effect:{show:!reduceMotion, period:2.4, trailLength:0, symbol:'circle', symbolSize:5}, lineStyle:{width:1.4, opacity:.75, curveness:.28}, data:[]},
      {id:'remotes', type:'scatter', coordinateSystem:'geo', zlevel:3, symbolSize:d => 5 + 12 * Math.sqrt(d[2] / rmax), itemStyle:{color:C.ext, shadowBlur:12, shadowColor:C.ext},
        label:lbl('right', 12), labelLayout:{hideOverlap:true}, emphasis:{label:{show:true}},
        data:[...cities.values()].map(g => { const onSite = META.devices.some(d => d.lat != null && Math.abs(d.lat - g.lat) < 0.6 && Math.abs(d.lon - g.lon) < 0.9);
          return {name:g.name, full:`${g.name}, ${ccName(g.cc)}`, value:[g.lon, g.lat, g.v], v:g.v, label:onSite ? {show:false} : undefined}; })},
      {id:'sites', type:'scatter', coordinateSystem:'geo', zlevel:4, symbolSize:12, itemStyle:{color:C.int, borderColor:'rgba(255,255,255,.85)', borderWidth:2, shadowBlur:10, shadowColor:C.int}, label:lbl('left', 13), data:sites},
    ]});
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
  poll(); every(4000, poll); every(reduceMotion ? 3000 : 1000, tick);
}
function globe(el, geo){
  if (!echarts.getMap('world') || !window['echarts-gl']) { el.innerHTML = '<div class="empty">3D-режим недоступний у цьому браузері</div>'; return; }
  try {
    const tex = echarts.init(document.createElement('canvas'), null, {width:2048, height:1024});
    tex.setOption({backgroundColor:'#071431', animation:false, geo:{map:'world', silent:true, left:0, top:0, right:0, bottom:0, boundingCoords:[[-180, 90], [180, -90]], itemStyle:{areaColor:'#123072', borderColor:'#4C93FF', borderWidth:1.2}}});
    const c = mkChart(el); onCleanup(() => tex.dispose());
    const rows = geo.rows.slice(0, 80);
    const cities = new Map(); for (const r of geo.rows.slice(0, 10)) cities.set(r.city, {name:r.city || ccName(r.country), value:[r.lo, r.la, 0]});
    c.setOption({globe:{baseTexture:tex, shading:'lambert', environment:'none', globeRadius:100, light:{ambient:{intensity:.55}, main:{intensity:1.1, alpha:30, beta:40}},
        atmosphere:{show:true, color:'#2F7BFF', glowPower:5, innerGlowPower:2}, viewControl:{autoRotate:!reduceMotion, autoRotateSpeed:4, autoRotateAfterStill:20, distance:112, minDistance:60, maxDistance:260, targetCoord:[25, 45]}},
      series:[
        {type:'lines3D', coordinateSystem:'globe', blendMode:'lighter', effect:{show:!reduceMotion, trailWidth:2.5, trailLength:.22, trailOpacity:1, constantSpeed:28}, lineStyle:{width:1.2, opacity:.35},
          data:rows.map(r => { const s = siteGeo(r.exporter); if (!s) return null; const up = r.up > r.dn; return {coords:up ? [s, [r.lo, r.la]] : [[r.lo, r.la], s], lineStyle:{color:up ? C.up : C.down}}; }).filter(Boolean)},
        {type:'scatter3D', coordinateSystem:'globe', blendMode:'lighter', symbolSize:10, itemStyle:{color:C.int}, label:{show:true, formatter:'{b}', textStyle:{color:'#F2F6FF', fontSize:13, fontWeight:'bold', fontFamily:'Manrope', backgroundColor:'rgba(4,10,28,.7)', padding:[3, 6], borderRadius:4}},
          data:META.devices.filter(d => d.lat != null).map(d => ({name:d.city || d.name, value:[d.lon, d.lat, 0]}))},
        {type:'scatter3D', coordinateSystem:'globe', blendMode:'lighter', symbolSize:7, itemStyle:{color:C.ext}, label:{show:true, formatter:'{b}', textStyle:{color:'#DDFBEF', fontSize:12, fontFamily:'Manrope', backgroundColor:'rgba(4,10,28,.6)', padding:[2, 5], borderRadius:4}}, data:[...cities.values()]},
      ]});
  } catch (e) { el.innerHTML = '<div class="empty">3D-режим недоступний: ' + esc(e.message) + '</div>'; }
}

// ===================== shared UI =====================
const NAV = [
  ['overview','Огляд','M3 9.5L9 4l6 5.5V15H3z'], ['flows','Потоки','M2 6c4 0 5 6 9 6h5M2 12c4 0 5-6 9-6h5'], ['talkers','Топ хостів','M6 7a2.5 2.5 0 1 0 0-.01M2 15c0-2.5 2-4 4-4s4 1.5 4 4M13 8a2 2 0 1 0 0-.01M11.5 15c.3-2 1.3-3 3-3'],
  ['apps','Сервіси','M3 3h5v5H3zM10 3h5v5h-5zM3 10h5v5H3zM10 10h5v5h-5z'], ['ports','Порти','M6 2v4M12 2v4M4 6h10v3a5 5 0 0 1-10 0zM9 14v3'], ['geo','Геолокація','M9 16s5-4.5 5-8.5A5 5 0 0 0 4 7.5C4 11.5 9 16 9 16zM9 9a1.6 1.6 0 1 0 0-.01'],
  ['threats','Події','M9 2l6 2.5V9c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V4.5z'], ['devices','Пристрої','M2 5h14v6H2zM5 8h.01M8 8h.01M6 14h6'],
  ['users','Користувачі','M6.5 7.5a2.5 2.5 0 1 0 0-.01M2 15c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4M12 4.5h4M14 2.5v4', 'admin'],
];
const navIcon = k => NAV.find(n => n[0] === k)[2];
const icon = (d, s = 18) => `<svg width="${s}" height="${s}" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${d}"/></svg>`;
const ICO = {pulse:'M2 9h3l2-5 3 10 2-5h4', nodes:'M9 3a2 2 0 1 0 0 .01M4 13a2 2 0 1 0 0 .01M14 13a2 2 0 1 0 0 .01M8 5l-3 6M10 5l3 6', ip:'M3 5h12v6H3zM6 14h6M7 8h.01M10 8h.01', grid:navIcon('apps'), flow:navIcon('flows'),
  globe:'M9 2a7 7 0 1 0 0 14A7 7 0 0 0 9 2zM2 9h14M9 2c2.5 2.5 2.5 11.5 0 14M9 2c-2.5 2.5-2.5 11.5 0 14', chart:'M2 15l4-6 3 3 5-8 2 2', conv:'M3 5h8l-2-2M15 13H7l2 2', list:'M3 5h12M3 9h12M3 13h8',
  users:navIcon('talkers'), shield:navIcon('threats'), dev:navIcon('devices'), pie:'M9 2v7h7A7 7 0 1 1 9 2z', search:'M8 8m-5 0a5 5 0 1 0 10 0a5 5 0 1 0-10 0M12 12l4 4'};
const ph = (ic, title, sub, right = '', big = false) => `<div class="ph"><div class="ttl"><span class="ico">${icon(ICO[ic] || ic)}</span><div><h2${big ? ' class="big"' : ''}>${title}</h2>${sub ? `<span class="sub">${sub}</span>` : ''}</div></div>${right ? `<div class="right">${right}</div>` : ''}</div>`;
const seg = (id, opts, val) => `<div class="seg" id="${id}" role="group">${opts.map(([v, l, tip]) => `<button data-v="${v}" aria-pressed="${v === val}"${tip ? ` title="${tip}"` : ''}>${l}</button>`).join('')}</div>`;
const wireSeg = (id, fn) => document.querySelectorAll(`#${id} button`).forEach(b => b.onclick = () => fn(b.dataset.v));
const hostCell = (ip, name) => `<span class="idot int"></span><b class="mono">${esc(name || ip)}</b>${name ? ` <span class="nat">${esc(ip)}</span>` : ''}`;
const svcBadge = name => { const c = keyColor(name); return `<span class="app-b"><i style="background:${hexA(c, .85)};box-shadow:0 0 8px ${hexA(c, .6)}">${esc((name || '?')[0])}</i>${esc(name)}</span>`; };
const fill = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; return el; };
const errBox = e => `<div class="err">Не вдалося завантажити: ${esc(e.message)}</div>`;
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
  : '<div class="empty">Немає трафіку під цей фільтр</div>';

// ===================== views =====================
async function kpiCards(){
  const [s, ser] = await Promise.all([api('summary'), api('series')]);
  // trend vs the previous equal period; until enough history exists, say since when data is collected and when the comparison appears
  const since = s.oldest ? (Date.now() / 1000 - s.oldest > 86400 ? dmy(s.oldest) + ' ' : '') + hhmm(s.oldest) : '';
  const ready = s.oldest ? s.oldest + 2 * s.range : 0, readyTxt = ready ? new Date(ready * 1000).toLocaleString('uk-UA', {day:'numeric', month:'long', hour:'2-digit', minute:'2-digit'}) : '';
  const noPrev = `<span class="tr" style="color:var(--ink3)" title="Порівняння з попереднім таким самим періодом з’явиться, коли назбирається вдвічі більше даних${readyTxt ? ' — орієнтовно ' + readyTxt : ''}">${since ? 'дані з ' + since : 'немає даних'}</span>`;
  const trend = (a, b) => !s.has_prev || !b ? noPrev : `<span class="tr ${a < b ? 'dn' : ''}" title="порівняно з попереднім таким самим періодом">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
  const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]);
  const card = (ic, k, v, tr, sp, col) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sparkSvg(sp, col)}</div>`;
  return card('pulse', 'Загальний трафік', fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
    + card('nodes', 'Оброблено flow', fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext)
    + card('ip', 'Унікальні IP', fmtN(s.ips), trend(s.ips, s.p_ips), fl.map(Math.sqrt), '#4C93FF')
    + card('grid', 'Топ сервіс', esc(s.top_service || '—'), s.top_service ? `<span class="tr" style="color:var(--ink2)">${pct(s.top_service_bytes, s.bytes)}</span>` : '', vals.map(Math.sqrt), C.int);
}
let heroScope = null;
function mountHero(){
  if (heroScope) heroScope.dispose();
  heroScope = childScope();
  const g = state.heroMode === 'graph';
  fill('heroSec', `${ph('flow', 'Мережевий трафік', g ? '<span id="heroLbl" class="tnum">наживо · вікно 2 хв · оновлюється…</span>' : 'з’єднання за вибраний період · нові лінії з’являються наживо',
      `<span style="visibility:${g ? 'visible' : 'hidden'}">${seg('scaleSeg', [['sqrt', 'Стиснений', 'Ширина ∝ √обсягу — дрібні потоки помітні поруч із великими'], ['lin', 'Лінійний', 'Ширина пропорційна обсягу']], state.scale)}</span>` + seg('heroSeg', [['graph', 'Graph'], ['map', 'Map'], ['3d', '3D']], state.heroMode)
      + `<span class="legend"><span><i class="bar" style="background:${C.down}"></i>download</span><span><i class="bar" style="background:${C.up}"></i>upload</span><span><i style="background:${C.int}"></i>внутр.</span><span><i style="background:${C.ext}"></i>зовн.</span></span>`)}
    <div id="heroBody" class="${g ? 'river' : 'chart hero-h'}"></div><div id="heroOvl"></div>`);
  wireSeg('heroSeg', m => { if (m === state.heroMode) return; state.heroMode = m; mountHero(); });
  wireSeg('scaleSeg', m => { state.scale = m; setPressed('scaleSeg', m); RIVERS.forEach(k => k()); });
  const hb = document.getElementById('heroBody'), myScope = heroScope;
  heroScope.run(() => {
    if (g) createRiver(hb, {compact:true, refreshMs:10000, fetchData:() => api('river', {top:8, live:1, win:120, metric:state.metric}),
      onData:() => fill('heroLbl', `наживо · вікно 2 хв · оновлено ${hms(Math.floor(Date.now() / 1000))}${scaleNote()}`)});
  });
  if (!g) {
    api('geo').then(geo => { if (!hb.isConnected || heroScope !== myScope) return; myScope.run(() => state.heroMode === 'map' ? flatMap(hb, geo) : globe(hb, geo)); }).catch(e => fill('heroBody', errBox(e)));
    section('heroOvl', async () => {
      const [h, d, s] = await Promise.all([api('top', {dim:'int_ip', limit:1}), api('top', {dim:'ext_ip', limit:1}), api('top', {dim:'service', limit:1})]);
      if (heroScope !== myScope) return null;
      const a = h.rows[0], b = d.rows[0], c = s.rows[0];
      return `<div class="overlay"><div class="ovl">
        <div><span class="ico">${icon(ICO.users, 15)}</span><span>Топ джерело</span><b>${esc(a ? a.name || a.k : '—')}</b><small>${a ? fmtB(tot(a)) : ''}</small></div>
        <div><span class="ico">${icon(ICO.globe, 15)}</span><span>Топ призначення</span><b>${esc(b ? b.k : '—')}</b><small>${b ? [b.city, fmtB(tot(b))].filter(Boolean).join(' · ') : ''}</small></div>
        <div><span class="ico">${icon(ICO.grid, 15)}</span><span>Топ сервіс</span><b>${esc(c ? c.k : '—')}</b><small>${c ? pct(tot(c), s.total) : ''}</small></div></div>
        <div class="livebadge"><b>Наживо</b>нові з’єднання</div></div>`;
    });
  }
}
function vOverview(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><div id="kpis" class="s12 grid" style="grid-column:span 12"><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div><div class="glass kcard s3 loading"></div></div>
    <section class="glass panel s8 hero" id="heroSec"></section>
    <div class="col s4">
      <section class="glass panel">${ph('pie', 'Топ сервісів', 'за обсягом трафіку')}<div id="svcBox" class="loading"></div></section>
      <section class="glass panel">${ph('users', 'Топ хостів', 'внутрішні адреси')}<div id="hostBox" class="loading"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', 'Динаміка трафіку', rangeLabel())}<div class="chart" id="cTrend"></div></section>
    <section class="glass panel s4">${ph('conv', 'Топ розмов', 'внутрішня → зовнішня адреса')}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('list', 'Останні потоки', 'нова мережева активність', '<button class="lnk" id="toFlows">Усі</button>')}<div id="recentBox" class="loading"></div></section></div>`;
  document.getElementById('toFlows').onclick = () => { state.view = 'flows'; render(); };
  section('kpis', kpiCards);
  mountHero();
  section('svcBox', async () => {
    const t = await api('top', {dim:'service', limit:5}); const rest = t.total - t.rows.reduce((s, r) => s + tot(r), 0);
    const rows = [...t.rows, ...(rest > 0 ? [{k:'Інші', up:rest, dn:0}] : [])];
    setTimeout(() => { const el = document.getElementById('cDonut'); if (el) donut(el, rows, k => k === 'Інші' ? C.other : keyColor(k), [fmtB(t.total), 'весь трафік']); });
    return `<div class="donut-wrap"><div class="chart donut" id="cDonut"></div><div class="dl">${rows.map(r => `<i class="idot" style="background:${r.k === 'Інші' ? C.other : keyColor(r.k)}"></i>${r.k === 'Інші' ? '<span>Інші</span>' : `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.k)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div></div>`;
  });
  section('hostBox', async () => { const t = await api('top', {dim:'int_ip', limit:5});
    return `<div class="tw"><table class="compact"><thead><tr><th>#</th><th>Хост</th><th class="num">Трафік</th><th class="num">%</th><th></th></tr></thead><tbody>${t.rows.map((r, i) => `<tr class="click" data-host="${esc(r.k)}"><td class="mono">${i + 1}</td><td><div class="two-line"><b class="mono">${esc(r.name || r.k)}</b>${r.name ? `<span class="nat">${esc(r.k)}</span>` : ''}</div></td><td class="num mono">${fmtB(tot(r))}</td><td class="num mono">${pct(tot(r), t.total)}</td><td class="chev">›</td></tr>`).join('')}</tbody></table></div>`; });
  api('series').then(s => { const el = document.getElementById('cTrend'); if (el) trendChart(el, s); }).catch(e => fill('cTrend', errBox(e)));
  section('convBox', async () => { const t = await api('top', {dim:'conv', limit:5}); return convRows(t.rows, t.total); });
  section('recentBox', async () => { const t = await api('flows', {limit:7});
    return `<div class="tw"><table class="compact"><thead><tr><th>Час</th><th>Внутр. → зовн. · сервіс</th><th class="num">Обсяг</th></tr></thead><tbody>${t.rows.map(f => `<tr><td class="mono">${hms(f.t)}</td><td><div class="two-line"><span class="ipl">${esc(f.name || f.int_ip)} <span class="${f.dir === 'up' ? 'u' : 'd'}">${f.dir === 'up' ? '→' : '←'}</span> ${esc(f.ext_ip)}</span><span class="nat">${esc(f.service)}${f.l7 ? ' · ' + esc(f.l7) : ''}</span></div></td><td class="num mono">${fmtB(f.bytes)}</td></tr>`).join('') || '<tr><td colspan="4"><div class="empty">Немає записів</div></td></tr>'}</tbody></table></div>`; });
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
  if (!sel) return `<p class="note" style="margin:0">Наведіть на стрічку чи вузол, щоб побачити обсяг. Клік додає вибране у фільтри й показує деталі тут.</p>`;
  const extra = selFilters(sel);
  let title, subtitle = '';
  const isOther = k => k === '__other';
  if (sel.type === 'band') { title = `${isOther(sel.l) ? 'Інші' : sel.l} ⇄ ${isOther(sel.r) ? 'Інші' : sel.r}`; subtitle = 'розмова'; }
  else if (sel.side === 'L') title = isOther(sel.k) ? 'Інші внутрішні' : sel.k;
  else title = isOther(sel.k) ? 'Інші зовнішні' : sel.k;
  if (!extra.length) return `<div class="insp"><div class="who"><b>${esc(title)}</b></div><p class="note" style="margin:0">Згорнута група — виберіть конкретну адресу.</p></div>`;
  const [s, svc, l7, ext] = await Promise.all([api('summary', {}, extra), api('top', {dim:'service', limit:4}, extra), api('top', {dim:'l7', limit:4}, extra), api('top', {dim:'ext_ip', limit:1}, extra)]);
  const e0 = ext.rows[0];
  if (sel.type !== 'band' && sel.side === 'R' && e0) subtitle = [e0.as_org && `AS${e0.asn} ${e0.as_org}`, [e0.city, ccName(e0.country)].filter(Boolean).join(', ')].filter(Boolean).join(' · ');
  return `<div class="insp"><div class="who"><b>${esc(title)}</b><span>${esc(subtitle)}</span></div>
    <div class="dk"><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">Сервіси</h4><div class="tagrow">${svc.rows.map(g => `<span class="tag">${esc(g.k)} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4 style="margin:0 0 6px;font-size:12.5px;color:var(--ink2)">Протоколи</h4><div class="tagrow">${l7.rows.map(g => `<span class="tag mono">${esc(g.k)}</span>`).join('') || '—'}</div></div>
    <div class="chart" id="cInsp" style="height:120px" data-extra="${esc(JSON.stringify(extra))}"></div></div>`;
}
function vFlows(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid">
    <section class="glass panel s9">${ph('flow', 'Обмін між внутрішніми та зовнішніми адресами', 'Колір = напрямок · ширина = обсяг (стиснений масштаб показує й дрібні потоки) · топ-10 з кожного боку, решта в «Інші»',
      seg('metricSeg', [['bytes', 'Байти'], ['packets', 'Пакети'], ['flows', 'Flows']], state.metric) + seg('scaleSeg', [['sqrt', 'Стиснений', 'Ширина ∝ √обсягу — дрібні потоки помітні поруч із великими'], ['lin', 'Лінійний', 'Ширина пропорційна обсягу']], state.scale) + seg('liveSeg', [['live', 'Наживо'], ['period', 'За період']], state.flowLive ? 'live' : 'period'), true)}
      <div class="legend" style="margin:-6px 0 10px"><span><i class="bar" style="background:${C.down}"></i>download (зовн. → внутр.)</span><span><i class="bar" style="background:${C.up}"></i>upload (внутр. → зовн.)</span><span><i style="background:${C.int}"></i>внутрішня адреса</span><span><i style="background:${C.ext}"></i>зовнішня адреса</span><span id="winLbl" class="mono" style="margin-left:auto"></span></div>
      <div class="river big" id="river"></div></section>
    <div class="col s3">
      <section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO.pulse, 22)}</span><span class="k">Загальний трафік</span><span class="v" id="kTot">—</span></section>
      <section class="glass panel kcard" style="grid-template-columns:auto 1fr"><span class="ico">${icon(ICO.nodes, 22)}</span><span class="k">Flow-записи</span><span class="v" id="kFl">—</span></section>
      <section class="glass panel">${ph('search', 'Інспектор', 'деталі вибраного')}<div id="insp"></div></section>
    </div>
    <section class="glass panel s4">${ph('chart', 'Обсяг трафіку', 'download / upload')}<div class="chart" id="cVol"></div></section>
    <section class="glass panel s4">${ph('conv', 'Топ розмов', 'з сервісом')}<div id="convBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', 'Протоколи', 'рівень L7 за портом')}<div id="protoBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('list', 'Записи потоків', 'сирі записи, по одному на напрямок сесії · клік розгортає')}<div id="recBox" class="loading"></div></section></div>`;
  const showInsp = async sel => {
    const seq = renderSeq; let html; try { html = await inspectorHtml(sel); } catch (e) { html = errBox(e); }
    if (seq !== renderSeq) return; fill('insp', html);
    const el = document.getElementById('cInsp');
    if (el) api('series', {}, JSON.parse(el.dataset.extra)).then(s => { if (el.isConnected) trendChart(el, s, true); });
  };
  showInsp(state.sel);
  // a click on the river works like everywhere else: the selection goes into the filters (and stays selected)
  const onRiverSelect = sel => { const ex = selFilters(sel);
    if (!ex.length) return showInsp(sel);
    ex.forEach(f => putFilter({...f, neg:false})); state.sel = sel; render(); };
  let riverScope = null;
  const winLbl = d => { const el = document.getElementById('winLbl'); if (el) el.textContent = (d.live && d.window_end ? `вікно 2 хв до ${hms(d.window_end)} · оновлено ${hms(Math.floor(Date.now() / 1000))}` : rangeLabel()) + scaleNote(); };
  let lastData = null;
  const mountRiver = () => {
    if (riverScope) riverScope.dispose();
    riverScope = childScope();
    riverScope.run(() => createRiver(document.getElementById('river'), {compact:false, refreshMs:state.flowLive ? 10000 : 0, onSelect:onRiverSelect,
      fetchData:() => api('river', {top:10, live:state.flowLive ? 1 : 0, win:120, metric:state.metric}), onData:d => { lastData = d; winLbl(d); }}));
  };
  mountRiver();
  wireSeg('scaleSeg', m => { state.scale = m; setPressed('scaleSeg', m); RIVERS.forEach(k => k()); if (lastData) winLbl(lastData); });
  wireSeg('metricSeg', m => { if (m === state.metric) return; state.metric = m; setPressed('metricSeg', m); mountRiver(); });
  wireSeg('liveSeg', m => { const live = m === 'live'; if (live === state.flowLive) return; state.flowLive = live; setPressed('liveSeg', m); mountRiver(); });
  api('summary').then(s => { fill('kTot', fmtB(s.bytes)); fill('kFl', fmtN(s.flows)); }).catch(() => {});
  api('series').then(s => { const el = document.getElementById('cVol'); if (el) trendChart(el, s); }).catch(e => fill('cVol', errBox(e)));
  section('convBox', async () => { const t = await api('top', {dim:'conv', limit:6});
    return `<div class="tw"><table class="compact"><thead><tr><th>Внутр.</th><th>Зовн.</th><th>Сервіс</th><th class="num">Обсяг</th></tr></thead><tbody>${t.rows.map(x => `<tr class="click" data-conv="${esc(x.int_ip)}|${esc(x.ext_ip)}" title="Фільтр за цією розмовою"><td class="ipl">${esc(x.name || x.int_ip)}</td><td class="ipl">${esc(x.ext_ip)}</td><td>${svcBadge(x.service)}</td><td class="num mono">${fmtB(tot(x))}</td></tr>`).join('')}</tbody></table></div>`; });
  document.getElementById('convBox').addEventListener('click', e => { const tr = e.target.closest('tr[data-conv]'); if (!tr) return;
    const [ip, dst] = tr.dataset.conv.split('|'); putFilter({k:'ip', v:ip, neg:false}); putFilter({k:'dst', v:dst, neg:false}); state.sel = null; render(); });
  section('protoBox', async () => { const t = await api('top', {dim:'l7', limit:6});
    setTimeout(() => { const el = document.getElementById('cProto'); if (el) donut(el, t.rows, k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), 'протоколів']); });
    return `<div class="donut-wrap"><div class="chart donut" id="cProto"></div><div class="dl">${t.rows.map((r, i) => `<i class="idot" style="background:${PAL[i]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(r.k)}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div></div>`; });
  section('recBox', async () => { const t = await api('flows', {limit:60}); window.__recs = t.rows; return recTable(t.rows); });
}
function recTable(rows){
  return `<div class="tw"><table><thead><tr><th>Час</th><th>Експортер</th><th>Внутрішня адреса</th><th></th><th>Зовнішня адреса</th><th>Протокол</th><th>Сервіс</th><th>Країна</th><th class="num">Байти</th><th class="num">Пакети</th><th class="num">Трив.</th></tr></thead><tbody>
    ${rows.map((f, i) => `<tr class="click" data-rec="${i}"><td class="mono">${hms(f.t)}</td><td class="ipl">${esc(devName(f.exporter))}</td>
      <td class="ipl"><button class="link" data-f="ip" data-v="${esc(f.int_ip)}">${esc(f.name || f.int_ip)}</button> <span class="nat">:${f.int_port}</span></td><td class="${f.dir === 'up' ? 'u' : 'd'}">${f.dir === 'up' ? '→' : f.dir === 'down' ? '←' : '↔'}</td>
      <td class="ipl"><button class="link" data-f="dst" data-v="${esc(f.ext_ip)}">${esc(f.ext_ip)}</button> <span class="nat">:${f.ext_port}</span></td><td><span class="tag">${esc(f.l7)}</span></td><td>${svcBadge(f.service)}</td>
      <td>${f.country ? `<button class="link" data-f="country" data-v="${esc(f.country)}">${esc(f.country)}</button>` : '—'}</td><td class="num mono">${fmtB(f.bytes)}</td><td class="num mono">${fmtN(f.packets)}</td><td class="num mono">${Math.max(0, f.t - f.t0).toFixed(0)} с</td></tr>
      ${state.openFlow === i ? `<tr class="detail"><td colspan="11"><div class="kv"><div><span>Хост</span><b>${esc(f.name || '—')} · ${esc(f.int_ip)}</b></div><div><span>NAT (після трансляції)</span><b>${f.nat_ip ? esc(f.nat_ip) + ':' + f.nat_port : '—'}</b></div>
        <div><span>ASN</span><b>${f.asn ? 'AS' + f.asn + ' ' + esc(f.as_org) : '—'}</b></div><div><span>Місто</span><b>${esc([f.city, ccName(f.country)].filter(Boolean).join(', ') || '—')}</b></div>
        <div><span>Інтерфейси</span><b>${esc(ifLabel(f.exporter, f.in_if))} → ${esc(ifLabel(f.exporter, f.out_if))}</b></div><div><span>Вибірка</span><b>${f.sampling > 1 ? '1:' + f.sampling + ' (обсяг перераховано)' : '1:1 (без вибірки)'}</b></div><div><span>L4</span><b>${({1:'ICMP', 6:'TCP', 17:'UDP', 50:'ESP', 47:'GRE'})[f.proto] || f.proto}</b></div></div></td></tr>` : ''}`).join('') || '<tr><td colspan="11"><div class="empty">Немає записів під цей фільтр</div></td></tr>'}
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
      <section class="glass panel">${ph('users', 'Топ хостів', 'за загальним обсягом · клік по рядку додає хост у фільтри', '<button class="lnk" id="tMore"></button>')}<div id="tBox" class="loading"></div></section>
      <section class="glass panel grow">${ph('chart', 'Тренд топ-хостів', 'топ-5 і решта')}<div class="chart" id="cTop5"></div></section>
    </div>
    <div class="col s4">
      <section class="glass panel">${ph('pie', 'Трафік топ-хостів', 'частка від усього обсягу')}<div id="tDonut" class="loading"></div></section>
      <section class="glass panel">${ph('grid', 'За сервісами', 'частка трафіку · клік — фільтр')}<div id="tSvc" class="loading"></div></section>
      <section class="glass panel">${ph('globe', 'Куди йде трафік', 'країни призначення')}<div id="tGeo" class="loading"></div></section>
      <section class="glass panel">${ph('search', 'Швидкі дії', '<span id="qaFor">—</span>')}<div class="qa" id="qa"></div></section>
    </div>
    <section class="glass panel s12">${ph('list', 'Топ хостів детально', 'головний сервіс і протокол кожного · клік — фільтр', '<button class="lnk" id="toFlows2">Потоки →</button>')}<div id="tDetail" class="loading"></div></section></div>`;
  document.getElementById('toFlows2').onclick = () => { state.view = 'flows'; render(); };
  const limit = state.talkersAll ? 50 : 10, secs = rangeSecs();
  fill('tMore', state.talkersAll ? 'Показати топ-10' : 'Показати топ-50');
  document.getElementById('tMore').onclick = () => { state.talkersAll = !state.talkersAll; render(); };
  const colorOf = new Map();
  let selected = null, topRows = [];
  const drawQa = () => {
    const h = selected; fill('qaFor', h ? `для ${esc(h.name || h.k)}` : 'немає даних');
    const box = fill('qa', h ? [
      ['flow', 'Деталі потоків', 'сторінка Потоки з фільтром', () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'flows'; render(); }],
      ['users', 'Картка хоста', 'сервіси, протоколи, напрямки', () => openHost(h.k)],
      ['globe', 'Геолокація', 'карта з’єднань цього хоста', () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'geo'; render(); }],
      ['list', 'Експорт CSV', 'таблиця топ-хостів', () => downloadCsv(`flowtrack-top-hosts-${state.range}.csv`, ['rank', 'ip', 'name', 'bytes', 'upload', 'download', 'percent', 'flows', 'avg_bps'],
        topRows.map((r, i) => [i + 1, r.k, r.name || '', tot(r), r.up, r.dn, (100 * tot(r) / (window.__tTotal || 1)).toFixed(2), r.fl, Math.round(tot(r) * 8 / secs)]))],
    ].map(([ic, t, sub], i) => `<button class="qa-btn" data-qa="${i}"><span class="ico">${icon(ICO[ic], 18)}</span><span><b>${t}</b><small>${sub}</small></span></button>`).join('') : '');
    if (box && h) { const acts = [() => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'flows'; render(); }, () => openHost(h.k), () => { putFilter({k:'ip', v:h.k, neg:false}); state.view = 'geo'; render(); },
      () => downloadCsv(`flowtrack-top-hosts-${state.range}.csv`, ['rank', 'ip', 'name', 'bytes', 'upload', 'download', 'percent', 'flows', 'avg_bps'], topRows.map((r, i) => [i + 1, r.k, r.name || '', tot(r), r.up, r.dn, (100 * tot(r) / (window.__tTotal || 1)).toFixed(2), r.fl, Math.round(tot(r) * 8 / secs)]))];
      box.querySelectorAll('[data-qa]').forEach(b => b.onclick = acts[+b.dataset.qa]); }
  };
  section('tKpi', async () => {
    const [s, ser, t] = await Promise.all([api('summary'), api('series'), api('top', {dim:'int_ip', limit:1})]);
    const trend = (a, b) => !s.has_prev || !b ? `<span class="tr" style="color:var(--ink3)">дані з ${hhmm(s.oldest)}</span>` : `<span class="tr ${a < b ? 'dn' : ''}">${a >= b ? '↑' : '↓'} ${Math.abs(100 * (a - b) / b).toFixed(1)}%</span>`;
    const vals = ser.rows.map(r => r[1] + r[2] + r[3]), fl = ser.rows.map(r => r[4]), top = t.rows[0];
    const card = (ic, k, v, tr, sp, col, sub) => `<div class="glass kcard s3"><span class="ico">${icon(ICO[ic], 22)}</span><span class="k">${k}</span><span></span><span class="v">${v}</span>${tr}${sub ? `<span class="s" style="grid-column:2/-1;font-size:12.5px;color:var(--ink2)">${sub}</span>` : ''}${sp ? sparkSvg(sp, col) : ''}</div>`;
    return card('pulse', 'Загальний трафік', fmtB(s.bytes), trend(s.bytes, s.p_bytes), vals, C.down)
      + card('ip', 'Топ хост (за обсягом)', esc(top ? top.name || top.k : '—'), '', null, '', top ? `${esc(top.name ? top.k + ' · ' : '')}${fmtB(tot(top))} (${pct(tot(top), t.total)})` : '')
      + card('users', 'Унікальні хости', fmtN(s.hosts), trend(s.hosts, s.p_hosts), fl.map(Math.sqrt), C.int)
      + card('nodes', 'Усього flow', fmtN(s.flows), trend(s.flows, s.p_flows), fl, C.ext);
  });
  Promise.all([api('top', {dim:'int_ip', limit}), api('series', {by:'int_ip', top:Math.min(limit, 20)})]).then(([t, ser]) => {
    topRows = t.rows; window.__tTotal = t.total;
    t.rows.forEach((r, i) => colorOf.set(r.k, HOSTPAL[i % HOSTPAL.length]));
    const fip = (state.filters.find(f => f.k === 'ip' && !f.neg) || {}).v;
    selected = t.rows.find(r => r.k === fip) || t.rows[0] || null; drawQa();
    const sp = new Map(); for (const [ts, k, b] of ser.rows) { if (!sp.has(k)) sp.set(k, new Map()); sp.get(k).set(ts, b); }
    const {ts} = grid(ser), max = t.rows.length ? tot(t.rows[0]) : 1;
    const box = fill('tBox', `<div class="tw"><table class="talkers"><thead><tr><th>#</th><th>Хост / IP</th><th style="width:26%">Обсяг</th><th class="num">%</th><th class="num">Flows</th><th class="num">Сер. швидкість</th><th>Тренд</th><th></th></tr></thead><tbody>
      ${t.rows.map((r, i) => { const c = colorOf.get(r.k);
        return `<tr class="click${r.k === fip ? ' is-picked' : ''}" data-pick="${esc(r.k)}" title="Додати у фільтри"><td class="mono">${i + 1}</td><td><div class="hcell"><span class="hbar" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="htxt"><b class="mono">${esc(r.k)}</b><span class="nat">${esc(r.name || (r.k.startsWith('10.') || r.k.startsWith('192.168.') || r.k.startsWith('172.') ? 'без імені' : 'публічна адреса'))}</span></span></div></td>
          <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .55)},${c});box-shadow:0 0 8px ${hexA(c, .6)}"></i></div></td>
          <td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${fmtN(r.fl)}</td><td class="num mono">${fmtR(tot(r) * 8 / secs)}</td>
          <td style="width:120px">${sp.has(r.k) ? sparkSvg(ts.map(x => sp.get(r.k).get(x) || 0), c, 120, 26) : ''}</td><td><button class="btn" data-open="${esc(r.k)}" title="Картка хоста">›</button></td></tr>`; }).join('') || '<tr><td colspan="8"><div class="empty">Немає даних</div></td></tr>'}</tbody></table></div>`);
    if (box) { box.classList.remove('loading');
      box.querySelectorAll('tr[data-pick]').forEach(tr => tr.onclick = () => addFilter('ip', tr.dataset.pick));
      box.querySelectorAll('[data-open]').forEach(b => b.onclick = e => { e.stopPropagation(); openHost(b.dataset.open); }); }
    // donut: top 5 + rest, same colours as the table
    const top5 = t.rows.slice(0, 5), rest = t.total - top5.reduce((a, r) => a + tot(r), 0);
    const drows = [...top5.map(r => ({k:r.k, label:r.name || r.k, up:r.up, dn:r.dn})), ...(rest > 0 ? [{k:'__other', label:'Інші', up:rest, dn:0}] : [])];
    const db = fill('tDonut', `<div class="donut-wrap"><div class="chart donut" id="cTDonut"></div><div class="dl">${drows.map(r => `<i class="idot" style="background:${r.k === '__other' ? C.other : colorOf.get(r.k)}"></i>${r.k === '__other' ? '<span>Інші</span>' : `<button class="link mono" data-f="ip" data-v="${esc(r.k)}">${esc(r.label)}</button>`}<span class="p">${pct(tot(r), t.total)}</span><span class="t"></span>`).join('')}</div></div>`);
    if (db) { db.classList.remove('loading'); wireFilters(db); donut(document.getElementById('cTDonut'), drows.map(r => ({...r, k:r.label})), k => { const r = drows.find(x => x.label === k); return r.k === '__other' ? C.other : colorOf.get(r.k); }, [fmtB(t.total), 'весь трафік']); }
    // stacked trend: top 5 + others, same colours
    api('series', {by:'int_ip', top:5}).then(s5 => { const el = document.getElementById('cTop5'); if (!el) return;
      const {ts: t5, step} = grid(s5), keys = new Map(); for (const [x, k, b] of s5.rows) { if (!keys.has(k)) keys.set(k, new Map()); keys.get(k).set(x, b); }
      const order = [...keys.keys()].sort((a, b) => (a === '__other') - (b === '__other'));
      const c = mkChart(el);
      c.setOption({animation:false, grid:{left:14, right:10, top:36, bottom:4, containLabel:true}, legend:{top:0, left:0, icon:'roundRect', itemWidth:10, itemHeight:10, textStyle:{color:C.ink2, fontFamily:'Manrope'}},
        tooltip:{...tipBase(), trigger:'axis', order:'valueDesc', valueFormatter:v => fmtR(v)}, xAxis:axisX(), yAxis:axisY(v => fmtR(v)),
        series:order.map(k => { const col = k === '__other' ? C.other : (colorOf.get(k) || C.other), r = t.rows.find(x => x.k === k);
          return {name:k === '__other' ? 'інші' : (r && r.name) || k, type:'line', stack:'a', smooth:.3, showSymbol:false, lineStyle:{width:1.6, color:col}, itemStyle:{color:col},
            areaStyle:{color:new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset:0, color:hexA(col, .45)}, {offset:1, color:hexA(col, .05)}])}, data:t5.map(x => [x * 1000, (keys.get(k).get(x) || 0) * 8 / step])}; })});
    }).catch(e => fill('cTop5', errBox(e)));
  }).catch(e => fill('tBox', errBox(e)));
  section('tSvc', async () => { const p = await api('top', {dim:'service', limit:6}); const rows = p.rows.slice(0, 5), rest = p.total - rows.reduce((a, r) => a + tot(r), 0);
    const all = [...rows.map(r => ({label:r.k, v:tot(r), k:r.k})), ...(rest > 0 ? [{label:'Інші', v:rest}] : [])];
    return `<div class="pbars">${all.map(r => { const c = r.k ? keyColor(r.k) : C.other;
      return `<span>${r.k ? `<button class="link" data-f="service" data-v="${esc(r.k)}">${esc(r.label)}</button>` : r.label}</span><div class="vbar"><i style="width:${Math.max(1, 100 * r.v / (p.total || 1)).toFixed(1)}%;background:linear-gradient(90deg,${hexA(c, .6)},${c})"></i></div><b class="mono">${pct(r.v, p.total)}</b>`; }).join('') || '<div class="empty">Немає даних</div>'}</div>`; });
  section('tGeo', async () => { const [cc, city] = await Promise.all([api('top', {dim:'country', limit:5}), api('top', {dim:'city', limit:25})]);
    const rest = cc.total - cc.rows.reduce((a, r) => a + tot(r), 0), cols = ['#27D3F5', '#2F7BFF', '#2EE59D', '#8B5CFF', '#FFB547'];
    setTimeout(() => { const el = document.getElementById('cMini'); if (!el || !echarts.getMap('world')) return; const c = mkChart(el), cmax = city.rows.length ? tot(city.rows[0]) : 1;
      c.setOption({animation:false, geo:{map:'world', silent:true, roam:false, left:0, right:0, top:0, bottom:0, itemStyle:{areaColor:'rgba(30,56,120,.45)', borderColor:'rgba(110,160,255,.25)', borderWidth:.4}},
        series:[{type:'scatter', coordinateSystem:'geo', symbolSize:d => 4 + 10 * Math.sqrt(d[2] / cmax), itemStyle:{color:'#27D3F5', shadowBlur:10, shadowColor:'#27D3F5'},
          data:city.rows.filter(r => r.la || r.lo).map(r => [r.lo, r.la, tot(r)])}]}); });
    return `<div class="geomini"><div class="chart" id="cMini" style="height:120px"></div><div class="dl">${cc.rows.map((r, i) => `<i class="idot" style="background:${cols[i]}"></i><button class="link" data-f="country" data-v="${esc(r.k)}">${esc(r.k ? ccName(r.k) : 'Локальні')}</button><span class="p">${pct(tot(r), cc.total)}</span><span class="t"></span>`).join('')}${rest > 0 ? `<i class="idot" style="background:${C.other}"></i><span>Інші</span><span class="p">${pct(rest, cc.total)}</span><span class="t"></span>` : ''}</div></div>`; });
  section('tDetail', async () => { const d = await api('top', {dim:'host_svc', limit:6});
    return `<div class="tw"><table class="compact"><thead><tr><th>Хост</th><th>Головний сервіс</th><th>Протокол</th><th class="num">Обсяг</th></tr></thead><tbody>${d.rows.map((r, i) => { const c = HOSTPAL[i % HOSTPAL.length];
      return `<tr class="click" data-f="ip" data-v="${esc(r.k)}"><td><span class="idot" style="background:${c};box-shadow:0 0 8px ${c}"></span><span class="mono">${esc(r.name || r.k)}</span></td><td>${svcBadge(r.service)}</td><td><span class="tag">${L4[r.proto] || r.proto} · ${esc(r.l7)}</span></td><td class="num mono">${fmtB(tot(r))}</td></tr>`; }).join('')}</tbody></table></div>`; });
}
function vPorts(){
  const v = document.getElementById('view'), all = !!state.portsAll;
  v.innerHTML = `<div class="grid">
    <section class="glass panel s12">${ph('chart', 'Порти в часі', 'топ-7 · клік по лінії — фільтр за портом')}<div class="chart" id="cPorts"></div></section>
    <section class="glass panel s8">${ph('list', 'Топ портів', 'клік — фільтр за портом', '<button class="lnk" id="pMore"></button>')}<div id="pTbl" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', 'Протоколи L7', 'за портом')}<div id="pL7" class="loading"></div></section></div>`;
  api('series', {by:'ext_port', top:7}).then(s => { const el = document.getElementById('cPorts'); if (el) stackChart(el, s, k => ':' + k, k => addFilter('port', k)); }).catch(e => fill('cPorts', errBox(e)));
  section('pTbl', async () => { const t = await api('top', {dim:'ext_port', limit:all ? 100 : 11}), rows = all ? t.rows : t.rows.slice(0, 10), max = rows.length ? tot(rows[0]) : 1;
    moreToggle('pMore', 'portsAll', all, t.rows.length > 10);
    return `<div class="tw"><table><thead><tr><th>Порт</th><th>Протокол</th><th>Типовий сервіс</th><th style="width:24%">Обсяг</th><th class="num">%</th><th class="num">Хостів</th><th class="num">Зовн. адрес</th><th class="num">Flows</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="port" data-v="${esc(r.k)}"><td><b class="mono">${esc(r.k)}</b></td><td><span class="tag">${L4[r.proto_n] || r.proto_n} · ${esc(r.l7)}</span></td><td>${svcBadge(r.service)}</td>
        <td><b class="mono">${fmtB(tot(r))}</b><div class="vbar"><i style="width:${(100 * tot(r) / max).toFixed(1)}%;background:linear-gradient(90deg,#1aa7d6,#27D3F5)"></i></div></td><td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${r.hosts}</td><td class="num mono">${fmtN(r.peers)}</td><td class="num mono">${fmtN(r.fl)}</td></tr>`).join('') || '<tr><td colspan="8"><div class="empty">Немає даних</div></td></tr>'}</tbody></table></div>`; });
  section('pL7', async () => { const t = await api('top', {dim:'l7', limit:8});
    setTimeout(() => { const el = document.getElementById('cPL7'); if (el) donut(el, t.rows, k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), 'протоколів']); });
    return `<div class="chart" id="cPL7" style="height:200px"></div><div class="dl">${t.rows.map((r, i) => `<i class="idot" style="background:${PAL[i % PAL.length]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(r.k)}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div>`; });
}
// "show all" / "top 10" link in a panel header; hidden when there is nothing more to show
function moreToggle(id, key, all, hasMore){
  const b = document.getElementById(id); if (!b) return;
  b.hidden = !all && !hasMore; b.textContent = all ? 'Показати топ-10' : 'Показати всі';
  b.onclick = () => { state[key] = !all; render(); };
}
function vApps(){
  const v = document.getElementById('view'), all = !!state.appsAll;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('chart', 'Сервіси в часі', 'сервіс визначається за ASN адреси призначення та портом')}<div class="chart" id="cApps"></div></section>
    <section class="glass panel s8">${ph('grid', 'Сервіси', 'клік — фільтр за сервісом', '<button class="lnk" id="aMore"></button>')}<div id="aBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('pie', 'Протоколи', 'L7 за портом')}<div id="pBox" class="loading"></div></section></div>`;
  api('series', {by:'service', top:7}).then(s => { const el = document.getElementById('cApps'); if (el) stackChart(el, s, k => k, k => addFilter('service', k)); }).catch(e => fill('cApps', errBox(e)));
  section('aBox', async () => { const t = await api('top', {dim:'service', limit:all ? 100 : 11}), rows = all ? t.rows : t.rows.slice(0, 10);
    moreToggle('aMore', 'appsAll', all, t.rows.length > 10);
    return `<div class="tw"><table><thead><tr><th>Сервіс</th><th>Протокол</th><th class="num">↓</th><th class="num">↑</th><th class="num">Разом</th><th class="num">%</th><th class="num">Хостів</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="click" data-f="service" data-v="${esc(r.k)}"><td><button class="link" data-f="service" data-v="${esc(r.k)}">${svcBadge(r.k)}</button></td><td class="ipl">${esc(r.l7)}</td><td class="num d mono">${fmtB(r.dn)}</td><td class="num u mono">${fmtB(r.up)}</td><td class="num mono"><b>${fmtB(tot(r))}</b></td><td class="num mono">${pct(tot(r), t.total)}</td><td class="num mono">${r.hosts}</td></tr>`).join('')}</tbody></table></div>`; });
  section('pBox', async () => { const t = await api('top', {dim:'l7', limit:10});
    setTimeout(() => { const el = document.getElementById('cL7'); if (el) donut(el, t.rows.slice(0, 8), k => PAL[t.rows.findIndex(r => r.k === k) % PAL.length], [String(t.rows.length), 'протоколів']); });
    return `<div class="chart" id="cL7" style="height:220px"></div><div class="dl">${t.rows.slice(0, 8).map((r, i) => `<i class="idot" style="background:${PAL[i % PAL.length]}"></i><button class="link" data-f="l7" data-v="${esc(r.k)}">${esc(r.k)}</button><span class="p">${pct(tot(r), t.total)}</span><span class="t">${fmtB(tot(r))}</span>`).join('')}</div>`; });
}
function vGeo(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s8">${ph('globe', 'Карта з’єднань', 'GeoIP призначення · лінія з’являється, коли надходить новий flow · колір = напрямок',
      `<span class="legend"><span><i class="bar" style="background:${C.down}"></i>download</span><span><i class="bar" style="background:${C.up}"></i>upload</span><span><i style="background:${C.int}"></i>майданчики</span><span><i style="background:${C.ext}"></i>призначення</span></span>`)}<div class="chart map" id="cMap"></div></section>
    <section class="glass panel s4">${ph('pulse', 'З’єднання наживо', 'нові flow із геолокацією')}<div class="ticker" id="ticker"><div class="empty">Чекаю на нові записи (експорт іде раз на ~хвилину)…</div></div></section>
    <section class="glass panel s4">${ph('globe', 'Країни', 'за адресою призначення')}<div id="ccBox" class="loading"></div></section>
    <section class="glass panel s8">${ph('nodes', 'Автономні системи', 'хто насправді обслуговує трафік')}<div id="asBox" class="loading"></div></section></div>`;
  const tk = document.getElementById('ticker');
  api('geo').then(g => { const el = document.getElementById('cMap'); if (!el) return; flatMap(el, g, r => {
    if (tk.querySelector('.empty')) tk.innerHTML = '';
    const up = r.dir === 'up', site = siteCity(r.exporter), place = r.city || ccName(r.country);
    const d = document.createElement('div'); d.className = 'tick';
    d.innerHTML = `<span class="mono" style="color:var(--ink3)">${hms(r.t)}</span><span><b class="${up ? 'u' : 'd'}">${up ? '↑' : '↓'}</b> ${esc(up ? site : place)} → ${esc(up ? place : site)}<br><span class="nat ipl">${esc(r.name || r.int_ip)} ${up ? '→' : '←'} ${esc(r.ext_ip)}:${r.ext_port} · ${esc(r.service)}</span></span><span class="mono">${fmtB(r.bytes)}</span>`;
    tk.prepend(d); while (tk.children.length > 14) tk.lastChild.remove(); }); }).catch(e => fill('cMap', errBox(e)));
  section('ccBox', async () => { const t = await api('top', {dim:'country', limit:20}); const max = t.rows.length ? tot(t.rows[0]) : 1;
    return `<div class="blist">${t.rows.map(r => `<button class="brow" data-f="country" data-v="${esc(r.k)}"><span class="n"><span class="tag mono">${esc(r.k || '—')}</span>&nbsp; ${esc(r.k ? ccName(r.k) : 'Локальні / невідомі')}</span><span class="t">${fmtB(tot(r))}</span><span class="p">${pct(tot(r), t.total)}</span>
      <span class="bar2" style="width:${(100 * tot(r) / max).toFixed(1)}%"><i class="u" style="width:${(100 * r.up / (tot(r) || 1)).toFixed(1)}%"></i><i class="d" style="flex:1"></i></span></button>`).join('')}</div>`; });
  section('asBox', async () => { const t = await api('top', {dim:'asn', limit:25});
    return `<div class="tw"><table><thead><tr><th>ASN</th><th>Країна</th><th class="num">↓</th><th class="num">↑</th><th class="num">Разом</th><th class="num">%</th></tr></thead><tbody>
      ${t.rows.map(r => `<tr><td>${r.k !== '0' ? `<button class="link" data-f="asn" data-v="${esc(r.k)}">AS${esc(r.k)} ${esc(r.as_org)}</button>` : 'локальні адреси'}</td><td><span class="tag mono">${esc(r.country || '—')}</span></td><td class="num d mono">${fmtB(r.dn)}</td><td class="num u mono">${fmtB(r.up)}</td><td class="num mono"><b>${fmtB(tot(r))}</b></td><td class="num mono">${pct(tot(r), t.total)}</td></tr>`).join('')}</tbody></table></div>`; });
}
function vThreats(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s8">${ph('shield', 'Події та аномалії', 'обчислюються з потоків за останню добу')}<div id="alBox" class="loading"></div></section>
    <section class="glass panel s4">${ph('search', 'Що відстежується')}<div class="kv">
      <div><span>Тривале вивантаження</span><b>&gt;5 Мбіт/с · 45 хв із 3 год</b></div><div><span>Сплески</span><b>×8 від медіани хоста</b></div><div><span>Нові країни</span><b>перший контакт за тиждень</b></div>
      <div><span>Здоров’я експорту</span><b>пропуски sequence</b></div></div><p class="note">Сканування портів, репутація IP і сповіщення в Telegram — наступні кроки.</p></section></div>`;
  section('alBox', async () => { const a = (await api('alerts')).alerts;
    if (!a.length) return '<div class="empty">Подій немає — усе спокійно</div>';
    return '<div class="alerts">' + a.map(x => `<div class="alert ${x.sev}"><span class="sev">${x.sev === 'info' ? 'i' : '!'}</span><div class="body"><b>${esc(x.title)}</b><p>${esc(x.text)}</p></div>
      <div class="meta"><span class="pill ${x.sev}">${{warn:'увага', crit:'аномалія', info:'інфо'}[x.sev]}</span><span class="mono">${esc(String(x.when).slice(11, 16) || x.when)}</span>${x.ip ? `<button class="btn" data-f="ip" data-v="${esc(x.ip)}">Фільтр</button>` : ''}</div></div>`).join('') + '</div>'; });
}
const VENDORS = {
  Fortinet:(ip, port) => `config system netflow\n    set active-flow-timeout 60\n    config collectors\n        edit 1\n            set collector-ip ${ip}\n            set collector-port ${port}\n        next\n    end\nend\nconfig system interface\n    edit "wan1"\n        set netflow-sampler both\n    next\nend`,
  Cisco:(ip, port) => `flow exporter FLOWTRACK\n destination ${ip}\n transport udp ${port}\n template data timeout 60\nflow monitor FT-MON\n exporter FLOWTRACK\n record netflow ipv4 original-input\ninterface GigabitEthernet0/0/0\n ip flow monitor FT-MON input\n ip flow monitor FT-MON output`,
  MikroTik:(ip, port) => `/ip traffic-flow set enabled=yes interfaces=ether1 active-flow-timeout=1m\n/ip traffic-flow target add dst-address=${ip} port=${port} version=ipfix`,
  Juniper:(ip, port) => `set services flow-monitoring version-ipfix template FT ipv4-template\nset forwarding-options sampling instance FT input rate 1\nset forwarding-options sampling instance FT family inet output flow-server ${ip} port ${port}\nset forwarding-options sampling instance FT family inet output flow-server ${ip} version-ipfix template FT`,
  'Linux / pmacct':(ip, port) => `# /etc/pmacct/pmacctd.conf\nplugins: nfprobe\nnfprobe_receiver: ${ip}:${port}\nnfprobe_version: 10\npcap_interface: eth0`,
};
function vDevices(){
  const v = document.getElementById('view'); state.ifEdit = null;
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('dev', 'Пристрої-експортери', 'NetFlow v5/v9 та IPFIX від будь-якого виробника · статистика за 15 хв', isAdmin() ? '<button class="btn primary" id="addDev">+ Підключити пристрій</button>' : '<span class="nat">додавати пристрої може адміністратор</span>')}<div id="dBox" class="loading"></div></section>
    <section class="glass panel s12">${ph('ip', 'Інтерфейси', 'індекси, які колектор бачив за 24 год · роль WAN визначає, що таке upload і download')}<div id="ifBox" class="loading"></div></section></div>`;
  if (isAdmin()) document.getElementById('addDev').onclick = () => openDevice(null);
  section('dBox', async () => { const res = await api('devices'), d = res.devices; window.__devs = d;
    // the interfaces panel shows one device: the one picked in the table, else the global device filter, else the first
    const df = state.filters.find(f => f.k === 'device' && !f.neg);
    if (!d.some(x => x.ip === state.ifDev)) state.ifDev = (d.find(x => df && x.ip === df.v) || d.find(x => x.interfaces.length) || d[0] || {}).ip;
    setTimeout(() => {
      showIfaces(d);
      document.querySelectorAll('#dBox tr[data-pick]').forEach(tr => tr.onclick = () => { if (tr.dataset.pick === state.ifDev) return; if (state.ifEdit && !confirm('Скасувати незбережені зміни інтерфейсів?')) return; state.ifEdit = null; state.ifDev = tr.dataset.pick; showIfaces(d); });
      document.querySelectorAll('[data-edit]').forEach(b => b.onclick = e => { e.stopPropagation(); openDevice(d.find(x => x.ip === b.dataset.edit)); });
    });
    return `<div class="tw"><table><thead><tr><th>Стан</th><th>Пристрій</th><th>Виробник / модель</th><th>Протокол</th><th>Майданчик</th><th>IP експорту</th><th class="num">Записів/с</th><th class="num">Шаблони</th><th>Вибірка</th><th class="num">Втрати</th><th class="num">Без шаблону</th>${isAdmin() ? '<th></th>' : ''}</tr></thead><tbody>
      ${d.map(x => { const never = !x.last, stale = Date.now() / 1000 - x.last > 180, st = never ? 'warn' : stale ? 'crit' : x.loss_pct > 0.5 ? 'warn' : '';
        return `<tr class="click" data-pick="${esc(x.ip)}"><td><span class="dot ${st}" title="${never ? 'ще не надсилав даних' : stale ? 'немає даних понад 3 хв' : 'онлайн'}"></span></td><td><b class="mono">${esc(x.name)}</b>${x.configured ? '' : ' <span class="tag">не описаний</span>'}</td><td>${esc(x.vendor || '—')}<br><span class="nat">${esc(x.model)}</span></td><td><span class="tag">${never ? 'очікую' : esc(x.proto)}</span></td><td>${esc(x.site || '—')}</td><td class="ipl">${esc(x.ip)}</td>
          <td class="num mono">${x.rps}</td><td class="num mono">${x.templates}</td><td class="mono">${esc(x.sampling)}</td><td class="num mono" style="color:${x.loss_pct ? 'var(--warn)' : 'inherit'}">${x.loss_pct}%</td><td class="num mono">${x.no_template}</td>
          ${isAdmin() ? `<td><button class="btn" data-edit="${esc(x.ip)}">Змінити</button></td>` : ''}</tr>`; }).join('') || '<tr><td colspan="12"><div class="empty">Ще жоден пристрій не надіслав дані</div></td></tr>'}</tbody></table></div>${collectorBar(res.collector, res.listen)}<p class="note">Клік по рядку показує інтерфейси пристрою нижче. Фільтр за пристроєм — у списку пристроїв угорі.${isAdmin() ? ' Зміни опису колектор підхоплює протягом хвилини.' : ''}</p>`; });
}
// where devices must send NetFlow: the collector's own interface address when it listens on specific interfaces
// (the web UI may be on another one), otherwise the address this page was opened with
function collectorTarget(){
  const nf = (META.listen || {}).netflow, addrs = nf ? nf.listen.flatMap(x => x.addrs) : [];
  return [addrs.find(a => !a.includes(':')) || addrs[0] || location.hostname, nf ? nf.port : 2055];
}
const listenText = l => !l ? '—' : l.listen.map(x => (x.iface || 'усі інтерфейси') + (x.addrs.length ? ` (${x.addrs.join(', ')})` : '')).join('; ');
// receiver health: workers, socket buffer and every place a packet can be lost on the way to the database
function collectorBar(c, listen){
  const nf = listen && listen.netflow, web = listen && listen.web;
  const where = (nf || web) ? `<div class="collbar-where">${nf ? `<span>Прийом NetFlow/IPFIX: <b class="mono">UDP ${nf.port} · ${esc(listenText(nf))}</b></span>` : ''}${web ? `<span>Вебінтерфейс: <b class="mono">TCP ${web.port} · ${esc(listenText(web))}</b></span>` : ''}</div>` : '';
  if (!c) return where ? `<div class="collbar">${where}</div>` : '';
  const lost = c.socket_drops + c.queue_drops, pct = 100 * lost / Math.max(1, c.packets + lost), fill = c.rcvbuf ? Math.round(100 * c.rx_queue_peak / c.rcvbuf) : 0;
  const cell = (k, v, tip, bad) => `<div title="${esc(tip)}"><span>${k}</span><b class="mono"${bad ? ' style="color:var(--warn)"' : ''}>${v}</b></div>`;
  return `<div class="collbar"><div class="collbar-h"><b>Колектор</b><span class="nat">за ${c.minutes} хв</span></div>
    ${cell('Воркери', c.workers, 'Процеси, що декодують пакети (FT_WORKERS у /etc/flowtrack/env)', !c.workers)}
    ${cell('Пакетів прийнято', c.packets.toLocaleString('uk-UA'), 'Датаграми, прочитані із сокета')}
    ${cell('Відкинуто сокетом', c.socket_drops.toLocaleString('uk-UA'), 'Ядро відкинуло пакети: буфер сокета був повний (колектор не встигав або сплеск більший за буфер)', c.socket_drops)}
    ${cell('Відкинуто чергою', c.queue_drops.toLocaleString('uk-UA'), 'Воркери не встигали забирати пакети', c.queue_drops)}
    ${cell('Втрачено записів', c.dropped_rows.toLocaleString('uk-UA'), 'Записи, які не вдалося зберегти: ClickHouse був недоступний занадто довго', c.dropped_rows)}
    ${cell('Буфер сокета', `${fmtB(c.rcvbuf)} · пік ${fill}%`, 'Розмір буфера прийому і найбільше його заповнення (net.core.rmem_max обмежує розмір)', fill > 50)}
    ${cell('Втрати', (lost ? pct.toFixed(pct < 0.01 ? 3 : 2) : '0') + '%', 'Частка пакетів, які колектор не обробив', lost)}${where}</div>`;
}
// generic centered dialog; returns {root, close}
const ROLE_UI = {lan:'LAN', wan:'WAN (інтернет)', local:'Сам пристрій'};
function showIfaces(devices){
  document.querySelectorAll('#dBox tr[data-pick]').forEach(tr => tr.classList.toggle('picked', tr.dataset.pick === state.ifDev));
  const x = devices.find(d => d.ip === state.ifDev), box = document.getElementById('ifBox'); if (!box) return;
  box.classList.remove('loading');
  if (!x) { box.innerHTML = '<div class="empty">Ще жоден пристрій не надіслав дані</div>'; return; }
  box.innerHTML = ifaceTable(x, state.ifEdit === x.ip);
  wireIfaces(box, x, devices);
}
const addrHtml = i => {
  const own = i.addrs.map(a => `<b class="mono">${esc(a)}</b>`), seen = i.seen_addrs.filter(a => !i.addrs.some(o => o === a || o.split('/')[0] === a));
  const auto = seen.map(a => `<span class="mono nat" title="${a.includes('/') ? 'мережа, з якої приходить трафік у цей інтерфейс (за 24 год)' : 'адреса NAT, з якою трафік виходить через цей інтерфейс (за 24 год)'}">${esc(a)}</span>`);
  return [...own, ...auto].join('<br>') || '<span class="nat">—</span>';
};
function ifaceTable(x, edit){
  const admin = isAdmin(), total = x.interfaces.reduce((a, i) => a + i.bytes, 0) || 1;
  // suggest the interface that clearly carries the most internet-facing traffic
  const ranked = [...x.interfaces].filter(i => i.bytes > 0.02 * total).sort((a, b) => b.ext_share - a.ext_share);
  const best = ranked[0] && ranked[0].ext_share >= 0.3 && ranked[0].ext_share >= 3 * ((ranked[1] || {}).ext_share || 0) ? ranked[0].index : null;
  const rows = x.interfaces.map(i => {
    const hint = i.index === best && i.role !== 'wan' ? `<span class="pill info" title="${Math.round(i.ext_share * 100)}% трафіку цього інтерфейсу — з/до публічних адрес; у решти значно менше">схоже на WAN</span>` : '';
    const name = edit ? `<input class="ifname" data-idx="${i.index}" value="${esc(i.custom_name)}" placeholder="${esc(i.role === 'local' ? 'local' : 'if ' + i.index)}" maxlength="32" aria-label="Назва інтерфейсу ${i.index}">`
                      : `<b class="ipl">${esc(i.name)}</b>`;
    const role = edit ? `<select class="ifrole" data-idx="${i.index}" aria-label="Роль інтерфейсу ${i.index}">${Object.entries(ROLE_UI).map(([k, l]) => `<option value="${k}"${k === i.role ? ' selected' : ''}>${l}</option>`).join('')}</select>`
                      : (i.role === 'wan' ? '<span class="pill warn">WAN</span>' : i.role === 'local' ? '<span class="tag">сам пристрій</span>' : '<span class="tag">LAN</span>');
    const addrs = edit ? `<input class="ifaddr" data-idx="${i.index}" value="${esc(i.addrs.join(', '))}" placeholder="IP або IP/маска, через кому" aria-label="IP-адреси інтерфейсу ${i.index}">${i.seen_addrs.length ? `<div class="nat ifseen">у даних: ${i.seen_addrs.map(esc).join(', ')}</div>` : ''}`
                       : addrHtml(i);
    const unseen = i.unseen ? ` <span class="pill warn" title="Індекс є в налаштуваннях, але в даних за 24 год не траплявся — можливо, його вказано помилково">не бачили за 24 год</span>` : '';
    return `<tr${i.unseen ? ' class="unseen"' : ''}><td class="num mono">${i.index}</td><td>${name}</td><td>${addrs}</td><td>${role} ${hint}${unseen}</td><td class="num mono">${i.unseen ? '—' : fmtB(i.bytes)}</td><td class="num mono">${i.unseen ? '—' : Math.round(i.ext_share * 100) + '%'}</td></tr>`;
  }).join('');
  const btns = !admin || !x.interfaces.length ? '' : edit ? '<span class="nat ifmsg"></span><button class="btn ifcancel">Скасувати</button><button class="btn primary ifsave" disabled>Зберегти</button>'
                                                           : '<span class="nat ifmsg"></span><button class="btn ifedit">Змінити</button>';
  return `<div class="ifdev${edit ? ' editing' : ''}" data-dev="${esc(x.ip)}"><div class="ifdev-h"><h4 class="mono">${esc(x.name)} <span class="nat">${esc(x.ip)}${x.vendor ? ' · ' + esc(x.vendor) : ''}</span></h4>${btns}</div>
    ${x.interfaces.length ? `<div class="tw"><table class="compact"><thead><tr><th class="num">Індекс</th><th>Назва</th><th>IP-адреси</th><th>Роль</th><th class="num">Трафік за 24 год</th><th class="num" title="Частка трафіку із зовнішніми адресами">Зовн.</th></tr></thead><tbody>${rows}</tbody></table></div>
    <p class="note">Жирним — адреси, вказані вручну; сірим — те, що видно з потоків за 24 год: адреса NAT, з якою трафік виходить в інтернет (так зазвичай виглядає WAN), і мережі, з яких трафік приходить в інтерфейс.</p>`
      : '<div class="empty">Колектор ще не бачив інтерфейсів цього пристрою (за 24 год)</div>'}</div>`;
}
function wireIfaces(box, x, devices){
  const card = box.querySelector('.ifdev'), msg = card.querySelector('.ifmsg');
  const say = (t, color) => { if (msg) { msg.textContent = t; msg.style.color = color || ''; } };
  const edit = card.querySelector('.ifedit'); if (edit) edit.onclick = () => { state.ifEdit = x.ip; showIfaces(devices); const f = box.querySelector('.ifname'); if (f) f.focus(); };
  const cancel = card.querySelector('.ifcancel'); if (cancel) cancel.onclick = () => { state.ifEdit = null; showIfaces(devices); };
  const save = card.querySelector('.ifsave'); if (!save) return;
  card.querySelectorAll('input,select').forEach(el => el.addEventListener('input', () => { save.disabled = false; say('є незбережені зміни', 'var(--warn)'); }));
  card.addEventListener('keydown', e => { if (e.key === 'Escape') cancel.click(); else if (e.key === 'Enter' && e.target.matches('input') && !save.disabled) save.click(); });
  save.onclick = async () => {
    const roles = [...card.querySelectorAll('.ifrole')], val = (cls, idx) => card.querySelector(`.${cls}[data-idx="${idx}"]`).value.trim();
    if (roles.filter(r => r.value === 'local').length > 1) { say('Роль «Сам пристрій» може мати лише один інтерфейс', 'var(--crit)'); return; }
    const interfaces = roles.map(r => ({index:+r.dataset.idx, role:r.value, name:val('ifname', r.dataset.idx), addrs:val('ifaddr', r.dataset.idx).split(/[\s,;]+/).filter(Boolean)}));
    save.disabled = true; say('Зберігаю…');
    try {
      await apiPost('devices/interfaces', {ip:x.ip, interfaces});
      META = await fetch('api/meta').then(r => r.json());
      const fresh = (await api('devices')).devices, i = devices.findIndex(d => d.ip === x.ip), nx = fresh.find(d => d.ip === x.ip);
      if (i >= 0 && nx) devices[i] = nx;
      state.ifEdit = null; showIfaces(devices);
      const m = document.querySelector('#ifBox .ifmsg'); if (m) { m.textContent = 'Збережено · колектор застосує ролі протягом хвилини'; m.style.color = 'var(--ok)'; }
    } catch (e) { save.disabled = false; say(e.message, 'var(--crit)'); }
  };
}
function openModal(title, sub, body, wide){
  const root = document.getElementById('drawerRoot');
  root.innerHTML = `<div class="scrim" id="scrim"></div><div class="modal glass${wide ? '' : ' narrow'}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <header><div><h3>${esc(title)}</h3>${sub ? `<span class="nat">${sub}</span>` : ''}</div><button class="btn x" id="dx">Закрити</button></header>${body}</div>`;
  const close = () => { root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  document.getElementById('scrim').onclick = close; document.getElementById('dx').onclick = close;
  return {root, close};
}
const formErr = (id, msg) => { const el = document.getElementById(id); if (el) { el.textContent = msg || ''; el.hidden = !msg; } };
function openDevice(dev){
  const c = dev ? dev.config || {} : {}, editing = !!dev;
  let vendor = c.vendor && VENDORS[c.vendor] ? c.vendor : (c.vendor || 'Fortinet');
  const [me, nfPort] = collectorTarget();
  const draw = () => {
    const m = openModal(editing ? `Пристрій ${dev.name}` : 'Підключити пристрій', editing ? esc(dev.ip) : 'Налаштуйте експорт на пристрої та опишіть його тут', `
      <div class="vendors" role="group">${Object.keys(VENDORS).map(k => `<button type="button" data-v="${esc(k)}" aria-pressed="${k === vendor}">${esc(k)}</button>`).join('')}</div>
      <div class="cols"><div><h4>1. Конфігурація на пристрої</h4><pre class="codebox">${esc((VENDORS[vendor] || VENDORS.Fortinet)(me, nfPort))}</pre></div>
      <form class="form" id="devForm"><h4 style="margin:0">2. Опис для FlowTrack</h4>
        <div class="two"><label>IP, з якого йде експорт<input id="fIp" required value="${esc(editing ? dev.ip : '')}" ${editing ? 'readonly' : ''} placeholder="192.0.2.1"></label><label>Назва<input id="fName" value="${esc(c.name || '')}" placeholder="branch-fw01"></label></div>
        <div class="two"><label>Модель<input id="fModel" value="${esc(c.model || '')}" placeholder="FortiGate 60F"></label><label>Вибірка (sampling)<input id="fSamp" value="${esc(c.sampling || '1:1')}"></label></div>
        <div class="two"><label>snmp-index WAN-інтерфейсів (через кому)<input id="fWan" value="${esc((c.wan_ifs || []).join(', '))}" placeholder="1"></label><label>Індекс «сам пристрій» (FortiOS: 0)<input id="fLocal" value="${c.local_if ?? ''}" placeholder="0"></label></div>
        <label>Публічні IP пристрою (через кому)<input id="fPub" value="${esc((c.public_ips || []).join(', '))}" placeholder="198.51.100.10"></label>
        <div class="two"><label>Місто<input id="fCity" value="${esc(c.city || '')}" placeholder="Amsterdam"></label><label>Код країни<input id="fCc" value="${esc(c.country || '')}" maxlength="2" placeholder="NL"></label></div>
        <div class="two"><label>Широта<input id="fLat" value="${c.lat ?? ''}" placeholder="52.37"></label><label>Довгота<input id="fLon" value="${c.lon ?? ''}" placeholder="4.90"></label></div>
        <p class="err" id="fErr" hidden></p>
        <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${editing ? 'Зберегти' : 'Додати пристрій'}</button>${editing && dev.configured ? '<button class="btn" type="button" id="fDel">Видалити опис</button>' : ''}<span class="nat" id="fDelAsk" hidden>Точно видалити? <button class="btn" type="button" id="fDelYes">Так, видалити</button></span></div></form></div>`, true);
    m.root.querySelectorAll('.vendors button').forEach(b => b.onclick = () => { vendor = b.dataset.v; keep(); draw(); restore(); });
    const list = id => document.getElementById(id).value.split(',').map(x => x.trim()).filter(Boolean);
    document.getElementById('devForm').addEventListener('submit', async e => { e.preventDefault(); formErr('fErr');
      try {
        await apiPost('devices/save', {ip:document.getElementById('fIp').value.trim(), name:document.getElementById('fName').value, vendor, model:document.getElementById('fModel').value,
          sampling:document.getElementById('fSamp').value, wan_ifs:list('fWan'), local_if:document.getElementById('fLocal').value.trim(), public_ips:list('fPub'),
          city:document.getElementById('fCity').value, country:document.getElementById('fCc').value, lat:document.getElementById('fLat').value.trim(), lon:document.getElementById('fLon').value.trim()});
        m.close(); META = await fetch('api/meta').then(r => r.json()); render();
      } catch (err) { formErr('fErr', err.message); } });
    const del = document.getElementById('fDel');
    if (del) { del.onclick = () => { document.getElementById('fDelAsk').hidden = false; del.hidden = true; };
      document.getElementById('fDelYes').onclick = async () => { try { await apiPost('devices/delete', {ip:dev.ip}); m.close(); render(); } catch (err) { formErr('fErr', err.message); } }; }
  };
  // keep typed values when switching vendor tabs
  let saved = null;
  const ids = ['fIp', 'fName', 'fModel', 'fSamp', 'fWan', 'fLocal', 'fPub', 'fCity', 'fCc', 'fLat', 'fLon'];
  const keep = () => { saved = Object.fromEntries(ids.map(id => [id, (document.getElementById(id) || {}).value])); };
  const restore = () => { if (saved) ids.forEach(id => { const el = document.getElementById(id); if (el && saved[id] != null) el.value = saved[id]; }); };
  draw();
}

// ===================== users (admin) =====================
const ROLE_LABEL = {admin:'Адміністратор', viewer:'Перегляд'};
function vUsers(){
  const v = document.getElementById('view');
  v.innerHTML = `<div class="grid"><section class="glass panel s12">${ph('users', 'Користувачі', 'адміністратор керує всім; «Перегляд» — лише читання, без змін пристроїв і користувачів', '<button class="btn primary" id="addUser">+ Новий користувач</button>')}<div id="uBox" class="loading"></div></section></div>`;
  document.getElementById('addUser').onclick = () => openUser(null);
  section('uBox', async () => { const r = await fetch('api/users'); if (!r.ok) throw new Error((await r.json()).error || r.status); const users = (await r.json()).users;
    setTimeout(() => document.querySelectorAll('[data-user]').forEach(b => b.onclick = () => openUser(users.find(u => u.name === b.dataset.user))));
    const when = t => t ? new Date(t * 1000).toLocaleString('uk-UA', {day:'numeric', month:'short', hour:'2-digit', minute:'2-digit'}) : 'ще не входив';
    return `<div class="tw"><table><thead><tr><th>Логін</th><th>Роль</th><th>Створено</th><th>Останній вхід</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td><b class="mono">${esc(u.name)}</b>${u.name === ME.name ? ' <span class="tag">це ви</span>' : ''}${u.default_password ? ' <span class="pill warn">стандартний пароль</span>' : ''}</td><td>${u.role === 'admin' ? '<span class="pill info">Адміністратор</span>' : '<span class="tag">Перегляд</span>'}</td>
        <td class="nat">${when(u.created)}</td><td class="nat">${when(u.last_login)}</td><td><button class="btn" data-user="${esc(u.name)}">Змінити</button></td></tr>`).join('')}</tbody></table></div>`; });
}
function genPassword(){ const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const b = new Uint32Array(14); crypto.getRandomValues(b); return [...b].map(x => a[x % a.length]).join(''); }
function openUser(u){
  const editing = !!u, self = editing && u.name === ME.name;
  const m = openModal(editing ? `Користувач ${u.name}` : 'Новий користувач', '', `<form class="form" id="uForm">
    <label>Логін<input id="uName" ${editing ? `value="${esc(u.name)}" readonly` : 'required placeholder="olena"'} autocomplete="off"></label>
    <label>Роль<select id="uRole" ${self ? 'disabled' : ''}><option value="viewer">Перегляд — лише читання</option><option value="admin">Адміністратор — повний доступ</option></select></label>
    <label>${editing ? 'Новий пароль (залиште порожнім, щоб не змінювати)' : 'Пароль'}<input id="uPass" type="text" autocomplete="new-password" ${editing ? '' : 'required'} minlength="8" placeholder="щонайменше 8 символів"></label>
    <button class="lnk" type="button" id="uGen" style="justify-self:start">Згенерувати пароль</button>
    <p class="err" id="uErr" hidden></p>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" type="submit">${editing ? 'Зберегти' : 'Створити'}</button>${editing && !self ? '<button class="btn" type="button" id="uDel">Видалити користувача</button><span class="nat" id="uDelAsk" hidden>Точно? <button class="btn" type="button" id="uDelYes">Так, видалити</button></span>' : ''}</div>
    ${self ? '<p class="note" style="margin:0">Власний пароль зручніше змінити в меню користувача — там потрібен поточний пароль.</p>' : ''}</form>`);
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
  w.innerHTML = `${ME.default_password ? '<button class="pill warn" id="pwWarn" style="border:0;cursor:pointer" title="Змініть стандартний пароль">змініть пароль</button>' : ''}
    <button class="user" id="userBtn" aria-haspopup="menu" aria-expanded="false"><span class="avatar">${esc(ME.name[0].toUpperCase())}</span><span class="who"><b>${esc(ME.name)}</b><small>${ROLE_LABEL[ME.role]}</small></span></button>
    <div class="menu glass" id="userMenu" role="menu" hidden><button role="menuitem" id="miPass">Змінити пароль</button>${isAdmin() ? '<button role="menuitem" id="miUsers">Користувачі</button>' : ''}<button role="menuitem" id="miOut">Вийти</button></div>`;
  const btn = document.getElementById('userBtn'), menu = document.getElementById('userMenu');
  btn.onclick = e => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden)); };
  menu.addEventListener('click', () => closeUserMenu());
  document.getElementById('miPass').onclick = openPassword;
  const pw = document.getElementById('pwWarn'); if (pw) pw.onclick = openPassword;
  const mu = document.getElementById('miUsers'); if (mu) mu.onclick = () => { state.view = 'users'; render(); };
  document.getElementById('miOut').onclick = async () => { try { await apiPost('logout', {}); } catch (e) {} ME = null; showLogin(); };
}
function closeUserMenu(){ const m = document.getElementById('userMenu'), b = document.getElementById('userBtn'); if (m) m.hidden = true; if (b) b.setAttribute('aria-expanded', 'false'); }
// one global listener: any click outside the user menu, or Esc, closes it
document.addEventListener('click', e => { if (!e.target.closest || !e.target.closest('#userWrap')) closeUserMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeUserMenu(); });
function openPassword(){
  const m = openModal('Змінити пароль', ME.default_password ? 'Зараз використовується стандартний пароль' : '', `<form class="form" id="pForm">
    <label>Поточний пароль<input id="pCur" type="password" required autocomplete="current-password"></label>
    <label>Новий пароль<input id="pNew" type="password" required minlength="8" autocomplete="new-password" placeholder="щонайменше 8 символів"></label>
    <label>Повторіть новий пароль<input id="pNew2" type="password" required minlength="8" autocomplete="new-password"></label>
    <p class="err" id="pErr" hidden></p><p class="note" id="pOk" hidden style="color:var(--ok)">Пароль змінено. Інші сесії цього користувача завершено.</p>
    <div><button class="btn primary" type="submit">Змінити пароль</button></div></form>`);
  document.getElementById('pCur').focus();
  document.getElementById('pForm').addEventListener('submit', async e => { e.preventDefault(); formErr('pErr');
    const n1 = document.getElementById('pNew').value, n2 = document.getElementById('pNew2').value;
    if (n1 !== n2) return formErr('pErr', 'Нові паролі не збігаються');
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
    <div class="brand" style="padding:0"><svg width="40" height="34" viewBox="0 0 40 34" aria-hidden="true"><path d="M3 10c6-6 11-6 17 0s11 6 17 0" fill="none" stroke="#27D3F5" stroke-width="4.5" stroke-linecap="round"/><path d="M3 22c6-6 11-6 17 0s11 6 17 0" fill="none" stroke="#2F7BFF" stroke-width="4.5" stroke-linecap="round"/></svg><div><b>FlowTrack</b><small>Вхід до панелі</small></div></div>
    ${msg ? `<p class="note" style="margin:0">${esc(msg)}</p>` : ''}
    <label>Логін<input id="lUser" required autocomplete="username" autofocus></label>
    <label>Пароль<input id="lPass" type="password" required autocomplete="current-password"></label>
    <p class="err" id="lErr" hidden></p>
    <button class="btn primary" type="submit" style="justify-self:stretch;text-align:center;padding:9px">Увійти</button></form>`;
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
  root.innerHTML = `<div class="scrim" id="scrim"></div><aside class="drawer glass" role="dialog" aria-modal="true" aria-label="Хост ${esc(ip)}"><div class="loading" style="min-height:200px"></div></aside>`;
  const close = () => { if (hc) { hc.dispose(); const i = charts.indexOf(hc); if (i >= 0) charts.splice(i, 1); } root.innerHTML = ''; document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  let hc = null; document.addEventListener('keydown', onKey); document.getElementById('scrim').onclick = close;
  let d; try { d = await api('host', {ip}); } catch (e) { root.querySelector('.drawer').innerHTML = errBox(e); return; }
  const s = d.summary;
  root.querySelector('.drawer').innerHTML = `<header><div><h3>${esc(d.host.name || ip)}</h3><div class="ipl" style="color:var(--ink2)">${esc(ip)} · ${d.host.private ? 'внутрішня адреса' : 'публічна адреса'}</div></div><button class="btn x" id="dx">Закрити</button></header>
    <div class="dk"><div><span>↓ download</span><b class="d">${fmtB(s.down)}</b></div><div><span>↑ upload</span><b class="u">${fmtB(s.up)}</b></div><div><span>flows</span><b>${fmtN(s.flows)}</b></div></div>
    <div><h4>Трафік · ${rangeLabel()}</h4><div class="chart short" id="cHost"></div></div>
    <div><h4>Сервіси</h4><div class="tagrow">${d.services.rows.map(g => `<span class="tag">${esc(g.k)} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>Протоколи</h4><div class="tagrow">${d.ports.rows.map(g => `<span class="tag mono">${esc(g.k)} · ${fmtB(tot(g))}</span>`).join('') || '—'}</div></div>
    <div><h4>Куди ходить</h4><div class="blist">${d.dests.rows.map(g => `<div class="brow" style="cursor:default"><span class="n"><span class="idot ext"></span>${esc(g.k)} <span class="nat">${esc([g.service, g.city || ccName(g.country)].filter(Boolean).join(' · '))}</span></span><span class="t">${fmtB(tot(g))}</span><span class="p"></span></div>`).join('')}</div></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" id="dfilter">Фільтрувати все за цим хостом</button></div>`;
  const before = charts.length; trendChart(document.getElementById('cHost'), d.series, true); hc = charts[before];
  document.getElementById('dx').onclick = close;
  document.getElementById('dfilter').onclick = () => { close(); addFilter('ip', ip); };
  document.getElementById('dx').focus();
}

// ===================== shell =====================
const VIEWS = {overview:vOverview, flows:vFlows, talkers:vTalkers, apps:vApps, ports:vPorts, geo:vGeo, threats:vThreats, devices:vDevices, users:vUsers};
function renderShell(){
  document.getElementById('nav').innerHTML = NAV.filter(n => n[3] !== 'admin' || isAdmin()).map(([k, l, d]) => `<button data-view="${k}" ${state.view === k ? 'aria-current="page"' : ''}>${icon(d)}${l}</button>`).join('');
  document.querySelectorAll('#nav button').forEach(b => b.onclick = () => { state.view = b.dataset.view; state.sel = null; state.openFlow = null; render(); });
  document.getElementById('chips').innerHTML = state.filters.map((f, i) => `<span class="fchip ${f.neg ? 'neg' : ''}"><span class="k">${FILTER_LABEL[f.k] || f.k}${f.neg ? ' ≠' : ':'}</span>${esc(f.k === 'device' ? devName(f.v) : f.v)}<button aria-label="Прибрати фільтр" data-i="${i}">×</button></span>`).join('')
    + (state.filters.length ? '<button class="lnk" id="clearF">Скинути всі</button>' : '');
  document.querySelectorAll('#chips button[data-i]').forEach(b => b.onclick = () => { state.filters.splice(+b.dataset.i, 1); render(); });
  const cf = document.getElementById('clearF'); if (cf) cf.onclick = () => { state.filters = []; render(); };
  const ds = document.getElementById('devSel'), df = state.filters.find(f => f.k === 'device' && !f.neg);
  ds.innerHTML = `<option value="">Усі пристрої (${META.devices.length})</option>` + META.devices.map(d => `<option value="${esc(d.ip)}">${esc(d.name)}${d.vendor ? ' · ' + esc(d.vendor) : ''}</option>`).join('');
  ds.value = df ? df.v : '';
  document.getElementById('rangeSel').value = state.range;
}
function saveUrl(){ const p = new URLSearchParams({v:state.view, r:state.range}); if (state.filters.length) p.set('f', JSON.stringify(state.filters)); history.replaceState(null, '', '#' + p); }
function loadUrl(){ try { const p = new URLSearchParams(location.hash.slice(1)); if (p.get('v') && VIEWS[p.get('v')]) state.view = p.get('v'); if (p.get('r')) state.range = p.get('r'); if (p.get('f')) { state.filters = []; JSON.parse(p.get('f')).forEach(putFilter); } } catch (e) {} }
function render(){ if (state.view === 'users' && !isAdmin()) state.view = 'overview'; renderSeq++; cleanup(); renderShell(); renderUser(); saveUrl(); VIEWS[state.view](); }

document.getElementById('devSel').onchange = e => { state.filters = state.filters.filter(f => f.k !== 'device'); if (e.target.value) putFilter({k:'device', v:e.target.value, neg:false}); render(); };
document.getElementById('rangeSel').onchange = e => { state.range = e.target.value; render(); };
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
    document.getElementById('collState').textContent = d.length ? (online ? 'Колектор онлайн' : 'Немає даних') : 'Чекаю на експорт';
    document.getElementById('collDot').className = 'dot' + (online ? '' : ' crit');
    document.getElementById('expCount').textContent = `${online}/${d.length} експортер${d.length === 1 ? '' : 'и'}`;
    ingHist.push(rps); if (ingHist.length > 40) ingHist.shift();
    document.getElementById('ingV').innerHTML = `${rps.toFixed(1)} <small>записів/с</small>`;
    document.getElementById('ingM').style.width = Math.max(2, Math.min(100, 100 * rps / 2000)).toFixed(1) + '%';
    const max = Math.max(...ingHist, 1); document.getElementById('ingS').innerHTML = `<polyline points="${ingHist.map((x, i) => `${(i / 39 * 200).toFixed(1)},${(28 - x / max * 24).toFixed(1)}`).join(' ')}" fill="none" stroke="${C.down}" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
    const al = (await fetch('api/alerts').then(r => r.json())).alerts || [];
    document.getElementById('bellBadge').hidden = !al.some(a => a.sev !== 'info');
  } catch (e) { document.getElementById('collState').textContent = 'API недоступне'; document.getElementById('collDot').className = 'dot crit'; }
}

(async () => {
  loadUrl();
  const r = await fetch('api/me').catch(() => null);
  if (!r || r.status === 401) { showLogin(); setInterval(() => ME && health(), 60000); return; }
  ME = await r.json();
  try { META = await fetch('api/meta').then(x => x.json()); } catch (e) {}
  render(); health(); setInterval(() => ME && health(), 60000);
})();
