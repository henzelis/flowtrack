// (1.17.0) FlowTrack by TELESPHERA: the TELESPHERA globe — latitude arcs of a tilted sphere, the front ones solid, the
// back dissolving into faint dots, nodes at the ends of arcs — drawn in code as on telesphera.net (same geometry), on
// every canvas[data-logo] (the sidebar, the sign-in box; the ones made later too) and once as the tab's icon. It turns
// slowly (~18 s a turn, 30 frames/s on a 36 px canvas: nothing on a NOC screen); still when the system asks for less motion.
(function () {
  const RINGS = [
    {lat: -0.82, start: 3.30, span: 2.60, w: 0.85, dots: true},
    {lat: -0.64, start: 3.00, span: 3.20, w: 1.00},
    {lat: -0.40, start: 2.45, span: 4.00, w: 1.30, node: 0.05},
    {lat: -0.16, start: 2.90, span: 3.40, w: 0.95, dots: true},
    {lat: 0.08, start: 2.35, span: 4.30, w: 1.45, node: 0.96},
    {lat: 0.30, start: 3.05, span: 3.60, w: 0.95, dots: true},
    {lat: 0.52, start: 2.55, span: 4.10, w: 1.35, node: 0.98},
    {lat: 0.74, start: 3.20, span: 3.10, w: 1.05, node: 0.94},
  ];
  const TILT = -0.36, SEG = 48, PI2 = Math.PI * 2;
  function paint(c, angle) {
    const ctx = c.getContext('2d'), w = c.width, h = c.height;
    ctx.clearRect(0, 0, w, h);
    const R = Math.min(w, h) * 0.45, cx = w / 2, cy = h / 2, sc = w / 38;
    if (w < 128) { ctx.strokeStyle = ctx.fillStyle = '#3AC9FF'; }     // small: one colour, as the site's nav mark
    else {
      const g = ctx.createLinearGradient(cx - R, cy - R, cx + R, cy + R);
      g.addColorStop(0, '#2BEAFF'); g.addColorStop(0.5, '#4D7CFF'); g.addColorStop(1, '#8B5CF6');
      ctx.strokeStyle = ctx.fillStyle = g;
    }
    ctx.lineCap = 'round';
    const ca = Math.cos(angle), sa = Math.sin(angle), ct = Math.cos(TILT), st = Math.sin(TILT), p = {x: 0, y: 0, z: 0};
    const proj = (x0, y0, z0) => {
      const x = x0 * ca + z0 * sa, z1 = -x0 * sa + z0 * ca;
      p.x = cx + x * R; p.y = cy - (y0 * ct - z1 * st) * R; p.z = y0 * st + z1 * ct;
    };
    for (const r of RINGS) {
      const rr = Math.sqrt(Math.max(1 - r.lat * r.lat, 0)), at = i => r.start + (i / SEG) * r.span;
      ctx.lineWidth = r.w * sc;
      if (r.dots) {
        for (let i = 0; i <= SEG; i += 3) {
          proj(rr * Math.cos(at(i)), r.lat, rr * Math.sin(at(i)));
          const front = p.z >= 0;
          ctx.globalAlpha = front ? 0.55 + 0.45 * p.z : 0.14;
          ctx.beginPath(); ctx.arc(p.x, p.y, r.w * sc * (front ? 0.62 : 0.42), 0, PI2); ctx.fill();
        }
        continue;
      }
      ctx.globalAlpha = 0.92;
      let drawing = false;
      ctx.beginPath();
      for (let i = 0; i <= SEG; i++) {
        proj(rr * Math.cos(at(i)), r.lat, rr * Math.sin(at(i)));
        if (p.z >= 0) { if (drawing) ctx.lineTo(p.x, p.y); else { ctx.moveTo(p.x, p.y); drawing = true; } }
        else if (drawing) { ctx.stroke(); drawing = false; ctx.beginPath(); }
      }
      if (drawing) ctx.stroke();
      ctx.globalAlpha = 0.13;                                          // the back of the shell: faint dots
      for (let i = 0; i <= SEG; i += 4) {
        proj(rr * Math.cos(at(i)), r.lat, rr * Math.sin(at(i)));
        if (p.z < 0) { ctx.beginPath(); ctx.arc(p.x, p.y, 0.55 * sc, 0, PI2); ctx.fill(); }
      }
      if (r.node !== undefined) {
        const t = r.start + r.node * r.span;
        proj(rr * Math.cos(t), r.lat, rr * Math.sin(t));
        if (p.z >= 0) { ctx.globalAlpha = 0.95; ctx.beginPath(); ctx.arc(p.x, p.y, 1.5 * sc, 0, PI2); ctx.fill(); }
      }
    }
    ctx.globalAlpha = 1;
  }
  function fit(c) {
    const k = Math.min(window.devicePixelRatio || 1, 2), b = c.getBoundingClientRect();
    const w = Math.max(Math.round(b.width * k), 1), h = Math.max(Math.round(b.height * k), 1);
    if (c.width !== w || c.height !== h) { c.width = w; c.height = h; }
  }
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let angle = 0.4, last = 0, acc = 1;
  const all = () => document.querySelectorAll('canvas[data-logo]').forEach(c => { if (c.clientWidth) { fit(c); paint(c, angle); } });
  function frame(now) {
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now; angle += dt * 0.34; acc += dt;
    if (acc >= 1 / 30) { acc = 0; all(); }
    requestAnimationFrame(frame);
  }
  function icon() {                       // the tab's icon: the globe, still, in its colours
    const c = document.createElement('canvas');
    c.width = c.height = 128;
    paint(c, 0.4);
    const l = document.createElement('link');
    l.rel = 'icon'; l.href = c.toDataURL('image/png');
    document.head.appendChild(l);
  }
  window.addEventListener('DOMContentLoaded', () => {
    icon();
    if (!still) { requestAnimationFrame(t => { last = t; frame(t); }); return; }
    all();                                // still: drawn once, and again when a page puts a new one in
    new MutationObserver(() => requestAnimationFrame(all)).observe(document.body, {childList: true, subtree: true});
  });
})();
