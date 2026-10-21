"""Scheduled reports (1.10.0): a PDF of the last day, week or month — totals against the period before, traffic over
time, the busiest hosts, outside networks, services, countries, named networks, security events and the devices —
e-mailed through the mail server of Settings -> Notifications to the report's own recipients.

The numbers come from the same queries as the pages (the web service runs the reports: `call(path, q)` is its API in
process), so a report never disagrees with what FlowTrack shows for that period. A period is whole local days of the
report's time zone: a daily report covers yesterday, a weekly one Monday to Sunday, a monthly one the calendar month,
each sent at its hour on the first day after it. A server that was off at that hour sends it when it is back (within
the next period); a failed sending is tried again every 15 minutes, 8 times.

Reports live in STATE_DIR/reports.json, what was sent in reports_state.json."""
import datetime
import html
import io
import json
import os
import re
import threading
import time
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

import detect
import notify
from common import N_, STATE_DIR, get_lang, known_lang, set_lang, tr, trn

CONFIG = os.path.join(STATE_DIR, 'reports.json')
STATE = os.path.join(STATE_DIR, 'reports_state.json')
HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(HERE, 'report', 'fonts')
EVERY = ('day', 'week', 'month')
SECTIONS = ('summary', 'chart', 'hosts', 'outside', 'services', 'countries', 'networks', 'capacity', 'events', 'devices')
NEW_SECTIONS = {'capacity': '1.13.0'}      # added to the reports made before, once (`seen` remembers what a report was offered)
TRAFFIC = ('internet', 'internal', 'all')
FILTER_KEYS = ('ip', 'dst', 'net', 'service', 'l7', 'country', 'city', 'port', 'device', 'asn', 'dir', 'proto', 'in_if', 'out_if', 'iface')
MAX_REPORTS = 20
RETRY, TRIES = 900, 8
TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
_lock = threading.Lock()


# ------------------------------------------------------------------ settings

def system_tz():
    """The server's own time zone name (Europe/Kyiv), UTC when it has none."""
    try:
        name = os.path.realpath('/etc/localtime').split('/zoneinfo/', 1)[1]
        ZoneInfo(name)
        return name
    except (IndexError, ZoneInfoNotFoundError, ValueError, OSError):
        return 'UTC'


def blank():
    return {'id': '', 'name': '', 'on': True, 'every': 'week', 'wday': 0, 'mday': 1, 'at': '07:00', 'tz': system_tz(), 'lang': 'uk', 'to': [],
            't': 'internet', 'f': [], 'sections': list(SECTIONS), 'seen': list(SECTIONS), 'created': 0}


def load():
    try:
        with open(CONFIG) as f:
            saved = json.load(f)
    except (FileNotFoundError, ValueError):
        return []
    out = []
    for r in saved.get('reports') or []:
        if isinstance(r, dict) and r.get('id'):
            x = blank()
            x.update({k: v for k, v in r.items() if k in x})
            # (1.13.0) a part that did not exist when the report was made is switched on in it once
            seen = r.get('seen') or [k for k in SECTIONS if k not in NEW_SECTIONS]
            x['sections'] = [k for k in SECTIONS if k in x['sections'] or k not in seen]
            x['seen'] = list(SECTIONS)
            out.append(x)
    return out


def _write(path, data):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def save(reports):
    _write(CONFIG, {'reports': reports})


def load_state():
    try:
        with open(STATE) as f:
            s = json.load(f)
        return s if isinstance(s, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def validate(body, old=None):
    """One report from the UI, checked (ValueError for people); a new one gets its id."""
    r = blank()
    if old:
        r.update(old)
    name = str(body.get('name') or '').strip()
    if not name or len(name) > 80:
        raise ValueError(tr('Give the report a name (up to 80 characters).'))
    r['name'] = name
    r['on'] = bool(body.get('on', True))
    if body.get('every') not in EVERY:
        raise ValueError(tr('Choose how often the report is sent.'))
    r['every'] = body['every']
    # (1.10.0) the day it goes out: a weekday (0 = Monday) for a weekly report, a day of the month 1–28 for a monthly one
    try:
        r['wday'] = int(body.get('wday', r['wday']))
        r['mday'] = int(body.get('mday', r['mday']))
        assert 0 <= r['wday'] <= 6 and 1 <= r['mday'] <= 28
    except (TypeError, ValueError, AssertionError):
        raise ValueError(tr('The day of sending is a weekday, or a day of the month from 1 to 28.')) from None
    at = str(body.get('at') or '07:00').strip()
    if not TIME_RE.match(at):
        raise ValueError(tr('The time of sending is HH:MM, e.g. 07:00.'))
    r['at'] = at
    tz = str(body.get('tz') or system_tz()).strip()
    try:
        ZoneInfo(tz)                  # an old name (Europe/Kiev) is fine where the system still has it
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(tr('Unknown time zone {tz}.', tz=tz[:60])) from None
    r['tz'] = tz
    if known_lang(body.get('lang')):
        r['lang'] = body['lang']
    to = body.get('to') or []
    to = [x.strip() for x in (re.split(r'[\s,;]+', to) if isinstance(to, str) else to) if str(x).strip()]
    bad = [x for x in to if not notify.MAIL_RE.match(str(x))]
    if bad:
        raise ValueError(tr('Not an e-mail address: {addr}.', addr=str(bad[0])[:80]))
    if len(to) > 20:
        raise ValueError(tr('At most 20 recipients.'))
    r['to'] = to
    r['t'] = body.get('t') if body.get('t') in TRAFFIC else 'internet'
    flt = body.get('f') or []
    if not isinstance(flt, list) or len(flt) > 20:
        raise ValueError(tr('The filters of the report are wrong.'))
    r['f'] = [{'k': f['k'], 'v': str(f.get('v', ''))[:200], 'neg': bool(f.get('neg'))}
              for f in flt if isinstance(f, dict) and f.get('k') in FILTER_KEYS and str(f.get('v', '')).strip()]
    secs = [s for s in body.get('sections') or [] if s in SECTIONS]
    if not secs:
        raise ValueError(tr('Choose at least one part of the report.'))
    r['sections'] = [s for s in SECTIONS if s in secs]
    r['seen'] = list(SECTIONS)
    if not r['id']:
        r['id'] = uuid.uuid4().hex[:10]
        r['created'] = int(time.time())
    return r


def once(body, t0, t1, now=None):
    """(1.10.0) A report of any period, made now (an attack, an outage): the settings of a report without the schedule.
    -> the report (every = 'custom'); ValueError for people."""
    now = now or time.time()
    if not (isinstance(t0, int) and isinstance(t1, int)) or t1 - t0 < 300:
        raise ValueError(tr('The period of the report must be at least 5 minutes long.'))
    if t0 > now - 60:
        raise ValueError(tr('The period of the report must start in the past.'))
    r = validate(dict(body, every='day', on=False, name=body.get('name') or tr('Report for a period')))
    r.update(every='custom', id='', created=0)
    return r


def upsert(body):
    """Saves a new or a changed report; a new one starts with the next period (Send now covers the last one)."""
    with _lock:
        reports = load()
        old = next((r for r in reports if r['id'] == body.get('id')), None) if body.get('id') else None
        if body.get('id') and not old:
            raise ValueError(tr('There is no such report any more.'))
        if not old and len(reports) >= MAX_REPORTS:
            raise ValueError(tr('At most {n} reports.', n=MAX_REPORTS))
        r = validate(body, old)
        if old:
            reports[reports.index(old)] = r
        else:
            reports.append(r)
            st = load_state()
            st[r['id']] = {'done': period(r, time.time())[1]}
            _write(STATE, st)
        save(reports)
        return r


def remove(rid):
    with _lock:
        reports = load()
        if not any(r['id'] == rid for r in reports):
            raise ValueError(tr('There is no such report any more.'))
        save([r for r in reports if r['id'] != rid])
        st = load_state()
        st.pop(rid, None)
        _write(STATE, st)


# ------------------------------------------------------------------ periods

def period(r, now, back=0):
    """-> (t0, t1): the last whole period of the report's time zone that ended by `now` (back=1: the one before it).
    A period ends at midnight of the day the report goes out: a daily one covers the day before, a weekly one the 7 days
    before its weekday (Monday: Monday to Sunday), a monthly one the month before its day (the 1st: the calendar
    month; the 15th: 15 September to 14 October)."""
    tz = ZoneInfo(r['tz'])
    d = datetime.datetime.fromtimestamp(now, tz).date()
    if r['every'] == 'day':
        end = d - datetime.timedelta(days=back)
        start = end - datetime.timedelta(days=1)
    elif r['every'] == 'week':
        end = d - datetime.timedelta(days=(d.weekday() - r.get('wday', 0)) % 7 + 7 * back)
        start = end - datetime.timedelta(days=7)
    else:
        n = r.get('mday', 1)
        end = d.replace(day=n) if d.day >= n else _month_before(d.replace(day=n))
        for _ in range(back):
            end = _month_before(end)
        start = _month_before(end)
    ts = lambda x: int(datetime.datetime.combine(x, datetime.time(), tz).timestamp())     # noqa: E731
    return ts(start), ts(end)


def _month_before(d):
    """The same day (1–28) a month earlier."""
    return (d.replace(day=1) - datetime.timedelta(days=1)).replace(day=d.day)


def send_time(r, t1):
    """When the period that ends at t1 is sent: the report's hour on the first day after it."""
    tz = ZoneInfo(r['tz'])
    h, m = map(int, r['at'].split(':'))
    d = datetime.datetime.fromtimestamp(t1, tz).date()
    return int(datetime.datetime.combine(d, datetime.time(h, m), tz).timestamp())


def period_label(r, t0, t1):
    """A day (2026-10-17), a calendar month (October 2026), days (2026-10-12 — 2026-10-18), or, for a period that
    does not start or end at midnight, with the times."""
    tz = ZoneInfo(r['tz'])
    a, e = datetime.datetime.fromtimestamp(t0, tz), datetime.datetime.fromtimestamp(t1, tz)
    if (a.hour, a.minute, e.hour, e.minute) != (0, 0, 0, 0):
        return f"{a.strftime('%Y-%m-%d %H:%M')} — {e.strftime('%Y-%m-%d %H:%M')}"
    b = e - datetime.timedelta(days=1)
    if a.date() == b.date():
        return a.strftime('%Y-%m-%d')
    if a.day == 1 and e.day == 1 and (a.year, a.month) == (b.year, b.month):
        return f"{month_name(a.month)} {a.year}"
    return f"{a.strftime('%Y-%m-%d')} — {b.strftime('%Y-%m-%d')}"


def month_name(m):
    return tr(MONTHS[m - 1])


MONTHS = (N_('January'), N_('February'), N_('March'), N_('April'), N_('May'), N_('June'), N_('July'), N_('August'),
          N_('September'), N_('October'), N_('November'), N_('December'))


# ------------------------------------------------------------------ data

def collect(r, t0, t1, call):
    """Everything the report shows, from the API (`call(path, q)` -> its JSON as a dict)."""
    base = {'from': [str(t0)], 'to': [str(t1)], 'f': [json.dumps(r['f'])], 't': [r['t']]}
    q = lambda **kw: dict(base, **{k: [str(v)] for k, v in kw.items()})      # noqa: E731
    sec = set(r['sections'])
    d = {'summary': call('/api/summary', q())}
    if 'chart' in sec or 'summary' in sec:
        d['series'] = call('/api/series', q())
    for name, dim, n in (('hosts', 'int_ip', 15), ('outside', 'asn', 10), ('services', 'service', 10),
                         ('countries', 'country', 10), ('networks', 'net', 15)):
        if name in sec:
            d[name] = call('/api/top', q(dim=dim, limit=n))
    if 'events' in sec:
        d['events'] = call('/api/alerts', q(tz=r['tz']))['alerts']
    if 'devices' in sec:
        d['devices'] = call('/api/devices', {})['devices']
    if 'capacity' in sec:          # (1.13.0) whole days up to now in the report's zone: at least 30 for a trend
        d['capacity'] = call('/api/capacity', {'days': [str(max(30, -(-(t1 - t0) // 86400)))], 'tz': [r['tz']], 'f': base['f']})
    return d


# ------------------------------------------------------------------ the PDF

INK, INK2, INK3 = '#1C2333', '#5B6478', '#8A93A8'
NAVY, BLUE, HAIR, PANEL = '#0B1736', '#2F7BFF', '#E3E8F2', '#F4F6FA'
DOWN, UP = '#16B5D8', '#FF9F43'          # the page's cyan is too pale on paper; the same hue, deeper
SEV = {'crit': '#E5484D', 'warn': '#F5A524', 'info': '#3E8ED0'}
# (1.17.0) a colour per kind of event, as on the Events page (web/app.js EV_COLOR); the yellows and the lime deeper
# for paper
EV_COLORS = {'port_scan': '#FF9F43', 'brute_force': '#FF5C7A', 'probes': '#6E9BFF', 'heavy_client': '#E0B03C', 'ddos': '#E8384F',
             'inside_scan': '#C77DFF', 'lateral_scan': '#8B5CFF', 'link_load': '#16B5D8', 'malware_contact': '#FF4FA0',
             'listed_contact': '#E98BB2', 'listed_inbound': '#2F7BFF', 'sustained_upload': '#1FBF83', 'burst': '#2FB3A0',
             'new_country': '#84C11F'}
_fonts = []


def _register():
    if _fonts:
        return
    from reportlab.lib.fonts import addMapping
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for name, f in (('FT', 'manrope-400.ttf'), ('FT-Bold', 'manrope-700.ttf'), ('FT-Black', 'manrope-800.ttf')):
        pdfmetrics.registerFont(TTFont(name, os.path.join(FONTS, f)))
    addMapping('FT', 0, 0, 'FT')
    addMapping('FT', 1, 0, 'FT-Bold')
    addMapping('FT', 0, 1, 'FT')
    addMapping('FT', 1, 1, 'FT-Bold')
    _fonts.append(1)


_regions = {}


def country(code, lang):
    if not _regions:
        try:
            with open(os.path.join(HERE, 'report', 'regions.json')) as f:
                _regions.update(json.load(f))
        except (OSError, ValueError):
            _regions['en'] = {}
    names = _regions.get(lang) or _regions.get('en') or {}
    return names.get(code) or code or tr('unknown')


def fmt_b(b):
    b, i, u = float(b or 0), 0, ('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    while b >= 1000 and i < 5:
        b, i = b / 1000, i + 1
    return f"{b:.2f} {u[i]}" if i >= 2 and b < 10 else f"{b:.1f} {u[i]}" if i >= 2 and b < 100 else f"{b:.0f} {u[i]}"


def fmt_n(n):
    return f"{int(n or 0):,}".replace(',', '\u00a0')        # 557 470: grouped by a no-break space, in any language


def fmt_rate(bps):
    for d, s in ((1e9, 'Gbit/s'), (1e6, 'Mbit/s'), (1e3, 'kbit/s')):
        if bps >= d:
            v = bps / d
            return f"{v:.2f} {tr(s)}" if v < 10 else f"{v:.1f} {tr(s)}" if v < 100 else f"{v:.0f} {tr(s)}"
    return f"{bps:.0f} {tr('bit/s')}"


def delta(cur, prev):
    """'↑ 12%' against the period before, or '' when there is nothing to compare with."""
    if not prev:
        return ''
    p = (cur - prev) * 100 / prev
    if abs(p) < 0.5:
        return '= 0%'
    return f"{'↑' if p > 0 else '↓'} {abs(p):.0f}%"


def events_charts(ev, t0, t1, tz_name, W, tz):
    """(1.17.0) The events' two charts for the report: stacked bars of how many began in each step, by kind (left),
    and a ring of each kind's share (right); a note when some began before the period."""
    from reportlab.graphics.shapes import Drawing, Line, Rect, String, Wedge
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    C = colors.HexColor
    st = detect.stats(ev, t0, t1, tz_name)
    s, kinds = st['series'], sorted(st['kinds'].items(), key=lambda kv: -kv[1]['n'])
    step, start = s['step'], s['from']
    n_steps = max(1, -(-(s['to'] - start) // step))
    col = {}
    for b, k, n in s['rows']:
        col.setdefault(b, {})[k] = n
    # the bars
    bw, bh, lm, bm = W * 0.64, 46 * mm, 8 * mm, 6 * mm
    d = Drawing(bw, bh + bm + 4)
    pw, ph = bw - lm - 2, bh
    top = max([sum(v.values()) for v in col.values()] or [1])
    tick = next(t for t in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10000, 10 ** 9) if top <= t * 4)
    ymax = tick * max(1, -(-top // tick))
    y = lambda v: bm + ph * v / ymax                         # noqa: E731
    v = 0
    while v <= ymax:
        d.add(Line(lm, y(v), lm + pw, y(v), strokeColor=C(HAIR), strokeWidth=0.5))
        d.add(String(lm - 2, y(v) - 2.3, f'{v:g}', fontName='FT', fontSize=6.3, fillColor=C(INK3), textAnchor='end'))
        v += tick
    slot = pw / n_steps
    w = max(min(slot * 0.74, 9 * mm), 0.8)
    for i in range(n_steps):
        b, base = start + i * step, 0
        for k, _ in kinds:
            n = col.get(b, {}).get(k, 0)
            if n:
                d.add(Rect(lm + i * slot + (slot - w) / 2, y(base), w, y(base + n) - y(base), fillColor=C(EV_COLORS.get(k, INK3)), strokeColor=None))
                base += n
    d.add(Line(lm, bm, lm + pw, bm, strokeColor=C(INK3), strokeWidth=0.6))
    fmt = '%d.%m' if step >= 86400 else '%d.%m %H:%M' if t1 - t0 > 86400 + 3600 else '%H:%M'
    every = max(1, -(-n_steps // 7))
    for i in range(0, n_steps, every):
        t = start + i * step
        d.add(String(lm + i * slot + slot / 2, 0.5, datetime.datetime.fromtimestamp(max(t, t0), tz).strftime(fmt), fontName='FT', fontSize=6.1,
                     fillColor=C(INK3), textAnchor='middle'))
    # the ring
    rw = W - bw
    R, r0 = 20 * mm, 13 * mm
    p = Drawing(rw, bh + bm + 4)
    cx, cy, a = rw / 2, (bh + bm + 4) / 2, 90.0
    for k, v in kinds:
        sweep = 360.0 * v['n'] / max(st['total'], 1)
        if sweep >= 359.99:
            p.add(Wedge(cx, cy, R, 0, 359.99, radius1=r0, fillColor=C(EV_COLORS.get(k, INK3)), strokeColor=colors.white, strokeWidth=0))
        elif sweep > 0:
            p.add(Wedge(cx, cy, R, a - sweep, a, radius1=r0, fillColor=C(EV_COLORS.get(k, INK3)), strokeColor=colors.white, strokeWidth=1))
        a -= sweep
    p.add(String(cx, cy + 0.5, f"{st['total']:,}".replace(',', '\u00a0'), fontName='FT-Black', fontSize=14, fillColor=C(INK), textAnchor='middle'))
    p.add(String(cx, cy - 8, tr('events'), fontName='FT', fontSize=7, fillColor=C(INK2), textAnchor='middle'))
    head = ParagraphStyle('evh', fontName='FT-Bold', fontSize=7.4, leading=9, textColor=C(INK2))
    step_txt = tr('a day') if step >= 86400 else trn(step // 3600, '{n} hour', '{n} hours') if step >= 3600 else trn(step // 60, '{n} minute', '{n} minutes')
    t = Table([[Paragraph(esc_x(tr('EVENTS OVER TIME · ONE BAR = {step}', step=step_txt.upper())), head), Paragraph(esc_x(tr('BY KIND')), head)], [d, p]],
              colWidths=[bw, rw])
    t.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0), ('VALIGN', (0, 0), (-1, -1), 'BOTTOM'),
                           ('ALIGN', (1, 0), (1, -1), 'CENTER'), ('BOTTOMPADDING', (0, 0), (-1, 0), 2)]))
    out = [t, Spacer(0, 2 * mm)]
    if st['before']:
        out += [Paragraph(esc_x(trn(st['before'], '{n} event began before the period and is not drawn here.', '{n} events began before the period and are not drawn here.')),
                          ParagraphStyle('evb', fontName='FT', fontSize=7, leading=9, textColor=C(INK3))), Spacer(0, 1.5 * mm)]
    return out


def esc_x(s):
    return html.escape(str(s))


def render(r, data, t0, t1, version='', now=None):
    """-> the PDF (bytes) in the report's language."""
    _register()
    from reportlab.graphics.shapes import Circle, Drawing, Line, PolyLine, Polygon, Rect, String
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (CondPageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)
    C = colors.HexColor
    lang = r['lang']
    now = now or time.time()
    tz = ZoneInfo(r['tz'])
    sec = set(r['sections'])
    cov = data.get('cover') or {}
    p0, p1 = t0, t1                       # the planned period; t0, t1 from here on: what the report really covers
    t0, t1 = cov.get('t0', t0), cov.get('t1', t1)
    W = A4[0] - 32 * mm - 12          # the frame less its padding
    st = lambda name, **kw: ParagraphStyle(name, **{'fontName': 'FT', 'fontSize': 8.5, 'leading': 11, 'textColor': C(INK), **kw})  # noqa: E731
    P, PM, PR = st('p'), st('pm', textColor=C(INK2)), st('pr', alignment=TA_RIGHT)
    H2 = st('h2', fontName='FT-Black', fontSize=12.5, leading=16, spaceBefore=6 * mm, spaceAfter=2 * mm)
    esc = lambda s: html.escape(str(s))      # noqa: E731
    story = []
    s = data['summary']
    rows = (data.get('series') or {}).get('rows') or []
    step = (data.get('series') or {}).get('step') or 300

    def section(title, *flow, note=''):
        story.append(CondPageBreak(40 * mm))      # a title never ends a page; a long table goes on over the next one
        story.append(Paragraph(esc(title), H2))
        if note:
            story.extend([Paragraph(esc(note), st('note', textColor=C(INK2), keepWithNext=1)), Spacer(0, 1.5 * mm)])
        story.extend(flow)

    def bar(share, color, w=24 * mm, h=2.4 * mm):
        d = Drawing(w, h)
        d.add(Rect(0, 0, w, h, fillColor=C(HAIR), strokeColor=None, rx=1.2, ry=1.2))
        if share > 0:
            d.add(Rect(0, 0, max(w * min(share, 1), 1.2), h, fillColor=C(color), strokeColor=None, rx=1.2, ry=1.2))
        return d

    def dot(color, r=1.6 * mm):
        d = Drawing(2 * r, 2 * r)
        d.add(Circle(r, r, r * 0.62, fillColor=C(color), strokeColor=None))
        return d

    def table(head, body, widths, right=(), shares=None):
        t = Table([head] + body, colWidths=widths, repeatRows=1)
        style = [('FONT', (0, 0), (-1, -1), 'FT', 8.2), ('FONT', (0, 0), (-1, 0), 'FT-Bold', 7.4),
                 ('TEXTCOLOR', (0, 0), (-1, 0), C(INK2)), ('TEXTCOLOR', (0, 1), (-1, -1), C(INK)),
                 ('LINEBELOW', (0, 0), (-1, 0), 0.8, C(INK3)), ('LINEBELOW', (0, 1), (-1, -1), 0.4, C(HAIR)),
                 ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('TOPPADDING', (0, 0), (-1, -1), 2.6),
                 ('BOTTOMPADDING', (0, 0), (-1, -1), 2.6), ('LEFTPADDING', (0, 0), (-1, -1), 3), ('RIGHTPADDING', (0, 0), (-1, -1), 3)]
        for c in right:
            style.append(('ALIGN', (c, 0), (c, -1), 'RIGHT'))
        t.setStyle(TableStyle(style))
        return t

    def two_lines(a, b):
        return Paragraph(f'{esc(a)}<br/><font color="{INK3}" size="7">{esc(b)}</font>' if b else esc(a), P)

    # ---- (1.10.0) a period without (all) its records says so at the top, never as bare zeros
    note = cover_note(r, cov, p0, p1)
    if note:
        b = Table([[Paragraph(f'<font name="FT-Bold">{esc(note[0])}</font><br/>{esc(note[1])}', st('warn', textColor=C('#7A4B00')))]], colWidths=[W])
        b.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), C('#FFF4DC')), ('LINEBEFORE', (0, 0), (0, -1), 3, C(SEV['warn'])),
                               ('LEFTPADDING', (0, 0), (-1, -1), 8), ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 7)]))
        story.extend([b, Spacer(0, 4 * mm)])

    # ---- totals
    total_b = s['bytes']
    peak = max(((x[1] + x[2] + x[3]) * 8 / step for x in rows), default=0)
    avg = total_b * 8 / max(t1 - t0, 1)
    peak = max(peak, avg)        # a bucket wider than a few minutes covered must not show a peak under the average
    empty = cov.get('kind') in ('before', 'none')       # nothing at all: the note says it, no rows of zeros
    if 'summary' in sec and not empty:
        tiles = [(tr('Traffic'), fmt_b(total_b), delta(total_b, s['p_bytes']) if s.get('has_prev') else ''),
                 (tr('Downloaded'), fmt_b(s['down']), ''), (tr('Uploaded'), fmt_b(s['up']), ''),
                 (tr('Flows'), fmt_n(s['flows']), delta(s['flows'], s['p_flows']) if s.get('has_prev') else ''),
                 (tr('Inside hosts'), fmt_n(s['hosts']), delta(s['hosts'], s['p_hosts']) if s.get('has_prev') else ''),
                 (tr('Outside addresses'), fmt_n(s['ips'] - s['hosts']),
                  delta(s['ips'] - s['hosts'], s['p_ips'] - s['p_hosts']) if s.get('has_prev') else ''),
                 (tr('Peak'), fmt_rate(peak), ''), (tr('Average'), fmt_rate(avg), '')]
        accent = {1: DOWN, 2: UP}
        cells = []
        for i, (k, v, dl) in enumerate(tiles):
            cells.append([Paragraph(f'<font color="{INK2}" size="7.4">{esc(k.upper())}</font>', P),
                          Paragraph(f'<font name="FT-Black" size="14" color="{accent.get(i, INK)}">{esc(v)}</font>', st('v', leading=18)),
                          Paragraph(f'<font color="{INK2}" size="7.4">{esc(dl or " ")}</font>', P)])
        grid = [cells[:4], cells[4:]]
        tw = W / 4
        t = Table(grid, colWidths=[tw] * 4, rowHeights=19 * mm)
        t.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), C(PANEL)), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                               ('LINEAFTER', (0, 0), (-2, -1), 3, colors.white), ('LINEBELOW', (0, 0), (-1, 0), 3, colors.white),
                               ('TOPPADDING', (0, 0), (-1, -1), 6), ('LEFTPADDING', (0, 0), (-1, -1), 7)]))
        story.append(t)
        if any(x[2] for x in tiles):
            story.append(Spacer(0, 1.2 * mm))
            story.append(Paragraph(esc(tr('↑ ↓ against the period of the same length just before.')), st('cmp', textColor=C(INK3), fontSize=7)))

    # ---- traffic over time
    if 'chart' in sec and rows and not empty:
        cw, chh, lm, bm = W, 58 * mm, 15 * mm, 7 * mm
        d = Drawing(cw, chh + bm + 9)
        pw, ph = cw - lm - 2, chh
        top = max(max(x[1] * 8 / step for x in rows), max(x[2] * 8 / step for x in rows), 1)
        nice = 10 ** len(str(int(top))) / 10
        for k in (1, 2, 2.5, 5, 10):
            if top <= nice * k * 4:
                tick = nice * k
                break
        ymax = tick * max(1, -(-top // tick))
        y = lambda v: bm + ph * v / ymax                                    # noqa: E731
        x = lambda t: lm + pw * (t - t0) / max(t1 - t0, 1)                 # noqa: E731
        v = 0
        while v <= ymax + 1e-9:
            d.add(Line(lm, y(v), lm + pw, y(v), strokeColor=C(HAIR), strokeWidth=0.5))
            d.add(String(lm - 2, y(v) - 2.5, fmt_rate(v), fontName='FT', fontSize=6.3, fillColor=C(INK3), textAnchor='end'))
            v += tick
        marks, span = [], t1 - t0
        if span <= 2 * 86400:               # clock marks every 3 (6) hours, also for a part of a day
            every = 1 if span <= 6 * 3600 else 2 if span <= 12 * 3600 else 3 if span <= 86400 + 3600 else 6
            t = t0 - t0 % 3600
            while t <= t1:
                h = datetime.datetime.fromtimestamp(t, tz)
                if h.minute == 0 and h.hour % every == 0:
                    marks.append((t, h.strftime('%H:%M') if h.hour or span <= 86400 + 3600 else h.strftime('%d.%m')))
                t += 3600
        elif span <= 4 * 86400:             # a few days: midnights (the date) and noons
            t = t0 - t0 % 3600
            while t <= t1:
                h = datetime.datetime.fromtimestamp(t, tz)
                if h.minute == 0 and h.hour in (0, 12):
                    marks.append((t, h.strftime('%d.%m') if h.hour == 0 else '12:00'))
                t += 3600
        else:
            days = span // 86400 + 1
            every = 1 if days <= 9 else 3 if days <= 32 else 7
            day = datetime.datetime.fromtimestamp(t0, tz).date()
            for i in range(0, days + 1, every):
                dd = day + datetime.timedelta(days=i)
                marks.append((int(datetime.datetime.combine(dd, datetime.time(), tz).timestamp()), dd.strftime('%d.%m')))
        for t, label in marks:
            if t0 <= t <= t1:
                d.add(Line(x(t), bm, x(t), bm - 1.5, strokeColor=C(INK3), strokeWidth=0.5))
                d.add(String(x(t), 0.5, label, fontName='FT', fontSize=6.3, fillColor=C(INK3), textAnchor='middle'))
        xin = lambda t: x(min(max(t, t0), t1))      # noqa: E731 — a bucket that began before the period starts at its edge
        for col, color in ((1, DOWN), (2, UP)):
            pts = []
            for row in rows:
                pts += [xin(row[0] + step / 2), y(row[col] * 8 / step)]
            if len(pts) == 2:                    # one bucket (a short burst): a narrow column instead of nothing
                pts = [pts[0] - 1.5, pts[1], pts[0] + 1.5, pts[1]]
            if len(pts) >= 4:
                d.add(Polygon([pts[0], bm] + pts + [pts[-2], bm], fillColor=C(color), fillOpacity=0.16, strokeColor=None))
                d.add(PolyLine(pts, strokeColor=C(color), strokeWidth=0.9))
        d.add(Line(lm, bm, lm + pw, bm, strokeColor=C(INK3), strokeWidth=0.6))
        lx = lm + pw
        for label, color in ((tr('Uploaded'), UP), (tr('Downloaded'), DOWN)):
            lx -= 6 + len(label) * 3.6
            d.add(Rect(lx, chh + bm + 5, 6, 2.4, fillColor=C(color), strokeColor=None))
            d.add(String(lx + 8, chh + bm + 4.6, label, fontName='FT', fontSize=6.8, fillColor=C(INK2)))
            lx -= 10
        section(tr('Traffic over time'), d)

    tot = max(total_b, 1)

    # ---- inside hosts
    if 'hosts' in sec and data.get('hosts', {}).get('rows'):
        body = []
        for i, h in enumerate(data['hosts']['rows'], 1):
            b = h['up'] + h['dn']
            body.append([str(i), two_lines(h.get('name') or h['k'], h['k'] if h.get('name') else ''), fmt_b(h['dn']),
                         fmt_b(h['up']), fmt_b(b), bar(b / tot, DOWN)])
        section(tr('Busiest inside hosts'),
                table(['#', tr('Host'), tr('Downloaded'), tr('Uploaded'), tr('Total'), tr('Share')], body,
                      [8 * mm, W - 8 * mm - 3 * 22 * mm - 28 * mm, 22 * mm, 22 * mm, 22 * mm, 28 * mm], right=(2, 3, 4)))

    # ---- outside networks
    if 'outside' in sec and data.get('outside', {}).get('rows'):
        body = []
        for i, a in enumerate(data['outside']['rows'], 1):
            b = a['up'] + a['dn']
            org = a.get('as_org') or (tr('unknown') if a['k'] in ('0', '') else '')
            body.append([str(i), two_lines(org, f"AS{a['k']}" if a['k'] not in ('0', '') else ''),
                         country(a.get('country', ''), lang), fmt_b(a['dn']), fmt_b(a['up']), bar(b / tot, UP)])
        section(tr('Outside networks (AS)'),
                table(['#', tr('Network'), tr('Country'), tr('Downloaded'), tr('Uploaded'), tr('Share')], body,
                      [8 * mm, W - 8 * mm - 32 * mm - 2 * 22 * mm - 28 * mm, 32 * mm, 22 * mm, 22 * mm, 28 * mm], right=(3, 4)))

    # ---- services and countries side by side
    halves = []
    hw = (W - 6 * mm) / 2
    for name, title, label in (('services', tr('Services'), lambda x: two_lines(x['k'] or tr('unknown'), x.get('l7', ''))),
                               ('countries', tr('Countries'), lambda x: Paragraph(esc(country(x['k'], lang)), P))):
        if name in sec and data.get(name, {}).get('rows'):
            body = [[label(x), fmt_b(x['up'] + x['dn']), bar((x['up'] + x['dn']) / tot, BLUE, w=20 * mm)] for x in data[name]['rows']]
            halves.append([Paragraph(esc(title), H2), table([title, tr('Total'), tr('Share')], body,
                                                           [hw - 22 * mm - 24 * mm, 22 * mm, 24 * mm], right=(1,))])
    if len(halves) == 2:
        story.append(CondPageBreak(60 * mm))
        t = Table([[halves[0], halves[1]]], colWidths=[hw + 6 * mm, hw])
        t.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 0),
                               ('RIGHTPADDING', (0, 0), (-1, -1), 0)]))
        story.append(t)
    elif halves:
        story.append(CondPageBreak(60 * mm))
        story.extend(halves[0])

    # ---- named networks
    nets = [x for x in (data.get('networks') or {}).get('rows') or [] if x['k']]
    if 'networks' in sec and nets:
        body = [[Paragraph(esc(x['k']), P), str(x.get('hosts', '')), fmt_b(x['dn']), fmt_b(x['up']),
                 bar((x['up'] + x['dn']) / tot, BLUE)] for x in nets]
        section(tr('Your networks'),
                table([tr('Network'), tr('Hosts'), tr('Downloaded'), tr('Uploaded'), tr('Share')], body,
                      [W - 18 * mm - 2 * 24 * mm - 30 * mm, 18 * mm, 24 * mm, 24 * mm, 30 * mm], right=(1, 2, 3)))

    # ---- (1.13.0) link capacity: the links with a known capacity, the fullest first, and what to plan for
    if 'capacity' in sec and data.get('capacity'):
        cd = data['capacity']
        links = [x for x in cd['interfaces'] if x['status'] != 'unknown'][:14]
        if not links:
            section(tr('Link capacity'), Paragraph(esc(tr('No link has a known capacity: set the port speeds or your ISP figures in Settings → Devices → Interfaces.')), PM))
        else:
            col = {'over': SEV['crit'], 'full': SEV['crit'], 'soon': SEV['warn'], 'watch': SEV['warn'], 'ok': '#1E9E6A'}
            day = lambda base, n: datetime.datetime.fromtimestamp(base + n * 86400 + 43200, tz).strftime('%Y-%m-%d')      # noqa: E731

            def load(x, k):
                v = x[k]
                return [[Paragraph(f'<b>{v["p95_pct"]:g}%</b>\u00a0\u00a0<font color="{INK2}" size="7">{esc(fmt_rate(v["p95"]))}</font>', P)],
                        [bar((v['p95_pct'] or 0) / 100, col['full'] if (v['p95_pct'] or 0) >= cd['full_pct'] else col['watch'] if (v['p95_pct'] or 0) >= cd['watch_pct'] else BLUE, w=28 * mm)]]

            def when(x):
                v = x[x['worst']]
                fc = v['forecast']
                if not fc:
                    return Paragraph(f'<font color="{INK3}">{esc(tr("collecting"))}</font>', P)
                if fc['full_in'] == 0:
                    return Paragraph(f'<font color="{SEV["crit"]}"><b>{esc(tr("already"))}</b></font>', P)
                if fc['full_in'] is None:
                    return Paragraph(f'<font color="{INK3}">{esc(tr("not within {n} days", n=fc["horizon"]))}</font>', P)
                return Paragraph(f'<font color="{SEV["warn"]}"><b>{day(v["trend"]["last_day"], fc["full_in"])}</b></font>', P)

            def trend(x):
                fc = x[x['worst']]['forecast']
                if not fc:
                    return ''
                if not fc.get('clear', True):            # (1.13.1) noisy days: no figure
                    return '≈'
                g = fc['growth_pct_month']
                return f"{'↑' if fc['direction'] == 'up' else '↓' if fc['direction'] == 'down' else '='} " + \
                    (f"{g:+g}%" if abs(g) <= 100 else ('>+100%' if g > 0 else '<−100%'))
            body = [[dot(col[x['status']]), two_lines(x['name'], x['device_name']),
                     two_lines(fmt_rate(x['cap_in'] * 1e6), '') if x['cap_in'] == x['cap_out'] else
                     Paragraph(f"{esc(fmt_rate(x['cap_in'] * 1e6))} ↓<br/>{esc(fmt_rate(x['cap_out'] * 1e6))} ↑", P),
                     Table(load(x, 'in')), Table(load(x, 'out')), trend(x), when(x)] for x in links]
            for row in body:
                for c in (3, 4):
                    row[c].setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                                                ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0)]))
            # the links to plan for, in one sentence each
            says = []
            for x in [y for y in links if y['status'] in ('over', 'full', 'soon')][:4]:
                v, d = x[x['worst']], x['worst']
                fc = v['forecast']
                who = f"<b>{esc(x['name'])}</b> ({esc(x['device_name'])}), {esc(tr('incoming traffic') if d == 'in' else tr('outgoing traffic'))}: "
                if fc and fc['full_in'] is not None and fc['full_in'] > 0:
                    says.append(who + esc(tr('{pct}% of the capacity around {date}, growing {g}% a month.', pct=cd['full_pct'], date=day(v['trend']['last_day'], fc['full_in']), g=f"{fc['growth_pct_month']:g}")))
                else:
                    says.append(who + esc(tr('busy hours at {pct}% of the capacity already.', pct=f"{v['p95_pct']:g}")))
            for x in links:              # (1.14.0) links whose own counters show traffic the flows miss
                for k in ('in', 'out'):
                    v = (x.get('seen_pct') or {}).get(k)
                    if v is not None and v < 80:
                        says.append(f"<b>{esc(x['name'])}</b> ({esc(x['device_name'])}), {esc(tr('incoming traffic') if k == 'in' else tr('outgoing traffic'))}: "
                                    + esc(tr('the flows see only {pct}% of what the interface counted — the rest is not exported.', pct=f'{v:g}')))
            flow = [table(['', tr('Interface'), tr('Capacity'), tr('In (95th percentile)'), tr('Out (95th percentile)'), tr('Trend'), tr('Reaches {pct}%', pct=cd['full_pct'])],
                          body, [5 * mm, 34 * mm, 28 * mm, 34 * mm, 34 * mm, 17 * mm, W - 152 * mm], right=(5,))]
            if says:
                flow = [Paragraph('<br/>'.join(says), st('say', leading=12.5)), Spacer(0, 2.5 * mm)] + flow
            section(tr('Link capacity'), *flow,
                    note=tr('The last {n} days up to when the report was made; 95th percentile = the load of the busy hours, trend a month.', n=cd['days']))

    # ---- security events
    if 'events' in sec:
        ev = [e for e in data.get('events') or [] if e.get('stored', True)]
        if not ev:
            section(tr('Security events'), Paragraph(esc(tr('No events in this period.')), PM))
        else:
            kinds = {}
            for e in ev:
                k = kinds.setdefault(e['kind'], {'n': 0, 'sev': e['sev'], 'title': tr(detect.NAMES[e['kind']]) if e['kind'] in detect.NAMES else e['title']})
                k['n'] += 1
                if list(SEV).index(e['sev']) < list(SEV).index(k['sev']):
                    k['sev'] = e['sev']
            order = sorted(kinds.items(), key=lambda kv: (list(SEV).index(kv[1]['sev']), -kv[1]['n']))
            # (1.17.0) how many began in each step, by kind, and the share of each kind — the Events page's two charts
            graphs = events_charts(ev, t0, t1, r['tz'], W, tz)
            cells = [x for k, v in order for x in (dot(EV_COLORS.get(k, INK3)), Paragraph(f'{esc(v["title"])} <b>{v["n"]}</b> '
                                                                                       f'<font color="{INK3}" size="7">{100 * v["n"] / len(ev):.0f}%</font>', P))]
            cells += [''] * (-len(cells) % 6)
            chips = Table([cells[i:i + 6] for i in range(0, len(cells), 6)], colWidths=[5 * mm, W / 3 - 5 * mm] * 3)
            chips.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('TOPPADDING', (0, 0), (-1, -1), 1.5),
                                       ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')]))
            body = []
            for e in ev[:15]:
                body.append([dot(SEV.get(e['sev'], INK3)),
                             Paragraph(f'<b>{esc(e["title"])}</b><br/><font color="{INK2}">{esc(e["text"][:400])}</font>', P),
                             Paragraph(f'<font color="{INK2}" size="7.4">{esc(e.get("last") or e.get("when", ""))}</font>', PR)])
            note = trn(len(ev), '{n} event in this period.', '{n} events in this period.') + \
                (' ' + tr('The 15 most important are shown; all of them are in FlowTrack → Events.') if len(ev) > 15 else '')
            section(tr('Security events'), *graphs, chips, Spacer(0, 2 * mm),
                    table(['', tr('Event'), tr('Last seen')], body, [6 * mm, W - 6 * mm - 30 * mm, 30 * mm], right=(2,)), note=note)

    # ---- devices
    if 'devices' in sec and data.get('devices'):
        body = []
        for x in data['devices']:
            seen = int(now - x['last']) if x.get('last') else None
            ok = seen is not None and seen < 600
            state = tr('sending') if ok else tr('silent since {when}', when=datetime.datetime.fromtimestamp(x['last'], tz).strftime('%Y-%m-%d %H:%M')) \
                if x.get('last') else tr('never sent')
            body.append([Paragraph(esc(x.get('name') or x['ip']), P), x['ip'], x.get('proto') or '', f"{x.get('rps', 0):g}",
                         f"{x.get('loss_pct', 0):g}%", Paragraph(f'<font color="{"#1E9E6A" if ok else SEV["crit"]}">{esc(state)}</font>', P)])
        section(tr('Devices'), table([tr('Device'), tr('Address'), tr('Protocol'), tr('Records/s'), tr('Lost'), tr('State')], body,
                                     [W - 30 * mm - 26 * mm - 20 * mm - 16 * mm - 34 * mm, 30 * mm, 26 * mm, 20 * mm, 16 * mm, 34 * mm],
                                     right=(3, 4)), note=tr('As of the moment the report was made.'))

    # ---- the page frame: a navy head on the first page, a footer on each
    title = r['name']
    plabel = period_label(r, t0, t1)
    made = datetime.datetime.fromtimestamp(now, tz).strftime('%Y-%m-%d %H:%M')
    flt = ', '.join(('-' if f['neg'] else '') + f"{f['k']}:{f['v']}" for f in r['f'])
    scope = {'internet': tr('Internet traffic'), 'internal': tr('Traffic between inside hosts'), 'all': tr('All traffic')}[r['t']]

    def first(c, doc):
        c.saveState()
        c.setFillColor(C(NAVY))
        c.rect(0, A4[1] - 34 * mm, A4[0], 34 * mm, stroke=0, fill=1)
        c.setFillColor(C(BLUE))
        c.rect(0, A4[1] - 34 * mm, A4[0], 1.2 * mm, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont('FT-Black', 9)
        c.drawString(16 * mm, A4[1] - 11 * mm, 'FLOWTRACK')
        c.setFont('FT-Black', 18)
        c.drawString(16 * mm, A4[1] - 20.5 * mm, title[:60])
        c.setFont('FT', 9)
        c.setFillColor(C('#A9B7D9'))
        c.drawString(16 * mm, A4[1] - 27 * mm, (scope + (' · ' + flt if flt else ''))[:110])
        c.setFillColor(colors.white)
        c.setFont('FT-Bold', 11)
        c.drawRightString(A4[0] - 16 * mm, A4[1] - 20.5 * mm, plabel)
        c.setFont('FT', 8)
        c.setFillColor(C('#A9B7D9'))
        c.drawRightString(A4[0] - 16 * mm, A4[1] - 11 * mm, {'day': tr('Daily report'), 'week': tr('Weekly report'),
                                                             'month': tr('Monthly report'), 'custom': tr('Report for a period')}[r['every']])
        c.drawRightString(A4[0] - 16 * mm, A4[1] - 27 * mm, r['tz'])
        c.restoreState()
        later(c, doc)

    def later(c, doc):
        c.saveState()
        c.setFont('FT', 7)
        c.setFillColor(C(INK3))
        c.drawString(16 * mm, 9 * mm, f"FlowTrack {version} · {tr('made {when}', when=made)}".strip())
        c.drawRightString(A4[0] - 16 * mm, 9 * mm, f"{plabel} · {tr('page {n}', n=doc.page)}")
        c.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f'{title} — {plabel}', author='FlowTrack', creator='FlowTrack')
    story.insert(0, Spacer(0, 24 * mm))       # under the head of the first page
    doc.build(story, onFirstPage=first, onLaterPages=later)
    return buf.getvalue()


# ------------------------------------------------------------------ making and sending

def cover(r, data, t0, t1, now):
    """What the report can really cover of the period (1.10.0). `oldest` of the summary is the first record of the
    period — or, when it has none, the moment FlowTrack began receiving (0: never). -> {'kind', 't0', 't1'}:
    full; part (records from a moment inside the period); later (none in the period, all came after it: the report
    shows what there is instead, up to one period long); silent (the devices sent nothing then); none (never)."""
    s = data['summary']
    first = int(s.get('oldest') or 0)
    if r['every'] == 'custom' and not s['bytes'] and first >= t1 - 60:
        return {'kind': 'before', 't0': t0, 't1': t1, 'first': first}      # a chosen period (an incident): never another instead
    if s['bytes']:
        return {'kind': 'part', 't0': first, 't1': t1} if first > t0 + 3600 else {'kind': 'full', 't0': t0, 't1': t1}
    if not first:
        return {'kind': 'none', 't0': t0, 't1': t1}
    if first >= t1 - 60:
        end = int(min(now, first + (t1 - t0))) // 300 * 300
        if end - first >= 300:
            return {'kind': 'later', 't0': first, 't1': end}
        return {'kind': 'none', 't0': t0, 't1': t1}
    return {'kind': 'silent', 't0': t0, 't1': t1}


def cover_note(r, cov, p0, p1):
    """(title, text) of the note on top of a report that does not cover its whole period, or None."""
    k = cov.get('kind', 'full')
    if k == 'full':
        return None
    tz = ZoneInfo(r['tz'])
    start = datetime.datetime.fromtimestamp(cov.get('first', cov['t0']), tz).strftime('%Y-%m-%d %H:%M')
    have = period_label(r, cov['t0'], cov['t1'])
    if k == 'part':
        return (tr('Not the whole period: records from {start}', start=start),
                tr('FlowTrack has records of {period} only from {start} (it began collecting then, or older records are no longer kept). '
                   'The report covers {have}.', period=period_label(r, p0, p1), start=start, have=have))
    if k == 'later':
        return (tr('No records of {period} yet: the report shows {have}', period=period_label(r, p0, p1), have=have),
                tr('FlowTrack has been collecting since {start}, after this period ended. So that the report is not empty, it shows '
                   'everything collected so far; the next one will cover its whole period.', start=start))
    if k == 'before':
        return (tr('No records of {period}', period=period_label(r, p0, p1)),
                tr('FlowTrack has records only from {start}, after this period (or older records are no longer kept).', start=start))
    if k == 'silent':
        return (tr('No records in this period'),
                tr('FlowTrack was running, but the devices sent it nothing then. Check them in Settings → Devices.'))
    return (tr('FlowTrack has not received any records yet'),
            tr('Connect a firewall, router or switch in Settings → Devices: the next report will show its traffic.'))


def make(r, t0, t1, call, version=''):
    """-> (pdf bytes, data) in the report's language (the caller's language is kept)."""
    ui = get_lang()
    set_lang(r['lang'])
    try:
        data = collect(r, t0, t1, call)
        cov = cover(r, data, t0, t1, time.time())
        if cov['kind'] == 'later':           # nothing in the period: what there is, instead of zeros
            data = collect(r, cov['t0'], cov['t1'], call)
        elif cov['kind'] == 'part' and 'series' in data and cov['t1'] - cov['t0'] >= 300:
            data['series'] = collect(dict(r, sections=['chart']), cov['t0'], cov['t1'], call)['series']     # steps of the part there is
        data['cover'] = cov
        return render(r, data, t0, t1, version), data
    finally:
        set_lang(ui)


def file_name(r, t0):
    slug = re.sub(r'[^A-Za-z0-9]+', '-', r['name']).strip('-').lower()[:40] or 'report'
    when = datetime.datetime.fromtimestamp(t0, ZoneInfo(r['tz'])).strftime('%Y-%m-%d_%H%M' if r['every'] == 'custom' else '%Y-%m-%d')
    return f"flowtrack-{slug}-{when}.pdf"


def mail_problem(r, cfg=None):
    """Why the report cannot go out by e-mail at all ('' = it can): no mail server, or nobody to send it to."""
    m = (cfg or notify.load())['email']
    if not (m['host'] and m['sender']):
        return tr('No mail server: set it up in Settings → General → Mail server.')
    if not (r['to'] or m['to']):
        return tr('No recipients: enter them in the report.')
    return ''


def mail(r, pdf, data, t0, t1, cfg=None):
    """The message with the PDF attached, to the report's recipients (or those of the notifications)."""
    cfg = cfg or notify.load()
    m = dict(cfg['email'])
    m['to'] = r['to'] or m['to']
    why = mail_problem(r, cfg)
    if why:
        raise ValueError(why)
    ui = get_lang()
    set_lang(r['lang'])
    try:
        plabel = sent_label(r, data, t0, t1)
        note = cover_note(r, data.get('cover') or {}, t0, t1)
        s = data['summary']
        lines = [(tr('Traffic'), fmt_b(s['bytes'])), (tr('Downloaded'), fmt_b(s['down'])), (tr('Uploaded'), fmt_b(s['up'])),
                 (tr('Inside hosts'), str(s['hosts']))]
        ev = [e for e in data.get('events') or [] if e.get('stored', True)]
        if 'events' in r['sections']:
            lines.append((tr('Security events'), str(len(ev))))
        text = f"{r['name']} — {plabel}\n\n" + (f"{note[0]}. {note[1]}\n\n" if note else '') + '\n'.join(f'{k}: {v}' for k, v in lines) + '\n\n' + tr('The full report is attached (PDF).')
        body = (f'<p style="margin:0 0 4px;font-weight:800;font-size:15px">{html.escape(r["name"])}</p>'
                f'<p style="margin:0 0 14px;color:#5b6478">{html.escape(plabel)}</p>' +
                (f'<div style="background:#fff4dc;border-left:3px solid #f5a524;padding:8px 12px;margin:0 0 14px;color:#7a4b00">'
                 f'<b>{html.escape(note[0])}</b><br>{html.escape(note[1])}</div>' if note else '') + '<table style="border-collapse:collapse">' +
                ''.join(f'<tr><td style="padding:3px 18px 3px 0;color:#5b6478">{html.escape(k)}</td><td style="padding:3px 0;font-weight:700">'
                        f'{html.escape(v)}</td></tr>' for k, v in lines) +
                f'</table><p style="margin:14px 0 0">{html.escape(tr("The full report is attached (PDF)."))}</p>')
        if cfg.get('link'):
            body += (f'<p><a href="{html.escape(cfg["link"])}" style="display:inline-block;background:#2f7bff;color:#fff;'
                     f'text-decoration:none;padding:8px 14px;border-radius:7px;font-weight:700">{html.escape(tr("Open FlowTrack"))}</a></p>')
        msg = notify._mail(m, f"FlowTrack: {r['name']} — {plabel}", text, body)
    finally:
        set_lang(ui)
    msg.add_attachment(pdf, maintype='application', subtype='pdf', filename=file_name(r, t0))
    return m, msg


def sent_label(r, data, t0, t1):
    """The period a sent report shows: its own, or what there was instead (no records of it yet)."""
    cov = data.get('cover') or {}
    return period_label(r, cov['t0'], cov['t1']) if cov.get('kind') == 'later' else period_label(r, t0, t1)


def send(r, t0, t1, call, version=''):
    """-> (recipients, the period the report shows)."""
    pdf, data = make(r, t0, t1, call, version)
    m, msg = mail(r, pdf, data, t0, t1)
    try:
        notify.smtp_send(m, msg, timeout=60)
    except notify.MailError as e:
        raise ValueError(str(e)) from None
    return len(m['to']), sent_label(r, data, t0, t1)


def next_send(r, done, now):
    """When the report goes out next: its last period if that is not sent yet (now or overdue), else the one after."""
    t = now
    for _ in range(40):
        t1 = period(r, t)[1]
        if t1 > done:
            return send_time(r, t1)
        t += 86400
    return 0


def note_sent(r, label, n, now=None):
    """Send now: shown as the last sending; the schedule (what period is done) is left as it was."""
    with _lock:
        st = load_state()
        if any(x['id'] == r['id'] for x in load()):
            s = st.get(r['id'], {})
            s.update(sent=int(now or time.time()), sent_period=label, to=n)
            for k in ('error', 'error_at'):
                s.pop(k, None)
            st[r['id']] = s
            _write(STATE, st)


def status(now=None):
    """Per report: when it was last sent, the error of the last try, the next sending (after `now`, for the tests)."""
    st, now, out, cfg = load_state(), now or time.time(), {}, notify.load()
    for r in load():
        s = st.get(r['id'], {})
        out[r['id']] = {'blocked': mail_problem(r, cfg), 'sent': s.get('sent', 0), 'sent_period': s.get('sent_period', ''), 'to': s.get('to', 0),
                        'error': s.get('error', ''), 'error_at': s.get('error_at', 0),
                        'next': next_send(r, s.get('done', 0), now) if r['on'] else 0}
    return out


def tick(call, version='', now=None, log=lambda m: print(m, flush=True)):
    """One look at the schedule: sends what is due. Returns the ids sent (for the tests)."""
    now = now or time.time()
    sent = []
    for r in load():
        if not r['on']:
            continue
        t0, t1 = period(r, now)
        at = send_time(r, t1)
        with _lock:
            st = load_state()
            s = st.get(r['id'], {})
        if now < at or s.get('done', 0) >= t1 or now - s.get('error_at', 0) < RETRY:
            continue
        why = mail_problem(r)
        if why:                         # nothing to try until the settings change: no tries spent, shown in the list
            if s.get('blocked') != why:
                with _lock:
                    st = load_state()
                    st[r['id']] = dict(st.get(r['id'], {}), blocked=why)
                    _write(STATE, st)
                log(f"[flowtrack-api] report {r['name']!r} not sent: {why}")
            continue
        try:
            n, label = send(r, t0, t1, call, version)
            s = {'done': t1, 'sent': int(now), 'sent_period': label, 'to': n}      # (blocked and errors cleared)
            sent.append(r['id'])
            log(f"[flowtrack-api] report {r['name']!r} ({label}) sent to {n} recipient(s)")
        except Exception as e:          # noqa: BLE001 — a report must never stop the schedule of the others
            tries = s.get('tries', 0) + 1 if s.get('try_period') == t1 else 1
            s = dict(s, error=str(e)[:300], error_at=int(now), tries=tries, try_period=t1)
            if tries >= TRIES:
                s['done'] = t1          # given up for this period; the error stays shown
            log(f"[flowtrack-api] report {r['name']!r}: {e}")
        with _lock:
            st = load_state()
            if any(x['id'] == r['id'] for x in load()):
                st[r['id']] = s
                _write(STATE, st)
    return sent


def scheduler(call, version='', stop=None):
    """The web service's thread: a look at the schedule every minute."""
    stop = stop or threading.Event()
    while not stop.wait(60):
        try:
            tick(call, version)
        except Exception as e:          # noqa: BLE001
            print(f'[flowtrack-api] reports: {e}', flush=True)
