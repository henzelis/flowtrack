"""Notifications: new events go to Telegram through the user's own bot (1.6.2), by e-mail over SMTP (1.6.4) and to a
webhook (1.11.0: JSON, Slack / Mattermost / Rocket.Chat or Discord, signed with HMAC-SHA256 when a secret is set) and
to a SIEM as syslog (1.11.0: RFC 5424 over UDP / TCP / TLS, CEF or JSON; every event its own message, no hourly limit).

Only an event's first appearance is sent — an activity that goes on extends its event quietly; looking back over the
past at the first start sends nothing. What goes out: the kinds ticked for it, at or above a minimum priority, at most
`per_hour` messages an hour per channel (the rest are counted in the next message); several events of one 10-minute
check go as one message. Each channel sends from its own thread with retries, so an unreachable Telegram or mail
server never holds up the detections or the other channel.

The bot token, the SMTP password and the webhook's secret and extra header are secrets: kept in STATE_DIR/notify.json (0600, the service user only), never
sent to the browser and never written to the log."""
import datetime
import functools
import hashlib
import hmac
import html
import json
import os
import queue
import re
import smtplib
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from common import STATE_DIR, VERSION, get_lang, known_lang, set_lang, tr, trn

CONFIG = os.path.join(STATE_DIR, 'notify.json')
SEVERITIES = ('info', 'warn', 'crit')
TOKEN_RE = re.compile(r'^\d{5,15}:[A-Za-z0-9_-]{30,50}$')
CHAT_RE = re.compile(r'^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$')
MAIL_RE = re.compile(r'^[^@\s<>"(),;:\\]{1,64}@[A-Za-z0-9.-]{1,253}$')
HOST_RE = re.compile(r'^([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$|^[0-9a-fA-F:]{2,39}$')
SECURITY = ('starttls', 'ssl', 'none')
CHANNELS = ('telegram', 'email', 'webhook', 'siem')
KINDS = {'telegram': 'kinds', 'email': 'email_kinds', 'webhook': 'webhook_kinds', 'siem': 'siem_kinds'}      # per channel: which kinds go out (absent = yes)
SIEM_TRANSPORTS = ('udp', 'tcp', 'tls')
SIEM_FORMATS = ('cef', 'json')
SIEM_SEV = {'info': (6, 3), 'warn': (4, 6), 'crit': (2, 9)}      # -> (syslog severity, CEF severity 0–10)
PROTO = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 132: 'SCTP'}
FORMATS = ('json', 'slack', 'discord')
HEADER_RE = re.compile(r'^([A-Za-z0-9-]{1,64}):\s*([^\r\n]{1,1000})$')
SEV_COLOR = {'crit': '#e5484d', 'warn': '#f5a524', 'info': '#3e8ed0'}
RECENT = 1800              # only windows that ended this recently are notified (not the look back at the first start)
ICON = {'crit': '🔴', 'warn': '🟠', 'info': '🔵'}


def api_base():
    return os.environ.get('FT_TELEGRAM_API', 'https://api.telegram.org').rstrip('/')


def defaults():
    return {'telegram': {'on': False, 'token': '', 'chat': '', 'min_sev': 'warn', 'lang': 'uk'},
            'email': {'on': False, 'host': '', 'port': 587, 'security': 'starttls', 'verify': True, 'user': '', 'password': '',
                      'sender': '', 'to': [], 'min_sev': 'warn', 'lang': 'uk'},
            'webhook': {'on': False, 'url': '', 'format': 'json', 'secret': '', 'header': '', 'verify': True, 'min_sev': 'warn', 'lang': 'uk'},
            'siem': {'on': False, 'host': '', 'port': 514, 'transport': 'udp', 'format': 'cef', 'facility': 16, 'verify': True,
                     'min_sev': 'info', 'lang': 'en'},
            'kinds': {}, 'email_kinds': {}, 'webhook_kinds': {}, 'siem_kinds': {}, 'link': '', 'per_hour': 20}


def load():
    cfg = defaults()
    try:
        with open(CONFIG) as f:
            saved = json.load(f)
    except (FileNotFoundError, ValueError):
        return cfg
    for ch in CHANNELS:
        cfg[ch].update({k: v for k, v in (saved.get(ch) or {}).items() if k in cfg[ch]})
        cfg[KINDS[ch]] = {k: bool(v) for k, v in (saved.get(KINDS[ch]) or {}).items()}
    cfg['link'] = str(saved.get('link', (saved.get('telegram') or {}).get('link', '')) or '')     # in telegram up to 1.6.3
    if isinstance(saved.get('per_hour'), int):
        cfg['per_hour'] = saved['per_hour']
    return cfg


def save(cfg):
    tmp = CONFIG + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=1, ensure_ascii=False)
    os.replace(tmp, CONFIG)


def public(cfg):
    """The settings for the browser: the token and the password only as 'set or not'."""
    t = dict(cfg['telegram'], token='', token_set=bool(cfg['telegram']['token']))
    m = dict(cfg['email'], password='', password_set=bool(cfg['email']['password']))
    w = cfg['webhook']
    w = dict(w, secret='', secret_set=bool(w['secret']), header=w['header'].split(':', 1)[0] if w['header'] else '', header_set=bool(w['header']))
    return {'telegram': t, 'email': m, 'webhook': w, 'siem': dict(cfg['siem']), 'kinds': cfg['kinds'], 'email_kinds': cfg['email_kinds'],
            'webhook_kinds': cfg['webhook_kinds'], 'siem_kinds': cfg['siem_kinds'], 'link': cfg['link'], 'per_hour': cfg['per_hour']}


def validate(body, old):
    """The settings from the UI, checked; an empty token keeps the stored one. Raises ValueError for people."""
    cfg = defaults()
    t, src = cfg['telegram'], body.get('telegram') or {}
    t['on'] = bool(src.get('on'))
    tok = str(src.get('token') or '').strip()
    if tok and not TOKEN_RE.match(tok):
        raise ValueError(tr('The bot token looks wrong: it is like 123456789:AA… (from @BotFather).'))
    t['token'] = tok or old['telegram']['token']
    chat = str(src.get('chat') or '').strip()
    if chat and not CHAT_RE.match(chat):
        raise ValueError(tr('The chat ID is a number (a group\'s starts with -) or @channel.'))
    t['chat'] = chat
    if src.get('min_sev') in SEVERITIES:
        t['min_sev'] = src['min_sev']
    if known_lang(src.get('lang')):
        t['lang'] = src['lang']
    link = str(body.get('link', src.get('link')) or '').strip().rstrip('/')
    if link and not re.match(r'^https?://[^\s<>"]+$', link):
        raise ValueError(tr('The FlowTrack address must start with https:// or http://.'))
    cfg['link'] = link
    if t['on'] and not (t['token'] and t['chat']):
        raise ValueError(tr('Enter the bot token and the chat ID to switch Telegram on.'))
    cfg['kinds'] = {str(k): bool(v) for k, v in (body.get('kinds') or {}).items()}
    if 'email' in body:      # (1.10.0) the server itself is set in Settings → General: what the form leaves out is kept
        src = body.get('email') or {}
        cfg['email'] = _validate_email(dict({k: old['email'][k] for k in SERVER_KEYS}, **src), old['email'])
        cfg['email_kinds'] = {str(k): bool(v) for k, v in (body.get('email_kinds') or {}).items()}
    else:                                         # a client that knows only Telegram keeps the e-mail settings
        cfg['email'], cfg['email_kinds'] = dict(old['email']), dict(old['email_kinds'])
    if 'webhook' in body:
        cfg['webhook'] = _validate_webhook(body.get('webhook') or {}, old['webhook'])
        cfg['webhook_kinds'] = {str(k): bool(v) for k, v in (body.get('webhook_kinds') or {}).items()}
    else:
        cfg['webhook'], cfg['webhook_kinds'] = dict(old['webhook']), dict(old['webhook_kinds'])
    if 'siem' in body:
        cfg['siem'] = _validate_siem(body.get('siem') or {})
        cfg['siem_kinds'] = {str(k): bool(v) for k, v in (body.get('siem_kinds') or {}).items()}
    else:
        cfg['siem'], cfg['siem_kinds'] = dict(old['siem']), dict(old['siem_kinds'])
    try:
        cfg['per_hour'] = max(1, min(600, int(body.get('per_hour', 20))))
    except (TypeError, ValueError):
        raise ValueError(tr('Messages an hour must be a number.')) from None
    return cfg


def _validate_email(src, old):
    m = defaults()['email']
    m['on'] = bool(src.get('on'))
    host = str(src.get('host') or '').strip()
    if host and not HOST_RE.match(host):
        raise ValueError(tr('The mail server is a host name or an IP address, e.g. smtp.example.com.'))
    m['host'] = host
    try:
        m['port'] = int(src.get('port') or 587)
        assert 1 <= m['port'] <= 65535
    except (TypeError, ValueError, AssertionError):
        raise ValueError(tr('The mail server port is a number 1–65535.')) from None
    if src.get('security') in SECURITY:
        m['security'] = src['security']
    m['verify'] = bool(src.get('verify', True))
    user = str(src.get('user') or '').strip()
    pw = str(src.get('password') or '')
    if len(user) > 256 or len(pw) > 256 or any(ord(c) < 32 for c in user + pw):
        raise ValueError(tr('The login and the password: up to 256 characters each, no control characters.'))
    m['user'] = user
    m['password'] = (pw or old['password']) if user else ''      # an empty field keeps the saved password
    sender = str(src.get('sender') or '').strip()
    if sender and not MAIL_RE.match(sender):
        raise ValueError(tr('The sender is one e-mail address, e.g. flowtrack@example.com.'))
    m['sender'] = sender
    to = src.get('to') or []
    to = [str(x).strip() for x in (to if isinstance(to, list) else re.split(r'[\s,;]+', str(to))) if str(x).strip()]
    bad = [x for x in to if not MAIL_RE.match(x)]
    if bad:
        raise ValueError(tr('Not an e-mail address: {addr}', addr=bad[0][:100]))
    if len(to) > 20:
        raise ValueError(tr('At most 20 recipients.'))
    m['to'] = list(dict.fromkeys(to))
    if src.get('min_sev') in SEVERITIES:
        m['min_sev'] = src['min_sev']
    if known_lang(src.get('lang')):
        m['lang'] = src['lang']
    if m['on'] and not (m['host'] and m['sender'] and m['to']):
        raise ValueError(tr('Set up the mail server in Settings → General, and enter at least one recipient, to switch e-mail on.'))
    return m


SERVER_KEYS = ('host', 'port', 'security', 'verify', 'user', 'password', 'sender')


def validate_server(src, cfg):
    """(1.10.0) The mail server alone (Settings → General → Mail server: for the notifications and the reports), checked
    over the stored settings; recipients, priorities and on/off of the notifications are kept."""
    old = cfg['email']
    m = _validate_email(dict(old, on=False, **{k: src[k] for k in SERVER_KEYS if k in src}), old)
    m.update(on=old['on'], to=old['to'], min_sev=old['min_sev'], lang=old['lang'])
    return dict(cfg, email=m)


def server_public(cfg):
    m = cfg['email']
    return dict({k: m[k] for k in SERVER_KEYS if k != 'password'}, password_set=bool(m['password']), ready=bool(m['host'] and m['sender']))


def test_server(cfg, to, lang):
    """A test letter to one address through the given mail server (not saved yet); ValueError for people."""
    if not MAIL_RE.match(str(to or '')):
        raise ValueError(tr('Enter the address to send the test letter to.'))
    m = dict(cfg['email'], to=[to], lang=lang if known_lang(lang) else cfg['email']['lang'])
    if not (m['host'] and m['sender']):
        raise ValueError(tr('Enter the mail server and the sender first.'))
    ui = get_lang()
    set_lang(m['lang'])
    t = tr('Test message: FlowTrack reports reach this mailbox.')
    msg = _mail(m, 'FlowTrack: ' + tr('test message'), t, f'<p>✅ {html.escape(t)}</p>')
    set_lang(ui)
    try:
        smtp_send(m, msg)
    except MailError as e:
        raise ValueError(str(e)) from None


def _validate_webhook(src, old):
    """(1.11.0) The webhook from the UI: an empty secret / header field keeps the stored one, `clear_*` removes it."""
    w = defaults()['webhook']
    w['on'] = bool(src.get('on'))
    url = str(src.get('url') or '').strip()
    if url and (len(url) > 1000 or not re.match(r'^https?://[^\s<>"]+$', url)):
        raise ValueError(tr('The webhook address must start with https:// or http://.'))
    w['url'] = url
    if src.get('format') in FORMATS:
        w['format'] = src['format']
    sec = str(src.get('secret') or '')
    if len(sec) > 256 or any(ord(c) < 32 for c in sec):
        raise ValueError(tr('The secret: up to 256 characters, no control characters.'))
    w['secret'] = '' if src.get('clear_secret') else (sec or old['secret'])
    hdr = str(src.get('header') or '').strip()
    if hdr and not HEADER_RE.match(hdr):
        raise ValueError(tr('The extra header is "Name: value", e.g. Authorization: Bearer abc123.'))
    w['header'] = '' if src.get('clear_header') else (hdr or old['header'])
    w['verify'] = bool(src.get('verify', True))
    if src.get('min_sev') in SEVERITIES:
        w['min_sev'] = src['min_sev']
    if known_lang(src.get('lang')):
        w['lang'] = src['lang']
    if w['on'] and not w['url']:
        raise ValueError(tr('Enter the webhook address to switch the webhook on.'))
    return w


def _validate_siem(src):
    """(1.11.0) The syslog / SIEM receiver from the UI."""
    m = defaults()['siem']
    m['on'] = bool(src.get('on'))
    host = str(src.get('host') or '').strip()
    if host and not HOST_RE.match(host):
        raise ValueError(tr('The SIEM / syslog server is a host name or an IP address, e.g. siem.example.com.'))
    m['host'] = host
    try:
        m['port'] = 514 if src.get('port') in (None, '') else int(src['port'])      # an empty field: the syslog port
        assert 1 <= m['port'] <= 65535
    except (TypeError, ValueError, AssertionError):
        raise ValueError(tr('The port is a number 1–65535.')) from None
    if src.get('transport') in SIEM_TRANSPORTS:
        m['transport'] = src['transport']
    if src.get('format') in SIEM_FORMATS:
        m['format'] = src['format']
    try:
        m['facility'] = int(src.get('facility', 16))
        assert 16 <= m['facility'] <= 23          # local0 … local7
    except (TypeError, ValueError, AssertionError):
        raise ValueError(tr('The facility is local0 … local7.')) from None
    m['verify'] = bool(src.get('verify', True))
    if src.get('min_sev') in SEVERITIES:
        m['min_sev'] = src['min_sev']
    if known_lang(src.get('lang')):
        m['lang'] = src['lang']
    if m['on'] and not m['host']:
        raise ValueError(tr('Enter the SIEM / syslog server to switch it on.'))
    return m


class SiemError(Exception):
    pass


def _utc(t):
    """'2026-10-18 15:30:00' (ClickHouse, UTC) or unix seconds -> aware datetime."""
    if isinstance(t, (int, float)):
        return datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    try:
        return datetime.datetime.strptime(str(t)[:19], '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _trim(v, n=50):
    """The event's own details (info JSON) for a SIEM: scalars as they are, long lists and maps cut to n items."""
    if isinstance(v, list):
        return [_trim(x, n) for x in v[:n]]
    if isinstance(v, dict):
        return {str(k): _trim(x, n) for k, x in list(v.items())[:n]}
    return v


def siem_record(e):
    """One event's fields for a SIEM: kind, severity, title, text and what the stored row says."""
    r = e.get('row') or {}
    info = r.get('info') or {}
    if isinstance(info, str):             # the detector hands its rows with info parsed; a row read back has the JSON
        try:
            info = json.loads(info)
        except ValueError:
            info = {}
    info = info if isinstance(info, dict) else {}
    rec = {'kind': e.get('kind', ''), 'severity': e.get('sev', 'info'), 'title': e.get('title', ''), 'text': e.get('text', ''),
           'src': r.get('src') or e.get('src') or '', 'dst': r.get('dst') or e.get('dst') or '', 'port': int(r.get('port') or e.get('port') or 0),
           'proto': PROTO.get(int(r.get('proto') or 0), str(r.get('proto') or '')) if r.get('proto') else '',
           'device': r.get('exporter') or e.get('device') or '', 'hits': int(r.get('hits') or 0), 'value': r.get('value'),
           'first_seen': _utc(r['first_seen']).isoformat() if r.get('first_seen') and _utc(r['first_seen']) else '',
           'last_seen': _utc(r['last_seen']).isoformat() if r.get('last_seen') and _utc(r['last_seen']) else '',
           'key': r.get('key', ''), 'country': info.get('country', ''), 'org': info.get('org', ''), 'asn': info.get('asn') or 0}
    rec['details'] = _trim({k: v for k, v in info.items() if k not in ('country', 'org', 'asn')})
    return rec


def _cef_h(v):
    return str(v).replace('\\', '\\\\').replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def _cef_v(v):
    return str(v).replace('\\', '\\\\').replace('=', '\\=').replace('\r', '').replace('\n', '\\n')


def siem_lines(m, events, now=None):
    """RFC 5424 syslog messages (bytes), one per event, with a CEF or a JSON body."""
    now = now or time.time()
    host = re.sub(r'[^!-~]', '', socket.gethostname())[:255] or '-'
    ts = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'
    out = []
    for e in events:
        rec = siem_record(e)
        sys_sev, cef_sev = SIEM_SEV.get(rec['severity'], (6, 3))
        msgid = re.sub(r'[^!-~]', '', rec['kind'])[:32] or '-'
        if m['format'] == 'json':
            body = json.dumps(dict({'@timestamp': ts, 'source': 'FlowTrack', 'version': VERSION, 'host': host}, **rec), ensure_ascii=False)
        else:
            ext = {'rt': int(now * 1000), 'msg': rec['text'], 'src': rec['src'], 'dst': rec['dst'], 'dpt': rec['port'] or '', 'proto': rec['proto'],
                   'dvc': rec['device'], 'cnt': rec['hits'] or '', 'cs1Label': 'country', 'cs1': rec['country'], 'cs2Label': 'org', 'cs2': rec['org'],
                   'cn1Label': 'asn', 'cn1': rec['asn'] or '', 'cs3Label': 'key', 'cs3': rec['key']}
            for k, col in (('start', 'first_seen'), ('end', 'last_seen')):
                if rec[col]:
                    ext[k] = int(datetime.datetime.fromisoformat(rec[col]).timestamp() * 1000)
            for lab in ('cs1', 'cs2', 'cn1', 'cs3'):          # a label only with its value
                if ext.get(lab) in ('', None, 0):
                    ext.pop(lab, None)
                    ext.pop(lab + 'Label', None)
            body = (f"CEF:0|FlowTrack|FlowTrack|{_cef_h(VERSION)}|{_cef_h(rec['kind'])}|{_cef_h(rec['title'])}|{cef_sev}|"
                    + ' '.join(f'{k}={_cef_v(v)}' for k, v in ext.items() if v not in ('', None)))
        line = f"<{m['facility'] * 8 + sys_sev}>1 {ts} {host} FlowTrack - {msgid} - ".encode() + body.encode()
        out.append(line[:8000] if m['transport'] == 'udp' else line)      # a UDP datagram stays within what receivers take
    return out


def siem_send(m, lines, timeout=10):
    """UDP: one datagram per message; TCP / TLS: one connection, messages ended by a newline (RFC 6587 non-transparent
    framing, which rsyslog, syslog-ng, Graylog, Splunk and the SIEM agents read). SiemError for people."""
    where = f"{m['host']}:{m['port']}"
    try:
        if m['transport'] == 'udp':
            fam = socket.getaddrinfo(m['host'], m['port'], type=socket.SOCK_DGRAM)[0]
            with socket.socket(fam[0], socket.SOCK_DGRAM) as s:
                for x in lines:
                    s.sendto(x, fam[4])
            return
        with socket.create_connection((m['host'], m['port']), timeout=timeout) as raw:
            s = raw
            if m['transport'] == 'tls':
                ctx = ssl.create_default_context() if m['verify'] else ssl._create_unverified_context()
                s = ctx.wrap_socket(raw, server_hostname=m['host'])
            s.sendall(b''.join(x + b'\n' for x in lines))
            if s is not raw:
                s.close()
    except ssl.SSLCertVerificationError as e:
        raise SiemError(tr('The certificate of {where} is not trusted ({error}). Untick "Verify the certificate" only for your own server.',
                           where=where, error=e.verify_message or e.reason)) from None
    except ssl.SSLError as e:
        raise SiemError(tr('TLS with {where} failed ({error}).', where=where, error=e.reason or e)) from None
    except (socket.timeout, TimeoutError):
        raise SiemError(tr('No answer from {where}.', where=where)) from None
    except OSError as e:
        raise SiemError(tr('No connection to {where} ({error}).', where=where, error=e.strerror or e)) from None


def test_siem(cfg):
    m = cfg['siem']
    if not m['host']:
        raise ValueError(tr('Enter the SIEM / syslog server first.'))
    ui = get_lang()
    set_lang(m['lang'])
    lines = siem_lines(m, [{'kind': 'test', 'sev': 'info', 'title': 'FlowTrack', 'text': tr('Test message: events reach this SIEM / syslog server.')}])
    set_lang(ui)
    try:
        siem_send(m, lines)
    except SiemError as e:
        raise ValueError(str(e)) from None


class WebhookError(Exception):
    pass


def webhook_body(w, events, more, link):
    """The JSON a webhook gets: FlowTrack's own (`json`) or a message for Slack / Mattermost / Rocket.Chat or Discord."""
    if w['format'] == 'json':
        keep = lambda r: {k: v for k, v in (r or {}).items() if isinstance(v, (str, int, float, bool)) and k not in ('addrs', 'ports')}   # noqa: E731
        return {'source': 'FlowTrack', 'version': VERSION, 'link': link or '', 'more': more,
                'events': [{'kind': e.get('kind', ''), 'severity': e.get('sev', 'info'), 'title': e.get('title', ''), 'text': e.get('text', ''),
                            'details': dict(keep(e.get('row')) or keep({k: e[k] for k in ('src', 'dst', 'port', 'ip', 'device', 'when') if k in e}),
                                            **{k: v for k, v in siem_record(e).items() if k in ('country', 'org', 'asn', 'details') and v})}
                           for e in events]}
    bold = (lambda t: f'*{t}*') if w['format'] == 'slack' else (lambda t: f'**{t}**')
    lines = [f"{ICON.get(e.get('sev'), '•')} {bold(e.get('title', '')[:200])}\n{e.get('text', '')[:1500]}" for e in events]
    if more:
        lines.append(trn(more, '…and {n} more event (the hourly limit of messages).', '…and {n} more events (the hourly limit of messages).'))
    if link:
        lines.append(f"{link}/#v=threats")
    text = '\n\n'.join(lines)
    return {'text': text} if w['format'] == 'slack' else {'content': text[:1990]}


def webhook_send(w, body, timeout=15):
    """POSTs the JSON; with a secret the request carries X-FlowTrack-Timestamp and X-FlowTrack-Signature =
    sha256=HMAC-SHA256(secret, "<timestamp>.<body>"). WebhookError for people (never with the secret)."""
    data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(w['url'], data=data, method='POST', headers={'Content-Type': 'application/json; charset=utf-8',
                                                                              'User-Agent': f'FlowTrack/{VERSION}'})
    if w['secret']:
        ts = str(int(time.time()))
        req.add_header('X-FlowTrack-Timestamp', ts)
        req.add_header('X-FlowTrack-Signature', 'sha256=' + hmac.new(w['secret'].encode(), ts.encode() + b'.' + data, hashlib.sha256).hexdigest())
    if w['header']:
        k, v = HEADER_RE.match(w['header']).groups()
        req.add_header(k, v)
    ctx = ssl.create_default_context() if w['verify'] else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            r.read(4096)
    except urllib.error.HTTPError as e:
        raise WebhookError(tr('The webhook answered {code}: {text}', code=e.code, text=e.read(300).decode(errors='replace').strip()[:200] or e.reason)) from None
    except urllib.error.URLError as e:
        why = e.reason
        if isinstance(why, ssl.SSLCertVerificationError):
            raise WebhookError(tr('The certificate of the webhook is not trusted ({error}). Untick "Verify the certificate" only for your own server.',
                                  error=why.verify_message or why.reason)) from None
        raise WebhookError(tr('No connection to the webhook ({error}).', error=getattr(why, 'strerror', None) or why)) from None
    except (socket.timeout, TimeoutError):
        raise WebhookError(tr('The webhook did not answer in {n} s.', n=timeout)) from None


def test_webhook(cfg):
    w = cfg['webhook']
    if not w['url']:
        raise ValueError(tr('Enter the webhook address first.'))
    ui = get_lang()
    set_lang(w['lang'])
    t = tr('Test message: notifications reach this webhook.')
    body = webhook_body(w, [{'kind': 'test', 'sev': 'info', 'title': 'FlowTrack', 'text': t}], 0, cfg['link'])
    set_lang(ui)
    try:
        webhook_send(w, body)
    except WebhookError as e:
        raise ValueError(str(e)) from None


class TelegramError(Exception):
    pass


def call(token, method, params=None, timeout=15):
    """One Bot API call -> its result. Errors never carry the token."""
    req = urllib.request.Request(f'{api_base()}/bot{token}/{method}', data=json.dumps(params or {}).encode(),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ans = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            ans = json.loads(e.read().decode())
        except ValueError:
            raise TelegramError(f'HTTP {e.code}') from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise TelegramError(str(getattr(e, 'reason', e)).replace(token, '…')) from None
    if not ans.get('ok'):
        raise TelegramError(str(ans.get('description') or 'error').replace(token, '…'))
    return ans.get('result')


def _explain(e):
    m = str(e)
    if 'Unauthorized' in m or 'Not Found' in m:
        return tr('Telegram does not know this bot token.')
    if 'chat not found' in m:
        return tr('Chat not found: send any message to the bot first (or add it to the group), then try again.')
    if 'blocked' in m or 'kicked' in m:
        return tr('The bot was blocked or removed from the chat.')
    return 'Telegram: ' + m


def test(cfg):
    t = cfg['telegram']
    if not (t['token'] and t['chat']):
        raise ValueError(tr('Enter the bot token and the chat ID first.'))
    set_lang(t['lang'])
    try:
        call(t['token'], 'sendMessage', {'chat_id': t['chat'], 'parse_mode': 'HTML', 'disable_web_page_preview': True,
             'text': '✅ <b>FlowTrack</b>\n' + html.escape(tr('Test message: notifications reach this chat.'))})
    except TelegramError as e:
        raise ValueError(_explain(e)) from None


def _token(cfg, token=''):
    token = token or cfg['telegram']['token']
    if not token:
        raise ValueError(tr('Enter the bot token first.'))
    if not TOKEN_RE.match(token):
        raise ValueError(tr('The bot token looks wrong.'))
    return token


def _chat_info(c):
    name = c.get('title') or ' '.join(x for x in (c.get('first_name'), c.get('last_name')) if x) or c.get('username') or ''
    return {'id': str(c['id']), 'type': c.get('type', ''), 'name': name}


def check_chat(cfg, token=''):
    """The entered chat as Telegram knows it (getChat). Unlike chats() it needs no fresh message to the bot:
    Telegram keeps the messages to a bot (getUpdates) for 24 hours only."""
    token = _token(cfg, token)
    try:
        return _chat_info(call(token, 'getChat', {'chat_id': cfg['telegram']['chat']}))
    except TelegramError as e:
        raise ValueError(_explain(e)) from None


def chats(cfg, token=''):
    """Chats that wrote to the bot in the last 24 hours (getUpdates): to pick the chat ID without looking it up elsewhere."""
    token = _token(cfg, token)
    try:
        ups = call(token, 'getUpdates', {'limit': 100, 'timeout': 0}) or []
    except TelegramError as e:
        raise ValueError(_explain(e)) from None
    out = {}
    for u in ups:
        for k in ('message', 'channel_post', 'my_chat_member', 'edited_message'):
            c = (u.get(k) or {}).get('chat')
            if c:
                out[str(c['id'])] = _chat_info(c)
    return list(out.values())


class MailError(Exception):
    pass


@functools.lru_cache(maxsize=1)
def ehlo_name():
    """This server's name for EHLO, looked up once (1.10.0): with a slow reverse DNS socket.getfqdn() took 5 s for
    every message."""
    return socket.getfqdn()


class _LoginDropped(Exception):
    pass


def _login(s, user, password):
    """One sign-in attempt (1.12.0). smtplib's login() tries the next mechanism after a refusal, and Gmail drops the line
    after the first one — so a wrong password showed as "the server closed the connection, check the encryption"."""
    mechs = (s.esmtp_features.get('auth') or '').upper().split()
    mech = next((x for x in ('PLAIN', 'LOGIN') if x in mechs), None)
    try:
        if not mech:
            s.login(user, password)
            return
        s.user, s.password = user, password
        s.auth(mech, getattr(s, 'auth_' + mech.lower()), initial_response_ok=True)
    except smtplib.SMTPServerDisconnected:
        raise _LoginDropped() from None


def _auth_refused(m):
    h = m['host'].lower()
    if h.endswith('gmail.com') or h.endswith('googlemail.com'):
        return tr('Gmail did not accept the login or the password. Gmail needs an app password: turn on 2-Step Verification in your Google account, create an app password (Security → App passwords) and enter it here instead of your usual password.')
    if 'office365' in h or 'outlook' in h:
        return tr('Microsoft 365 did not accept the login or the password: use an app password, and check that SMTP AUTH is allowed for this mailbox.')
    return tr('The mail server did not accept the login or the password (some services need an app password).')


def smtp_send(m, msg, timeout=20):
    """Sends one message through the configured server; errors are explained for people (never with the password)."""
    ctx = ssl.create_default_context() if m['verify'] else ssl._create_unverified_context()
    where = f"{m['host']}:{m['port']}"
    try:
        s = (smtplib.SMTP_SSL(m['host'], m['port'], timeout=timeout, context=ctx, local_hostname=ehlo_name()) if m['security'] == 'ssl'
             else smtplib.SMTP(m['host'], m['port'], timeout=timeout, local_hostname=ehlo_name()))
        with s:
            s.ehlo()
            if m['security'] == 'starttls':
                if not s.has_extn('starttls'):
                    raise MailError(tr('The mail server does not offer STARTTLS: choose SSL/TLS (usually port 465) or no encryption.'))
                s.starttls(context=ctx)
                s.ehlo()
            if m['user']:
                if not s.has_extn('auth'):
                    raise MailError(tr('The mail server does not ask for a login here: leave the login empty, or turn on encryption.'))
                _login(s, m['user'], m['password'])
            s.send_message(msg)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise MailError(_auth_refused(m)) from None
    except _LoginDropped:
        raise MailError(_auth_refused(m)) from None
    except smtplib.SMTPRecipientsRefused as e:
        raise MailError(tr('The mail server refused the recipients: {to}.', to=', '.join(e.recipients))) from None
    except smtplib.SMTPSenderRefused:
        raise MailError(tr('The mail server refused the sender address {sender}.', sender=m['sender'])) from None
    except smtplib.SMTPServerDisconnected:
        raise MailError(tr('{where} closed the connection — check the encryption and the port (465 is SSL/TLS, 587 is STARTTLS).',
                           where=where)) from None
    except smtplib.SMTPResponseException as e:
        raise MailError(tr('The mail server answered: {code} {text}', code=e.smtp_code,
                           text=e.smtp_error.decode(errors='replace')[:200] if isinstance(e.smtp_error, bytes) else str(e.smtp_error)[:200])) from None
    except ssl.SSLCertVerificationError as e:
        raise MailError(tr('The certificate of {where} is not trusted ({error}). Untick "Verify the certificate" only for your own server.',
                           where=where, error=e.verify_message or e.reason)) from None
    except ssl.SSLError as e:
        raise MailError(tr('TLS with {where} failed ({error}) — check the encryption and the port (465 is SSL/TLS, 587 is STARTTLS).',
                           where=where, error=e.reason or e)) from None
    except (socket.timeout, TimeoutError):
        raise MailError(tr('No answer from {where}.', where=where)) from None
    except smtplib.SMTPException as e:
        raise MailError('SMTP: ' + str(e)[:200]) from None
    except OSError as e:
        raise MailError(tr('No connection to {where} ({error}).', where=where, error=e.strerror or e)) from None


def _mail(m, subject, text, body_html):
    msg = EmailMessage()
    msg['Subject'] = re.sub(r'[\r\n]+', ' ', subject)[:200]
    msg['From'] = m['sender']
    msg['To'] = ', '.join(m['to'])
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=m['sender'].rsplit('@', 1)[-1])
    msg.set_content(text)
    msg.add_alternative(f'<!doctype html><html><body style="margin:0;padding:16px;background:#f4f6fa;font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;color:#1c2333">'
                        f'<div style="max-width:640px;margin:0 auto;background:#fff;border-radius:10px;padding:18px 20px">'
                        f'<div style="font-weight:800;font-size:16px;margin-bottom:12px">FlowTrack</div>{body_html}</div></body></html>', subtype='html')
    return msg


def test_mail(cfg):
    m = cfg['email']
    if not (m['host'] and m['sender'] and m['to']):
        raise ValueError(tr('Enter the mail server, the sender and at least one recipient first.'))
    ui = get_lang()
    set_lang(m['lang'])
    t = tr('Test message: notifications reach this mailbox.')
    msg = _mail(m, 'FlowTrack: ' + tr('test message'), t, f'<p>✅ {html.escape(t)}</p>')
    set_lang(ui)                                  # errors in the language of the page
    try:
        smtp_send(m, msg)
    except MailError as e:
        raise ValueError(str(e)) from None


def format_mail(events, more, m, link):
    """One e-mail for the events of a check: subject, plain text and HTML."""
    set_lang(m['lang'])
    events = events[:10]
    n = len(events) - 1 + more
    subject = f"FlowTrack: {ICON.get(events[0]['sev'], '•')} {events[0]['title'][:120]}" + (f' +{n}' if n > 0 else '')
    text, body = [], []
    for e in events:
        text.append(f"{ICON.get(e['sev'], '•')} {e['title'][:200]}\n{e['text'][:3000]}")
        body.append(f'<div style="border-left:4px solid {SEV_COLOR.get(e["sev"], "#888")};padding:6px 0 6px 12px;margin:0 0 14px">'
                    f'<b>{html.escape(e["title"][:200])}</b><br>{html.escape(e["text"][:3000])}</div>')
    if more:
        t = trn(more, '…and {n} more event (the hourly limit of messages).', '…and {n} more events (the hourly limit of messages).')
        text.append(t)
        body.append(f'<p style="color:#5b6478">{html.escape(t)}</p>')
    if link:
        t = tr('Open the events in FlowTrack')
        text.append(f'{t}: {link}/#v=threats')
        body.append(f'<p><a href="{html.escape(link)}/#v=threats" style="display:inline-block;background:#2f7bff;color:#fff;'
                    f'text-decoration:none;padding:8px 14px;border-radius:7px;font-weight:700">{html.escape(t)}</a></p>')
    return _mail(m, subject, '\n\n'.join(text), ''.join(body))


def format_events(events, more, lang, link):
    """One message for the events of a check (HTML)."""
    set_lang(lang)
    parts, size = [], 0
    for i, e in enumerate(events):
        part = f"{ICON.get(e['sev'], '•')} <b>{html.escape(e['title'][:200])}</b>\n{html.escape(e['text'][:3000])}"
        if parts and size + len(part) > 3500:      # Telegram takes 4096 characters: whole events only, the rest counted
            more += len(events) - i
            break
        parts.append(part)
        size += len(part) + 2
    if more:
        parts.append(html.escape(trn(more, '…and {n} more event (the hourly limit of messages).', '…and {n} more events (the hourly limit of messages).')))
    if link:
        parts.append(f'<a href="{html.escape(link)}/#v=threats">{html.escape(tr("Open the events in FlowTrack"))}</a>')
    return '\n\n'.join(parts)


def _ready(cfg, ch):
    c = cfg[ch]
    if ch == 'webhook':
        return bool(c['on'] and c['url'])
    if ch == 'siem':
        return bool(c['on'] and c['host'])
    if ch == 'email':      # (1.10.0) the server of Settings → General with the notification recipients
        return bool(c['on'] and c['host'] and c['sender'] and c['to'])
    return bool(c['on'] and c['token'] and c['chat'])


class Notifier:
    """Takes the new events of each check, decides what goes out on each channel and sends it from the channel's thread."""

    def __init__(self, log=print):
        self.log = log
        self.q = {ch: queue.Queue(maxsize=200) for ch in CHANNELS}
        self.sent, self.held = {ch: [] for ch in CHANNELS}, {ch: 0 for ch in CHANNELS}
        for ch in CHANNELS:
            threading.Thread(target=self._worker, args=(ch,), name=f'notify-{ch}', daemon=True).start()

    def push(self, events, kinds_cfg, t1, now=None):
        """events: dicts with kind (and row or title/text) — the new events of the window ending t1. Returns how many
        events went to the queues, over all channels."""
        now = now or time.time()
        if t1 < now - RECENT or not events:
            return 0
        cfg = load()
        return sum(self._push(ch, cfg, events, kinds_cfg, now) for ch in CHANNELS if _ready(cfg, ch))

    def _push(self, ch, cfg, events, kinds_cfg, now):
        c = cfg[ch]
        lo = SEVERITIES.index(c['min_sev'])
        pick = []
        for e in events:
            sev = kinds_cfg.get(e['kind'], {}).get('sev', 'info')
            if cfg[KINDS[ch]].get(e['kind'], True) and SEVERITIES.index(sev) >= lo:
                pick.append(dict(e, sev=sev))
        if not pick:
            return 0
        if ch == 'siem':                  # (1.11.0) a SIEM wants every event: no hourly limit, one message each
            try:
                self.q[ch].put_nowait((pick[:500], 0, dict(c, link=cfg['link']), time.time()))
            except queue.Full:
                self.log('WARN notifications (siem): the queue is full, events not sent')
                return 0
            return len(pick[:500])
        self.sent[ch] = [x for x in self.sent[ch] if x > now - 3600]
        room = cfg['per_hour'] - len(self.sent[ch])
        if room <= 0:
            self.held[ch] += len(pick)
            return 0
        pick.sort(key=lambda e: -SEVERITIES.index(e['sev']))
        go, more = pick[:max(1, min(room, 10))], len(pick) - min(len(pick), max(1, min(room, 10)))
        self.sent[ch].append(now)
        try:
            self.q[ch].put_nowait((go, more + self.held[ch], dict(c, link=cfg['link']), time.time()))
            self.held[ch] = 0
        except queue.Full:
            self.log(f'WARN notifications ({ch}): the queue is full, events not sent')
        return len(go)

    def _send(self, ch, events, more, c):
        texts = [render(e, c['lang']) for e in events]
        if ch == 'siem':
            set_lang(c['lang'])
            lines = siem_lines(c, texts)
            set_lang('en')
            siem_send(c, lines)
        elif ch == 'webhook':
            set_lang(c['lang'])
            body = webhook_body(c, texts, more, c['link'])
            set_lang('en')                        # errors go to the log, in English
            webhook_send(c, body)
        elif ch == 'telegram':
            call(c['token'], 'sendMessage', {'chat_id': c['chat'], 'parse_mode': 'HTML', 'disable_web_page_preview': True,
                                             'text': format_events(texts, more, c['lang'], c['link'])})
        else:
            msg = format_mail(texts, more, c, c['link'])
            set_lang('en')                        # errors go to the log, in English
            smtp_send(c, msg)

    def _worker(self, ch):
        while True:
            events, more, c, at = self.q[ch].get()
            for attempt in range(5):
                try:
                    self._send(ch, events, more, c)
                    break
                except (TelegramError, MailError, WebhookError, SiemError) as e:
                    set_lang('en')
                    why = _explain(e) if ch == 'telegram' else str(e)
                    self.log(f'WARN {ch}: {why}' + (' — trying again' if attempt < 4 else ' — not sent'))
                    if time.time() - at > 3600:
                        break
                    time.sleep(min(600, 20 * 3 ** attempt))
                except Exception as e:            # a bug must not stop the thread
                    self.log(f'WARN {ch}: {str(e)[:200]}')
                    break


def render(e, lang):
    """Title and text of an event in the notification language (a stored event is described again in it)."""
    if 'row' in e:
        import detect
        set_lang(lang)
        title, text = detect.describe(e['row'])
        return dict(e, title=title, text=text)
    return e
