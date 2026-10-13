"""Notifications: new events go to Telegram through the user's own bot (1.6.2) and by e-mail over SMTP (1.6.4).

Only an event's first appearance is sent — an activity that goes on extends its event quietly; looking back over the
past at the first start sends nothing. What goes out: the kinds ticked for it, at or above a minimum priority, at most
`per_hour` messages an hour per channel (the rest are counted in the next message); several events of one 10-minute
check go as one message. Each channel sends from its own thread with retries, so an unreachable Telegram or mail
server never holds up the detections or the other channel.

The bot token and the SMTP password are secrets: kept in STATE_DIR/notify.json (0600, the service user only), never
sent to the browser and never written to the log."""
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

from common import STATE_DIR, get_lang, known_lang, set_lang, tr, trn

CONFIG = os.path.join(STATE_DIR, 'notify.json')
SEVERITIES = ('info', 'warn', 'crit')
TOKEN_RE = re.compile(r'^\d{5,15}:[A-Za-z0-9_-]{30,50}$')
CHAT_RE = re.compile(r'^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$')
MAIL_RE = re.compile(r'^[^@\s<>"(),;:\\]{1,64}@[A-Za-z0-9.-]{1,253}$')
HOST_RE = re.compile(r'^([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$|^[0-9a-fA-F:]{2,39}$')
SECURITY = ('starttls', 'ssl', 'none')
CHANNELS = ('telegram', 'email')
KINDS = {'telegram': 'kinds', 'email': 'email_kinds'}      # per channel: which kinds go out (absent = yes)
SEV_COLOR = {'crit': '#e5484d', 'warn': '#f5a524', 'info': '#3e8ed0'}
RECENT = 1800              # only windows that ended this recently are notified (not the look back at the first start)
ICON = {'crit': '🔴', 'warn': '🟠', 'info': '🔵'}


def api_base():
    return os.environ.get('FT_TELEGRAM_API', 'https://api.telegram.org').rstrip('/')


def defaults():
    return {'telegram': {'on': False, 'token': '', 'chat': '', 'min_sev': 'warn', 'lang': 'uk'},
            'email': {'on': False, 'host': '', 'port': 587, 'security': 'starttls', 'verify': True, 'user': '', 'password': '',
                      'sender': '', 'to': [], 'min_sev': 'warn', 'lang': 'uk'},
            'kinds': {}, 'email_kinds': {}, 'link': '', 'per_hour': 20}


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
    return {'telegram': t, 'email': m, 'kinds': cfg['kinds'], 'email_kinds': cfg['email_kinds'], 'link': cfg['link'],
            'per_hour': cfg['per_hour']}


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
    if 'email' in body:
        cfg['email'] = _validate_email(body.get('email') or {}, old['email'])
        cfg['email_kinds'] = {str(k): bool(v) for k, v in (body.get('email_kinds') or {}).items()}
    else:                                         # a client that knows only Telegram keeps the e-mail settings
        cfg['email'], cfg['email_kinds'] = dict(old['email']), dict(old['email_kinds'])
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
        raise ValueError(tr('Enter the mail server, the sender and at least one recipient to switch e-mail on.'))
    return m


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


def smtp_send(m, msg, timeout=20):
    """Sends one message through the configured server; errors are explained for people (never with the password)."""
    ctx = ssl.create_default_context() if m['verify'] else ssl._create_unverified_context()
    where = f"{m['host']}:{m['port']}"
    try:
        s = (smtplib.SMTP_SSL(m['host'], m['port'], timeout=timeout, context=ctx) if m['security'] == 'ssl'
             else smtplib.SMTP(m['host'], m['port'], timeout=timeout))
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
                s.login(m['user'], m['password'])
            s.send_message(msg)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise MailError(tr('The mail server did not accept the login or the password (some services need an app password).')) from None
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
    return bool(c['on'] and (c['token'] and c['chat'] if ch == 'telegram' else c['host'] and c['sender'] and c['to']))


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
        if ch == 'telegram':
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
                except (TelegramError, MailError) as e:
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
