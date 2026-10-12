"""Notifications (FlowTrack 1.6.2): new events go to Telegram through the user's own bot.

Only an event's first appearance is sent — an activity that goes on extends its event quietly; looking back over the
past at the first start sends nothing. What goes out: the kinds ticked for it, at or above a minimum priority, at most
`per_hour` messages an hour (the rest are counted in the next message); several events of one 10-minute check go as
one message. Sending runs in its own thread with retries, so an unreachable Telegram never holds up the detections.

The bot token is a secret: kept in STATE_DIR/notify.json (0600, the service user only), never sent to the browser and
never written to the log."""
import html
import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request

from common import STATE_DIR, set_lang, tr

CONFIG = os.path.join(STATE_DIR, 'notify.json')
SEVERITIES = ('info', 'warn', 'crit')
TOKEN_RE = re.compile(r'^\d{5,15}:[A-Za-z0-9_-]{30,50}$')
CHAT_RE = re.compile(r'^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$')
RECENT = 1800              # only windows that ended this recently are notified (not the look back at the first start)
ICON = {'crit': '🔴', 'warn': '🟠', 'info': '🔵'}


def api_base():
    return os.environ.get('FT_TELEGRAM_API', 'https://api.telegram.org').rstrip('/')


def defaults():
    return {'telegram': {'on': False, 'token': '', 'chat': '', 'min_sev': 'warn', 'lang': 'uk', 'link': ''},
            'kinds': {}, 'per_hour': 20}


def load():
    cfg = defaults()
    try:
        with open(CONFIG) as f:
            saved = json.load(f)
    except (FileNotFoundError, ValueError):
        return cfg
    cfg['telegram'].update({k: v for k, v in (saved.get('telegram') or {}).items() if k in cfg['telegram']})
    cfg['kinds'] = {k: bool(v) for k, v in (saved.get('kinds') or {}).items()}
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
    """The settings for the browser: the token only as 'set or not'."""
    t = dict(cfg['telegram'], token='', token_set=bool(cfg['telegram']['token']))
    return {'telegram': t, 'kinds': cfg['kinds'], 'per_hour': cfg['per_hour']}


def validate(body, old):
    """The settings from the UI, checked; an empty token keeps the stored one. Raises ValueError for people."""
    cfg = defaults()
    t, src = cfg['telegram'], body.get('telegram') or {}
    t['on'] = bool(src.get('on'))
    tok = str(src.get('token') or '').strip()
    if tok and not TOKEN_RE.match(tok):
        raise ValueError(tr('The bot token looks wrong: it is like 123456789:AA… (from @BotFather).',
                            'Токен бота схожий на хибний: він має вигляд 123456789:AA… (від @BotFather).'))
    t['token'] = tok or old['telegram']['token']
    chat = str(src.get('chat') or '').strip()
    if chat and not CHAT_RE.match(chat):
        raise ValueError(tr('The chat ID is a number (a group\'s starts with -) or @channel.',
                            'ID чату — це число (у групи починається з -) або @канал.'))
    t['chat'] = chat
    if src.get('min_sev') in SEVERITIES:
        t['min_sev'] = src['min_sev']
    if src.get('lang') in ('en', 'uk'):
        t['lang'] = src['lang']
    link = str(src.get('link') or '').strip().rstrip('/')
    if link and not re.match(r'^https?://[^\s<>"]+$', link):
        raise ValueError(tr('The FlowTrack address must start with https:// or http://.', 'Адреса FlowTrack має починатися з https:// або http://.'))
    t['link'] = link
    if t['on'] and not (t['token'] and t['chat']):
        raise ValueError(tr('Enter the bot token and the chat ID to switch Telegram on.', 'Щоб увімкнути Telegram, введіть токен бота й ID чату.'))
    cfg['kinds'] = {str(k): bool(v) for k, v in (body.get('kinds') or {}).items()}
    try:
        cfg['per_hour'] = max(1, min(600, int(body.get('per_hour', 20))))
    except (TypeError, ValueError):
        raise ValueError(tr('Messages an hour must be a number.', 'Кількість повідомлень на годину має бути числом.')) from None
    return cfg


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
        return tr('Telegram does not know this bot token.', 'Telegram не знає цього токена бота.')
    if 'chat not found' in m:
        return tr('Chat not found: send any message to the bot first (or add it to the group), then try again.',
                  'Чат не знайдено: спершу надішліть боту будь-яке повідомлення (або додайте його в групу) і спробуйте знову.')
    if 'blocked' in m or 'kicked' in m:
        return tr('The bot was blocked or removed from the chat.', 'Бота заблоковано або видалено з чату.')
    return tr(f'Telegram: {m}', f'Telegram: {m}')


def test(cfg):
    t = cfg['telegram']
    if not (t['token'] and t['chat']):
        raise ValueError(tr('Enter the bot token and the chat ID first.', 'Спершу введіть токен бота й ID чату.'))
    set_lang(t['lang'])
    try:
        call(t['token'], 'sendMessage', {'chat_id': t['chat'], 'parse_mode': 'HTML', 'disable_web_page_preview': True,
             'text': '✅ <b>FlowTrack</b>\n' + html.escape(tr('Test message: notifications reach this chat.',
                                                             'Тестове повідомлення: сповіщення доходять у цей чат.'))})
    except TelegramError as e:
        raise ValueError(_explain(e)) from None


def chats(cfg, token=''):
    """Chats that wrote to the bot lately (getUpdates): to pick the chat ID without looking it up elsewhere."""
    token = token or cfg['telegram']['token']
    if not token:
        raise ValueError(tr('Enter the bot token first.', 'Спершу введіть токен бота.'))
    if not TOKEN_RE.match(token):
        raise ValueError(tr('The bot token looks wrong.', 'Токен бота схожий на хибний.'))
    try:
        ups = call(token, 'getUpdates', {'limit': 100, 'timeout': 0}) or []
    except TelegramError as e:
        raise ValueError(_explain(e)) from None
    out = {}
    for u in ups:
        for k in ('message', 'channel_post', 'my_chat_member', 'edited_message'):
            c = (u.get(k) or {}).get('chat')
            if c:
                name = c.get('title') or ' '.join(x for x in (c.get('first_name'), c.get('last_name')) if x) or c.get('username') or ''
                out[str(c['id'])] = {'id': str(c['id']), 'type': c.get('type', ''), 'name': name}
    return list(out.values())


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
        parts.append(html.escape(tr(f'…and {more} more event{"s" if more != 1 else ""} (the hourly limit of messages).',
                                    f'…і ще подій: {more} (ліміт повідомлень на годину).')))
    if link:
        parts.append(f'<a href="{html.escape(link)}/#v=threats">{html.escape(tr("Open the events in FlowTrack", "Відкрити події у FlowTrack"))}</a>')
    return '\n\n'.join(parts)


class Notifier:
    """Takes the new events of each check, decides what goes out and sends it from its own thread."""

    def __init__(self, log=print):
        self.log, self.q, self.sent, self.held = log, queue.Queue(maxsize=200), [], 0
        threading.Thread(target=self._worker, name='notify', daemon=True).start()

    def push(self, events, kinds_cfg, t1, now=None):
        """events: dicts with kind, title, text (in the notification language) — the new events of the window ending t1."""
        now = now or time.time()
        if t1 < now - RECENT or not events:
            return 0
        cfg = load()
        t = cfg['telegram']
        if not (t['on'] and t['token'] and t['chat']):
            return 0
        lo = SEVERITIES.index(t['min_sev'])
        pick = []
        for e in events:
            sev = kinds_cfg.get(e['kind'], {}).get('sev', 'info')
            if cfg['kinds'].get(e['kind'], True) and SEVERITIES.index(sev) >= lo:
                pick.append(dict(e, sev=sev))
        if not pick:
            return 0
        self.sent = [x for x in self.sent if x > now - 3600]
        room = cfg['per_hour'] - len(self.sent)
        if room <= 0:
            self.held += len(pick)
            return 0
        pick.sort(key=lambda e: -SEVERITIES.index(e['sev']))
        go, more = pick[:max(1, min(room, 10))], len(pick) - min(len(pick), max(1, min(room, 10)))
        self.sent.append(now)
        try:
            self.q.put_nowait((go, more + self.held, t, time.time()))
            self.held = 0
        except queue.Full:
            self.log('WARN notifications: the queue is full, events not sent')
        return len(go)

    def _worker(self):
        while True:
            events, more, t, at = self.q.get()
            for attempt in range(5):
                try:
                    texts = [render(e, t['lang']) for e in events]
                    call(t['token'], 'sendMessage', {'chat_id': t['chat'], 'parse_mode': 'HTML', 'disable_web_page_preview': True,
                                                     'text': format_events(texts, more, t['lang'], t['link'])})
                    break
                except TelegramError as e:
                    self.log(f'WARN telegram: {_explain(e)}' + (' — trying again' if attempt < 4 else ' — not sent'))
                    if time.time() - at > 3600:
                        break
                    time.sleep(min(600, 20 * 3 ** attempt))
                except Exception as e:            # a bug must not stop the thread
                    self.log(f'WARN telegram: {str(e)[:200]}')
                    break


def render(e, lang):
    """Title and text of an event in the notification language (a stored event is described again in it)."""
    if 'row' in e:
        import detect
        set_lang(lang)
        title, text = detect.describe(e['row'])
        return dict(e, title=title, text=text)
    return e
