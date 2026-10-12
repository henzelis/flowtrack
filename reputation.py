"""IP reputation (FlowTrack 1.6.1): public lists of malicious addresses, downloaded by the collector once a day
straight from their publishers (nothing is sent anywhere but a plain download) and looked up by the detector for the
outside addresses of each 10-minute window — never on the receiving path, so it costs nothing per record.

All lists of one IP version are merged into one sorted table of non-overlapping ranges, each with the set of lists
that cover it: a lookup is one binary search, whatever the number of lists and however their networks nest."""
import bisect
import csv
import io
import ipaddress
import json
import os
import time
import urllib.request

from common import STATE_DIR, VERSION

DIR = os.path.join(STATE_DIR, 'reputation')
META = os.path.join(DIR, 'meta.json')
REFRESH = 86400          # a list is downloaded again after a day (ThreatFox's "recent" export: every 6 hours)
RETRY = 3600             # after a failed download
MAX_BYTES = 32 << 20


def _lines(text):
    for line in text.splitlines():
        line = line.strip()
        if line and line[0] not in '#;':
            yield line.split()[0]


def _drop(text):
    for line in text.splitlines():
        try:
            yield json.loads(line)['cidr']
        except (ValueError, KeyError, TypeError):
            continue


def _threatfox(text):
    for row in csv.reader(io.StringIO(text), skipinitialspace=True):
        if len(row) > 4 and not row[0].startswith('#'):
            yield row[2].rsplit(':', 1)[0].strip('[]')


def _dshield(text):
    for line in text.splitlines():
        p = line.split('\t')
        if len(p) > 2 and p[0][:1].isdigit():
            yield f'{p[0]}/{p[2]}'


# name -> (category, urls, parser, refresh seconds, link for people). Categories: malware = botnet controllers and
# malware delivery (contact is critical), drop = netblocks run by criminals, attack = hosts seen attacking others,
# anon = Tor exit relays. All are free to use; FlowTrack downloads them on the customer's own server.
LISTS = {
    'feodo':          ('malware', ['https://feodotracker.abuse.ch/downloads/ipblocklist.txt'], _lines, REFRESH, 'https://feodotracker.abuse.ch/'),
    'threatfox':      ('malware', ['https://threatfox.abuse.ch/export/csv/ip-port/recent/'], _threatfox, 6 * 3600, 'https://threatfox.abuse.ch/'),
    'spamhaus_drop':  ('drop', ['https://www.spamhaus.org/drop/drop_v4.json', 'https://www.spamhaus.org/drop/drop_v6.json'], _drop, REFRESH, 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/'),
    'et_compromised': ('attack', ['https://rules.emergingthreats.net/blockrules/compromised-ips.txt'], _lines, REFRESH, 'https://rules.emergingthreats.net/'),
    'cins':           ('attack', ['https://cinsscore.com/list/ci-badguys.txt'], _lines, REFRESH, 'https://cinsscore.com/'),
    'blocklist_de':   ('attack', ['https://lists.blocklist.de/lists/all.txt'], _lines, REFRESH, 'https://www.blocklist.de/'),
    'dshield':        ('attack', ['https://feeds.dshield.org/block.txt'], _dshield, REFRESH, 'https://www.dshield.org/'),
    'tor_exit':       ('anon', ['https://check.torproject.org/torbulkexitlist'], _lines, REFRESH, 'https://metrics.torproject.org/'),
}
TITLES = {'feodo': 'abuse.ch Feodo Tracker', 'threatfox': 'abuse.ch ThreatFox', 'spamhaus_drop': 'Spamhaus DROP',
          'et_compromised': 'ET compromised', 'cins': 'CINS Army', 'blocklist_de': 'blocklist.de', 'dshield': 'DShield top',
          'tor_exit': 'Tor exits', 'custom': 'own list'}
CUSTOM = 'custom'


_SPECIAL = [ipaddress.ip_network(n) for n in ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3', '::/8', 'fc00::/7', 'fe80::/10', 'ff00::/8')]


def networks(items):
    """Valid networks from list entries. Left out: private, loopback and other special ranges and anything that
    overlaps them, and blocks wider than /8 (IPv6 /16) — a list with a bogon or 0.0.0.0/0 must never flag the LAN
    or the whole internet."""
    out = []
    for s in items:
        try:
            n = ipaddress.ip_network(s.strip(), strict=False)
        except ValueError:
            continue
        if n.prefixlen < (8 if n.version == 4 else 16) or n.is_private or n.is_reserved or n.is_multicast \
                or any(n.version == x.version and n.overlaps(x) for x in _SPECIAL):
            continue
        out.append(n)
    return out


def meta():
    try:
        with open(META) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def _save_meta(m):
    tmp = META + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(m, f)
    os.replace(tmp, META)


def _get(url):
    req = urllib.request.Request(url, headers={'User-Agent': f'FlowTrack/{VERSION} (+https://github.com/henzelis/flowtrack)'})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('too large')
    return data.decode('utf-8', 'replace')


def update(enabled, log=print, now=None):
    """Download the enabled lists that are due. A failed or empty download keeps the previous copy. -> names updated."""
    os.makedirs(DIR, exist_ok=True)
    now, m, done = now or time.time(), meta(), []
    for name in enabled:
        if name not in LISTS:
            continue
        cat, urls, parse, every, _ = LISTS[name]
        st = m.get(name, {})
        if now - st.get('tried', 0) < (every if st.get('ok') else RETRY):
            continue
        st['tried'] = now
        try:
            nets = networks([x for u in urls for x in parse(_get(u))])
            if not nets:
                raise ValueError('no addresses in the answer')
            tmp = os.path.join(DIR, name + '.tmp')
            with open(tmp, 'w') as f:
                f.write('\n'.join(str(n) for n in nets) + '\n')
            os.replace(tmp, os.path.join(DIR, name + '.txt'))
            st.update(ok=True, updated=now, count=len(nets), error='')
            done.append(name)
        except Exception as ex:          # unreachable, refused, garbage: keep the old copy, try again in an hour
            st.update(ok=False, error=str(ex)[:200])
            log(f'WARN reputation list {name}: {str(ex)[:200]}')
        m[name] = st
        _save_meta(m)
    return done


class Index:
    """Lookup of addresses in the enabled lists (and the own list from the settings)."""

    def __init__(self, enabled=(), custom=()):
        self.key = None
        self.build(enabled, custom)

    def build(self, enabled, custom):
        files = [(n, os.path.join(DIR, n + '.txt')) for n in enabled if n in LISTS]
        key = (tuple(sorted(custom)), tuple((n, os.path.getmtime(p)) for n, p in files if os.path.exists(p)))
        if key == self.key:
            return False
        bounds = {4: [], 6: []}
        for name, path in files:
            try:
                with open(path) as f:
                    nets = networks(f.read().split())
            except OSError:
                continue
            for n in nets:
                bounds[n.version].append((int(n.network_address), int(n.broadcast_address), name))
        for n in networks(custom):
            bounds[n.version].append((int(n.network_address), int(n.broadcast_address), CUSTOM))
        self.tables = {v: _segments(b) for v, b in bounds.items()}
        self.size = sum(len(b) for b in bounds.values())
        self.key = key
        return True

    def lookup(self, ip):
        """-> frozenset of list names covering the address (empty if none or not an address)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return frozenset()
        starts, ends, names = self.tables[a.version]
        x = int(a)
        i = bisect.bisect_right(starts, x) - 1
        return names[i] if i >= 0 and x <= ends[i] else frozenset()


def _segments(ranges):
    """[(start, end, name)] (may overlap) -> (starts, ends, names): sorted non-overlapping segments, each with the
    set of names covering all of it."""
    ev = []
    for s, e, n in ranges:
        ev.append((s, 1, n))
        ev.append((e + 1, -1, n))
    ev.sort(key=lambda x: (x[0], x[1]))
    starts, ends, names, active, i = [], [], [], {}, 0
    while i < len(ev):
        pos = ev[i][0]
        while i < len(ev) and ev[i][0] == pos:
            _, d, n = ev[i]
            active[n] = active.get(n, 0) + d
            if not active[n]:
                del active[n]
            i += 1
        if active:
            nxt = ev[i][0] if i < len(ev) else pos
            if starts and ends[-1] == pos - 1 and names[-1] == frozenset(active):
                ends[-1] = nxt - 1
            else:
                starts.append(pos)
                ends.append(nxt - 1)
                names.append(frozenset(active))
    return starts, ends, names


def category(names):
    """The worst category among list names: malware > drop > attack > anon (own list counts as attack)."""
    cats = {LISTS[n][0] if n in LISTS else 'attack' for n in names}
    return next((c for c in ('malware', 'drop', 'attack', 'anon') if c in cats), '')
