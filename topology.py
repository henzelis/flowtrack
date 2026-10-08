"""Layer-3 topology of the exporting devices (FlowTrack 1.4, Path analysis): which devices are neighbours, through
which interfaces, and how much traffic each link carries as seen from both ends.

NetFlow carries no interface addresses, so the picture is built from the same data as the Through device page:
the interface addresses set in Settings → Devices, each device's own addresses (the one it exports from, its public
addresses), the inside networks that enter a device on its LAN interfaces, and the addresses the records show on
every interface.

- A device owns the networks of its configured interface addresses, its own addresses and (second pass) the inside
  /24 networks that enter it on interfaces behind which no other device was found.
- Device B is behind interface X of device A when addresses owned by B are the near end of A's records on X
  (sources of packets entering through X, destinations of packets leaving through X).
- B is A's neighbour through X unless a third device C, also behind X, sees A and B on different interfaces of its
  own (then C is in between). A subnet configured on an interface of both devices always makes them neighbours.
- Each link carries what one end sent out of its interface and the other received on its interface; when the
  receiving end reports much less, the link shows a gap (more is none: that interface carries other traffic too).
  A device that exports nothing (only configured) is drawn without observation."""
import ipaddress

INTERNET = 'internet'
MIN_RECORDS = 3          # fewer records of a device's addresses on an interface do not put the device behind it
GAP = 0.9                # the receiving end reports less than this share of what the other end sent: a gap


def _net(a):
    """'10.0.0.1/30' -> the network 10.0.0.0/30 (with the interface address kept), a bare address -> /32 or /128"""
    try:
        i = ipaddress.ip_interface(a)
    except ValueError:
        return None
    return i.network


def _private(a):
    try:
        x = ipaddress.ip_address(a)
    except ValueError:
        return False
    return x.is_private and not x.is_loopback


class Owners:
    """Longest-prefix lookup: address -> (device, interface or None)"""

    def __init__(self):
        self.nets = []           # (network, device, interface)

    def add(self, net, dev, iface=None):
        if net is not None:
            self.nets.append((net, dev, iface))

    def find(self, addr):
        try:
            a = ipaddress.ip_address(addr)
        except ValueError:
            return None
        best = None
        for net, dev, iface in self.nets:
            if a.version == net.version and a in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, dev, iface)
        return best and (best[1], best[2])


def build(cfg, near, ifaces, exporting, pairs=()):
    """cfg: exporters config {ip: {...}}; near: rows (exporter, iface, addr, records) — addresses at the near end of
    each interface; ifaces: rows (exporter, iface, out_bytes, in_bytes, by direction); exporting: the devices that
    sent records in the period; pairs: rows (a, ai, ao, b, bi, bo, n) — n conversations recorded by both devices a and
    b, with the interfaces each used (see query()). -> {'nodes': {ip: node}, 'links': [link]}"""
    devs = set(cfg) | set(exporting)
    owners = Owners()
    for d in devs:
        c = cfg.get(d, {})
        owners.add(_net(d), d)                                   # the address it exports from
        for a in c.get('public_ips', []):
            owners.add(_net(a), d)
        for i, addrs in c.get('if_addrs', {}).items():
            for a in addrs:
                owners.add(_net(a), d, int(i))

    def behind_map():
        out = {}                 # (device, iface) -> {other device: records}
        for r in near:
            o = owners.find(r['addr'])
            if o and o[0] != r['exporter']:
                k = (r['exporter'], int(r['iface']))
                out.setdefault(k, {}).setdefault(o[0], 0)
                out[k][o[0]] += int(r['records'])
        return {k: {d for d, n in v.items() if n >= MIN_RECORDS} for k, v in out.items()}

    behind = behind_map()
    # second pass: inside /24 networks entering a device on a LAN interface that leads to no other device
    wan = {d: set(cfg.get(d, {}).get('wan_ifs', [])) for d in devs}
    seen = {}
    for r in near:
        k = (r['exporter'], int(r['iface']))
        if int(r['iface']) in wan.get(r['exporter'], ()) or behind.get(k) or owners.find(r['addr']):
            continue
        if _private(r['addr']) and ':' not in r['addr']:
            n = ipaddress.ip_network(r['addr'] + '/24', strict=False)
            seen.setdefault(n, {}).setdefault(k, 0)
            seen[n][k] += int(r['records'])
    for n, where in seen.items():
        (d, i), cnt = max(where.items(), key=lambda kv: kv[1])
        if len(where) == 1 or cnt >= 2 * sorted(where.values())[-2]:     # one clear home, else it is transit
            owners.add(n, d, i)
    behind = behind_map()
    # the same conversation recorded by two devices: the interface it leaves one through faces the interface it enters
    # the other through. Which device came first is not in a record, so both readings get the vote; the real pair of
    # facing interfaces collects votes from every kind of traffic between the two, the other reading's interfaces
    # (where the endpoints sit) differ from one kind to the next. A tie is settled by the addresses behind them.
    votes = {}
    for r in pairs:
        a, b, n = r['a'], r['b'], int(r['n'])
        if a == b:
            continue
        for k in (((a, int(r['ao'])), (b, int(r['bi']))), ((b, int(r['bo'])), (a, int(r['ai'])))):
            (d1, x1), (d2, x2) = sorted(k)
            votes.setdefault((d1, d2), {}).setdefault((x1, x2), 0)
            votes[(d1, d2)][(x1, x2)] += n
    for (d1, d2), cand in votes.items():
        def score(xy):
            bonus = (d2 in behind.get((d1, xy[0]), ())) + (d1 in behind.get((d2, xy[1]), ()))
            return (cand[xy] * (1 + bonus), bonus)
        ranked = sorted(cand, key=score, reverse=True)
        if len(ranked) > 1 and score(ranked[0]) == score(ranked[1]):
            continue                     # no way to tell which reading is right
        x1, x2 = ranked[0]
        behind.setdefault((d1, x1), set()).add(d2)
        behind.setdefault((d2, x2), set()).add(d1)

    # a subnet configured on both ends: neighbours for sure (also when one end exports nothing); side: (a, b) -> a's
    # interface towards b
    conf = {}
    for d in devs:
        for i, addrs in cfg.get(d, {}).get('if_addrs', {}).items():
            for a in addrs:
                n = _net(a)
                if n is not None and '/' in a and n.num_addresses > 1:
                    conf.setdefault(n, []).append((d, int(i), a))
    side, subnet = {}, {}
    for n, ends in conf.items():
        for a, x, aa in ends:
            for b, y, ba in ends:
                if a != b:
                    side[(a, b)] = x
                    subnet[(a, b)] = (aa, ba, str(n))
    by_subnet = {(a, x) for (a, _), x in side.items()}     # interfaces whose neighbours the addressing names

    # the records: devices behind an interface; on an interface with a configured link only that link's other end is
    # a neighbour (whatever is seen behind it is further away)
    for (a, x), bs in behind.items():
        if (a, x) in by_subnet:
            continue
        for b in bs:
            between = False
            for c in bs - {b}:
                cb = [z for (cc, z), s in behind.items() if cc == c and b in s]
                ca = [z for (cc, z), s in behind.items() if cc == c and a in s]
                if cb and ca and set(cb) != set(ca):
                    between = True
                    break
            if not between and (a, b) not in side:
                side[(a, b)] = x
    vol = {(r['exporter'], int(r['iface'])): r for r in ifaces}
    links, done = [], set()
    for (a, b), x in side.items():
        if (b, a) in done:
            continue
        done.add((a, b))
        y = side.get((b, a))
        va, vb = vol.get((a, x), {}), vol.get((b, y), {}) if y is not None else {}
        a_out, a_in = int(va.get('out_bytes', 0)), int(va.get('in_bytes', 0))
        b_out, b_in = int(vb.get('out_bytes', 0)), int(vb.get('in_bytes', 0))
        if b not in exporting or a not in exporting:
            state = 'unobserved' if (a_out + a_in + b_out + b_in) else 'adjacent'
        elif y is None:                  # both export, but which interface of b faces a is not known
            state = 'one_sided' if a_out + a_in else 'adjacent'
        elif not (a_out + a_in + b_out + b_in):
            state = 'adjacent'
        else:
            # only less arriving than was sent is a loss; more arriving means the interface carries other traffic too
            seen_ab = min(1, b_in / a_out) if a_out else 1
            seen_ba = min(1, a_in / b_out) if b_out else 1
            state = 'observed' if min(seen_ab, seen_ba) >= GAP else 'gap'
        s = subnet.get((a, b))
        links.append({'a': a, 'b': b, 'a_if': x, 'b_if': y, 'state': state, 'evidence': 'subnet' if s else 'flows',
                      'a_addr': s[0] if s else '', 'b_addr': s[1] if s else '', 'net': s[2] if s else '',
                      'a_out': a_out, 'a_in': a_in, 'b_out': b_out, 'b_in': b_in,
                      'a_dir': {k: int(va.get(k, 0)) for k in ('up', 'down', 'internal')},
                      'b_dir': {k: int(vb.get(k, 0)) for k in ('up', 'down', 'internal')}})
    # the internet behind each device's WAN interfaces
    facing = {(a, x) for (a, _), x in side.items()}
    for d in sorted(devs):
        for w in sorted(wan.get(d, ())):
            if (d, w) in facing:         # a WAN interface towards another device: the internet is beyond that one
                continue
            v = vol.get((d, w), {})
            links.append({'a': d, 'b': INTERNET, 'a_if': w, 'b_if': None, 'state': 'observed' if d in exporting else 'unobserved',
                          'evidence': 'wan', 'a_addr': (cfg.get(d, {}).get('if_addrs', {}).get(str(w)) or [''])[0], 'b_addr': '', 'net': '',
                          'a_out': int(v.get('out_bytes', 0)), 'a_in': int(v.get('in_bytes', 0)), 'b_out': 0, 'b_in': 0,
                          'a_dir': {k: int(v.get(k, 0)) for k in ('up', 'down', 'internal')}, 'b_dir': {}})
    nodes = {d: {'ip': d, 'exporting': d in exporting, **{k: cfg.get(d, {}).get(k) for k in ('name', 'vendor', 'model', 'city', 'country')}}
             for d in devs}
    if any(lk['b'] == INTERNET for lk in links):
        nodes[INTERNET] = {'ip': INTERNET, 'exporting': False, 'name': 'Internet'}
    return {'nodes': nodes, 'links': links}


def around(topo, pov, depth=1):
    """The part of the topology within `depth` links of `pov` (breadth first); links between shown devices only."""
    adj = {}
    for lk in topo['links']:
        adj.setdefault(lk['a'], set()).add(lk['b'])
        adj.setdefault(lk['b'], set()).add(lk['a'])
    dist, todo = {pov: 0}, [pov]
    while todo:
        n = todo.pop(0)
        if dist[n] >= depth or n == INTERNET:
            continue
        for m in sorted(adj.get(n, ())):
            if m not in dist:
                dist[m] = dist[n] + 1
                todo.append(m)
    links = [lk for lk in topo['links'] if lk['a'] in dist and lk['b'] in dist]
    nodes = [{**topo['nodes'][n], 'hop': h, 'more': len(adj.get(n, set()) - set(dist)) if n != INTERNET else 0}
             for n, h in sorted(dist.items(), key=lambda kv: (kv[1], kv[0])) if n in topo['nodes']]
    return {'nodes': nodes, 'links': links}


OTHER_EXIT = 0.2         # another output interface carrying at least this share of a hop's traffic: shown as another exit (a parallel path, or a part of a wide destination)


def path(topo, cfg, rows):
    """Hops of the traffic from a source to a destination, in order. rows: (exporter, in_if, out_if, b (bytes), records,
    convs, nat) — the matching records per device and interface pair (see path_query()). Each device's main pair (the
    most bytes) says where the traffic came from and where it went: the device facing its output interface is the
    next hop. A next device that exports but recorded none of the traffic is a gap, one that exports nothing is
    unobserved; devices that recorded the traffic but are not on the chain are listed last: as a branch when another
    exit of a hop leads to them (via_hop: its index), else unplaced.
    -> {'hops': [hop], 'complete': bool}"""
    facing = {}
    for lk in topo['links']:
        facing[(lk['a'], lk['a_if'])] = lk['b']
        if lk['b_if'] is not None:
            facing[(lk['b'], lk['b_if'])] = lk['a']
    seen = {}
    for r in rows:
        d = seen.setdefault(r['exporter'], {'pairs': {}, 'bytes': 0, 'records': 0, 'convs': 0, 'nat': set()})
        k = (int(r['in_if']), int(r['out_if']))
        b = int(r['b'])
        d['pairs'][k] = d['pairs'].get(k, 0) + b
        d['bytes'] += b
        d['records'] += int(r['records'])
        d['convs'] = max(d['convs'], int(r['convs']))
        d['nat'] |= {x for x in r.get('nat') or () if x}
    if not seen:
        return {'hops': [], 'complete': False}
    top = max(d['convs'] for d in seen.values()) or 1

    def ifname(d, i):
        return cfg.get(d, {}).get('if_names', {}).get(str(i)) or (f'if {i}' if i is not None else '')

    def main(d):
        (i, o), _ = max(seen[d]['pairs'].items(), key=lambda kv: kv[1])
        outs = {}
        for (_, oo), b in seen[d]['pairs'].items():
            outs[oo] = outs.get(oo, 0) + b
        other_exits = [{'out_if': oo, 'out_name': ifname(d, oo), 'bytes': b, 'next': facing.get((d, oo))}
                for oo, b in sorted(outs.items(), key=lambda kv: -kv[1]) if oo != o and b >= OTHER_EXIT * seen[d]['bytes']]
        return i, o, other_exits

    def hop(d, state, **kw):
        n = topo['nodes'].get(d, {})
        return {'device': d, 'name': n.get('name') or ('Internet' if d == INTERNET else d), 'state': state,
                'in_if': None, 'out_if': None, 'in_name': '', 'out_name': '', 'bytes': 0, 'records': 0, 'convs': 0,
                'share': 0, 'other_exits': [], 'nat': [], **kw}

    def observed(d):
        i, o, other_exits = main(d)
        x = seen[d]
        return hop(d, 'observed', in_if=i, out_if=o, in_name=ifname(d, i), out_name=ifname(d, o), bytes=x['bytes'],
                   records=x['records'], convs=x['convs'], share=round(x['convs'] / top, 3), other_exits=other_exits, nat=sorted(x['nat'])[:5])

    # the first hop: a device the traffic did not reach from another device that recorded it (the busiest such)
    starts = [d for d in seen if facing.get((d, main(d)[0])) not in seen]
    start = max(starts or seen, key=lambda d: (seen[d]['convs'], seen[d]['bytes']))
    # the device the traffic came from, when the addressing knows it (it recorded nothing)
    prev = facing.get((start, main(start)[0])) if starts else None
    hops, done, d, complete = [], set(), start, False
    if prev and prev != INTERNET:
        n = topo['nodes'].get(prev, {})
        hops.append(hop(prev, 'gap' if n.get('exporting') else 'unobserved'))
        done.add(prev)
    elif prev == INTERNET:
        hops.append(hop(INTERNET, 'internet'))
    while d and d not in done:
        done.add(d)
        if d == INTERNET:
            hops.append(hop(INTERNET, 'internet'))
            complete = True
            break
        if d not in seen:
            n = topo['nodes'].get(d, {})
            hops.append(hop(d, 'gap' if n.get('exporting') else 'unobserved'))
            break
        hops.append(observed(d))
        nxt = facing.get((d, main(d)[1]))
        if nxt is None:          # the traffic leaves towards no known device: the destination is behind this one
            complete = True
        d = nxt
    # devices on another exit of a hop (a wide destination reached through more than one neighbour)
    via = {e['next']: k for k, h in enumerate(hops) for e in h['other_exits'] if e['next']}
    for x in sorted(set(seen) - done, key=lambda x: -seen[x]['convs']):
        hops.append({**observed(x), 'state': 'branch', 'via_hop': via[x]} if x in via else {**observed(x), 'state': 'unplaced'})
    return {'hops': hops, 'complete': complete and all(h['state'] in ('observed', 'internet', 'branch') for h in hops)}


def path_query(ch, where, p, src, dst):
    """Rows for path(): the records of packets sent from `src` to `dst` (an address or a network each; the inside
    source also by its address after NAT) per device and interface pair."""
    sender, receiver = "if(dir = 'down', ext_ip, int_ip)", "if(dir = 'down', int_ip, ext_ip)"
    key = "cityHash64(int_ip, ext_ip, int_port, ext_port, proto)"
    p = dict(p, src=str(ipaddress.ip_network(src, strict=False)), dst=str(ipaddress.ip_network(dst, strict=False)))
    return ch(f"""SELECT exporter, in_if, out_if, sum(bytes) AS b, count() AS records, uniqExact({key}) AS convs,
            groupUniqArray(5)(nat_ip) AS nat
        FROM flows WHERE {where}
            AND (isIPAddressInRange({sender}, {{src:String}}) OR (dir = 'up' AND nat_ip != '' AND isIPAddressInRange(nat_ip, {{src:String}})))
            AND isIPAddressInRange({receiver}, {{dst:String}})
        GROUP BY exporter, in_if, out_if ORDER BY b DESC LIMIT 500""", p, fmt='JSON')


def query(ch, where, p, known):
    """Rows for build() from the records of the period: near-end addresses per interface (inside addresses and the
    devices' own `known` addresses only — outside addresses are many and say nothing about neighbours) and the
    traffic in and out of every interface."""
    src = "if(dir = 'down', ext_ip, int_ip)"     # who sent the packet
    dst = "if(dir = 'down', int_ip, ext_ip)"     # who received it
    p = dict(p, known=sorted(known))
    keep = ("(has({{known:Array(String)}}, {x}) OR isIPAddressInRange({x}, '10.0.0.0/8') OR isIPAddressInRange({x}, '172.16.0.0/12')"
            " OR isIPAddressInRange({x}, '192.168.0.0/16') OR isIPAddressInRange({x}, '100.64.0.0/10') OR isIPAddressInRange({x}, 'fc00::/7'))")
    near = ch(f"""SELECT exporter, iface, addr, sum(n) AS records FROM (
            SELECT exporter, in_if AS iface, {src} AS addr, count() AS n FROM flows WHERE {where} AND {keep.format(x=src)} GROUP BY exporter, iface, addr
            UNION ALL
            SELECT exporter, out_if AS iface, {dst} AS addr, count() AS n FROM flows WHERE {where} AND {keep.format(x=dst)} GROUP BY exporter, iface, addr)
        GROUP BY exporter, iface, addr ORDER BY records DESC LIMIT 50000""", p, fmt='JSON')
    ifaces = ch(f"""SELECT exporter, iface, sum(o) AS out_bytes, sum(i) AS in_bytes, sum(u) AS up, sum(dn) AS down, sum(it) AS internal FROM (
            SELECT exporter, out_if AS iface, bytes AS o, 0 AS i, if(dir = 'up', bytes, 0) AS u, if(dir = 'down', bytes, 0) AS dn,
                   if(dir NOT IN ('up', 'down'), bytes, 0) AS it FROM flows WHERE {where}
            UNION ALL
            SELECT exporter, in_if, 0, bytes, if(dir = 'up', bytes, 0), if(dir = 'down', bytes, 0), if(dir NOT IN ('up', 'down'), bytes, 0)
                FROM flows WHERE {where})
        GROUP BY exporter, iface""", p, fmt='JSON')
    exporting = {r['exporter'] for r in ifaces}
    # conversations recorded by more than one device (a busy network: a sample of them, chosen by the conversation,
    # so every device keeps all records of a conversation in the sample)
    total = sum(1 for _ in ifaces) and int(ch(f"SELECT count() AS n FROM flows WHERE {where}", p, fmt='JSON')[0]['n'])
    p['every'] = max(1, total // 2_000_000)
    key = ("cityHash64(if(dir = 'down', ext_ip, int_ip), if(dir = 'down', int_ip, ext_ip), if(dir = 'down', ext_port, int_port), "
           "if(dir = 'down', int_port, ext_port), proto)")
    pairs = ch(f"""SELECT h1.1 AS a, h1.2 AS ai, h1.3 AS ao, h2.1 AS b, h2.2 AS bi, h2.3 AS bo, count() AS n FROM (
            SELECT groupUniqArray((exporter, in_if, out_if)) AS hops FROM flows WHERE {where} AND {key} % {{every:UInt32}} = 0
            GROUP BY {key} HAVING uniqExact(exporter) > 1 LIMIT 200000)
        ARRAY JOIN hops AS h1 ARRAY JOIN hops AS h2 WHERE h1.1 < h2.1
        GROUP BY a, ai, ao, b, bi, bo ORDER BY n DESC LIMIT 5000""", p, fmt='JSON') if len(exporting) > 1 else []
    return near, ifaces, exporting, pairs
