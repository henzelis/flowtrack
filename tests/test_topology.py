"""Path analysis (1.4): which exporting devices topology.build() makes neighbours, through which interfaces, and the
state of each link. Run: python -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import topology as T  # noqa: E402

A, B, C = '192.0.2.1', '192.0.2.2', '192.0.2.3'


def near(dev, iface, addr, n=10):
    return {'exporter': dev, 'iface': iface, 'addr': addr, 'records': n}


def iface(dev, i, out=0, inb=0):
    return {'exporter': dev, 'iface': i, 'out_bytes': out, 'in_bytes': inb, 'up': 0, 'down': 0, 'internal': out + inb}


def links(topo):
    return {frozenset((lk['a'], lk['b'])): lk for lk in topo['links']}


class Subnets(unittest.TestCase):
    cfg = {A: {'name': 'fw', 'if_addrs': {'9': ['10.255.0.1/30']}, 'wan_ifs': [3]},
           B: {'name': 'core', 'if_addrs': {'1': ['10.255.0.2/30'], '2': ['10.255.0.5/30']}},
           C: {'name': 'backup', 'if_addrs': {'1': ['10.255.0.6/30']}}}

    def test_shared_subnet_and_states(self):
        ifs = [iface(A, 9, 1000, 500), iface(B, 1, 500, 1000), iface(B, 2, 700, 0), iface(A, 3, 300, 900)]
        t = T.build(self.cfg, [], ifs, {A, B})
        ls = links(t)
        ab = ls[frozenset((A, B))]
        self.assertEqual(ab['state'], 'observed')
        self.assertEqual(ab['evidence'], 'subnet')
        self.assertEqual(ab['net'], '10.255.0.0/30')
        x = ab['a_if'] if ab['a'] == A else ab['b_if']
        self.assertEqual(x, 9)
        # C is configured but exports nothing: the link is there, its far end unobserved
        self.assertEqual(ls[frozenset((B, C))]['state'], 'unobserved')
        self.assertNotIn(frozenset((A, C)), ls)
        # the internet behind A's WAN interface
        inet = ls[frozenset((A, T.INTERNET))]
        self.assertEqual((inet['a_if'], inet['a_out'], inet['a_in']), (3, 300, 900))
        self.assertIn(T.INTERNET, t['nodes'])

    def test_gap(self):
        ifs = [iface(A, 9, 1000, 500), iface(B, 1, 500, 400)]       # B received 400 of the 1000 A sent towards it
        self.assertEqual(links(T.build(self.cfg, [], ifs, {A, B}))[frozenset((A, B))]['state'], 'gap')

    def test_receiving_more_is_no_gap(self):
        ifs = [iface(A, 9, 1000, 500), iface(B, 1, 500, 1600)]      # B's interface also carries other traffic
        self.assertEqual(links(T.build(self.cfg, [], ifs, {A, B}))[frozenset((A, B))]['state'], 'observed')

    def test_internet_without_traffic(self):
        self.assertEqual(links(T.build(self.cfg, [], [iface(A, 9, 10, 10)], {A, B}))[frozenset((A, T.INTERNET))]['state'], 'adjacent')

    def test_adjacent_without_traffic(self):
        self.assertEqual(links(T.build(self.cfg, [], [], {A, B}))[frozenset((A, B))]['state'], 'adjacent')

    def test_wan_towards_device_is_no_internet(self):
        cfg = {**self.cfg, A: {**self.cfg[A], 'wan_ifs': [9]}}
        self.assertNotIn(frozenset((A, T.INTERNET)), links(T.build(cfg, [], [], {A, B})))


class Flows(unittest.TestCase):
    """No addresses configured: neighbours from the devices' own addresses seen in the records"""

    def chain(self):
        # A -(2)- (1) B (2) -(1)- C ; each device sees the others' addresses on the interface towards them
        return [near(A, 2, B), near(A, 2, C), near(B, 1, A), near(B, 2, C), near(C, 1, B), near(C, 1, A)]

    def test_chain_keeps_direct_neighbours_only(self):
        ls = links(T.build({}, self.chain(), [], {A, B, C}))
        self.assertEqual(set(ls), {frozenset((A, B)), frozenset((B, C))})
        self.assertTrue(all(lk['evidence'] == 'flows' for lk in ls.values()))
        ab = ls[frozenset((A, B))]
        self.assertEqual({ab['a']: ab['a_if'], ab['b']: ab['b_if']}, {A: 2, B: 1})

    def test_too_few_records(self):
        self.assertEqual(T.build({}, [near(A, 2, B, n=T.MIN_RECORDS - 1)], [], {A, B})['links'], [])

    def test_inside_network_owned_by_its_device(self):
        # 10.20.0.0/24 enters B on its LAN interface 5 with all its traffic, A sees a part of it on interface 2:
        # the network is B's, so B is behind A's interface 2
        rows = [near(B, 5, '10.20.0.%d' % i, 30) for i in range(1, 6)] + [near(A, 2, '10.20.0.%d' % i) for i in range(1, 6)]
        ls = links(T.build({}, rows, [], {A, B}))
        ab = ls[frozenset((A, B))]
        self.assertEqual(ab['a_if'] if ab['a'] == A else ab['b_if'], 2)

    def test_inside_network_without_clear_home_is_transit(self):
        rows = [near(B, 5, '10.20.0.%d' % i) for i in range(1, 6)] + [near(A, 2, '10.20.0.%d' % i) for i in range(1, 6)]
        self.assertEqual(T.build({}, rows, [], {A, B})['links'], [])

    def test_conversations_pick_facing_interfaces(self):
        # the same conversations recorded by A (in 1, out 7) and B (in 4, out 8): A's out 7 faces B's in 4
        pairs = [{'a': A, 'ai': 1, 'ao': 7, 'b': B, 'bi': 4, 'bo': 8, 'n': 50},
                 {'a': A, 'ai': 6, 'ao': 7, 'b': B, 'bi': 4, 'bo': 9, 'n': 30}]
        ls = links(T.build({}, [], [], {A, B}, pairs))
        ab = ls[frozenset((A, B))]
        self.assertEqual({ab['a']: ab['a_if'], ab['b']: ab['b_if']}, {A: 7, B: 4})


class Around(unittest.TestCase):
    def test_depth(self):
        t = T.build({}, Flows().chain(), [], {A, B, C})
        one = T.around(t, A, 1)
        self.assertEqual([n['ip'] for n in one['nodes']], [A, B])
        self.assertEqual(one['nodes'][1]['more'], 1)              # C beyond B, not shown yet
        self.assertEqual(len(one['links']), 1)
        two = T.around(t, A, 2)
        self.assertEqual({n['ip'] for n in two['nodes']}, {A, B, C})
        self.assertEqual({n['ip']: n['hop'] for n in two['nodes']}[C], 2)

    def test_no_neighbours(self):
        t = T.build({A: {}, B: {}}, [], [], {A, B})
        self.assertEqual([n['ip'] for n in T.around(t, A, 3)['nodes']], [A])



def hop(dev, i, o, b=1000, convs=10, nat=()):
    return {'exporter': dev, 'in_if': i, 'out_if': o, 'b': b, 'records': convs, 'convs': convs, 'nat': list(nat)}


class Path(unittest.TestCase):
    """10.30.0.5 behind C -> C (2 -> 1) -> B (2 -> 1) -> A (9 -> 3, NAT) -> the internet"""
    cfg = {**Subnets.cfg, A: {**Subnets.cfg[A], 'if_names': {'3': 'wan1'}}}

    def trace(self, rows, exporting=(A, B, C)):
        t = T.build(self.cfg, [], [], set(exporting))
        return T.path(t, self.cfg, rows)

    def states(self, r):
        return [(h['device'], h['state']) for h in r['hops']]

    def test_whole_path(self):
        r = self.trace([hop(C, 2, 1), hop(B, 2, 1), hop(A, 9, 3, nat=['203.0.113.10'])])
        self.assertEqual(self.states(r), [(C, 'observed'), (B, 'observed'), (A, 'observed'), (T.INTERNET, 'internet')])
        self.assertTrue(r['complete'])
        self.assertEqual((r['hops'][2]['out_name'], r['hops'][2]['nat']), ('wan1', ['203.0.113.10']))

    def test_gap(self):
        # B exports but recorded none of it: the chain stops at B, A is listed as unplaced
        r = self.trace([hop(C, 2, 1), hop(A, 9, 3)])
        self.assertEqual(self.states(r), [(C, 'observed'), (B, 'gap'), (A, 'unplaced')])
        self.assertFalse(r['complete'])

    def test_first_device_exports_nothing(self):
        r = self.trace([hop(B, 2, 1), hop(A, 9, 3)], exporting=(A, B))
        self.assertEqual(self.states(r), [(C, 'unobserved'), (B, 'observed'), (A, 'observed'), (T.INTERNET, 'internet')])
        self.assertFalse(r['complete'])

    def test_share_and_parallel_path(self):
        r = self.trace([hop(C, 2, 1, convs=20), hop(B, 2, 1, b=600, convs=10), hop(B, 2, 4, b=400, convs=10), hop(A, 9, 3, convs=10)])
        b = r['hops'][1]
        self.assertEqual((b['device'], b['out_if'], b['share']), (B, 1, 0.5))
        self.assertEqual([(e['out_if'], e['bytes']) for e in b['other_exits']], [(4, 400)])

    def test_other_exit_is_a_branch(self):
        # B sends most of it to A, a part to C (a wide destination): C is a branch of hop B, the path is whole
        r = self.trace([hop(B, 3, 1, b=700), hop(B, 3, 2, b=300), hop(A, 9, 3), hop(C, 1, 4)])
        self.assertEqual(self.states(r), [(B, 'observed'), (A, 'observed'), (T.INTERNET, 'internet'), (C, 'branch')])
        self.assertEqual(r['hops'][3]['via_hop'], 0)
        self.assertTrue(r['complete'])

    def test_nothing_recorded(self):
        self.assertEqual(self.trace([]), {'hops': [], 'complete': False})


if __name__ == '__main__':
    unittest.main()
