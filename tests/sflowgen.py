"""sFlow v5 datagrams for tests (sflow.org/sflow_version_5.txt): flow samples with a raw Ethernet / IPv4 / IPv6 header,
and generic interface counters. Also used by flowsphera-verify to send sFlow to a collector."""
import socket
import struct


def _item(fmt, body):
    return struct.pack('!II', fmt, len(body)) + body + b'\0' * ((4 - len(body) % 4) % 4)


def ip_header(src, dst, proto=6, sport=50000, dport=443, length=1500):
    """An IPv4 or IPv6 packet header with a TCP/UDP header (ICMP: dport = type * 256 + code)."""
    l4 = struct.pack('!HH', sport, dport) + b'\0' * 16 if proto in (6, 17) else struct.pack('!BB', dport >> 8, dport & 255) + b'\0' * 6
    if ':' in src:
        return struct.pack('!IHBB', 0x60000000, length - 40, proto, 64) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + l4
    return struct.pack('!BBHHHBBH', 0x45, 0, length, 0, 0x4000, 64, proto, 0) + socket.inet_aton(src) + socket.inet_aton(dst) + l4


def flow_sample(src, dst, proto=6, sport=50000, dport=443, length=1500, rate=1000, in_if=1, out_if=2, seq=1, vlan=None):
    eth = b'\x00\x11\x22\x33\x44\x55\x00\x66\x77\x88\x99\xaa'
    if vlan is not None:
        eth += struct.pack('!HH', 0x8100, vlan)
    eth += struct.pack('!H', 0x86DD if ':' in src else 0x0800)
    hdr = eth + ip_header(src, dst, proto, sport, dport, length)
    raw = struct.pack('!IIII', 1, length + 18, 4, len(hdr)) + hdr
    body = struct.pack('!IIIIIIII', seq, in_if, rate, rate * seq, 0, in_if, out_if, 1) + _item(1, raw)
    return _item(1, body)


def counter_sample(if_index, in_octets, out_octets, speed=1_000_000_000, status=3, in_errors=0, out_discards=0, seq=1):
    rec = struct.pack('!IIQIIQIIIIIIQIIIIII', if_index, 6, speed, 1, status, in_octets, 0, 0, 0, 0, in_errors, 0,
                      out_octets, 0, 0, 0, out_discards, 0, 0)
    return _item(2, struct.pack('!III', seq, if_index, 1) + _item(1, rec))


def datagram(samples, seq=1, agent='192.0.2.1', sub_agent=0, uptime=1000):
    a = struct.pack('!I', 2) + socket.inet_pton(socket.AF_INET6, agent) if ':' in agent else struct.pack('!I', 1) + socket.inet_aton(agent)
    return struct.pack('!I', 5) + a + struct.pack('!IIII', sub_agent, seq, uptime, len(samples)) + b''.join(samples)
