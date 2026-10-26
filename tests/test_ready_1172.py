"""(1.17.2) The collector tells systemd READY=1 only once its UDP sockets are open (Type=notify): the installer said
«running» before the collector listened, and devices' first packets were dropped by the kernel"""
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import collector  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), '..')


class Notify(unittest.TestCase):
    def receive(self, addr, bind):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as srv:
            srv.bind(bind)
            srv.settimeout(2)
            with mock.patch.dict(os.environ, {'NOTIFY_SOCKET': addr}):
                collector.sd_notify('READY=1')
            return srv.recv(100)

    def test_path_socket(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'notify')
            self.assertEqual(self.receive(path, path), b'READY=1')

    def test_abstract_socket(self):
        name = f'ft-test-{os.getpid()}'
        self.assertEqual(self.receive('@' + name, '\0' + name), b'READY=1')

    def test_nothing_outside_systemd(self):
        env = dict(os.environ)
        env.pop('NOTIFY_SOCKET', None)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(socket, 'socket') as sock:
            collector.sd_notify('READY=1')
        sock.assert_not_called()

    def test_ready_after_the_sockets(self):
        src = open(os.path.join(ROOT, 'collector.py')).read()
        run = src[src.index('    def run(self):'):]
        self.assertLess(run.index('self.listeners = open_listeners('), run.index("sd_notify('READY=1')"))


class Units(unittest.TestCase):
    def unit(self, name):
        return open(os.path.join(ROOT, 'deploy', name)).read()

    def test_collector_is_notify(self):
        u = self.unit('flowtrack-collector.service')
        self.assertIn('\nType=notify\n', u)
        self.assertIn('\nTimeoutStartSec=', u)

    def test_web_after_collector(self):
        after = [ln for ln in self.unit('flowtrack-web.service').splitlines() if ln.startswith('After=')]
        self.assertIn('flowtrack-collector.service', after[0])

    def test_agg_state_in_the_schema(self):
        # applied before the collector's threads start: the rates thread read it before the rollups thread made it
        self.assertIn('CREATE TABLE IF NOT EXISTS agg_state', open(os.path.join(ROOT, 'schema.sql')).read())

    def test_installer_waits_for_the_udp_port(self):
        src = open(os.path.join(ROOT, 'install.sh')).read()
        start = src[src.index('start_all() {'):]
        self.assertIn('udp_busy "$NF_PORT"', start[:start.index('\n}\n')])


if __name__ == '__main__':
    unittest.main()
