"""Endpoint supervisor: config changes apply without dropping unrelated tunnels.

Runs the real supervisor against fake_endpoint.py, which keeps the official
endpoint's contract: credentials are read only at start, hosts.toml on SIGHUP.
"""
import os
from pathlib import Path
import secrets
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = tempfile.TemporaryDirectory(prefix='endpoint-reload-tests-')
os.environ.update(DATA_DIR=SANDBOX.name, SECRET_KEY=secrets.token_urlsafe(48), ADMIN_PASSWORD=secrets.token_urlsafe(32))
sys.path.insert(0, str(ROOT/'server/upstream'))
from app import config, db, endpoint

DOMAIN = 'vpn.example.invalid'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Tunnel:
    """One authenticated client connection to the fake endpoint."""

    def __init__(self, port, username, password):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.stream = self.sock.makefile('rwb', buffering=0)
        self.stream.write(f'{username} {password}\n'.encode())
        self.status = self.stream.readline().strip().decode()

    def alive(self):
        try:
            self.stream.write(b'ping\n')
            return self.stream.readline() == b'ping\n'
        except OSError:
            return False

    def close(self):
        self.stream.close()
        self.sock.close()


class EndpointReloadTests(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp(dir=SANDBOX.name))
        workdir = root/'runtime'; workdir.mkdir()
        live = root/'certs/live'/DOMAIN; live.mkdir(parents=True)
        (live/'fullchain.pem').write_text('synthetic chain')
        (live/'privkey.pem').write_text('synthetic key')
        binary = root/'trusttunnel_endpoint'
        binary.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{ROOT/"server/tests/fake_endpoint.py"}" "$@"\n')
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        self.workdir = workdir
        for name, value in (('DB_PATH', str(root/'portal.db')), ('ENDPOINT_WORKDIR', str(workdir)),
                            ('CERT_DIR', str(root/'certs')), ('ENDPOINT_BIN', str(binary))):
            p = patch.object(config, name, value); p.start(); self.addCleanup(p.stop)
        db.init_db()
        self.port = free_port()
        db.set_settings({'panel_domain': DOMAIN, 'conn_port': str(self.port)})
        self.manager = endpoint.EndpointManager()
        self.manager.restart_quiet, self.manager.restart_min_interval, self.manager.restart_max_delay = .2, .5, 3
        self.spawns = []
        spawn = self.manager._spawn
        def counted():
            spawn(); self.spawns.append(self.manager._proc.pid)
        self.manager._spawn = counted
        self.addCleanup(self.manager.stop)
        p = patch.object(endpoint, 'manager', self.manager); p.start(); self.addCleanup(p.stop)
        self.assertEqual(self.manager.reconcile(), 'started')
        self.wait_listening()
        self.user = db.create_user('owner@example.invalid', 'unused')

    def wait_listening(self, port=None):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(('127.0.0.1', port or self.port), timeout=.2).close()
                return
            except OSError:
                time.sleep(.02)
        self.fail('endpoint did not start listening')

    def issue(self, user=None):
        cfg = db.get_config(db.create_config(user or self.user, 'u-fallback-' + secrets.token_hex(4), secrets.token_urlsafe(9), None))
        self.manager.apply_credentials()
        self.wait_listening()
        return cfg

    def connect(self, cfg, port=None):
        tunnel = Tunnel(port or self.port, cfg['tt_username'], cfg['tt_password'])
        self.addCleanup(tunnel.close)
        return tunnel

    def test_new_config_is_hot_applied_without_dropping_sessions(self):
        first = self.issue()
        held = self.connect(first)
        self.assertEqual(held.status, 'OK')
        second = self.issue()
        self.assertEqual(self.connect(second).status, 'OK')
        self.assertEqual(len(self.spawns), 1)
        self.assertTrue(held.alive())
        self.assertNotIn(first['tt_username'], {c['username'] for c in db.standby_credentials()})

    def test_unchanged_config_does_not_restart(self):
        held = self.connect(self.issue())
        before = (self.workdir/'credentials.toml').read_bytes()
        for _ in range(5):
            self.manager.apply_credentials()
            self.manager.apply_settings()
            self.assertEqual(self.manager.reconcile(), 'unchanged')
        self.assertEqual(len(self.spawns), 1)
        self.assertEqual((self.workdir/'credentials.toml').read_bytes(), before)
        self.assertTrue(held.alive())

    def test_revoked_config_is_closed_and_refused(self):
        revoked, kept = self.issue(), self.issue()
        held = self.connect(revoked)
        self.connect(kept)
        db.delete_config(revoked['id'])
        self.manager.apply_credentials()
        self.wait_listening()
        self.assertEqual(len(self.spawns), 2)
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(revoked).status, 'DENY')
        self.assertEqual(self.connect(kept).status, 'OK')
        self.assertNotIn(revoked['tt_username'], (self.workdir/'credentials.toml').read_text())

    def test_blocked_user_loses_access(self):
        other = db.create_user('other@example.invalid', 'unused')
        blocked, kept = self.issue(other), self.issue()
        held = self.connect(blocked)
        db.set_user_status(other, 'blocked')
        self.manager.apply_credentials()
        self.wait_listening()
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(blocked).status, 'DENY')
        self.assertEqual(self.connect(kept).status, 'OK')

    def test_burst_of_revocations_restarts_once(self):
        configs = [self.issue() for _ in range(4)]
        threads = []
        for cfg in configs:
            db.delete_config(cfg['id'])
            threads.append(threading.Thread(target=self.manager.apply_credentials))
            threads[-1].start()
            time.sleep(.05)
        for thread in threads:
            thread.join(10)
        self.wait_listening()
        self.assertEqual(len(self.spawns), 2)
        for cfg in configs:
            self.assertEqual(self.connect(cfg).status, 'DENY')

    def test_exhausted_standby_restarts_once_and_refills(self):
        with patch.dict(os.environ, ENDPOINT_STANDBY_CREDENTIALS='2'):
            with db.connect() as c:
                c.execute('DELETE FROM endpoint_standby WHERE rowid NOT IN (SELECT rowid FROM endpoint_standby LIMIT 2)')
            self.manager.reconcile()  # the trimmed standby set is now what is loaded
            self.wait_listening()
            spawned = len(self.spawns)
            first, second = self.issue(), self.issue()
            self.assertEqual(len(self.spawns), spawned)
            third = self.issue()
            self.assertEqual(len(self.spawns), spawned + 1)
            self.assertEqual(len(db.standby_credentials()), 2)
            for cfg in (first, second, third):
                self.assertEqual(self.connect(cfg).status, 'OK')
            self.issue()
            self.assertEqual(len(self.spawns), spawned + 1)

    def test_sni_change_reloads_hosts_without_restart_and_port_change_restarts(self):
        held = self.connect(self.issue())
        db.set_settings({'conn_sni': 'cdn.example.invalid'})
        self.manager.apply_settings()
        deadline = time.monotonic() + 5
        while not (self.workdir/'sighup.count').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertEqual((self.workdir/'sighup.count').read_text(), '1')
        self.assertEqual(len(self.spawns), 1)
        self.assertTrue(held.alive())
        port = free_port()
        db.set_settings({'conn_port': str(port)})
        self.manager.apply_settings()
        self.wait_listening(port)
        self.assertEqual(len(self.spawns), 2)


if __name__ == '__main__':
    unittest.main()
