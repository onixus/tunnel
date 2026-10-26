"""Endpoint supervisor: config changes apply without dropping unrelated tunnels.

Runs the real supervisor against fake_endpoint.py, which keeps the official
endpoint's contract: credentials are read only at start, hosts.toml on SIGHUP.
"""
import os
from pathlib import Path
import secrets
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
sys.path.insert(0, str(ROOT/'server/tests'))
from app import config, db, endpoint
from endpoint_harness import FakeEndpoint, free_port


class EndpointReloadTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(config, 'DB_PATH', str(Path(tempfile.mkdtemp(dir=SANDBOX.name))/'portal.db'))
        p.start(); self.addCleanup(p.stop)
        db.init_db()
        self.fake = FakeEndpoint(self, config, db, endpoint, SANDBOX.name)
        self.manager, self.spawns, self.workdir, self.port = self.fake.manager, self.fake.spawns, self.fake.workdir, self.fake.port
        self.assertEqual(self.fake.start(), 'started')
        self.user = db.create_user('owner@example.invalid', 'unused')

    def issue(self, user=None):
        cfg = db.get_config(db.create_config(user or self.user, 'u-fallback-' + secrets.token_hex(4), secrets.token_urlsafe(9), None))
        self.manager.apply_credentials()
        self.fake.wait()
        return cfg

    def connect(self, cfg, port=None):
        return self.fake.connect(cfg['tt_username'], cfg['tt_password'], port)

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
        self.fake.wait()
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
        self.fake.wait()
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
        self.fake.wait()
        self.assertEqual(len(self.spawns), 2)
        for cfg in configs:
            self.assertEqual(self.connect(cfg).status, 'DENY')

    def test_continuous_requests_do_not_postpone_revocation_past_max_delay(self):
        revoked = self.issue()
        held = self.connect(revoked)
        self.manager.restart_quiet, self.manager.restart_max_delay = .5, 1.5
        stop = threading.Event()
        callers = []
        def churn():
            # Every request needs a restart and resets the quiet window.
            while not stop.is_set():
                cfg = db.create_config(self.user, 'u-churn-' + secrets.token_hex(4), secrets.token_urlsafe(9), None)
                db.delete_config(cfg)
                callers.append(threading.Thread(target=self.manager.apply_credentials))
                callers[-1].start()
                time.sleep(.1)
        worker = threading.Thread(target=churn); worker.start()
        self.addCleanup(lambda: [t.join(10) for t in callers])
        self.addCleanup(worker.join); self.addCleanup(stop.set)
        time.sleep(.3)
        started = time.monotonic()
        db.delete_config(revoked['id'])
        self.manager.apply_credentials()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, self.manager.restart_max_delay + 1)
        self.assertFalse(held.alive())
        self.fake.wait()
        self.assertEqual(self.connect(revoked).status, 'DENY')

    def test_failed_deferred_restart_reaches_the_caller_and_is_retried(self):
        revoked = self.issue()
        held = self.connect(revoked)
        db.delete_config(revoked['id'])
        original = self.manager.reconcile
        calls = []
        def failing(*args, **kwargs):
            calls.append(kwargs)
            if not kwargs.get('defer_restart') and len([c for c in calls if not c.get('defer_restart')]) == 1:
                raise OSError('synthetic write failure')
            return original(*args, **kwargs)
        with patch.object(self.manager, 'reconcile', side_effect=failing):
            with self.assertRaisesRegex(RuntimeError, 'restart failed'):
                self.manager.apply_credentials()
            deadline = time.monotonic() + 5
            while len(self.spawns) < 2 and time.monotonic() < deadline:
                time.sleep(.05)
        self.assertEqual(len(self.spawns), 2)
        self.assertFalse(held.alive())
        self.fake.wait()
        self.assertEqual(self.connect(revoked).status, 'DENY')

    def test_waiting_for_a_stuck_restart_times_out(self):
        revoked = self.issue()
        db.delete_config(revoked['id'])
        self.manager.restart_wait_timeout = .5
        release = threading.Event()
        self.addCleanup(release.set)
        original = self.manager.reconcile
        def stuck(*args, **kwargs):
            if not kwargs.get('defer_restart'):
                release.wait(10)
            return original(*args, **kwargs)
        with patch.object(self.manager, 'reconcile', side_effect=stuck):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                self.manager.apply_credentials()
            self.assertLess(time.monotonic() - started, self.manager.restart_quiet + 2)
            release.set()

    def test_standby_failure_does_not_block_revocation(self):
        revoked = self.issue()
        held = self.connect(revoked)
        db.delete_config(revoked['id'])
        with patch.object(db, 'rotate_standby', side_effect=RuntimeError('database is locked')):
            self.manager.apply_credentials()
        self.fake.wait()
        self.assertEqual(len(self.spawns), 2)
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(revoked).status, 'DENY')

    def test_standby_is_replaced_on_restart_and_disabled_by_zero(self):
        before = {c['username'] for c in db.standby_credentials()}
        self.assertEqual(len(before), 16)
        revoked = self.issue()
        db.delete_config(revoked['id'])
        self.manager.apply_credentials()
        after = {c['username'] for c in db.standby_credentials()}
        self.assertEqual(len(after), 16)
        self.assertFalse(before & after)
        self.assertFalse(before & set((self.workdir/'credentials.toml').read_text().split('"')))
        with patch.dict(os.environ, ENDPOINT_STANDBY_CREDENTIALS='0'):
            db.delete_config(self.issue()['id'])
            self.manager.apply_credentials()
        self.assertEqual(db.standby_credentials(), [])
        self.assertNotIn('username = "t', (self.workdir/'credentials.toml').read_text())

    def test_exhausted_standby_restarts_once_and_refills(self):
        with patch.dict(os.environ, ENDPOINT_STANDBY_CREDENTIALS='2'):
            db.set_settings({'conn_port': str(free_port())})
            self.manager.reconcile()  # restart loads a standby set of two
            self.port = self.fake.port = int(db.get_settings()['conn_port'])
            self.fake.wait()
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

    def test_crashed_endpoint_is_restarted_by_periodic_check(self):
        cfg = self.issue()
        self.manager._proc.kill(); self.manager._proc.wait()
        self.manager._check_drift()
        self.fake.wait()
        self.assertEqual(len(self.spawns), 2)
        self.assertEqual(self.connect(cfg).status, 'OK')

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
        self.fake.wait(port)
        self.assertEqual(len(self.spawns), 2)


if __name__ == '__main__':
    unittest.main()
