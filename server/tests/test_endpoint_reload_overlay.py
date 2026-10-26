"""Managed credentials through the installed overlay and the real supervisor.

apply_pending holds a BEGIN IMMEDIATE fence while it reconciles; every path that
must restart the endpoint is exercised here end to end against fake_endpoint.py.
"""
import os
from pathlib import Path
import sys
import time
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_exchange as base
from app import config, db, endpoint, rtrust_credentials as managed
import secrets
from endpoint_harness import FakeEndpoint, failing_after

BOUND = 15


class OverlayEndpointTests(unittest.TestCase):
    setUp_exchange = base.ExchangeTests.setUp
    login = base.ExchangeTests.login
    post = base.ExchangeTests.post
    enrolled = base.ExchangeTests.enrolled

    def setUp(self):
        self.setUp_exchange()
        env = patch.dict(os.environ, RTRUST_MANAGED_CREDENTIALS='1'); env.start(); self.addCleanup(env.stop)
        self.fake = FakeEndpoint(self, config, db, endpoint, base.SANDBOX.name)
        self.assertEqual(self.fake.start(), 'started')

    def change(self, device, action):
        started = time.monotonic()
        response = self.client.post(f'/portal/v2/devices/{device}/credentials/{action}',
                                    headers={**self.headers, 'Idempotency-Key': str(uuid.uuid4())})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['operations'][0]['state'], 'applied')
        self.assertLess(time.monotonic() - started, BOUND)
        return db.get_device_config(device)

    def connect(self, cfg):
        return self.fake.connect(cfg['tt_username'], cfg['tt_password'])

    def test_provision_from_standby_keeps_sessions(self):
        first, _ = self.enrolled('first'); second, _ = self.enrolled('second')
        held = self.connect(self.change(first, 'provision'))
        self.assertEqual(held.status, 'OK')
        self.assertEqual(self.connect(self.change(second, 'provision')).status, 'OK')
        self.assertEqual(len(self.fake.spawns), 1)
        self.assertTrue(held.alive())

    def test_revoke_restarts_closes_and_denies(self):
        lost, _ = self.enrolled('lost'); neighbor, _ = self.enrolled('neighbor')
        revoked, kept = self.change(lost, 'provision'), self.change(neighbor, 'provision')
        held = self.connect(revoked)
        started = time.monotonic()
        response = self.client.delete(f'/portal/v2/devices/{lost}', headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['credentials']['operations'][0]['state'], 'applied')
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertEqual(len(self.fake.spawns), 2)
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(revoked).status, 'DENY')
        self.assertEqual(self.connect(kept).status, 'OK')

    def test_failed_standby_rotation_under_fence_rolls_back(self):
        lost, _ = self.enrolled('lost'); neighbor, _ = self.enrolled('neighbor')
        revoked, kept = self.change(lost, 'provision'), self.change(neighbor, 'provision')
        held = self.connect(revoked)
        before = db.standby_credentials()
        with patch.object(secrets, 'token_urlsafe', side_effect=failing_after(3)):
            response = self.client.delete(f'/portal/v2/devices/{lost}', headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['credentials']['operations'][0]['state'], 'applied')
        self.assertEqual(len(self.fake.spawns), 2)
        self.assertEqual(db.standby_credentials(), before)
        active = {c['username'] for c in db.active_credentials()}
        self.assertEqual(self.fake.loaded_usernames(), active | {c['username'] for c in before})
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(revoked).status, 'DENY')
        self.assertEqual(self.connect(kept).status, 'OK')

    def test_legacy_revoke_restarts(self):
        device, _ = self.enrolled('legacy')
        cfg = self.change(device, 'provision')
        held = self.connect(cfg)
        self.assertEqual(db.revoke_device(device), 1)
        self.assertEqual(len(self.fake.spawns), 2)
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(cfg).status, 'DENY')

    def test_rotate_restarts_and_denies_old_password(self):
        device, _ = self.enrolled('rotated')
        old = self.change(device, 'provision')
        held = self.connect(old)
        new = self.change(device, 'rotate')
        self.assertEqual(len(self.fake.spawns), 2)
        self.assertFalse(held.alive())
        self.assertEqual(self.connect(old).status, 'DENY')
        self.assertEqual(self.connect(new).status, 'OK')

    def test_provision_with_empty_standby_restarts_once(self):
        with patch.dict(os.environ, ENDPOINT_STANDBY_CREDENTIALS='0'):
            self.fake.manager._kill(); self.fake.start()
            self.assertEqual(db.standby_credentials(), [])
            device, _ = self.enrolled('empty')
            cfg = self.change(device, 'provision')
        self.assertEqual(len(self.fake.spawns), 3)
        self.assertEqual(self.connect(cfg).status, 'OK')

    def test_crashed_endpoint_is_restarted_by_apply_pending(self):
        first, _ = self.enrolled('first'); second, _ = self.enrolled('second')
        cfg = self.change(first, 'provision')
        self.fake.manager._proc.kill(); self.fake.manager._proc.wait()
        self.change(second, 'provision')
        self.assertEqual(len(self.fake.spawns), 2)
        self.assertEqual(self.connect(cfg).status, 'OK')

    def test_install_refuses_old_supervisor(self):
        with patch.object(endpoint, 'SUPERVISOR_CONTRACT', 1), self.assertRaisesRegex(RuntimeError, 'supervisor contract'):
            managed.install()
        claim = db.claim_credential
        del db.claim_credential
        try:
            with self.assertRaisesRegex(RuntimeError, 'supervisor contract'):
                managed.install()
        finally:
            db.claim_credential = claim


if __name__ == '__main__':
    unittest.main()
