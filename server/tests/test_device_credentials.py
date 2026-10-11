"""Credential state-machine regressions against real SQLite and portal auth."""
import os
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from test_exchange import ExchangeTests
from app import db, endpoint, rtrust_credentials as managed


class CredentialTests(ExchangeTests):
    # Inherited exchange tests additionally exercise the credential integration.
    def setUp(self):
        super().setUp()
        db.set_settings({'panel_domain':'vpn.example.invalid'})
        self.env = patch.dict(os.environ, RTRUST_MANAGED_CREDENTIALS='1')
        self.env.start()
        self.addCleanup(self.env.stop)
        self.certificate = patch.object(endpoint,'cert_present',return_value=True)
        self.certificate.start()
        self.addCleanup(self.certificate.stop)
        self.running = patch.object(endpoint.manager, '_is_running', return_value=True)
        self.running.start()
        self.addCleanup(self.running.stop)
        self.restart = patch.object(endpoint.manager, 'reconcile')
        self.restart.start()
        self.addCleanup(self.restart.stop)
        self.kill = patch.object(endpoint.manager, '_kill')
        self.kill.start()
        self.addCleanup(self.kill.stop)

    def change(self, device, action, key=None):
        return self.client.post(f'/portal/v2/devices/{device}/credentials/{action}',
                                headers={**self.headers, 'Idempotency-Key': key or str(uuid.uuid4())})

    def test_distinct_credentials_idempotency_rotation_and_revoke(self):
        device,auth=self.enrolled(); neighbor,other_auth=self.enrolled('neighbor')
        # Avoid a clock mock infinite loop; use observation time progression.
        with patch.object(managed.time, 'monotonic', side_effect=range(1000)):
            key=str(uuid.uuid4())
            first=self.change(device,'provision',key)
            self.assertEqual(first.status_code,200,first.text)
            self.assertEqual(self.change(device,'provision',key).json(),first.json())
            second=self.change(neighbor,'provision').json()
            with db.connect() as c:
                initial=[dict(r) for r in c.execute('SELECT * FROM configs ORDER BY id')]
            self.assertNotEqual(initial[0]['tt_password'],initial[1]['tt_password'])
            self.assertEqual(self.change(device,'rotate').status_code,200)
            self.assertEqual(self.change(device,'rotate',key).status_code,409)
            self.assertEqual(self.post('profiles/'+first.json()['profile_id']+'/grants',{'device_id':neighbor,'allow':True}).status_code,409)
            # Even a legacy/direct grant cannot bypass the credential owner.
            with db.connect() as c:c.execute('INSERT INTO rtrust_grants VALUES(?,?)',(first.json()['profile_id'],neighbor))
            self.assertEqual(self.post_export(first.json()['profile_id'],other_auth).status_code,404)
            result=self.client.delete(f'/portal/v2/devices/{device}',headers=self.headers)
            self.assertEqual(result.json()['credentials']['operations'][0]['state'],'applied')
            self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).status_code,401)
            creds=managed.active_credentials()
            self.assertEqual(creds,[{'username':initial[1]['tt_username'],'password':initial[1]['tt_password']}])
            self.assertEqual(self.change(device,'rotate').status_code,409)
            repeated=self.client.delete(f'/portal/v2/devices/{device}',headers=self.headers)
            self.assertEqual(repeated.json()['credentials']['operations'],result.json()['credentials']['operations'])
            self.assertEqual(self.client.get('/portal/v2/profiles',headers=other_auth).status_code,200)

    def post_export(self, profile, auth):
        return self.client.post('/portal/v2/profiles/'+profile+'/export',json={'include_secrets':True,'revision':'unused'},headers=auth)

    def test_outage_restart_retry_supersedes_and_no_secret_audit(self):
        device,_=self.enrolled()
        with patch.object(endpoint.manager, '_is_running', return_value=False):
            response=self.change(device,'provision')
            self.assertEqual(response.json()['operations'][0]['state'],'failed')
            # A crash/restart keeps the failed operation; schema init is idempotent.
            managed.init()
            revoked=self.client.delete(f'/portal/v2/devices/{device}',headers=self.headers)
            self.assertEqual(revoked.json()['credentials']['operations'][0]['state'],'failed')
        with patch.object(managed.time,'monotonic',side_effect=range(1000)):
            retry=self.client.post(f'/portal/v2/devices/{device}/credentials-retry',headers=self.headers)
        ops=retry.json()['operations']
        self.assertEqual(ops[0]['state'],'applied')
        self.assertEqual(ops[1]['error'],'superseded_by_revoke')
        self.assertEqual(ops[1]['state'],'failed')
        self.assertEqual(managed.active_credentials(),[])
        with db.connect() as c:
            audit=str([dict(r) for r in c.execute('SELECT * FROM rtrust_audit')])
            secret=c.execute('SELECT tt_password FROM configs').fetchone()[0]
        self.assertNotIn(secret,audit)

    def test_legacy_shared_survives_migration_and_revocation(self):
        device,_=self.enrolled();neighbor,_=self.enrolled('other')
        cfg=db.create_config(self.owner,'legacy',secrets.token_urlsafe(32),'Shared')
        for target in (device,neighbor):self.post(f'profiles/managed-{cfg}/grants',{'device_id':target,'allow':True})
        with patch.object(managed.time,'monotonic',side_effect=range(1000)):
            result=self.change(device,'provision')
            self.assertTrue(result.json()['shared_credentials_unmanaged'])
            self.client.delete(f'/portal/v2/devices/{device}',headers=self.headers)
        self.assertEqual(managed.active_credentials()[0]['username'],'legacy')
        self.assertIsNone(db.get_config(cfg)['revoked_at'])

    def test_auth_disabled_token_renewal_and_file_permissions(self):
        device,auth=self.enrolled()
        self.assertEqual(self.client.post(f'/portal/v2/devices/{device}/credentials/provision',headers=auth).status_code,403)
        self.assertEqual(self.client.post(f'/portal/v2/devices/{device}/credentials/provision').status_code,403)
        self.assertEqual(self.change(device,'provision','bad').status_code,422)
        with patch.dict(os.environ,RTRUST_MANAGED_CREDENTIALS='0'):
            self.assertEqual(self.change(device,'provision').status_code,409)
        renewed=self.client.post('/portal/v2/device-token/renew',headers=auth)
        self.assertEqual(renewed.status_code,200,renewed.text)
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).status_code,401)
        new={'Authorization':'Bearer '+renewed.json()['token']}
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=new).status_code,200)
        self.login(self.other)
        self.assertEqual(self.change(device,'provision').status_code,404)
        self.assertEqual(self.client.post(f'/portal/v2/devices/{device}/credentials-retry',headers=self.headers).status_code,404)
        import tempfile,tomllib
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder, patch.object(endpoint.config,'ENDPOINT_WORKDIR',folder):
            creds=[{'username':'quote"line\n','password':'slash\\secret'}]
            managed.write_credentials(creds)
            path=Path(folder)/'credentials.toml'
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(tomllib.loads(path.read_text())['client'],creds)

    def test_retry_after_write_failure_forces_process_restart(self):
        device,_=self.enrolled()
        with patch.object(endpoint.manager,'reconcile',side_effect=RuntimeError('secret exception text')):
            result=self.change(device,'provision')
        self.assertEqual(result.json()['operations'][0]['state'],'failed')
        self.assertNotIn('secret exception',str(result.json()))
        before=endpoint.manager._kill.call_count
        with patch.object(managed.time,'monotonic',side_effect=range(1000)):
            managed.apply_pending()
        self.assertGreater(endpoint.manager._kill.call_count,before)
        self.assertEqual(managed.snapshot(self.owner,device)['operations'][0]['state'],'applied')

    def test_legacy_admin_device_revoke_uses_durable_state(self):
        device,auth=self.enrolled()
        with patch.object(managed.time,'monotonic',side_effect=range(1000)):
            self.change(device,'provision')
            self.assertEqual(db.revoke_device(device),1)
        self.assertEqual(managed.active_credentials(),[])
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).status_code,401)
        self.assertEqual(managed.snapshot(self.owner,device)['operations'][0]['action'],'revoke')

    def test_second_supervisor_is_rejected_before_startup(self):
        from fastapi.testclient import TestClient
        with TestClient(self.client.app):
            with self.assertRaisesRegex(RuntimeError,'one endpoint supervisor'):
                with TestClient(self.client.app):pass

    def test_concurrent_rotate_revoke_never_resurrects(self):
        device,_=self.enrolled()
        with patch.object(managed.time,'monotonic',side_effect=range(1000)):
            self.change(device,'provision')
            def rotate():
                try:return managed.mutate(self.owner,device,'rotate',str(uuid.uuid4()))
                except Exception as e:return e
            def revoke():return self.client.delete(f'/portal/v2/devices/{device}',headers=self.headers)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(rotate),pool.submit(revoke)]
                [f.result() for f in futures]
        self.assertEqual(managed.active_credentials(),[])
        self.assertIsNotNone(db.get_device(device)['revoked_at'])
        with db.connect() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM configs WHERE device_id=? AND revoked_at IS NULL",(device,)).fetchone()[0],0)


if __name__=='__main__':
    import unittest
    unittest.main()
