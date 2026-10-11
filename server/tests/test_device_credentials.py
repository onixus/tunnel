"""Isolated SQLite/API lifecycle tests. Probe mocks are not endpoint acceptance."""
import json
from unittest.mock import patch
import test_exchange as fixture
from app import db, rtrust_profiles as exchange, device_credentials as credentials, endpoint

class DeviceCredentialTests(fixture.ExchangeTests):
    def managed(self):
        with db.connect() as c:
            c.execute("UPDATE settings SET value='endpoint.example.invalid' WHERE key='panel_domain'")
            number=c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',(self.owner,'legacy-user','legacy-synthetic-password','Managed')).lastrowid
        return 'managed-'+str(number)
    def grant(self, profile, device):
        with patch.object(credentials,'enabled',return_value=True):
            response=self.post('profiles/'+profile+'/grants',{'device_id':device,'allow':True})
        self.assertEqual(response.status_code,200,response.text)
    def reconcile(self, device, probe):
        with patch.object(credentials,'enabled',return_value=True), patch.object(endpoint.manager,'apply_device_credentials',return_value=0), patch.object(endpoint.manager,'credential_generation',return_value=0), patch.object(credentials,'CHECKER',fixture.exchange.CODEC), patch.object(credentials,'probe',side_effect=probe):
            return self.post('devices/'+str(device)+'/credentials/reconcile',{'consent_restart_endpoint':True})
    @staticmethod
    def positive(row,payload,protocol,**kwargs):return {'protocol':protocol,'outcome':'authenticated','elapsed_ms':1}

    def test_unique_encrypted_credentials_are_not_exported_before_verified_apply(self):
        profile=self.managed(); first,a=self.enrolled('one'); second,b=self.enrolled('two')
        self.grant(profile,first); self.grant(profile,second)
        with db.connect() as c:
            rows=c.execute('SELECT * FROM rtrust_device_credentials ORDER BY device').fetchall()
            values=[exchange.unseal(self.owner,row['payload']) for row in rows]
        self.assertNotEqual(values[0]['username'],values[1]['username']); self.assertNotEqual(values[0]['password'],values[1]['password'])
        self.assertNotIn(values[0]['password'].encode(),rows[0]['payload'])
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=a).status_code,503)
        response=self.reconcile(first,self.positive); self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['profiles'][0]['state'],'applied')
        item=self.client.get('/portal/v2/profiles',headers=a).json()['profiles'][0]
        self.assertEqual(item['origin'],'device_managed')
        exported=self.client.post('/portal/v2/profiles/'+profile+'/export',json={'revision':item['revision'],'include_secrets':True},headers=a)
        self.assertEqual(exported.status_code,200,exported.text)
        self.assertEqual(json.loads(exported.json()['content'])['endpoint']['password'],values[0]['password'])
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=b).status_code,503)
        self.assertNotIn(values[0]['password'],json.dumps(response.json()))

    def test_rotation_is_fenced_idempotent_and_requires_both_protocol_receipts(self):
        profile=self.managed(); device,_=self.enrolled(); self.grant(profile,device); self.reconcile(device,self.positive)
        body={'device_id':device,'expected_generation':1,'request_key':'rotation-fixture-key-123456','consent':True}
        with patch.object(credentials,'enabled',return_value=True):
            a=self.post('profiles/'+profile+'/device-credentials',body); b=self.post('profiles/'+profile+'/device-credentials',body)
            self.assertEqual(a.status_code,200,a.text); self.assertEqual(a.json()['generation'],b.json()['generation'])
            self.assertEqual(self.post('profiles/'+profile+'/device-credentials',{**body,'request_key':'another-fixture-key-123456'}).status_code,409)
        def partial(row,payload,protocol,**kwargs):
            expected='authenticated' if payload==row['payload'] else 'rejected'
            return {'protocol':protocol,'outcome':'unavailable' if protocol=='http3' else expected}
        response=self.reconcile(device,partial)
        self.assertEqual(response.json()['profiles'][0]['state'],'failed')
        def all_protocols(row,payload,protocol,**kwargs):return {'protocol':protocol,'outcome':'authenticated' if payload==row['payload'] else 'rejected'}
        response=self.reconcile(device,all_protocols)
        self.assertEqual(response.json()['profiles'][0]['state'],'applied')
        self.assertEqual(len(response.json()['profiles'][0]['receipt']['checks']),4)

    def test_revoke_is_requested_until_old_password_is_rejected_and_is_idempotent(self):
        profile=self.managed(); device,auth=self.enrolled(); self.grant(profile,device); self.reconcile(device,self.positive)
        response=self.client.delete('/portal/v2/devices/'+str(device),headers=self.headers)
        self.assertEqual(response.status_code,200,response.text); self.assertEqual(response.json()['scope'],'portal_access')
        self.assertEqual(response.json()['vpn']['profiles'][0]['state'],'requested')
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).status_code,401)
        response=self.reconcile(device,self.positive); self.assertEqual(response.json()['profiles'][0]['state'],'failed')
        response=self.reconcile(device,lambda row,payload,protocol,**kwargs:{'protocol':protocol,'outcome':'rejected'})
        self.assertEqual(response.json()['profiles'][0]['state'],'applied')
        again=self.client.delete('/portal/v2/devices/'+str(device),headers=self.headers)
        self.assertEqual(again.json()['vpn']['profiles'][0]['generation'],2)
        self.assertEqual(again.json()['vpn']['profiles'][0]['state'],'applied')

    def test_late_receipt_cannot_accept_newer_rotation_and_owner_boundaries_hold(self):
        profile=self.managed(); device,_=self.enrolled(); self.grant(profile,device)
        rotated=[]
        def late(row,payload,protocol,**kwargs):
            if not rotated:
                rotated.append(True)
                with db.connect() as c: credentials.request(c,self.owner,device,credentials.number(profile),expected=1,key='late-fixture-key-123456789')
            return self.positive(row,payload,protocol)
        response=self.reconcile(device,late)
        self.assertEqual(response.json()['profiles'][0]['generation'],2)
        self.assertEqual(response.json()['profiles'][0]['state'],'requested')
        self.login(self.other)
        self.assertEqual(self.client.get('/portal/v2/devices/'+str(device)+'/credentials').status_code,404)
        self.assertEqual(self.post('devices/'+str(device)+'/credentials/reconcile',{'consent_restart_endpoint':True}).status_code,404)

    def test_restarted_endpoint_invalidates_otherwise_successful_receipts(self):
        profile=self.managed(); device,_=self.enrolled(); self.grant(profile,device)
        with patch.object(endpoint.manager,'credential_generation',return_value=1):
            with patch.object(credentials,'enabled',return_value=True), patch.object(endpoint.manager,'apply_device_credentials',return_value=0), patch.object(credentials,'CHECKER',fixture.exchange.CODEC), patch.object(credentials,'probe',side_effect=self.positive):
                response=self.post('devices/'+str(device)+'/credentials/reconcile',{'consent_restart_endpoint':True})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['profiles'][0]['state'],'failed')
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=self.enrolled('unrelated')[1]).status_code,200)
