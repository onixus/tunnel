"""Real Rust codec + isolated SQLite; never opens a production profile/database."""
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TARGET = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT.parent/'R-Trusttunnel/target')))
SANDBOX = tempfile.TemporaryDirectory(prefix='rtrust-portal-tests-')
os.environ.update(DATA_DIR=SANDBOX.name, SECRET_KEY=secrets.token_urlsafe(48), ADMIN_PASSWORD=secrets.token_urlsafe(32), RTRUST_CODEC=os.environ.get('RTRUST_CODEC',str(TARGET/'debug/rtrust-codec')))
PORTAL = Path(os.environ.get('RTRUST_PORTAL_SRC', str(ROOT/'server/upstream')))
if not (PORTAL/'app').is_dir():
    raise SystemExit('Set RTRUST_PORTAL_SRC to server/upstream of a tunnel checkout (the portal source)')
sys.path.insert(0, str(PORTAL))
import app
app.__path__.append(str(ROOT/'server/overlay/app'))
from app import db, config, security, rtrust_profiles as exchange
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

def valid_origin_label(value):
    # Client contract (docs/device-credentials.md): 1-80 printable ASCII bytes.
    return isinstance(value, str) and 1 <= len(value) <= 80 and all(0x20 <= ord(ch) <= 0x7e for ch in value)

class ExchangeTests(unittest.TestCase):
    def test_explicit_freshness_snapshot_caps_token_lifetime_and_preserves_legacy_shape(self):
        from unittest.mock import patch
        import time
        device,auth=self.enrolled('freshness')
        with db.connect() as c:c.execute('UPDATE rtrust_tokens SET expires=? WHERE device=?',(int(time.time())+120,device))
        request={'include_secrets':True,'freshness_version':1}
        with patch.dict(os.environ,{'RTRUST_OFFLINE_MAX_AGE_SECONDS':'3600'}):
            response=self.client.post('/portal/v2/snapshot',json=request,headers=auth)
        self.assertEqual(response.status_code,200,response.text)
        lease=response.json()['freshness'];self.assertEqual(lease['version'],1);self.assertEqual(lease['max_age_seconds'],3600)
        self.assertTrue(0<lease['token_remaining_seconds']<=120)
        legacy=self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth)
        self.assertEqual(legacy.status_code,200);self.assertNotIn('freshness',legacy.json())
        self.assertEqual(self.client.post('/portal/v2/snapshot',json={**request,'freshness_version':2},headers=auth).status_code,422)
        with patch.dict(os.environ,{'RTRUST_OFFLINE_MAX_AGE_SECONDS':'86401'}):
            self.assertEqual(self.client.post('/portal/v2/snapshot',json=request,headers=auth).status_code,503)

    def setUp(self):
        config.DB_PATH = str(Path(SANDBOX.name)/(secrets.token_hex(8)+'.db'))
        db.init_db(); exchange.init()
        self.owner = db.create_user('owner@example.invalid', 'unused')
        self.other = db.create_user('other@example.invalid', 'unused')
        exchange.templates = Jinja2Templates(directory=str(ROOT/'server/overlay/app/templates'))
        api = FastAPI(); exchange.install(api)
        api.mount('/static', StaticFiles(directory=ROOT/'server/overlay/app/static'), name='static')
        self.client = TestClient(api)
        self.login(self.owner)
        self.content = (ROOT/'server/test-environment/demo.endpoint.toml').read_text()

    def login(self, owner):
        cookie = security.create_session_token(str(owner), 'user')
        self.client.cookies.set('user_token', cookie)
        self.headers = {'x-csrf-token': hmac.new(config.SECRET_KEY.encode(), ('rtrust-csrf:'+cookie).encode(), hashlib.sha256).hexdigest()}

    def post(self, path, data):
        return self.client.post('/portal/v2/'+path, json=data, headers=self.headers)

    def preview(self):
        response = self.post('profile-imports/preview', {'content':self.content,'intent':'external_stored'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn('content', response.json())
        self.assertEqual(response.json()['origin'], exchange.ORIGIN_STORED)
        return response.json()['preview_id']

    def imported(self):
        preview = self.preview()
        response = self.post('profile-imports/'+preview+'/commit', {'action':'create','consent':True})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_page_and_assets_have_real_routes(self):
        response=self.client.get('/profiles')
        self.assertEqual(response.status_code,200,response.text)
        self.assertIn('csrf-token',response.text)
        self.assertIn('rtrust-profiles.js',response.text)
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(self.client.get('/static/rtrust-profiles.js').status_code,200)
        self.assertEqual(self.client.get('/static/rtrust-profiles.css').status_code,200)
        self.client.cookies.clear()
        self.assertEqual(self.client.get('/profiles',follow_redirects=False).status_code,302)

    def test_qr_uses_browser_https_origin_and_only_one_time_code(self):
        response=self.client.post('/portal/v2/enrollment-codes',json={'origin':'https://panel.example'},headers={**self.headers,'origin':'https://panel.example'})
        self.assertEqual(response.status_code,200,response.text)
        value=response.json(); invite=value['invitation']
        self.assertEqual(invite['kind'],'rtrust_enrollment'); self.assertEqual(invite['origin'],'https://panel.example')
        self.assertEqual(set(invite),{'kind','version','origin','code','expires_at'})
        self.assertEqual(invite['code'],value['code']); self.assertTrue(value['qr_svg'])
        self.assertEqual(response.headers['cache-control'],'no-store')
        for origin in ['http://panel.example','https://panel.example/path','https://user@panel.example','https://foreign.example']:
            rejected=self.client.post('/portal/v2/enrollment-codes',json={'origin':origin},headers={**self.headers,'origin':'https://panel.example'})
            self.assertEqual(rejected.status_code,422)
        body={'code':invite['code'],'name':'QR fixture','platform':'android'}
        self.assertEqual(self.post('enroll',body).status_code,200)
        self.assertEqual(self.post('enroll',body).status_code,401)

    def test_token_renewal_requires_current_device_and_rechecks_expiry_in_transaction(self):
        from unittest.mock import patch
        device,auth=self.enrolled('renew')
        path='/portal/v2/token/renew'
        self.assertEqual(self.client.post(path,json={'consent':False},headers=auth).status_code,422)
        self.assertEqual(self.post('token/renew',{'consent':True}).status_code,403)
        response=self.client.post(path,json={'consent':True},headers=auth)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json(),{'expires_in':30*86400,'scope':'portal_access_only'})
        self.assertEqual(self.client.post(path,json={'consent':True,'device_id':999},headers=auth).status_code,422)
        original=exchange.actor
        def expire(request,*args):
            result=original(request,*args)
            with db.connect() as c:c.execute('UPDATE rtrust_tokens SET expires=1 WHERE device=?',(device,))
            return result
        with patch.object(exchange,'actor',side_effect=expire):
            self.assertEqual(self.client.post(path,json={'consent':True},headers=auth).status_code,401)
        self.assertEqual(self.client.post(path,json={'consent':True},headers=auth).status_code,401)

    def test_roundtrip_encryption_and_idempotency(self):
        preview = self.preview()
        body = {'action':'create','consent':True}
        first = self.post('profile-imports/'+preview+'/commit', body)
        second = self.post('profile-imports/'+preview+'/commit', body)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json(),second.json())
        item = first.json()
        response = self.post('profiles/'+item['id']+'/export', {'format':'profile_json','revision':item['revision'],'include_secrets':True})
        self.assertEqual(response.status_code,200,response.text)
        exported = response.json()['content']
        with db.connect() as c:
            stored = c.execute('SELECT payload FROM rtrust_profiles').fetchone()[0]
            self.assertNotIn(exported.encode(),stored)
            self.assertEqual(exchange.unseal(self.owner,stored),exported)
            with self.assertRaises(Exception): exchange.unseal(self.other,stored)
        self.assertEqual(self.post('profiles/'+item['id']+'/export', {'revision':'wrong','include_secrets':True}).status_code,409)
        self.assertEqual(self.post('profiles/'+item['id']+'/export', {'revision':'1'}).status_code,422)

    def test_owner_isolation_and_csrf(self):
        item = self.imported(); preview=self.preview()
        denied = self.client.post('/portal/v2/enrollment-codes')
        self.assertEqual(denied.status_code,403)
        self.assertEqual(denied.headers['cache-control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", denied.headers['content-security-policy'])
        self.login(self.other)
        self.assertEqual(self.client.get('/portal/v2/profiles').json()['profiles'],[])
        self.assertEqual(self.post('profiles/'+item['id']+'/export', {'revision':'1','include_secrets':True}).status_code,404)
        self.assertEqual(self.post('profile-imports/'+preview+'/commit', {'action':'create','consent':True}).status_code,404)

    def test_device_grants_revocation_and_code_reuse(self):
        item=self.imported()
        code=self.post('enrollment-codes',{}).json()['code']
        data={'code':code,'name':'CI device','platform':'windows'}
        registered=self.post('enroll',data)
        self.assertEqual(registered.status_code,200,registered.text)
        device=registered.json()
        self.assertEqual(self.post('enroll',data).status_code,401)
        auth={'Authorization':'Bearer '+device['token']}
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).json()['profiles'],[])
        self.assertEqual(self.post('profiles/'+item['id']+'/grants', {'device_id':device['device_id'],'allow':True}).status_code,200)
        self.assertEqual(len(self.client.get('/portal/v2/profiles',headers=auth).json()['profiles']),1)
        revoked=self.client.delete('/portal/v2/devices/'+str(device['device_id']),headers=self.headers)
        self.assertEqual(revoked.status_code,200,revoked.text)
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=auth).status_code,401)
        self.assertEqual(self.client.get('/portal/v2/profiles',headers={'Authorization':'Bearer invalid'}).status_code,401)

    def test_atomic_snapshot_rechecks_token_and_freezes_policy_with_profiles(self):
        from unittest.mock import patch
        item=self.imported(); device,auth=self.enrolled()
        self.post('profiles/'+item['id']+'/grants', {'device_id':device,'allow':True})
        group=self.group(); self.post('route-groups/'+str(group['id'])+'/members',{'device_id':device,'member':True})
        original=exchange.accessible
        changed=[]
        def concurrent_change(c, owner, device_id, identifier, settings=None):
            value=original(c,owner,device_id,identifier,settings)
            if not changed:
                changed.append(True)
                with db.connect() as writer:
                    writer.execute('UPDATE rtrust_route_groups SET revision=revision+1,name=? WHERE id=?',('Updated concurrently',group['id']))
            return value
        with patch.object(exchange,'accessible',side_effect=concurrent_change):
            response=self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth)
        self.assertEqual(response.status_code,200,response.text)
        value=response.json()
        self.assertEqual(value['routing']['policy']['revision'],str(group['id'])+':1')
        self.assertEqual(value['profiles'][0]['metadata']['id'],item['id'])
        self.assertEqual(len(value['revision']),64)
        self.assertEqual(response.headers['cache-control'],'no-store')
        current=self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth).json()
        self.assertNotEqual(value['revision'],current['revision'])
        self.assertEqual(current['routing']['policy']['revision'],str(group['id'])+':2')
        # A revoke committed after actor() must still be rejected by the
        # token check inside the snapshot's own transaction.
        actor=exchange.actor
        def revoke_after_actor(request, mutate=False):
            result=actor(request,mutate)
            with db.connect() as writer:writer.execute('DELETE FROM rtrust_tokens WHERE device=?',(device,))
            return result
        with patch.object(exchange,'actor',side_effect=revoke_after_actor):
            response=self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth)
        self.assertEqual(response.status_code,401)

    def test_snapshot_requires_device_and_explicit_secret_consent(self):
        self.assertEqual(self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=self.headers).status_code,403)
        _,auth=self.enrolled()
        self.assertEqual(self.client.post('/portal/v2/snapshot',json={},headers=auth).status_code,422)
        response=self.client.post('/portal/v2/snapshot',json={'include_secrets':True,'unknown':True},headers=auth)
        self.assertEqual(response.status_code,422)
        self.assertEqual(self.client.get('/portal/v2/capabilities').json()['snapshot'],1)

    def test_ios_enrollment_is_accepted(self):
        code = self.post('enrollment-codes', {}).json()['code']
        response = self.post('enroll', {'code': code, 'name': 'iPhone fixture', 'platform': 'ios'})
        self.assertEqual(response.status_code, 200, response.text)
        devices = self.client.get('/portal/v2/devices').json()['devices']
        self.assertEqual(devices[0]['platform'], 'ios')

    def test_replace_revision_and_expired_preview(self):
        item=self.imported(); first=self.preview(); stale=self.preview()
        data={'action':'replace','target_id':item['id'],'base_revision':'1','consent':True}
        result=self.post('profile-imports/'+first+'/commit',data)
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['revision'],'2')
        self.assertEqual(self.post('profile-imports/'+stale+'/commit',data).status_code,409)
        expired=self.preview()
        with db.connect() as c:c.execute('UPDATE rtrust_imports SET expires=0 WHERE id=?',(expired,))
        self.assertEqual(self.post('profile-imports/'+expired+'/commit',{'action':'create','consent':True}).status_code,410)

    def test_managed_profile_uses_codec_and_cannot_be_replaced(self):
        with db.connect() as c:
            c.execute("UPDATE settings SET value='endpoint.example.invalid' WHERE key='panel_domain'")
            identifier=c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',(self.owner,'fixture-user',secrets.token_urlsafe(24),'Managed fixture')).lastrowid
        items=self.client.get('/portal/v2/profiles')
        self.assertEqual(items.status_code,200,items.text)
        item=items.json()['profiles'][0]
        self.assertEqual(item['id'],'managed-'+str(identifier))
        self.assertEqual(item['summary']['hostname'],'endpoint.example.invalid')
        for fmt in ['profile_json','endpoint_toml','cli_toml','tt']:
            response=self.post('profiles/'+item['id']+'/export',{'revision':item['revision'],'include_secrets':True,'format':fmt,'accept_losses':True})
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(exchange.codec(response.json()['content'])['summary']['hostname'],'endpoint.example.invalid')
        preview=self.preview()
        self.assertEqual(self.post('profile-imports/'+preview+'/commit',{'action':'replace','target_id':item['id'],'base_revision':item['revision'],'consent':True}).status_code,403)

    def test_profile_origin_labels_follow_client_contract(self):
        # Android/iOS reject a whole managed batch unless origin is 1-80 printable ASCII.
        for label in ['', 'x'*81, 'portal\u200bmanaged', 'caf\u00e9', 'line\n', '\x7f', None, 1]:
            self.assertFalse(valid_origin_label(label), repr(label))
        for label in ['portal_managed', 'external_stored', '~', 'x'*80, *exchange.ORIGIN_LABELS]:
            self.assertTrue(valid_origin_label(label), label)
        with db.connect() as c:
            c.execute("UPDATE settings SET value='endpoint.example.invalid' WHERE key='panel_domain'")
            c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',(self.owner,'fixture-user',secrets.token_urlsafe(24),'Managed fixture'))
        self.assertEqual(self.post('profile-imports/'+self.preview()+'/commit',{'action':'create','consent':True}).status_code,200)
        items=self.client.get('/portal/v2/profiles').json()['profiles']
        self.assertEqual(sorted(item['origin'] for item in items),['external_stored','portal_managed'])
        for item in items:
            self.assertIn(item['origin'],exchange.ORIGIN_LABELS)
            self.assertTrue(valid_origin_label(item['origin']))

    def test_invalid_import_cannot_commit_and_body_limit(self):
        self.assertEqual(self.post('profile-imports/preview', {'content':'not a profile','intent':'external_stored'}).status_code,422)
        self.assertEqual(self.post('profile-imports/preview', {'content':'x'*(exchange.LIMIT+1),'intent':'external_stored'}).status_code,413)
        self.assertEqual(self.post('profile-imports/preview', {'content':self.content,'intent':'provision'}).status_code,422)
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_profiles').fetchone()[0],0)

    def seed_profiles(self, count, device=None):
        # Synthetic historical rows; bypasses the API caps on purpose.
        import json, uuid
        document=exchange.codec(self.content)
        ids=[]
        with db.connect() as c:
            for _ in range(count):
                identifier=str(uuid.uuid4());ids.append(identifier)
                c.execute('INSERT INTO rtrust_profiles VALUES(?,?,1,?,?,0)',(identifier,self.owner,exchange.seal(self.owner,document['content']),json.dumps(document['summary'])))
                if device is not None:c.execute('INSERT INTO rtrust_grants VALUES(?,?)',(identifier,device))
        return ids

    def test_client_profile_limit_blocks_creation_beyond_64(self):
        limit=exchange.MAX_CLIENT_PROFILES
        self.assertEqual(limit,64)
        self.assertEqual(self.client.get('/portal/v2/capabilities').json()['max_client_profiles'],64)
        device,auth=self.enrolled('limit device')
        self.seed_profiles(limit-1,device)
        # The device itself may import the 64th; it is granted to it atomically.
        preview=self.client.post('/portal/v2/profile-imports/preview',json={'content':self.content,'intent':'external_stored'},headers=auth).json()['preview_id']
        own=self.client.post('/portal/v2/profile-imports/'+preview+'/commit',json={'action':'create','consent':True},headers=auth)
        self.assertEqual(own.status_code,200,own.text)
        listed=self.client.get('/portal/v2/profiles',headers=auth)
        self.assertEqual(listed.status_code,200,listed.text);self.assertEqual(len(listed.json()['profiles']),64)
        snapshot=self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth)
        self.assertEqual(snapshot.status_code,200,snapshot.text);self.assertEqual(len(snapshot.json()['profiles']),64)
        # Owner imports are not bound by the device sync limit (previous cap 100).
        committed=self.post('profile-imports/'+self.preview()+'/commit',{'action':'create','consent':True})
        self.assertEqual(committed.status_code,200,committed.text)
        extra=committed.json()['id']
        # Re-granting an existing grant stays idempotent; a 65th grant is refused.
        self.assertEqual(self.post('profiles/'+own.json()['id']+'/grants',{'device_id':device,'allow':True}).status_code,200)
        refused=self.post('profiles/'+extra+'/grants',{'device_id':device,'allow':True})
        self.assertEqual(refused.status_code,409);self.assertIn('64',refused.text)
        self.assertNotIn(extra,refused.text);self.assertNotIn(str(device),refused.text)
        with db.connect() as c:self.assertIsNone(c.execute('SELECT 1 FROM rtrust_grants WHERE profile=?',(extra,)).fetchone())
        # A full device cannot import more either; nothing is created.
        preview=self.client.post('/portal/v2/profile-imports/preview',json={'content':self.content,'intent':'external_stored'},headers=auth).json()['preview_id']
        self.assertEqual(self.client.post('/portal/v2/profile-imports/'+preview+'/commit',json={'action':'create','consent':True},headers=auth).status_code,409)
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_profiles WHERE revoked=0').fetchone()[0],65)
        # Another device's limit is independent.
        _,neighbor=self.enrolled('neighbor')
        self.assertEqual(self.client.get('/portal/v2/profiles',headers=neighbor).json()['profiles'],[])

    def test_owner_import_cap_stays_100_without_counting_configs(self):
        with db.connect() as c:
            for i in range(5):c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',(self.owner,f'fixture-{i}',secrets.token_urlsafe(24),'Managed fixture'))
        self.seed_profiles(99)
        self.assertEqual(self.post('profile-imports/'+self.preview()+'/commit',{'action':'create','consent':True}).status_code,200)
        self.assertEqual(self.post('profile-imports/'+self.preview()+'/commit',{'action':'create','consent':True}).status_code,409)

    def test_historical_excess_fails_closed_for_device_only(self):
        device,auth=self.enrolled('historical device')
        ids=self.seed_profiles(exchange.MAX_CLIENT_PROFILES+1,device)
        for response in (self.client.get('/portal/v2/profiles',headers=auth),
                         self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth),
                         self.client.post('/portal/v2/snapshot',json={'include_secrets':True,'freshness_version':1},headers=auth)):
            self.assertEqual(response.status_code,409,response.text)
            self.assertEqual(response.json(),{'detail':exchange.SYNC_LIMIT_ERROR})
            self.assertEqual(response.headers['cache-control'],'no-store')
        # The owner browser view is not a client sync: >64 imports+configs stay listable.
        db.set_settings({'panel_domain':'endpoint.example.invalid'})
        with db.connect() as c:c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',(self.owner,'fixture-user',secrets.token_urlsafe(24),'Managed fixture'))
        owner=self.client.get('/portal/v2/profiles')
        self.assertEqual(owner.status_code,200,owner.text);self.assertEqual(len(owner.json()['profiles']),66)
        # Stale grants do not count: removing one live profile restores sync.
        with db.connect() as c:c.execute('UPDATE rtrust_profiles SET revoked=1,payload=NULL WHERE id=?',(ids[0],))
        listed=self.client.get('/portal/v2/profiles',headers=auth)
        self.assertEqual(listed.status_code,200,listed.text);self.assertEqual(len(listed.json()['profiles']),64)
        self.assertEqual(len(self.client.post('/portal/v2/snapshot',json={'include_secrets':True},headers=auth).json()['profiles']),64)

    def enrolled(self, name='Route device'):
        code=self.post('enrollment-codes',{}).json()['code']
        response=self.post('enroll',{'code':code,'name':name,'platform':'linux'})
        self.assertEqual(response.status_code,200,response.text)
        return response.json()['device_id'],{'Authorization':'Bearer '+response.json()['token']}

    def group(self, **extra):
        data={'name':'Офис','include':['10.0.0.0/8','192.168.10.0/24'],'exclude':['10.1.0.0/16'],'exclude_lan':True,**extra}
        response=self.post('route-groups',data)
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def test_route_group_crud_and_validation(self):
        self.assertEqual(self.client.get('/portal/v2/capabilities').json()['routing'],1)
        self.assertEqual(self.client.get('/portal/v2/route-groups').json(),{'groups':[]})
        created=self.group(include=['10.0.0.0/8',' 10.0.0.0/255.0.0.0 ','0.0.0.0/0'])
        self.assertEqual(created,{'id':created['id'],'name':'Офис','include':['10.0.0.0/8','0.0.0.0/0'],'exclude':['10.1.0.0/16'],'exclude_lan':True,'revision':1,'devices':[]})
        self.assertEqual(self.client.get('/portal/v2/route-groups').json()['groups'],[created])
        base={'name':'x','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':False}
        for bad in [{'include':['10.0.0.1/8']},{'include':['10.0.0.0/33']},{'include':['fd00::/8']},{'include':['10.0.0.0']},{'include':[]},{'include':'10.0.0.0/8'},
                    {'include':[f'10.{i}.0.0/16' for i in range(17)]},{'exclude':[f'10.{i}.0.0/16' for i in range(65)]},{'exclude':[167772160]},
                    {'exclude_lan':1},{'name':''},{'name':'x'*81},{'name':'a\nb'},{'unknown':True}]:
            self.assertEqual(self.post('route-groups',{**base,**bad}).status_code,422,bad)
        self.assertEqual(self.post('route-groups',{k:v for k,v in base.items() if k!='exclude'}).status_code,422)
        self.assertEqual(self.post('route-groups',{**base,'include':[f'10.{i}.0.0/16' for i in range(16)],'exclude':[f'11.{i}.0.0/16' for i in range(64)]}).status_code,200)
        path='/portal/v2/route-groups/'+str(created['id'])
        updated=self.client.put(path,json={**base,'name':'Склад','revision':1},headers=self.headers)
        self.assertEqual(updated.status_code,200,updated.text)
        self.assertEqual((updated.json()['name'],updated.json()['revision'],updated.json()['include']),('Склад',2,['10.0.0.0/8']))
        self.assertEqual(self.client.put(path,json={**base,'revision':1},headers=self.headers).status_code,409)
        self.assertEqual(self.client.put(path,json={**base,'revision':'2'},headers=self.headers).status_code,422)
        self.assertEqual(self.client.put(path,json={**base,'revision':2,'extra':1},headers=self.headers).status_code,422)
        self.assertEqual(self.client.put('/portal/v2/route-groups/999999',json={**base,'revision':1},headers=self.headers).status_code,404)
        self.assertEqual(self.client.delete(path,headers=self.headers).status_code,409)
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'1'}).status_code,409)
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'2'}).status_code,200)
        self.assertEqual(len(self.client.get('/portal/v2/route-groups').json()['groups']),1)
        with db.connect() as c:
            actions=[r[0] for r in c.execute("SELECT action FROM rtrust_audit WHERE action LIKE 'route_%' ORDER BY id")]
        self.assertEqual(actions,['route_group_create','route_group_create','route_group_update','route_group_delete'])

    def test_route_group_limit_and_csrf(self):
        data={'name':'g','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':False}
        self.assertEqual(self.client.post('/portal/v2/route-groups',json=data).status_code,403)
        self.assertEqual(self.client.post('/portal/v2/route-groups',json=data,headers={'x-csrf-token':'0'*64}).status_code,403)
        created=self.group()
        path='/portal/v2/route-groups/'+str(created['id'])
        self.assertEqual(self.client.put(path,json={**data,'revision':1}).status_code,403)
        self.assertEqual(self.client.delete(path,headers={'If-Match':'1'}).status_code,403)
        self.assertEqual(self.client.post(path+'/members',json={'device_id':1,'member':True}).status_code,403)
        with db.connect() as c:
            for i in range(49):c.execute('INSERT INTO rtrust_route_groups(owner,name,policy,revision) VALUES(?,?,?,1)',(self.owner,'g'+str(i),'{"include":["10.0.0.0/8"],"exclude":[],"exclude_lan":false}'))
        self.assertEqual(self.post('route-groups',data).status_code,409)
        self.login(self.other)
        self.assertEqual(self.post('route-groups',data).status_code,200)

    def test_route_group_owner_isolation(self):
        created=self.group();device,_=self.enrolled()
        path='/portal/v2/route-groups/'+str(created['id'])
        self.login(self.other)
        own=self.group(name='Чужая');other_device,_=self.enrolled('Other device')
        self.assertEqual([g['id'] for g in self.client.get('/portal/v2/route-groups').json()['groups']],[own['id']])
        data={'name':'x','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':False,'revision':1}
        self.assertEqual(self.client.put(path,json=data,headers=self.headers).status_code,404)
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'1'}).status_code,404)
        self.assertEqual(self.post('route-groups/'+str(created['id'])+'/members',{'device_id':other_device,'member':True}).status_code,404)
        self.assertEqual(self.post('route-groups/'+str(own['id'])+'/members',{'device_id':device,'member':True}).status_code,404)
        self.login(self.owner)
        self.assertEqual(self.post('route-groups/'+str(created['id'])+'/members',{'device_id':other_device,'member':True}).status_code,404)
        self.assertEqual(self.client.get('/portal/v2/route-groups').json()['groups'],[created])

    def test_device_routing_policy_membership(self):
        first=self.group();second=self.group(name='Дом',include=['0.0.0.0/0'],exclude=[],exclude_lan=False)
        device,auth=self.enrolled()
        self.assertEqual(self.client.get('/portal/v2/routing').status_code,403)
        self.assertEqual(self.client.get('/portal/v2/routing',headers={'Authorization':'Bearer invalid'}).status_code,401)
        response=self.client.get('/portal/v2/routing',headers=auth)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json(),{'policy':None})
        self.assertEqual(response.headers['cache-control'],'no-store')
        for method,path in [('GET','route-groups'),('POST','route-groups'),('PUT','route-groups/'+str(first['id'])),('DELETE','route-groups/'+str(first['id'])),('POST','route-groups/'+str(first['id'])+'/members')]:
            self.assertEqual(self.client.request(method,'/portal/v2/'+path,json={'device_id':device,'member':True},headers={**auth,'If-Match':'1'}).status_code,403,path)
        members='route-groups/'+str(first['id'])+'/members'
        for bad in [{'device_id':str(device),'member':True},{'device_id':device,'member':1},{'device_id':device},{'device_id':device,'member':True,'x':1}]:
            self.assertEqual(self.post(members,bad).status_code,422,bad)
        self.assertEqual(self.post(members,{'device_id':999999,'member':True}).status_code,404)
        added=self.post(members,{'device_id':device,'member':True})
        self.assertEqual(added.status_code,200,added.text)
        self.assertEqual(added.json()['devices'],[device])
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':{'group':'Офис','revision':str(first['id'])+':1','include':['10.0.0.0/8','192.168.10.0/24'],'exclude':['10.1.0.0/16'],'exclude_lan':True}})
        self.client.put('/portal/v2/route-groups/'+str(first['id']),json={'name':'Офис','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':True,'revision':1},headers=self.headers)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['revision'],str(first['id'])+':2')
        moved=self.post('route-groups/'+str(second['id'])+'/members',{'device_id':device,'member':True})
        self.assertEqual(moved.json()['devices'],[device])
        groups={g['id']:g['devices'] for g in self.client.get('/portal/v2/route-groups').json()['groups']}
        self.assertEqual(groups,{first['id']:[],second['id']:[device]})
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy'],{'group':'Дом','revision':str(second['id'])+':1','include':['0.0.0.0/0'],'exclude':[],'exclude_lan':False})
        self.assertEqual(self.post(members,{'device_id':device,'member':False}).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['group'],'Дом')
        self.assertEqual(self.post('route-groups/'+str(second['id'])+'/members',{'device_id':device,'member':False}).json()['devices'],[])
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':None})
        self.post(members,{'device_id':device,'member':True})
        self.assertEqual(self.client.delete('/portal/v2/devices/'+str(device),headers=self.headers).status_code,200)
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_route_members').fetchone()[0],0)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).status_code,401)
        self.assertEqual(self.post(members,{'device_id':device,'member':True}).status_code,404)
        latest=self.client.get('/portal/v2/route-groups').json()['groups'][0]
        self.assertEqual(self.client.delete('/portal/v2/route-groups/'+str(first['id']),headers={**self.headers,'If-Match':str(latest['revision'])}).status_code,200)

    def test_deleting_group_clears_device_policy(self):
        created=self.group();device,auth=self.enrolled()
        self.post('route-groups/'+str(created['id'])+'/members',{'device_id':device,'member':True})
        self.assertEqual(self.client.delete('/portal/v2/route-groups/'+str(created['id']),headers={**self.headers,'If-Match':'1'}).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':None})
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_route_members').fetchone()[0],0)

if __name__=='__main__': unittest.main()
