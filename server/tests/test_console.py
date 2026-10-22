"""Isolated identities, real SQLite, fake transport. Never sends messages or touches live VPNs."""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
PORTAL_ROOT=Path(os.environ.get('RTRUST_SOURCE_DIR',str(ROOT.parent/'R-Trusttunnel')))
TMP=tempfile.TemporaryDirectory(prefix='vpn-console-tests-')
os.environ.update(DATA_DIR=TMP.name,SECRET_KEY=secrets.token_hex(32),ADMIN_PASSWORD=secrets.token_hex(24),CONSOLE_DATA=TMP.name+'/console')
sys.path.insert(0,str(ROOT/'server/upstream')); sys.path.insert(0,str(ROOT/'server/console'))
import app
app.__path__.append(str(ROOT/'server/overlay/app'))
os.environ.setdefault('RTRUST_CODEC',str(PORTAL_ROOT/'target/debug/rtrust-codec'))
from app import db,config,security
import console_app as ui
import agent
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

class ConsoleTests(unittest.TestCase):
    def setUp(self):
        ui.STATE=Path(TMP.name)/secrets.token_hex(8); ui.init()
        config.DB_PATH=str(Path(TMP.name)/(secrets.token_hex(8)+'.db'));db.init_db()
        self.client=TestClient(ui.app)
        with db.connect() as c:self.admin=c.execute('SELECT id FROM admins LIMIT 1').fetchone()[0]
        self.cookie=security.create_session_token(str(self.admin),'admin');self.client.cookies.set('admin_token',self.cookie)
        self.csrf=hmac.new(config.SECRET_KEY.encode(),('console:'+self.cookie).encode(),hashlib.sha256).hexdigest()
        self.user=db.create_user('test@example.invalid','unused')
        self.mock=patch.object(ui,'agent',return_value={'hysteria_users':[],'routing':{'selected':'reserve'}});self.mock.start();self.addCleanup(self.mock.stop)
    def post(self,path,data):return self.client.post('/console/api/'+path,json=data,headers={'X-CSRF-Token':self.csrf})
    def job(self,action,data,key=None):return self.post('jobs',{'action':action,'data':data,'confirm':True,'request_id':key or secrets.token_hex(16)})
    def test_auth_csrf_origin_and_redaction(self):
        db.create_config(self.user,'test-key','secret-not-in-state','test')
        s=self.client.get('/console/api/state');self.assertEqual(s.status_code,200);self.assertNotIn('secret-not-in-state',s.text);self.assertNotIn('password_hash',s.text)
        self.assertEqual(s.headers['cache-control'],'no-store')
        self.assertEqual(self.client.post('/console/api/jobs',json={}).status_code,403)
        self.assertEqual(self.client.post('/console/api/jobs',json={},headers={'X-CSRF-Token':self.csrf,'Origin':'https://evil.invalid'}).status_code,403)
        self.client.cookies.clear();self.assertEqual(self.client.get('/console/api/state').status_code,401)
        self.client.cookies.set('admin_token',security.create_session_token(str(self.user),'user'));self.assertEqual(self.client.get('/console/api/state').status_code,401)
    def test_real_templates_assets_and_logout_state(self):
        r=self.client.get('/console');self.assertEqual(r.status_code,200);self.assertIn('csrf-token',r.text)
        for asset in ['console.css','console.js']:self.assertEqual(self.client.get('/console/static/'+asset).status_code,200)
        self.client.cookies.clear();self.assertEqual(self.client.get('/console',follow_redirects=False).headers['location'],'/admin/login')
    def test_job_idempotence_and_no_automatic_replay(self):
        key=secrets.token_hex(16);data={'id':self.user}
        self.assertEqual(self.job('trusttunnel.block',data,key).status_code,200)
        self.assertEqual(self.job('trusttunnel.block',data,key).status_code,200)
        self.assertEqual(self.job('trusttunnel.unblock',data,key).status_code,409)
        with patch.object(ui,'perform',return_value={'message':'done'}) as perform:
            self.assertTrue(ui.work_once());self.assertFalse(ui.work_once());perform.assert_called_once()
        with ui.connect() as c:c.execute("UPDATE jobs SET state='running'")
        ui.init()
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM jobs').fetchone()[0],'unknown')
        self.assertFalse(ui.work_once())
    def test_create_retry_uses_canonical_payload_without_reexecution(self):
        for action,data in [('hysteria.create',{'username':'testuser'}),
                            ('trusttunnel.create',{'email':'  NEW@EXAMPLE.INVALID  '})]:
            with self.subTest(action=action):
                key=secrets.token_hex(16)
                first=self.job(action,data,key)
                self.assertEqual(first.status_code,200,first.text)
                self.assertEqual(self.job(action,data,key).status_code,200)
                with patch.object(ui,'perform',return_value={'message':'done'}) as perform:
                    ui.work_once()
                    if action=='trusttunnel.create':db.create_user('new@example.invalid','unused')
                    retry=self.job(action,data,key)
                    self.assertEqual(retry.status_code,200,retry.text)
                    self.assertEqual(retry.json()['state'],'success')
                    self.assertFalse(ui.work_once());perform.assert_called_once()
                changed={'username':'different'} if action=='hysteria.create' else {'email':'other@example.invalid'}
                self.assertEqual(self.job(action,changed,key).status_code,409)

    def test_campaign_retry_after_send_returns_existing_job(self):
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':True})
        draft=self.post('campaigns',{'channel':'email','subject':'Test','body':'Hello',
                    'recipients':[{'source':'trusttunnel','id':self.user}]}).json()
        key=secrets.token_hex(16);data={'id':draft['id']}
        self.assertEqual(self.job('campaign.send',data,key).status_code,200)
        with patch.object(ui.mailer,'send_mail') as send:
            ui.work_once()
            self.assertEqual(self.job('campaign.send',data,key).status_code,200)
            self.assertFalse(ui.work_once());send.assert_called_once()

    def test_telegram_validates_complete_message_before_creating_draft(self):
        self.post('contacts',{'source':'trusttunnel','id':self.user,'chat_id':123456,'consent':True})
        payload={'channel':'telegram','subject':'s'*160,'body':'b'*3339,
                 'recipients':[{'source':'trusttunnel','id':self.user}]}
        self.assertEqual(self.post('campaigns',payload).status_code,422)
        with ui.connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM campaigns').fetchone()[0],0)
        payload['body']='b'*3338
        draft=self.post('campaigns',payload);self.assertEqual(draft.status_code,200,draft.text)
        self.job('campaign.send',{'id':draft.json()['id']});ui.work_once()
        text=ui.agent.call_args.args[1]['text'];self.assertEqual(len(text),3500)
        tg=ui.STATE/'telegram.json';tg.write_text(json.dumps({'token':'test-only'}))
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self):return b'{"ok":true,"result":{"message_id":1}}'
        with patch.object(agent,'TG',tg),patch.object(agent.urllib.request,'build_opener') as opener:
            opener.return_value.open.return_value=Response()
            self.assertEqual(agent.telegram({'chat_id':123456,'text':text}),{'message_id':1})
            opener.return_value.open.assert_called_once()

    def test_deleted_admin_cannot_execute_queued_job(self):
        self.job('routes.check',{})
        with db.connect() as c:c.execute('DELETE FROM admins')
        with patch.object(ui,'perform') as p:ui.work_once();p.assert_not_called()
    def test_contact_consent_preview_no_send_and_single_delivery(self):
        self.assertEqual(self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':True}).status_code,200)
        payload={'channel':'email','subject':'Maintenance','body':'Hello','recipients':[{'source':'trusttunnel','id':self.user}]}
        with patch.object(ui.mailer,'send_mail') as send:
            draft=self.post('campaigns',payload);self.assertEqual(draft.status_code,200);send.assert_not_called()
            id=draft.json()['id'];self.assertEqual(self.job('campaign.send',{'id':id}).status_code,200)
            self.assertEqual(self.job('campaign.send',{'id':id}).status_code,409)
            ui.work_once();send.assert_called_once_with('test@example.invalid','Maintenance','Hello')
            self.assertEqual(self.job('campaign.send',{'id':id}).status_code,409)
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM deliveries').fetchone()[0],'accepted')
    def test_revoked_consent_and_failed_send_not_retried(self):
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':True})
        payload={'channel':'email','subject':'Maintenance','body':'Hello','recipients':[{'source':'trusttunnel','id':self.user}]}
        id=self.post('campaigns',payload).json()['id']
        self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'test@example.invalid','consent':False})
        self.job('campaign.send',{'id':id})
        with patch.object(ui.mailer,'send_mail') as send:ui.work_once();send.assert_not_called()
        with ui.connect() as c:self.assertEqual(c.execute('SELECT state FROM deliveries').fetchone()[0],'skipped')
    def test_export_requires_consent_and_audits_without_secret(self):
        id=db.create_config(self.user,'test-key','only-in-export','test')
        self.assertEqual(self.post('export',{'source':'trusttunnel','id':id}).status_code,422)
        db.set_settings({'conn_address':'vpn.example.invalid','conn_port':'8443','panel_domain':'vpn.example.invalid'})
        r=self.post('export',{'source':'trusttunnel','id':id,'consent':True});self.assertEqual(r.status_code,200,r.text);self.assertTrue(r.json()['content'].startswith('tt://'))
        with ui.connect() as c:self.assertNotIn('only-in-export',str(c.execute('SELECT * FROM audit').fetchall()))
    def test_device_revocation_removes_only_its_keys(self):
        device=db.create_device(self.user,'test device',secrets.token_hex(32))
        key=db.create_device_config(self.user,device,'device-key','not-logged','device')
        other=db.create_config(self.user,'other-key','other-secret','other')
        self.assertEqual(self.job('trusttunnel.device-revoke',{'id':device}).status_code,200)
        with patch.object(ui,'legacy',return_value={'message':'reconciled'}):ui.work_once()
        self.assertTrue(db.get_device(device)['revoked_at'])
        self.assertTrue(db.get_config(key)['revoked_at'])
        self.assertIsNone(db.get_config(other)['revoked_at'])

    def deliver_setup(self,chat=None):
        db.set_settings({'conn_address':'vpn.example.invalid','conn_port':'8443','panel_domain':'vpn.example.invalid','smtp_host':'smtp.example.invalid'})
        id=db.create_config(self.user,'test-key','delivered-secret','phone')
        # The legacy deeplink helper shells out to the endpoint binary, absent outside the image.
        from app import conninfo
        deeplink=patch.object(conninfo,'build_deeplink',return_value='tt://legacy-deeplink');deeplink.start();self.addCleanup(deeplink.stop)
        self.assertEqual(self.post('contacts',{'source':'trusttunnel','id':self.user,'email':'',**({'chat_id':chat} if chat else {})}).status_code,200)
        return id
    def test_config_send_validation_and_missing_contacts(self):
        self.deliver_setup()
        for bad in [{'source':'trusttunnel','id':self.user},{'source':'trusttunnel','id':self.user,'channels':[]},
                    {'source':'trusttunnel','id':self.user,'channels':['sms']},{'source':'trusttunnel','id':self.user,'channels':['email','email']},
                    {'source':'shell','id':self.user,'channels':['email']},{'source':'trusttunnel','id':'1','channels':['email']}]:
            self.assertEqual(self.job('config.send',bad).status_code,422,bad)
        # Telegram needs an explicit chat ID; TrustTunnel e-mail falls back to the login.
        self.assertEqual(self.job('config.send',{'source':'trusttunnel','id':self.user,'channels':['telegram']}).status_code,422)
        self.assertEqual(self.job('config.send',{'source':'trusttunnel','id':999999,'channels':['email']}).status_code,404)
        self.assertEqual(self.job('config.send',{'source':'trusttunnel','id':self.user,'channels':['email']}).status_code,200)
        self.assertEqual(self.job('config.send',{'source':'trusttunnel','id':self.user,'channels':['email']}).status_code,429)
    def test_config_send_email_and_telegram_without_persisting_secrets(self):
        self.deliver_setup(chat=424242)
        calls=[]
        def fake_agent(op,data=None):
            calls.append((op,data))
            return {'hysteria_users':[]} if op=='snapshot' else {'message_id':1}
        sent=[]
        with patch.object(ui,'agent',side_effect=fake_agent),patch.object(ui.config_delivery,'smtp_send',side_effect=sent.append):
            r=self.job('config.send',{'source':'trusttunnel','id':self.user,'channels':['telegram','email']});self.assertEqual(r.status_code,200,r.text)
            ui.work_once()
        msg=sent[0];self.assertEqual(msg['To'],'test@example.invalid')
        files={part.get_filename():part.get_content() for part in msg.iter_attachments()}
        self.assertTrue(any(n.endswith('.toml') and b'delivered-secret' in v for n,v in files.items()))
        self.assertTrue(files['qr-1.png'].startswith(b'\x89PNG'))
        self.assertIn('tt://',msg.get_body().get_content())
        ops=[op for op,_ in calls if op.startswith('telegram')]
        self.assertEqual(ops.count('telegram.file'),2);self.assertIn('telegram.send',ops)
        self.assertTrue(all(d['chat_id']==424242 for op,d in calls if op.startswith('telegram')))
        with ui.connect() as c:
            job=c.execute("SELECT state,payload,result FROM jobs WHERE action='config.send'").fetchone()
            self.assertEqual(job['state'],'success',job['result'])
            stored=str(dict(job))+str(c.execute('SELECT * FROM audit').fetchall())
        self.assertNotIn('delivered-secret',stored);self.assertNotIn('tt://',stored)
    def test_config_send_partial_failure_is_not_retried_and_hides_errors(self):
        self.deliver_setup(chat=424242)
        def fake_agent(op,data=None):
            if op=='telegram.file':raise RuntimeError('upstream echoed delivered-secret')
            return {'hysteria_users':[]} if op=='snapshot' else {'message_id':1}
        with patch.object(ui,'agent',side_effect=fake_agent),patch.object(ui.config_delivery,'smtp_send') as smtp:
            self.job('config.send',{'source':'trusttunnel','id':self.user,'channels':['email','telegram']});ui.work_once()
            self.assertFalse(ui.work_once());smtp.assert_called_once()
        with ui.connect() as c:job=c.execute("SELECT state,result FROM jobs WHERE action='config.send'").fetchone()
        self.assertEqual(job['state'],'failed');self.assertIn('E-mail: принято',job['result']);self.assertIn('Telegram: ошибка',job['result'])
        self.assertNotIn('delivered-secret',job['result'])
    def test_config_send_refuses_blocked_or_keyless_users(self):
        db.set_settings({'smtp_host':'smtp.example.invalid'})
        with patch.object(ui.config_delivery,'smtp_send') as smtp:
            self.job('config.send',{'source':'trusttunnel','id':self.user,'channels':['email']});ui.work_once();smtp.assert_not_called()
        with ui.connect() as c:self.assertIn('нет действующих ключей',c.execute("SELECT result FROM jobs").fetchone()[0])
        hy={'id':7,'username':'blocked-user','deleted':1}
        with patch.object(ui,'agent',return_value={'hysteria_users':[hy]}),patch.object(ui.config_delivery,'smtp_send') as smtp:
            self.post('contacts',{'source':'hysteria','id':7,'email':'h@example.invalid'})
            self.job('config.send',{'source':'hysteria','id':7,'channels':['email']});ui.work_once();smtp.assert_not_called()
    def test_qr_png_is_valid_and_bounded(self):
        import struct,zlib
        png=ui.config_delivery.qr_png('hysteria2://secret@example.invalid:443/?sni=example.invalid#user')
        self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n'))
        width,height=struct.unpack('>II',png[16:24]);self.assertEqual(width,height)
        idat=png[png.index(b'IDAT')+4:png.index(b'IEND')-8];self.assertEqual(len(zlib.decompress(idat)),height*(width+1))
        self.assertIsNone(ui.config_delivery.qr_png('x'*5000))

    def test_validation_rejects_injection_and_nonexistent_contacts(self):
        self.assertEqual(self.job('system.shell',{'cmd':'id'}).status_code,422)
        self.assertEqual(self.job('trusttunnel.block',{'id':'1/../../'}).status_code,422)
        self.assertEqual(self.job('hysteria.create',{'username':'x; touch /tmp/foo'}).status_code,422)
        self.assertEqual(self.post('contacts',{'source':'trusttunnel','id':999999,'email':'x@y.invalid'}).status_code,404)

    def test_person_create_generates_every_account_and_links_contacts(self):
        snapshot={'hysteria_users':[],'amnezia_users':[],'cdn_users':[]}
        created=[]
        def fake_agent(op,data=None):
            if op=='snapshot':return snapshot
            created.append((op,data));return {'message':'ok','id':7}
        def fake_legacy(admin,path,data):
            if path=='users/create':db.create_user(data['email'],'unused')
            created.append((path,data.get('label')));return {'message':'ok'}
        with patch.object(ui,'agent',side_effect=fake_agent):
            r=self.job('person.create',{'nick':'Ivan','email':'','chat_id':42,'consent':True,'protocols':['cdn','trusttunnel','hysteria','amnezia']})
            self.assertEqual(r.status_code,200,r.text)
            with patch.object(ui,'legacy',side_effect=fake_legacy):ui.work_once()
        with ui.connect() as c:job=dict(c.execute('SELECT * FROM jobs').fetchone())
        self.assertEqual(job['state'],'success',job['result'])
        tt=db.get_user_by_email('ivan@onixus-rf.duckdns.org')
        self.assertIsNotNone(tt)
        self.assertIn(('hysteria.create',{'username':'ivan-vpn','days':365,'devices':3}),created)
        self.assertIn(('amnezia.create',{'username':'ivan'}),created)
        self.assertIn((f'users/{tt["id"]}/configs','Основной'),created)
        people=self.client.get('/console/api/state').json()['people']
        self.assertEqual(people[0]['nick'],'ivan')
        self.assertEqual(people[0]['accounts'],{'trusttunnel':tt['id'],'hysteria':7,'amnezia':7,'cdn':7})
        with ui.connect() as c:self.assertEqual(c.execute("SELECT chat_id,consent FROM contacts WHERE source='cdn'").fetchone()[:],(42,1))
        # The same nick, or a login already taken in a protocol, is refused before any job.
        self.assertEqual(self.job('person.create',{'nick':'ivan','protocols':['trusttunnel']}).status_code,409)
        snapshot['cdn_users']=[{'id':1,'username':'petr'}]
        with patch.object(ui,'agent',return_value=snapshot):
            r=self.job('person.create',{'nick':'petr','protocols':['cdn']})
        self.assertEqual(r.status_code,409);self.assertIn('CDN (petr)',r.json()['detail'])
        self.assertEqual(self.job('person.create',{'nick':'Bad Nick','protocols':['trusttunnel']}).status_code,422)
        self.assertEqual(self.job('person.create',{'nick':'okay','protocols':[]}).status_code,422)

    def test_person_partial_failure_keeps_created_accounts(self):
        def fake_agent(op,data=None):
            if op=='snapshot':return {'hysteria_users':[]}
            raise RuntimeError('H UI отклонил операцию')
        def fake_legacy(admin,path,data):
            if path=='users/create':db.create_user(data['email'],'unused')
            return {'message':'ok'}
        with patch.object(ui,'agent',side_effect=fake_agent):
            self.job('person.create',{'nick':'anna','email':'anna@example.invalid','protocols':['trusttunnel','hysteria']})
            with patch.object(ui,'legacy',side_effect=fake_legacy):ui.work_once()
        with ui.connect() as c:
            job=c.execute('SELECT * FROM jobs').fetchone()
            self.assertEqual(job['state'],'failed')
            self.assertIn('создан частично',job['result']);self.assertIn('H UI отклонил',job['result'])
            self.assertEqual([tuple(r) for r in c.execute('SELECT source FROM person_accounts')],[('trusttunnel',)])
        self.assertIsNotNone(db.get_user_by_email('anna@example.invalid'))

    def test_person_delete_removes_accounts_devices_and_card(self):
        with ui.connect() as c:pid=c.execute("INSERT INTO people(nick) VALUES('olga')").lastrowid
        ui.link(pid,'trusttunnel',self.user);ui.link(pid,'cdn',3)
        device=db.create_device(self.user,'phone',secrets.token_hex(32))
        calls=[]
        with patch.object(ui,'agent',side_effect=lambda op,data=None:calls.append((op,data)) or {'message':'ok'}),\
             patch.object(ui,'legacy',side_effect=lambda a,path,data:calls.append(path) or db.delete_user(self.user)) as legacy:
            self.job('person.delete',{'id':pid});ui.work_once()
        self.assertIn(('cdn.delete',{'id':3}),calls);self.assertIn(f'users/{self.user}/delete',calls)
        self.assertIsNone(db.get_user(self.user));self.assertIsNone(db.get_device(device))
        with ui.connect() as c:
            self.assertEqual(c.execute('SELECT state FROM jobs').fetchone()[0],'success')
            self.assertEqual(c.execute('SELECT COUNT(*) FROM people').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM contacts').fetchone()[0],0)

    def test_key_and_device_deletion(self):
        device=db.create_device(self.user,'phone',secrets.token_hex(32))
        bound=db.create_device_config(self.user,device,'device-key','x','device')
        plain=db.create_config(self.user,'plain-key','y','plain')
        for action,id in (('trusttunnel.key-delete',bound),('trusttunnel.key-delete',plain),('trusttunnel.device-delete',device)):
            self.assertEqual(self.job(action,{'id':id}).status_code,200)
        with patch.object(ui,'legacy',side_effect=lambda a,path,data:db.delete_config(plain) if path.startswith('configs/') else {'message':'ok'}):
            for _ in range(3):ui.work_once()
        with ui.connect() as c:states=[r[0] for r in c.execute('SELECT state FROM jobs ORDER BY rowid')]
        self.assertEqual(states,['failed','success','success'])
        self.assertIsNone(db.get_config(plain));self.assertIsNone(db.get_device(device));self.assertIsNone(db.get_config(bound))

    def test_device_enrollment_code_is_single_use_secret(self):
        db.set_settings({'portal_url':'https://vpn.example.invalid/'})
        r=self.post('enroll',{'id':self.user});self.assertEqual(r.status_code,200,r.text)
        link=r.json()['content'];code=link.split('#',1)[1]
        self.assertTrue(link.startswith('https://vpn.example.invalid/e#'))
        self.assertTrue(r.json()['qr_data_url'].startswith('data:image/svg+xml'))
        self.assertIn('server=https%3A%2F%2Fvpn.example.invalid#',r.json()['app_link'])
        with db.connect() as c:self.assertEqual(c.execute('SELECT code_hash FROM enroll_codes').fetchone()[0],security.hash_api_token(code))
        with ui.connect() as c:self.assertNotIn(code,str(c.execute('SELECT * FROM audit').fetchall()))
        with db.connect() as c:c.execute("UPDATE users SET status='blocked'")
        self.assertEqual(self.post('enroll',{'id':self.user}).status_code,409)

    def test_link_existing_account_to_person(self):
        self.post('contacts',{'source':'trusttunnel','id':self.user,'chat_id':5,'consent':True})
        r=self.post('people/link',{'source':'trusttunnel','user_id':self.user,'nick':'tester'});self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.post('people/link',{'source':'trusttunnel','user_id':self.user,'nick':'other'}).status_code,409)
        person=self.client.get('/console/api/state').json()['people'][0]
        self.assertEqual((person['email'],person['chat_id'],person['consent']),('test@example.invalid',5,1))
        self.assertEqual(self.post('people/contact',{'id':person['id'],'email':'new@example.invalid','consent':False}).status_code,200)
        with ui.connect() as c:self.assertEqual(tuple(c.execute('SELECT email,chat_id,consent FROM contacts').fetchone()),('new@example.invalid',None,0))
        self.assertEqual(self.post('people/unlink',{'source':'trusttunnel','user_id':self.user}).status_code,200)
        self.assertEqual(self.client.get('/console/api/state').json()['people'][0]['accounts'],{})

    def test_pending_revocation_survives_device_account_and_person_deletion(self):
        from app import rtrust_credentials as managed
        managed.init()
        for state in ('requested','pending','failed'):
            for action in ('trusttunnel.device-delete','trusttunnel.delete','person.delete'):
                with self.subTest(state=state,action=action):
                    uid=db.create_user(secrets.token_hex(8)+'@example.invalid','unused')
                    device=db.create_device(uid,'phone',secrets.token_hex(32))
                    cfg=db.create_device_config(uid,device,secrets.token_hex(8),'synthetic','phone')
                    operation=secrets.token_hex(16)
                    with db.connect() as c:
                        c.execute("UPDATE app_devices SET revoked_at=datetime('now') WHERE id=?",(device,))
                        c.execute("UPDATE configs SET revoked_at=datetime('now') WHERE id=?",(cfg,))
                        c.execute("INSERT INTO rtrust_credential_operations(id,device,owner,action,generation,state,requested) VALUES(?,?,?,'revoke',1,?,0)",(operation,device,uid,state))
                    with ui.connect() as c:pid=c.execute('INSERT INTO people(nick) VALUES(?)',('p'+secrets.token_hex(8),)).lastrowid
                    ui.link(pid,'trusttunnel',uid)
                    identifier=device if action=='trusttunnel.device-delete' else uid if action=='trusttunnel.delete' else pid
                    # Integration still owns revocation when provisioning is disabled.
                    with patch.dict(os.environ,RTRUST_MANAGED_CREDENTIALS='0'),patch.object(ui,'managed_device_revoke',side_effect=RuntimeError('endpoint pending')) as revoke,patch.object(ui,'legacy') as legacy:
                        with self.assertRaisesRegex(RuntimeError,'endpoint pending'):ui.perform(action,{'id':identifier},self.admin)
                        revoke.assert_called_once_with(self.admin,device)
                        legacy.assert_not_called()
                    self.assertIsNotNone(db.get_device(device));self.assertIsNotNone(db.get_user(uid));self.assertIsNotNone(db.get_config(cfg))
                    self.assertEqual(ui.person(pid)['accounts'],{'trusttunnel':uid})
                    with db.connect() as c:self.assertEqual(c.execute('SELECT state FROM rtrust_credential_operations WHERE id=?',(operation,)).fetchone()[0],state)
                    # Once the owner confirms application, normal deletion can finish.
                    with db.connect() as c:c.execute("UPDATE rtrust_credential_operations SET state='applied' WHERE id=?",(operation,))
                    with patch.object(ui,'managed_device_revoke',return_value={'message':'applied'}) as revoke,patch.object(ui,'legacy',side_effect=lambda *a:db.delete_user(uid)):
                        ui.perform(action,{'id':identifier},self.admin)
                        revoke.assert_called_once_with(self.admin,device)
                    self.assertIsNone(db.get_device(device));self.assertIsNone(db.get_config(cfg))
                    with db.connect() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM rtrust_credential_operations WHERE id=?',(operation,)).fetchone()[0],0)

    def test_deleting_revoked_shared_device_keeps_shared_key(self):
        from app import rtrust_credentials as managed
        managed.init()
        device=db.create_device(self.user,'shared-phone',secrets.token_hex(32))
        shared=db.create_config(self.user,'shared-key','synthetic','shared')
        db.revoke_device(device)
        with patch.object(ui,'managed_device_revoke',return_value={'message':'Shared and external credentials remain valid'}) as revoke:
            ui.perform('trusttunnel.device-delete',{'id':device},self.admin)
            revoke.assert_called_once_with(self.admin,device)
        self.assertIsNone(db.get_device(device));self.assertIsNotNone(db.get_config(shared))

    def test_people_migration_preserves_links_contacts_and_deleted_id_high_water(self):
        with ui.connect() as c:
            c.execute('DROP TABLE people')
            c.execute('CREATE TABLE people(id INTEGER PRIMARY KEY,nick TEXT NOT NULL UNIQUE COLLATE NOCASE,email TEXT,chat_id INTEGER,consent INTEGER NOT NULL DEFAULT 0,created TEXT DEFAULT CURRENT_TIMESTAMP)')
            c.execute("INSERT INTO people VALUES(7,'alice','alice@example.invalid',42,1,'original')")
            c.execute("INSERT INTO jobs(id,action,payload,state) VALUES('historical','person.delete',?, 'success')",(json.dumps({'id':41}),))
        ui.link(7,'trusttunnel',self.user)
        ui.init()
        self.assertEqual(ui.person(7),{'id':7,'nick':'alice','email':'alice@example.invalid','chat_id':42,'consent':1,'created':'original','accounts':{'trusttunnel':self.user}})
        with ui.connect() as c:
            self.assertEqual(tuple(c.execute('SELECT email,chat_id,consent FROM contacts').fetchone()),('alice@example.invalid',42,1))
            with self.assertRaises(ui.sqlite3.IntegrityError):c.execute("INSERT INTO people(nick) VALUES('ALICE')")
            new=c.execute("INSERT INTO people(nick) VALUES('bob')").lastrowid
        self.assertGreater(new,41)
        with ui.connect() as c:c.execute('DELETE FROM people')
        ui.init()
        with ui.connect() as c:after=c.execute("INSERT INTO people(nick) VALUES('carol')").lastrowid
        self.assertGreater(after,new)

    def test_stale_person_delete_cannot_target_a_new_person(self):
        old=self.post('people/link',{'source':'trusttunnel','user_id':self.user,'nick':'alice'}).json()['id']
        self.job('person.delete',{'id':old})
        with patch.object(ui,'legacy',side_effect=lambda *a:db.delete_user(self.user)):ui.work_once()
        replacement=db.create_user('bob@example.invalid','unused')
        new=self.post('people/link',{'source':'trusttunnel','user_id':replacement,'nick':'bob'}).json()['id']
        self.assertGreater(new,old)
        self.job('person.delete',{'id':old})
        with patch.object(ui,'legacy') as legacy:
            ui.work_once();legacy.assert_not_called()
        self.assertIsNotNone(db.get_user(replacement));self.assertEqual(ui.person(new)['accounts'],{'trusttunnel':replacement})
        self.assertEqual(self.post('people/contact',{'id':old,'email':'stale@example.invalid'}).status_code,404)

class AgentTests(unittest.TestCase):
    def test_fixed_allowlist(self):
        with self.assertRaises(agent.Rejected):agent.dispatch('system.shell',{'command':'id'})
    def test_rules_preserve_grammar(self):
        self.assertEqual(agent.validate_rules([{'target':'reserve','kind':'suffix','value':'hostkey.ru'}]),[('reserve','suffix:hostkey.ru')])
        for rule in [{'target':'root','kind':'suffix','value':'x.ru'},{'target':'local','kind':'suffix','value':'ru)\nlocal(all)'},{'target':'reserve','kind':'cidr','value':'10.0.0.1/8'},{'target':'local','kind':'geoip','value':'private'}]:
            with self.assertRaises(agent.Rejected):agent.validate_rules([rule])
    def test_feed_signature_hash_and_downgrade(self):
        root=Path(TMP.name)/secrets.token_hex(8);root.mkdir();key=Ed25519PrivateKey.generate();pub=root/'root.pub';pub.write_bytes(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
        def release(seq,data=b'installer'):
            p=root/str(seq)/'windows-x86_64';p.mkdir(parents=True);(p/'setup.exe').write_bytes(data)
            m={'schema':1,'sequence':seq,'version':'0.3.2','target':'windows-x86_64','min_ipc':1,'max_ipc':1,'published':int(time.time())-10,'expires':int(time.time())+3600,'url':f'https://onixus-rf.duckdns.org/rtrust/releases/{seq}/windows-x86_64/setup.exe','size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            raw=json.dumps(m).encode();env=json.dumps({'payload':base64.b64encode(raw).decode(),'signature':base64.b64encode(key.sign(raw)).decode()}).encode();(p/'manifest.json').write_bytes(env);return p,env
        p1,e1=release(1);p2,e2=release(2);active=root/'windows-x86_64';active.mkdir();(active/'latest.json').write_bytes(e1)
        with patch.object(agent,'FEED',root),patch.object(agent,'ROOT_KEY',pub),patch.object(agent,'PACKAGES',root/'backups'):
            agent.promote({'sequence':2});self.assertEqual((active/'latest.json').read_bytes(),e2)
            with self.assertRaises(agent.Rejected):agent.promote({'sequence':1})
            (p2/'setup.exe').write_bytes(b'bad-file!')
            with self.assertRaises(agent.Rejected):agent.verify_manifest(p2/'manifest.json',True)
            tampered=json.loads(e1);tampered['signature']=base64.b64encode(bytes(64)).decode();(p1/'manifest.json').write_text(json.dumps(tampered))
            with self.assertRaises(Exception):agent.verify_manifest(p1/'manifest.json',True)
    def test_limits_validation_and_api_mapping(self):
        with patch.object(agent,'account',return_value={'id':1,'username':'fixture'}),patch.object(agent,'hui') as hui:
            agent.dispatch('hysteria.update',{'id':1,'days':10,'devices':2,'quota_gb':5})
            self.assertEqual(hui.call_args.args[2]['quota'],5*1024**3)
            with self.assertRaises(agent.Rejected):agent.dispatch('hysteria.update',{'id':1,'days':0,'devices':2,'quota_gb':5})

    def test_route_probe_failure_restores_and_disarms_watchdog(self):
        from unittest.mock import MagicMock, mock_open
        prefix=['local(10.254.77.1, tcp/18082, 127.0.0.1)','local(10.254.77.1, tcp/8081, 127.0.0.1)','reject(geoip:private)']
        protected=['local(all, udp/53, 127.0.0.1)','local(all, tcp/53, 127.0.0.1)']
        old=json.dumps({'acl':{'inline':prefix+protected+['reserve(all)']}})
        m=MagicMock();m.get_config.return_value=old;m.probe_hysteria.side_effect=RuntimeError('probe failed')
        temp=Path(TMP.name)/secrets.token_hex(8);temp.mkdir();exits=temp/'exits.json'
        exits.write_text(json.dumps({'primary':{'outbound':{'name':'primary'},'expected_ip':'192.0.2.1'}}))
        with patch('builtins.open',mock_open()),patch.object(agent.fcntl,'flock'),patch.object(agent,'route_snapshot',return_value={'revision':'known'}),patch.object(agent,'module_switch',return_value=m),patch.object(agent,'EXITS',exits),patch.object(agent,'BACKUPS',temp/'backups'),patch.object(agent,'run') as run:
            with self.assertRaises(RuntimeError):agent.apply_routes({'exit':'primary','rules':[],'revision':'known'})
            changed=agent.yaml.safe_load(m.write_config.call_args.args[0])
            self.assertEqual(changed['acl']['inline'][:5],prefix+protected)
            m.restore.assert_called_once()
            self.assertEqual(m.restore.call_args.args[0].read_text(),old)
            self.assertTrue(any(c.args[0][0]=='systemd-run' for c in run.call_args_list))
            self.assertTrue(any(c.args[0][-1].endswith('.timer') for c in run.call_args_list))

    def test_route_revision_conflict_never_stops_service(self):
        from unittest.mock import mock_open
        with patch('builtins.open',mock_open()),patch.object(agent.fcntl,'flock'),patch.object(agent,'route_snapshot',return_value={'revision':'new'}),patch.object(agent,'run') as run:
            with self.assertRaises(agent.Rejected):agent.apply_routes({'exit':'primary','rules':[],'revision':'old'})
            run.assert_not_called()

    def test_telegram_file_validation_and_multipart(self):
        good={'chat_id':5,'kind':'photo','filename':'qr-1.png','data':base64.b64encode(b'\x89PNG\r\n\x1a\nrest').decode(),'caption':'phone'}
        with patch.object(agent,'telegram_call',return_value={'message_id':3}) as call:
            self.assertEqual(agent.dispatch('telegram.file',good),{'message_id':3})
            method,body,ctype=call.call_args[0]
            self.assertEqual(method,'sendPhoto');self.assertIn(b'filename="qr-1.png"',body);self.assertTrue(ctype.startswith('multipart/form-data; boundary='))
            for bad in [dict(good,kind='video'),dict(good,filename='../etc/passwd'),dict(good,filename='a"b.png'),dict(good,chat_id=-1),
                        dict(good,data='not base64!'),dict(good,data=base64.b64encode(b'GIF89a').decode()),
                        dict(good,kind='document',data=base64.b64encode(b'x'*(agent.TG_FILE_LIMIT+1)).decode())]:
                with self.assertRaises(agent.Rejected):agent.dispatch('telegram.file',bad)
            self.assertEqual(call.call_count,1)

if __name__=='__main__':unittest.main(verbosity=2)
