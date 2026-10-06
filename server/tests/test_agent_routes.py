"""Admin policy precedence, CSRF, revision checks and device revocation."""
import hashlib
import hmac
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import test_exchange as fixture
from test_exchange import config, db, exchange, security


class AgentRouteTests(unittest.TestCase):
    setUp = fixture.ExchangeTests.setUp
    login = fixture.ExchangeTests.login
    post = fixture.ExchangeTests.post

    def admin(self):
        with db.connect() as c:
            identifier = c.execute('SELECT id FROM admins LIMIT 1').fetchone()[0]
        cookie = security.create_session_token(str(identifier), 'admin')
        self.client.cookies.set('admin_token', cookie)
        return {'x-csrf-token': hmac.new(config.SECRET_KEY.encode(), ('rtrust-admin-routes:'+cookie).encode(), hashlib.sha256).hexdigest()}

    def device(self, platform='linux'):
        code = self.post('enrollment-codes', {}).json()['code']
        result = self.post('enroll', {'code':code, 'name':'Test device', 'platform':platform}).json()
        return result['device_id'], {'Authorization':'Bearer '+result['token']}

    def create(self, headers):
        data = {'name':'Office','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':True}
        result = self.client.post('/admin/api/agent-routes/groups', json=data, headers=headers)
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()['id'], data

    def test_admin_authentication_csrf_and_assets(self):
        self.assertEqual(self.client.get('/admin/api/agent-routes').status_code,401)
        self.assertEqual(self.client.get('/admin/agent-routes',follow_redirects=False).status_code,302)
        headers = self.admin()
        page = self.client.get('/admin/agent-routes')
        self.assertEqual(page.status_code,200,page.text)
        self.assertIn('rtrust-admin-routes.js',page.text)
        self.assertEqual(page.headers['cache-control'],'no-store')
        self.assertEqual(self.client.get('/static/rtrust-admin-routes.js').status_code,200)
        self.assertEqual(self.client.post('/admin/api/agent-routes/groups',json={}).status_code,403)
        _, auth = self.device()
        self.assertEqual(self.client.get('/admin/api/agent-routes',headers=auth).status_code,403)
        self.create(headers)

    def test_assignment_precedence_revision_delivery_and_revoke(self):
        device, auth = self.device()
        own = self.post('route-groups',{'name':'User','include':['0.0.0.0/0'],'exclude':[],'exclude_lan':False}).json()
        self.assertEqual(self.post(f'route-groups/{own["id"]}/members',{'device_id':device,'member':True}).status_code,200)
        headers = self.admin(); group, data = self.create(headers)
        path=f'/admin/api/agent-routes/devices/{device}'
        self.assertEqual(self.client.put(path,json={'group_id':group,'previous_group_id':None},headers=headers).status_code,200)
        policy=self.client.get('/portal/v2/routing',headers=auth).json()['policy']
        self.assertEqual(policy['revision'],f'admin:{group}:1')
        self.assertEqual(self.client.put(path,json={'group_id':None,'previous_group_id':None},headers=headers).status_code,409)
        group_path=f'/admin/api/agent-routes/groups/{group}'
        self.assertEqual(self.client.put(group_path,json={**data,'revision':1},headers=headers).status_code,200)
        self.assertEqual(self.client.put(group_path,json={**data,'revision':1},headers=headers).status_code,409)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['revision'],f'admin:{group}:2')
        observed=self.client.get('/admin/api/agent-routes').json()['devices'][0]
        self.assertEqual(observed['fetched_revision'],f'admin:{group}:2')
        self.assertEqual(self.client.put(path,json={'group_id':None,'previous_group_id':group},headers=headers).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['group'],'User')
        self.client.put(path,json={'group_id':group,'previous_group_id':None},headers=headers)
        self.assertEqual(self.client.delete(f'/portal/v2/devices/{device}',headers=self.headers).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).status_code,401)
        with db.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM rtrust_admin_route_members').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM rtrust_route_delivery').fetchone()[0],0)

    def test_delete_restores_user_policy_and_rejects_mobile_or_inactive(self):
        device, auth=self.device(); mobile,_=self.device('android')
        headers=self.admin();group,_=self.create(headers)
        path='/admin/api/agent-routes/devices/'
        data={'group_id':group,'previous_group_id':None}
        self.assertEqual(self.client.put(path+str(mobile),json=data,headers=headers).status_code,422)
        with db.connect() as c:c.execute("UPDATE users SET status='blocked' WHERE id=?",(self.owner,))
        self.assertEqual(self.client.put(path+str(device),json=data,headers=headers).status_code,404)
        with db.connect() as c:c.execute("UPDATE users SET status='active' WHERE id=?",(self.owner,))
        self.assertEqual(self.client.put(path+str(device),json=data,headers=headers).status_code,200)
        self.assertEqual(self.client.delete(f'/admin/api/agent-routes/groups/{group}',headers={**headers,'If-Match':'99'}).status_code,409)
        self.assertEqual(self.client.delete(f'/admin/api/agent-routes/groups/{group}',headers={**headers,'If-Match':'1'}).status_code,200)
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json(),{'policy':None})
        with db.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM rtrust_admin_route_members').fetchone()[0],0)

    def test_user_group_recreation_rejects_stale_revision(self):
        data={'name':'Old','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':True}
        first=self.post('route-groups',data).json()
        path=f'/portal/v2/route-groups/{first["id"]}'
        self.assertEqual(self.client.delete(path,headers={**self.headers,'If-Match':'1'}).status_code,200)
        second=self.post('route-groups',{**data,'name':'Replacement'}).json()
        self.assertNotEqual(first['id'],second['id'],'Deleted group IDs must not be reused')
        self.assertEqual(self.client.put(path,json={**data,'revision':1},headers=self.headers).status_code,404)

    def test_legacy_counter_upgrade_preserves_memberships_and_deleted_ids(self):
        data={'name':'Legacy','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':True}
        group=self.post('route-groups',data).json()
        device,auth=self.device()
        self.post(f'route-groups/{group["id"]}/members',{'device_id':device,'member':True})
        with db.connect() as c:
            c.execute('DROP TABLE rtrust_route_counter')
            c.execute("INSERT INTO rtrust_audit(actor,action,object,created) VALUES('legacy','route_group_delete','500',1)")
        exchange.init();exchange.init()
        self.assertEqual(self.client.get('/portal/v2/routing',headers=auth).json()['policy']['revision'],f'{group["id"]}:1')
        replacement=self.post('route-groups',{**data,'name':'New'}).json()
        self.assertGreater(replacement['id'],500)
        with db.connect() as c:
            c.execute('INSERT INTO rtrust_route_groups(id,owner,name,policy,revision) VALUES(900,?,?,?,1)',(self.owner,'Old writer','{"include":["10.0.0.0/8"],"exclude":[],"exclude_lan":true}'))
        self.assertGreater(self.post('route-groups',data).json()['id'],900)

    def test_admin_enrollment_is_one_time_and_audited(self):
        headers=self.admin()
        response=self.client.post('/admin/api/agent-routes/enrollment-codes',json={'user_id':self.other},headers=headers)
        self.assertEqual(response.status_code,200,response.text)
        data={'code':response.json()['code'],'name':'Other device','platform':'windows'}
        enrolled=self.post('enroll',data)
        self.assertEqual(enrolled.status_code,200,enrolled.text)
        self.assertEqual(self.post('enroll',data).status_code,401)
        with db.connect() as c:
            self.assertEqual(c.execute('SELECT user_id FROM app_devices WHERE id=?',(enrolled.json()['device_id'],)).fetchone()[0],self.other)
            self.assertEqual(c.execute("SELECT count(*) FROM rtrust_audit WHERE action='admin_route_enroll'").fetchone()[0],1)


if __name__=='__main__': unittest.main()
