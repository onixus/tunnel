"""One ASGI event loop stays responsive while credential application fences SQL."""
import asyncio
import threading
import time
from unittest.mock import patch
import httpx
from test_exchange import ExchangeTests
from app import db, security, rtrust_profiles as exchange


def test_all_async_writer_categories_preserve_event_loop():
    fixture=ExchangeTests();fixture.setUp()
    try:
        device,_=fixture.enrolled()
        profile=fixture.imported();preview=fixture.preview();group=fixture.group()
        code=fixture.post('enrollment-codes',{}).json()['code']
        with db.connect() as c:admin=c.execute('SELECT id FROM admins LIMIT 1').fetchone()[0]
        cookie=security.create_session_token(str(admin),'admin')
        fixture.client.cookies.set('admin_token',cookie)
        from app import routes_admin, endpoint
        fixture.client.app.include_router(routes_admin.router)
        exchange.install_legacy_handlers(fixture.client.app)
        exchange.install_legacy_handlers(fixture.client.app)
        from starlette.requests import Request
        admin_headers={'X-CSRF-Token':exchange.admin_csrf(Request({'type':'http','headers':[(b'cookie',('admin_token='+cookie).encode())]}))}
        policy={'name':'Regression','include':['10.0.0.0/8'],'exclude':[],'exclude_lan':True}
        created=fixture.client.post('/admin/api/agent-routes/groups',json=policy,headers=admin_headers)
        admin_group=created.json()['id']
        cases=[
            ('POST','/portal/v2/enroll',{'code':code,'name':'New','platform':'linux'},fixture.headers),
            ('POST',f'/portal/v2/profiles/{profile["id"]}/export',{'format':'profile_json','revision':profile['revision'],'include_secrets':True},fixture.headers),
            ('POST','/portal/v2/profile-imports/preview',{'content':fixture.content,'intent':'external_stored'},fixture.headers),
            ('POST',f'/portal/v2/profile-imports/{preview}/commit',{'action':'create','consent':True},fixture.headers),
            ('POST',f'/portal/v2/profiles/{profile["id"]}/grants',{'device_id':device,'allow':True},fixture.headers),
            ('POST','/portal/v2/route-groups',policy,fixture.headers),
            ('PUT',f'/portal/v2/route-groups/{group["id"]}',{**policy,'revision':group['revision']},fixture.headers),
            ('POST',f'/portal/v2/route-groups/{group["id"]}/members',{'device_id':device,'member':True},fixture.headers),
            ('POST','/admin/api/agent-routes/enrollment-codes',{'user_id':fixture.owner},admin_headers),
            ('POST','/admin/api/agent-routes/groups',policy,admin_headers),
            ('PUT',f'/admin/api/agent-routes/groups/{admin_group}',{**policy,'revision':1},admin_headers),
            ('PUT',f'/admin/api/agent-routes/devices/{device}',{'group_id':admin_group,'previous_group_id':None},admin_headers),
            ('POST','/admin/settings',{'brand_name':'Updated'},admin_headers),
        ]
        @fixture.client.app.get('/regression-health')
        async def health():return {'ok':True}
        async def exercise():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture.client.app),base_url='http://testserver',cookies=fixture.client.cookies) as client:
                for method,path,payload,headers in cases:
                    held=threading.Event();release=threading.Event()
                    def fence():
                        with db.connect() as c:
                            c.execute('BEGIN IMMEDIATE');held.set()
                            if not release.wait(3):raise RuntimeError('Fence timeout')
                    thread=threading.Thread(target=fence);thread.start()
                    assert held.wait(2)
                    kwargs={'data':payload} if path=='/admin/settings' else {'json':payload}
                    task=asyncio.create_task(client.request(method,path,headers=headers,**kwargs))
                    try:
                        started=time.monotonic()
                        await asyncio.sleep(.05)
                        response=await client.get('/regression-health')
                        elapsed=time.monotonic()-started
                        assert response.status_code==200
                        assert elapsed<.5,(path,elapsed)
                        assert not task.done(),path
                    finally:
                        release.set()
                        await asyncio.to_thread(thread.join,3)
                    result=await task
                    assert result.status_code==(302 if path=='/admin/settings' else 200),(path,result.status_code,result.text)
        with patch.object(endpoint.manager,'apply_settings'):
            asyncio.run(exercise())
        assert db.get_setting('brand_name')=='Updated'
    finally:fixture.client.close()


def test_concurrent_grants_cannot_exceed_device_limit():
    from fastapi import HTTPException
    fixture=ExchangeTests();fixture.setUp()
    try:
        device,_=fixture.enrolled()
        fixture.seed_profiles(exchange.MAX_CLIENT_PROFILES-1,device)
        candidates=fixture.seed_profiles(2)
        # Both writers finish the capacity check before either inserts, unless
        # the transaction serializes them (then the barrier times out).
        barrier=threading.Barrier(2,timeout=1)
        original=exchange.require_device_capacity
        def paused(*args,**kwargs):
            original(*args,**kwargs)
            try:barrier.wait()
            except threading.BrokenBarrierError:pass
        context=(fixture.owner,'u:test',None)
        results=[]
        def grant(identifier):
            try:results.append(exchange._grant(identifier,None,{'device_id':device,'allow':True},context).status_code)
            except HTTPException as error:results.append(error.status_code)
        with patch.object(exchange,'require_device_capacity',paused):
            threads=[threading.Thread(target=grant,args=(i,)) for i in candidates]
            for t in threads:t.start()
            for t in threads:t.join(30)
        assert sorted(results)==[200,409],results
        with db.connect() as c:
            assert c.execute('SELECT count(*) FROM rtrust_grants WHERE device=?',(device,)).fetchone()[0]==exchange.MAX_CLIENT_PROFILES
    finally:
        fixture.client.close()
