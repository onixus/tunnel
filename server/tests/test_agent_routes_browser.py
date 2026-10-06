"""Browser and real isolated API: create, assign, cancel, edit and delete."""
from pathlib import Path
import socket
import sys
import threading
import time

import pytest
from playwright.sync_api import sync_playwright, expect
import uvicorn

sys.path.insert(0,str(Path(__file__).parent))
import test_agent_routes as api_tests


@pytest.mark.parametrize('viewport', [{'width':1280,'height':900},{'width':390,'height':844}])
def test_route_admin_browser(viewport):
    fixture=api_tests.AgentRouteTests()
    fixture.setUp()
    device,auth=fixture.device()
    fixture.admin()
    listener=socket.socket(); listener.bind(('127.0.0.1',0))
    origin=f'http://127.0.0.1:{listener.getsockname()[1]}'
    server=uvicorn.Server(uvicorn.Config(fixture.client.app,log_level='error',lifespan='off'))
    thread=threading.Thread(target=lambda:server.run(sockets=[listener]),daemon=True);thread.start()
    try:
        deadline=time.monotonic()+5
        while not server.started:
            if not thread.is_alive() or time.monotonic()>deadline:raise RuntimeError('Test API did not start')
            time.sleep(.02)
        with sync_playwright() as p:
            browser=p.chromium.launch()
            try:
                context=browser.new_context(viewport=viewport)
                context.add_cookies([{'name':'admin_token','value':fixture.client.cookies.get('admin_token'),'url':origin}])
                page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(origin+'/admin/agent-routes')
                expect(page.locator('#devices')).to_contain_text('Test device')
                page.locator('#name').fill('Office <script>')
                page.locator('#include').fill('10.0.0.0/8')
                page.get_by_role('button',name='Сохранить',exact=True).click()
                expect(page.locator('#groups')).to_contain_text('Office <script>')
                assert page.locator('#groups script').count()==0
                groups=fixture.client.get('/admin/api/agent-routes').json()['groups'];group=groups[0]['id']
                page.once('dialog',lambda dialog:dialog.dismiss())
                page.locator('#devices select').select_option(str(group))
                expect(page.locator('#devices select')).to_have_value('')
                assert fixture.client.get('/portal/v2/routing',headers=auth).json()['policy'] is None
                page.once('dialog',lambda dialog:dialog.accept())
                page.locator('#devices select').select_option(str(group))
                expect(page.locator('#status')).to_contain_text('Сохранено')
                expect(page.locator('#devices select')).to_have_value(str(group))
                assert fixture.client.get('/portal/v2/routing',headers=auth).json()['policy']['revision']==f'admin:{group}:1'
                page.get_by_role('button',name='Редактировать',exact=True).click()
                page.locator('#include').fill('192.168.10.0/24')
                page.get_by_role('button',name='Сохранить',exact=True).click()
                expect(page.locator('#groups')).to_contain_text('ревизия 2')
                page.get_by_role('button',name='Обновить',exact=True).click()
                expect(page.locator('#devices')).to_contain_text(f'admin:{group}:1')
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                page.once('dialog',lambda dialog:dialog.accept())
                page.get_by_role('button',name='Удалить',exact=True).click()
                expect(page.locator('#groups .row')).to_have_count(0)
                assert fixture.client.get('/portal/v2/routing',headers=auth).json()['policy'] is None
                assert not errors,errors
                context.close()
            finally:browser.close()
    finally:
        server.should_exit=True;thread.join(timeout=5);listener.close();fixture.client.close()
