"""Actual admin UI and grant API, with isolated identities and no live network."""
import os
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect
import test_console as fixture


def test_admin_can_grant_and_revoke_from_device_ui():
    case=fixture.ConsoleTests();case.setUp()
    try:
        _,device,_=case.grant_fixture()
        with sync_playwright() as playwright:
            options={'headless':True}
            if os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE'):
                options['executable_path']=os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE']
            browser=playwright.chromium.launch(**options)
            context=browser.new_context(viewport={'width':1280,'height':900})
            context.add_cookies([{'name':'admin_token','value':case.cookie,
                                 'domain':'onixus-rf.duckdns.org','path':'/','secure':True}])
            page=context.new_page();errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            def dispatch(route):
                request=route.request;parsed=urlsplit(request.url)
                assert parsed.hostname=='onixus-rf.duckdns.org'
                response=case.client.request(request.method,parsed.path+('?' + parsed.query if parsed.query else ''),
                    content=request.post_data_buffer,
                    headers={k:v for k,v in request.headers.items() if k not in {'host','content-length'}})
                route.fulfill(status=response.status_code,body=response.content,
                    headers={k:v for k,v in response.headers.items() if k not in {'content-length','content-encoding'}})
            page.route('**/*',dispatch)
            page.goto('https://onixus-rf.duckdns.org/console')
            page.wait_for_function('Boolean(state.devices?.length)')
            page.evaluate("navigate('keys')")
            page.get_by_role('button',name='Доступ к профилям',exact=True).click()
            expect(page.get_by_role('dialog')).to_contain_text('Approval profile')
            page.get_by_role('button',name='Дать доступ',exact=True).click()
            expect(page.get_by_role('button',name='Отозвать доступ',exact=True)).to_be_visible()
            with fixture.db.connect() as c:
                assert c.execute('SELECT COUNT(*) FROM rtrust_grants WHERE device=?',(device,)).fetchone()[0]==1
            page.get_by_role('button',name='Отозвать доступ',exact=True).click()
            expect(page.get_by_role('button',name='Дать доступ',exact=True)).to_be_visible()
            with fixture.db.connect() as c:
                assert c.execute('SELECT COUNT(*) FROM rtrust_grants WHERE device=?',(device,)).fetchone()[0]==0
            assert not errors
            browser.close()
    finally:
        case.doCleanups()
