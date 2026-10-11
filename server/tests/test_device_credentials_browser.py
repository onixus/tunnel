"""Desktop/mobile browser: failed application is visible after device revocation."""
import os
import socket
import threading
import time
from unittest.mock import patch
import pytest
from playwright.sync_api import sync_playwright, expect
import uvicorn
from test_exchange import ExchangeTests
from app import endpoint

@pytest.mark.parametrize('viewport',[{'width':1280,'height':900},{'width':390,'height':844}])
def test_credential_browser(viewport):
    fixture=ExchangeTests();fixture.setUp();device,_=fixture.enrolled('Managed fixture')
    from app import db
    db.set_settings({'panel_domain':'vpn.example.invalid'})
    listener=socket.socket();listener.bind(('127.0.0.1',0))
    origin=f'http://127.0.0.1:{listener.getsockname()[1]}'
    server=uvicorn.Server(uvicorn.Config(fixture.client.app,log_level='error',lifespan='off'))
    with patch.dict(os.environ,RTRUST_MANAGED_CREDENTIALS='1'),patch.object(endpoint.manager,'reconcile'),patch.object(endpoint.manager,'_kill'),patch.object(endpoint.manager,'_is_running',return_value=False):
        thread=threading.Thread(target=lambda:server.run(sockets=[listener]),daemon=True);thread.start()
        try:
            deadline=time.monotonic()+5
            while not server.started:
                if time.monotonic()>deadline:raise RuntimeError('Test API did not start')
                time.sleep(.02)
            with sync_playwright() as p:
                browser=p.chromium.launch()
                try:
                    context=browser.new_context(viewport=viewport)
                    context.add_cookies([{'name':'user_token','value':fixture.client.cookies.get('user_token'),'url':origin}])
                    page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(origin+'/profiles')
                    # The private HTTP portal may lack secure-context randomUUID.
                    page.evaluate("Object.defineProperty(crypto,'randomUUID',{value:undefined})")
                    expect(page.locator('#devices')).to_contain_text('Managed fixture')
                    page.once('dialog',lambda d:d.accept())
                    page.get_by_role('button',name='Выдать отдельный VPN-пароль',exact=True).click()
                    expect(page.locator('#devices')).to_contain_text('Не применено')
                    expect(page.locator('#devices')).not_to_contain_text('Применено на endpoint')
                    page.once('dialog',lambda d:d.accept())
                    page.get_by_role('button',name='Отозвать устройство',exact=True).click()
                    expect(page.locator('#devices')).to_contain_text('отозвано')
                    expect(page.locator('#devices')).to_contain_text('Не применено')
                    expect(page.get_by_role('button',name='Повторить применение',exact=True)).to_be_visible()
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                    assert not errors,errors
                    context.close()
                finally:browser.close()
        finally:
            server.should_exit=True;thread.join(5);listener.close();fixture.client.close()
