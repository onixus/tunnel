"""Real console assets, CSP, export endpoint and QR renderer; fake VPN boundary.

Playwright routes the fixture origin into TestClient, so neither a live server
nor external network access is needed. QR decoding is not a VPN connection test.
"""
import os
from pathlib import Path
import types
from urllib.parse import urlsplit

import cv2
import numpy as np
import pytest
from playwright.sync_api import sync_playwright, expect

from test_config_qr import api, HY, TT


@pytest.fixture
def browser(api):
    api.ui.agent.side_effect = lambda op, data=None: {'content': HY} if op == 'hysteria.export' else {
        'hysteria_users': [{'id': 7, 'username': 'hysteria-fixture', 'deleted': 0,
                           'download': 0, 'upload': 0, 'expire_time': 1900000000000}],
    }
    with sync_playwright() as playwright:
        options = {'headless': True}
        if os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE'):
            options['executable_path'] = os.environ['PLAYWRIGHT_CHROMIUM_EXECUTABLE']
        instance = playwright.chromium.launch(**options)
        context = instance.new_context(viewport={'width': 1440, 'height': 1050})
        context.add_cookies([{'name': 'admin_token', 'value': 'test-admin',
                             'domain': 'console.example.invalid', 'path': '/', 'secure': True}])
        page = context.new_page()
        page.set_default_timeout(5000)
        errors, requests, pending, external = [], [], [], []
        state = types.SimpleNamespace(hold=False, fail=False)
        page.on('pageerror', lambda error: errors.append(str(error)))
        def fulfill(route):
            request = route.request
            parsed = urlsplit(request.url)
            response = api.client.request(request.method, parsed.path,
                content=request.post_data_buffer,
                headers={k: v for k, v in request.headers.items() if k not in {'host', 'content-length'}})
            route.fulfill(status=response.status_code, body=response.content,
                          headers={k: v for k, v in response.headers.items() if k not in {'content-length', 'content-encoding'}})
        def dispatch(route):
            request = route.request
            parsed = urlsplit(request.url)
            if parsed.netloc != 'console.example.invalid':
                external.append(request.url)
                route.abort()
                return
            if parsed.path == '/console/api/export':
                requests.append(request.post_data_json)
                if state.hold:
                    pending.append(route)
                    return
                if state.fail:
                    route.fulfill(status=503, json={'detail': 'Временная ошибка экспорта'})
                    return
            fulfill(route)
        page.route('**/*', dispatch)
        page.goto('https://console.example.invalid/console/')
        expect(page.locator('h1')).to_be_visible()
        yield types.SimpleNamespace(page=page, context=context, requests=requests,
                                    pending=pending, fulfill=fulfill, state=state, api=api)
        context.close()
        instance.close()
        assert not errors
        assert not external


def open_qr(browser, source='trusttunnel'):
    page = browser.page
    page.locator(f'[data-page="{"keys" if source == "trusttunnel" else "users"}"]').click()
    page.locator(f'[data-action="export-qr"][data-source="{source}"][data-id="7"]').click()
    expect(page.locator('#reveal')).to_be_visible()


@pytest.mark.parametrize('source,content', [('trusttunnel', TT), ('hysteria', HY)])
def test_visible_qr_button_consent_decode_and_download(browser, source, content):
    page = browser.page
    open_qr(browser, source)
    assert not browser.requests
    page.locator('#modal [aria-label="Закрыть"]').click()
    assert not browser.requests
    open_qr(browser, source)
    page.locator('#reveal').click()
    image = page.locator('.config-qr-image')
    expect(image).to_be_visible()
    assert browser.requests == [{'source': source, 'id': 7, 'consent': True, 'qr': True}]
    pixels = cv2.imdecode(np.frombuffer(image.screenshot(), np.uint8), cv2.IMREAD_COLOR)
    assert cv2.QRCodeDetector().detectAndDecode(pixels)[0] == content
    output = Path('test-results/config-qr')
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(output / (source + '-desktop.png')))
    with page.expect_download() as download:
        page.locator('#download-qr').click()
    assert download.value.suggested_filename == source + '-7.svg'
    assert b'<svg' in Path(download.value.path()).read_bytes()
    page.locator('#show-link').click()
    expect(page.locator('#secret')).to_have_text(content)
    with page.expect_download() as download:
        page.locator('#download').click()
    assert Path(download.value.path()).read_text() == content
    page.keyboard.press('Escape')
    expect(page.locator('#modal-body')).to_be_empty()
    assert 'fixture-secret' not in page.content()
    assert 'qr_data_url' not in page.evaluate('JSON.stringify(state)')


def test_revoked_key_has_no_qr_button(browser):
    browser.page.locator('[data-page="keys"]').click()
    expect(browser.page.locator('[data-action="export-qr"]')).to_have_count(1)
    expect(browser.page.locator('[data-action="export-qr"][data-id="8"]')).to_have_count(0)


def test_old_response_cannot_reveal_key_in_new_dialog(browser):
    browser.state.hold = True
    open_qr(browser)
    browser.page.locator('#reveal').click()
    expect(browser.page.locator('#reveal')).to_be_disabled()
    assert len(browser.pending) == 1
    browser.page.keyboard.press('Escape')
    open_qr(browser, 'hysteria')
    browser.fulfill(browser.pending.pop())
    browser.page.wait_for_timeout(80)
    expect(browser.page.locator('#reveal')).to_be_visible()
    expect(browser.page.locator('#secret')).to_have_count(0)
    assert 'fixture-secret' not in browser.page.content()


def test_duplicate_reveal_is_disabled(browser):
    browser.state.hold = True
    open_qr(browser)
    browser.page.locator('#reveal').click()
    browser.page.locator('#reveal').evaluate('(button) => button.click()')
    assert len(browser.requests) == 1 and len(browser.pending) == 1
    browser.fulfill(browser.pending.pop())
    expect(browser.page.locator('.config-qr-image')).to_be_visible()


def test_error_allows_retry_without_disclosing_secret(browser):
    browser.state.fail = True
    open_qr(browser)
    browser.page.locator('#reveal').click()
    expect(browser.page.locator('.export-status')).to_have_text('Временная ошибка экспорта')
    expect(browser.page.locator('#reveal')).to_be_enabled()
    assert 'fixture-secret' not in browser.page.content()
    browser.state.fail = False
    browser.page.locator('#reveal').click()
    expect(browser.page.locator('.config-qr-image')).to_be_visible()


def test_oversized_profile_preserves_complete_download(browser):
    content = 'tt://?' + 'x' * 4000
    browser.api.profiles.codec.return_value = {'content': content}
    open_qr(browser)
    browser.page.locator('#reveal').click()
    expect(browser.page.locator('.qr-error')).to_contain_text('не помещается')
    expect(browser.page.locator('#download-qr')).to_be_disabled()
    expect(browser.page.locator('.config-qr-image')).not_to_be_visible()
    with browser.page.expect_download() as download:
        browser.page.locator('#download').click()
    assert Path(download.value.path()).read_text() == content


def test_copy_and_clipboard_denial_fallback(browser):
    open_qr(browser)
    browser.page.locator('#reveal').click()
    expect(browser.page.locator('#copy-config')).to_be_visible()
    browser.page.evaluate("Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async(value)=>{window.testCopied=value}}})")
    browser.page.locator('#copy-config').click()
    expect(browser.page.locator('.export-status')).to_have_text('Ссылка скопирована.')
    assert browser.page.evaluate('window.testCopied') == TT
    browser.page.evaluate("Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async()=>{throw Error('denied')}}})")
    browser.page.locator('#copy-config').click()
    expect(browser.page.locator('.export-status')).to_contain_text('скопируйте её вручную')
    assert browser.page.evaluate('window.getSelection().toString()') == TT


def test_export_text_is_not_interpreted_as_html(browser):
    content = TT + '<img src=x onerror="window.injected=true">'
    browser.api.profiles.codec.return_value = {'content': content}
    open_qr(browser)
    browser.page.locator('#reveal').click()
    browser.page.locator('#show-link').click()
    expect(browser.page.locator('#secret')).to_have_text(content)
    assert browser.page.evaluate('window.injected') is None
    expect(browser.page.locator('#secret img')).to_have_count(0)


def test_mobile_qr_fits_dialog_and_can_be_decoded(browser):
    page = browser.page
    page.set_viewport_size({'width': 390, 'height': 844})
    open_qr(browser, 'hysteria')
    page.locator('#reveal').click()
    image = page.locator('.config-qr-image')
    expect(image).to_be_visible()
    bounds = image.bounding_box()
    assert bounds['x'] >= 0 and bounds['x'] + bounds['width'] <= 390
    pixels = cv2.imdecode(np.frombuffer(image.screenshot(), np.uint8), cv2.IMREAD_COLOR)
    assert cv2.QRCodeDetector().detectAndDecode(pixels)[0] == HY
    output = Path('test-results/config-qr')
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(output / 'hysteria-mobile.png'))
