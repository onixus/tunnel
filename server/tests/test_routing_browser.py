"""Real browser + repository assets, with a local fake API. No production access."""
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading

import pytest
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server/console'))
from routing_policy import PolicyError, initial_policy, make_plan
REV = 'a' * 64


def fixture_state():
    modes = initial_policy({'hysteria': 'primary', 'trusttunnel': 'direct'})
    services = [dict(id=k, title=t, actual_exit=e, desired_exit=e, configurable=True, reason='',
                     available_exits=['primary', 'reserve', 'direct'], drift=False, **modes['services'][k])
                for k, t, e in [('hysteria', 'Hysteria 2', 'primary'), ('trusttunnel', 'TrustTunnel / R-TrustTunnel', 'direct')]]
    return {'observed_at': '2026-10-01T16:22:00Z', 'jobs': [], 'audit': [], 'users': [{}, {}], 'keys': [{}, {}, {}, {}],
            'hysteria_users': [{}, {}], 'devices': [], 'smtp': True, 'services': {'hysteria': 'active', 'trusttunnel': 'running'},
            'updates': {'active_sequence': 6}, 'telegram': {'running': True}, 'adblock': {'running': True, 'dns_interception': True},
            'routing': {'selected': 'primary', 'host': 'direct', 'trusttunnel': 'direct', 'revision': REV,
                        'rules': ['local(10.254.77.1, tcp/18082, 127.0.0.1)', 'local(10.254.77.1, tcp/8081, 127.0.0.1)', 'reject(geoip:private)', 'primary(all)'],
                        'exits': [{'id': 'primary', 'name': 'primary', 'host': 'onixus.duckdns.org', 'via': '10.254.77.2:1080'},
                                  {'id': 'reserve', 'name': 'reserve', 'host': 'onixus-reverse.duckdns.org', 'via': '10.254.78.2:1080'}],
                        'policy': {'revision': REV, 'group_exit': 'primary', 'services': services}}}


def internal(data):
    p = data['routing']['policy']
    return {'revision': p['revision'], 'saved': {'schema': 1, 'group_exit': p['group_exit'],
            'services': {s['id']: {'mode': s['mode'], **({'exit': s['exit']} if s['mode'] == 'pinned' else {})} for s in p['services']}},
            'services': {s['id']: s for s in p['services']}}


@pytest.fixture
def site():
    box = {'state': fixture_state(), 'posts': [], 'lose_response': False}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def send(self, value, code=200, kind='application/json'):
            raw = json.dumps(value).encode() if kind == 'application/json' else value
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'")
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self):
            if self.path == '/console/api/state':
                return self.send(box['state'])
            if self.path in ('/console', '/console/'):
                return self.send((ROOT / 'server/console/templates/index.html').read_bytes().replace(b'{{ csrf }}', b'test-csrf'), kind='text/html')
            name = self.path.removeprefix('/console/static/')
            source = ROOT / 'server/console/static' / name
            # Optional compatibility assets for isolated extension development. CI uses repository files.
            if not source.exists() and os.environ.get('TUNNEL_LEGACY_ASSETS'):
                source = Path(os.environ['TUNNEL_LEGACY_ASSETS']) / name
            if source.is_file() and (name.startswith('apex/') and '..' not in name or name in ('console.js', 'console.css', 'routing-ui.js', 'routing.css', 'protocols-ui.js', 'protocols.css', 'config-export.js', 'config-export.css')):
                return self.send(source.read_bytes(), kind='text/javascript' if name.endswith('.js') else 'text/css' if name.endswith('.css') else 'font/ttf')
            self.send({'detail': 'not found'}, 404)
        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            box['posts'].append((self.path, deepcopy(data)))
            if self.path.endswith('/routing/preview'):
                try:
                    plan = make_plan(data, internal(box['state']))
                except PolicyError as e:
                    return self.send({'detail': str(e)}, 409)
                return self.send({k: plan[k] for k in ('changes', 'untouched', 'control_plane', 'revision')})
            if self.path.endswith('/routing/jobs'):
                key = data['request_id']
                if not any(j['id'] == key for j in box['state']['jobs']):
                    box['state']['jobs'].append({'id': key, 'action': 'routes.services', 'state': 'queued', 'created_at': '', 'result': '{}'})
                if box['lose_response']:
                    box['lose_response'] = False
                    return self.send({'detail': 'Ответ потерян'}, 503)
                return self.send({'id': key, 'state': 'queued'})
            self.send({'detail': 'unexpected request'}, 404)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    box['url'] = f'http://127.0.0.1:{server.server_port}/console/'
    yield box
    server.shutdown()
    server.server_close()


@pytest.fixture
def browser_page(site):
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH'), headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 1080}, locale='ru-RU')
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        yield page
        browser.close()
        assert errors == []


def visit(page, site):
    page.goto(site['url'])
    expect(page.locator('[data-exit-node="reserve"]')).to_be_visible()


def choose(page):
    page.locator('[data-exit-node="reserve"]').click()
    page.locator('#map-route-form [type=submit]').click()
    expect(page.locator('#confirm-service-routes')).to_be_visible()


def queued(site):
    return [p for path, p in site['posts'] if path.endswith('/routing/jobs')]


def test_cancel_never_mutates(browser_page, site):
    page = browser_page
    visit(page, site)
    page.locator('[data-exit-node="reserve"]').click()
    page.keyboard.press('Escape')
    assert not queued(site)
    assert not site['posts']
    expect(page.locator('[data-service-node="hysteria"]')).to_have_attribute('data-route', 'primary')


def test_selected_services_and_explicit_confirmation(browser_page, site):
    page = browser_page
    visit(page, site)
    page.locator('[data-exit-node="reserve"]').click()
    page.locator('input[value=hysteria]').uncheck()
    page.locator('input[value=trusttunnel]').check()
    page.locator('#map-route-form [type=submit]').click()
    expect(page.locator('#confirm-service-routes')).to_be_visible()
    assert not queued(site)
    page.locator('#confirm-service-routes').click()
    expect(page.locator('#modal')).not_to_be_visible()
    assert len(queued(site)) == 1
    assert queued(site)[0]['data']['services'] == {'hysteria': {'mode': 'pinned', 'exit': 'primary'}, 'trusttunnel': {'mode': 'follow'}}
    expect(page.locator('[data-service-node="trusttunnel"]')).to_have_attribute('data-route', 'direct')
    expect(page.locator('[data-exit-node="primary"]')).to_be_disabled()


def test_independent_route(browser_page, site):
    page = browser_page
    visit(page, site)
    page.locator('[data-service-node="trusttunnel"]').click()
    page.locator('#service-route-form .service-mode').select_option('pinned')
    page.locator('#service-route-form .service-exit').select_option('reserve')
    page.locator('#service-route-form [type=submit]').click()
    expect(page.locator('#confirm-service-routes')).to_be_visible()
    page.locator('#confirm-service-routes').click()
    expect(page.locator('#modal')).not_to_be_visible()
    assert queued(site)[0]['data'] == {'revision': REV, 'group_exit': 'primary', 'services': {'trusttunnel': {'mode': 'pinned', 'exit': 'reserve'}}}


def test_settings_do_not_reconcile_excluded_drift(browser_page, site):
    site['state']['routing']['policy']['services'][1].update(mode='pinned', exit='reserve', actual_exit='primary', desired_exit='reserve', drift=True)
    page = browser_page
    visit(page, site)
    page.locator('nav [data-page=routing]').click()
    page.locator('#group-exit').select_option('reserve')
    page.locator('[data-action=route-settings]').click()
    expect(page.locator('#confirm-service-routes')).to_be_visible()
    assert site['posts'][-1][1]['services'] == {}
    expect(page.locator('#modal-body')).to_contain_text('TrustTunnel / R-TrustTunnel: Основной')


def test_displayed_revision_is_preserved(browser_page, site):
    page = browser_page
    visit(page, site)
    page.locator('nav [data-page=routing]').click()
    site['state']['routing']['policy']['revision'] = 'b' * 64
    page.evaluate("state.routing.policy.revision='b'.repeat(64)")
    page.locator('#group-exit').select_option('reserve')
    page.locator('[data-action=route-settings]').click()
    expect(page.locator('#notice')).to_contain_text('Маршруты изменились')
    assert site['posts'][-1][1]['revision'] == REV
    assert not queued(site)


def test_lost_response_retry_reuses_idempotency_key(browser_page, site):
    page = browser_page
    site['lose_response'] = True
    visit(page, site)
    choose(page)
    page.locator('#confirm-service-routes').click()
    expect(page.locator('#modal-body .route-error')).to_contain_text('Ответ потерян')
    page.locator('#confirm-service-routes').click()
    expect(page.locator('#modal')).not_to_be_visible()
    assert len(queued(site)) == 2
    assert queued(site)[0]['request_id'] == queued(site)[1]['request_id']
    assert len(site['state']['jobs']) == 1


def test_pending_recovery_disables_switches(browser_page, site):
    site['state']['routing']['pending'] = True
    visit(browser_page, site)
    expect(browser_page.locator('[data-exit-node=reserve]')).to_be_disabled()
    assert not site['posts']


def test_escape_hosts_and_responsive_screenshots(browser_page, site):
    page = browser_page
    visit(page, site)
    path = Path(os.environ.get('ROUTING_ARTIFACTS', 'test-results/routing'))
    path.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(path / 'desktop.png'), full_page=True)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path=str(path / 'mobile.png'), full_page=True)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    site['state']['routing']['exits'][1]['host'] = '<img src=x onerror="window.bad=1">'
    page.reload()
    expect(page.locator('[data-exit-node=reserve]')).to_contain_text('<img')
    assert page.locator('.network-board img').count() == 0
    assert page.evaluate('window.bad || 0') == 0


@pytest.mark.parametrize('replacement', [False, True])
def test_cancelled_preview_cannot_reopen_or_replace_dialog(browser_page, site, replacement):
    page = browser_page
    visit(page, site)
    pending = []
    page.route('**/console/api/routing/preview', lambda route: pending.append(route))
    page.locator('[data-exit-node="reserve"]').click()
    page.locator('#map-route-form [type=submit]').click()
    expect(page.locator('#map-route-form [type=submit]')).to_be_disabled()
    page.keyboard.press('Escape')
    if replacement:
        page.locator('[data-service-node="trusttunnel"]').click()
        expect(page.locator('#service-route-form')).to_be_visible()
    assert len(pending) == 1
    plan = make_plan(pending[0].request.post_data_json, internal(site['state']))
    pending[0].fulfill(json=plan)
    # Flush the delivered fetch response and rendering before checking absence.
    page.wait_for_timeout(200)
    expect(page.locator('#confirm-service-routes')).to_have_count(0)
    if replacement:
        expect(page.locator('#service-route-form')).to_be_visible()
    else:
        expect(page.locator('#modal')).not_to_be_visible()
    assert not queued(site)
