"""APEX contract and isolated browser QA; only synthetic users/configurations."""
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
import importlib.util
import json
import os
import re
import subprocess

import pytest
from jinja2 import Environment, FileSystemLoader, ChainableUndefined
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
DS = ROOT / 'server/design-system'
OUT = ROOT / 'test-results/design-system'
BASELINE = os.environ.get('DS_BASELINE') == '1'


def test_vendored_assets_and_component_colors():
    spec = importlib.util.spec_from_file_location('sync_ds', ROOT / 'scripts/sync-design-system.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.sync(check=True)
    import hashlib
    for line in (DS / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ')
        assert hashlib.sha256((DS / name).read_bytes()).hexdigest() == digest
    for folder in ['server/design-system', 'server/console/static', 'server/upstream/app/static', 'server/upstream/app/templates',
                   'server/overlay/app/static', 'server/overlay/app/templates']:
        for path in (ROOT / folder).rglob('*'):
            if path.suffix not in ('.css', '.js', '.html') or 'apex' in path.parts or path.name == 'tokens.css':
                continue
            source = path.read_text()
            assert not re.search(r'#[0-9a-fA-F]{3,8}\b|rgba?\(|(?:slate|gray)-\d', source), path
            assert 'fonts.googleapis.com' not in source, path
            assert not re.search(r'font-size:\s*10(?:\.\d+)?px', source), path


def source(path):
    if BASELINE:
        return subprocess.check_output(['git', 'show', 'cf61422:' + str(path.relative_to(ROOT))], cwd=ROOT)
    return path.read_bytes()


def render_portal(name):
    env = Environment(loader=FileSystemLoader(ROOT / 'server/upstream/app/templates'), undefined=ChainableUndefined, autoescape=True)
    if BASELINE:
        from jinja2 import DictLoader
        env.loader = DictLoader({p.name: source(p).decode() for p in (ROOT / 'server/upstream/app/templates').glob('*.html')})
    user = dict(id=1, email='operator@example.invalid', status='active', created_at='2026-10-22', recovery_email='operator@example.invalid', is_superadmin=True)
    request = SimpleNamespace(cookies={'admin_token': 'fixture', 'user_token': 'fixture'} if name != 'admin_login.html' else {}, url=SimpleNamespace(path='/admin/' + name.removeprefix('admin_').removesuffix('.html')))
    config = dict(id=1, label='Рабочее устройство', address='vpn.example.invalid', port=443, domain='vpn.example.invalid', sni='vpn.example.invalid', username='synthetic', password='not-a-real-secret', protocol='HTTP/2', show_address=True, show_port=True, show_domain=True, show_sni=True, show_username=True, show_password=True, show_protocol=True, created_at='2026-10-22', user_id=1, user_email='operator@example.invalid', tt_username='synthetic')
    return env.get_template(name).render(brand='ONIXUS', request=request, csrf='synthetic', user=user, admin=user,
        users=[user], admins=[user], configs=[config], devices=[], counts={'users': 12, 'configs': 24, 'blocked': 0},
        status={'running': True, 'cert_present': True, 'domain': 'vpn.example.invalid', 'port': 443},
        s={'brand_name': 'ONIXUS', 'cert_mode': 'external', 'conn_port': '443'}, cert_domains=[], cert_dir='/certs',
        registration_enabled=True, smtp_enabled=True, msg='', err='', token='synthetic', qr_svg='', ttl=180, link='https://design.example.invalid/enroll#synthetic', app_link='trusttunnel://synthetic', endpoint_ready=True,
        windows_available=True, android_available=True, android_sha256='a'*64, windows_version='0.6.2', android_version='0.6.2').encode()


@pytest.fixture
def page():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, executable_path=os.environ.get('CHROMIUM_PATH'))
        context = browser.new_context(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce', color_scheme='dark')
        context.add_init_script("try { if (!localStorage.getItem('apex.theme')) localStorage.setItem('apex.theme', 'dark'); } catch (_) {}")
        pg = context.new_page()
        errors, external, missing = [], [], []
        pg.on('pageerror', lambda e: errors.append(str(e)))
        def route(req):
            path = urlsplit(req.request.url).path
            if urlsplit(req.request.url).hostname != 'design.example.invalid':
                external.append(req.request.url)
                return req.abort()
            if path == '/console/api/state':
                from test_routing_browser import fixture_state
                return req.fulfill(json=fixture_state())
            if path == '/console/':
                return req.fulfill(body=source(ROOT / 'server/console/templates/index.html').replace(b'{{ csrf }}', b'synthetic'), content_type='text/html', headers={'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:"})
            if path.startswith('/portal/v2/') or path == '/admin/api/agent-routes':
                return req.fulfill(json={'profiles': [], 'devices': [], 'groups': [], 'users': [], 'managed_credentials': {'enabled': False}})
            if path.startswith('/overlay/'):
                env = Environment(loader=FileSystemLoader(ROOT / 'server/overlay/app/templates'), autoescape=True)
                html = env.get_template(path.rsplit('/', 1)[-1]).render(csrf='synthetic', brand='ONIXUS', user={'email': 'operator@example.invalid'})
                return req.fulfill(body=html, content_type='text/html')
            if path.startswith('/screen/'):

                return req.fulfill(body=render_portal(path.rsplit('/', 1)[-1]), content_type='text/html')
            for prefix, folder in [('/console/static/', 'server/console/static'), ('/static/', 'server/upstream/app/static'), ('/static/', 'server/overlay/app/static')]:
                if path.startswith(prefix):
                    file = ROOT / folder / path.removeprefix(prefix)
                    if file.is_file():
                        return req.fulfill(body=source(file), content_type='text/css' if file.suffix == '.css' else 'text/javascript' if file.suffix == '.js' else 'font/ttf')
            missing.append(path)
            req.fulfill(status=404)
        pg.route('**/*', route)
        yield pg
        browser.close()
        assert errors == []
        if not BASELINE:
            assert external == []
        assert missing == []


def screenshot(page, name):
    OUT.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(OUT / (( 'before-' if BASELINE else '') + name + '.png')), full_page=True)


def theme(page, value):
    if BASELINE:
        page.evaluate('(v) => document.documentElement.dataset.theme = v', value)
    else:
        page.locator('[data-theme-switch]').select_option(value)
        expect(page.locator('html')).to_have_attribute('data-theme', value)
        assert page.evaluate("document.documentElement.classList.contains('dark')") == (value == 'dark')


@pytest.mark.parametrize('mode', ['dark', 'light'])
def test_console_screens(page, mode):
    page.goto('https://design.example.invalid/console/')
    expect(page.locator('#content h1')).to_be_visible()
    theme(page, mode)
    for name in ['overview', 'users', 'keys', 'routing', 'protocols', 'updates', 'campaigns', 'telegram', 'audit']:
        page.locator(f'nav [data-page={name}]').click()
        expect(page.locator('#content h1')).to_be_visible()
        assert BASELINE or page.locator('#content .primary').count() <= 1
        screenshot(page, f'console-{name}-{mode}')
        assert_contrast(page)
    if not BASELINE:
        assert page.locator('aside').bounding_box()['width'] == 240
        assert page.locator('header').bounding_box()['height'] == 56
    page.set_viewport_size({'width': 390, 'height': 844})
    page.locator('nav [data-page=overview]').click()
    screenshot(page, f'console-mobile-{mode}')
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


@pytest.mark.parametrize('mode', ['dark', 'light'])
def test_portal_screens(page, mode):
    for name in ['admin_dashboard', 'admin_login', 'admin_users', 'admin_user_detail', 'admin_admins', 'admin_configs', 'admin_settings',
                 'login', 'register', 'forgot', 'reset', 'connect', 'dashboard', 'device_qr', 'enroll_landing']:
        page.goto('https://design.example.invalid/screen/' + name + '.html')
        theme(page, mode)
        screenshot(page, f'portal-{name}-{mode}')
        assert_contrast(page)
        if not BASELINE:
            assert page.locator('.primary:visible').count() <= 1
            assert page.evaluate("document.fonts.check('14px Inter')")
    page.goto('https://design.example.invalid/screen/dashboard.html')
    theme(page, mode)
    page.set_viewport_size({'width': 390, 'height': 844})
    screenshot(page, f'portal-mobile-{mode}')
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


def test_theme_lifecycle_and_contrast(page):
    page.goto('https://design.example.invalid/console/')
    theme(page, 'light')
    assert page.evaluate("localStorage.getItem('apex.theme')") == 'light'
    page.reload()
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')
    page.locator('[data-theme-switch]').select_option('system')
    page.emulate_media(color_scheme='light')
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')
    page.emulate_media(color_scheme='dark')
    expect(page.locator('html')).to_have_attribute('data-theme', 'dark')
    # Browser resolves color-mix, aliases and inherited theme values for actual backgrounds.
    for mode in ['dark', 'light']:
        theme(page, mode)
        page.locator('#content').evaluate('''e => e.insertAdjacentHTML('beforeend', `<div class="card"><span class="pill">Активно</span><span class="pill warn">Ожидание</span><span class="pill red">Ошибка</span><span class="pill blue">Выполняется</span><span class="pill gray">Нет данных</span><p class="note warn">Предупреждение</p><p class="note error">Ошибка</p><span class="sev-critical">Critical</span><span class="sev-high">High</span><span class="sev-medium">Medium</span><span class="sev-low">Low</span><span class="sev-info">Info</span></div>`)''')
        assert_contrast(page)
        ratios = page.evaluate('''() => {
          const css = getComputedStyle(document.documentElement);
          const canvas = document.createElement('canvas').getContext('2d');
          function lum(name) { canvas.fillStyle=css.getPropertyValue('--'+name).trim(); const c=canvas.fillStyle.match(/\\w\\w/g).slice(0,3).map(x=>parseInt(x,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4); return c[0]*.2126+c[1]*.7152+c[2]*.0722; }
          function ratio(a,b) { const x=lum(a), y=lum(b); return (Math.max(x,y)+.05)/(Math.min(x,y)+.05); }
          return Object.fromEntries(['bg-canvas','bg-sunken','surface-1','surface-2'].flatMap(bg=>['text-primary','text-secondary','text-muted','accent'].map(fg=>[fg+'/'+bg,ratio(fg,bg)])));
        }''')
        assert min(ratios.values()) >= 4.5, {k:v for k,v in ratios.items() if v<4.5}
    for mode in ['dark', 'light']:
        theme(page, mode)
        for background in ['surface-1', 'surface-2']:
            ratio = page.evaluate('''bg => {
                const css=getComputedStyle(document.documentElement);
                const luminance=name=>{const hex=css.getPropertyValue('--'+name).trim();const v=hex.match(/\\w\\w/g).map(x=>parseInt(x,16)/255).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4);return v[0]*.2126+v[1]*.7152+v[2]*.0722;};
                const a=luminance('border-control'),b=luminance(bg);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
            }''', background)
            assert ratio >= 3
    page.emulate_media(media='print')
    assert page.locator('body').evaluate('(e)=>getComputedStyle(e).backgroundColor') == 'rgb(245, 247, 251)'


def test_additive_image_ui_keeps_navigation(tmp_path):
    spec = importlib.util.spec_from_file_location('apply_ds', ROOT / 'deploy/apply-design-system.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / 'templates').mkdir()
    (tmp_path / 'templates/base_client.html').write_text('<a href="/profiles">Profiles</a>')
    (tmp_path / 'templates/base_admin.html').write_text('<a href="/admin/agent-routes">Routes</a>')
    (tmp_path / 'static').mkdir()
    (tmp_path / 'static/existing-overlay.js').write_text('preserved')
    module.apply(ROOT / 'server/upstream/app', tmp_path)
    module.apply(ROOT / 'server/upstream/app', tmp_path)
    assert (tmp_path / 'templates/base_client.html').read_text().count('href="/profiles"') == 1
    assert (tmp_path / 'templates/base_admin.html').read_text().count('href="/admin/agent-routes"') == 1
    assert (tmp_path / 'static/existing-overlay.js').read_text() == 'preserved'
    assert (tmp_path / 'static/apex/fonts/Inter.ttf').read_bytes() == (DS / 'fonts/Inter.ttf').read_bytes()


def assert_contrast(page):
    if not BASELINE:
        failures = page.evaluate(r'''() => {
  const ctx=document.createElement('canvas').getContext('2d');
  function rgba(color) { ctx.clearRect(0,0,1,1); ctx.fillStyle=color; ctx.fillRect(0,0,1,1); return Array.from(ctx.getImageData(0,0,1,1).data); }
  function blend(f,b) { const a=f[3]/255; return f.slice(0,3).map((v,i)=>v*a+b[i]*(1-a)).concat(255); }
  function bg(el) { if (!el) return [255,255,255,255]; return blend(rgba(getComputedStyle(el).backgroundColor),bg(el.parentElement)); }
  function lum(c) { const v=c.slice(0,3).map(x=>x/255).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4); return .2126*v[0]+.7152*v[1]+.0722*v[2]; }
  const failures=[];
  for(const el of document.querySelectorAll('body *')) {
    if(!el.checkVisibility() || el.closest(':disabled') || !Array.from(el.childNodes).some(n=>n.nodeType===3&&n.textContent.trim()) || ['SCRIPT','STYLE','OPTION'].includes(el.tagName)) continue;
    const style=getComputedStyle(el), background=bg(el), color=blend(rgba(style.color),background);
    const a=lum(color),b=lum(background),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
    if(ratio<4.5) failures.push({text:el.textContent.slice(0,60),class:el.className,ratio});
  }
  return failures;
}
''')
        assert failures == []


def test_theme_invalid_storage_cross_tab_and_denied_storage(page):
    page.goto('https://design.example.invalid/console/')
    page.evaluate("localStorage.setItem('apex.theme', 'invalid')")
    page.reload()
    expect(page.locator('[data-theme-switch]')).to_have_value('system')
    page.evaluate("dispatchEvent(new StorageEvent('storage', {key:'apex.theme',newValue:'light'}))")
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')
    page.add_init_script("Storage.prototype.getItem = Storage.prototype.setItem = function() { throw new DOMException('Denied', 'SecurityError'); }")
    page.reload()
    page.locator('[data-theme-switch]').select_option('light')
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')
    page.locator('[data-theme-switch]').focus()
    assert page.locator('[data-theme-switch]').evaluate('(e)=>getComputedStyle(e).outlineWidth') == '2px'


@pytest.mark.parametrize('mode', ['dark', 'light'])
def test_overlay_screens(page, mode):
    for name in ['rtrust_profiles', 'rtrust_admin_routes']:
        page.goto('https://design.example.invalid/overlay/' + name + '.html')
        theme(page, mode)
        expect(page.locator('#status')).not_to_contain_text('Ошибка')
        screenshot(page, f'overlay-{name}-{mode}')
        assert_contrast(page)
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        screenshot(page, f'overlay-{name}-mobile-{mode}')
        page.set_viewport_size({'width': 1440, 'height': 1000})
