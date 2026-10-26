"""APEX contract and isolated browser QA; only synthetic users/configurations."""
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
import ast
import importlib.util
import json
import os
import re
import shutil
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


def overlay_csp():
    """The production policy of the overlay pages, so blocked assets fail here too."""
    match = re.search(r'^CSP = (".*")$', (ROOT / 'server/overlay/app/rtrust_profiles.py').read_text(), re.M)
    return ast.literal_eval(match.group(1))


def source(path):
    if BASELINE:
        return subprocess.check_output(['git', 'show', 'cf61422:' + str(path.relative_to(ROOT))], cwd=ROOT)
    return path.read_bytes()


def render_portal(name, templates=None):
    env = Environment(loader=FileSystemLoader(templates or ROOT / 'server/upstream/app/templates'), undefined=ChainableUndefined, autoescape=True)
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
        registration_enabled=True, smtp_enabled=True, msg='', err='', token='synthetic', qr_svg='', ttl=180, origin='https://design.example.invalid', code='synthetic', endpoint_ready=True,
        windows_available=True, android_available=True, android_sha256='a'*64, windows_version='0.6.2', android_version='0.6.2').encode()


@pytest.fixture
def console_state():
    from test_routing_browser import fixture_state
    data = fixture_state()
    data['protocols'] = {
        'checked': '2026-10-23T00:00:00Z',
        'units': [{'id': 'h-ui', 'title': 'Hysteria 2', 'state': 'active'},
                  {'id': 'vpn-console-agent', 'title': 'Агент консоли', 'state': 'active'}],
        'items': [dict(id=name, title=title, runtime=runtime, installed=installed, state='running' if installed else 'absent',
                       version='1.0.0' if installed else '', latest='2.0.0', update=update,
                       repo='https://github.com/example/' + name, releases=[{'version': '2.0.0', 'published': '2026-10-23'}])
                  for name, title, runtime, installed, update in [
                      ('hysteria', 'Hysteria 2', 'systemd · h-ui', True, True),
                      ('trusttunnel', 'TrustTunnel', 'docker · trusttunnel-web', True, False),
                      ('amnezia', 'AmneziaWG 3.1', 'docker · amnezia-awg', False, False),
                      ('cdn', 'VLESS через CDN', 'docker · xray-cdn', False, False)]],
        'containers': [dict(name='vpn-console-backup-production-20261023-001122-' + str(i), role='Консоль',
                            image='registry.example.invalid/onixus/vpn-console@sha256:' + 'a' * 64,
                            state='running' if i == 0 else 'exited', health='healthy' if i == 0 else 'unhealthy',
                            restarts=i, since='2026-10-23T00:11:22Z', exit_code=0,
                            ports=['127.0.0.1:18090->8000/tcp', '[::]:8443->8443/udp']) for i in range(6)]}
    return data


@pytest.fixture
def page(tmp_path, console_state):
    installed = tmp_path / 'portal'
    shutil.copytree(ROOT / 'server/upstream/app', installed, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    load_apply().apply(ROOT / 'server/upstream/app', installed)
    spec = importlib.util.spec_from_file_location('portal_patch', ROOT / 'deploy/portal_patch.py')
    patcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patcher)
    patcher.integrate(installed)
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
                return req.fulfill(json=console_state)
            if path == '/console/':
                return req.fulfill(body=source(ROOT / 'server/console/templates/index.html').replace(b'{{ csrf }}', b'synthetic'), content_type='text/html', headers={'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:"})
            if path.startswith('/portal/v2/') or path == '/admin/api/agent-routes':
                return req.fulfill(json={'profiles': [], 'devices': [], 'groups': [], 'users': [], 'managed_credentials': {'enabled': False}})
            if path.startswith('/overlay/'):
                env = Environment(loader=FileSystemLoader(ROOT / 'server/overlay/app/templates'), autoescape=True)
                html = env.get_template(path.rsplit('/', 1)[-1]).render(csrf='synthetic', brand='ONIXUS', user={'email': 'operator@example.invalid'})
                return req.fulfill(body=html, content_type='text/html', headers={'Content-Security-Policy': overlay_csp()})
            if path.startswith('/screen/'):

                return req.fulfill(body=render_portal(path.rsplit('/', 1)[-1]), content_type='text/html')
            if path.startswith('/installed/'):
                return req.fulfill(body=render_portal(path.rsplit('/', 1)[-1], installed / 'templates'), content_type='text/html')
            for prefix, folder in [('/console/static/', 'server/console/static'), ('/static/', 'server/upstream/app/static'), ('/static/', 'server/overlay/app/static')]:
                if path.startswith(prefix):
                    file = ROOT / folder / path.removeprefix(prefix)
                    if file.is_file():
                        return req.fulfill(body=source(file), content_type={'.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml'}.get(file.suffix, 'font/ttf'))
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
            assert page.evaluate("fetch(document.querySelector('link[rel=icon]').href).then(r => r.ok)")
            assert page.evaluate("document.fonts.check('14px Inter')")
    page.goto('https://design.example.invalid/screen/dashboard.html')
    theme(page, mode)
    page.set_viewport_size({'width': 390, 'height': 844})
    screenshot(page, f'portal-mobile-{mode}')
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


@pytest.mark.parametrize('mode', ['dark', 'light'])
@pytest.mark.parametrize('width', [320, 390])
def test_installed_portal_mobile_navigation(page, mode, width):
    page.set_viewport_size({'width': width, 'height': 844})
    page.goto('https://design.example.invalid/installed/dashboard.html')
    theme(page, mode)
    for selector in ['header a[href="/profiles"]', 'header [data-theme-switch]', 'header a[href="/logout"]']:
        control = page.locator(selector)
        expect(control).to_be_visible()
        box = control.bounding_box()
        assert box['x'] >= 0 and box['x'] + box['width'] <= width, selector
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    assert_contrast(page)
    screenshot(page, f'installed-portal-mobile-{width}-{mode}')


@pytest.mark.parametrize('mode', ['dark', 'light'])
@pytest.mark.parametrize('width', [1280, 1920, 2560])
def test_console_uses_available_desktop_width(page, mode, width):
    page.set_viewport_size({'width': width, 'height': 1100})
    page.goto('https://design.example.invalid/console/')
    theme(page, mode)
    aside = page.locator('aside').bounding_box()
    main = page.locator('main').bounding_box()
    assert main['x'] == aside['width']
    assert main['width'] == width - aside['width']
    assert page.locator('.heading').bounding_box()['x'] <= aside['width'] + 40
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    screenshot(page, f'overview-wide-{width}-{mode}')
    page.locator('nav [data-page=protocols]').click()
    region = page.get_by_role('region', name='Контейнеры', exact=True)
    assert region.evaluate('(e) => e.scrollWidth <= e.clientWidth')
    assert region.locator('table').evaluate('(e) => e.scrollWidth <= e.clientWidth')
    assert region.locator('th').nth(4).evaluate('(e) => {const range=document.createRange();range.selectNodeContents(e);return range.getClientRects().length}') == 1
    assert page.locator('tbody tr').count() == 6
    assert_contrast(page)
    screenshot(page, f'protocols-wide-{width}-{mode}')


@pytest.mark.parametrize('mode', ['dark', 'light'])
def test_protocol_actions_have_consistent_priority_and_colors(page, console_state, mode):
    page.goto('https://design.example.invalid/console/')
    theme(page, mode)
    page.locator('nav [data-page=protocols]').click()
    check = page.locator('[data-action=protocol-check]')
    expect(check).to_have_class('primary')
    actions = page.locator('[data-action=protocol-install], [data-action=protocol-update]')
    assert actions.count() == 3
    colors = actions.evaluate_all('(buttons) => buttons.map(b => {const s=getComputedStyle(b);return [s.color,s.backgroundColor,s.borderColor]})')
    assert all(color == colors[0] for color in colors)
    assert page.locator('#content .primary').count() == 1
    for action in actions.all():
        expect(action).to_be_enabled()
        assert_control_boundary(action)
        action.hover()
        assert_contrast(page)
        assert_control_boundary(action)
        action.focus()
        page.keyboard.press('Tab')
        page.keyboard.press('Shift+Tab')
        assert action.evaluate('(e) => getComputedStyle(e).outlineWidth') == '2px'
    for name, title in [('amnezia', 'Установить AmneziaWG 3.1'), ('hysteria', 'Обновить Hysteria 2')]:
        page.locator(f'.protocol-card [data-id={name}]').click()
        expect(page.locator('#modal-title')).to_have_text(title)
        expect(page.locator('#protocol-form select[name=version]')).to_have_value('2.0.0')
        page.locator('#modal').get_by_role('button', name='Закрыть', exact=True).click()
    # Reordering cards must not change the priority or color of their actions.
    console_state['protocols']['items'].reverse()
    page.mouse.move(0, 0)
    page.locator('#refresh').click()
    assert actions.evaluate_all('(buttons) => buttons.map(b => {const s=getComputedStyle(b);return [s.color,s.backgroundColor,s.borderColor]})') == colors
    console_state['jobs'] = [{'action': 'protocols.install', 'state': 'running'}]
    page.locator('#refresh').click()
    expect(check).to_be_disabled()
    for action in actions.all():
        expect(action).to_be_disabled()


def test_protocol_table_remains_keyboard_scrollable_on_mobile(page):
    page.set_viewport_size({'width': 390, 'height': 844})
    page.goto('https://design.example.invalid/console/')
    page.locator('nav [data-page=protocols]').click()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    region = page.get_by_role('region', name='Контейнеры', exact=True)
    region.focus()
    region.press('ArrowRight')
    expect(region).not_to_have_js_property('scrollLeft', 0)


def test_legacy_theme_preference_is_migrated(page):
    # Runs after the fixture's default, once: a returning user of the old portal toggle.
    page.context.add_init_script("""if (!sessionStorage.getItem('seeded')) {
      sessionStorage.setItem('seeded', '1'); localStorage.removeItem('apex.theme'); localStorage.setItem('theme', 'light');
    }""")
    page.emulate_media(color_scheme='dark')
    page.goto('https://design.example.invalid/console/')
    expect(page.locator('html')).to_have_attribute('data-theme', 'light')
    assert page.locator('[data-theme-switch]').input_value() == 'light'
    assert page.evaluate("[localStorage.getItem('apex.theme'), localStorage.getItem('theme')]") == ['light', None]


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


def load_apply():
    spec = importlib.util.spec_from_file_location('apply_ds', ROOT / 'deploy/apply-design-system.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_portal_modules(module, target):
    for name in module.RENDERING_MODULES:
        (target / name).write_bytes((ROOT / 'server/upstream/app' / name).read_bytes())


def test_additive_image_ui_keeps_navigation(tmp_path):
    module = load_apply()
    install_portal_modules(module, tmp_path)
    (tmp_path / 'templates').mkdir()
    (tmp_path / 'templates/base_client.html').write_text('<a href="/profiles">Profiles</a>')
    (tmp_path / 'templates/base_admin.html').write_text('<a href="/admin/agent-routes">Routes</a>')
    (tmp_path / 'static').mkdir()
    (tmp_path / 'static/existing-overlay.js').write_text('preserved')
    for name in module.RENDERING_MODULES:
        (tmp_path / name).write_bytes((ROOT / 'server/upstream/app' / name).read_bytes())
    module.apply(ROOT / 'server/upstream/app', tmp_path)
    module.apply(ROOT / 'server/upstream/app', tmp_path)
    assert (tmp_path / 'templates/base_client.html').read_text().count('href="/profiles"') == 1
    assert (tmp_path / 'templates/base_admin.html').read_text().count('href="/admin/agent-routes"') == 1
    assert (tmp_path / 'static/existing-overlay.js').read_text() == 'preserved'
    assert (tmp_path / 'static/apex/fonts/Inter.ttf').read_bytes() == (DS / 'fonts/Inter.ttf').read_bytes()
    (tmp_path / 'routes_client.py').write_text('different installed portal')
    before = (tmp_path / 'templates/base_client.html').read_bytes()
    with pytest.raises(RuntimeError, match='differs'):
        module.apply(ROOT / 'server/upstream/app', tmp_path)
    assert (tmp_path / 'templates/base_client.html').read_bytes() == before


def test_additive_image_ui_refuses_other_portal_version(tmp_path):
    module = load_apply()
    install_portal_modules(module, tmp_path)
    (tmp_path / 'routes_client.py').write_text('# another portal release')
    (tmp_path / 'templates').mkdir()
    (tmp_path / 'templates/dashboard.html').write_text('kept')
    with pytest.raises(RuntimeError, match='routes_client.py'):
        module.apply(ROOT / 'server/upstream/app', tmp_path)
    assert (tmp_path / 'templates/dashboard.html').read_text() == 'kept'


def assert_control_boundary(control):
    ratio = control.evaluate('''e => {
      const ctx=document.createElement('canvas').getContext('2d'), style=getComputedStyle(e);
      function lum(color) {
        ctx.fillStyle=color;ctx.fillRect(0,0,1,1);
        const c=Array.from(ctx.getImageData(0,0,1,1).data).slice(0,3).map(x=>x/255).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4);
        return .2126*c[0]+.7152*c[1]+.0722*c[2];
      }
      const a=lum(style.borderTopColor),b=lum(style.backgroundColor);
      return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
    }''')
    assert ratio >= 3


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
        if not BASELINE:
            assert page.evaluate("document.fonts.load('14px Inter').then(faces => faces.some(f => f.status === 'loaded'))")
        screenshot(page, f'overlay-{name}-{mode}')
        assert_contrast(page)
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        screenshot(page, f'overlay-{name}-mobile-{mode}')
        page.set_viewport_size({'width': 1440, 'height': 1000})
