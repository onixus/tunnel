"""Protocol lifecycle and AmneziaWG: fake GitHub, fake Docker, temporary state. No network, no live VPN."""
import base64
import hashlib
import hmac
import io
import json
from pathlib import Path
import random
import sys
import types
import urllib.request

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server/console'))
import amnezia
import cdn
import protocols
from routing_policy import PolicyError

GO = [{'name': 'v3.1.20260828', 'commit': {'sha': 'a' * 40}}, {'name': 'v3.1.20260812', 'commit': {'sha': 'b' * 40}},
      {'name': 'v3.0.20260805', 'commit': {'sha': 'c' * 40}}, {'name': 'v3.1.20260901-rc', 'commit': {'sha': 'd' * 40}}]
TOOLS = [{'name': 'v3.1.20260812', 'commit': {'sha': 'e' * 40}}, {'name': 'v3.1.20260901', 'commit': {'sha': 'f' * 40}}]
DIGEST = 'sha256:' + '1' * 64


def release(tag, asset, **extra):
    return {'tag_name': tag, 'published_at': '2026-09-01T00:00:00Z', 'assets': [{'name': asset, 'size': 1000, 'digest': DIGEST}], **extra}


@pytest.fixture
def host(tmp_path, monkeypatch):
    """Temporary agent paths and a recording Docker stand-in."""
    home = tmp_path / 'amneziawg'
    monkeypatch.setattr(amnezia, 'STATE', home / 'state.json')
    monkeypatch.setattr(amnezia, 'RUNTIME', home / 'runtime')
    monkeypatch.setattr(cdn, 'STATE', tmp_path / 'xray-cdn/state.json')
    monkeypatch.setattr(cdn, 'RUNTIME', tmp_path / 'xray-cdn/runtime')
    for name in ('CACHE', 'ROLLBACK', 'BUILD', 'ASSETS'):
        monkeypatch.setattr(protocols, name, tmp_path / name.lower())
    (tmp_path / 'assets/amnezia').mkdir(parents=True)
    for name in ('Dockerfile', 'entrypoint.sh'):
        (tmp_path / 'assets/amnezia' / name).write_text('fixture')
    monkeypatch.setattr(protocols.service_routes, 'trusted', lambda path, executable=False: path.is_file())
    protocols._MEMO['value'] = None
    box = {'calls': [], 'port': None, 'containers': set()}

    def run(args, timeout=30, env=None):
        box['calls'].append(args)
        if args[:2] == ['docker', 'run']:
            box['containers'].add(args[args.index('--name') + 1])
        return ''

    def quiet(args, timeout=8):
        box['calls'].append(args)
        if args[:2] == ['docker', 'inspect']:
            return (0, 'running') if args[2] in box['containers'] else (1, '')
        if args[:2] == ['docker', 'exec'] and 'listen-port' in args:
            return 0, str(box['port'] or '')
        if args[:3] == ['docker', 'rm', '-f']:
            box['containers'].discard(args[3])
        return 0, ''
    monkeypatch.setattr(protocols, 'run', run)
    monkeypatch.setattr(protocols, 'quiet', quiet)
    monkeypatch.setattr(amnezia, 'run', run)
    monkeypatch.setattr(amnezia, 'running', lambda: amnezia.CONTAINER in box['containers'])
    monkeypatch.setattr(protocols.time, 'sleep', lambda s: None)
    return box


def test_awg31_parameters_satisfy_protocol_constraints():
    for seed in range(200):
        p = amnezia.new_params(random.Random(seed))
        # Header protection (AWG 3+) requires every padding to be at least 12.
        assert all(p[k] >= 12 for k in ('S1', 'S2', 'S3', 'S4'))
        assert len({148 + p['S1'], 92 + p['S2'], 64 + p['S3']}) == 3
        assert 4 <= p['Jc'] <= 12 and p['Jmin'] <= p['Jmax'] < amnezia.MTU
        ranges = sorted(tuple(map(int, p[k].split('-'))) for k in ('H1', 'H2', 'H3', 'H4'))
        assert all(4 < low <= high < 2 ** 31 for low, high in ranges)
        assert all(a[1] < b[0] for a, b in zip(ranges, ranges[1:]))
        assert len(base64.b64decode(p['HeaderProtectionKey'], validate=True)) == 32


@pytest.mark.parametrize('port', [None, '47443', 80, 443, 8443, 51831, 70000, True])
def test_port_is_validated(port):
    with pytest.raises(PolicyError):
        amnezia.new_state(port)


def test_peer_lifecycle_and_secret_boundaries(host):
    with pytest.raises(PolicyError, match='не установлен'):
        amnezia.users()
    amnezia.save(amnezia.new_state(47443), sync=False)
    for name in ('alice', 'bob-2'):
        amnezia.dispatch('amnezia.create', {'username': name}, 'vpn.example.invalid')
    for bad in ('ab', 'alice', 'bad name', '../x', 7):
        with pytest.raises(PolicyError):
            amnezia.dispatch('amnezia.create', {'username': bad}, 'vpn.example.invalid')
    state = amnezia.load()
    alice, bob = state['peers']
    assert (alice['address'], bob['address']) == ('10.8.1.2', '10.8.1.3')
    listing = json.dumps(amnezia.users())
    for secret in (state['private_key'], alice['private_key'], alice['psk'], bob['psk']):
        assert secret not in listing
    conf = amnezia.dispatch('amnezia.export', {'id': 1}, 'vpn.example.invalid')['content']
    assert 'Endpoint = vpn.example.invalid:47443' in conf and alice['private_key'] in conf
    assert bob['private_key'] not in conf and state['private_key'] not in conf and state['public_key'] in conf
    # Both sides carry identical AWG 3.1 obfuscation values.
    server = (amnezia.RUNTIME / 'awg0.conf').read_text()
    for key in amnezia.SHARED:
        line = f'{key} = {state["params"][key]}'
        assert line in conf and line in server
    assert (amnezia.STATE.stat().st_mode & 0o777, (amnezia.RUNTIME / 'awg0.conf').stat().st_mode & 0o777) == (0o600, 0o600)

    amnezia.dispatch('amnezia.block', {'id': 2}, 'h')
    assert bob['public_key'] not in (amnezia.RUNTIME / 'awg0.conf').read_text()
    with pytest.raises(PolicyError, match='заблокирован'):
        amnezia.dispatch('amnezia.export', {'id': 2}, 'h')
    amnezia.dispatch('amnezia.unblock', {'id': 2}, 'h')
    amnezia.dispatch('amnezia.rotate', {'id': 1}, 'h')
    rotated = amnezia.load()['peers'][0]
    server = (amnezia.RUNTIME / 'awg0.conf').read_text()
    assert rotated['public_key'] != alice['public_key'] and alice['public_key'] not in server and rotated['public_key'] in server
    for op, data in (('amnezia.block', {'id': 99}), ('amnezia.block', {'id': '1'}), ('amnezia.delete', {'id': 1})):
        with pytest.raises(PolicyError):
            amnezia.dispatch(op, data, 'h')


def test_live_reload_uses_one_fixed_command(host):
    amnezia.save(amnezia.new_state(47443), sync=False)
    host['containers'].add(amnezia.CONTAINER)
    amnezia.dispatch('amnezia.create', {'username': 'alice'}, 'h')
    assert host['calls'][-1] == ['docker', 'exec', 'amnezia-awg', 'bash', '-c', 'awg syncconf awg0 <(awg-quick strip awg0)']


def test_discovery_keeps_only_stable_verifiable_releases(monkeypatch):
    replies = {
        'HyNetworks/hysteria/releases?per_page=30': [
            release('app/v2.13.0', 'hysteria-linux-amd64', prerelease=True),
            release('app/v2.12.4', 'hysteria-linux-amd64'),
            {'tag_name': 'app/v2.12.5', 'assets': [{'name': 'hysteria-linux-amd64', 'size': 1000}]},  # no published digest
            release('app/v2.12.3', 'hysteria-linux-arm64'),
            release('evil/v9.9.9', 'hysteria-linux-amd64')],
        'TrustTunnel/TrustTunnel/releases?per_page=30': [
            release('v1.3.0-beta.1', 'trusttunnel-v1.3.0-beta.1-linux-x86_64.tar.gz'),
            release('v1.1.0', 'trusttunnel-v1.1.0-linux-x86_64.tar.gz'), release('v1.2.0', 'trusttunnel-v1.2.0-linux-x86_64.tar.gz', draft=True)],
        'amnezia-vpn/amneziawg-go/tags?per_page=50': GO,
        'amnezia-vpn/amneziawg-tools/tags?per_page=50': TOOLS,
    }
    monkeypatch.setattr(protocols, 'api', lambda path: replies[path])
    assert [r['version'] for r in protocols.discover('hysteria')] == ['2.12.4']
    assert protocols.discover('trusttunnel') == [{'version': '1.1.0', 'tag': 'v1.1.0', 'sha256': '1' * 64, 'published': '2026-09-01'}]
    awg = protocols.discover('amnezia')
    # Only 3.1 tags; tools are never newer than the protocol tag they are paired with.
    assert [(r['version'], r['commit'], r['tools_tag'], r['tools_commit']) for r in awg] == [
        ('3.1.20260828', 'a' * 40, 'v3.1.20260812', 'e' * 40), ('3.1.20260812', 'b' * 40, 'v3.1.20260812', 'e' * 40)]
    assert awg[0]['published'] == '2026-08-28'


def test_redirects_cannot_leave_github():
    handler = protocols.GitHubOnly()
    request = urllib.request.Request('https://github.com/x')
    for url in ('http://github.com/x', 'https://evil.invalid/x', 'https://githubusercontent.com.evil.invalid/x', 'file:///etc/passwd'):
        assert handler.redirect_request(request, None, 302, 'Found', {}, url) is None
    assert handler.redirect_request(request, None, 302, 'Found', {}, 'https://release-assets.githubusercontent.com/x') is not None


def test_download_rejects_wrong_hash_and_oversize(tmp_path, monkeypatch):
    monkeypatch.setattr(protocols, 'open_url', lambda url: io.BytesIO(b'artifact'))
    protocols.download('https://github.com/x', tmp_path / 'ok', hashlib.sha256(b'artifact').hexdigest())
    with pytest.raises(PolicyError, match='Хеш'):
        protocols.download('https://github.com/x', tmp_path / 'bad', '0' * 64)
    monkeypatch.setattr(protocols, 'LIMIT', 4)
    with pytest.raises(PolicyError, match='размер'):
        protocols.download('https://github.com/x', tmp_path / 'big', hashlib.sha256(b'artifact').hexdigest())


def cache(**components):
    protocols.amnezia.write(protocols.CACHE, json.dumps({'checked': '2026-10-03T00:00:00Z', 'components': {
        name: {'releases': releases} for name, releases in components.items()}}))


AWG = {'version': '3.1.20260828', 'tag': 'v3.1.20260828', 'commit': 'a' * 40, 'tools_tag': 'v3.1.20260812', 'tools_commit': 'e' * 40}


def test_install_accepts_only_registry_components_and_discovered_versions(host, monkeypatch):
    monkeypatch.setattr(protocols, 'check', lambda data=None: None)
    cache(amnezia=[AWG])
    for data in ({'component': 'openvpn'}, {'component': 'amnezia', 'url': 'https://evil.invalid'}, {},
                 {'component': 'amnezia', 'version': '3.1.20260828; rm -rf /', 'port': 47443},
                 {'component': 'amnezia', 'version': '9.9.9', 'port': 47443}):
        with pytest.raises(PolicyError):
            protocols.dispatch('protocols.install', data, None)
    with pytest.raises(PolicyError, match='не установлен'):
        protocols.dispatch('protocols.update', {'component': 'amnezia', 'version': '3.1.20260828'}, None)
    with pytest.raises(PolicyError):
        protocols.dispatch('protocols.remove', {'component': 'amnezia'}, None)
    assert not any(c[:2] in (['docker', 'build'], ['docker', 'run']) for c in host['calls'])


def test_amnezia_install_pins_commits_then_update_keeps_keys(host):
    cache(amnezia=[AWG])
    host['port'] = 47443
    result = protocols.dispatch('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert 'UDP 47443' in result['message']
    build = next(c for c in host['calls'] if c[:2] == ['docker', 'build'])
    for arg in ('AWG_GO_REF=v3.1.20260828', 'AWG_GO_COMMIT=' + 'a' * 40, 'AWG_TOOLS_REF=v3.1.20260812', 'AWG_TOOLS_COMMIT=' + 'e' * 40):
        assert arg in build
    start = next(c for c in host['calls'] if c[:2] == ['docker', 'run'])
    assert start[start.index('--cap-drop') + 1] == 'ALL' and '--privileged' not in start and '47443:47443/udp' in start
    assert [p.name for p in protocols.BUILD.iterdir() if p.name != '.docker'] == []
    state = amnezia.load()
    assert state['version'] == '3.1.20260828' and protocols.installed('amnezia')['installed']
    with pytest.raises(PolicyError, match='уже установлен'):
        protocols.dispatch('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    for version, message in (('3.1.20260828', 'уже установлена'), ('3.1.20260812', 'Понижение')):
        cache(amnezia=[AWG, dict(AWG, version='3.1.20260812', tag='v3.1.20260812')])
        with pytest.raises(PolicyError, match=message):
            protocols.dispatch('protocols.update', {'component': 'amnezia', 'version': version}, None)

    amnezia.dispatch('amnezia.create', {'username': 'alice'}, 'h')
    newer = dict(AWG, version='3.1.20260915', tag='v3.1.20260915', commit='9' * 40)
    cache(amnezia=[newer, AWG])
    protocols.dispatch('protocols.update', {'component': 'amnezia', 'version': '3.1.20260915'}, None)
    after = amnezia.load()
    assert after['version'] == '3.1.20260915'
    assert all(after[k] == state[k] for k in ('private_key', 'params', 'port')) and after['peers'][0]['name'] == 'alice'
    assert ['docker', 'rename', 'amnezia-awg', 'amnezia-awg-previous'] in host['calls']


def test_failed_first_install_leaves_nothing_and_failed_update_restores(host):
    cache(amnezia=[AWG])
    host['port'] = 1  # the new container never reports the expected listen port
    with pytest.raises(PolicyError, match='не прошёл проверку'):
        protocols.dispatch('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert not amnezia.STATE.exists() and amnezia.CONTAINER not in host['containers']

    host['port'] = 47443
    protocols.dispatch('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    before = amnezia.STATE.read_text()
    cache(amnezia=[dict(AWG, version='3.1.20260915', tag='v3.1.20260915')])
    host['port'] = 1
    with pytest.raises(PolicyError, match='не прошёл проверку'):
        protocols.dispatch('protocols.update', {'component': 'amnezia', 'version': '3.1.20260915'}, None)
    assert amnezia.STATE.read_text() == before
    assert ['docker', 'rename', 'amnezia-awg-previous', 'amnezia-awg'] in host['calls']


def test_status_reports_versions_containers_and_no_secrets(host, monkeypatch):
    cache(amnezia=[AWG], hysteria=[{'version': '2.12.4', 'tag': 'app/v2.12.4', 'sha256': '1' * 64}])
    inspect = [{'Name': '/trusttunnel-web', 'RestartCount': 2, 'Config': {'Image': 'sha256:' + 'a' * 64, 'Env': ['SECRET_KEY=never-shown']},
                'State': {'Status': 'running', 'Running': True, 'StartedAt': '2026-10-01T10:00:00.123Z', 'Health': {'Status': 'healthy'}},
                'HostConfig': {'PortBindings': {'8443/udp': [{'HostIp': '', 'HostPort': '8443'}]}}},
               {'Name': '/other', 'Config': {'Image': 'nginx:1'}, 'State': {'Status': 'exited', 'ExitCode': 137, 'FinishedAt': '2026-10-02T00:00:00Z'}}]
    monkeypatch.setattr(protocols, 'quiet', lambda args, timeout=8: (0, 'a' * 64 + '\n' + 'b' * 64) if args[:2] == ['docker', 'ps'] else (1, ''))
    monkeypatch.setattr(protocols, 'run', lambda args, timeout=30: json.dumps(inspect))
    value = protocols.status()
    assert [i['id'] for i in value['items']] == ['hysteria', 'trusttunnel', 'amnezia', 'cdn']
    assert value['items'][2] == dict(value['items'][2], installed=False, latest='3.1.20260828', update=False, repo='https://github.com/amnezia-vpn/amneziawg-go')
    first, second = value['containers']
    assert first == {'name': 'trusttunnel-web', 'role': 'TrustTunnel и портал', 'state': 'running', 'image': 'sha256:aaaaaaaaaaaa', 'health': 'healthy',
                     'restarts': 2, 'exit_code': 0, 'since': '2026-10-01T10:00:00', 'ports': ['*:8443 → 8443/udp']}
    assert (second['state'], second['exit_code']) == ('exited', 137)
    assert 'never-shown' not in json.dumps(value)
    assert protocols.status() is value  # memoised between UI polls


@pytest.fixture
def console(tmp_path, monkeypatch):
    """The real console API over a stub portal identity."""
    app = types.ModuleType('app')
    app.__path__ = []
    parts = {name: types.ModuleType('app.' + name) for name in ('config', 'db', 'security', 'webauth', 'mailer', 'conninfo')}
    parts['config'].SECRET_KEY = 'test-secret'
    parts['webauth'].ADMIN_COOKIE = 'admin_token'
    parts['webauth'].current_admin = lambda request: {'id': 1} if request.cookies.get('admin_token') == 'session' else None
    parts['mailer'].is_configured = lambda: False
    monkeypatch.setitem(sys.modules, 'app', app)
    for name, module in parts.items():
        setattr(app, name, module)
        monkeypatch.setitem(sys.modules, 'app.' + name, module)
    monkeypatch.delitem(sys.modules, 'console_app', raising=False)
    import console_app
    monkeypatch.setattr(console_app, 'STATE', tmp_path)
    console_app.init()
    client = TestClient(console_app.app)
    client.cookies.set('admin_token', 'session')
    client.headers['X-CSRF-Token'] = hmac.new(b'test-secret', b'console:session', hashlib.sha256).hexdigest()
    yield client, console_app
    sys.modules.pop('console_app', None)


def job(client, action, data, key):
    return client.post('/console/api/jobs', json={'action': action, 'data': data, 'confirm': True, 'request_id': key})


def test_api_validates_and_serialises_protocol_jobs(console):
    client, ui = console
    for action, data in [('protocols.install', {'component': 'openvpn'}), ('protocols.install', {'component': 'amnezia'}),
                         ('protocols.install', {'component': 'amnezia', 'port': 80}), ('protocols.install', {'component': 'hysteria', 'port': 47443}),
                         ('protocols.install', {'component': 'amnezia', 'port': 47443, 'image': 'evil'}),
                         ('protocols.update', {'component': 'hysteria'}), ('protocols.update', {'component': 'hysteria', 'version': 'latest'}),
                         ('protocols.check', {'component': 'hysteria'}), ('amnezia.create', {'username': 'a b'}), ('amnezia.block', {'id': '1'})]:
        assert job(client, action, data, 'k' * 16 + action).status_code == 422, (action, data)
    assert job(client, 'protocols.install', {'component': 'amnezia', 'port': 47443}, 'install-request-0001').status_code == 200
    assert job(client, 'protocols.install', {'component': 'amnezia', 'port': 47443}, 'install-request-0001').status_code == 200
    # One lifecycle operation at a time, across all protocols.
    assert job(client, 'protocols.update', {'component': 'hysteria', 'version': '2.12.4'}, 'update-request-0001').status_code == 409
    assert job(client, 'amnezia.create', {'username': 'alice'}, 'create-request-0001').status_code == 200
    with ui.connect() as c:
        rows = {r['action']: json.loads(r['payload']) for r in c.execute('SELECT action,payload FROM jobs')}
    assert rows == {'protocols.install': {'component': 'amnezia', 'port': 47443}, 'amnezia.create': {'username': 'alice'}}
    client.headers.pop('X-CSRF-Token')
    assert job(client, 'protocols.check', {}, 'check-request-00001').status_code == 403


def test_amnezia_config_bundle_and_blocked_user():
    import config_delivery
    bundle = config_delivery.amnezia_bundle({'id': 3, 'username': 'alice', 'deleted': 0}, lambda d: {'content': '[Interface]\nfixture\n'})
    assert bundle['kind'] == 'amnezia' and bundle['items'][0]['files'] == [('amneziawg-alice.conf', b'[Interface]\nfixture\n', 'text/plain')]
    assert 'AmneziaWG' in config_delivery.body_text(bundle)
    with pytest.raises(config_delivery.DeliveryError):
        config_delivery.amnezia_bundle({'id': 3, 'username': 'alice', 'deleted': 1}, lambda d: {})


def test_failed_live_reload_restarts_interface_or_reports_stale_keys(host, monkeypatch):
    amnezia.save(amnezia.new_state(47443), sync=False)
    amnezia.dispatch('amnezia.create', {'username': 'alice'}, 'h')
    host['containers'].add(amnezia.CONTAINER)
    failing = {'exec'}

    def run(args, timeout=30, env=None):
        host['calls'].append(args)
        if args[1] in failing:
            raise PolicyError('docker')
        return ''
    monkeypatch.setattr(amnezia, 'run', run)
    # syncconf fails: the interface is reloaded from the saved file, so the block takes effect.
    assert amnezia.dispatch('amnezia.block', {'id': 1}, 'h')['message']
    assert host['calls'][-1] == ['docker', 'restart', '--time', '10', 'amnezia-awg']
    failing.add('restart')
    with pytest.raises(PolicyError, match='прежние ключи AmneziaWG ещё действуют'):
        amnezia.dispatch('amnezia.rotate', {'id': 1}, 'h')
    # Desired state is still saved for the operator's restart.
    assert amnezia.load()['peers'][0]['enabled'] is False


def test_stopped_trusttunnel_is_an_existing_deployment(host, monkeypatch):
    for state in ('exited', 'restarting'):
        monkeypatch.setattr(protocols, 'quiet', lambda args, timeout=8: (0, state) if args[:2] == ['docker', 'inspect'] else (1, ''))
        assert protocols.installed('trusttunnel') == {'installed': True, 'version': None, 'state': state}
        cache(trusttunnel=[{'version': '1.0.33', 'tag': 'v1.0.33', 'sha256': '1' * 64}])
        with pytest.raises(PolicyError, match='уже установлен'):
            protocols.dispatch('protocols.install', {'component': 'trusttunnel', 'version': '1.0.33'}, None)
    monkeypatch.setattr(protocols, 'quiet', lambda args, timeout=8: (1, ''))
    assert protocols.installed('trusttunnel')['installed'] is False
    # Running container without an endpoint binary is the only first-install case.
    monkeypatch.setattr(protocols, 'quiet', lambda args, timeout=8: (0, 'running') if args[:2] == ['docker', 'inspect'] else (127, ''))
    assert protocols.installed('trusttunnel')['installed'] is False


def test_swap_restarts_old_container_when_rename_fails(host, monkeypatch):
    host['containers'].add('svc')
    plain = protocols.run

    def run(args, timeout=30, env=None):
        if args[:2] == ['docker', 'rename']:
            host['calls'].append(args)
            raise PolicyError('rename')
        return plain(args, timeout)
    monkeypatch.setattr(protocols, 'run', run)
    with pytest.raises(PolicyError):
        protocols.swap_container('svc', ['image'], lambda: None)
    # The old container still owns the name: it is started again, never removed.
    assert host['calls'][-1] == ['docker', 'start', 'svc']
    assert ['docker', 'rm', '-f', 'svc'] not in host['calls'] and 'svc' in host['containers']
    assert not any(c[:2] == ['docker', 'run'] for c in host['calls'])


@pytest.fixture
def hysteria(host, tmp_path, monkeypatch):
    from contextlib import nullcontext
    binary = tmp_path / 'h-ui/bin/hysteria-linux-amd64'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'old-core')
    unit = tmp_path / 'h-ui.service'
    unit.write_text('unit')
    monkeypatch.setattr(protocols, 'HYSTERIA_BIN', binary)
    monkeypatch.setattr(protocols, 'HYSTERIA_UNIT', unit)
    monkeypatch.setattr(protocols.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(protocols, 'download', lambda url, dest, sha256: dest.write_bytes(b'new-core'))
    monkeypatch.setattr(protocols.service_routes, 'route_lock', lambda wait=False: nullcontext())
    monkeypatch.setattr(protocols.service_routes, 'PENDING', tmp_path / 'no-pending')
    box = {'probe_ok': True}

    class Runtime:
        def __init__(self, agent): pass
        def observe(self): return {'services': {'hysteria': {'actual_exit': 'primary'}}, 'profiles': {}}
        def expected_ip(self, exit_id, profiles): return '192.0.2.1'
        def probe(self, name, expected):
            host['calls'].append(['probe', name, expected])
            if not box['probe_ok']:
                raise PolicyError('probe')
    monkeypatch.setattr(protocols.service_routes, 'Runtime', Runtime)
    cache(hysteria=[{'version': '2.12.4', 'tag': 'app/v2.12.4', 'sha256': '1' * 64}])
    box.update(binary=binary, update=lambda: protocols.dispatch('protocols.update', {'component': 'hysteria', 'version': '2.12.4'}, None))
    return box


def test_hysteria_update_probes_real_traffic_and_keeps_previous_binary(host, hysteria):
    assert '2.12.4' in hysteria['update']()['message']
    assert hysteria['binary'].read_bytes() == b'new-core' and hysteria['binary'].stat().st_mode & 0o777 == 0o755
    assert ['probe', 'hysteria', '192.0.2.1'] in host['calls']
    assert [p.read_bytes() for p in protocols.ROLLBACK.iterdir()] == [b'old-core']


def test_hysteria_failed_probe_restores_previous_binary_and_restarts(host, hysteria):
    hysteria['probe_ok'] = False
    with pytest.raises(PolicyError, match='Предыдущая версия восстановлена'):
        hysteria['update']()
    assert hysteria['binary'].read_bytes() == b'old-core'
    assert host['calls'][-1] == ['systemctl', 'start', 'h-ui']


def test_hysteria_is_started_even_when_rollback_cannot_write(host, hysteria, monkeypatch):
    def denied(*args):
        raise OSError(30, 'Read-only file system')
    monkeypatch.setattr(protocols.shutil, 'chown', denied)
    with pytest.raises(PolicyError, match='откат не подтверждён'):
        hysteria['update']()
    # Neither replacement happened; the service must not be left stopped.
    assert hysteria['binary'].read_bytes() == b'old-core'
    assert [p.name for p in hysteria['binary'].parent.iterdir()] == ['hysteria-linux-amd64']
    assert host['calls'][-1] == ['systemctl', 'start', 'h-ui']
    assert not any(c[0] == 'probe' for c in host['calls'])


def test_agent_writable_paths_exist_before_it_starts():
    """systemd resolves ReadWritePaths at start; a path created later stays read-only."""
    import re
    unit = (ROOT / 'deploy/vpn-console-agent.service').read_text()
    installer = (ROOT / 'deploy/install-console.py').read_text()
    paths = re.search(r'^ReadWritePaths=(.+)$', unit, re.M)[1].split()
    assert '/var/lib/h-ui' in paths and '/opt/amneziawg' in paths
    for path in ('/var/lib/h-ui', '/opt/amneziawg'):
        assert f"Path('{path}')" in installer and installer.index(f"Path('{path}')") < installer.index("'enable','--now','vpn-console-agent'")


def test_overview_does_not_show_uninstalled_protocol_as_failure():
    script = (ROOT / 'server/console/static/console.js').read_text()
    assert 's === "absent"' in script and 'pill gray">Не установлен' in script
    assert 'servicePill("amnezia")' not in script and '${servicePill(k)}' in script
    assert '${servicePill(id)}' in (ROOT / 'server/console/static/routing-ui.js').read_text()


def test_auto_check_refreshes_only_stale_cache(host, monkeypatch):
    import threading, time
    calls = []
    monkeypatch.setattr(protocols, 'check', lambda: calls.append(1))
    assert protocols.stale()

    class Stop(Exception):
        pass

    def wait(seconds):
        raise Stop
    with pytest.raises(Stop):
        protocols.auto_check(wait=wait)
    assert calls == [1]
    protocols.CACHE.parent.mkdir(parents=True, exist_ok=True)
    protocols.CACHE.write_text(json.dumps({'checked': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'components': {}}))
    assert not protocols.stale()
    with pytest.raises(Stop):
        protocols.auto_check(wait=wait)
    assert calls == [1]
    protocols.CACHE.write_text(json.dumps({'checked': '2020-01-01T00:00:00Z', 'components': {}}))
    assert protocols.stale()


def test_slow_manual_and_background_discovery_leave_mutation_lock_free(host, monkeypatch):
    import socket
    import threading
    import routing_agent
    entered = threading.Event()
    release = threading.Event()
    refreshed = threading.Event()
    manual_entered = threading.Event()
    errors = []
    peers = []
    workers = []
    observed = []
    lock = threading.Lock()
    monkeypatch.setattr(routing_agent.agent, 'LOCK', lock)

    def discover(name):
        entered.set()
        assert release.wait(3), 'Synthetic upstream did not finish'
        return []
    monkeypatch.setattr(protocols, 'discover', discover)

    def dispatch(op, data):
        if op == 'protocols.check':
            manual_entered.set()
            return protocols.check()
        observed.append(lock.locked())
        return {'mutation': 'accepted'}
    monkeypatch.setattr(routing_agent, 'dispatch', dispatch)

    class Stop(Exception):
        pass
    def wait(seconds):
        refreshed.set()
        raise Stop
    def background():
        try:
            protocols.auto_check(wait=wait)
        except Stop:
            pass
        except BaseException as error:
            errors.append(error)
    def request(op):
        client, peer = socket.socketpair()
        peers.extend((client, peer))
        client.settimeout(1)
        def handle():
            try:
                routing_agent.Handler(peer, None, None)
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=handle, daemon=True)
        workers.append(worker); worker.start()
        client.sendall((json.dumps({'op': op, 'data': {}})+'\n').encode())
        return client

    worker = threading.Thread(target=background, daemon=True)
    workers.append(worker); worker.start()
    try:
        assert entered.wait(1)
        manual = request('protocols.check')
        assert manual_entered.wait(1)
        # The manual refresh is serialized with the background writer, while a
        # VPN mutation can still execute without waiting for either GitHub call.
        mutation = request('routes.preview')
        result = json.loads(mutation.recv(4096))
        assert result == {'ok': True, 'result': {'mutation': 'accepted'}}
        assert observed == [True], 'VPN mutations must retain their own lock'
        release.set()
        assert json.loads(manual.recv(4096))['ok'] is True
        assert refreshed.wait(1)
    finally:
        release.set()
        for worker in workers:
            worker.join(3)
        for peer in peers:
            peer.close()
    assert not errors, errors
    assert all(not worker.is_alive() for worker in workers)
    assert isinstance(protocols.cached()['components'], dict)


def cdn_state(**settings):
    state = cdn.new_state('origin.example.invalid')
    state['settings'].update(settings)
    cdn.save(state)
    return state


def test_cdn_settings_are_validated_against_fixed_sets(host):
    current = cdn_state()['settings']
    good = cdn.validate({'domain': 'CDN.Example.com.', 'address': '104.16.0.1', 'origin_tls': False, 'origin_port': 8880,
                         'transport': 'xhttp', 'client_port': 2053}, current)
    assert good == dict(current, domain='cdn.example.com', address='104.16.0.1', origin_tls=False, origin_port=8880,
                        transport='xhttp', client_port=2053)
    assert cdn.validate({'regenerate_path': True}, current)['path'] != current['path']
    for bad in ({'domain': 'evil.com/x'}, {'domain': 'a b.com'}, {'origin_port': 443}, {'origin_port': 8880},
                {'origin_tls': False}, {'client_port': 80}, {'transport': 'grpc'}, {'path': '/../etc'},
                {'path': '/short'}, {'origin_port': '2053'}, {'image': 'evil'}, {'regenerate_path': 'yes'}):
        with pytest.raises(PolicyError):
            cdn.validate(bad, current)


def test_cdn_users_links_and_server_config(host):
    cdn_state()
    cdn.dispatch('cdn.create', {'username': 'alice'}, )
    cdn.dispatch('cdn.create', {'username': 'bob'})
    with pytest.raises(PolicyError, match='домен CDN'):
        cdn.dispatch('cdn.export', {'id': 1})
    state = cdn.load()
    state['settings'].update(domain='cdn.example.com', address='104.16.0.1')
    cdn.save(state)
    link = cdn.dispatch('cdn.export', {'id': 1})['content']
    alice, bob = state['users']
    assert link.startswith(f'vless://{alice["uuid"]}@104.16.0.1:443?')
    assert 'sni=cdn.example.com' in link and 'host=cdn.example.com' in link and 'type=ws' in link and '#CDN-alice' in link
    cdn.dispatch('cdn.block', {'id': 2})
    server = json.loads((cdn.RUNTIME / 'config.json').read_text())
    inbound = server['inbounds'][0]
    assert [c['id'] for c in inbound['settings']['clients']] == [alice['uuid']]
    assert inbound['port'] == 2053 and inbound['streamSettings']['security'] == 'tls'
    assert '/etc/letsencrypt/live/origin.example.invalid/' in inbound['streamSettings']['tlsSettings']['certificates'][0]['keyFile']
    assert '10.0.0.0/8' in server['routing']['rules'][0]['ip']
    with pytest.raises(PolicyError, match='заблокирован'):
        cdn.dispatch('cdn.export', {'id': 2})
    cdn.dispatch('cdn.rotate', {'id': 1})
    assert cdn.load()['users'][0]['uuid'] != alice['uuid']
    assert [u['username'] for u in cdn.users()] == ['alice', 'bob'] and 'uuid' not in json.dumps(cdn.users())
    for op, data in (('cdn.create', {'username': 'alice'}), ('cdn.create', {'username': 'x'}), ('cdn.block', {'id': '1'}),
                     ('cdn.delete', {'id': 1})):
        with pytest.raises(PolicyError):
            cdn.dispatch(op, data)


XRAY = {'version': '25.10.15', 'tag': 'v25.10.15', 'sha256': '2' * 64}


def test_cdn_install_then_configure_recreates_container(host, monkeypatch):
    import zipfile
    (protocols.ASSETS / 'xray').mkdir(parents=True)
    (protocols.ASSETS / 'xray/Dockerfile').write_text('fixture')
    monkeypatch.setattr(protocols, 'require_x86', lambda: None)

    def download(url, dest, sha256):
        assert url == 'https://github.com/XTLS/Xray-core/releases/download/v25.10.15/Xray-linux-64.zip' and sha256 == '2' * 64
        with zipfile.ZipFile(dest, 'w') as z:
            z.writestr('xray', b'binary')
    monkeypatch.setattr(protocols, 'download', download)
    monkeypatch.setattr(cdn, 'running', lambda: cdn.CONTAINER in host['containers'])
    monkeypatch.setattr(cdn, 'verify', lambda port: None)
    cache(cdn=[XRAY])
    agent = types.SimpleNamespace(ORIGIN='https://origin.example.invalid')
    result = protocols.dispatch('protocols.install', {'component': 'cdn'}, agent)
    assert 'TCP 2053' in result['message']
    start = next(c for c in host['calls'] if c[:2] == ['docker', 'run'])
    assert '2053:2053/tcp' in start and start[start.index('--cap-drop') + 1] == 'ALL' and start[-1] == 'vpn-xray:25.10.15'
    assert 'type=bind,src=/etc/letsencrypt,dst=/etc/letsencrypt,readonly' in start
    info = protocols.installed('cdn')
    assert info['installed'] and info['version'] == '25.10.15' and info['settings']['domain'] == ''

    host['calls'].clear()
    cdn.dispatch('cdn.configure', {'domain': 'cdn.example.com', 'origin_tls': False, 'origin_port': 2095})
    start = next(c for c in host['calls'] if c[:2] == ['docker', 'run'])
    assert '2095:2095/tcp' in start and not any('letsencrypt' in a for a in start)
    assert ['docker', 'rename', 'xray-cdn', 'xray-cdn-previous'] in host['calls']
    assert cdn.load()['settings']['domain'] == 'cdn.example.com'

    monkeypatch.setattr(cdn, 'verify', lambda port: (_ for _ in ()).throw(PolicyError('down')))
    with pytest.raises(PolicyError, match='не запустился'):
        cdn.dispatch('cdn.configure', {'domain': 'other.example.com'})
    assert cdn.load()['settings']['domain'] == 'cdn.example.com'


@pytest.mark.parametrize('change', [
    {'origin_port': 2083},
    {'origin_tls': False, 'origin_port': 2095, 'transport': 'xhttp', 'path': '/new-review-path'},
])
def test_cdn_rollback_restores_mounted_config_before_old_container_starts(host, monkeypatch, change):
    state = cdn_state(domain='cdn.example.com')
    state['image'] = 'vpn-xray:previous'
    cdn.save(state)
    before_state, before_config = cdn.STATE.read_text(), (cdn.RUNTIME / 'config.json').read_text()
    host['containers'].add(cdn.CONTAINER)
    plain = protocols.quiet
    starts = []
    def quiet(args, timeout=8):
        if args[:2] == ['docker', 'start']:
            starts.append(args[2])
            assert cdn.STATE.read_text() == before_state
            assert (cdn.RUNTIME / 'config.json').read_text() == before_config
        return plain(args, timeout)
    monkeypatch.setattr(protocols, 'quiet', quiet)
    monkeypatch.setattr(cdn, 'verify', lambda port: (_ for _ in ()).throw(PolicyError('new process failed')))
    with pytest.raises(PolicyError, match='не запустился'):
        cdn.configure(state, change)
    assert starts == [cdn.CONTAINER]


@pytest.mark.parametrize('existing', [False, True])
def test_cdn_install_failure_restores_files_before_restarting_previous(host, monkeypatch, tmp_path, existing):
    import zipfile
    work = tmp_path / 'cdn-build'
    work.mkdir()
    (protocols.ASSETS / 'xray').mkdir()
    (protocols.ASSETS / 'xray/Dockerfile').write_text('fixture')
    monkeypatch.setattr(protocols, 'require_x86', lambda: None)
    def download(url, dest, sha256):
        with zipfile.ZipFile(dest, 'w') as archive:
            archive.writestr('xray', b'fixture')
    monkeypatch.setattr(protocols, 'download', download)
    before = None
    if existing:
        state = cdn_state(domain='cdn.example.com')
        state.update(image='vpn-xray:previous', version='previous')
        cdn.save(state)
        before = (cdn.STATE.read_text(), (cdn.RUNTIME / 'config.json').read_text())
        host['containers'].add(cdn.CONTAINER)
    plain = protocols.quiet
    starts = []
    def quiet(args, timeout=8):
        if args[:2] == ['docker', 'start']:
            starts.append(args[2])
            assert (cdn.STATE.read_text(), (cdn.RUNTIME / 'config.json').read_text()) == before
        return plain(args, timeout)
    monkeypatch.setattr(protocols, 'quiet', quiet)
    monkeypatch.setattr(cdn, 'verify', lambda port: (_ for _ in ()).throw(PolicyError('new process failed')))
    with pytest.raises(PolicyError, match='не прошёл проверку'):
        protocols.install_cdn('protocols.update' if existing else 'protocols.install', {}, XRAY, work,
                              types.SimpleNamespace(ORIGIN='https://origin.example.invalid'))
    assert starts == ([cdn.CONTAINER] if existing else [])
    if not existing:
        assert not cdn.STATE.exists() and not (cdn.RUNTIME / 'config.json').exists()


def test_swap_does_not_start_previous_container_when_file_restore_fails(host):
    host['containers'].add('svc')
    def fail():
        raise PolicyError('failed')
    with pytest.raises(PolicyError):
        protocols.swap_container('svc', ['image'], fail, restore=fail)
    assert ['docker', 'start', 'svc'] not in host['calls']
