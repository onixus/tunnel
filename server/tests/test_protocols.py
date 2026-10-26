"""Protocol lifecycle and AmneziaWG: fake GitHub, fake Docker, temporary state. No network, no live VPN."""
import base64
import hashlib
import hmac
import io
import json
import os
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
    monkeypatch.setattr(amnezia, 'ROUTING', home / 'routing.json')
    monkeypatch.setattr(amnezia, 'CIS', tmp_path / 'cis.json')
    (tmp_path / 'cis.json').write_text('{"version": 3, "rules": []}')
    monkeypatch.setattr(cdn, 'STATE', tmp_path / 'xray-cdn/state.json')
    monkeypatch.setattr(cdn, 'RUNTIME', tmp_path / 'xray-cdn/runtime')
    monkeypatch.setattr(cdn, 'ROUTING', tmp_path / 'xray-cdn/routing.json')
    for name in ('CACHE', 'ROLLBACK', 'BUILD', 'ASSETS'):
        monkeypatch.setattr(protocols, name, tmp_path / name.lower())
    (tmp_path / 'assets/amnezia').mkdir(parents=True)
    for name in ('Dockerfile', 'entrypoint.sh'):
        (tmp_path / 'assets/amnezia' / name).write_text('fixture')
    monkeypatch.setattr(protocols.service_routes, 'trusted', lambda path, executable=False: path.is_file())
    protocols._MEMO['value'] = None
    box = {'calls': [], 'port': None, 'containers': set(), 'tun': True}
    real_discover = protocols.discover
    monkeypatch.setattr(protocols, 'discover', lambda name: protocols.cached()['components'].get(name, {}).get('releases', [])
                        if name == 'amnezia' else real_discover(name))

    def run(args, timeout=30, env=None):
        box['calls'].append(args)
        if args[:2] == ['docker', 'run']:
            box['containers'].add(args[args.index('--name') + 1])
        if args[:2] == ['docker', 'exec'] and 'listen-port' in args:
            return str(box['port'] or '')
        if args[:2] == ['docker', 'exec'] and args[-1] == '--version':
            state = amnezia.load()
            if args[-2] == 'amneziawg-go':
                return 'amneziawg-go ' + box.get('server_version', state['version'])
            if args[-2] == 'awg':
                return 'amneziawg-tools v' + box.get('tools_version', state['tools_version']) + ' - https://amnezia.org'
        if args[:2] == ['docker', 'exec'] and args[-1] == amnezia.TUN:
            if not box['tun']:
                raise PolicyError('no tun')
            return '7: egress0: <POINTOPOINT,UP>'
        return ''

    real_download = protocols.download

    def download(url, dest, sha256):
        if 'SagerNet' not in url:
            return real_download(url, dest, sha256)
        # The official sing-box archive layout: a versioned directory holding the binary.
        assert url == 'https://github.com/SagerNet/sing-box/releases/download/v1.12.9/sing-box-1.12.9-linux-amd64.tar.gz'
        assert sha256 == '3' * 64
        import io, tarfile
        with tarfile.open(dest, 'w:gz') as tar:
            info = tarfile.TarInfo('sing-box-1.12.9-linux-amd64/sing-box')
            info.size = 6
            tar.addfile(info, io.BytesIO(b'binary'))
    monkeypatch.setattr(protocols, 'download', download)
    monkeypatch.setattr(protocols, 'require_x86', lambda: None)

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
    for op, data in (('amnezia.block', {'id': 99}), ('amnezia.block', {'id': '1'}), ('amnezia.delete', {'id': 99}),
                     ('amnezia.purge', {'id': 1})):
        with pytest.raises(PolicyError):
            amnezia.dispatch(op, data, 'h')
    assert amnezia.dispatch('amnezia.delete', {'id': 1}, 'h')['message']
    assert [p['id'] for p in amnezia.load()['peers']] == [2]
    assert rotated['public_key'] not in (amnezia.RUNTIME / 'awg0.conf').read_text()
    # Freed IDs are never reused: a stale link must not point at a new person.
    assert amnezia.dispatch('amnezia.create', {'username': 'carol'}, 'h')['id'] == 3


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
        # GitHub resolves /latest to the newest stable, non-draft release.
        'SagerNet/sing-box/releases/latest': release('v1.12.9', 'sing-box-1.12.9-linux-amd64.tar.gz'),
    }
    monkeypatch.setattr(protocols, 'api', lambda path: replies[path])
    assert [r['version'] for r in protocols.discover('hysteria')] == ['2.12.4']
    assert protocols.discover('trusttunnel') == [{'version': '1.1.0', 'tag': 'v1.1.0', 'sha256': '1' * 64, 'published': '2026-09-01'}]
    awg = protocols.discover('amnezia')
    # Only 3.1 tags; tools use the newest tag in the compatible protocol line.
    assert [(r['version'], r['commit'], r['tools_tag'], r['tools_commit']) for r in awg] == [
        ('3.1.20260828', 'a' * 40, 'v3.1.20260901', 'f' * 40), ('3.1.20260812', 'b' * 40, 'v3.1.20260901', 'f' * 40)]
    assert awg[0]['published'] == '2026-08-28'
    # Router: the latest stable 1.12+ release with a published digest, never a new major line.
    assert {(r['box_version'], r['box_tag'], r['box_sha256']) for r in awg} == {('1.12.9', 'v1.12.9', '1' * 64)}
    replies['SagerNet/sing-box/releases/latest'] = release('v2.0.0', 'sing-box-2.0.0-linux-amd64.tar.gz')
    assert not any('box_tag' in r for r in protocols.discover('amnezia'))


SETUP = 'R-TrustTunnel-Windows-x64-Setup.exe'


def git_sha(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def client_api(releases, sources):
    blobs = {}

    def api(path):
        if path == 'onixus/Rust-trustvpn/releases?per_page=30':
            return releases
        if '/git/blobs/' in path:
            return {'encoding': 'base64', 'content': base64.b64encode(blobs[path.rsplit('/', 1)[1]]).decode()}
        name, ref = path.split('?ref=')
        lib, root = sources[ref]
        data = lib if name.endswith('lib.rs') else root
        blobs[git_sha(data)] = data
        # Like GitHub, the contents API may mangle binary bytes; only the blob is trusted.
        return {'sha': git_sha(data), 'size': len(data), 'encoding': 'base64', 'content': base64.b64encode(b'mangled').decode()}
    return api


def lib(sequence):
    return f'pub const CURRENT_SEQUENCE: u64 = {sequence};\npub const CURRENT_IPC: u32 = 1;\n'.encode()


def test_client_releases_are_reported_with_build_identity(host, monkeypatch):
    root = bytes(range(32))
    releases = [release('v0.6.2', SETUP, html_url='https://evil.invalid/'), release('v0.6.2-beta.1', SETUP, prerelease=True),
                release('v0.6.1', 'R-TrustTunnel-Android.apk'), release('v0.6.0', SETUP), release('v0.7.0', SETUP, draft=True),
                {'tag_name': 'v0.5.9', 'assets': [{'name': SETUP, 'size': 1000}]}]  # no published digest
    monkeypatch.setattr(protocols, 'api', client_api(releases, {'v0.6.2': (lib(12), root), 'v0.6.0': (b'no constants', root)}))
    found = protocols.discover('client')
    assert [r['version'] for r in found] == ['0.6.2', '0.6.0']
    assert found[0] == {'version': '0.6.2', 'tag': 'v0.6.2', 'published': '2026-09-01', 'sha256': '1' * 64, 'size': 1000,
                        'url': 'https://github.com/onixus/Rust-trustvpn/releases/tag/v0.6.2', 'sequence': 12, 'ipc': 1, 'root': root.hex()}
    assert 'sequence' not in found[1] and found[1]['build_error']
    # A blob that does not hash to the advertised Git object is rejected.
    tampered = client_api(releases, {'v0.6.2': (lib(12), root)})
    def lying(path):
        reply = tampered(path)
        return dict(reply, content=base64.b64encode(lib(99)).decode()) if '/git/blobs/' in path else reply
    monkeypatch.setattr(protocols, 'api', lying)
    with pytest.raises(PolicyError, match='хешем'):
        protocols.source_file('onixus/Rust-trustvpn', 'crates/update/src/lib.rs', 'v0.6.2')

    monkeypatch.setattr(protocols, 'discover', lambda name: [{'version': '0.6.2'}] if name == 'client' else [])
    protocols.check()
    assert protocols.client_releases()['releases'] == [{'version': '0.6.2'}]

    def offline(name):
        raise OSError('GitHub down')
    monkeypatch.setattr(protocols, 'discover', offline)
    with pytest.raises(PolicyError, match='R-TrustTunnel'):
        protocols.check()
    kept = protocols.client_releases()
    assert kept['releases'] == [{'version': '0.6.2'}] and 'недоступен' in kept['error']


def test_client_release_is_signed_staged_and_immutable(host, tmp_path, monkeypatch):
    import agent as console_agent
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    key = Ed25519PrivateKey.generate()
    root = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub = tmp_path / 'root.pub'
    pub.write_bytes(root)
    feed = tmp_path / 'feed'
    monkeypatch.setattr(console_agent, 'ROOT_KEY', pub)
    monkeypatch.setattr(console_agent, 'FEED', feed)
    monkeypatch.setattr(protocols, 'CLIENT_KEY', tmp_path / 'update-signing.pk8')
    monkeypatch.setattr(protocols, 'KEY_OWNER', os.getuid())
    installer = b'signed installer bytes'
    entry = {'version': '0.6.2', 'tag': 'v0.6.2', 'published': '2026-10-20', 'sha256': hashlib.sha256(installer).hexdigest(),
             'size': len(installer), 'url': 'https://github.com/onixus/Rust-trustvpn/releases/tag/v0.6.2',
             'sequence': 12, 'ipc': 1, 'root': root.hex()}
    protocols.amnezia.write(protocols.CACHE, json.dumps({'checked': '2026-10-22T00:00:00Z', 'components': {}, 'client': {'releases': [entry]}}))
    fetched = []
    monkeypatch.setattr(protocols, 'open_url', lambda url: fetched.append(url) or io.BytesIO(installer))

    with pytest.raises(PolicyError, match='не установлен'):
        protocols.publish_client({'version': '0.6.2'}, console_agent)
    assert protocols.client_releases(console_agent)['signing']
    other = Ed25519PrivateKey.generate().private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    protocols.CLIENT_KEY.write_bytes(other)
    protocols.CLIENT_KEY.chmod(0o644)
    with pytest.raises(PolicyError, match='0600'):
        protocols.publish_client({'version': '0.6.2'}, console_agent)
    protocols.CLIENT_KEY.chmod(0o600)
    with pytest.raises(PolicyError, match='не совпадает'):
        protocols.publish_client({'version': '0.6.2'}, console_agent)
    protocols.CLIENT_KEY.write_bytes(key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))
    view = protocols.client_releases(console_agent)
    assert view['signing'] is None and view['releases'][0]['root_ok'] and 'root' not in view['releases'][0]
    for bad in ({'version': '0.6.1'}, {'version': '0.6.2', 'sequence': 1}, {}):
        with pytest.raises(PolicyError):
            protocols.publish_client(bad, console_agent)
    assert not feed.exists() and not fetched

    result = protocols.publish_client({'version': '0.6.2'}, console_agent)
    assert 'sequence 12' in result['message']
    assert fetched == ['https://github.com/onixus/Rust-trustvpn/releases/download/v0.6.2/' + SETUP]
    folder = feed / '12' / 'windows-x86_64'
    assert (folder / 'setup.exe').read_bytes() == installer
    assert sorted(p.name for p in folder.iterdir()) == ['manifest.json', 'setup.exe']
    assert (folder / 'manifest.json').stat().st_mode & 0o777 == 0o644
    assert folder.stat().st_mode & 0o777 == folder.parent.stat().st_mode & 0o777 == 0o755
    manifest, _ = console_agent.verify_manifest(folder / 'manifest.json', artifact=True)
    assert (manifest['sequence'], manifest['version'], manifest['min_ipc'], manifest['max_ipc']) == (12, '0.6.2', 1, 1)
    assert manifest['expires'] - manifest['published'] == 30 * 86400
    assert manifest['url'] == 'https://onixus-rf.duckdns.org/rtrust/releases/12/windows-x86_64/setup.exe'
    with pytest.raises(PolicyError, match='неизменяемы'):
        protocols.publish_client({'version': '0.6.2'}, console_agent)

    # A tampered download never leaves a partial release behind.
    entry.update(version='0.6.3', tag='v0.6.3', sequence=13)
    protocols.amnezia.write(protocols.CACHE, json.dumps({'checked': '2026-10-22T00:00:00Z', 'components': {}, 'client': {'releases': [entry]}}))
    monkeypatch.setattr(protocols, 'open_url', lambda url: io.BytesIO(b'tampered'))
    with pytest.raises(PolicyError, match='Хеш'):
        protocols.publish_client({'version': '0.6.3'}, console_agent)
    assert not (feed / '13').exists()
    # A release built against another root is refused before any download.
    entry.update(root='00' * 32)
    protocols.amnezia.write(protocols.CACHE, json.dumps({'checked': '2026-10-22T00:00:00Z', 'components': {}, 'client': {'releases': [entry]}}))
    with pytest.raises(PolicyError, match='другим корнем'):
        protocols.publish_client({'version': '0.6.3'}, console_agent)


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


AWG = {'version': '3.1.20260828', 'tag': 'v3.1.20260828', 'commit': 'a' * 40, 'tools_tag': 'v3.1.20260812', 'tools_version': '3.1.20260812',
       'tools_commit': 'e' * 40,
       'box_version': '1.12.9', 'box_tag': 'v1.12.9', 'box_sha256': '3' * 64}


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
    assert '--network' not in start and not (amnezia.RUNTIME / 'route.json').exists()
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


def test_amnezia_install_refreshes_server_tags_and_refuses_stale_cache(host, monkeypatch):
    cache(amnezia=[AWG])
    latest = dict(AWG, version='3.1.20260915', tag='v3.1.20260915', commit='9' * 40)
    checked = []
    def discover(name):
        checked.append(name)
        return [latest, AWG]
    monkeypatch.setattr(protocols, 'discover', discover)
    host['port'] = 47443
    protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert checked == ['amnezia']
    assert amnezia.load()['version'] == latest['version']
    def offline(name):
        raise OSError('offline')
    monkeypatch.setattr(protocols, 'discover', offline)
    host['calls'].clear()
    with pytest.raises(PolicyError, match='актуальную серверную версию'):
        protocols.install('protocols.update', {'component': 'amnezia'}, None)
    assert not any(c[:2] == ['docker', 'build'] for c in host['calls'])


@pytest.mark.parametrize('field', ['server_version', 'tools_version'])
def test_amnezia_binary_version_mismatch_rolls_back_first_install(host, field):
    cache(amnezia=[AWG])
    host.update(port=47443, **{field: '0.0.20250522'})
    with pytest.raises(PolicyError, match='не прошёл проверку'):
        protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert not amnezia.STATE.exists()
    assert amnezia.CONTAINER not in host['containers']


def test_amnezia_status_reads_binaries_and_allows_tools_only_update(host):
    cache(amnezia=[AWG])
    host['port'] = 47443
    protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    # Images built before provenance report upstream's legacy constant: unknown, not 0.0.
    host['server_version'] = '0.0.20250522'
    assert protocols.installed('amnezia')['version'] is None
    del host['server_version']
    newer = dict(AWG, tools_tag='v3.1.20260901', tools_version='3.1.20260901', tools_commit='f' * 40)
    cache(amnezia=[newer])
    item = next(i for i in protocols.status()['items'] if i['id'] == 'amnezia')
    assert item['update'] and item['tools_version'] == '3.1.20260812' and item['tools_latest'] == '3.1.20260901'
    protocols.install('protocols.update', {'component': 'amnezia'}, None)
    assert protocols.installed('amnezia')['tools_version'] == '3.1.20260901'


def test_amnezia_existing_unmanaged_container_is_not_overwritten_as_fresh(host):
    host['containers'].add(amnezia.CONTAINER)
    assert protocols.installed('amnezia')['installed']
    with pytest.raises(PolicyError, match='уже установлен'):
        protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)


def test_amnezia_update_wrong_binary_restores_state_and_container(host):
    cache(amnezia=[AWG])
    host['port'] = 47443
    protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    before = amnezia.STATE.read_text()
    cache(amnezia=[dict(AWG, tools_tag='v3.1.20260901', tools_version='3.1.20260901')])
    host['tools_version'] = '3.1.20260812'
    with pytest.raises(PolicyError, match='не прошёл проверку'):
        protocols.install('protocols.update', {'component': 'amnezia'}, None)
    assert amnezia.STATE.read_text() == before
    assert ['docker', 'rename', 'amnezia-awg-previous', 'amnezia-awg'] in host['calls']


def test_amnezia_stopped_container_does_not_report_saved_version(host, monkeypatch):
    state = amnezia.new_state(47443)
    state['version'] = AWG['version']
    amnezia.save(state, sync=False)
    monkeypatch.setattr(protocols, 'quiet', lambda args, timeout=8: (0, 'exited'))
    assert protocols.installed('amnezia') == {
        'installed': True, 'version': None, 'tools_version': None, 'state': 'exited', 'port': 47443}
    # Existing deployments can still switch routes before their first upgrade.
    host['port'] = 47443
    amnezia.verify(state, attempts=1)


def test_amnezia_new_install_requires_userspace_socket(host, monkeypatch):
    cache(amnezia=[AWG])
    host['port'] = 47443
    original = amnezia.run
    def run(args, timeout=30):
        if args[-3:] == ['test', '-S', '/var/run/amneziawg/awg0.sock']:
            raise PolicyError('no userspace socket')
        return original(args, timeout)
    monkeypatch.setattr(amnezia, 'run', run)
    with pytest.raises(PolicyError, match='не прошёл проверку'):
        protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert not amnezia.STATE.exists()


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
                     ('cdn.delete', {'id': 99}), ('cdn.purge', {'id': 1})):
        with pytest.raises(PolicyError):
            cdn.dispatch(op, data)
    uuid = cdn.load()['users'][0]['uuid']
    cdn.dispatch('cdn.delete', {'id': 1})
    assert [u['username'] for u in cdn.users()] == ['bob']
    assert uuid not in (cdn.RUNTIME / 'config.json').read_text()
    assert cdn.dispatch('cdn.create', {'username': 'carol'})['id'] == 3


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


def test_cdn_route_switch_recreates_xray_on_exit_network_and_rolls_back(host, monkeypatch, tmp_path):
    cdn_state()
    state = cdn.load()
    state['image'] = 'vpn-xray:25.10.15'
    cdn.save(state)
    monkeypatch.setattr(cdn, 'verify', lambda port: None)
    geoip = tmp_path / 'geoip.dat'
    geoip.write_bytes(b'geo')
    profile = {'outbound': {'name': 'onixus', 'type': 'socks5',
               'socks5': {'addr': '127.0.0.1:10810', 'username': 'u', 'password': 'p'}}}
    routed = json.dumps(cdn.routing_config('primary', {'primary': profile}, ['local(geoip:ru)', 'onixus(all)'],
                                           ['203.0.113.9'], geoip))
    cdn.apply_routing(routed)
    start = next(c for c in host['calls'] if c[:2] == ['docker', 'run'])
    assert start[start.index('--network') + 1] == 'trusttunnel-web_default' and 'XRAY_LOCATION_ASSET=/etc/xray' in start
    assert (cdn.RUNTIME / 'geoip.dat').read_bytes() == b'geo' and cdn.current_routing() == routed
    assert cdn.actual_exit(cdn.load()) == 'primary'

    # A failed start restores the previous routing before the old container reads the mounted files.
    host['calls'].clear()
    monkeypatch.setattr(cdn, 'verify', lambda port: (_ for _ in ()).throw(PolicyError('down')))
    with pytest.raises(PolicyError, match='не запустился'):
        cdn.apply_routing(None)
    assert cdn.current_routing() == routed and cdn.actual_exit(cdn.load()) == 'primary'
    assert ['docker', 'rename', 'xray-cdn-previous', 'xray-cdn'] in host['calls']

    monkeypatch.setattr(cdn, 'verify', lambda port: None)
    host['calls'].clear()
    cdn.apply_routing(None)
    start = next(c for c in host['calls'] if c[:2] == ['docker', 'run'])
    assert '--network' not in start and cdn.actual_exit(cdn.load()) == 'direct'


def test_amnezia_route_switch_runs_router_on_exit_network_and_fails_closed(host, monkeypatch):
    host['port'] = 47443
    cache(amnezia=[AWG])
    protocols.dispatch('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert amnezia.actual_exit() == 'direct'
    profile = {'outbound': {'name': 'onixus', 'type': 'socks5',
               'socks5': {'addr': '127.0.0.1:10810', 'username': 'u', 'password': 'p'}}}
    routed = json.dumps(amnezia.routing_config('primary', {'primary': profile}, ['local(suffix:ru)', 'onixus(all)'],
                                               ['203.0.113.9']))
    host['calls'].clear()
    amnezia.apply_routing(routed)
    start = next(c for c in host['calls'] if c[:2] == ['docker', 'run'])
    assert start[start.index('--network') + 1] == 'trusttunnel-web_default' and 'net.ipv4.conf.all.rp_filter=0' in start
    assert (amnezia.RUNTIME / 'blocked').read_text() == '203.0.113.9\n' and (amnezia.RUNTIME / 'cis.json').exists()
    route = json.loads((amnezia.RUNTIME / 'route.json').read_text())
    assert route['outbounds'][0]['server'] == '172.18.0.1' and amnezia.actual_exit() == 'primary'
    # Peer edits re-render only awg0.conf; the router keeps its exit.
    amnezia.dispatch('amnezia.create', {'username': 'alice'}, 'h')
    assert amnezia.actual_exit() == 'primary'

    # Without its TUN the new container fails the check; the old one returns with the old files.
    host['tun'] = False
    host['calls'].clear()
    with pytest.raises(PolicyError, match='не запустился'):
        amnezia.apply_routing(json.dumps(amnezia.routing_config('primary', {'primary': profile}, ['onixus(all)'], [])))
    assert amnezia.current_routing() == routed and amnezia.actual_exit() == 'primary'
    assert ['docker', 'rename', 'amnezia-awg-previous', 'amnezia-awg'] in host['calls']

    host['tun'] = True
    amnezia.apply_routing(None)
    assert not any((amnezia.RUNTIME / n).exists() for n in amnezia.ROUTE_FILES) and amnezia.actual_exit() == 'direct'


def test_amnezia_install_requires_a_verified_router_release(host):
    cache(amnezia=[{k: v for k, v in AWG.items() if not k.startswith('box_')}])
    with pytest.raises(PolicyError, match='sing-box'):
        protocols.dispatch('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert not any(c[:2] == ['docker', 'build'] for c in host['calls'])


def test_amnezia_unknown_binary_version_still_refuses_downgrade(host, monkeypatch):
    cache(amnezia=[AWG])
    host['port'] = 47443
    protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    older = dict(AWG, version='3.1.20260812', tag='v3.1.20260812')
    cache(amnezia=[AWG, older])
    for server in ('0.0.20230223', None):
        if server:
            host['server_version'] = server
        else:
            monkeypatch.setattr(protocols, 'quiet', lambda args, timeout=8: (0, 'exited'))
        assert protocols.installed('amnezia')['version'] is None
        with pytest.raises(PolicyError, match='Понижение'):
            protocols.install('protocols.update', {'component': 'amnezia', 'version': '3.1.20260812'}, None)
    assert sum(c[:2] == ['docker', 'build'] for c in host['calls']) == 1


def test_amnezia_install_rejects_inconsistent_tools_version_and_refreshes_cache(host, monkeypatch):
    latest = dict(AWG, version='3.1.20260915', tag='v3.1.20260915', commit='9' * 40)
    monkeypatch.setattr(protocols, 'discover', lambda name: [dict(latest, tools_version='3.1.20260901')])
    host['port'] = 47443
    with pytest.raises(PolicyError, match='Некорректные данные'):
        protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    assert protocols.cached()['components']['amnezia']['releases'][0]['version'] == '3.1.20260915'
    for version in (['3.1.20260915'], '3.1.20260915; id'):
        with pytest.raises(PolicyError, match='Некорректная версия'):
            protocols.install('protocols.install', {'component': 'amnezia', 'version': version, 'port': 47443}, None)


def test_amnezia_versions_are_read_once_per_container(host, monkeypatch):
    cache(amnezia=[AWG])
    host['port'] = 47443
    protocols.install('protocols.install', {'component': 'amnezia', 'port': 47443}, None)
    real = protocols.quiet
    ids = {'id': 'a' * 64}
    def quiet(args, timeout=8):
        code, out = real(args, timeout)
        return (code, out + ' ' + ids['id']) if args[:2] == ['docker', 'inspect'] and code == 0 else (code, out)
    monkeypatch.setattr(protocols, 'quiet', quiet)
    monkeypatch.setattr(protocols, '_AWG_VERSIONS', {})
    reads = lambda: sum(c[-1] == '--version' for c in host['calls'])
    host['calls'].clear()
    protocols.installed('amnezia'), protocols.installed('amnezia')
    assert reads() == 2
    ids['id'] = 'b' * 64
    assert protocols.installed('amnezia')['tools_version'] == '3.1.20260812' and reads() == 4
