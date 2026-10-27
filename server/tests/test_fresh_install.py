"""Fresh installer input validation and preservation of existing host state."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fresh_installer', ROOT / 'deploy/install-fresh.py')
fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fresh)


@pytest.mark.parametrize('value', ['vpn.example.org', '203.0.113.10', 'VPN.Example.org'])
def test_public_address(value):
    assert fresh.address(value) == value.lower()


@pytest.mark.parametrize('value', ['https://vpn.example.org', '../escape', '-bad.example', 'a..b', '999.1.1.1',
                                   'a\nSECRET_KEY=bad', 'a:443', '::1', 'a/b', 'a;reboot'])
def test_reject_address_before_writing(value):
    with pytest.raises(ValueError):
        fresh.address(value)


@pytest.fixture
def host(tmp_path, monkeypatch):
    real_path = Path
    etc = tmp_path / 'os-release'
    etc.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    systemd = tmp_path / 'systemd'
    systemd.mkdir()
    monkeypatch.setattr(fresh, 'Path', lambda path: etc if path == '/etc/os-release' else systemd if path == '/run/systemd/system' else real_path(path))
    monkeypatch.setattr(fresh.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(fresh.host_platform, 'platform_id', lambda: 'ubuntu24')
    monkeypatch.setattr(fresh.platform, 'machine', lambda: 'x86_64')
    source = tmp_path / 'source'
    (source / 'client-source').mkdir(parents=True)
    (source / 'client-source/Cargo.lock').touch()
    monkeypatch.setattr(fresh, 'ROOT', source)
    monkeypatch.setattr(fresh, 'STATE', tmp_path / 'state')
    monkeypatch.setattr(fresh, 'MANAGED', (tmp_path / 'existing-vpn',))
    monkeypatch.setattr(fresh.shutil, 'which', lambda name: None)
    return tmp_path


def test_existing_install_is_preserved(host):
    existing = host / 'existing-vpn'
    existing.mkdir()
    state = existing / 'data.db'
    state.write_bytes(b'production-data')
    with pytest.raises(ValueError, match='чистый сервер'):
        fresh.preflight(False)
    assert state.read_bytes() == b'production-data'
    assert not fresh.STATE.exists()


def test_resume_requires_owned_state(host):
    with pytest.raises(ValueError, match='Нет прерванной'):
        fresh.preflight(True)
    fresh.STATE.mkdir()
    (fresh.STATE / 'settings.json').write_text('{}')
    # Existing managed directories are expected during recovery.
    fresh.MANAGED[0].mkdir()
    fresh.preflight(True)


def test_private_settings_permissions(tmp_path):
    path = tmp_path / 'settings.json'
    fresh.write(path, json.dumps({'password': 'synthetic-secret'}))
    assert path.stat().st_mode & 0o777 == 0o600


def test_trusttunnel_first_install_uses_resolved_local_base(tmp_path, monkeypatch):
    """Exercise endpoint image switch and backup, including BuildKit's FROM contract."""
    import contextlib
    import io
    import sqlite3
    import sys
    import tarfile
    sys.path.insert(0, str(ROOT / 'server/console'))
    import protocols
    import yaml
    monkeypatch.setattr(protocols, 'require_x86', lambda: None)
    monkeypatch.setattr(protocols, 'asset', lambda *parts: ROOT / 'deploy' / Path(*parts))
    compose = tmp_path / 'compose.yaml'
    compose.write_text('services:\n  trusttunnel-web:\n    image: original\n')
    database = tmp_path / 'portal.db'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE preserve(value TEXT)')
        db.execute("INSERT INTO preserve VALUES('existing-state')")
    monkeypatch.setattr(protocols, 'TT_COMPOSE', compose)
    monkeypatch.setattr(protocols, 'TT_DB', database)
    monkeypatch.setattr(protocols, 'ROLLBACK', tmp_path / 'rollback')
    monkeypatch.setattr(protocols.service_routes, 'PENDING', tmp_path / 'pending')
    monkeypatch.setattr(protocols.service_routes, 'TT_PROBE', tmp_path / 'absent-probe')
    monkeypatch.setattr(protocols.service_routes, 'route_lock', contextlib.nullcontext)
    base = 'sha256:' + 'a' * 64
    candidate = 'sha256:' + 'b' * 64
    calls, builds = [], []

    def run(args, *unused, **kwargs):
        calls.append(args)
        if args[:2] == ['docker', 'inspect']:
            return base
        if args[:3] == ['docker', 'image', 'inspect']:
            return candidate
        return ''

    def download(url, dest, digest):
        with tarfile.open(dest, 'w:gz') as archive:
            entry = tarfile.TarInfo('trusttunnel_endpoint')
            entry.size = 7
            archive.addfile(entry, io.BytesIO(b'fixture'))

    monkeypatch.setattr(protocols, 'run', run)
    monkeypatch.setattr(protocols, 'quiet', lambda *args, **kwargs: (0, '1.1.0'))
    monkeypatch.setattr(protocols, 'build', lambda args, timeout: builds.append(args))
    monkeypatch.setattr(protocols, 'download', download)
    work = tmp_path / 'work'
    work.mkdir()
    result = protocols.install_trusttunnel('protocols.install', {},
                                           {'version': '1.1.0', 'tag': 'v1.1.0', 'sha256': '1' * 64}, work, None)
    pinned = 'trusttunnel-web-base:' + 'a' * 64
    assert ['docker', 'tag', base, pinned] in calls
    assert 'BASE_IMAGE=' + pinned in builds[0]
    assert yaml.safe_load(compose.read_text())['services']['trusttunnel-web']['image'] == candidate
    backup = next(protocols.ROLLBACK.glob('*.db'))
    with sqlite3.connect(backup) as db:
        assert db.execute('SELECT value FROM preserve').fetchone()[0] == 'existing-state'
    assert '1.1.0' in result


@pytest.mark.parametrize('local_health,fail_final_health,agent_python', [
    (True, False, '/usr/bin/python3'), (False, False, '/usr/bin/python3'),
    (True, True, '/usr/bin/python3'), (True, False, '/opt/vpn-console/venv/bin/python3')])
def test_console_installer_keeps_cli_options_after_container_arguments(tmp_path, monkeypatch, local_health, fail_final_health, agent_python):
    """Exercise the installer through final health verification, with no host mutations."""
    import io
    import sys
    import types
    spec = importlib.util.spec_from_file_location('console_installer', ROOT / 'deploy/install-console.py')
    installer = importlib.util.module_from_spec(spec)
    # Import sets a restrictive umask for the standalone command; restore the test process.
    import os
    previous_mask = os.umask(0o077)
    try:
        spec.loader.exec_module(installer)
    finally:
        os.umask(previous_mask)
    real_path = Path

    def path(value):
        value = str(value)
        if value.startswith(('/opt/', '/etc/', '/root/', '/run/', '/var/lib/')):
            return tmp_path / 'host' / value.lstrip('/')
        return real_path(value)

    monkeypatch.setattr(installer, 'Path', path)
    monkeypatch.setattr(installer, 'DEST', tmp_path / 'console')
    monkeypatch.setattr(installer, 'BACK', tmp_path / 'console/backups/test')
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installer.os, 'chown', lambda *unused: None)
    monkeypatch.setattr(installer.time, 'sleep', lambda *unused: None)
    path('/etc/systemd/system').mkdir(parents=True)
    for folder in ('root', 'opt', 'var/lib', 'run'):
        (tmp_path / 'host' / folder).mkdir(parents=True, exist_ok=True)
    data = tmp_path / 'portal'
    data.mkdir()
    import sqlite3
    with sqlite3.connect(data / 'trusttunnel-web.db') as db:
        db.execute('CREATE TABLE preserve(value TEXT)')
    nginx = tmp_path / 'nginx.conf'
    nginx.write_text('server {\n    location / {\n    }\n}\n')
    current = {'Config': {'Env': ['SECRET_KEY=synthetic-installer-test', 'CONSOLE_AGENT_PYTHON=' + agent_python]}, 'Image': 'sha256:' + 'a' * 64,
               'Mounts': [{'Destination': '/data', 'Source': str(data)}, {'Destination': '/certs', 'Source': str(tmp_path)}]}
    if agent_python.startswith('/opt/'):
        current['Config']['Env'].append('CONSOLE_SELINUX_TYPE=vpn_console_t')
    calls = []

    def run(args):
        calls.append(args)
        return json.dumps([current]) if args == ['docker', 'inspect', 'trusttunnel-web'] else ''

    monkeypatch.setattr(installer, 'run', run)
    fallback_calls = []
    def fallback(args, **kwargs):
        fallback_calls.append(args)
        return types.SimpleNamespace(returncode=1, stdout='synthetic startup diagnostic', stderr='')
    monkeypatch.setattr(installer.subprocess, 'run', fallback)
    health_urls = []

    def urlopen(url, **kwargs):
        health_urls.append(url)
        if fail_final_health and len(health_urls) == 2:
            raise RuntimeError('synthetic final health failure')
        response = io.BytesIO(b'{"status":"ok"}')
        response.status = 200
        return response

    monkeypatch.setattr(installer.urllib.request, 'urlopen', urlopen)
    monkeypatch.setattr(sys, 'argv', ['install-console.py', '--nginx', str(nginx), '--origin', 'https://new.example.invalid']
                        + (['--local-health'] if local_health else []))
    if fail_final_health:
        with pytest.raises(RuntimeError, match='synthetic final health failure'):
            installer.main()
        assert ['systemctl', 'disable', '--now', 'vpn-console-agent'] in fallback_calls
        assert not path('/etc/systemd/system/vpn-console-agent.service').exists()
        assert (installer.BACK / 'console-startup.log').read_text() == 'synthetic startup diagnostic'
        assert '# BEGIN VPN CONSOLE' not in nginx.read_text()
        return
    installer.main()
    assert health_urls[-1] == ('http://127.0.0.1:18090/console/healthz' if local_health else 'https://new.example.invalid/console/healthz')
    assert any(command[:3] == ['docker', 'tag', current['Image']] for command in calls)
    assert '# BEGIN VPN CONSOLE' in nginx.read_text()
    assert (installer.BACK / 'portal.db').exists()
    assert 'ExecStart=' + agent_python + ' ' in path('/etc/systemd/system/vpn-console-agent.service').read_text()
    starts = [command for command in calls if command[:3] == ['docker', 'run', '-d']]
    assert ('label=type:vpn_console_t' in starts[0]) is agent_python.startswith('/opt/')


@pytest.mark.parametrize('version,python', [('9', '/usr/bin/python3.12'), ('10', '/usr/bin/python3')])
def test_centos_dependencies_isolate_agent_and_verify_rpm_key(tmp_path, monkeypatch, version, python):
    import io
    calls = []
    monkeypatch.setattr(fresh, 'ensure_kernel_modules', lambda: calls.append(['kernel-modules']))
    monkeypatch.setattr(fresh, 'install_selinux_policy', lambda: calls.append(['console-selinux-policy']))
    monkeypatch.setattr(fresh, 'Path', lambda value: tmp_path / str(value).lstrip('/'))
    monkeypatch.setattr(fresh, 'STATE', tmp_path / 'state')
    monkeypatch.setattr(fresh, 'run', lambda args, **kwargs: calls.append([str(arg) for arg in args]))
    monkeypatch.setattr(fresh.urllib.request, 'urlopen', lambda *args, **kwargs: io.BytesIO(b'synthetic-public-key'))
    monkeypatch.setattr(fresh.subprocess, 'check_output', lambda *args, **kwargs: 'fpr:::::::::060A61C51B558A7F742B77AAC52FEB6B621E9F35:\n')
    monkeypatch.setattr(fresh.host_platform, 'selinux_enabled', lambda: True)
    monkeypatch.setattr(fresh.host_platform, 'configure_container_labels', lambda: calls.append(['labels']))
    result = fresh.dependencies('centos-stream' + version)
    assert result == str(tmp_path / 'opt/vpn-console/venv/bin/python3')
    assert [python, '-m', 'venv', '--symlinks', str(tmp_path / 'opt/vpn-console/venv')] in calls
    assert json.loads((tmp_path / 'etc/docker/daemon.json').read_text())['selinux-enabled'] is True
    assert ['labels'] in calls
    assert not any('setenforce' in arg or '--allowerasing' in arg for call in calls for arg in call)
    assert 'gpgcheck=1' in (tmp_path / 'etc/yum.repos.d/tunnel-docker-ce.repo').read_text()
    # A key mismatch must stop before importing it or enabling a package source.
    calls.clear()
    monkeypatch.setattr(fresh.subprocess, 'check_output', lambda *args, **kwargs: 'fpr:::::::::BAD:\n')
    with pytest.raises(ValueError, match='отпечаток'):
        fresh.dependencies('centos-stream' + version)
    assert not any(call[0] == 'rpm' for call in calls)


@pytest.mark.parametrize('state,ok', [
    ({'error': 'Agent unavailable', 'users': []}, False),
    ({'users': []}, False),
    ({'protocols': {'items': [{'id': name} for name in ('trusttunnel', 'hysteria', 'cdn', 'amnezia')]}}, True),
])
def test_first_login_requires_working_agent_not_only_http_200(monkeypatch, state, ok):
    import io
    from types import SimpleNamespace
    monkeypatch.setattr(fresh.http.cookiejar, 'CookieJar', lambda: [SimpleNamespace(name='admin_token')])
    monkeypatch.setattr(fresh.ssl, 'create_default_context', lambda **kwargs: None)
    def open_response(url, *args, **kwargs):
        result = io.BytesIO(json.dumps(state if url.endswith('/state') else {}).encode())
        result.status = 200
        return result
    monkeypatch.setattr(fresh.urllib.request, 'build_opener', lambda *args: SimpleNamespace(open=open_response))
    if ok:
        fresh.check_login({'email': 'test@example.invalid', 'password': 'synthetic'}, Path('/unused'))
    else:
        with pytest.raises(RuntimeError, match='агент'):
            fresh.check_login({'email': 'test@example.invalid', 'password': 'synthetic'}, Path('/unused'))


def test_cloud_kernel_installs_modules_for_running_release(monkeypatch):
    from types import SimpleNamespace
    ready, calls = [False], []
    monkeypatch.setattr(fresh.platform, 'release', lambda: '6.12.0-278.el10.x86_64')
    monkeypatch.setattr(fresh.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0 if ready[0] else 1))
    def run(args, **kwargs):
        calls.append(args)
        ready[0] = True
    monkeypatch.setattr(fresh, 'run', run)
    fresh.ensure_kernel_modules()
    assert calls == [['dnf', 'install', '-y', 'kernel-modules-6.12.0-278.el10.x86_64']]


def test_cloud_kernel_requires_operator_reboot_when_running_modules_retired(monkeypatch):
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(fresh.platform, 'release', lambda: '6.12.0-old.el10.x86_64')
    monkeypatch.setattr(fresh.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1))
    def run(args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise fresh.subprocess.CalledProcessError(1, args)
    monkeypatch.setattr(fresh, 'run', run)
    with pytest.raises(ValueError, match='sudo reboot'):
        fresh.ensure_kernel_modules()
    assert calls[-1] == ['dnf', 'install', '-y', 'kernel', 'kernel-modules']
    assert not any(call[0] == 'reboot' for call in calls)


@pytest.mark.parametrize('tamper, arch', [(False, 'linux/amd64'), (True, 'linux/amd64'), (False, 'linux/arm64')])
def test_prebuilt_images_verified_before_and_after_load(tmp_path, monkeypatch, tamper, arch):
    import hashlib
    (tmp_path / 'images').mkdir()
    archive = tmp_path / 'images/tunnel-images.tar.gz'
    archive.write_bytes(b'synthetic image archive')
    digest = hashlib.sha256(b'synthetic image archive').hexdigest()
    (tmp_path / 'manifest.json').write_text(json.dumps({'images': {
        'archive': 'images/tunnel-images.tar.gz', 'sha256': '0' * 64 if tamper else digest,
        'tags': ['tunnel-fresh-portal:local', 'nginx:1.28-alpine']}}))
    calls = []
    monkeypatch.setattr(fresh, 'ROOT', tmp_path)
    monkeypatch.setattr(fresh, 'run', lambda args, **kwargs: calls.append(args))
    monkeypatch.setattr(fresh.subprocess, 'check_output', lambda *args, **kwargs: arch + '\n')
    if tamper or arch != 'linux/amd64':
        with pytest.raises(ValueError):
            fresh.load_images()
        assert calls == ([] if tamper else [['docker', 'load', '-i', archive]])
    else:
        fresh.load_images()
        assert calls == [['docker', 'load', '-i', archive]]
