"""Protocol lifecycle for the root agent: status, container monitoring, install and update.

Sources are a fixed registry of the protocol developers' GitHub repositories. A request can
only name a component and a version already discovered there; it never supplies a URL, path,
image or command. Binaries are checked against the SHA-256 GitHub publishes for the release
asset; source builds are pinned to the commit GitHub reported for the tag.
"""
import base64
import calendar
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile

import yaml

import amnezia
import cdn
from routing_policy import PolicyError
import service_routes

BASE = Path('/opt/vpn-console')
CACHE = BASE / 'protocols/releases.json'
ROLLBACK = BASE / 'protocols/rollback'
BUILD = BASE / 'build'
ASSETS = BASE / 'assets'
API = 'https://api.github.com/repos/'
LIMIT = 64 * 1024 * 1024
AUTO_CHECK = 6 * 3600
CHECK_LOCK = threading.RLock()
HYSTERIA_BIN = Path('/var/lib/h-ui/bin/hysteria-linux-amd64')
HYSTERIA_UNIT = Path('/etc/systemd/system/h-ui.service')
TT_CONTAINER = 'trusttunnel-web'
TT_COMPOSE = Path('/opt/trusttunnel-web/compose.yaml')
TT_DB = Path('/opt/trusttunnel-web/data/trusttunnel-web.db')
TT_ENDPOINT = '/opt/trusttunnel/trusttunnel_endpoint'
SHA = re.compile('[0-9a-f]{40}')
IMAGE_ID = re.compile('sha256:[0-9a-f]{64}')

SOURCES = {
    'hysteria': {'title': 'Hysteria 2', 'repo': 'HyNetworks/hysteria', 'tag': r'app/v(\d+\.\d+\.\d+)',
                 'asset': 'hysteria-linux-amd64', 'runtime': 'systemd · h-ui'},
    'trusttunnel': {'title': 'TrustTunnel', 'repo': 'TrustTunnel/TrustTunnel', 'tag': r'v(\d+\.\d+\.\d+)',
                    'asset': 'trusttunnel-{tag}-linux-x86_64.tar.gz', 'runtime': 'docker · ' + TT_CONTAINER},
    'amnezia': {'title': 'AmneziaWG 3.1', 'repo': 'amnezia-vpn/amneziawg-go', 'tools': 'amnezia-vpn/amneziawg-tools',
                'tag': r'v(3\.1\.\d{8})', 'runtime': 'docker · ' + amnezia.CONTAINER},
    'cdn': {'title': 'VLESS через CDN', 'repo': 'XTLS/Xray-core', 'tag': r'v(\d+\.\d+\.\d+)',
            'asset': 'Xray-linux-64.zip', 'runtime': 'docker · ' + cdn.CONTAINER},
}
# The desktop client is published like a protocol: the installer is downloaded against
# the digest GitHub publishes, and the agent signs a manifest with the pinned update root.
# Sequence and IPC version come from the tagged source the installer was built from.
CLIENT = {'title': 'R-TrustTunnel', 'repo': 'onixus/Rust-trustvpn', 'tag': r'v(\d+\.\d+\.\d+)',
          'asset': 'R-TrustTunnel-Windows-x64-Setup.exe'}
CLIENT_KEY = BASE / 'update-signing.pk8'
KEY_OWNER = 0
CLIENT_LIFETIME = 30 * 86400
# The console drives H UI through its 0.0.25 API and database layout; see docs/versions.md.
HUI = {'repo': 'jonssonyan/h-ui', 'tag': 'v0.0.25', 'asset': 'h-ui-linux-amd64',
       'sha256': '900ed683b3a3af3a79e5bdcc691b9f3db82f1758545f0f603f8bdecd9d1cd7ee'}
ROLES = {TT_CONTAINER: 'TrustTunnel и портал', amnezia.CONTAINER: 'AmneziaWG', cdn.CONTAINER: 'VLESS через CDN', 'vpn-console': 'Консоль',
         'vpn-adblock': 'Фильтр рекламы', 'rtrust-portal-https': 'HTTPS-вход'}
UNITS = (('h-ui', 'Hysteria 2 / H UI'), ('vpn-console-agent', 'Агент консоли'), ('vpn-telegram', 'Telegram-бот'),
         ('vpn-adblock-dns', 'Перехват DNS'), ('docker', 'Docker Engine'))
_MEMO = {'at': 0.0, 'value': None}


def run(args, timeout=30, env=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if p.returncode:
        raise PolicyError('Операция не завершена: ' + Path(args[0]).name)
    return p.stdout.strip()


def quiet(args, timeout=8):
    """Status probes: a stopped service or missing container is an answer, not an error."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 1, ''


def key(version):
    return tuple(int(part) for part in version.split('.'))


class GitHubOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        host = url.hostname or ''
        if url.scheme != 'https' or not (host in ('github.com', 'api.github.com') or host.endswith('.githubusercontent.com')):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'vpn-console'})
    return urllib.request.build_opener(GitHubOnly).open(request, timeout=30)


def api(path):
    for attempt in (0, 1):
        try:
            with open_url(API + path) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            break
        except OSError:
            # The GitHub API intermittently times out; one retry, then report.
            if attempt:
                raise
    if len(raw) > 4 * 1024 * 1024:
        raise PolicyError('Слишком большой ответ GitHub')
    return json.loads(raw)


def download(url, dest, sha256):
    digest = hashlib.sha256()
    size = 0
    with open_url(url) as response, open(dest, 'wb') as stream:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > LIMIT:
                raise PolicyError('Артефакт превышает допустимый размер')
            digest.update(chunk)
            stream.write(chunk)
    if not hmac.compare_digest(digest.hexdigest(), sha256):
        raise PolicyError('Хеш загруженного артефакта не совпадает с опубликованным разработчиком')


def asset_url(repo, tag, asset):
    return f'https://github.com/{repo}/releases/download/{tag}/{asset}'


def source_file(repo, path, tag):
    # The contents API re-encodes some binary files as text; the blob is the exact bytes.
    entry = api(f'{repo}/contents/{path}?ref={urllib.parse.quote(tag)}')
    if not SHA.fullmatch(str(entry.get('sha', ''))) or not 0 < entry.get('size', 0) <= 1024 * 1024:
        raise PolicyError('Неожиданный ответ GitHub для исходника релиза')
    blob = api(f"{repo}/git/blobs/{entry['sha']}")
    if blob.get('encoding') != 'base64':
        raise PolicyError('Неожиданный ответ GitHub для исходника релиза')
    data = base64.b64decode(blob['content'])
    if len(data) != entry['size'] or hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest() != entry['sha']:
        raise PolicyError('Исходник релиза не совпадает со своим хешем в Git')
    return data


def client_build(tag):
    # The manifest must carry the sequence and IPC version compiled into this installer.
    text = source_file(CLIENT['repo'], 'crates/update/src/lib.rs', tag).decode()
    sequence = re.search(r'pub const CURRENT_SEQUENCE: u64 = (\d{1,9});', text)
    ipc = re.search(r'pub const CURRENT_IPC: u32 = (\d{1,4});', text)
    if not sequence or not ipc:
        raise PolicyError('В исходнике релиза нет номера sequence или версии IPC')
    root = source_file(CLIENT['repo'], 'crates/update/src/root.pub', tag)
    return {'sequence': int(sequence[1]), 'ipc': int(ipc[1]), 'root': root.hex()}


def discover(name):
    if name == 'client':
        found = []
        for release in api(CLIENT['repo'] + '/releases?per_page=30'):
            match = re.fullmatch(CLIENT['tag'], str(release.get('tag_name', '')))
            if not match or release.get('draft') or release.get('prerelease'):
                continue
            asset = next((a for a in release.get('assets', []) if a.get('name') == CLIENT['asset']), None)
            digest = str((asset or {}).get('digest') or '')
            if not asset or not re.fullmatch('sha256:[0-9a-f]{64}', digest) or not 0 < asset.get('size', 0) <= LIMIT:
                continue
            # The link is built locally; nothing from the API reaches the page as a URL.
            found.append({'version': match[1], 'tag': release['tag_name'], 'published': str(release.get('published_at', ''))[:10],
                          'sha256': digest[7:], 'size': asset['size'],
                          'url': f"https://github.com/{CLIENT['repo']}/releases/tag/{release['tag_name']}"})
        found = sorted(found, key=lambda r: key(r['version']), reverse=True)[:5]
        for release in found:
            try:
                release.update(client_build(release['tag']))
            except (PolicyError, ValueError, UnicodeError):
                # Shown without a publish action; other releases stay usable.
                release['build_error'] = 'Не удалось прочитать sequence и IPC из исходника релиза'
        return found
    src = SOURCES[name]
    found = []
    if name == 'amnezia':
        def tags(repo):
            result = {}
            for item in api(repo + '/tags?per_page=50'):
                match = re.fullmatch(src['tag'], str(item.get('name', '')))
                commit = str(item.get('commit', {}).get('sha', ''))
                if match and SHA.fullmatch(commit):
                    result[match[1]] = (item['name'], commit)
            return result
        core, tools = tags(src['repo']), tags(src['tools'])
        for version, (tag, commit) in core.items():
            # The newest tools tag that is not newer than the protocol tag.
            fit = [v for v in tools if key(v) <= key(version)]
            if fit:
                tools_tag, tools_commit = tools[max(fit, key=key)]
                date = version.rsplit('.', 1)[1]
                found.append({'version': version, 'tag': tag, 'commit': commit, 'tools_tag': tools_tag,
                              'tools_commit': tools_commit, 'published': f'{date[:4]}-{date[4:6]}-{date[6:]}'})
    else:
        for release in api(src['repo'] + '/releases?per_page=30'):
            match = re.fullmatch(src['tag'], str(release.get('tag_name', '')))
            if not match or release.get('draft') or release.get('prerelease'):
                continue
            wanted = src['asset'].format(tag=release['tag_name'])
            asset = next((a for a in release.get('assets', []) if a.get('name') == wanted), None)
            digest = str((asset or {}).get('digest') or '')
            if not asset or not re.fullmatch('sha256:[0-9a-f]{64}', digest) or not 0 < asset.get('size', 0) <= LIMIT:
                continue
            found.append({'version': match[1], 'tag': release['tag_name'], 'sha256': digest[7:],
                          'published': str(release.get('published_at', ''))[:10]})
    return sorted(found, key=lambda r: key(r['version']), reverse=True)[:5]


def cached():
    try:
        value = json.loads(CACHE.read_text())
        return value if isinstance(value.get('components'), dict) else {'components': {}}
    except (OSError, ValueError, AttributeError):
        return {'components': {}}


def check(data=None):
    # Discovery may take minutes during an upstream outage. Serialize cache writers
    # independently of the agent's VPN mutation lock.
    with CHECK_LOCK:
        return _check(data)


def _check(data=None):
    if data:
        raise PolicyError('Некорректные параметры')
    old = cached()['components']
    result = {'checked': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'components': {}}
    failed = []
    for name in SOURCES:
        try:
            result['components'][name] = {'releases': discover(name)}
        except Exception:
            failed.append(SOURCES[name]['title'])
            result['components'][name] = {'releases': old.get(name, {}).get('releases', []),
                                          'error': 'Репозиторий разработчика недоступен; показаны прежние данные'}
    try:
        result['client'] = {'releases': discover('client')}
    except Exception:
        failed.append(CLIENT['title'])
        result['client'] = {'releases': cached().get('client', {}).get('releases', []),
                            'error': 'Репозиторий клиента недоступен; показаны прежние данные'}
    amnezia.write(CACHE, json.dumps(result, sort_keys=True))
    _MEMO['value'] = None
    if failed:
        raise PolicyError('Не удалось получить версии: ' + ', '.join(failed))
    return {'message': 'Версии в репозиториях разработчиков проверены'}


def signing_key(agent):
    """The root-only update key, accepted only if it is the root pinned in clients."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_private_key
    try:
        info = CLIENT_KEY.stat()
    except FileNotFoundError:
        raise PolicyError(f'Ключ подписи обновлений не установлен: {CLIENT_KEY}') from None
    if info.st_uid != KEY_OWNER or info.st_mode & 0o077:
        raise PolicyError('Ключ подписи обновлений должен принадлежать root с правами 0600')
    try:
        key = load_der_private_key(CLIENT_KEY.read_bytes(), None)
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (ValueError, TypeError, AttributeError):
        raise PolicyError('Ключ подписи обновлений повреждён или не Ed25519') from None
    if not hmac.compare_digest(public, agent.ROOT_KEY.read_bytes()):
        raise PolicyError('Ключ подписи не совпадает с корнем, закреплённым в клиентах')
    return key


def client_releases(agent=None):
    value = cached()
    client = value.get('client') if isinstance(value.get('client'), dict) else {}
    result = {'releases': client.get('releases', []), 'error': client.get('error'), 'checked': value.get('checked'),
              'repo': 'https://github.com/' + CLIENT['repo']}
    if agent is not None:
        root = agent.ROOT_KEY.read_bytes().hex()
        result['releases'] = [dict({k: v for k, v in r.items() if k != 'root'}, root_ok=r.get('root') == root)
                              for r in result['releases']]
        try:
            signing_key(agent)
            result['signing'] = None
        except PolicyError as exc:
            result['signing'] = str(exc)
    return result


def publish_client(data, agent):
    """Stage a discovered client release in the update feed; promotion stays a separate step."""
    if set(data) != {'version'} or not isinstance(data['version'], str):
        raise PolicyError('Некорректные параметры')
    release = next((r for r in cached().get('client', {}).get('releases', []) if r.get('version') == data['version']), None)
    if release is None or type(release.get('sequence')) is not int or not 0 < release['sequence'] < 10 ** 9:
        raise PolicyError('Версия не найдена среди проверенных релизов. Проверьте GitHub заново.')
    if release.get('root') != agent.ROOT_KEY.read_bytes().hex():
        raise PolicyError('Релиз собран с другим корнем обновлений; клиенты его не примут')
    key = signing_key(agent)
    target = 'windows-x86_64'
    folder = agent.FEED / str(release['sequence']) / target
    if folder.exists():
        raise PolicyError(f"Sequence {release['sequence']} уже выложен; выложенные релизы неизменяемы")
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='client-', dir=BUILD))
    try:
        installer = work / 'setup.exe'
        download(asset_url(CLIENT['repo'], release['tag'], CLIENT['asset']), installer, release['sha256'])
        if installer.stat().st_size != release['size']:
            raise PolicyError('Размер установщика не совпадает с опубликованным на GitHub')
        now = int(time.time())
        payload = json.dumps({'schema': 1, 'sequence': release['sequence'], 'version': release['version'], 'target': target,
                              'min_ipc': release['ipc'], 'max_ipc': release['ipc'], 'published': now,
                              'expires': now + CLIENT_LIFETIME, 'size': release['size'], 'sha256': release['sha256'],
                              'url': f"https://onixus-rf.duckdns.org/rtrust/releases/{release['sequence']}/{target}/setup.exe"},
                             separators=(',', ':')).encode()
        envelope = json.dumps({'payload': base64.b64encode(payload).decode(),
                               'signature': base64.b64encode(key.sign(payload)).decode()}).encode()
        # The agent runs with umask 077; the update host needs world-readable releases.
        created = not folder.parent.exists()
        folder.mkdir(parents=True)
        for path in (folder, folder.parent) if created else (folder,):
            path.chmod(0o755)
        try:
            # Public files for the update host; the manifest appears last.
            for name, source in (('setup.exe', installer), ('manifest.json', None)):
                part = folder / (name + '.part')
                shutil.copyfile(source, part) if source else part.write_bytes(envelope)
                part.chmod(0o644)
                part.replace(folder / name)
            agent.verify_manifest(folder / 'manifest.json', artifact=True)
        except BaseException:
            shutil.rmtree(folder.parent if created else folder, ignore_errors=True)
            raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {'message': f"R-TrustTunnel {release['version']} выложен (sequence {release['sequence']}). "
                       'Проверьте его и нажмите «Опубликовать», чтобы клиенты получили обновление.'}


def stale(max_age=AUTO_CHECK):
    """True when the cached release list is missing or older than max_age seconds."""
    try:
        checked = calendar.timegm(time.strptime(cached()['checked'], '%Y-%m-%dT%H:%M:%SZ'))
    except (KeyError, TypeError, ValueError):
        return True
    return time.time() - checked >= max_age


def auto_check(interval=AUTO_CHECK, wait=None):
    """Background loop: refresh the release cache so new upstream versions appear without a click."""
    wait = wait or time.sleep
    while True:
        if stale(interval):
            with CHECK_LOCK:
                # A manual refresh may have completed while this worker waited.
                if stale(interval):
                    try:
                        check()
                    except Exception:
                        pass  # Preserve cached releases and per-component errors.
        wait(600)


def pick(name, version):
    if version is not None and (not isinstance(version, str) or not re.fullmatch(r'\d+(\.\d+){1,3}', version)):
        raise PolicyError('Некорректная версия')
    for attempt in (0, 1):
        releases = cached()['components'].get(name, {}).get('releases', [])
        release = next((r for r in releases if version in (None, r.get('version'))), None)
        if release:
            return release
        if attempt == 0:
            try:
                check()
            except PolicyError:
                pass
    raise PolicyError('Версия не найдена в репозитории разработчика. Проверьте обновления.')


def installed(name):
    if name == 'hysteria':
        code, out = quiet([str(HYSTERIA_BIN), 'version']) if HYSTERIA_BIN.is_file() else (1, '')
        match = re.search(r'Version:\s*v?(\d+\.\d+\.\d+)', out)
        return {'installed': HYSTERIA_BIN.is_file() and HYSTERIA_UNIT.exists(), 'version': match[1] if match else None,
                'state': quiet(['systemctl', 'is-active', 'h-ui'])[1] or 'unknown'}
    if name == 'trusttunnel':
        code, state = quiet(['docker', 'inspect', TT_CONTAINER, '--format', '{{.State.Status}}'])
        if code:
            return {'installed': False, 'version': None, 'state': 'absent'}
        if state != 'running':
            # The endpoint cannot be queried, but an existing deployment is never a first install:
            # only the update path, with its mandatory probe, may replace it.
            return {'installed': True, 'version': None, 'state': state}
        code, out = quiet(['docker', 'exec', TT_CONTAINER, TT_ENDPOINT, '--version'])
        match = re.search(r'(\d+\.\d+\.\d+)', out)
        return {'installed': code == 0, 'version': match[1] if match and code == 0 else None, 'state': state}
    if name == 'cdn':
        code, state = quiet(['docker', 'inspect', cdn.CONTAINER, '--format', '{{.State.Status}}'])
        try:
            saved = cdn.load()
        except PolicyError:
            saved = None
        return {'installed': code == 0 and saved is not None, 'version': (saved or {}).get('version'),
                'state': state if code == 0 else 'absent', 'settings': cdn.public_settings(saved) if saved else None}
    code, state = quiet(['docker', 'inspect', amnezia.CONTAINER, '--format', '{{.State.Status}}'])
    try:
        saved = amnezia.load()
    except PolicyError:
        saved = None
    return {'installed': code == 0 and saved is not None, 'version': (saved or {}).get('version'),
            'state': state if code == 0 else 'absent', 'port': (saved or {}).get('port')}


def containers():
    code, ids = quiet(['docker', 'ps', '-aq', '--no-trunc'])
    if code:
        raise PolicyError('Docker недоступен')
    ids = [i for i in ids.split() if re.fullmatch('[0-9a-f]{64}', i)][:60]
    if not ids:
        return []
    result = []
    for item in json.loads(run(['docker', 'inspect', *ids], 15)):
        state, name = item.get('State', {}), str(item.get('Name', '')).lstrip('/')
        image = str(item.get('Config', {}).get('Image', ''))
        ports = sorted(f'{b.get("HostIp") or "*"}:{b.get("HostPort")} → {port}'
                       for port, binds in (item.get('HostConfig', {}).get('PortBindings') or {}).items() for b in binds or [])
        result.append({'name': name, 'role': ROLES.get(name, ''), 'state': str(state.get('Status', 'unknown')),
                       'image': image[:19] if image.startswith('sha256:') else image[:80],
                       'health': str((state.get('Health') or {}).get('Status', '')),
                       'restarts': int(item.get('RestartCount', 0)), 'exit_code': int(state.get('ExitCode', 0)),
                       'since': str(state.get('StartedAt' if state.get('Running') else 'FinishedAt', ''))[:19],
                       'ports': ports[:8]})
    return sorted(result, key=lambda c: (c['role'] == '', c['name']))


def status():
    """Snapshot section. Cached briefly: the UI polls state every two seconds during a job."""
    if _MEMO['value'] is not None and time.monotonic() - _MEMO['at'] < 5:
        return _MEMO['value']
    cache = cached()
    items = []
    for name, src in SOURCES.items():
        info = installed(name)
        known = cache['components'].get(name, {})
        releases = [{'version': r['version'], 'published': r.get('published', '')} for r in known.get('releases', [])]
        latest = releases[0]['version'] if releases else None
        newer = bool(latest and info['installed'] and (not info['version'] or key(latest) > key(info['version'])))
        items.append(dict(info, id=name, title=src['title'], repo='https://github.com/' + src['repo'],
                          runtime=src['runtime'], releases=releases, latest=latest, update=newer,
                          error=known.get('error', '')))
    try:
        listing, docker_error = containers(), ''
    except Exception:
        listing, docker_error = [], 'Состояние контейнеров недоступно'
    units = [{'id': unit, 'title': title, 'state': quiet(['systemctl', 'is-active', unit])[1] or 'unknown'} for unit, title in UNITS]
    value = {'checked': cache.get('checked'), 'items': items, 'containers': listing, 'containers_error': docker_error, 'units': units}
    _MEMO.update(at=time.monotonic(), value=value)
    return value


def build(args, timeout):
    # The agent's home is read-only; give the builder its own state directory.
    return run(['docker', 'build', *args], timeout, env={**os.environ, 'DOCKER_CONFIG': str(BUILD / '.docker')})


def asset(*parts):
    path = ASSETS.joinpath(*parts)
    if not service_routes.trusted(path):
        raise PolicyError('Файлы установки отсутствуют или небезопасны. Переустановите консоль.')
    return path


def require_x86():
    if platform.machine() not in ('x86_64', 'amd64'):
        raise PolicyError('Готовые сборки разработчика поддерживаются только для linux x86_64')


def swap_container(name, args, verify, restore=None):
    """Replace a container, keeping the previous one until the new one passes its check."""
    backup = name + '-previous'
    exists = quiet(['docker', 'inspect', name])[0] == 0
    renamed = False
    try:
        if exists:
            quiet(['docker', 'rm', '-f', backup], 30)
            run(['docker', 'stop', '--time', '10', name], 40)
            run(['docker', 'rename', name, backup])
            renamed = True
        run(['docker', 'run', '-d', '--name', name, *args], 90)
        verify()
    except BaseException:
        if renamed or not exists:
            # Only then does `name` refer to the new container.
            quiet(['docker', 'rm', '-f', name], 30)
        if renamed:
            quiet(['docker', 'rename', backup, name])
        # Mounted files belong to both containers. Restore them before the old process reads them.
        if restore is not None:
            restore()
        if exists:
            quiet(['docker', 'start', name], 30)
        raise
    if exists:
        quiet(['docker', 'rm', backup], 30)


def install_amnezia(op, data, release, work, agent):
    for field, pattern in (('tag', SOURCES['amnezia']['tag']), ('tools_tag', SOURCES['amnezia']['tag'])):
        if not re.fullmatch(pattern, str(release.get(field, ''))):
            raise PolicyError('Некорректные данные релиза. Проверьте обновления.')
    if not SHA.fullmatch(str(release.get('commit', ''))) or not SHA.fullmatch(str(release.get('tools_commit', ''))):
        raise PolicyError('Некорректные данные релиза. Проверьте обновления.')
    fresh = not amnezia.STATE.exists()
    # Validate the port before a build that takes minutes.
    state = amnezia.new_state(data.get('port')) if fresh else amnezia.load()
    for name in ('Dockerfile', 'entrypoint.sh'):
        shutil.copy2(asset('amnezia', name), work / name)
    image = 'vpn-amneziawg:' + release['version']
    build(['--pull', '--build-arg', 'AWG_GO_REF=' + release['tag'],
         '--build-arg', 'AWG_GO_COMMIT=' + release['commit'], '--build-arg', 'AWG_TOOLS_REF=' + release['tools_tag'],
         '--build-arg', 'AWG_TOOLS_COMMIT=' + release['tools_commit'], '-t', image, str(work)], 1500)
    before = None if fresh else json.dumps(state, sort_keys=True)
    state.update(version=release['version'], tag=release['tag'], image=image)
    amnezia.save(state, sync=False)
    port = str(state['port'])

    def verify():
        for _ in range(20):
            if quiet(['docker', 'exec', amnezia.CONTAINER, 'awg', 'show', amnezia.INTERFACE, 'listen-port'])[1] == port:
                return
            time.sleep(1)
        raise PolicyError('AmneziaWG не запустился в новом контейнере')
    def restore():
        if before is None:
            amnezia.STATE.unlink(missing_ok=True)
            (amnezia.RUNTIME / (amnezia.INTERFACE + '.conf')).unlink(missing_ok=True)
        else:
            amnezia.save(json.loads(before), sync=False)
    try:
        swap_container(amnezia.CONTAINER, [
            '--restart', 'unless-stopped', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
            '--device', '/dev/net/tun', '--sysctl', 'net.ipv4.ip_forward=1', '--security-opt', 'no-new-privileges',
            '-p', f'{port}:{port}/udp', '--mount', f'type=bind,src={amnezia.RUNTIME},dst=/etc/amnezia/amneziawg,readonly',
            '--label', 'vpn.console.version=' + release['version'], '--log-opt', 'max-size=5m', '--log-opt', 'max-file=2',
            image], verify, restore=restore)
    except BaseException:
        raise PolicyError('AmneziaWG не прошёл проверку запуска. Проверьте состояние предыдущего контейнера.') from None
    return (f'AmneziaWG {release["version"]} работает на UDP {port}. '
            + ('Откройте этот порт в firewall и создайте пользователей.' if fresh else 'Ключи пользователей сохранены.'))


def install_trusttunnel(op, data, release, work, agent):
    require_x86()
    probe = service_routes.TT_PROBE
    update = op == 'protocols.update'
    if update and not service_routes.trusted(probe, True):
        raise PolicyError('Не установлен проверенный протокольный probe TrustTunnel')
    base = run(['docker', 'inspect', TT_CONTAINER, '--format', '{{.Image}}'])
    if not IMAGE_ID.fullmatch(base):
        raise PolicyError('Не удалось определить текущий образ портала')
    archive = work / 'endpoint.tar.gz'
    download(asset_url(SOURCES['trusttunnel']['repo'], release['tag'], SOURCES['trusttunnel']['asset'].format(tag=release['tag'])),
             archive, release['sha256'])
    with tarfile.open(archive) as tar:
        member = next((m for m in tar if m.isfile() and Path(m.name).name == 'trusttunnel_endpoint'), None)
        if member is None or member.size > LIMIT:
            raise PolicyError('В архиве разработчика нет endpoint')
        with tar.extractfile(member) as source, open(work / 'trusttunnel_endpoint', 'wb') as target:
            shutil.copyfileobj(source, target)
    archive.unlink()
    shutil.copy2(asset('trusttunnel', 'Dockerfile'), work / 'Dockerfile')
    tag = 'trusttunnel-web:endpoint-' + release['version']
    build(['--build-arg', 'BASE_IMAGE=' + base, '-t', tag, str(work)], 300)
    image = run(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'])
    if not IMAGE_ID.fullmatch(image):
        raise PolicyError('Сборка образа не подтверждена')
    with service_routes.route_lock():
        if service_routes.PENDING.exists():
            raise PolicyError('Сначала завершите восстановление предыдущего переключения маршрутов')
        old = TT_COMPOSE.read_text()
        config = yaml.safe_load(old)
        config['services'][TT_CONTAINER]['image'] = image
        ROLLBACK.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        amnezia.write(ROLLBACK / f'trusttunnel-{stamp}.compose.yaml', old)
        with sqlite3.connect(TT_DB) as source, sqlite3.connect(ROLLBACK / f'trusttunnel-{stamp}.db') as target:
            source.backup(target)

        def up():
            run(['docker', 'compose', '-f', str(TT_COMPOSE), 'up', '-d', '--no-deps', TT_CONTAINER], 90)
        health = "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status==200"
        try:
            TT_COMPOSE.write_text(yaml.safe_dump(config, sort_keys=False))
            up()
            for _ in range(20):
                if quiet(['docker', 'exec', TT_CONTAINER, 'python', '-c', health])[0] == 0:
                    break
                time.sleep(2)
            else:
                raise PolicyError('Проверка панели не пройдена')
            if release['version'] not in quiet(['docker', 'exec', TT_CONTAINER, TT_ENDPOINT, '--version'])[1]:
                raise PolicyError('Версия endpoint не подтверждена')
            # Real client traffic is mandatory for an update; a first install has no clients yet.
            if update or service_routes.trusted(probe, True):
                run([str(probe)], 60)
        except BaseException:
            TT_COMPOSE.write_text(old)
            up()
            raise PolicyError('TrustTunnel не прошёл проверку. Предыдущий образ восстановлен.') from None
    return f'TrustTunnel endpoint {release["version"]} установлен и проверен'


def install_hysteria(op, data, release, work, agent):
    require_x86()
    binary = work / 'hysteria'
    download(asset_url(SOURCES['hysteria']['repo'], release['tag'], SOURCES['hysteria']['asset']), binary, release['sha256'])
    binary.chmod(0o755)
    if op == 'protocols.install':
        panel = work / 'h-ui'
        download(asset_url(HUI['repo'], HUI['tag'], HUI['asset']), panel, HUI['sha256'])
        panel.chmod(0o755)
        result = work / 'result.json'
        # Host users, units and /usr/local/bin are outside the agent sandbox: run the fixed
        # root-owned installer as its own transient unit. Its arguments are agent-built paths.
        code = quiet(['systemd-run', '--wait', '--collect', '--quiet', '--unit=vpn-console-hysteria-install-' + secrets.token_hex(4),
                      '/usr/bin/python3', str(asset('install-hysteria-host.py')), str(binary), str(panel), str(result)], 240)[0]
        try:
            outcome = json.loads(result.read_text())
        except (OSError, ValueError):
            outcome = {}
        if code or outcome.get('ok') is not True:
            raise PolicyError(str(outcome.get('message') or 'Установка Hysteria не завершена; проверьте журнал systemd')[:300])
        return (f'Hysteria {release["version"]} и H UI {HUI["tag"]} установлены, ядро выключено. Разрешите UDP 443, '
                'затем настройте ядро в H UI; пароль администратора — в /root/h-ui-bootstrap.json.')
    with service_routes.route_lock():
        if service_routes.PENDING.exists():
            raise PolicyError('Сначала завершите восстановление предыдущего переключения маршрутов')
        runtime = service_routes.Runtime(agent)
        try:
            seen = runtime.observe()
            exit_id = seen['services']['hysteria']['actual_exit']
            expected = runtime.expected_ip(exit_id, seen['profiles'])
        except Exception:
            raise PolicyError('Маршрут Hysteria не определён: обновление без проверки трафика запрещено') from None
        owner = HYSTERIA_BIN.stat()
        ROLLBACK.mkdir(mode=0o700, parents=True, exist_ok=True)
        previous = ROLLBACK / ('hysteria-' + time.strftime('%Y%m%d-%H%M%S'))
        shutil.copy2(HYSTERIA_BIN, previous)

        def place(source):
            temp = HYSTERIA_BIN.with_name('.console-' + secrets.token_hex(6))
            try:
                shutil.copy2(source, temp)
                temp.chmod(0o755)
                shutil.chown(temp, owner.st_uid, owner.st_gid)
                temp.replace(HYSTERIA_BIN)
            finally:
                temp.unlink(missing_ok=True)
        try:
            run(['systemctl', 'stop', 'h-ui'])
            place(binary)
            run(['systemctl', 'start', 'h-ui'])
            time.sleep(2)
            runtime.probe('hysteria', expected)
        except BaseException:
            quiet(['systemctl', 'stop', 'h-ui'], 30)
            try:
                place(previous)
                restored = True
            except OSError:
                restored = False
            # Whatever binary is in place, never leave the service stopped.
            quiet(['systemctl', 'start', 'h-ui'], 30)
            if not restored:
                raise PolicyError('Обновление Hysteria не удалось, и откат не подтверждён. H UI запущен; проверьте версию ядра. '
                                  'Прежний бинарник: ' + str(previous)) from None
            raise PolicyError('Hysteria не прошла проверку. Предыдущая версия восстановлена.') from None
    return f'Hysteria {release["version"]} установлена и проверена реальным трафиком'


def install_cdn(op, data, release, work, agent):
    require_x86()
    archive = work / 'xray.zip'
    download(asset_url(SOURCES['cdn']['repo'], release['tag'], SOURCES['cdn']['asset']), archive, release['sha256'])
    with zipfile.ZipFile(archive) as bundle:
        member = next((m for m in bundle.infolist() if m.filename == 'xray'), None)
        if member is None or member.file_size > LIMIT:
            raise PolicyError('В архиве разработчика нет xray')
        with bundle.open(member) as source, open(work / 'xray', 'wb') as target:
            shutil.copyfileobj(source, target)
    archive.unlink()
    shutil.copy2(asset('xray', 'Dockerfile'), work / 'Dockerfile')
    image = 'vpn-xray:' + release['version']
    build(['--pull', '-t', image, str(work)], 300)
    fresh = not cdn.STATE.exists()
    state = cdn.new_state(urllib.parse.urlsplit(agent.ORIGIN).hostname) if fresh else cdn.load()
    before = None if fresh else json.dumps(state, sort_keys=True)
    state.update(version=release['version'], tag=release['tag'], image=image)
    cdn.save(state)
    def restore():
        if before is None:
            cdn.STATE.unlink(missing_ok=True)
            (cdn.RUNTIME / 'config.json').unlink(missing_ok=True)
        else:
            cdn.save(json.loads(before))
    try:
        swap_container(cdn.CONTAINER, cdn.container_args(state, image),
                       lambda: cdn.verify(state['settings']['origin_port']), restore=restore)
    except BaseException:
        raise PolicyError('Xray не прошёл проверку запуска. Проверьте состояние предыдущего контейнера.') from None
    port = state['settings']['origin_port']
    return (f'Xray {release["version"]} работает на TCP {port}. '
            + ('Откройте порт для адресов CDN, затем укажите домен CDN кнопкой «Настроить CDN».' if fresh
               else 'Пользователи и настройки CDN сохранены.'))


HANDLERS = {'hysteria': install_hysteria, 'trusttunnel': install_trusttunnel, 'amnezia': install_amnezia, 'cdn': install_cdn}


def install(op, data, agent):
    name = data.get('component')
    if name not in SOURCES or not set(data) <= {'component', 'version', 'port'}:
        raise PolicyError('Некорректные параметры')
    current = installed(name)
    if op == 'protocols.install' and current['installed']:
        raise PolicyError('Протокол уже установлен. Используйте обновление.')
    if op == 'protocols.update' and not current['installed']:
        raise PolicyError('Протокол не установлен')
    release = pick(name, data.get('version'))
    if op == 'protocols.update' and current['version']:
        if key(release['version']) == key(current['version']):
            raise PolicyError('Эта версия уже установлена')
        if key(release['version']) < key(current['version']):
            raise PolicyError('Понижение версии запрещено')
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = BUILD / f'{name}-{release["version"]}-{secrets.token_hex(4)}'
    work.mkdir(mode=0o700)
    try:
        return {'message': HANDLERS[name](op, data, release, work, agent)}
    finally:
        shutil.rmtree(work, ignore_errors=True)
        _MEMO['value'] = None


def dispatch(op, data, agent):
    if op == 'protocols.check':
        return check(data)
    if op in ('protocols.install', 'protocols.update'):
        return install(op, data, agent)
    raise PolicyError('Операция запрещена')
