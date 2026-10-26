"""VLESS behind a CDN (Xray-core, WebSocket or XHTTP). Root agent only; fixed paths, no browser-chosen commands.

Clients reach the CDN edge over HTTPS with SNI/Host set to the operator's CDN domain; the CDN
forwards to this origin on a CDN-proxied port. Hysteria (UDP) and TrustTunnel cannot pass a CDN.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse
import uuid

import amnezia
from routing_policy import EXITS, PolicyError
import trusttunnel_routing as acl_rules

HOME = Path('/opt/xray-cdn')
STATE = HOME / 'state.json'
RUNTIME = HOME / 'runtime'
# Selected exit and the translated Hysteria exceptions; root-only, holds upstream credentials.
ROUTING = HOME / 'routing.json'
# Docker network whose gateway reaches the host TrustTunnel SOCKS of the primary exit.
EXIT_NETWORK = 'trusttunnel-web_default'
# Unpublished SOCKS inbound inside the container: the real egress check uses the same rules as clients.
PROBE_PORT = 10899
SNIFFING = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
COUNTRY = re.compile(r'[a-z]{2}')
CONTAINER = 'xray-cdn'
LETSENCRYPT = '/etc/letsencrypt'
MAX_USERS = 500
NAME = re.compile(r'[A-Za-z0-9_-]{3,32}')
HOST = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
PATH = re.compile(r'/[A-Za-z0-9_-]{8,64}')
# Ports the major CDNs (Cloudflare and compatible) proxy to an origin. 443/8443 are already taken
# by the portal and TrustTunnel, 80/8080 by certificate issuance and local services.
ORIGIN_TLS_PORTS = (2053, 2083, 2087, 2096)
ORIGIN_HTTP_PORTS = (2052, 2082, 2086, 2095, 8880)
CLIENT_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
TRANSPORTS = ('ws', 'xhttp')
SETTINGS = ('domain', 'address', 'client_port', 'origin_port', 'origin_tls', 'transport', 'path')
# Clients must not reach the host's panels or private networks through the tunnel.
PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
           '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']


def run(args, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise PolicyError('Операция не завершена: ' + Path(args[0]).name)
    return p.stdout.strip()


def new_path():
    return '/' + secrets.token_urlsafe(18).replace('-', 'a').replace('_', 'b')


def new_state(origin_host):
    return {'schema': 1, 'origin_host': origin_host, 'next_id': 1, 'users': [],
            'settings': {'domain': '', 'address': '', 'client_port': 443, 'origin_port': ORIGIN_TLS_PORTS[0],
                         'origin_tls': True, 'transport': 'ws', 'path': new_path()}}


def load():
    try:
        if STATE.stat().st_size > 1024 * 1024:
            raise PolicyError('Состояние CDN повреждено')
        state = json.loads(STATE.read_text())
    except FileNotFoundError:
        raise PolicyError('VLESS через CDN не установлен. Установите протокол в разделе «Протоколы».') from None
    except ValueError:
        raise PolicyError('Состояние CDN повреждено') from None
    if state.get('schema') != 1:
        raise PolicyError('Неподдерживаемая версия состояния CDN')
    return state


def host_name(value, field):
    value = str(value).strip().lower().rstrip('.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise PolicyError(field + ': некорректное имя') from None
    if not HOST.fullmatch(value):
        raise PolicyError(field + ': нужно доменное имя, например cdn.example.com')
    return value


def validate(data, current):
    """Full settings object from the browser; every field is checked against a fixed set."""
    if not isinstance(data, dict) or not set(data) <= set(SETTINGS) | {'regenerate_path'}:
        raise PolicyError('Некорректные параметры CDN')
    result = dict(current)
    if 'domain' in data:
        result['domain'] = host_name(data['domain'], 'Домен CDN') if data['domain'] else ''
    if 'address' in data:
        address = str(data['address'] or '').strip()
        if address:
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError:
                address = host_name(address, 'Адрес подключения')
        result['address'] = address
    for field in ('client_port', 'origin_port'):
        if field in data:
            if type(data[field]) is not int:
                raise PolicyError('Некорректный порт')
            result[field] = data[field]
    if 'origin_tls' in data:
        if type(data['origin_tls']) is not bool:
            raise PolicyError('Некорректный режим TLS')
        result['origin_tls'] = data['origin_tls']
    if 'transport' in data:
        if data['transport'] not in TRANSPORTS:
            raise PolicyError('Транспорт: WebSocket или XHTTP')
        result['transport'] = data['transport']
    if 'path' in data:
        if not isinstance(data['path'], str) or not PATH.fullmatch(data['path']):
            raise PolicyError('Путь: «/» и 8–64 латинских символа, цифры, «-» и «_»')
        result['path'] = data['path']
    if data.get('regenerate_path') is True:
        result['path'] = new_path()
    elif data.get('regenerate_path') not in (None, False):
        raise PolicyError('Некорректные параметры CDN')
    if result['client_port'] not in CLIENT_PORTS:
        raise PolicyError('Порт клиента: ' + ', '.join(map(str, CLIENT_PORTS)))
    allowed = ORIGIN_TLS_PORTS if result['origin_tls'] else ORIGIN_HTTP_PORTS
    if result['origin_port'] not in allowed:
        raise PolicyError(('HTTPS' if result['origin_tls'] else 'HTTP') + '-порт origin: ' + ', '.join(map(str, allowed)))
    return result


def translate_acl(acl, names):
    """Hysteria ACL exceptions as Xray routing rules, in order; same grammar as the TrustTunnel relay.

    Returns (rules, skipped, uses_geoip). A trailing catch-all is left to the selected exit.
    """
    rules, skipped, uses_geoip = [], [], False
    if acl and isinstance(acl[-1], str) and acl_rules._CATCH_ALL.match(acl[-1].strip()):
        acl = acl[:-1]
    for line in acl:
        m = acl_rules._ACL_LINE.match(line.strip()) if isinstance(line, str) else None
        tag = None if not m else 'block' if m.group(1) == 'reject' else names.get(m.group(1))
        if tag is None:
            skipped.append(line)
            continue
        match = m.group(2).lower()
        if match.startswith('suffix:') and acl_rules._HOST.match(match[7:]):
            rule = {'domain': ['domain:' + match[7:]]}
        elif match == 'geoip:private':
            rule = {'ip': PRIVATE}
        elif match.startswith('geoip:') and COUNTRY.fullmatch(match[6:]):
            # Hysteria's own geoip.dat is copied next to the config: identical country data.
            rule, uses_geoip = {'ip': [match]}, True
        elif acl_rules._HOST.match(match) and not match.replace('.', '').isdigit():
            rule = {'domain': ['full:' + match]}
        else:
            try:
                rule = {'ip': [str(ipaddress.ip_network(match, strict=False))]}
            except ValueError:
                skipped.append(line)
                continue
        rules.append({'type': 'field', **rule, 'outboundTag': tag})
    return rules, skipped, uses_geoip


def xray_socks(profile, tag):
    """An exit's authenticated SOCKS as an Xray outbound, reached like the TrustTunnel relay does."""
    o = acl_rules._socks(profile, tag)
    return {'tag': tag, 'protocol': 'socks', 'settings': {'servers': [
        {'address': o['server'], 'port': o['server_port'], 'users': [{'user': o['username'], 'pass': o['password']}]}]}}


def routing_config(exit_id, profiles=None, acl=None, blocked=(), geoip=None):
    """Routing for the selected exit; no network access. `blocked` are the host's own addresses."""
    if exit_id == 'direct':
        return {'schema': 1, 'exit': 'direct'}
    profile = profiles[exit_id]
    names, extra = acl_rules.exit_tags(profile, profiles, 'direct')
    rules, _, uses_geoip = translate_acl(DEFAULT_ACL if acl is None else acl, names)
    used = {r['outboundTag'] for r in rules}
    value = {'schema': 1, 'exit': exit_id, 'blocked': sorted(blocked), 'rules': rules,
             'outbounds': [xray_socks(profile, 'egress')] + [xray_socks(extra[t], t) for t in sorted(extra) if t in used]}
    if uses_geoip:
        if not geoip:
            raise PolicyError('Для исключений GeoIP нужна база geoip.dat Hysteria')
        value['geoip'] = str(geoip)
    return value


# Used when Hysteria has no ACL: the same RU/CIS policy as the TrustTunnel relay.
DEFAULT_ACL = ['local(suffix:ru)', 'local(suffix:su)', 'local(suffix:xn--p1ai)'] + [
    f'local(geoip:{c})' for c in acl_rules.CIS]


def load_routing():
    try:
        if ROUTING.stat().st_size > 256 * 1024:
            raise PolicyError('Маршрутизация CDN повреждена')
        value = json.loads(ROUTING.read_text())
    except FileNotFoundError:
        return {'schema': 1, 'exit': 'direct'}
    except ValueError:
        raise PolicyError('Маршрутизация CDN повреждена') from None
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('exit') not in ('direct',) + EXITS:
        raise PolicyError('Маршрутизация CDN повреждена')
    if value['exit'] != 'direct' and not all(isinstance(value.get(k), list) for k in ('outbounds', 'rules', 'blocked')):
        raise PolicyError('Маршрутизация CDN повреждена')
    return value


def render_server(state, routing=None):
    s = state['settings']
    routing = load_routing() if routing is None else routing
    stream = {'network': s['transport'], 'security': 'none',
              ('wsSettings' if s['transport'] == 'ws' else 'xhttpSettings'): {'path': s['path']}}
    if s['origin_tls']:
        live = f'{LETSENCRYPT}/live/{state["origin_host"]}/'
        stream.update(security='tls', tlsSettings={'minVersion': '1.2', 'certificates': [
            {'certificateFile': live + 'fullchain.pem', 'keyFile': live + 'privkey.pem'}]})
    clients = [{'id': u['uuid'], 'email': u['name']} for u in state['users'] if u['enabled']]
    inbounds = [{'tag': 'cdn', 'listen': '0.0.0.0', 'port': s['origin_port'], 'protocol': 'vless',
                 'settings': {'clients': clients, 'decryption': 'none'}, 'streamSettings': stream},
                {'tag': 'probe', 'listen': '127.0.0.1', 'port': PROBE_PORT, 'protocol': 'socks',
                 'settings': {'auth': 'noauth', 'udp': False}}]
    outbounds = [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}]
    rules = [{'type': 'field', 'ip': PRIVATE, 'outboundTag': 'block'}]
    route = {'rules': rules}
    if routing['exit'] != 'direct':
        for inbound in inbounds:
            inbound['sniffing'] = SNIFFING
        # The exit network also reaches the host's public address: never let clients hairpin to its panels.
        rules[0] = {'type': 'field', 'ip': PRIVATE + routing['blocked'], 'outboundTag': 'block'}
        rules += [{'type': 'field', 'port': '53', 'outboundTag': 'direct'}, *routing['rules'],
                  {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'egress'}]
        outbounds = routing['outbounds'] + outbounds
        # Resolve at the first IP rule, as Hysteria does: rules keep the ACL's top-down order.
        route['domainStrategy'] = 'IPOnDemand'
    return json.dumps({
        'log': {'loglevel': 'warning', 'access': 'none'},
        'inbounds': inbounds,
        'outbounds': outbounds,
        'routing': route,
    }, indent=2, sort_keys=True) + '\n'


def actual_exit(state):
    """The exit the mounted config really uses: the routing file only counts when rendered into it."""
    try:
        live = json.loads((RUNTIME / 'config.json').read_text())
        routing = load_routing()
    except (OSError, ValueError, PolicyError):
        return 'unknown'
    expected = json.loads(render_server(state, routing))
    if all(live.get(k) == expected[k] for k in ('outbounds', 'routing')):
        return routing['exit']
    if routing['exit'] == 'direct' and not any(o.get('tag') == 'egress' for o in live.get('outbounds', [])):
        return 'direct'  # Rendered before routing support; nothing to migrate.
    return 'custom'


def render_client(state, user):
    s = state['settings']
    if not s['domain']:
        raise PolicyError('Сначала укажите домен CDN в разделе «Протоколы» → «Настроить CDN»')
    query = {'encryption': 'none', 'security': 'tls', 'sni': s['domain'], 'host': s['domain'], 'fp': 'chrome',
             'type': s['transport'], 'path': s['path']}
    if s['transport'] == 'ws':
        query['alpn'] = 'http/1.1'
    else:
        query['mode'] = 'auto'
    address = s['address'] or s['domain']
    if ':' in address:
        address = f'[{address}]'
    return (f'vless://{user["uuid"]}@{address}:{s["client_port"]}?' + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
            + '#' + urllib.parse.quote('CDN-' + user['name']))


def running():
    try:
        return run(['docker', 'inspect', CONTAINER, '--format', '{{.State.Running}}'], 8) == 'true'
    except Exception:
        return False


def container_args(state, image):
    s = state['settings']
    port = str(s['origin_port'])
    args = ['--restart', 'unless-stopped', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
            '-p', f'{port}:{port}/tcp', '--mount', f'type=bind,src={RUNTIME},dst=/etc/xray,readonly',
            '--label', 'vpn.console.version=' + state.get('version', ''), '--log-opt', 'max-size=5m', '--log-opt', 'max-file=2']
    if s['origin_tls']:
        # Live symlinks point into ../../archive: mount the whole tree read-only.
        args += ['--mount', f'type=bind,src={LETSENCRYPT},dst={LETSENCRYPT},readonly']
    if load_routing()['exit'] != 'direct':
        # The firewall admits only this network to the primary exit's SOCKS; geoip.dat sits beside the config.
        args += ['--network', EXIT_NETWORK, '-e', 'XRAY_LOCATION_ASSET=/etc/xray']
    return args + [image]


def verify(port, attempts=20):
    for _ in range(attempts):
        if running():
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=2):
                    return
            except OSError:
                pass
        time.sleep(1)
    raise PolicyError('Xray не запустился в новом контейнере')


def save(state):
    amnezia.write(STATE, json.dumps(state, sort_keys=True))
    amnezia.write(RUNTIME / 'config.json', render_server(state))


def restart():
    """Xray has no safe live reload of clients: a short restart drops CDN sessions, which reconnect."""
    if running():
        try:
            run(['docker', 'restart', '--time', '5', CONTAINER], 40)
        except (PolicyError, subprocess.TimeoutExpired):
            raise PolicyError('Изменение сохранено, но не применено: прежние ключи CDN ещё действуют. '
                              'Перезапустите контейнер xray-cdn.') from None


def copy_file(source, target):
    temp = target.with_name('.' + target.name + '.' + secrets.token_hex(6))
    try:
        with open(source, 'rb') as src, open(temp, 'xb') as dst:
            os.fchmod(dst.fileno(), 0o600)
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)


def current_routing():
    return ROUTING.read_text() if ROUTING.exists() else None


def apply_routing(text):
    """Install a rendered routing file (None: direct) and recreate Xray with it.

    On failure the previous container keeps running with the previous files.
    """
    import protocols
    state = load()
    if not state.get('image'):
        raise PolicyError('VLESS через CDN не установлен')
    before = current_routing()

    def put(value):
        if value is None:
            ROUTING.unlink(missing_ok=True)
        else:
            amnezia.write(ROUTING, value)
        geoip = load_routing().get('geoip')
        if geoip:
            # Hysteria's file is not readable from the container; a root-only copy is.
            copy_file(Path(geoip), RUNTIME / 'geoip.dat')
        save(state)
    put(text)
    try:
        protocols.swap_container(CONTAINER, container_args(state, state['image']),
                                 lambda: verify(state['settings']['origin_port']), restore=lambda: put(before))
    except BaseException:
        raise PolicyError('Xray не запустился с новым маршрутом. Предыдущий контейнер восстановлен.') from None


def probe():
    return amnezia.netns_probe(CONTAINER, PROBE_PORT)


def configure(state, data):
    import protocols  # Circular at import time: protocols registers this module.
    before = json.dumps(state, sort_keys=True)
    state['settings'] = validate(data, state['settings'])
    save(state)
    if not state.get('image'):
        return
    try:
        # Port and certificate mounts may change: recreate, keeping the old container until the new one listens.
        protocols.swap_container(CONTAINER, container_args(state, state['image']),
                                 lambda: verify(state['settings']['origin_port']),
                                 restore=lambda: save(json.loads(before)))
    except BaseException:
        raise PolicyError('Xray не запустился с новыми настройками. Проверьте состояние предыдущего контейнера.') from None


def public_settings(state):
    return {k: state['settings'][k] for k in SETTINGS}


def users():
    state = load()
    return [{'id': u['id'], 'username': u['name'], 'deleted': 0 if u['enabled'] else 1, 'created': u['created']}
            for u in state['users']]


def find(state, id):
    for user in state['users']:
        if user['id'] == id:
            return user
    raise PolicyError('Пользователь CDN не найден')


def dispatch(op, data):
    state = load()
    if op == 'cdn.configure':
        configure(state, data)
        return {'message': 'Настройки CDN применены. Передайте пользователям обновлённые ссылки.'}
    if op == 'cdn.create':
        name = data.get('username', '')
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise PolicyError('Имя CDN: 3–32 латинских символа, цифры, «-» и «_»')
        if any(u['name'] == name for u in state['users']):
            raise PolicyError('Такой пользователь CDN уже существует')
        if len(state['users']) >= MAX_USERS:
            raise PolicyError('Достигнут лимит пользователей CDN')
        state['users'].append({'id': state['next_id'], 'name': name, 'uuid': str(uuid.uuid4()), 'enabled': True,
                               'created': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())})
        state['next_id'] += 1
        save(state)
        restart()
        return {'message': 'Пользователь CDN создан', 'id': state['next_id'] - 1}
    id = data.get('id')
    if type(id) is not int:
        raise PolicyError('Некорректный ID')
    user = find(state, id)
    if op == 'cdn.export':
        if not user['enabled']:
            raise PolicyError('Пользователь CDN заблокирован')
        return {'content': render_client(state, user)}
    if op in ('cdn.block', 'cdn.unblock'):
        user['enabled'] = op == 'cdn.unblock'
    elif op == 'cdn.rotate':
        user['uuid'] = str(uuid.uuid4())
    elif op == 'cdn.delete':
        state['users'].remove(user)
    else:
        raise PolicyError('Операция запрещена')
    save(state)
    restart()
    return {'message': 'Изменение CDN применено'}
