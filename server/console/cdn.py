"""VLESS behind a CDN (Xray-core, WebSocket or XHTTP). Root agent only; fixed paths, no browser-chosen commands.

Clients reach the CDN edge over HTTPS with SNI/Host set to the operator's CDN domain; the CDN
forwards to this origin on a CDN-proxied port. Hysteria (UDP) and TrustTunnel cannot pass a CDN.
"""
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
import urllib.parse
import uuid

import amnezia
from routing_policy import PolicyError

HOME = Path('/opt/xray-cdn')
STATE = HOME / 'state.json'
RUNTIME = HOME / 'runtime'
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


def render_server(state):
    s = state['settings']
    stream = {'network': s['transport'], 'security': 'none',
              ('wsSettings' if s['transport'] == 'ws' else 'xhttpSettings'): {'path': s['path']}}
    if s['origin_tls']:
        live = f'{LETSENCRYPT}/live/{state["origin_host"]}/'
        stream.update(security='tls', tlsSettings={'minVersion': '1.2', 'certificates': [
            {'certificateFile': live + 'fullchain.pem', 'keyFile': live + 'privkey.pem'}]})
    clients = [{'id': u['uuid'], 'email': u['name']} for u in state['users'] if u['enabled']]
    return json.dumps({
        'log': {'loglevel': 'warning', 'access': 'none'},
        'inbounds': [{'tag': 'cdn', 'listen': '0.0.0.0', 'port': s['origin_port'], 'protocol': 'vless',
                      'settings': {'clients': clients, 'decryption': 'none'}, 'streamSettings': stream}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'rules': [{'type': 'field', 'ip': PRIVATE, 'outboundTag': 'block'}]},
    }, indent=2, sort_keys=True) + '\n'


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
                                 lambda: verify(state['settings']['origin_port']))
    except BaseException:
        save(json.loads(before))
        raise PolicyError('Xray не запустился с новыми настройками. Прежние настройки восстановлены.') from None


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
        return {'message': 'Пользователь CDN создан'}
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
    else:
        raise PolicyError('Операция запрещена')
    save(state)
    restart()
    return {'message': 'Изменение CDN применено'}
