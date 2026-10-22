"""AmneziaWG 3.1 server state and peers. Root agent only; fixed paths, no browser-chosen commands."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from routing_policy import PolicyError

HOME = Path('/opt/amneziawg')
STATE = HOME / 'state.json'
RUNTIME = HOME / 'runtime'
CONTAINER = 'amnezia-awg'
INTERFACE = 'awg0'
SUBNET = ipaddress.ip_network('10.8.1.0/24')
MTU = 1280
MAX_PEERS = 250
RESERVED_PORTS = (443, 8443, 51831)
NAME = re.compile(r'[A-Za-z0-9_-]{3,32}')
# Obfuscation values that must match on both sides, in config order.
SHARED = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4', 'HeaderProtectionKey')


def run(args, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise PolicyError('Операция не завершена: ' + Path(args[0]).name)
    return p.stdout.strip()


def genkey():
    """Same clamping as `awg genkey`; also used for the header protection key."""
    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    return base64.b64encode(bytes(raw)).decode()


def pubkey(private):
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private))
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def new_params(rng=None):
    """AWG 3.1: header protection needs S1-S4 >= 12; padded handshake sizes must differ."""
    rng = rng or secrets.SystemRandom()
    while True:
        s1, s2, s3 = rng.randint(15, 150), rng.randint(15, 150), rng.randint(12, 64)
        # init 148+S1, response 92+S2, cookie 64+S3 must stay distinguishable from each other.
        if len({148 + s1, 92 + s2, 64 + s3}) == 3:
            break
    zone = (2 ** 31 - 6) // 4
    headers = []
    for index in range(4):
        low = 5 + index * zone + rng.randint(0, zone // 2)
        headers.append(f'{low}-{low + rng.randint(1000, zone // 4)}')
    rng.shuffle(headers)
    jmin = rng.randint(8, 24)
    return {'Jc': rng.randint(4, 8), 'Jmin': jmin, 'Jmax': jmin + rng.randint(24, 56),
            'S1': s1, 'S2': s2, 'S3': s3, 'S4': rng.randint(12, 32),
            'H1': headers[0], 'H2': headers[1], 'H3': headers[2], 'H4': headers[3],
            'HeaderProtectionKey': genkey()}


def valid_port(port):
    if type(port) is not int or not 1024 <= port <= 65535 or port in RESERVED_PORTS:
        raise PolicyError('Порт AmneziaWG: 1024–65535, кроме занятых 8443 и 51831')
    return port


def new_state(port):
    private = genkey()
    return {'schema': 1, 'port': valid_port(port), 'private_key': private, 'public_key': pubkey(private),
            'dns': ['1.1.1.1', '1.0.0.1'], 'params': new_params(), 'next_id': 1, 'peers': []}


def load():
    try:
        if STATE.stat().st_size > 1024 * 1024:
            raise PolicyError('Состояние AmneziaWG повреждено')
        state = json.loads(STATE.read_text())
    except FileNotFoundError:
        raise PolicyError('AmneziaWG не установлен. Установите протокол в разделе «Протоколы».') from None
    except ValueError:
        raise PolicyError('Состояние AmneziaWG повреждено') from None
    if state.get('schema') != 1:
        raise PolicyError('Неподдерживаемая версия состояния AmneziaWG')
    return state


def write(path, text):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name('.' + path.name + '.' + secrets.token_hex(6))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def shared_lines(state):
    return [f'{key} = {state["params"][key]}' for key in SHARED]


def render_server(state):
    server = SUBNET.network_address + 1
    lines = ['[Interface]', 'PrivateKey = ' + state['private_key'], f'Address = {server}/{SUBNET.prefixlen}',
             f'ListenPort = {state["port"]}', f'MTU = {MTU}'] + shared_lines(state)
    for peer in state['peers']:
        if peer['enabled']:
            lines += ['', '[Peer]', 'PublicKey = ' + peer['public_key'], 'PresharedKey = ' + peer['psk'],
                      f'AllowedIPs = {peer["address"]}/32']
    return '\n'.join(lines) + '\n'


def render_client(state, peer, host):
    return '\n'.join(['[Interface]', f'Address = {peer["address"]}/32', 'DNS = ' + ', '.join(state['dns']),
                      'PrivateKey = ' + peer['private_key'], f'MTU = {MTU}'] + shared_lines(state) +
                     ['', '[Peer]', 'PublicKey = ' + state['public_key'], 'PresharedKey = ' + peer['psk'],
                      'AllowedIPs = 0.0.0.0/0, ::/0', f'Endpoint = {host}:{state["port"]}',
                      'PersistentKeepalive = 25']) + '\n'


def running():
    try:
        return run(['docker', 'inspect', CONTAINER, '--format', '{{.State.Running}}'], 8) == 'true'
    except Exception:
        return False


def save(state, sync=True):
    """State first: a failed live reload leaves the desired configuration for the next start."""
    write(STATE, json.dumps(state, sort_keys=True))
    write(RUNTIME / (INTERFACE + '.conf'), render_server(state))
    if sync and running():
        try:
            # Fixed command: reload peers without dropping established sessions.
            run(['docker', 'exec', CONTAINER, 'bash', '-c',
                 f'awg syncconf {INTERFACE} <(awg-quick strip {INTERFACE})'], 20)
        except (PolicyError, subprocess.TimeoutExpired):
            # A blocked or rotated key must not stay accepted: reload the whole interface.
            try:
                run(['docker', 'restart', '--time', '10', CONTAINER], 40)
            except (PolicyError, subprocess.TimeoutExpired):
                raise PolicyError('Изменение сохранено, но не применено: прежние ключи AmneziaWG ещё действуют. '
                                  'Перезапустите контейнер amnezia-awg.') from None


def live():
    """Traffic counters by public key. Preshared keys in the dump are discarded."""
    result = {}
    try:
        dump = run(['docker', 'exec', CONTAINER, 'awg', 'show', INTERFACE, 'dump'], 8)
    except Exception:
        return None
    for line in dump.splitlines()[1:]:
        parts = line.split('\t')
        if len(parts) >= 7 and parts[4].isdigit() and parts[5].isdigit() and parts[6].isdigit():
            result[parts[0]] = {'handshake': int(parts[4]), 'download': int(parts[5]), 'upload': int(parts[6])}
    return result


def users():
    state = load()
    stats = live()
    return [{'id': p['id'], 'username': p['name'], 'address': p['address'], 'deleted': 0 if p['enabled'] else 1,
             'created': p['created'],
             **((stats or {}).get(p['public_key']) or {'handshake': 0, 'download': 0, 'upload': 0})}
            for p in state['peers']]


def find(state, id):
    for peer in state['peers']:
        if peer['id'] == id:
            return peer
    raise PolicyError('Пользователь AmneziaWG не найден')


def dispatch(op, data, host):
    state = load()
    if op == 'amnezia.create':
        name = data.get('username', '')
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise PolicyError('Имя AmneziaWG: 3–32 латинских символа, цифры, «-» и «_»')
        if any(p['name'] == name for p in state['peers']):
            raise PolicyError('Такой пользователь AmneziaWG уже существует')
        if len(state['peers']) >= MAX_PEERS:
            raise PolicyError('Достигнут лимит пользователей AmneziaWG')
        used = {p['address'] for p in state['peers']}
        address = next(str(a) for a in list(SUBNET.hosts())[1:] if str(a) not in used)
        private = genkey()
        state['peers'].append({'id': state['next_id'], 'name': name, 'address': address, 'private_key': private,
                               'public_key': pubkey(private), 'psk': genkey(), 'enabled': True,
                               'created': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())})
        state['next_id'] += 1
        save(state)
        return {'message': 'Пользователь AmneziaWG создан', 'id': state['next_id'] - 1}
    id = data.get('id')
    if type(id) is not int:
        raise PolicyError('Некорректный ID')
    peer = find(state, id)
    if op == 'amnezia.export':
        if not peer['enabled']:
            raise PolicyError('Пользователь AmneziaWG заблокирован')
        return {'content': render_client(state, peer, host)}
    if op in ('amnezia.block', 'amnezia.unblock'):
        peer['enabled'] = op == 'amnezia.unblock'
    elif op == 'amnezia.rotate':
        peer['private_key'] = genkey()
        peer['public_key'] = pubkey(peer['private_key'])
        peer['psk'] = genkey()
    elif op == 'amnezia.delete':
        state['peers'].remove(peer)
        save(state)
        return {'message': 'Пользователь AmneziaWG удалён'}
    else:
        raise PolicyError('Операция запрещена')
    save(state)
    return {'message': 'Изменение AmneziaWG применено'}
