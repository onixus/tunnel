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

from routing_policy import EXITS, PolicyError
import trusttunnel_routing as acl_rules

HOME = Path('/opt/amneziawg')
STATE = HOME / 'state.json'
RUNTIME = HOME / 'runtime'
CONTAINER = 'amnezia-awg'
INTERFACE = 'awg0'
SUBNET = ipaddress.ip_network('10.8.1.0/24')
MTU = 1280
MAX_PEERS = 250
# Selected exit and the sing-box router mirroring the Hysteria exceptions; root-only, holds upstream credentials.
ROUTING = HOME / 'routing.json'
# Rendered into the mounted directory only when clients leave through an exit.
ROUTE_FILES = ('route.json', 'cis.json', 'blocked')
CIS = Path('/opt/vpn-console/trusttunnel-routing/cis.json')
MOUNT = '/etc/amnezia/amneziawg'
# Docker network whose gateway reaches the host TrustTunnel SOCKS of the primary exit.
EXIT_NETWORK = 'trusttunnel-web_default'
TUN = 'egress0'
TUN_ADDRESS = '198.18.0.1/30'
# Unpublished SOCKS inbound inside the container: the real egress check uses the same rules as clients.
PROBE_PORT = 10899
PROBE_URL = 'https://api.ipify.org'
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


def netns_probe(container, port):
    """Real egress IP through a container's own rules, from the host inside its network namespace."""
    pid = run(['docker', 'inspect', '--format', '{{.State.Pid}}', container], 8)
    if not pid.isdigit() or pid == '0':
        raise PolicyError('Контейнер ' + container + ' не запущен')
    return run(['nsenter', '-t', pid, '-n', 'curl', '-s', '-4', '--max-time', '20',
                '--socks5-hostname', f'127.0.0.1:{port}', PROBE_URL], 40)


def routing_config(exit_id, profiles=None, acl=None, blocked=()):
    """sing-box router for client traffic; the relay's rules with a TUN inbound. No network access."""
    if exit_id == 'direct':
        return {'schema': 1, 'exit': 'direct'}
    config = acl_rules.relay_config(profiles[exit_id], acl, profiles)
    config['inbounds'] = [
        # Policy routing sends everything from awg0 here; gVisor terminates any client source address.
        {'type': 'tun', 'tag': 'clients', 'interface_name': TUN, 'address': [TUN_ADDRESS], 'mtu': MTU,
         'stack': 'gvisor', 'auto_route': False},
        {'type': 'socks', 'tag': 'probe', 'listen': '127.0.0.1', 'listen_port': PROBE_PORT}]
    config['route']['rule_set'][0]['path'] = MOUNT + '/cis.json'
    for address in blocked:
        ipaddress.IPv4Address(address)
    return {'schema': 1, 'exit': exit_id, 'config': config, 'blocked': sorted(blocked)}


def load_routing():
    try:
        if ROUTING.stat().st_size > 256 * 1024:
            raise PolicyError('Маршрутизация AmneziaWG повреждена')
        value = json.loads(ROUTING.read_text())
    except FileNotFoundError:
        return {'schema': 1, 'exit': 'direct'}
    except ValueError:
        raise PolicyError('Маршрутизация AmneziaWG повреждена') from None
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('exit') not in ('direct',) + EXITS:
        raise PolicyError('Маршрутизация AmneziaWG повреждена')
    if value['exit'] != 'direct' and not (isinstance(value.get('config'), dict) and isinstance(value.get('blocked'), list)):
        raise PolicyError('Маршрутизация AmneziaWG повреждена')
    return value


def route_json(routing):
    return json.dumps(routing['config'], indent=2, sort_keys=True) + '\n'


def actual_exit(state=None):
    """The exit the mounted files really select: the routing file only counts when rendered into them.

    `state` is accepted for parity with the CDN router; peers do not affect routing.
    """
    try:
        routing = load_routing()
    except PolicyError:
        return 'unknown'
    live = RUNTIME / 'route.json'
    if routing['exit'] == 'direct':
        return 'custom' if live.exists() else 'direct'
    try:
        return routing['exit'] if live.read_text() == route_json(routing) else 'custom'
    except OSError:
        return 'custom'


def current_routing():
    return ROUTING.read_text() if ROUTING.exists() else None


def render_routing():
    """Mounted router files from the routing file; the entrypoint reads them at container start."""
    routing = load_routing()
    if routing['exit'] == 'direct':
        for name in ROUTE_FILES:
            (RUNTIME / name).unlink(missing_ok=True)
        return
    # TrustTunnel's CIS rule set, so both relays resolve "СНГ" from the same data.
    write(RUNTIME / 'cis.json', CIS.read_text())
    write(RUNTIME / 'blocked', ''.join(a + '\n' for a in routing['blocked']))
    write(RUNTIME / 'route.json', route_json(routing))


def container_args(state, image):
    port = str(state['port'])
    args = ['--restart', 'unless-stopped', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
            '--device', '/dev/net/tun', '--sysctl', 'net.ipv4.ip_forward=1', '--security-opt', 'no-new-privileges',
            '-p', f'{port}:{port}/udp', '--mount', f'type=bind,src={RUNTIME},dst={MOUNT},readonly',
            '--label', 'vpn.console.version=' + state.get('version', ''), '--log-opt', 'max-size=5m', '--log-opt', 'max-file=2']
    if load_routing()['exit'] != 'direct':
        # Replies from the router TUN arrive on another interface than the route to their source.
        args += ['--network', EXIT_NETWORK, '--sysctl', 'net.ipv4.conf.all.rp_filter=0',
                 '--sysctl', 'net.ipv4.conf.default.rp_filter=0']
    return args + [image]


def verify(state, attempts=20):
    routed = load_routing()['exit'] != 'direct'
    for _ in range(attempts):
        try:
            if (run(['docker', 'exec', CONTAINER, 'awg', 'show', INTERFACE, 'listen-port'], 8) == str(state['port'])
                    and (not routed or run(['docker', 'exec', CONTAINER, 'ip', '-o', 'link', 'show', TUN], 8))):
                return
        except (PolicyError, subprocess.TimeoutExpired):
            pass
        time.sleep(1)
    raise PolicyError('AmneziaWG не запустился в новом контейнере')


def apply_routing(text):
    """Install a rendered routing file (None: direct) and recreate the container with it.

    On failure the previous container keeps running with the previous files.
    """
    import protocols  # Circular at import time: protocols registers this module.
    state = load()
    if not state.get('image'):
        raise PolicyError('AmneziaWG не установлен')
    before = current_routing()

    def put(value):
        if value is None:
            ROUTING.unlink(missing_ok=True)
        else:
            write(ROUTING, value)
        render_routing()
    put(text)
    try:
        protocols.swap_container(CONTAINER, container_args(state, state['image']), lambda: verify(state),
                                 restore=lambda: put(before))
    except BaseException:
        raise PolicyError('AmneziaWG не запустился с новым маршрутом. Предыдущий контейнер восстановлен.') from None


def probe():
    return netns_probe(CONTAINER, PROBE_PORT)
