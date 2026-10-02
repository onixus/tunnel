"""TrustTunnel image integration: persistent forwarding and a loopback SOCKS relay.

Called by endpoint.write_vpn_toml, including after credential regeneration.
Never changes the host route table or the portal's own outbound connections.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import tomllib

VERSION = 1
CONFIG = Path('/console-routing/trusttunnel.json')
RUNTIME = Path('/tmp/trusttunnel-egress')
SING_BOX = '/usr/local/bin/sing-box'
LISTEN = '127.0.0.1:11080'
_LOCK = threading.Lock()
_FINGERPRINT = None
_PROC = None
_THREAD = None


def relay_config(profile):
    """Apply domain/CIS policy before the selected authenticated interserver exit."""
    import ipaddress
    socks = profile['outbound']['socks5']
    host, port = socks['addr'].rsplit(':', 1)
    if ipaddress.ip_address(host).version != 4 or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid SOCKS address')
    outbound = {'type': 'socks', 'tag': 'egress', 'server': host, 'server_port': int(port), 'version': '5'}
    if host == '127.0.0.1' and int(port) == 10810:
        # Host tt-primary SOCKS, reached from the container via the docker bridge.
        # TrustTunnel client refuses a non-loopback listener without credentials.
        outbound['server'] = '172.18.0.1'
    if all(isinstance(socks.get(k), str) and socks[k] for k in ('username', 'password')):
        outbound.update(username=socks['username'], password=socks['password'])
    else:
        raise ValueError('Missing upstream credentials')
    return {
        'log': {'disabled': True},
        'dns': {'servers': [{'type': 'udp', 'tag': 'local-dns', 'server': '172.18.0.53'}], 'final': 'local-dns', 'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'socks', 'tag': 'endpoint', 'listen': '127.0.0.1', 'listen_port': 11080}],
        'outbounds': [outbound, {'type': 'direct', 'tag': 'dns-direct'}],
        'route': {
            'default_domain_resolver': 'local-dns',
            'rule_set': [{'type': 'local', 'tag': 'cis', 'format': 'source', 'path': '/console-routing/cis.json'}],
            'rules': [
                {'port': 53, 'action': 'route', 'outbound': 'dns-direct'},
                {'action': 'sniff'},
                {'domain_suffix': ['hostkey.ru'], 'action': 'route', 'outbound': 'egress'},
                {'domain_suffix': ['ru', 'su', 'xn--p1ai'], 'action': 'route', 'outbound': 'dns-direct'},
                {'action': 'resolve', 'strategy': 'ipv4_only'},
                {'ip_is_private': True, 'action': 'reject'},
                {'rule_set': ['cis'], 'action': 'route', 'outbound': 'dns-direct'},
            ],
            'final': 'egress',
        },
    }


def load():
    if not CONFIG.exists():
        return {'schema': 1, 'exit': 'direct'}
    if CONFIG.stat().st_size > 65536:
        raise ValueError('Routing configuration too large')
    value = json.loads(CONFIG.read_text())
    if value.get('schema') != 1 or value.get('exit') not in ('direct', 'primary', 'reserve'):
        raise ValueError('Invalid forwarding configuration')
    if value['exit'] != 'direct' and not isinstance(value.get('relay'), dict):
        raise ValueError('Missing relay configuration')
    return value


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _supervise(path):
    global _PROC
    delay = 1
    while True:
        # The endpoint remains pointed at SOCKS if the relay fails: no direct fallback.
        started = time.monotonic()
        try:
            with _LOCK:
                _PROC = subprocess.Popen([SING_BOX, 'run', '-c', str(path)],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            _PROC.wait()
        except OSError:
            pass
        if time.monotonic() - started > 30:
            delay = 1
        time.sleep(delay)
        delay = min(delay * 2, 15)


def forward_template(template):
    """Replace only the generated direct section; preserve TLS and private ACLs."""
    global _FINGERPRINT, _THREAD
    value = load()
    direct = '[forward_protocol]\n[forward_protocol.direct]'
    if template.count(direct) != 1:
        raise ValueError('Unsupported endpoint template; forwarding was not changed')
    digest = fingerprint(value)
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    if value['exit'] == 'direct':
        result = template
    else:
        path = RUNTIME / 'relay.json'
        with _LOCK:
            if _FINGERPRINT is not None and _FINGERPRINT != digest:
                raise ValueError('Restart the portal to change the relay configuration')
            if _THREAD is None:
                path.write_text(json.dumps(value['relay']))
                path.chmod(0o600)
                subprocess.run([SING_BOX, 'check', '-c', str(path)], check=True, timeout=15,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Fail closed if the reserved loopback port already belongs to another process.
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 11080))
                _FINGERPRINT = digest
                _THREAD = threading.Thread(target=_supervise, args=(path,), daemon=True)
                _THREAD.start()
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1', 11080), timeout=.1):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('Egress relay did not start')
        result = template.replace(direct, '[forward_protocol.socks5]\naddress = "' + LISTEN + '"\nextended_auth = false')
    marker = RUNTIME / 'rendered.json'
    marker.write_text(json.dumps({'fingerprint': digest, 'exit': value['exit']}))
    marker.chmod(0o600)
    return result


def status(workdir):
    """Safe to return through the console: never includes upstream credentials."""
    config = tomllib.loads((Path(workdir) / 'vpn.toml').read_text())
    forward = config.get('forward_protocol', {'direct': {}})
    value = load()
    actual = 'custom'
    if forward == {'direct': {}}:
        actual = 'direct'
    elif forward == {'socks5': {'address': LISTEN, 'extended_auth': False}}:
        try:
            marker = json.loads((RUNTIME / 'rendered.json').read_text())
            if marker['fingerprint'] == fingerprint(value):
                actual = value['exit']
        except (OSError, ValueError, KeyError):
            pass
    return {'version': VERSION, 'actual_exit': actual,
            'runtime_revision': fingerprint(config), 'config_revision': fingerprint(value)}
