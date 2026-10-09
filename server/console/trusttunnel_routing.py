"""TrustTunnel image integration: persistent forwarding and a loopback SOCKS relay.

Called by endpoint.write_vpn_toml, including after credential regeneration.
Never changes the host route table or the portal's own outbound connections.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
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


CIS = ('ru', 'by', 'kz', 'kg', 'tj', 'uz', 'am', 'az', 'md', 'tm')
# Hysteria ACL line with one plain argument: outbound(match). Port/hijack forms are skipped.
_ACL_LINE = re.compile(r'^([A-Za-z0-9_-]+)\(\s*([^(),\s]+)\s*\)$')
_CATCH_ALL = re.compile(r'^[A-Za-z0-9_-]+\(\s*all\s*\)$')
_HOST = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$')
# Used when no Hysteria ACL is supplied (installer self-check, legacy callers).
_DEFAULT_DOMAIN = [
    {'domain_suffix': ['hostkey.ru'], 'action': 'route', 'outbound': 'egress'},
    {'domain_suffix': ['ru', 'su', 'xn--p1ai'], 'action': 'route', 'outbound': 'dns-direct'},
]
_DEFAULT_NETWORK = [
    {'ip_is_private': True, 'action': 'reject'},
    {'rule_set': ['cis'], 'action': 'route', 'outbound': 'dns-direct'},
]


def translate_acl(acl, outbounds):
    """Translate Hysteria ACL exceptions into sing-box rules, keeping their order.

    `outbounds` maps Hysteria outbound names to relay tags. A trailing `outbound(all)`
    catch-all is replaced by the relay's own `final`; any other last line is an exception. Returns (domain, network,
    skipped): domain rules run before resolution, network rules after it.
    """
    domain, network, skipped = [], [], []
    if acl and isinstance(acl[-1], str) and _CATCH_ALL.match(acl[-1].strip()):
        acl = acl[:-1]
    for line in acl:
        m = _ACL_LINE.match(line.strip()) if isinstance(line, str) else None
        if not m:
            skipped.append(line)
            continue
        name, match = m.group(1), m.group(2).lower()
        if name == 'reject':
            action = {'action': 'reject'}
        elif name in outbounds:
            action = {'action': 'route', 'outbound': outbounds[name]}
        else:
            skipped.append(line)
            continue
        if match.startswith('suffix:') and _HOST.match(match[7:]):
            domain.append({'domain_suffix': [match[7:]], **action})
        elif match == 'geoip:private':
            network.append({'ip_is_private': True, **action})
        elif match.startswith('geoip:') and match[6:] in CIS and action.get('outbound') == 'dns-direct':
            # One combined CIS rule set: only the shared "direct" policy is representable.
            rule = {'rule_set': ['cis'], **action}
            if rule not in network:
                network.append(rule)
        elif _HOST.match(match) and not match.replace('.', '').isdigit():
            domain.append({'domain': [match], **action})
        else:
            try:
                cidr = str(ipaddress.ip_network(match, strict=False))
            except ValueError:
                skipped.append(line)
                continue
            network.append({'ip_cidr': [cidr], **action})
    # Never forward to private destinations, whatever the source ACL says.
    if {'ip_is_private': True, 'action': 'reject'} not in network:
        network.insert(0, {'ip_is_private': True, 'action': 'reject'})
    return domain, network, skipped


def _socks(profile, tag):
    socks = profile['outbound']['socks5']
    host, port = socks['addr'].rsplit(':', 1)
    if ipaddress.ip_address(host).version != 4 or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid SOCKS address')
    outbound = {'type': 'socks', 'tag': tag, 'server': host, 'server_port': int(port), 'version': '5'}
    if host == '127.0.0.1' and int(port) == 10810:
        # Host tt-primary SOCKS, reached from the container via the docker bridge.
        # TrustTunnel client refuses a non-loopback listener without credentials.
        outbound['server'] = '172.18.0.1'
    if all(isinstance(socks.get(k), str) and socks[k] for k in ('username', 'password')):
        outbound.update(username=socks['username'], password=socks['password'])
    else:
        raise ValueError('Missing upstream credentials')
    return outbound


def relay_config(profile, acl=None, profiles=None):
    """Apply the Hysteria exception policy before the selected authenticated exit.

    With `acl` (Hysteria `acl.inline`) and `profiles` (all exits), the relay mirrors
    every translatable Hysteria exception; otherwise the built-in RU/CIS policy is used.
    """
    outbounds = [_socks(profile, 'egress'), {'type': 'direct', 'tag': 'dns-direct'}]
    if acl is None:
        domain, network = _DEFAULT_DOMAIN, _DEFAULT_NETWORK
    else:
        names = {'local': 'dns-direct'}
        extra = {}
        for exit_id, item in sorted((profiles or {}).items()):
            name = item['outbound'].get('name')
            if not name or name in names:
                continue
            if item is profile or item['outbound'] == profile['outbound']:
                names[name] = 'egress'
            elif exit_id not in ('egress', 'dns-direct'):
                names[name] = exit_id
                extra[exit_id] = item
        if profile['outbound'].get('name'):
            names.setdefault(profile['outbound']['name'], 'egress')
        domain, network, _ = translate_acl(acl, names)
        used = {r.get('outbound') for r in domain + network}
        outbounds += [_socks(extra[t], t) for t in sorted(extra) if t in used]
    return {
        'log': {'disabled': True},
        'dns': {'servers': [{'type': 'udp', 'tag': 'local-dns', 'server': '172.18.0.53'}], 'final': 'local-dns', 'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'socks', 'tag': 'endpoint', 'listen': '127.0.0.1', 'listen_port': 11080}],
        'outbounds': outbounds,
        'route': {
            'default_domain_resolver': 'local-dns',
            'rule_set': [{'type': 'local', 'tag': 'cis', 'format': 'source', 'path': '/console-routing/cis.json'}],
            'rules': [
                {'port': 53, 'action': 'route', 'outbound': 'dns-direct'},
                {'action': 'sniff'},
                *domain,
                {'action': 'resolve', 'strategy': 'ipv4_only'},
                *network,
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
