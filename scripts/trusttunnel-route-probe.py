#!/usr/bin/env python3
"""Native HTTP/2 + HTTP/3 egress check; stdout contains only the verified IPv4."""
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import tomllib

PROFILE = Path('/etc/trusttunnel/routing-probe.toml')
CLIENT = Path('/usr/local/bin/trusttunnel_client')


def trusted(path, secret=False):
    st = path.lstat()
    if path.is_symlink() or not path.is_file() or st.st_uid != 0 or st.st_mode & (0o077 if secret else 0o022):
        raise ValueError('Unsafe probe file permissions')


def endpoint_config(raw):
    config = tomllib.loads(raw)
    endpoint = config.get('endpoint', {})
    if config.get('vpn_mode', 'general') != 'general' or config.get('exclusions') or 'tun' in config.get('listener', {}):
        raise ValueError('Probe profile must not contain TUN or split routing')
    if endpoint.get('skip_verification', False) is not False:
        raise ValueError('TLS verification is mandatory')
    required = ('hostname', 'username', 'password')
    if any(not isinstance(endpoint.get(k), str) or not endpoint[k] for k in required):
        raise ValueError('Incomplete native client profile')
    addresses = endpoint.get('addresses')
    if not isinstance(addresses, list) or not addresses or not all(isinstance(v, str) for v in addresses):
        raise ValueError('Missing endpoint addresses')
    # Only connection settings are copied. No host DNS, TUN or routing settings.
    allowed = (*required, 'addresses', 'certificate', 'client_random', 'anti_dpi', 'dns_upstreams')
    return {k: endpoint[k] for k in allowed if k in endpoint}


def probe(endpoint, protocol):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        address = '127.0.0.1:' + str(listener.getsockname()[1])
    username, password = secrets.token_hex(8), secrets.token_hex(16)
    settings = dict(endpoint, has_ipv6=False, skip_verification=False, upstream_protocol=protocol)
    text = 'vpn_mode = "general"\nkillswitch_enabled = false\nexclusions = []\n[endpoint]\n'
    text += ''.join(k + ' = ' + json.dumps(v, ensure_ascii=False) + '\n' for k, v in settings.items())
    text += '[listener.socks]\naddress = ' + json.dumps(address) + '\nusername = ' + json.dumps(username) + '\npassword = ' + json.dumps(password) + '\n'
    with tempfile.TemporaryDirectory(prefix='tt-route-probe-') as tmp:
        path = Path(tmp) / 'client.toml'
        path.write_text(text)
        path.chmod(0o600)
        proc = subprocess.Popen([str(CLIENT), '--config', str(path)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(3):
                time.sleep(1)
                if proc.poll() is not None:
                    raise RuntimeError('Native client exited')
                curl = 'proxy = ' + json.dumps('socks5h://' + address) + '\nproxy-user = ' + json.dumps(username + ':' + password) + '\n'
                result = subprocess.run(['curl', '--config', '-', '--noproxy', '', '--silent', '--fail',
                                         '--connect-timeout', '3', '--max-time', '6', 'https://api.ipify.org'],
                                        input=curl, text=True, capture_output=True, timeout=8)
                if result.returncode == 0:
                    return str(ipaddress.IPv4Address(result.stdout.strip()))
            raise RuntimeError('Native egress check failed')
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def main():
    os.umask(0o077)
    trusted(PROFILE, True)
    trusted(CLIENT)
    endpoint = endpoint_config(PROFILE.read_text())
    first = probe(endpoint, 'http2')
    if probe(endpoint, 'http3') != first:
        raise RuntimeError('HTTP/2 and HTTP/3 use different exits')
    print(first)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Native TrustTunnel routing probe failed; inspect profile and connectivity locally') from None
