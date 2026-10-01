#!/usr/bin/env python3
"""Opt-in TrustTunnel image extension. Does not change the selected egress."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEST = Path('/opt/vpn-console')
COMPOSE = Path('/opt/trusttunnel-web/compose.yaml')
PROBE = DEST / 'probes' / 'trusttunnel'
ROUTING = DEST / 'trusttunnel-routing'


def run(args, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: ' + Path(args[0]).name + '; inspect locally (output suppressed)')
    return result.stdout.strip()


def build_context(directory, binary):
    shutil.copy2(binary, directory / 'sing-box')
    (directory / 'sing-box').chmod(0o755)
    shutil.copy2(ROOT / 'server/console/trusttunnel_routing.py', directory / 'trusttunnel_routing.py')
    (directory / 'patch.py').write_text('''from pathlib import Path
p = Path('/app/app/endpoint.py')
s = p.read_text()
anchor = '_VPN_TOML_TEMPLATE.format(port=port)'
replacement = 'trusttunnel_routing.forward_template(' + anchor + ')'
if replacement not in s:
    if s.count(anchor) != 1 or s.count('[forward_protocol.direct]') != 1:
        raise SystemExit('Unsupported endpoint generator; no changes applied')
    s = s.replace(anchor, replacement)
    s = 'from . import trusttunnel_routing\\n' + s
    compile(s, str(p), 'exec')
    p.write_text(s)
''')
    (directory / 'Dockerfile').write_text('''ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY sing-box /usr/local/bin/sing-box
COPY trusttunnel_routing.py /app/app/trusttunnel_routing.py
COPY patch.py /tmp/patch-routing.py
RUN python /tmp/patch-routing.py && rm /tmp/patch-routing.py
USER 10001:10001
''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-box', type=Path, required=True, help='Locally staged Linux binary, version 1.11 or newer')
    parser.add_argument('--sha256', required=True, help='Verified SHA256 of the staged binary')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    os.umask(0o077)
    actual_hash = hashlib.sha256(args.sing_box.read_bytes()).hexdigest()
    if len(args.sha256) != 64 or actual_hash != args.sha256.lower():
        raise SystemExit('sing-box SHA256 mismatch')
    if not Path('/etc/trusttunnel/routing-probe.toml').is_file():
        raise SystemExit('Stage a root-only native SOCKS client profile first; see docs/service-routing.md')
    current = json.loads(run(['docker', 'inspect', 'trusttunnel-web']))[0]
    files = current['Config'].get('Labels', {}).get('com.docker.compose.project.config_files', '')
    if files != str(COMPOSE):
        raise SystemExit('Compose source differs from expected file; reconcile the deployment before installing')
    run(['docker', 'exec', 'trusttunnel-web', 'python', '-c',
         "import tomllib; from pathlib import Path; from app import config; assert tomllib.loads((Path(config.ENDPOINT_WORKDIR)/'vpn.toml').read_text()).get('forward_protocol') == {'direct': {}}"])
    old = COMPOSE.read_text()
    config = yaml.safe_load(old)
    service = config['services']['trusttunnel-web']
    tag = 'trusttunnel-web:service-routing-' + time.strftime('%Y%m%d%H%M%S') + '-' + secrets.token_hex(3)
    backup = DEST / 'backups' / tag.split(':')[1]
    backup.mkdir(mode=0o700, parents=True)
    (backup / 'compose.yaml').write_text(old)
    old_probe = PROBE.read_bytes() if PROBE.exists() else None
    if old_probe is not None:
        (backup / 'probe').write_bytes(old_probe)
    PROBE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copy2(ROOT / 'scripts/trusttunnel-route-probe.py', PROBE)
    PROBE.chmod(0o700)
    changed = False
    try:
        # Also validates the credentials, TLS and both transports before replacing an image.
        before_ip = str(ipaddress.IPv4Address(run([str(PROBE)], 60)))
        with tempfile.TemporaryDirectory(prefix='tt-routing-image-') as tmp:
            directory = Path(tmp)
            build_context(directory, args.sing_box)
            run(['docker', 'build', '--build-arg', 'BASE_IMAGE=' + current['Image'], '-t', tag, str(directory)], 300)
        # Check the staged binary and supported configuration before any live replacement.
        from sys import path as module_path
        module_path.insert(0, str(ROOT / 'server/console'))
        from trusttunnel_routing import relay_config
        test_config = relay_config({'outbound': {'socks5': {'addr': '192.0.2.1:1080', 'username': 'test', 'password': 'test'}}})
        with tempfile.TemporaryDirectory(prefix='tt-routing-check-') as tmp:
            Path(tmp).chmod(0o755)
            check = Path(tmp) / 'relay.json'
            check.write_text(json.dumps(test_config))
            check.chmod(0o644)
            run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--mount', f'type=bind,src={check},dst=/relay.json,readonly',
                 '--entrypoint', '/usr/local/bin/sing-box', tag, 'check', '-c', '/relay.json'])
        ROUTING.mkdir(mode=0o750, exist_ok=True)
        os.chown(ROUTING, 0, 10001)
        ROUTING.chmod(0o750)
        route = ROUTING / 'trusttunnel.json'
        if not route.exists():
            route.write_text('{"schema":1,"exit":"direct"}')
        os.chown(route, 0, 10001)
        route.chmod(0o640)
        volumes = service.setdefault('volumes', [])
        for mount in volumes:
            target = mount.get('target') if isinstance(mount, dict) else mount.split(':')[1]
            if target == '/console-routing':
                raise RuntimeError('Routing mount already configured; use the documented image upgrade procedure')
        volumes.append({'type': 'bind', 'source': str(ROUTING), 'target': '/console-routing', 'read_only': True})
        service['image'] = tag
        COMPOSE.write_text(yaml.safe_dump(config, sort_keys=False))
        changed = True
        run(['docker', 'compose', '-f', str(COMPOSE), 'up', '-d', '--no-deps', '--pull', 'never', 'trusttunnel-web'])
        time.sleep(3)
        if run([str(PROBE)], 60) != before_ip:
            raise RuntimeError('Egress changed during installation')
        run(['docker', 'exec', 'trusttunnel-web', 'python', '-c',
             'from app import config, trusttunnel_routing as r; assert r.status(config.ENDPOINT_WORKDIR)["version"] == 1'])
        print('Installed routing adapter without changing egress. Backup:', backup)
    except BaseException:
        if changed:
            COMPOSE.write_text(old)
            run(['docker', 'compose', '-f', str(COMPOSE), 'up', '-d', '--no-deps', '--pull', 'never', 'trusttunnel-web'])
        if old_probe is None:
            PROBE.unlink(missing_ok=True)
        else:
            PROBE.write_bytes(old_probe)
            PROBE.chmod(0o700)
        raise


if __name__ == '__main__':
    main()
