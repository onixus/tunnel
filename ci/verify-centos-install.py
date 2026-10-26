#!/usr/bin/env python3
"""Read-only post-install assertions inside the disposable CentOS VM."""
import json
from pathlib import Path
import subprocess
import sys

if not Path('/run/tunnel-disposable-install-test').is_file():
    raise SystemExit('Disposable VM marker required')
sys.path.insert(0, '/opt/vpn-console')
import host_platform


def run(*args):
    return subprocess.check_output(args, text=True, timeout=90).strip()


assert host_platform.platform_id().startswith('centos-stream')
assert run('getenforce') == 'Enforcing'
security = json.loads(run('docker', 'info', '--format', '{{json .SecurityOptions}}'))
assert 'name=selinux' in security, security
console_label = run('docker', 'inspect', 'vpn-console', '--format', '{{.ProcessLabel}}')
assert ':vpn_console_t:' in console_label, console_label
amnezia_label = run('docker', 'inspect', 'amnezia-awg', '--format', '{{.ProcessLabel}}')
assert ':vpn_amnezia_t:' in amnezia_label, amnezia_label
assert host_platform.hui_firewall_closed()
assert run('systemctl', 'is-active', 'vpn-console-agent', 'h-ui').splitlines() == ['active', 'active']
assert run('curl', '-fsS', '--max-time', '20', 'http://127.0.0.1:8081')
image = run('docker', 'inspect', 'trusttunnel-web', '--format', '{{.Image}}')
gateway = run('docker', 'network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}')
# Docker's trusted firewalld zone must not expose a native host panel.
blocked = run('docker', 'run', '--rm', '--network', 'bridge', '--entrypoint', 'python', image, '-c', '''import socket,sys
s=socket.socket();s.settimeout(5)
try:
    s.connect((sys.argv[1],8081))
except TimeoutError:
    print('blocked')
else:
    raise SystemExit('H UI reachable from Docker network')
finally:
    s.close()
''', gateway)
assert blocked == 'blocked'
rows = json.loads(Path('/root/fresh-install-protocols-results.json').read_text())
assert len(rows) == 4 and all(item['ok'] for item in rows)
versions = {item['component']: item['result'] for item in rows}
assert run('docker', 'exec', 'amnezia-awg', 'sing-box', 'version').startswith('sing-box version ')
shared = ['/opt/trusttunnel-web/data', '/opt/trusttunnel-web/nginx.conf',
          '/opt/vpn-console/data', '/run/vpn-console/agent.sock',
          '/opt/amneziawg/runtime/awg0.conf', '/opt/xray-cdn/runtime/config.json']
labels = {path: run('ls', '-Zd', path).split()[0] for path in shared}
assert all(':container_file_t:' in label for label in labels.values()), labels
assert Path('/opt/tunnel-installer/complete').is_file()
report = {'os': host_platform.release_info()['PRETTY_NAME'], 'selinux': 'Enforcing',
          'docker_security': security, 'hui_firewall': 'runtime+permanent IPv4+IPv6 ANY->HOST before zones',
          'console_process_label': console_label,
          'amnezia_process_label': amnezia_label,
          'hui_docker_network_probe': blocked, 'labels': labels, 'protocols': versions,
          'client_traffic_tested': False}
Path('/root/centos-install-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report, ensure_ascii=False, indent=2))
