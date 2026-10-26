#!/usr/bin/env python3
"""Only inside a disposable VM: real HTTPS admin session, queue and protocol installs.

Uses real releases, Docker builds and systemd. This is an installation/startup
acceptance test, not a VPN client traffic test. No credentials are printed.
"""
import argparse
import http.cookiejar
import json
from pathlib import Path
import re
import sqlite3
import ssl
import time
import urllib.parse
import urllib.request
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--only', nargs='+', choices=('trusttunnel', 'hysteria', 'cdn', 'amnezia'))
args = parser.parse_args()

if not Path('/run/tunnel-disposable-install-test').is_file():
    raise SystemExit('Disposable VM marker required')
access = json.loads(Path('/opt/tunnel-installer/access.json').read_text())
settings = json.loads(Path('/opt/tunnel-installer/settings.json').read_text())
origin = 'https://localhost:18443'
certificate = Path('/etc/letsencrypt/live') / settings['address'] / 'fullchain.pem'
cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies),
                                    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(certificate))))
with opener.open(origin + '/admin/login', urllib.parse.urlencode({'email': access['email'], 'password': access['password']}).encode(), timeout=60) as response:
    html = response.read().decode()
csrf = re.search(r'<meta name="csrf-token" content="([0-9a-f]{64})"', html)
assert csrf and any(cookie.name == 'admin_token' for cookie in cookies), 'Admin session/CSRF missing'


def install(name):
    identifier = 'fresh-install-' + uuid.uuid4().hex
    data = {'component': name}
    if name == 'amnezia':
        data['port'] = 47443
    request = urllib.request.Request(origin + '/console/api/jobs',
        json.dumps({'action': 'protocols.install', 'data': data, 'confirm': True, 'request_id': identifier}).encode(),
        headers={'Content-Type': 'application/json', 'Origin': origin, 'X-CSRF-Token': csrf[1]})
    with opener.open(request, timeout=60) as response:
        assert json.load(response)['id'] == identifier
    deadline = time.monotonic() + 3600
    while time.monotonic() < deadline:
        # Read the durable queue without repeated expensive full-host snapshots.
        with sqlite3.connect('file:/opt/vpn-console/data/console.db?mode=ro', uri=True) as db:
            row = db.execute('SELECT state,result FROM jobs WHERE id=?', (identifier,)).fetchone()
        if row and row[0] in ('success', 'failed', 'unknown'):
            result = json.loads(row[1] or '{}')
            if row[0] != 'success':
                raise RuntimeError(result.get('message', row[0]))
            return result
        time.sleep(3)
    raise RuntimeError('Timed out waiting for durable protocol job')


report = Path('/root/fresh-install-protocols-results.json')
selected = args.only or ('trusttunnel', 'hysteria', 'cdn', 'amnezia')
results = [item for item in json.loads(report.read_text()) if item['component'] not in selected] if args.only and report.exists() else []
for name in selected:
    started = time.time()
    try:
        result = install(name)
        results.append({'component': name, 'ok': True, 'seconds': round(time.time() - started, 1), 'result': result})
    except Exception as error:
        results.append({'component': name, 'ok': False, 'seconds': round(time.time() - started, 1), 'error': str(error)})
    report.write_text(json.dumps(results, ensure_ascii=False, indent=2))
    print(json.dumps(results[-1], ensure_ascii=False), flush=True)
with opener.open(origin + '/console/api/state', timeout=90) as response:
    state = json.load(response)
summary = [{k: item.get(k) for k in ('id', 'installed', 'version', 'state')} for item in state['protocols']['items']]
Path('/root/fresh-install-protocols-state.json').write_text(json.dumps(summary, indent=2))
print(json.dumps({'protocols': summary}, ensure_ascii=False), flush=True)
raise SystemExit(0 if all(item['ok'] for item in results) and all(item['installed'] for item in summary) else 1)
