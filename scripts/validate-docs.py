#!/usr/bin/env python3
"""Offline checks: links, JSON syntax, expected route invariants and secret markers.
Does not establish runtime correctness or replace a real secret scanner.
"""
import ipaddress
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
errors = []
for path in root.rglob('*.md'):
    if '.git' in path.parts:
        continue
    for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
        if '://' in target or target.startswith('#'):
            continue
        target = target.split('#')[0]
        if not (path.parent / target).exists():
            errors.append(f'{path.relative_to(root)}: missing {target}')
for path in (root / 'examples').rglob('*.json'):
    json.loads(path.read_text())
client = json.loads((root / 'examples/sing-box-client.json').read_text())
tun = next(i for i in client['inbounds'] if i['type'] == 'tun')
ip = ipaddress.ip_address('10.254.77.1')
assert not any(ip in ipaddress.ip_network(n) for n in tun['route_exclude_address'])
assert client['route']['final'] == 'hysteria'
for port in [8081, 18082]:
    assert any(r.get('port') == port and r.get('outbound') == 'hysteria'
               for r in client['route']['rules'])
for path in (root / 'examples').rglob('*'):
    if not path.is_file():
        continue
    content = path.read_text()
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', content):
        errors.append(f'{path}: private key material')
    if path.suffix == '.json':
        def walk(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    if k in {'password', 'secret', 'private_key'} and isinstance(v, str):
                        assert v.startswith('REPLACE_LOCALLY_'), f'{path}: unredacted {k}'
                    walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)
        walk(json.loads(content))
if errors:
    raise SystemExit('\n'.join(errors))
print('OK: local links, JSON, client route invariants, example secret markers')
