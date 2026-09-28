#!/usr/bin/env python3
"""Fresh h-ui 0.0.25 only. Run as root after initialization and service stop.
No secrets are printed. Never run this against an existing deployment.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the new H UI server')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'h-ui']).returncode == 0:
        raise SystemExit('Stop h-ui before bootstrapping')
    path = Path('/var/lib/h-ui/data/h_ui.db')
    output = Path('/root/h-ui-bootstrap.json')
    if not path.is_file() or output.exists():
        raise SystemExit('Expected initialized database and no existing bootstrap output')
    with sqlite3.connect(path) as db:
        accounts = db.execute('SELECT id, username, pass FROM account').fetchall()
        expected_hash = hashlib.sha224(b'sysadmin').hexdigest()
        if len(accounts) != 1 or accounts[0] != (1, 'sysadmin', expected_hash):
            raise SystemExit('Refusing to change a non-default database')
        password = secrets.token_hex(16)
        with open(output, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as f:
            json.dump({'username': 'sysadmin', 'password': password}, f, indent=2)
        db.execute('UPDATE account SET pass=?, con_pass=? WHERE id=1',
                   (hashlib.sha224(password.encode()).hexdigest(), secrets.token_hex(16)))
        db.execute('UPDATE config SET value=? WHERE key=?', (secrets.token_hex(32), 'JWT_SECRET'))
        db.execute('UPDATE config SET value=? WHERE key=?', ('0', 'HYSTERIA2_ENABLE'))
    print('Initialized. Credentials saved root-only in /root/h-ui-bootstrap.json')


if __name__ == '__main__':
    main()
