#!/usr/bin/env python3
"""Start the console sidecar and HTTPS front if Docker left them stopped."""
import json
import subprocess
import sys

# Exact names only. Backup containers must stay stopped.
NAMES = ('vpn-console', 'rtrust-portal-https')


def inspect(name):
    result = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0]


def main():
    failed = False
    for name in NAMES:
        info = inspect(name)
        if info is None:
            print(name, 'absent')
            continue
        status = info['State']['Status']
        if status == 'running':
            print(name, 'running')
            continue
        policy = info['HostConfig']['RestartPolicy']['Name']
        if policy not in ('unless-stopped', 'always'):
            print(name, 'skipped', policy)
            continue
        started = subprocess.run(['docker', 'start', name], capture_output=True, text=True)
        if started.returncode:
            failed = True
            print(name, 'start failed', file=sys.stderr)
            continue
        print(name, 'started')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
