#!/usr/bin/env python3
"""Start the console sidecar and HTTPS front if Docker left them stopped."""
import json
import subprocess
import sys
import time

# Exact names only. Backup containers must stay stopped.
NAMES = ('vpn-console', 'rtrust-portal-https')
# created/dead cover a restore that never reached running. restarting and paused
# are already under Docker's control and must not be started again.
STARTABLE = {'exited', 'created', 'dead'}
POLICIES = {'unless-stopped', 'always'}


def inspect(name):
    result = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0]


def running(name):
    for _ in range(10):
        info = inspect(name)
        if info and info['State']['Status'] == 'running' and not info['State'].get('Restarting'):
            return True
        time.sleep(0.2)
    return False


def main():
    failed = False
    for name in NAMES:
        info = inspect(name)
        if info is None:
            print(name, 'absent')
            continue
        status = info['State']['Status']
        policy = info['HostConfig']['RestartPolicy']['Name']
        if status == 'running':
            print(name, 'running')
            continue
        if status not in STARTABLE or policy not in POLICIES:
            print(name, 'skipped', status, policy)
            continue
        started = subprocess.run(['docker', 'start', name], capture_output=True, text=True)
        if started.returncode or not running(name):
            failed = True
            print(name, 'start failed', file=sys.stderr)
            continue
        print(name, 'started')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
