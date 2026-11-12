"""Boot recovery starts only the live console containers, never backups."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('restore_console', ROOT / 'deploy/restore-console.py')
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


def container(status, policy='unless-stopped', restarting=False):
    return {'State': {'Status': status, 'Restarting': restarting},
            'HostConfig': {'RestartPolicy': {'Name': policy}}}


def script(monkeypatch, states, start_code=0):
    calls = []
    seen = dict(states)

    def run(args, **kwargs):
        calls.append(args)
        if args[:2] == ['docker', 'inspect']:
            name = args[2]
            if name not in restore.NAMES or name not in seen:
                return SimpleNamespace(returncode=1, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout=json.dumps([seen[name]]), stderr='')
        if args[:2] == ['docker', 'start']:
            if start_code == 0:
                current = seen[args[2]]
                seen[args[2]] = container('running', current['HostConfig']['RestartPolicy']['Name'])
            return SimpleNamespace(returncode=start_code, stdout='', stderr='')
        return SimpleNamespace(returncode=1, stdout='', stderr='')

    monkeypatch.setattr(restore.subprocess, 'run', run)
    monkeypatch.setattr(restore.time, 'sleep', lambda *unused: None)
    return calls


def test_starts_stopped_console_and_leaves_running_https(monkeypatch):
    calls = script(monkeypatch, {
        'vpn-console': container('exited'),
        'rtrust-portal-https': container('running'),
        'vpn-console-backup-stale': container('exited'),
    })
    restore.main()
    assert ['docker', 'start', 'vpn-console'] in calls
    assert ['docker', 'start', 'rtrust-portal-https'] not in calls
    inspected = [args[2] for args in calls if args[:2] == ['docker', 'inspect']]
    assert inspected[0] == 'vpn-console' and set(inspected) <= set(restore.NAMES)


@pytest.mark.parametrize('status', ['restarting', 'paused', 'removing'])
def test_does_not_start_a_container_docker_still_owns(monkeypatch, status):
    calls = script(monkeypatch, {'vpn-console': container(status), 'rtrust-portal-https': container(status)})
    restore.main()
    assert not any(args[:2] == ['docker', 'start'] for args in calls)


def test_starts_a_created_container_and_requires_it_to_stay_up(monkeypatch):
    calls = script(monkeypatch, {
        'vpn-console': container('created'),
        'rtrust-portal-https': container('dead'),
    })
    restore.main()
    assert ['docker', 'start', 'vpn-console'] in calls
    assert ['docker', 'start', 'rtrust-portal-https'] in calls


def test_skips_a_container_that_was_intentionally_left_stopped(monkeypatch):
    calls = script(monkeypatch, {
        'vpn-console': container('exited', 'no'),
        'rtrust-portal-https': container('created', 'no'),
    })
    restore.main()
    assert not any(args[:2] == ['docker', 'start'] for args in calls)


def test_start_failure_fails_the_boot_unit(monkeypatch):
    script(monkeypatch, {'vpn-console': container('exited'), 'rtrust-portal-https': container('running')}, start_code=1)
    with pytest.raises(SystemExit):
        restore.main()


def test_success_exit_is_not_enough_when_the_container_stays_down(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        name = args[2]
        if name not in restore.NAMES:
            return SimpleNamespace(returncode=1, stdout='', stderr='')
        status = 'running' if name == 'rtrust-portal-https' else 'exited'
        return SimpleNamespace(returncode=0, stdout=json.dumps([container(status)]), stderr='')

    monkeypatch.setattr(restore.subprocess, 'run', run)
    monkeypatch.setattr(restore.time, 'sleep', lambda *unused: None)
    with pytest.raises(SystemExit):
        restore.main()
    assert ['docker', 'start', 'vpn-console'] in calls
