"""Boot recovery starts only the live console containers, never backups."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('restore_console', ROOT / 'deploy/restore-console.py')
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


def container(status, policy='unless-stopped'):
    return {'State': {'Status': status}, 'HostConfig': {'RestartPolicy': {'Name': policy}}}


def test_starts_stopped_console_and_https_only(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[:2] == ['docker', 'inspect']:
            name = args[2]
            if name == 'vpn-console':
                payload = container('exited')
            elif name == 'rtrust-portal-https':
                payload = container('running')
            else:
                return SimpleNamespace(returncode=1, stdout='', stderr='')
            return SimpleNamespace(returncode=0, stdout=json.dumps([payload]), stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(restore.subprocess, 'run', run)
    restore.main()
    assert ['docker', 'start', 'vpn-console'] in calls
    assert ['docker', 'start', 'rtrust-portal-https'] not in calls
    assert all('backup' not in ' '.join(args) for args in calls)


def test_skips_a_container_that_was_intentionally_left_stopped(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=json.dumps([container('exited', 'no')]), stderr='')

    monkeypatch.setattr(restore.subprocess, 'run', run)
    restore.main()
    assert not any(args[:2] == ['docker', 'start'] for args in calls)
