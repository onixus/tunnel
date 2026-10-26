"""Real EndpointManager driving fake_endpoint.py in a disposable directory."""
from pathlib import Path
import socket
import stat
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = 'vpn.example.invalid'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_listening(port, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=.2).close()
            return
        except OSError:
            time.sleep(.02)
    raise AssertionError('endpoint did not start listening')


def failing_after(calls):
    """secrets.token_urlsafe that raises on its calls-th use (mid standby rotation)."""
    import secrets
    real, count = secrets.token_urlsafe, [0]
    def token(*args):
        count[0] += 1
        if count[0] == calls:
            raise RuntimeError('synthetic failure inside standby rotation')
        return real(*args)
    return token


class Tunnel:
    """One authenticated client connection to the fake endpoint."""

    def __init__(self, port, username, password):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.stream = self.sock.makefile('rwb', buffering=0)
        self.stream.write(f'{username} {password}\n'.encode())
        self.status = self.stream.readline().strip().decode()

    def alive(self):
        try:
            self.stream.write(b'ping\n')
            return self.stream.readline() == b'ping\n'
        except OSError:
            return False

    def close(self):
        self.stream.close()
        self.sock.close()


class FakeEndpoint:
    """Points config at a sandbox and replaces endpoint.manager for one test."""

    def __init__(self, case, config, db, endpoint, parent):
        root = Path(tempfile.mkdtemp(dir=parent))
        self.workdir = root/'runtime'; self.workdir.mkdir()
        live = root/'certs/live'/DOMAIN; live.mkdir(parents=True)
        (live/'fullchain.pem').write_text('synthetic chain')
        (live/'privkey.pem').write_text('synthetic key')
        binary = root/'trusttunnel_endpoint'
        binary.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{ROOT/"server/tests/fake_endpoint.py"}" "$@"\n')
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        for name, value in (('ENDPOINT_WORKDIR', str(self.workdir)), ('CERT_DIR', str(root/'certs')),
                            ('ENDPOINT_BIN', str(binary))):
            p = patch.object(config, name, value); p.start(); case.addCleanup(p.stop)
        self.port = free_port()
        db.set_settings({'panel_domain': DOMAIN, 'conn_port': str(self.port)})
        self.manager = endpoint.EndpointManager()
        self.manager.restart_quiet, self.manager.restart_min_interval, self.manager.restart_max_delay = .2, .5, 3
        self.spawns = []
        spawn = self.manager._spawn
        def counted():
            spawn(); self.spawns.append(self.manager._proc.pid)
        self.manager._spawn = counted
        case.addCleanup(self.manager.stop)
        p = patch.object(endpoint, 'manager', self.manager); p.start(); case.addCleanup(p.stop)
        self.case = case

    def start(self):
        result = self.manager.reconcile()
        self.wait()
        return result

    def wait(self, port=None):
        wait_listening(port or self.port)

    def loaded_usernames(self):
        import tomllib
        return {c['username'] for c in tomllib.loads((self.workdir/'credentials.toml').read_text()).get('client', [])}

    def connect(self, username, password, port=None):
        tunnel = Tunnel(port or self.port, username, password)
        self.case.addCleanup(tunnel.close)
        return tunnel
