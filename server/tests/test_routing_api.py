"""API adapter contract with an isolated queue and a fake portal identity adapter."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import threading
from types import ModuleType

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server/console'))
DATA = {'revision': 'a' * 64, 'group_exit': 'reserve', 'services': {}}
KEY = 'test-routing-request-0001'


@pytest.fixture
def api(tmp_path, monkeypatch):
    portal = ModuleType('console_app')
    portal.app = FastAPI()
    portal.WRITE_LOCK = threading.Lock()
    portal.AGENT = '/nonexistent/test-only.sock'
    portal.perform = lambda a, d, u: {'legacy': a}
    portal.audit = lambda *args: None
    calls = []

    @contextmanager
    def connect():
        con = sqlite3.connect(tmp_path / 'queue.db')
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    with connect() as con:
        con.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY,actor INTEGER,action TEXT,payload TEXT,state TEXT)')
    portal.connect = connect

    def actor(req, write=False):
        calls.append(('actor', write))
        if not req.headers.get('x-test-admin'):
            raise HTTPException(401, 'unauthenticated')
        if write and req.headers.get('x-csrf-token') != 'test-csrf':
            raise HTTPException(403, 'csrf')
        return int(req.headers['x-test-admin'])

    portal.actor = actor

    async def body(req):
        return await req.json()

    portal.body = body
    portal.agent = lambda op, data: calls.append((op, data)) or {'changes': [], 'untouched': [], 'control_plane': 'direct', 'revision': data['revision']}
    monkeypatch.setitem(sys.modules, 'console_app', portal)
    spec = importlib.util.spec_from_file_location('routing_api_under_test', ROOT / 'server/console/routing_app.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = TestClient(module.app)
    client.headers.update({'x-test-admin': '1', 'x-csrf-token': 'test-csrf'})
    return client, portal, module, calls


def enqueue(client, **changes):
    return client.post('/console/api/routing/jobs', json={**{'data': DATA, 'confirm': True, 'request_id': KEY}, **changes})


def test_preview_is_read_only_and_calls_write_auth(api):
    client, portal, _, calls = api
    assert client.post('/console/api/routing/preview', json=DATA).status_code == 200
    assert calls[0] == ('actor', True)
    assert calls[1][0] == 'routes.preview'
    with portal.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0] == 0


def test_confirm_required(api):
    assert enqueue(api[0], confirm=False).status_code == 422


@pytest.mark.parametrize('confirm', ['true', 1, None])
def test_confirm_is_not_truthiness(api, confirm):
    assert enqueue(api[0], confirm=confirm).status_code == 422


def test_auth_mandatory(api):
    client = api[0]
    del client.headers['x-test-admin']
    assert enqueue(client).status_code == 401


def test_csrf_mandatory(api):
    client = api[0]
    del client.headers['x-csrf-token']
    assert enqueue(client).status_code == 403
    assert client.post('/console/api/routing/preview', json=DATA).status_code == 403


def test_replay_does_not_duplicate_job(api):
    client, portal, _, _ = api
    assert enqueue(client).status_code == 200
    assert enqueue(client).status_code == 200
    with portal.connect() as c:
        rows = list(c.execute('SELECT * FROM jobs'))
    assert len(rows) == 1 and rows[0]['action'] == 'routes.services'
    assert json.loads(rows[0]['payload']) == DATA


def test_conflicting_replay_rejected(api):
    client = api[0]
    enqueue(client)
    assert enqueue(client, data={**DATA, 'group_exit': 'primary'}).status_code == 409


def test_replay_cannot_cross_admins(api):
    client = api[0]
    enqueue(client)
    client.headers['x-test-admin'] = '2'
    assert enqueue(client).status_code == 409


def test_parallel_route_jobs_rejected(api):
    client = api[0]
    enqueue(client)
    assert enqueue(client, request_id=KEY + '-second').status_code == 409


def test_legacy_route_job_also_blocks(api):
    client, portal, _, _ = api
    with portal.connect() as c:
        c.execute('INSERT INTO jobs VALUES(?,?,?,?,?)', ('legacy', 1, 'routes.apply', '{}', 'running'))
    assert enqueue(client).status_code == 409


def test_service_allowlist_rechecked_before_queue(api):
    assert enqueue(api[0], data={**DATA, 'services': {'host': {'mode': 'follow'}}}).status_code == 422


def test_legacy_worker_operations_still_delegate(api):
    _, _, module, _ = api
    assert module.perform('hysteria.create', {}, 1) == {'legacy': 'hysteria.create'}


def test_preview_conflict_returns_safe_message(api):
    client, portal, _, _ = api
    def fail(*args):
        raise RuntimeError('Маршруты изменились')
    portal.agent = fail
    result = client.post('/console/api/routing/preview', json=DATA)
    assert result.status_code == 409
    assert result.json()['detail'] == 'Маршруты изменились'
