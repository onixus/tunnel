"""Service-routing API; uses the existing admin session, worker, audit and job DB."""
import json
import re
import socket
from fastapi import HTTPException, Request
import console_app as console
from routing_policy import PolicyError, validate_request

app = console.app
_legacy_perform = console.perform


def perform(action, data, admin):
    lifecycle = action in ('protocols.install', 'protocols.update')
    if action not in ('routes.services', 'updates.server') and not lifecycle:
        return _legacy_perform(action, data, admin)
    # The persistent watchdog still owns recovery if this worker disappears.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        # A source build of a protocol image takes minutes.
        sock.settimeout(1800 if lifecycle else 600)
        sock.connect(console.AGENT)
        sock.sendall(json.dumps({'op': action, 'data': data}).encode() + b'\n')
        with sock.makefile('rb') as stream:
            result = json.loads(stream.readline(2 * 1024 * 1024))
    if not result.get('ok'):
        raise RuntimeError(result.get('error', 'Переключение не подтверждено'))
    return result['result']


console.perform = perform


def validated(data):
    try:
        return validate_request(data)
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from None


@app.post('/console/api/routing/preview')
async def preview(request: Request):
    console.actor(request, True)
    data = validated(await console.body(request))
    try:
        return console.agent('routes.preview', data)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from None


@app.post('/console/api/routing/jobs')
async def enqueue(request: Request):
    admin = console.actor(request, True)
    body = await console.body(request)
    if set(body) != {'data', 'confirm', 'request_id'} or body['confirm'] is not True:
        raise HTTPException(422, 'Требуется подтверждение переключения')
    key = body['request_id']
    if not isinstance(key, str) or not re.fullmatch('[a-zA-Z0-9-]{16,80}', key):
        raise HTTPException(422, 'Некорректный идентификатор запроса')
    data = validated(body['data'])
    with console.WRITE_LOCK:
        with console.connect() as c:
            # BEGIN IMMEDIATE makes the check/enqueue atomic across worker processes.
            c.execute('BEGIN IMMEDIATE')
            existing = c.execute('SELECT * FROM jobs WHERE id=?', (key,)).fetchone()
            if existing:
                if existing['actor'] != admin or existing['action'] != 'routes.services' or json.loads(existing['payload']) != data:
                    raise HTTPException(409, 'Идентификатор уже используется')
                return {'id': key, 'state': existing['state']}
            if c.execute("SELECT 1 FROM jobs WHERE action LIKE 'routes.%' AND state IN ('queued','running')").fetchone():
                raise HTTPException(409, 'Уже выполняется операция с маршрутами')
            c.execute('INSERT INTO jobs(id,actor,action,payload,state) VALUES(?,?,?,?,?)',
                      (key, admin, 'routes.services', json.dumps(data, sort_keys=True), 'queued'))
    console.audit(admin, 'routes.services', 'queued')
    return {'id': key, 'state': 'queued'}
