"""Portal form CSRF and the cabinet must survive a missing profile exporter."""
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server/upstream'))
os.environ.setdefault('SECRET_KEY', 'guard-test-secret')
os.environ.setdefault('DATA_DIR', '/tmp/tunnel-guard-test')

from app.guards import PortalGuards, valid
from app import conninfo


def test_form_post_requires_the_signed_cookie_pair():
    app = FastAPI()
    app.add_middleware(PortalGuards)

    @app.get('/login', response_class=HTMLResponse)
    def login(request: Request):
        return f'<form method="post" action="/login"><input name="csrf" value="{request.state.csrf}"></form>'

    @app.post('/login')
    def submit(csrf: str = Form()):
        return HTMLResponse('ok ' + csrf[:4])

    client = TestClient(app)
    page = client.get('/login')
    assert page.status_code == 200
    assert page.headers['x-content-type-options'] == 'nosniff'
    assert 'frame-ancestors' in page.headers['content-security-policy']
    assert page.headers['x-frame-options'] == 'DENY'
    token = page.cookies['portal_csrf']
    assert valid(token)
    assert token in page.text
    assert client.post('/login', data={'email': 'a@b.c'}).status_code == 403
    accepted = client.post('/login', data={'csrf': token, 'email': 'a@b.c'})
    assert accepted.status_code == 200


def test_missing_exporter_does_not_raise(monkeypatch):
    def missing(*args):
        raise FileNotFoundError('missing')

    monkeypatch.setattr(conninfo, 'build_deeplink', missing)
    assert conninfo._deeplink('user', 'secret', 'vpn.example', '8443') == ''
