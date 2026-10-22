"""Offline QR and real export-route tests; no live accounts, codecs, or VPNs."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import types
from unittest.mock import Mock
import xml.etree.ElementTree as ET

import cairosvg
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

CONSOLE = Path(__file__).resolve().parents[1] / 'console'
sys.path.insert(0, str(CONSOLE))
from config_qr import with_qr, TOO_LARGE, UNAVAILABLE

HY = 'hysteria2://fixture-secret@vpn.example.invalid:443/?sni=vpn.example.invalid&obfs=salamander&obfs-password=A%2Bb%26c#%D0%A2%D0%B5%D1%81%D1%82'
TT = 'tt://?fixture=canonical-codec-output&credential=fixture-secret&certificate=ZmFrZS1jZXJ0aWZpY2F0ZQ%3D%3D&verify=true'


def svg_bytes(reply):
    prefix, raw = reply['qr_data_url'].split(',', 1)
    assert prefix == 'data:image/svg+xml;base64'
    return base64.b64decode(raw, validate=True)


@pytest.mark.parametrize('content', [HY, TT, HY + '-Устройство'])
def test_qr_decodes_to_exact_canonical_export(content):
    reply = with_qr({'content': content, 'format': 'original'})
    assert reply['content'] == content and reply['format'] == 'original'
    assert reply['qr_error'] is None
    svg = svg_bytes(reply)
    root = ET.fromstring(svg)
    assert root.find('{http://www.w3.org/2000/svg}rect').attrib['fill'] == 'white'
    png = cairosvg.svg2png(bytestring=svg, scale=2)
    pixels = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
    decoded, points, _ = cv2.QRCodeDetector().detectAndDecode(pixels)
    assert points is not None and decoded == content


@pytest.mark.parametrize('content', ['tt://?' + 'x' * 3000, HY + 'x' * 10000, 'я' * 5000], ids=['capacity', 'work-bound', 'utf8-bound'])
def test_oversize_keeps_complete_link_and_returns_actionable_error(content):
    assert with_qr({'content': content}) == {
        'content': content, 'qr_data_url': None, 'qr_error': TOO_LARGE}


@pytest.mark.parametrize('content', [None, '', 42, ['not-a-link'], '\ud800'])
def test_invalid_content_has_no_broken_qr(content):
    reply = with_qr({'content': content})
    assert reply['content'] == content
    assert reply['qr_data_url'] is None and reply['qr_error'] == UNAVAILABLE


def test_renderer_exception_is_sanitized_and_does_not_break_export(monkeypatch):
    import qrcode
    monkeypatch.setattr(qrcode, 'QRCode', Mock(side_effect=RuntimeError('secret-error-value')))
    reply = with_qr({'content': HY})
    assert reply['content'] == HY and reply['qr_error'] == UNAVAILABLE
    assert 'secret-error-value' not in json.dumps(reply)


def test_missing_optional_renderer_does_not_break_export(monkeypatch):
    monkeypatch.setitem(sys.modules, 'qrcode', None)
    assert with_qr({'content': HY})['qr_error'] == UNAVAILABLE


def test_svg_contains_only_geometry_not_payload_or_active_markup():
    content = HY + '<script>alert(1)</script>'
    svg = svg_bytes(with_qr({'content': content}))
    assert b'fixture-secret' not in svg and b'<script' not in svg
    assert all(e.tag.split('}')[-1] in {'svg', 'rect', 'path'} for e in ET.fromstring(svg).iter())


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Load the actual application with isolated portal/codec boundaries."""
    portal_path = tmp_path / 'portal.db'
    @contextmanager
    def connect():
        connection = sqlite3.connect(portal_path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    with connect() as connection:
        connection.executescript('''
            CREATE TABLE users(id INTEGER, email TEXT, status TEXT, created_at TEXT);
            CREATE TABLE configs(id INTEGER, user_id INTEGER, tt_username TEXT, label TEXT,
                                 created_at TEXT, revoked_at TEXT, tt_password TEXT, device_id INTEGER);
            CREATE TABLE app_devices(id INTEGER, user_id INTEGER, name TEXT, platform TEXT,
                                     last_seen_at TEXT, revoked_at TEXT);
            INSERT INTO users VALUES(1,'fixture@example.invalid','active','test');
            INSERT INTO configs VALUES(7,1,'fixture','Fixture','test',NULL,'fixture-secret',NULL);
            INSERT INTO configs VALUES(8,1,'revoked','Revoked','test','test','revoked-secret',NULL);
        ''')
    def get_config(id):
        with connect() as connection:
            row = connection.execute('SELECT * FROM configs WHERE id=?', (id,)).fetchone()
            return dict(row) if row else None
    portal = types.ModuleType('app')
    portal.__path__ = []
    portal.config = types.SimpleNamespace(SECRET_KEY='isolated-test-secret')
    portal.db = types.SimpleNamespace(connect=connect, get_config=Mock(side_effect=get_config))
    portal.security = types.SimpleNamespace()
    portal.webauth = types.SimpleNamespace(
        ADMIN_COOKIE='admin_token',
        current_admin=lambda request: {'id': 1} if request.cookies.get('admin_token') == 'test-admin' else None)
    portal.mailer = types.SimpleNamespace(is_configured=lambda: False)
    portal.conninfo = types.SimpleNamespace()
    profiles = types.ModuleType('app.rtrust_profiles')
    profiles.managed_document = Mock(return_value={'content': 'canonical-managed-document'})
    profiles.codec = Mock(return_value={'content': TT, 'format': 'tt'})
    monkeypatch.setitem(sys.modules, 'app', portal)
    monkeypatch.setitem(sys.modules, 'app.rtrust_profiles', profiles)
    monkeypatch.setenv('CONSOLE_ORIGIN', 'https://console.example.invalid')
    spec = importlib.util.spec_from_file_location('console_qr_test_app', CONSOLE / 'console_app.py')
    ui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ui)
    ui.STATE = tmp_path / 'console'
    ui.init()
    ui.agent = Mock(side_effect=lambda op, data=None: {'content': HY} if op == 'hysteria.export' else {'hysteria_users': []})
    client = TestClient(ui.app)
    client.cookies.set('admin_token', 'test-admin')
    csrf = hmac.new(portal.config.SECRET_KEY.encode(), b'console:test-admin', hashlib.sha256).hexdigest()
    client.headers['X-CSRF-Token'] = csrf
    client.headers['Origin'] = 'https://console.example.invalid'
    yield types.SimpleNamespace(client=client, ui=ui, portal=portal, profiles=profiles)
    client.close()


def post(api, **changes):
    return api.client.post('/console/api/export', json=dict(source='hysteria', id=7, consent=True, qr=True) | changes)


@pytest.mark.parametrize('source,content', [('hysteria', HY), ('trusttunnel', TT)])
def test_real_export_route_adds_local_qr_without_logging_secret(api, source, content):
    response = post(api, source=source)
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['referrer-policy'] == 'no-referrer'
    assert "img-src 'self' data:" in response.headers['content-security-policy']
    assert response.json()['content'] == content
    ET.fromstring(svg_bytes(response.json()))
    if source == 'trusttunnel':
        api.profiles.managed_document.assert_called_once()
        api.profiles.codec.assert_called_once_with('canonical-managed-document', 'tt')
    else:
        api.ui.agent.assert_called_once_with('hysteria.export', {'id': 7})
    with api.ui.connect() as connection:
        rows = [dict(row) for row in connection.execute('SELECT * FROM audit')]
        assert len(rows) == 1 and rows[0]['detail'] == source + ':7'
        assert connection.execute('SELECT COUNT(*) FROM jobs').fetchone()[0] == 0
    assert 'fixture-secret' not in json.dumps(rows)
    state = api.client.get('/console/api/state')
    assert state.status_code == 200
    assert 'fixture-secret' not in state.text and 'qr_data_url' not in state.text


@pytest.mark.parametrize('changes', [
    {'consent': False}, {'consent': 'true'}, {'id': True}, {'id': 0}, {'id': -1},
    {'id': '7'}, {'qr': 'true'}, {'qr': 1}, {'qr': None}, {'source': 'unknown'},
])
def test_invalid_request_cannot_fetch_credentials(api, changes):
    assert post(api, **changes).status_code == 422
    api.ui.agent.assert_not_called()
    api.portal.db.get_config.assert_not_called()


@pytest.mark.parametrize('failure,status', [('unauthenticated', 401), ('csrf', 403), ('origin', 403)])
def test_qr_uses_existing_admin_csrf_and_origin_checks(api, failure, status):
    if failure == 'unauthenticated':
        api.client.cookies.clear()
    elif failure == 'csrf':
        api.client.headers.pop('X-CSRF-Token')
    else:
        api.client.headers['Origin'] = 'https://untrusted.example.invalid'
    assert post(api).status_code == status
    api.ui.agent.assert_not_called()


@pytest.mark.parametrize('id', [8, 999])
def test_revoked_or_missing_trusttunnel_key_is_not_rendered(api, id):
    assert post(api, source='trusttunnel', id=id).status_code == 404
    api.profiles.codec.assert_not_called()


def test_legacy_export_contract_does_not_generate_qr(api, monkeypatch):
    renderer = Mock(side_effect=AssertionError('legacy export must not render QR'))
    monkeypatch.setattr(api.ui, 'with_qr', renderer)
    assert post(api, qr=False).json() == {'content': HY}
    response = api.client.post('/console/api/export', json={'source': 'hysteria', 'id': 7, 'consent': True})
    assert response.json() == {'content': HY}
    renderer.assert_not_called()


def test_long_profile_still_downloads_through_real_route(api):
    content = 'tt://?' + 'x' * 4000
    api.profiles.codec.return_value = {'content': content}
    response = post(api, source='trusttunnel')
    assert response.status_code == 200
    assert response.json() == {'content': content, 'qr_data_url': None, 'qr_error': TOO_LARGE}


def test_qr_not_exposed_by_get_and_new_assets_are_served(api):
    assert api.client.get('/console/api/export').status_code == 405
    for path in ['config-export.js', 'config-export.css']:
        assert api.client.get('/console/static/' + path).status_code == 200
