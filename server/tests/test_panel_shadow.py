"""Shadow import must not write panel databases or echo their secrets."""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'console'))
from panel_shadow import PanelImportError, ensure, import_panels, open_readonly

SECRET = 'con-pass-must-not-appear'
PORTAL_SECRET = 'tt-password-must-not-appear'
STANDBY_SECRET = 'standby-must-not-appear'


def _hui(path):
    with sqlite3.connect(path) as db:
        db.execute('''CREATE TABLE account(
            id INTEGER, username TEXT, pass TEXT, con_pass TEXT, quota INTEGER,
            download INTEGER, upload INTEGER, expire_time INTEGER, device_no INTEGER,
            deleted INTEGER, role TEXT, remark TEXT)''')
        db.execute('CREATE TABLE config(key TEXT, value TEXT)')
        db.execute(
            'INSERT INTO account VALUES(1,?,?,?,?,?,?,?,?,?,?,?)',
            ('sysadmin', 'a' * 56, 'admin-con', -1, 0, 0, 0, 1, 0, 'admin', None))
        db.execute(
            'INSERT INTO account VALUES(7,?,?,?,?,?,?,?,?,?,?,?)',
            ('alice', 'b' * 56, SECRET, 1024, 3, 4, 1_700_000_000_000, 3, 0, 'user', 'keep'))
        db.execute("INSERT INTO config VALUES('HYSTERIA2_CONFIG','listen: :443\n')")


def _portal(path, *, devices=True):
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE admins(id INTEGER, email TEXT, recovery_email TEXT, password_hash TEXT, created_at TEXT)')
        db.execute('CREATE TABLE users(id INTEGER, email TEXT, password_hash TEXT, status TEXT, created_at TEXT)')
        db.execute('''CREATE TABLE configs(
            id INTEGER, user_id INTEGER, tt_username TEXT, tt_password TEXT, label TEXT,
            created_at TEXT, revoked_at TEXT, device_id INTEGER)''')
        db.execute("INSERT INTO admins VALUES(1,'root@example.invalid',NULL,'hash-admin','2026-01-01')")
        db.execute("INSERT INTO users VALUES(4,'alice@example.invalid','hash-user','active','2026-01-02')")
        db.execute(
            "INSERT INTO configs VALUES(9,4,'alice-key',?,'Основной','2026-01-03',NULL,NULL)",
            (PORTAL_SECRET,))
        if not devices:
            return
        db.execute('''CREATE TABLE app_devices(
            id INTEGER, user_id INTEGER, name TEXT, token_hash TEXT, platform TEXT,
            created_at TEXT, last_seen_at TEXT, revoked_at TEXT)''')
        db.execute('''CREATE TABLE endpoint_standby(username TEXT, password TEXT)''')
        db.execute("INSERT INTO app_devices VALUES(3,4,'phone','token-hash','android','2026-01-04',NULL,NULL)")
        db.execute('INSERT INTO endpoint_standby VALUES(?,?)', ('spare', STANDBY_SECRET))


def _console(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    ensure(connection)
    return connection


def test_import_preserves_bytes_and_does_not_write_sources(tmp_path):
    hui = tmp_path / 'h_ui.db'
    portal = tmp_path / 'trusttunnel-web.db'
    _hui(hui)
    _portal(portal)
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (hui, portal)}
    with _console(tmp_path / 'console.db') as destination:
        report = import_panels(destination, hysteria=hui, portal=portal)
        stored = destination.execute('SELECT con_pass FROM hysteria_accounts WHERE id=7').fetchone()[0]
        portal_password = destination.execute('SELECT tt_password FROM portal_configs WHERE id=9').fetchone()[0]
        standby = destination.execute('SELECT password FROM portal_endpoint_standby').fetchone()[0]
        assert destination.execute('SELECT login FROM panel_admins WHERE source=? AND id=1', ('hysteria',)).fetchone()[0] == 'sysadmin'
    assert stored == SECRET
    assert portal_password == PORTAL_SECRET
    assert standby == STANDBY_SECRET
    assert report['hysteria']['users'] == 1
    assert report['hysteria']['admins'] == 1
    assert report['trusttunnel']['configs'] == 1
    assert report['hysteria']['config_fingerprint'] == hashlib.sha256(b'listen: :443\n').hexdigest()
    rendered = json.dumps(report)
    assert SECRET not in rendered
    assert PORTAL_SECRET not in rendered
    assert STANDBY_SECRET not in rendered
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (hui, portal)}


def test_readonly_handle_rejects_writes(tmp_path):
    path = tmp_path / 'h_ui.db'
    _hui(path)
    with open_readonly(path) as source:
        with pytest.raises(sqlite3.OperationalError):
            source.execute("UPDATE account SET con_pass='changed'")
    with sqlite3.connect(path) as check:
        assert check.execute("SELECT con_pass FROM account WHERE id=7").fetchone()[0] == SECRET


def test_second_import_is_refused_and_a_failed_import_rolls_back(tmp_path):
    hui = tmp_path / 'h_ui.db'
    _hui(hui)
    broken = tmp_path / 'broken.db'
    with sqlite3.connect(broken) as db:
        db.execute('CREATE TABLE admins(id INTEGER, email TEXT, password_hash TEXT)')
    with _console(tmp_path / 'console.db') as destination:
        import_panels(destination, hysteria=hui)
        with pytest.raises(PanelImportError, match='уже выполнен'):
            import_panels(destination, hysteria=hui)
        with pytest.raises(PanelImportError, match='users'):
            import_panels(destination, portal=broken)
        assert destination.execute('SELECT COUNT(*) FROM panel_import').fetchone()[0] == 1
        assert destination.execute("SELECT COUNT(*) FROM panel_import WHERE source='trusttunnel'").fetchone()[0] == 0


def test_missing_secret_column_copies_nothing(tmp_path):
    path = tmp_path / 'h_ui.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE account(id INTEGER, username TEXT, role TEXT)')
        db.execute("INSERT INTO account VALUES(1,'alice','user')")
    with _console(tmp_path / 'console.db') as destination:
        with pytest.raises(PanelImportError, match='con_pass'):
            import_panels(destination, hysteria=path)
        assert destination.execute('SELECT COUNT(*) FROM hysteria_accounts').fetchone()[0] == 0
        assert destination.execute('SELECT COUNT(*) FROM panel_import').fetchone()[0] == 0


def test_portal_without_optional_device_tables_is_imported(tmp_path):
    portal = tmp_path / 'trusttunnel-web.db'
    _portal(portal, devices=False)
    with _console(tmp_path / 'console.db') as destination:
        report = import_panels(destination, portal=portal)
        assert 'app_devices' in report['trusttunnel']['skipped']
        assert destination.execute('SELECT COUNT(*) FROM portal_users').fetchone()[0] == 1
