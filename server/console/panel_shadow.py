"""Read-only shadow of H UI and TrustTunnel portal accounts in console.db.

Phase 2 of the panel-retirement plan. The copy preserves source ids and secret
bytes so a later cutover can keep existing clients. It does not authenticate
anyone, start an endpoint, or write either panel database. Until that cutover
the panels remain the source of truth.
"""
import hashlib
import sqlite3
from pathlib import Path


class PanelImportError(Exception):
    """Refused import. The message names the check, not a secret."""


SCHEMA = '''
CREATE TABLE IF NOT EXISTS panel_import (
    source TEXT PRIMARY KEY,
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accounts INTEGER NOT NULL,
    fingerprint TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS panel_admins (
    source TEXT NOT NULL,
    id INTEGER NOT NULL,
    login TEXT NOT NULL,
    recovery_email TEXT,
    password_hash TEXT NOT NULL,
    created_at TEXT,
    PRIMARY KEY (source, id)
);
CREATE TABLE IF NOT EXISTS hysteria_accounts (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    con_pass TEXT NOT NULL,
    quota INTEGER NOT NULL,
    download INTEGER NOT NULL,
    upload INTEGER NOT NULL,
    expire_time INTEGER NOT NULL,
    device_no INTEGER NOT NULL,
    deleted INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role = 'user'),
    remark TEXT,
    login_at INTEGER,
    con_at INTEGER
);
CREATE TABLE IF NOT EXISTS portal_users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS portal_configs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES portal_users(id),
    tt_username TEXT NOT NULL UNIQUE,
    tt_password TEXT NOT NULL,
    label TEXT,
    created_at TEXT,
    revoked_at TEXT,
    device_id INTEGER
);
CREATE TABLE IF NOT EXISTS portal_devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES portal_users(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    created_at TEXT,
    last_seen_at TEXT,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS portal_enroll_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES portal_users(id),
    code_hash TEXT NOT NULL UNIQUE,
    created_at TEXT,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    device_id INTEGER REFERENCES portal_devices(id)
);
CREATE TABLE IF NOT EXISTS portal_endpoint_standby (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS portal_rtrust_credentials (
    device INTEGER PRIMARY KEY REFERENCES portal_devices(id),
    config INTEGER UNIQUE REFERENCES portal_configs(id),
    generation INTEGER NOT NULL,
    legacy_shared INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS portal_rtrust_credential_operations (
    id TEXT PRIMARY KEY,
    device INTEGER NOT NULL REFERENCES portal_devices(id),
    owner INTEGER NOT NULL REFERENCES portal_users(id),
    action TEXT NOT NULL,
    generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    requested INTEGER NOT NULL,
    applied INTEGER,
    error TEXT
);
'''

_HUI_REQUIRED = (
    'id', 'username', 'pass', 'con_pass', 'quota', 'download', 'upload',
    'expire_time', 'device_no', 'deleted', 'role',
)
_HUI_OPTIONAL = ('remark', 'login_at', 'con_at')
_PORTAL_USERS = ('id', 'email', 'password_hash', 'status', 'created_at')
_PORTAL_CONFIGS_REQUIRED = ('id', 'user_id', 'tt_username', 'tt_password')
_PORTAL_CONFIGS_OPTIONAL = ('label', 'created_at', 'revoked_at', 'device_id')
_PORTAL_DEVICES = (
    'id', 'user_id', 'name', 'token_hash', 'platform', 'created_at',
    'last_seen_at', 'revoked_at',
)
_PORTAL_ENROLL = (
    'id', 'user_id', 'code_hash', 'created_at', 'expires_at', 'used_at', 'device_id',
)
_OPTIONAL_PORTAL = {
    'app_devices': 'portal_devices',
    'enroll_codes': 'portal_enroll_codes',
    'endpoint_standby': 'portal_endpoint_standby',
    'rtrust_credentials': 'portal_rtrust_credentials',
    'rtrust_credential_operations': 'portal_rtrust_credential_operations',
}


def ensure(connection):
    """Create shadow tables. Existing rows are left untouched."""
    connection.executescript(SCHEMA)


def open_readonly(path):
    """Open a panel database without a writable handle.

    ``mode=ro`` is the URI guarantee; ``query_only`` is checked before any
    account row is read. A failed check closes the handle and copies nothing.
    """
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise PanelImportError('База панели не найдена')
    connection = sqlite3.connect(resolved.as_uri() + '?mode=ro', uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute('PRAGMA query_only=ON')
        if connection.execute('PRAGMA query_only').fetchone()[0] != 1:
            raise PanelImportError('База панели открылась не в режиме только чтения')
    except PanelImportError:
        connection.close()
        raise
    return connection


def import_panels(destination, *, hysteria=None, portal=None):
    """Copy one or both panels into an already-open console database.

    A source that already has a ``panel_import`` receipt is refused. A failed
    copy rolls back, including that receipt, so the same paths can be retried.
    The returned report contains counts and password fingerprints, never the
    passwords themselves.
    """
    if hysteria is None and portal is None:
        raise PanelImportError('Не указана база панели')
    ensure(destination)
    destination.execute('PRAGMA foreign_keys=ON')
    own = _database_path(destination)
    destination.execute('BEGIN IMMEDIATE')
    try:
        report = {}
        if hysteria is not None:
            report['hysteria'] = _import_hysteria(destination, hysteria, own)
        if portal is not None:
            report['trusttunnel'] = _import_portal(destination, portal, own)
    except Exception:
        destination.rollback()
        raise
    destination.commit()
    return report


def _database_path(connection):
    row = connection.execute("PRAGMA database_list").fetchone()
    if row is None or not row[2]:
        return None
    return Path(row[2]).resolve()


def _import_hysteria(destination, path, own):
    _refuse_same_file(path, own)
    _refuse_repeat(destination, 'hysteria')
    with open_readonly(path) as source:
        columns = _columns(source, 'account')
        _require(columns, _HUI_REQUIRED, 'account')
        selected = [name for name in _HUI_REQUIRED + _HUI_OPTIONAL if name in columns]
        rows = list(source.execute(
            'SELECT ' + ','.join(selected) + ' FROM account ORDER BY id'))
        config_fingerprint = _config_fingerprint(source)
    users = []
    admins = []
    for row in rows:
        role = _text(row, 'role', 'account')
        if role == 'user':
            users.append(row)
        elif role == 'admin':
            admins.append(row)
        else:
            raise PanelImportError('Неизвестная роль Hysteria у id=%s' % _identifier(row))
    _unique([_text(row, 'username', 'account') for row in users], 'Повторяющийся логин Hysteria')
    for row in users:
        destination.execute(
            '''INSERT INTO hysteria_accounts(
                   id,username,pass_hash,con_pass,quota,download,upload,expire_time,
                   device_no,deleted,role,remark,login_at,con_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (
                _identifier(row), _text(row, 'username', 'account'),
                _text(row, 'pass', 'account'), _text(row, 'con_pass', 'account'),
                _integer(row, 'quota', 'account'), _integer(row, 'download', 'account'),
                _integer(row, 'upload', 'account'), _integer(row, 'expire_time', 'account'),
                _integer(row, 'device_no', 'account'), _integer(row, 'deleted', 'account'),
                'user', _optional(row, 'remark'), _optional_int(row, 'login_at'),
                _optional_int(row, 'con_at'),
            ))
    for row in admins:
        destination.execute(
            '''INSERT INTO panel_admins(source,id,login,password_hash)
               VALUES('hysteria',?,?,?)''',
            (_identifier(row), _text(row, 'username', 'account'), _text(row, 'pass', 'account')))
    fingerprints = [
        _fingerprint(('hysteria-user', _identifier(row), _text(row, 'username', 'account'),
                      _text(row, 'con_pass', 'account')))
        for row in users
    ]
    fingerprints.extend(
        _fingerprint(('hysteria-admin', _identifier(row), _text(row, 'username', 'account'),
                      _text(row, 'pass', 'account')))
        for row in admins
    )
    receipt = _store_receipt(destination, 'hysteria', len(rows), fingerprints)
    return {
        'accounts': len(rows),
        'users': len(users),
        'admins': len(admins),
        'fingerprint': receipt,
        'config_fingerprint': config_fingerprint,
        'password_fingerprints': [
            {'id': _identifier(row), 'username': _text(row, 'username', 'account'),
             'fingerprint': _fingerprint((_text(row, 'con_pass', 'account'),))}
            for row in users
        ],
        'readonly': True,
    }


def _import_portal(destination, path, own):
    _refuse_same_file(path, own)
    _refuse_repeat(destination, 'trusttunnel')
    with open_readonly(path) as source:
        present = {row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('admins', 'users', 'configs'):
            if table not in present:
                raise PanelImportError('В базе портала нет таблицы %s' % table)
        admin_columns = _columns(source, 'admins')
        _require(admin_columns, ('id', 'email', 'password_hash'), 'admins')
        _require(_columns(source, 'users'), _PORTAL_USERS, 'users')
        config_columns = _columns(source, 'configs')
        _require(config_columns, _PORTAL_CONFIGS_REQUIRED, 'configs')
        copied = {
            'admins': list(source.execute(
                'SELECT id,email,%s,password_hash,%s FROM admins ORDER BY id' % (
                    'recovery_email' if 'recovery_email' in admin_columns else 'NULL AS recovery_email',
                    'created_at' if 'created_at' in admin_columns else 'NULL AS created_at'))),
            'users': list(source.execute(
                'SELECT ' + ','.join(_PORTAL_USERS) + ' FROM users ORDER BY id')),
            'configs': list(source.execute(
                'SELECT ' + ','.join(name for name in _PORTAL_CONFIGS_REQUIRED + _PORTAL_CONFIGS_OPTIONAL
                                     if name in config_columns) + ' FROM configs ORDER BY id')),
        }
        optional = {}
        skipped = []
        for table in _OPTIONAL_PORTAL:
            if table not in present:
                skipped.append(table)
                continue
            optional[table] = _read_optional(source, table)
    _unique([_text(row, 'email', 'users') for row in copied['users']], 'Повторяющийся email портала')
    _unique([_text(row, 'tt_username', 'configs') for row in copied['configs']],
            'Повторяющееся имя ключа TrustTunnel')
    fingerprints = []
    for row in copied['admins']:
        destination.execute(
            '''INSERT INTO panel_admins(source,id,login,recovery_email,password_hash,created_at)
               VALUES('trusttunnel',?,?,?,?,?)''',
            (_identifier(row), _text(row, 'email', 'admins'), _optional(row, 'recovery_email'),
             _text(row, 'password_hash', 'admins'), _optional(row, 'created_at')))
        fingerprints.append(_fingerprint((
            'portal-admin', _identifier(row), _text(row, 'password_hash', 'admins'))))
    for row in copied['users']:
        destination.execute(
            'INSERT INTO portal_users(id,email,password_hash,status,created_at) VALUES(?,?,?,?,?)',
            (_identifier(row), _text(row, 'email', 'users'), _text(row, 'password_hash', 'users'),
             _text(row, 'status', 'users'), _optional(row, 'created_at')))
        fingerprints.append(_fingerprint((
            'portal-user', _identifier(row), _text(row, 'password_hash', 'users'))))
    for row in copied['configs']:
        destination.execute(
            '''INSERT INTO portal_configs(
                   id,user_id,tt_username,tt_password,label,created_at,revoked_at,device_id)
               VALUES(?,?,?,?,?,?,?,?)''',
            (_identifier(row), _integer(row, 'user_id', 'configs'),
             _text(row, 'tt_username', 'configs'), _text(row, 'tt_password', 'configs'),
             _optional(row, 'label'), _optional(row, 'created_at'), _optional(row, 'revoked_at'),
             _optional_int(row, 'device_id')))
        fingerprints.append(_fingerprint((
            'portal-config', _identifier(row), _text(row, 'tt_username', 'configs'),
            _text(row, 'tt_password', 'configs'))))
    for table, rows in optional.items():
        _insert_optional(destination, table, rows)
        fingerprints.extend(_optional_fingerprints(table, rows))
    account_count = len(copied['admins']) + len(copied['users']) + len(copied['configs'])
    return {
        'accounts': account_count,
        'admins': len(copied['admins']),
        'users': len(copied['users']),
        'configs': len(copied['configs']),
        'fingerprint': _store_receipt(destination, 'trusttunnel', account_count, fingerprints),
        'password_fingerprints': [
            {'id': _identifier(row), 'username': _text(row, 'tt_username', 'configs'),
             'fingerprint': _fingerprint((_text(row, 'tt_password', 'configs'),))}
            for row in copied['configs']
        ],
        'skipped': skipped,
        'readonly': True,
    }


def _read_optional(source, table):
    if table == 'app_devices':
        _require(_columns(source, table), _PORTAL_DEVICES, table)
        return list(source.execute('SELECT ' + ','.join(_PORTAL_DEVICES) + ' FROM app_devices ORDER BY id'))
    if table == 'enroll_codes':
        _require(_columns(source, table), _PORTAL_ENROLL, table)
        return list(source.execute('SELECT ' + ','.join(_PORTAL_ENROLL) + ' FROM enroll_codes ORDER BY id'))
    if table == 'endpoint_standby':
        _require(_columns(source, table), ('username', 'password'), table)
        return list(source.execute('SELECT username,password FROM endpoint_standby ORDER BY username'))
    if table == 'rtrust_credentials':
        _require(_columns(source, table), ('device', 'config', 'generation', 'legacy_shared'), table)
        return list(source.execute(
            'SELECT device,config,generation,legacy_shared FROM rtrust_credentials ORDER BY device'))
    _require(_columns(source, table), (
        'id', 'device', 'owner', 'action', 'generation', 'state', 'requested', 'applied', 'error',
    ), table)
    return list(source.execute(
        '''SELECT id,device,owner,action,generation,state,requested,applied,error
           FROM rtrust_credential_operations ORDER BY id'''))


def _insert_optional(destination, table, rows):
    for row in rows:
        if table == 'app_devices':
            destination.execute(
                '''INSERT INTO portal_devices(
                       id,user_id,name,token_hash,platform,created_at,last_seen_at,revoked_at)
                   VALUES(?,?,?,?,?,?,?,?)''',
                (_identifier(row), _integer(row, 'user_id', table), _text(row, 'name', table),
                 _text(row, 'token_hash', table), _text(row, 'platform', table),
                 _optional(row, 'created_at'), _optional(row, 'last_seen_at'),
                 _optional(row, 'revoked_at')))
        elif table == 'enroll_codes':
            destination.execute(
                '''INSERT INTO portal_enroll_codes(
                       id,user_id,code_hash,created_at,expires_at,used_at,device_id)
                   VALUES(?,?,?,?,?,?,?)''',
                (_identifier(row), _integer(row, 'user_id', table), _text(row, 'code_hash', table),
                 _optional(row, 'created_at'), _text(row, 'expires_at', table),
                 _optional(row, 'used_at'), _optional_int(row, 'device_id')))
        elif table == 'endpoint_standby':
            destination.execute(
                'INSERT INTO portal_endpoint_standby(username,password) VALUES(?,?)',
                (_text(row, 'username', table), _text(row, 'password', table)))
        elif table == 'rtrust_credentials':
            destination.execute(
                '''INSERT INTO portal_rtrust_credentials(device,config,generation,legacy_shared)
                   VALUES(?,?,?,?)''',
                (_integer(row, 'device', table), _optional_int(row, 'config'),
                 _integer(row, 'generation', table), _integer(row, 'legacy_shared', table)))
        else:
            destination.execute(
                '''INSERT INTO portal_rtrust_credential_operations(
                       id,device,owner,action,generation,state,requested,applied,error)
                   VALUES(?,?,?,?,?,?,?,?,?)''',
                (_text(row, 'id', table), _integer(row, 'device', table),
                 _integer(row, 'owner', table), _text(row, 'action', table),
                 _integer(row, 'generation', table), _text(row, 'state', table),
                 _integer(row, 'requested', table), _optional_int(row, 'applied'),
                 _optional(row, 'error')))


def _optional_fingerprints(table, rows):
    if table == 'endpoint_standby':
        return [_fingerprint(('standby', _text(row, 'username', table), _text(row, 'password', table)))
                for row in rows]
    if table == 'app_devices':
        return [_fingerprint(('device', _identifier(row), _text(row, 'token_hash', table))) for row in rows]
    if table == 'enroll_codes':
        return [_fingerprint(('enroll', _identifier(row), _text(row, 'code_hash', table))) for row in rows]
    if table == 'rtrust_credentials':
        return [_fingerprint(('credential', _integer(row, 'device', table),
                              row['config'], _integer(row, 'generation', table))) for row in rows]
    return [_fingerprint(('operation', _text(row, 'id', table), _text(row, 'state', table))) for row in rows]


def _config_fingerprint(source):
    present = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'config' not in present:
        return None
    row = source.execute("SELECT value FROM config WHERE key='HYSTERIA2_CONFIG'").fetchone()
    if row is None or row['value'] is None:
        return None
    return hashlib.sha256(str(row['value']).encode()).hexdigest()


def _columns(connection, table):
    rows = list(connection.execute('PRAGMA table_info(%s)' % table))
    if not rows:
        raise PanelImportError('В базе нет таблицы %s' % table)
    return {row['name'] for row in rows}


def _require(columns, required, table):
    missing = [name for name in required if name not in columns]
    if missing:
        raise PanelImportError('%s: нет столбцов %s' % (table, ', '.join(missing)))


def _refuse_same_file(path, own):
    if own is not None and Path(path).resolve() == own:
        raise PanelImportError('Нельзя импортировать console.db саму в себя')


def _refuse_repeat(destination, source):
    if destination.execute('SELECT 1 FROM panel_import WHERE source=?', (source,)).fetchone():
        raise PanelImportError('Импорт %s уже выполнен' % source)


def _store_receipt(destination, source, accounts, fingerprints):
    receipt = hashlib.sha256('\n'.join(sorted(fingerprints)).encode()).hexdigest()
    destination.execute(
        'INSERT INTO panel_import(source,accounts,fingerprint) VALUES(?,?,?)',
        (source, accounts, receipt))
    return receipt


def _fingerprint(parts):
    return hashlib.sha256('\0'.join(str(part) for part in parts).encode()).hexdigest()


def _identifier(row):
    value = row['id']
    if type(value) is not int or value <= 0:
        raise PanelImportError('Некорректный id учётной записи')
    return value


def _text(row, name, table):
    value = row[name]
    if not isinstance(value, str) or value == '':
        raise PanelImportError('%s.%s пуст у id=%s' % (table, name, _safe_id(row)))
    return value


def _integer(row, name, table):
    value = row[name]
    if type(value) is not int:
        raise PanelImportError('%s.%s не число у id=%s' % (table, name, _safe_id(row)))
    return value


def _optional(row, name):
    if name not in row.keys():
        return None
    value = row[name]
    if value is None:
        return None
    if not isinstance(value, str):
        raise PanelImportError('Некорректное текстовое поле %s' % name)
    return value


def _optional_int(row, name):
    if name not in row.keys() or row[name] is None:
        return None
    if type(row[name]) is not int:
        raise PanelImportError('Некорректное числовое поле %s' % name)
    return row[name]


def _safe_id(row):
    value = row['id'] if 'id' in row.keys() else None
    return value if type(value) is int else '?'


def _unique(values, message):
    if len(values) != len(set(values)):
        raise PanelImportError(message)
