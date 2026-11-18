"""console.db: schema, migration and the audit log. Live VPN auth stays in H UI and the portal."""
import json
import sqlite3
from contextlib import contextmanager

import panel_shadow

# Set by console_app before the first call. Tests retarget that module's STATE.
state_dir = None


def _state():
    if state_dir is None:
        raise RuntimeError('Каталог консоли не задан')
    return state_dir()


@contextmanager
def connect():
    connection = sqlite3.connect(_state() / 'console.db', timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA journal_mode=WAL')
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init():
    _state().mkdir(mode=0o700, parents=True, exist_ok=True)
    with connect() as connection:
        connection.executescript('''
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT DEFAULT CURRENT_TIMESTAMP, actor INTEGER, action TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, actor INTEGER, action TEXT, payload TEXT, state TEXT, result TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP, updated TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS contacts(source TEXT, user_id INTEGER, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(source,user_id));
        CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, actor INTEGER, channel TEXT, subject TEXT, body TEXT, state TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS deliveries(campaign TEXT, recipient TEXT, state TEXT, error TEXT, PRIMARY KEY(campaign,recipient));
        CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY AUTOINCREMENT, nick TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS person_accounts(person INTEGER NOT NULL, source TEXT NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(source,user_id));
        ''')
        # Shadow tables only. Live auth still belongs to H UI and the portal.
        panel_shadow.ensure(connection)
        # Existing installations also need monotonic IDs: stale tabs/jobs retain person IDs.
        connection.execute('BEGIN IMMEDIATE')
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='people'").fetchone()[0]
        if 'AUTOINCREMENT' not in schema.upper():
            # Deleted IDs remain in the durable job history even when no live people remain.
            high_water = connection.execute("SELECT MAX(COALESCE((SELECT MAX(id) FROM people),0),COALESCE((SELECT MAX(CAST(json_extract(payload,'$.id') AS INTEGER)) FROM jobs WHERE action='person.delete' AND json_valid(payload)),0))").fetchone()[0]
            connection.execute("CREATE TABLE people_next(id INTEGER PRIMARY KEY AUTOINCREMENT, nick TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP)")
            connection.execute('INSERT INTO people_next SELECT id,nick,email,chat_id,consent,created FROM people')
            connection.execute('DROP TABLE people')
            connection.execute('ALTER TABLE people_next RENAME TO people')
            connection.execute("DELETE FROM sqlite_sequence WHERE name='people'")
            connection.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('people',?)", (high_water,))
        connection.execute("UPDATE jobs SET state='unknown',result=? WHERE state='running'", (json.dumps({'message': 'Сервис перезапущен. Проверьте состояние перед повтором.'}),))
        connection.execute("UPDATE deliveries SET state='unknown',error='Прервано; автоматический повтор отключён' WHERE state='sending'")
        connection.execute("UPDATE campaigns SET state='unknown' WHERE state='sending'")


def audit(actor, action, detail=''):
    with connect() as connection:
        connection.execute('INSERT INTO audit(actor,action,detail) VALUES(?,?,?)', (actor, action, detail))
