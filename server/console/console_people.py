"""A person (nick plus contacts) owns at most one account per protocol.

Accounts are linked explicitly, never merged by matching names, and logins are
derived from the nick. Privileged calls arrive through the services bound by
console_app, so tests can still replace them on that module.
"""
import os
import re
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException

from app import db

# One person (nick + contacts) owns at most one account per protocol.
NICK = re.compile(r'[a-z0-9][a-z0-9_-]{2,31}')
NAMES = {'trusttunnel': 'TrustTunnel', 'hysteria': 'Hysteria', 'amnezia': 'AmneziaWG', 'cdn': 'CDN'}


def console_names():
    names = []
    for key in ('CONSOLE_PUBLIC_ORIGIN', 'CONSOLE_ORIGIN'):
        host = urlsplit(os.environ.get(key, '')).hostname
        if host and host not in names:
            names.append(host.lower())
    return names


def console_host(request):
    # The label is a display name, not a routing input. A forwarded Host is shown
    # only when it is one of the names this installation was configured with.
    host = (request.headers.get('host') or '').split(':')[0].strip().lower()
    allowed = console_names()
    if host in allowed:
        return host
    return allowed[0] if allowed else 'console'


def user_domain():
    return os.environ.get('CONSOLE_USER_DOMAIN') or urlsplit(os.environ.get('CONSOLE_ORIGIN', 'https://onixus-rf.duckdns.org')).hostname


def logins(nick, email=''):
    # Hysteria requires 6+ characters; TrustTunnel requires an e-mail-shaped login.
    return {'trusttunnel': email or f'{nick}@{user_domain()}', 'hysteria': nick if len(nick) >= 6 else nick + '-vpn',
            'amnezia': nick, 'cdn': nick}


def bind(connect, services):
    """Return person operations for one console module and its patchable services."""
    def calls():
        current = services() if callable(services) else services
        if current is None:
            raise RuntimeError('Сервисы консоли не заданы')
        return current

    def source_user(source, identifier):
        if source == 'trusttunnel':
            user = db.get_user(identifier)
            if not user:
                raise HTTPException(404, 'Пользователь не найден')
            return dict(user)
        if source in ('hysteria', 'amnezia', 'cdn'):
            users = calls().agent('snapshot').get(source + '_users', [])
            if isinstance(users, list):
                for user in users:
                    if user['id'] == identifier:
                        return user
            raise HTTPException(404, 'Пользователь не найден')
        raise HTTPException(422, 'Неизвестный источник')

    def person(identifier):
        with connect() as connection:
            row = connection.execute('SELECT * FROM people WHERE id=?', (identifier,)).fetchone()
            if not row:
                raise RuntimeError('Пользователь не найден')
            accounts = {r['source']: r['user_id'] for r in connection.execute('SELECT source,user_id FROM person_accounts WHERE person=?', (identifier,))}
            return dict(row, accounts=accounts)

    def link(person_id, source, user_id):
        with connect() as connection:
            owner = connection.execute('SELECT * FROM people WHERE id=?', (person_id,)).fetchone()
            connection.execute('INSERT INTO person_accounts VALUES(?,?,?)', (person_id, source, user_id))
            # Delivery and campaigns keep reading per-account contacts.
            connection.execute('INSERT OR REPLACE INTO contacts VALUES(?,?,?,?,?)', (source, user_id, owner['email'] or '', owner['chat_id'], owner['consent']))

    def unlink(source, user_id):
        with connect() as connection:
            connection.execute('DELETE FROM person_accounts WHERE source=? AND user_id=?', (source, user_id))
            connection.execute('DELETE FROM contacts WHERE source=? AND user_id=?', (source, user_id))

    def create_account(source, owner, admin):
        login = logins(owner['nick'], owner['email'] or '')[source]
        if source == 'trusttunnel':
            calls().legacy(admin, 'users/create', {'email': login, 'password': secrets.token_urlsafe(24)})
            user_id = db.get_user_by_email(login)['id']
            calls().legacy(admin, f'users/{user_id}/configs', {'label': 'Основной'})
            return user_id
        user_id = calls().agent(source + '.create', {'username': login, 'days': 365, 'devices': 3} if source == 'hysteria' else {'username': login}).get('id')
        if user_id is None:
            raise RuntimeError(NAMES[source] + ': учётка создана, но не найдена. Привяжите её вручную.')
        return user_id

    def delete_account(source, user_id, admin):
        if source == 'trusttunnel':
            if not db.get_user(user_id):
                return unlink(source, user_id)
            with db.connect() as connection:
                devices = [r['id'] for r in connection.execute('SELECT id FROM app_devices WHERE user_id=?', (user_id,))]
                integrated = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rtrust_credential_operations'").fetchone()
            # Device credentials are revoked through their owner before the account disappears.
            for device in devices:
                calls().managed_device_revoke(admin, device) if integrated else db.revoke_device(device)
            calls().legacy(admin, f'users/{user_id}/delete', {})
        else:
            calls().agent(source + '.delete', {'id': user_id})
        unlink(source, user_id)

    def each_account(owner, fn):
        done, failed = [], []
        for source, user_id in sorted(owner['accounts'].items()):
            try:
                fn(source, user_id)
                done.append(NAMES[source])
            except Exception as exc:
                failed.append(NAMES[source] + ': ' + (str(exc) if isinstance(exc, RuntimeError) else 'ошибка'))
        return done, failed

    def person_perform(action, data, admin):
        if action == 'person.create':
            with connect() as connection:
                person_id = connection.execute('INSERT INTO people(nick,email,chat_id,consent) VALUES(?,?,?,?)',
                                               (data['nick'], data['email'], data['chat_id'], int(data['consent']))).lastrowid
            owner = person(person_id)
            done, failed = [], []
            for source in data['protocols']:
                try:
                    link(person_id, source, create_account(source, owner, admin))
                    done.append(NAMES[source])
                except Exception as exc:
                    failed.append(NAMES[source] + ': ' + (str(exc) if isinstance(exc, RuntimeError) else 'ошибка'))
            if failed:
                raise RuntimeError(f"Пользователь {data['nick']} создан частично. Готово: {', '.join(done) or 'ничего'}. Ошибки: {'; '.join(failed)}. Недостающие протоколы добавьте в карточке пользователя.")
            return {'message': f"Пользователь {data['nick']} создан: {', '.join(done)}", 'id': person_id}
        owner = person(data['id'])
        if action == 'person.add':
            if data['source'] in owner['accounts']:
                raise RuntimeError('У пользователя уже есть учётка ' + NAMES[data['source']])
            link(owner['id'], data['source'], create_account(data['source'], owner, admin))
            return {'message': NAMES[data['source']] + ': учётка создана'}
        if action in ('person.block', 'person.unblock'):
            done, failed = each_account(owner, lambda source, user_id: calls().perform(source + action[6:], {'id': user_id}, admin))
        elif action == 'person.delete':
            done, failed = each_account(owner, lambda source, user_id: delete_account(source, user_id, admin))
            if not failed:
                with connect() as connection:
                    connection.execute('DELETE FROM people WHERE id=?', (owner['id'],))
                return {'message': f"Пользователь {owner['nick']} удалён вместе с учётками: {', '.join(done) or 'нет'}"}
        else:
            raise RuntimeError('Операция не поддерживается')
        if failed:
            raise RuntimeError('Выполнено не полностью. Готово: ' + (', '.join(done) or 'ничего') + '. Ошибки: ' + '; '.join(failed))
        return {'message': 'Изменение применено: ' + (', '.join(done) or 'нет учёток')}

    return source_user, person, link, unlink, delete_account, person_perform
