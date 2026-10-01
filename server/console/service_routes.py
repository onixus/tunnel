"""Privileged, transactional service routing with a persistent crash watchdog."""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import yaml

from routing_policy import SERVICES, PolicyError, initial_policy, make_plan, target, validate_saved
from trusttunnel_routing import relay_config

POLICY = Path('/opt/vpn-console/routing-policy.json')
TT_CONFIG = Path('/opt/vpn-console/trusttunnel-routing/trusttunnel.json')
TT_PROBE = Path('/opt/vpn-console/probes/trusttunnel')
BACKUPS = Path('/root/hysteria-route-backups/services')
PENDING = Path('/opt/vpn-console/routing-pending.json')
LOCK = '/run/hysteria-exit-switch.lock'
WATCHDOG_SCRIPT = '/opt/vpn-console/service_routes.py'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def atomic(path, value, mode=0o600, gid=None):
    """Persist file and rename before publishing success, including across crashes."""
    path = Path(path)
    temp = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            if gid is not None:
                os.fchown(stream.fileno(), 0, gid)
            os.fsync(stream.fileno())
        os.replace(temp, path)
        with open_dir(path.parent) as parent:
            os.fsync(parent)
    finally:
        temp.unlink(missing_ok=True)


@contextmanager
def open_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def route_lock(wait=False):
    with open(LOCK, 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            raise PolicyError('Уже выполняется переключение маршрута. Дождитесь результата.')
        yield


def trusted(path, executable=False):
    try:
        stat = path.lstat()
        return (path.is_file() and not path.is_symlink() and stat.st_uid == 0
                and not stat.st_mode & 0o022 and (not executable or os.access(path, os.X_OK)))
    except OSError:
        return False


def text_or_none(path):
    return path.read_text() if path.exists() else None


def tt_status(agent):
    # A fixed read-only command, never a command/path supplied by the browser.
    code = '''import json, pathlib, tomllib
from app import config
try:
 from app.trusttunnel_routing import status
 result = status(config.ENDPOINT_WORKDIR)
except ImportError:
 c = tomllib.loads((pathlib.Path(config.ENDPOINT_WORKDIR)/'vpn.toml').read_text())
 f = c.get('forward_protocol', {'direct': {}})
 result = {'version': 0, 'actual_exit': 'direct' if f == {'direct': {}} else 'custom'}
print(json.dumps(result))'''
    try:
        result = json.loads(agent.run(['docker', 'exec', 'trusttunnel-web', 'python', '-c', code], 8))
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except Exception:
        return {'version': 0, 'actual_exit': 'unknown', 'error': 'Не удалось прочитать конфигурацию TrustTunnel'}


class Runtime:
    def __init__(self, agent):
        self.agent = agent

    def observe(self):
        a = self.agent
        raw = a.module_switch().get_config()
        config = yaml.safe_load(raw)
        profiles = json.loads(a.EXITS.read_text())
        rules = config.get('acl', {}).get('inline', [])
        names = {p['outbound']['name'] + '(all)': name for name, p in profiles.items()}
        names['local(all)'] = 'direct'
        actual_h = names.get(rules[-1], 'custom') if rules else 'custom'
        tt = tt_status(a)
        tt_raw = text_or_none(TT_CONFIG)
        actual = {'hysteria': actual_h, 'trusttunnel': tt.get('actual_exit', 'unknown')}
        saved_raw = text_or_none(POLICY)
        saved = validate_saved(json.loads(saved_raw)) if saved_raw else initial_policy(actual)
        h_ready = actual_h in ('primary', 'reserve', 'direct')
        tt_ready = tt.get('version') == 1 and trusted(TT_PROBE, True) and TT_CONFIG.parent.is_dir()
        has_direct = any(o.get('name') == 'local' and o.get('type') == 'direct' for o in config.get('outbounds', []))
        services = {
            'hysteria': {'actual_exit': actual_h, 'configurable': h_ready,
                         'reason': '' if h_ready else 'Нестандартный catch-all; требуется проверка оператора',
                         'available_exits': [p for p in ('primary', 'reserve') if p in profiles] + (['direct'] if has_direct else [])},
            'trusttunnel': {'actual_exit': actual['trusttunnel'], 'configurable': tt_ready and actual['trusttunnel'] in ('direct', 'primary', 'reserve'),
                           'reason': ('Нестандартный маршрут TrustTunnel; требуется проверка оператора' if tt_ready and actual['trusttunnel'] not in ('direct', 'primary', 'reserve') else '') if tt_ready else 'Установите модуль маршрутизации TrustTunnel и нативную проверку подключения',
                           'available_exits': ['direct'] + ([p for p in ('primary', 'reserve') if p in profiles] if tt_ready else [])},
        }
        revision = digest({'hysteria': raw, 'profiles': profiles, 'trusttunnel': tt,
                           'tt_config': tt_raw, 'saved': saved, 'capabilities': services})
        return {'revision': revision, 'saved': saved, 'services': services,
                'raw_h': raw, 'config': config, 'profiles': profiles, 'raw_tt': tt_raw, 'raw_policy': saved_raw}

    def snapshot(self):
        s = self.observe()
        profiles, config = s['profiles'], s['config']
        policy = {'revision': s['revision'], 'group_exit': s['saved']['group_exit'], 'services': []}
        for name, title in SERVICES.items():
            mode = s['saved']['services'][name]
            live = s['services'][name]
            desired = target(mode, policy['group_exit']) if mode['mode'] != 'unmanaged' else live['actual_exit']
            policy['services'].append(dict(live, id=name, title=title, **mode, desired_exit=desired,
                                           drift=desired != live['actual_exit']))
        return {'selected': s['services']['hysteria']['actual_exit'], 'rules': config.get('acl', {}).get('inline', []),
                'revision': digest(config), 'exits': [{'id': k, 'name': p['outbound']['name'],
                'host': p.get('expected_host', p.get('expected_ip', '')), 'via': p['outbound']['socks5']['addr']}
                for k, p in profiles.items()], 'trusttunnel': s['services']['trusttunnel']['actual_exit'],
                'host': 'direct', 'policy': policy, 'pending': PENDING.exists()}

    def expected_ip(self, exit_id, profiles):
        if exit_id == 'direct':
            # Explicit ingress hostname, not an arbitrary browser-controlled address.
            from urllib.parse import urlsplit
            address = socket.gethostbyname(urlsplit(self.agent.ORIGIN).hostname)
        else:
            profile = profiles[exit_id]
            address = socket.gethostbyname(profile['expected_host']) if profile.get('expected_host') else profile['expected_ip']
        return str(ipaddress.IPv4Address(address))

    def prepare(self, plan, state):
        prepared = {}
        # Resolve/check only exits actually changing, not an unrelated offline reserve.
        profiles = deepcopy(state['profiles'])
        used = {c['after'] for c in plan['changes'] if c['restart'] and c['after'] != 'direct'}
        for name in sorted(used):
            profiles[name]['expected_ip'] = self.expected_ip(name, profiles)
            self.agent.module_switch().check_exit(profiles[name])
        for change in plan['changes']:
            if not change['restart']:
                continue
            name, exit_id = change['id'], change['after']
            expected = self.expected_ip(exit_id, profiles)
            if name == 'hysteria':
                config = deepcopy(state['config'])
                # Preserve every exception, including unknown/advanced ACL syntax and DNS.
                config['acl']['inline'][-1] = ('local' if exit_id == 'direct' else profiles[exit_id]['outbound']['name']) + '(all)'
                if exit_id != 'direct':
                    outbound = profiles[exit_id]['outbound']
                    config['outbounds'] = [o for o in config.get('outbounds', []) if o['name'] != outbound['name']] + [outbound]
                new = yaml.safe_dump(config, sort_keys=False)
                old = state['raw_h']
            else:
                value = {'schema': 1, 'exit': exit_id}
                if exit_id != 'direct':
                    value['relay'] = relay_config(profiles[exit_id])
                new = json.dumps(value, sort_keys=True)
                old = state['raw_tt']
            prepared[name] = {'before': old, 'after': new, 'expected_ip': expected,
                              'before_ip': self.expected_ip(change['before'], profiles)}
        return prepared

    def current(self, name):
        return self.agent.module_switch().get_config() if name == 'hysteria' else text_or_none(TT_CONFIG)

    def write(self, name, value, expected_current):
        if name == 'hysteria':
            self.agent.run(['systemctl', 'stop', 'h-ui'])
            try:
                if self.current(name) != expected_current:
                    raise PolicyError('Конфигурация изменилась при остановке H UI')
                self.agent.module_switch().write_config(value)
            finally:
                self.agent.run(['systemctl', 'start', 'h-ui'])
        else:
            if self.current(name) != expected_current:
                raise PolicyError('Конфигурация TrustTunnel изменена другим оператором')
            if value is None:
                TT_CONFIG.unlink(missing_ok=True)
            else:
                atomic(TT_CONFIG, value, 0o640, 10001)
            self.agent.run(['docker', 'restart', '--time', '10', 'trusttunnel-web'], 40)

    def probe(self, name, expected):
        if name == 'hysteria':
            got = self.agent.module_switch().probe_hysteria(expected)
        else:
            got = self.agent.run([str(TT_PROBE)], 60).strip()
        if str(ipaddress.IPv4Address(got)) != expected:
            raise PolicyError(SERVICES[name] + ': проверка реального выходного IP не пройдена')
        return got

    def arm(self, name, path):
        self.agent.run(['systemd-run', '--quiet', '--unit=' + name, '--on-active=240s',
                        sys.executable, WATCHDOG_SCRIPT, '--restore', str(path)])

    def disarm(self, name):
        self.agent.run(['systemctl', 'stop', name + '.timer'])


def save_journal(path, journal):
    atomic(path, json.dumps(journal, sort_keys=True))


def restore(runtime, path, journal):
    failures = []
    for name in reversed(journal['attempted']):
        item = journal['prepared'][name]
        try:
            current = runtime.current(name)
            if current in (item['before'], item['after']):
                # Also recover a crash between file replacement and service restart.
                runtime.write(name, item['before'], current)
                runtime.probe(name, item['before_ip'])
            else:
                raise PolicyError('Конфигурация изменена другим оператором')
        except Exception:
            failures.append(name)
    if failures:
        journal['rollback_errors'] = failures
        save_journal(path, journal)
        raise PolicyError('Откат не подтверждён для: ' + ', '.join(failures) + '. Сохранён журнал восстановления; требуется проверка оператора.')
    if journal['old_policy'] is None:
        POLICY.unlink(missing_ok=True)
    else:
        atomic(POLICY, journal['old_policy'])
    journal['status'] = 'rolled_back'
    save_journal(path, journal)
    PENDING.unlink(missing_ok=True)


def apply(runtime, data):
    with route_lock():
        if PENDING.exists():
            raise PolicyError('Предыдущее переключение не завершено. Сначала проверьте журнал восстановления.')
        state = runtime.observe()
        plan = make_plan(data, state)
        prepared = runtime.prepare(plan, state)
        # Preflight can take time; never use it as permission to overwrite a newer edit.
        if runtime.observe()['revision'] != state['revision']:
            raise PolicyError('Конфигурация изменилась во время проверки. Обновите страницу.')
        BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = 'vpn-services-rollback-' + secrets.token_hex(8)
        path = BACKUPS / (name + '.json')
        journal = {'status': 'pending', 'watchdog': name, 'prepared': prepared, 'attempted': [], 'old_policy': state['raw_policy']}
        save_journal(path, journal)
        atomic(PENDING, json.dumps({'journal': str(path)}))
        try:
            runtime.arm(name, path)  # No live service changes before watchdog arming.
        except BaseException:
            journal['status'] = 'aborted'
            save_journal(path, journal)
            PENDING.unlink(missing_ok=True)
            raise
        try:
            for service, item in prepared.items():
                if runtime.current(service) != item['before']:
                    raise PolicyError('Конфигурация изменена другим оператором')
                journal['attempted'].append(service)
                save_journal(path, journal)
                runtime.write(service, item['after'], item['before'])
                runtime.probe(service, item['expected_ip'])
            atomic(POLICY, json.dumps(plan['policy'], sort_keys=True))
            journal['status'] = 'committed'
            save_journal(path, journal)  # A late watchdog sees committed and does nothing.
            PENDING.unlink(missing_ok=True)
        except BaseException:
            restore(runtime, path, journal)
            runtime.disarm(name)
            raise PolicyError('Переключение не прошло проверку. Предыдущие конфигурации восстановлены.') from None
        try:
            runtime.disarm(name)
        except Exception:
            pass  # Committed journal makes a late timer harmless.
        return {'message': 'Политика маршрутов применена. ' + ('Переключённые сервисы проверены.' if prepared else 'Перезапуск сервисов не потребовался.'),
                'changes': plan['changes'], 'untouched': plan['untouched'], 'backup': path.name}


def watchdog_restore(path):
    import agent
    if os.geteuid() != 0 or path.parent != BACKUPS or not trusted(path):
        raise PolicyError('Недопустимый журнал отката')
    with route_lock(wait=True):
        journal = json.loads(path.read_text())
        if journal['status'] == 'pending':
            restore(Runtime(agent), path, journal)
        elif PENDING.exists() and json.loads(PENDING.read_text()).get('journal') == str(path):
            PENDING.unlink()


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--restore':
        raise SystemExit('Usage: service_routes.py --restore JOURNAL')
    watchdog_restore(Path(sys.argv[2]))
