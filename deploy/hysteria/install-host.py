#!/usr/bin/env python3
"""Fresh Hysteria 2 + H UI host install, started by the console agent as a transient unit.

Arguments are agent-built paths to release binaries it already verified by SHA-256.
Refuses to touch an existing installation. Follows docs/hysteria-server.md: the core
stays disabled until the operator configures it in H UI. No secrets are printed.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import sys
import time

BUILD = Path('/opt/vpn-console/build')
HERE = Path(__file__).resolve().parent
if not (HERE / 'host_platform.py').exists():
    sys.path.insert(0, str(HERE.parents[1] / 'server/console'))
import host_platform
HOME = Path('/var/lib/h-ui')
UNIT = Path('/etc/systemd/system/h-ui.service')
CORE = Path('/usr/local/bin/hysteria')
PANEL = Path('/usr/local/bin/h-ui')


class Refused(Exception):
    pass


def run(args, timeout=60):
    subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout)


def source(value):
    path = Path(value).resolve()
    stat = path.lstat()
    if BUILD not in path.parents or not path.is_file() or path.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
        raise Refused('Недопустимый файл установки')
    return path


def install(core, panel):
    if (HOME / 'data/h_ui.db').exists() or UNIT.exists() or PANEL.exists():
        raise Refused('H UI уже установлен на этом сервере; установка с нуля отклонена')
    # H UI listens on every interface: verify the actual UFW or firewalld guard.
    if not host_platform.hui_firewall_closed():
        raise Refused('TCP 8081 должен быть закрыт извне: UFW deny либо policy ' + host_platform.HUI_POLICY + ' в firewalld')
    try:
        pwd.getpwnam('hysteria')
    except KeyError:
        run(['useradd', '--system', '--no-create-home', '--home-dir', str(HOME), '--shell', '/usr/sbin/nologin', 'hysteria'])
    user = pwd.getpwnam('hysteria')
    config = Path('/etc/hysteria')
    config.mkdir(mode=0o750, exist_ok=True)
    os.chown(config, 0, user.pw_gid)
    for path in (HOME, HOME / 'bin', HOME / 'data', HOME / 'logs', HOME / 'export', HOME / 'geo'):
        path.mkdir(mode=0o750, exist_ok=True)
        os.chown(path, user.pw_uid, user.pw_gid)
    for origin, target in ((core, CORE), (panel, PANEL)):
        shutil.copyfile(origin, target)
        os.chown(target, 0, 0)
        target.chmod(0o755)
    managed = HOME / 'bin/hysteria-linux-amd64'
    shutil.copyfile(core, managed)
    os.chown(managed, user.pw_uid, user.pw_gid)
    managed.chmod(0o755)
    shutil.copyfile(HERE / 'h-ui.service', UNIT)
    UNIT.chmod(0o644)
    for target in (CORE, PANEL, UNIT, HOME):
        host_platform.restore_labels(target)
    run(['systemctl', 'daemon-reload'])
    try:
        # First start creates the default database; bootstrap replaces its default secrets.
        run(['systemctl', 'start', 'h-ui'])
        for _ in range(30):
            try:
                with sqlite3.connect(f'file:{HOME}/data/h_ui.db?mode=ro', uri=True) as db:
                    if db.execute('SELECT COUNT(*) FROM account').fetchone()[0]:
                        break
            except sqlite3.Error:
                pass
            time.sleep(1)
        else:
            raise Refused('H UI не создал базу данных')
        run(['systemctl', 'stop', 'h-ui'])
        run([sys.executable, str(HERE / 'bootstrap-hui.py')])
        run(['systemctl', 'enable', '--now', 'h-ui'])
    except BaseException:
        # Never leave a panel running with default credentials.
        subprocess.run(['systemctl', 'disable', '--now', 'h-ui'], capture_output=True)
        raise


def main():
    if os.geteuid() != 0 or len(sys.argv) != 4:
        raise SystemExit('Run by the console agent only')
    result = Path(sys.argv[3])
    if BUILD not in result.resolve().parents:
        raise SystemExit('Invalid result path')
    try:
        install(source(sys.argv[1]), source(sys.argv[2]))
        outcome = {'ok': True}
    except Refused as exc:
        outcome = {'ok': False, 'message': str(exc)}
    except Exception:
        outcome = {'ok': False, 'message': 'Установка Hysteria прервана; H UI остановлен. Проверьте журнал и удалите частичную установку вручную.'}
    result.write_text(json.dumps(outcome))
    raise SystemExit(0 if outcome['ok'] else 1)


if __name__ == '__main__':
    main()
