#!/usr/bin/env python3
"""Fresh Ubuntu 24.04 / CentOS Stream 9/10 x86_64 installation, managed through SSH."""
import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server/console'))
import host_platform
HOME = Path('/opt/trusttunnel-web')
STATE = Path('/opt/tunnel-installer')
MANAGED = (HOME, Path('/opt/vpn-console'), Path('/opt/amneziawg'), Path('/opt/xray-cdn'),
           Path('/var/lib/h-ui'), Path('/etc/systemd/system/h-ui.service'))


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def address(value):
    value = value.strip().lower()
    try:
        parsed = ipaddress.ip_address(value)
        if parsed.version != 4:
            raise ValueError('Используйте IPv4 или домен')
        return value
    except ValueError:
        if len(value) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value):
            raise ValueError('Нужен IPv4 или домен без https://, пути и порта') from None
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
            raise ValueError('Некорректное имя сервера')
        # Numeric dotted input must be an IPv4, not a misspelled IP accepted as DNS.
        if re.fullmatch(r'[0-9.]+', value):
            raise ValueError('Некорректный IPv4')
        return value


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(content)
    path.chmod(mode)


def wait_health(url):
    for _ in range(60):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError('Служба не отвечает: ' + url)


def preflight(resume):
    if os.geteuid() != 0:
        raise ValueError('Запустите через sudo bash deploy/install.sh')
    host_platform.platform_id()
    if platform.machine() != 'x86_64':
        raise ValueError('Поддерживается только x86_64')
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('Нужен сервер с systemd; обычный Docker-контейнер не подходит')
    if not (ROOT / 'client-source/Cargo.lock').is_file():
        raise ValueError('Используйте собранный архив инсталлятора: отсутствует client-source')
    if resume:
        if not (STATE / 'settings.json').is_file():
            raise ValueError('Нет прерванной установки для --resume')
        return
    occupied = [str(p) for p in (*MANAGED, STATE) if p.exists()]
    if occupied:
        raise ValueError('Нужен чистый сервер. Уже существуют: ' + ', '.join(occupied))
    if shutil.which('docker'):
        for name in ('trusttunnel-web', 'vpn-console', 'rtrust-portal-https', 'amnezia-awg', 'xray-cdn'):
            probe = subprocess.run(['docker', 'inspect', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                raise ValueError('Уже существует контейнер ' + name)
    for port in (18082, 18090, 18443, 8443):
        with socket.socket() as probe:
            try:
                probe.bind(('0.0.0.0', port))
            except OSError:
                raise ValueError(f'Порт {port} занят') from None


def compose(*args, **kwargs):
    return run(['docker', 'compose', '-p', 'trusttunnel-web', '-f', HOME / 'compose.yaml', *args], **kwargs)


def check_login(settings, certificate):
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(certificate))))
    payload = urllib.parse.urlencode({'email': settings['email'], 'password': settings['password']}).encode()
    with opener.open('https://localhost:18443/admin/login', payload, timeout=30) as response:
        if response.status != 200 or not any(cookie.name == 'admin_token' for cookie in cookies):
            raise RuntimeError('Первый вход администратора не подтверждён')
    with opener.open('https://localhost:18443/console/api/state', timeout=60) as response:
        state = json.load(response)
        if (response.status != 200 or not isinstance(state, dict) or state.get('error')
                or {item.get('id') for item in state.get('protocols', {}).get('items', [])}
                != {'trusttunnel', 'hysteria', 'cdn', 'amnezia'}):
            raise RuntimeError('API консоли или агент недоступен после входа; проверьте журнал агента и SELinux AVC')


def ensure_kernel_modules():
    modules = ('tun', 'overlay', 'br_netfilter', 'xt_addrtype')
    def load():
        return all(subprocess.run(['modprobe', name], capture_output=True).returncode == 0 for name in modules)
    if load():
        return
    try:
        # GenericCloud may carry only kernel-core; a newer modules package cannot
        # satisfy the running kernel. Try its exact NEVRA before requiring reboot.
        run(['dnf', 'install', '-y', 'kernel-modules-' + platform.release()])
    except subprocess.CalledProcessError:
        run(['dnf', 'install', '-y', 'kernel', 'kernel-modules'])
        raise ValueError('Модули работающего ядра недоступны. Установлено новое ядро: выполните sudo reboot, затем запустите тот же .run с --resume') from None
    if not load():
        raise ValueError('Не загружаются TUN/overlay/сетевые модули ядра. Перезагрузите сервер и повторите --resume; для VPS проверьте поддержку Docker/TUN у хостинга')


def install_selinux_policy():
    run(['dnf', 'install', '-y', 'selinux-policy-devel', 'make'])
    work = STATE / 'selinux'
    work.mkdir(mode=0o700, exist_ok=True)
    shutil.copyfile(ROOT / 'deploy/selinux/vpn_console.te', work / 'vpn_console.te')
    run(['make', '-f', '/usr/share/selinux/devel/Makefile', '-C', work, 'vpn_console.pp'])
    run(['semodule', '-i', work / 'vpn_console.pp'])


def dependencies(host):
    if host == 'ubuntu24':
        run(['apt-get', 'update'])
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'docker.io', 'docker-buildx', 'docker-compose-v2', 'python3-yaml', 'python3-cryptography', 'openssl', 'curl', 'ca-certificates', 'ufw'],
            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
        return None
    run(['dnf', 'install', '-y', 'ca-certificates', 'curl', 'openssl', 'gnupg2', 'firewalld', 'policycoreutils-python-utils', 'container-selinux', 'kmod'])
    ensure_kernel_modules()
    write(Path('/etc/modules-load.d/vpn-console-tun.conf'), 'tun\n', 0o644)
    # Verify the Docker RPM signing key before enabling its only repository.
    key = STATE / 'docker-ce.asc'
    with urllib.request.urlopen('https://download.docker.com/linux/centos/gpg', timeout=30) as response:
        write(key, response.read(65536).decode('ascii'))
    info = subprocess.check_output(['gpg', '--batch', '--with-colons', '--show-keys', str(key)], text=True)
    fingerprints = [line.split(':')[9] for line in info.splitlines() if line.startswith('fpr:')]
    if not fingerprints or fingerprints[0] != '060A61C51B558A7F742B77AAC52FEB6B621E9F35':
        raise ValueError('Не совпал отпечаток ключа подписи Docker RPM')
    run(['rpm', '--import', key])
    repo = Path('/etc/yum.repos.d/tunnel-docker-ce.repo')
    repo_text = '[tunnel-docker-ce-stable]\nname=Docker CE Stable\nbaseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable\nenabled=1\ngpgcheck=1\ngpgkey=file://' + str(key) + '\n'
    if repo.exists() and repo.read_text() != repo_text:
        raise ValueError('Существующий tunnel-docker-ce.repo отличается; проверьте вручную')
    write(repo, repo_text, 0o644)
    python_packages = ['python3.12', 'python3.12-pip'] if host.endswith('9') else ['python3', 'python3-pip']
    run(['dnf', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin', *python_packages])
    interpreter = '/usr/bin/python3.12' if host.endswith('9') else '/usr/bin/python3'
    venv = Path('/opt/vpn-console/venv')
    if not (venv / 'bin/python3').exists():
        run([interpreter, '-m', 'venv', '--symlinks', venv])
    run([venv / 'bin/pip', 'install', 'PyYAML==6.0.3', 'cryptography==50.0.2'])
    if host_platform.selinux_enabled():
        config = Path('/etc/docker/daemon.json')
        daemon = json.loads(config.read_text()) if config.exists() else {}
        if daemon.get('selinux-enabled') is False:
            raise ValueError('В существующей конфигурации Docker явно отключён SELinux; проверьте вручную')
        daemon['selinux-enabled'] = True
        write(config, json.dumps(daemon, indent=2), 0o644)
        host_platform.configure_container_labels()
        install_selinux_policy()
    return str(venv / 'bin/python3')


def load_images():
    # The archive digest comes from the manifest inside the already verified payload.
    images = json.loads((ROOT / 'manifest.json').read_text()).get('images') or {}
    archive = ROOT / images.get('archive', 'images/tunnel-images.tar.gz')
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            digest.update(chunk)
    if digest.hexdigest() != images.get('sha256'):
        raise ValueError('Контрольная сумма архива образов не совпала с manifest.json')
    run(['docker', 'load', '-i', archive], stdout=subprocess.DEVNULL)
    for tag in images['tags']:
        arch = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Os}}/{{.Architecture}}', tag], text=True).strip()
        if arch != 'linux/amd64':
            raise ValueError(f'Образ {tag} собран для {arch}, нужен linux/amd64')


def install(settings):
    host_os = host_platform.platform_id()
    print('[1/6] Установка зависимостей ' + host_os, flush=True)
    agent_python = dependencies(host_os)
    print('[2/6] Защита H UI и подготовка локального HTTPS-входа', flush=True)
    if host_os == 'ubuntu24':
        run(['ufw', 'allow', str(settings['ssh_port']) + '/tcp'])
        run(['ufw', 'insert', '1', 'deny', '8081/tcp'])
        run(['ufw', 'allow', '8443/tcp']); run(['ufw', 'allow', '8443/udp'])
        run(['ufw', 'allow', '443/udp']); run(['ufw', 'allow', '47443/udp'])
        run(['ufw', '--force', 'enable'])
    else:
        host_platform.protect_hui_firewalld(settings['ssh_port'])
    run(['systemctl', 'enable', '--now', 'docker'])
    host = settings['address']
    live = Path('/etc/letsencrypt/live') / host
    live.mkdir(parents=True, exist_ok=True, mode=0o755)
    live.chmod(0o755)
    if not (live / 'privkey.pem').exists():
        san = ('IP:' if re.fullmatch(r'[0-9.]+', host) else 'DNS:') + host
        run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '365',
             '-subj', '/CN=' + host, '-addext', 'subjectAltName=DNS:localhost,' + san,
             '-keyout', live / 'privkey.pem', '-out', live / 'fullchain.pem'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for cert in ('fullchain.pem', 'privkey.pem'):
        os.chown(live / cert, 0, 10001); (live / cert).chmod(0o640)
    # Parent directories must be traversable by the non-root portal.
    for folder in (Path('/etc/letsencrypt'), live.parent):
        folder.chmod(0o755)
    HOME.mkdir(exist_ok=True, mode=0o700)
    for folder in (HOME / 'data', HOME / 'data/runtime'):
        folder.mkdir(exist_ok=True, mode=0o750); os.chown(folder, 10001, 10001)
    env = dict(ADMIN_EMAIL=settings['email'], ADMIN_PASSWORD=settings['password'], SECRET_KEY=settings['secret'],
               PUBLIC_ADDRESS=host, CLIENT_CA_FILE=f'/certs/live/{host}/fullchain.pem',
               CONSOLE_ORIGIN='https://localhost:18443', CONSOLE_PUBLIC_ORIGIN='https://' + host,
               CONSOLE_USER_DOMAIN=host)
    if agent_python:
        env['CONSOLE_AGENT_PYTHON'] = agent_python
        if host_platform.selinux_enabled():
            env['CONSOLE_SELINUX_TYPE'] = 'vpn_console_t'
    write(HOME / '.env', ''.join(f'{k}={v}\n' for k, v in env.items()))
    portal = {'image': 'tunnel-fresh-portal:local', 'container_name': 'trusttunnel-web',
              'env_file': '.env', 'restart': 'unless-stopped', 'user': '10001:10001',
              'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'read_only': True,
              'tmpfs': ['/tmp:size=32m,mode=1777'],
              'ports': ['127.0.0.1:18082:8000', '8443:8443/tcp', '8443:8443/udp'],
              'volumes': ['./data:/data', '/etc/letsencrypt:/certs:ro'],
              'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
    nginx = {'image': 'nginx:1.28-alpine', 'container_name': 'rtrust-portal-https', 'restart': 'unless-stopped',
             'ports': ['127.0.0.1:18443:443'],
             'volumes': ['./nginx.conf:/etc/nginx/conf.d/default.conf:ro', '/etc/letsencrypt:/certs:ro']}
    # On resume preserve an endpoint image already installed through the panel.
    config = {'services': {'trusttunnel-web': portal, 'https': nginx}}
    if not (HOME / 'compose.yaml').exists():
        write(HOME / 'compose.yaml', json.dumps(config, indent=2))
    nginx_text = (ROOT / 'deploy/portal-nginx.conf').read_text().replace('onixus-rf.duckdns.org', host)
    if (HOME / 'nginx.conf').exists():
        # Upgrade only our redirect/header settings when resuming a partial install.
        # The external SSH port differs from nginx's internal TLS listener.
        nginx_text = (HOME / 'nginx.conf').read_text().replace('proxy_set_header Host $host;', 'proxy_set_header Host $http_host;')
        if 'absolute_redirect off;' not in nginx_text:
            anchor = '    listen 443 ssl;'
            if nginx_text.count(anchor) != 1:
                raise ValueError('Не найден HTTPS listener в nginx.conf; проверьте изменённую конфигурацию')
            nginx_text = nginx_text.replace(anchor, anchor + '\n    absolute_redirect off;', 1)
    write(HOME / 'nginx.conf', nginx_text, 0o644)
    for shared in (HOME / 'data', HOME / 'nginx.conf', Path('/etc/letsencrypt')):
        host_platform.restore_labels(shared)
    if (ROOT / 'images').is_dir():
        print('[3/6] Загрузка готовых образов портала и nginx', flush=True)
        load_images()
    else:
        print('[3/6] Сборка портала и Rust codec (первый раз — несколько минут)', flush=True)
        run(['docker', 'build', '-f', ROOT / 'deploy/fresh-portal.Dockerfile', '-t', 'tunnel-fresh-portal:local', ROOT])
    print('[4/6] Закрытая регистрация и создание администратора', flush=True)
    init = '''from app import db\nimport os\ndb.init_db()\ndb.set_settings({'panel_domain': os.environ['PUBLIC_ADDRESS'], 'conn_domain': os.environ['PUBLIC_ADDRESS'], 'conn_address': os.environ['PUBLIC_ADDRESS'], 'conn_port': '8443', 'cert_mode': 'external', 'registration_enabled': '0', 'brand_name': 'VPN', 'portal_url': 'https://localhost:18443'})\n'''
    compose('run', '--rm', '-T', '--no-deps', 'trusttunnel-web', 'python', '-', input=init, text=True)
    compose('up', '-d')
    wait_health('http://127.0.0.1:18082/healthz')
    print('[5/6] Установка консоли и агента протоколов', flush=True)
    run([sys.executable, ROOT / 'deploy/install-console.py', '--nginx', HOME / 'nginx.conf', '--local-health'])
    print('[6/6] Проверка HTTPS, входа и агента', flush=True)
    run(['curl', '--fail', '--silent', '--show-error', '--cacert', live / 'fullchain.pem', 'https://localhost:18443/console/healthz'])
    run(['systemctl', 'is-active', '--quiet', 'vpn-console-agent'])
    check_login(settings, live / 'fullchain.pem')
    access = {'url': 'https://localhost:18443/admin/login', 'email': settings['email'], 'password': settings['password'],
              'ssh': f"ssh -N -L 18443:127.0.0.1:18443 -p {settings['ssh_port']} root@{host}",
              'certificate_sha256': subprocess.check_output(['openssl', 'x509', '-in', str(live / 'fullchain.pem'), '-noout', '-fingerprint', '-sha256'], text=True).strip()}
    write(STATE / 'access.json', json.dumps(access, ensure_ascii=False, indent=2))
    write(STATE / 'complete', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + '\n')
    print('\nГотово. Пароль и команда SSH: sudo cat /opt/tunnel-installer/access.json\n'
          'Откройте SSH-туннель на своём компьютере, затем https://localhost:18443/admin/login.\n'
          'Сверьте отпечаток сертификата. В панели откройте «Протоколы» → «Проверить обновления» → «Установить».\n'
          'Hysteria требует дальнейшей настройки ядра в H UI; CDN — домена и настройки CDN.\n'
          'Сертификат самоподписанный, срок 365 дней; замените/продлите до истечения срока.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address'); parser.add_argument('--email')
    ssh = os.environ.get('SSH_CONNECTION', '').split()
    parser.add_argument('--ssh-port', type=int, default=int(ssh[3]) if len(ssh) == 4 else 22)
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        preflight(args.resume)
        if args.resume:
            if args.address or args.email:
                raise ValueError('--resume использует сохранённые настройки, без --address/--email')
            settings = json.loads((STATE / 'settings.json').read_text())
            if (STATE / 'complete').exists():
                print('Установка уже завершена. Доступ: sudo cat /opt/tunnel-installer/access.json')
                return 0
        else:
            host = args.address or (None if args.non_interactive else input('Публичный IPv4 или домен сервера: '))
            email = args.email or (None if args.non_interactive else input('Логин администратора (e-mail): '))
            if not host or not email:
                raise ValueError('Укажите --address и --email')
            host = address(host)
            if not re.fullmatch(r'[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', email) or not 1 <= args.ssh_port <= 65535:
                raise ValueError('Проверьте e-mail и SSH-порт')
            settings = dict(address=host, email=email, ssh_port=args.ssh_port,
                            password=secrets.token_urlsafe(24), secret=secrets.token_hex(48))
            STATE.mkdir(mode=0o700)
            write(STATE / 'settings.json', json.dumps(settings))
        install(settings)
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f'\nУстановка остановлена: {error}\nПосле устранения причины: sudo bash deploy/install.sh --resume', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
