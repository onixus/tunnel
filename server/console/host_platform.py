"""Host-only platform, firewall and shared-volume SELinux helpers (no shell input)."""
import os
from pathlib import Path
import re
import shlex
import subprocess

HUI_POLICY = 'vpn-hui-guard'
HUI_RULES = tuple(f'rule family="{family}" port port="8081" protocol="tcp" drop' for family in ('ipv4', 'ipv6'))


def release_info():
    return {key: value.strip('"') for key, value in
            (line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)}


def platform_id(release=None):
    release = release_info() if release is None else release
    if release.get('ID') == 'ubuntu' and release.get('VERSION_ID') == '24.04':
        return 'ubuntu24'
    if (release.get('ID') == 'centos' and release.get('VERSION_ID') in ('9', '10')
            and 'Stream' in (release.get('NAME', '') + release.get('PRETTY_NAME', ''))):
        return 'centos-stream' + release['VERSION_ID']
    raise ValueError('Поддерживаются Ubuntu 24.04 и CentOS Stream 9/10 x86_64; CentOS 7/8 не поддерживаются')


def command(args, check=True):
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=120 if args[0] in ('semanage', 'restorecon') else 30,
                                env={**os.environ, 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('Истекло время ожидания ' + args[0]) from error
    if check and result.returncode:
        raise RuntimeError(args[0] + ': ' + (result.stderr.strip() or result.stdout.strip() or str(result.returncode))[-2000:])
    return result


def selinux_enabled():
    return Path('/sys/fs/selinux/enforce').exists()


def restore_labels(path):
    if selinux_enabled():
        command(['restorecon', '-RF', str(path)])


def amnezia_security_options():
    if selinux_enabled():
        try:
            if platform_id().startswith('centos-stream'):
                return ['--security-opt', 'label=type:vpn_amnezia_t']
        except ValueError:
            pass
    return []


def configure_container_labels():
    if not selinux_enabled():
        return
    # Do not rebuild the local policy for already correct mappings on every resume.
    existing = {}
    for line in command(['semanage', 'export']).stdout.splitlines():
        parts = shlex.split(line)
        if len(parts) > 3 and parts[0] == 'fcontext' and '-t' in parts:
            existing[parts[-1]] = (parts[parts.index('-t') + 1], parts[parts.index('-r') + 1] if '-r' in parts else 's0')
    # Shared s0 labels: portal, console and nginx must read the same data/certs.
    for expression in (r'/opt/trusttunnel-web/data(/.*)?', r'/opt/trusttunnel-web/nginx\.conf',
                       r'/opt/vpn-console/data(/.*)?', r'/run/vpn-console(/.*)?',
                       r'/etc/letsencrypt(/.*)?', r'/opt/amneziawg/runtime(/.*)?', r'/opt/xray-cdn/runtime(/.*)?'):
        if existing.get(expression) == ('container_file_t', 's0'):
            continue
        result = command(['semanage', 'fcontext', '-a', '-t', 'container_file_t', '-r', 's0', expression], check=False)
        if result.returncode:
            command(['semanage', 'fcontext', '-m', '-t', 'container_file_t', '-r', 's0', expression])


def protect_hui_firewalld(ssh_port):
    # Open the current SSH port before starting a firewall on an SSH-managed host.
    active = command(['firewall-cmd', '--state'], check=False).returncode == 0
    if not active:
        zone = command(['firewall-offline-cmd', '--get-default-zone']).stdout.strip()
        if not re.fullmatch('[A-Za-z0-9_-]+', zone):
            raise ValueError('Некорректная default zone firewalld')
        command(['firewall-offline-cmd', '--zone=' + zone, '--add-port=' + str(ssh_port) + '/tcp'])
        command(['systemctl', 'enable', '--now', 'firewalld'])
    default = command(['firewall-cmd', '--get-default-zone']).stdout.strip()
    zones = {default}
    # firewalld 2.4 annotates the zone heading as "public (default)".
    zones.update(line.split()[0] for line in command(['firewall-cmd', '--get-active-zones']).stdout.splitlines()
                 if line and not line[0].isspace() and line.split()[0] != 'docker')
    for zone in zones:
        if not re.fullmatch('[A-Za-z0-9_-]+', zone):
            raise ValueError('Некорректная active zone firewalld')
        for port in (str(ssh_port) + '/tcp', '8443/tcp', '8443/udp', '443/udp', '47443/udp'):
            command(['firewall-cmd', '--permanent', '--zone=' + zone, '--add-port=' + port])
    policies = command(['firewall-cmd', '--permanent', '--get-policies']).stdout.split()
    if HUI_POLICY not in policies:
        command(['firewall-cmd', '--permanent', '--new-policy=' + HUI_POLICY])
    prefix = ['firewall-cmd', '--permanent', '--policy=' + HUI_POLICY]
    command(prefix + ['--set-priority=-500'])
    command(prefix + ['--add-ingress-zone=ANY'])
    command(prefix + ['--add-egress-zone=HOST'])
    for rule in HUI_RULES:
        command(prefix + ['--add-rich-rule=' + rule])
    command(['firewall-cmd', '--reload'])
    if not hui_firewall_closed():
        raise ValueError('Запрет TCP 8081 в firewalld не подтверждён')


def hui_firewall_closed():
    try:
        firewalld = command(['firewall-cmd', '--state'], check=False).returncode == 0
    except OSError:
        firewalld = False
    if firewalld:
        # Both live and persistent policy must protect every network zone, including trusted/docker.
        if HUI_POLICY not in command(['firewall-cmd', '--get-active-policies'], check=False).stdout.split():
            return False
        for mode in ([], ['--permanent']):
            info = command(['firewall-cmd', *mode, '--info-policy=' + HUI_POLICY], check=False)
            if info.returncode:
                return False
            fields = {key.strip(): value.strip() for key, value in
                      (line.split(':', 1) for line in info.stdout.splitlines() if ':' in line)}
            if fields.get('ingress-zones', '').split() != ['ANY'] or fields.get('egress-zones', '').split() != ['HOST']:
                return False
            priority = fields.get('priority', '')
            if not re.fullmatch(r'-\d+', priority) or int(priority) >= 0:
                return False
            rules = {line.strip() for line in info.stdout.splitlines() if line.strip().startswith('rule ')}
            if fields.get('disable', 'no') != 'no' or fields.get('target') != 'CONTINUE' or set(HUI_RULES) != rules:
                return False
        return True
    try:
        result = command(['ufw', 'status'], check=False)
    except OSError:
        return False
    return result.returncode == 0 and any('8081/tcp' in line and 'DENY' in line for line in result.stdout.splitlines())
