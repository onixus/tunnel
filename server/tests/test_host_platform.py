"""Supported OS boundaries and fail-closed firewall verification, without host changes."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'console'))
import host_platform as host


@pytest.mark.parametrize('release,expected', [
    ({'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'ubuntu24'),
    ({'ID': 'centos', 'VERSION_ID': '9', 'NAME': 'CentOS Stream'}, 'centos-stream9'),
    ({'ID': 'centos', 'VERSION_ID': '10', 'PRETTY_NAME': 'CentOS Stream 10'}, 'centos-stream10'),
])
def test_supported_platforms(release, expected):
    assert host.platform_id(release) == expected


@pytest.mark.parametrize('release', [
    {'ID': 'centos', 'VERSION_ID': '7', 'NAME': 'CentOS Linux'},
    {'ID': 'centos', 'VERSION_ID': '8', 'NAME': 'CentOS Stream'},
    {'ID': 'centos', 'VERSION_ID': '9', 'NAME': 'CentOS Linux'},
    {'ID': 'ubuntu', 'VERSION_ID': '22.04'},
    {'ID': 'rocky', 'VERSION_ID': '9'},
])
def test_unverified_or_eol_platform_rejected(release):
    with pytest.raises(ValueError):
        host.platform_id(release)


@pytest.mark.parametrize('broken', ['', 'runtime-rule', 'persistent-rule', 'trusted-ingress', 'wrong-egress', 'late-priority', 'early-accept', 'disabled', 'accept-target'])
def test_hui_firewall_requires_both_families_and_persistent_host_policy(monkeypatch, broken):
    def command(args, check=True):
        option = args[-1]
        output, code = '', 0
        if option == '--get-active-policies':
            output = host.HUI_POLICY
        elif option == '--info-policy=' + host.HUI_POLICY:
            ingress = 'trusted' if broken == 'trusted-ingress' else 'ANY'
            egress = 'ANY' if broken == 'wrong-egress' else 'HOST'
            priority = '500' if broken == 'late-priority' else '-500'
            missing_rule = ((broken == 'runtime-rule' and '--permanent' not in args)
                            or (broken == 'persistent-rule' and '--permanent' in args))
            rules = host.HUI_RULES[:1] if missing_rule else host.HUI_RULES
            output = f'{host.HUI_POLICY} (active)\n  priority: {priority}\n  ingress-zones: {ingress}\n  egress-zones: {egress}\n' + '\n'.join(rules)
            output += '\n  target: ' + ('ACCEPT' if broken == 'accept-target' else 'CONTINUE')
            output += '\n  disable: ' + ('yes' if broken == 'disabled' else 'no')
            if broken == 'early-accept':
                output += '\n  rule priority="-1" port port="8081" protocol="tcp" accept'
        else:
            assert option == '--state', 'Unexpected firewalld CLI flag'
        return SimpleNamespace(returncode=code, stdout=output)
    monkeypatch.setattr(host, 'command', command)
    assert host.hui_firewall_closed() is (not broken)


def test_no_firewall_fails_closed(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError()
    monkeypatch.setattr(host, 'command', missing)
    assert not host.hui_firewall_closed()


def test_shared_container_labels_are_persistent_and_dont_disable_selinux(monkeypatch):
    calls = []
    monkeypatch.setattr(host, 'selinux_enabled', lambda: True)
    monkeypatch.setattr(host, 'command', lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0, stdout=''))
    host.configure_container_labels()
    host.restore_labels('/opt/amneziawg/runtime')
    assert calls[0] == ['semanage', 'export']
    assert all(args[:5] == ['semanage', 'fcontext', '-a', '-t', 'container_file_t'] for args in calls[1:-1])
    assert any('/run/vpn-console' in args[-1] for args in calls)
    assert calls[-1] == ['restorecon', '-RF', '/opt/amneziawg/runtime']


def test_firewalld_24_default_zone_annotation_and_ssh_before_enable(monkeypatch):
    calls = []
    def command(args, check=True):
        calls.append(args)
        output, code = '', 0
        if args == ['firewall-cmd', '--state']:
            code = 1
        if args[-1] == '--get-default-zone':
            output = 'public\n'
        if args[-1] == '--get-active-zones':
            output = 'public (default)\n  interfaces: enp0s2\ndocker\n  interfaces: docker0\n'
        return SimpleNamespace(stdout=output, returncode=code)
    monkeypatch.setattr(host, 'command', command)
    monkeypatch.setattr(host, 'hui_firewall_closed', lambda: True)
    host.protect_hui_firewalld(2222)
    assert calls.index(['firewall-offline-cmd', '--zone=public', '--add-port=2222/tcp']) < calls.index(['systemctl', 'enable', '--now', 'firewalld'])
    assert ['firewall-cmd', '--permanent', '--zone=public', '--add-port=8443/tcp'] in calls
    assert not any('default)' in arg or '--zone=docker' in arg for call in calls for arg in call)


def test_resume_skips_existing_shared_mapping(monkeypatch):
    calls = []
    expression = '/run/vpn-console(/.*)?'
    def command(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="fcontext -a -f a -t container_file_t -r 's0' '" + expression + "'\n")
    monkeypatch.setattr(host, 'selinux_enabled', lambda: True)
    monkeypatch.setattr(host, 'command', command)
    host.configure_container_labels()
    assert calls[0] == ['semanage', 'export']
    assert not any(args[-1] == expression for args in calls)
    assert any(args[1:3] == ['fcontext', '-a'] and '-r' in args for args in calls)


@pytest.mark.parametrize('enabled,platform,expected', [(True,'centos-stream9',True),(True,'centos-stream10',True),(False,'centos-stream10',False),(True,'ubuntu24',False)])
def test_amnezia_profile_is_scoped_to_selinux_centos(monkeypatch, enabled, platform, expected):
    monkeypatch.setattr(host,'selinux_enabled',lambda: enabled)
    monkeypatch.setattr(host,'platform_id',lambda: platform)
    assert host.amnezia_security_options() == (['--security-opt','label=type:vpn_amnezia_t'] if expected else [])
