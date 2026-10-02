"""Routing contracts and recovery. No real VPN, Docker or systemd calls."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server/console'))
from routing_policy import PolicyError, initial_policy, make_plan, validate_request
import service_routes as sr
import trusttunnel_routing as tt

REV = 'a' * 64


def state(h='primary', t='direct'):
    return {'revision': REV, 'saved': initial_policy({'hysteria': h, 'trusttunnel': t}),
            'raw_policy': None,
            'services': {name: {'actual_exit': value, 'configurable': True, 'reason': '',
                               'available_exits': ['primary', 'reserve', 'direct']}
                         for name, value in [('hysteria', h), ('trusttunnel', t)]}}


def request(group='reserve', **services):
    return {'revision': REV, 'group_exit': group, 'services': services}


def test_initial_policy_does_not_enroll_trusttunnel():
    assert state()['saved']['services'] == {'hysteria': {'mode': 'follow'}, 'trusttunnel': {'mode': 'direct'}}


def test_shared_switch_leaves_direct_service_untouched():
    plan = make_plan(request(), state())
    assert [c['id'] for c in plan['changes']] == ['hysteria']
    assert plan['untouched'][0]['id'] == 'trusttunnel'
    assert plan['control_plane'] == 'direct'


def test_each_service_uses_its_own_route():
    plan = make_plan(request(hysteria={'mode': 'pinned', 'exit': 'primary'}, trusttunnel={'mode': 'pinned', 'exit': 'reserve'}), state())
    assert [(c['after'], c['restart']) for c in plan['changes']] == [('primary', False), ('reserve', True)]


def test_unchecked_follower_freezes_without_restart():
    s = state(t='primary')
    s['saved']['services']['trusttunnel'] = {'mode': 'follow'}
    plan = make_plan(request(trusttunnel={'mode': 'pinned', 'exit': 'primary'}), s)
    assert plan['changes'][1]['restart'] is False
    assert plan['policy']['services']['trusttunnel']['mode'] == 'pinned'


def test_direct_can_be_selected_independently():
    plan = make_plan(request('primary', hysteria={'mode': 'direct'}), state())
    assert plan['changes'][0]['after'] == 'direct'
    assert plan['policy']['group_exit'] == 'primary'


def test_excluded_drift_is_not_reconciled():
    s = state(t='reserve')
    s['services']['trusttunnel']['actual_exit'] = 'primary'
    plan = make_plan(request(), s)
    assert plan['untouched'] == [{'id': 'trusttunnel', 'title': 'TrustTunnel / R-TrustTunnel', 'exit': 'primary'}]


def test_explicit_same_mode_can_reconcile_drift():
    s = state()
    s['services']['hysteria']['actual_exit'] = 'reserve'
    plan = make_plan(request('primary', hysteria={'mode': 'follow'}), s)
    assert plan['changes'][0]['after'] == 'primary'


def test_plan_does_not_mutate_inputs():
    s = state()
    old = deepcopy(s)
    plan = make_plan(request(), s)
    plan['policy']['services']['hysteria']['mode'] = 'direct'
    assert s == old


@pytest.mark.parametrize('bad', [None, [], {}, {'revision': REV}, request(host={'mode': 'follow'}),
    request(hysteria={'mode': 'pinned', 'exit': '127.0.0.1'}), request(hysteria={'mode': 'unmanaged'}),
    request(hysteria={'mode': 'direct', 'command': 'bad'}), request(hysteria={'mode': []}),
    request(hysteria=None), {**request(), 'revision': True}, {**request(), 'revision': 'A' * 64},
    {**request(), 'group_exit': 'direct'}, {**request(), 'extra': True}])
def test_invalid_requests_fail_closed(bad):
    with pytest.raises(PolicyError):
        validate_request(bad)


def test_stale_revision_rejected():
    with pytest.raises(PolicyError, match='изменились'):
        make_plan({**request(), 'revision': 'b' * 64}, state())


def test_noop_rejected():
    with pytest.raises(PolicyError, match='Изменений нет'):
        make_plan(request('primary'), state())


def test_unprepared_driver_rejected():
    s = state()
    s['services']['trusttunnel'].update(configurable=False, reason='not installed')
    with pytest.raises(PolicyError, match='not installed'):
        make_plan(request(trusttunnel={'mode': 'follow'}), s)


class FakeRuntime:
    def __init__(self):
        self.s = state()
        self.values = {'hysteria': 'old-h', 'trusttunnel': 'old-t'}
        self.calls = []
        self.fail = None
        self.fail_rollback = False
        self.arm_failure = False
        self.observe_count = 0
        self.drift_during_preflight = False

    def observe(self):
        self.observe_count += 1
        result = deepcopy(self.s)
        if self.drift_during_preflight and self.observe_count > 1:
            result['revision'] = 'b' * 64
        return result

    def prepare(self, plan, s):
        return {c['id']: {'before': self.values[c['id']], 'after': 'new-' + c['id'],
                          'expected_ip': '203.0.113.2', 'before_ip': '203.0.113.1'}
                for c in plan['changes'] if c['restart']}

    def current(self, name):
        return self.values[name]

    def write(self, name, value, expected):
        assert self.values[name] == expected
        assert sr.PENDING.exists()
        self.calls.append(('write', name, value))
        self.values[name] = value

    def probe(self, name, expected):
        self.calls.append(('probe', name, expected))
        if name == self.fail and (expected == '203.0.113.2' or self.fail_rollback):
            raise RuntimeError('probe failure')

    def arm(self, name, path):
        self.calls.append(('arm', name, path))
        if self.arm_failure:
            raise RuntimeError('systemd unavailable')

    def disarm(self, name):
        self.calls.append(('disarm', name))


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, 'LOCK', str(tmp_path / 'route.lock'))
    monkeypatch.setattr(sr, 'POLICY', tmp_path / 'policy.json')
    monkeypatch.setattr(sr, 'PENDING', tmp_path / 'pending.json')
    monkeypatch.setattr(sr, 'BACKUPS', tmp_path / 'backups')
    return FakeRuntime()


def both():
    return request(trusttunnel={'mode': 'follow'})


def journal():
    return json.loads(next(sr.BACKUPS.glob('*.json')).read_text())


def test_two_service_commit(runtime):
    result = sr.apply(runtime, both())
    assert len(result['changes']) == 2
    assert runtime.values == {'hysteria': 'new-hysteria', 'trusttunnel': 'new-trusttunnel'}
    assert journal()['status'] == 'committed'
    assert not sr.PENDING.exists()
    assert sr.POLICY.stat().st_mode & 0o777 == 0o600
    assert next(sr.BACKUPS.glob('*.json')).stat().st_mode & 0o777 == 0o600
    assert runtime.calls[0][0] == 'arm'


def test_second_failure_rolls_back_both_in_reverse_order(runtime):
    runtime.fail = 'trusttunnel'
    with pytest.raises(PolicyError, match='восстановлены'):
        sr.apply(runtime, both())
    assert runtime.values == {'hysteria': 'old-h', 'trusttunnel': 'old-t'}
    assert [c[1] for c in runtime.calls if c[0] == 'write'] == ['hysteria', 'trusttunnel', 'trusttunnel', 'hysteria']
    assert journal()['status'] == 'rolled_back'
    assert not sr.PENDING.exists() and not sr.POLICY.exists()


def test_first_failure_does_not_restart_unattempted_service(runtime):
    runtime.fail = 'hysteria'
    with pytest.raises(PolicyError):
        sr.apply(runtime, both())
    assert all(c[1] != 'trusttunnel' for c in runtime.calls if c[0] in ('write', 'probe'))


def test_failed_rollback_blocks_further_changes(runtime):
    runtime.fail = 'trusttunnel'
    runtime.fail_rollback = True
    with pytest.raises(PolicyError, match='Откат не подтверждён'):
        sr.apply(runtime, both())
    assert sr.PENDING.exists()
    assert journal()['rollback_errors'] == ['trusttunnel']
    assert not any(c[0] == 'disarm' for c in runtime.calls)
    with pytest.raises(PolicyError, match='Предыдущее'):
        sr.apply(runtime, request())


def test_no_write_before_watchdog_armed(runtime):
    runtime.arm_failure = True
    with pytest.raises(RuntimeError):
        sr.apply(runtime, request())
    assert not sr.PENDING.exists()
    assert not any(c[0] == 'write' for c in runtime.calls)
    assert journal()['status'] == 'aborted'


def test_preflight_conflict_does_not_arm_or_write(runtime):
    runtime.drift_during_preflight = True
    with pytest.raises(PolicyError, match='во время проверки'):
        sr.apply(runtime, request())
    assert runtime.calls == []
    assert not sr.PENDING.exists()


def test_metadata_change_needs_no_restart(runtime):
    sr.apply(runtime, request('primary', hysteria={'mode': 'pinned', 'exit': 'primary'}))
    assert not any(c[0] in ('write', 'probe') for c in runtime.calls)


def test_excluded_service_is_never_written(runtime):
    sr.apply(runtime, request())
    assert all(c[1] == 'hysteria' for c in runtime.calls if c[0] in ('write', 'probe'))


def test_restore_does_not_clobber_operator_edit(runtime):
    sr.BACKUPS.mkdir()
    path = sr.BACKUPS / 'journal.json'
    j = {'prepared': {'hysteria': {'before': 'old-h', 'after': 'new-h', 'before_ip': '203.0.113.1'}},
         'attempted': ['hysteria'], 'status': 'pending', 'old_policy': None}
    sr.PENDING.write_text('{}')
    runtime.values['hysteria'] = 'operator-edit'
    with pytest.raises(PolicyError, match='Откат не подтверждён'):
        sr.restore(runtime, path, j)
    assert runtime.values['hysteria'] == 'operator-edit'


def test_committed_watchdog_is_noop_and_cleans_pending(runtime, monkeypatch):
    sr.apply(runtime, request())
    path = next(sr.BACKUPS.glob('*.json'))
    sr.PENDING.write_text(json.dumps({'journal': str(path)}))
    monkeypatch.setitem(sys.modules, 'agent', SimpleNamespace())
    monkeypatch.setattr(sr.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(sr, 'trusted', lambda p: True)
    monkeypatch.setattr(sr, 'Runtime', lambda a: runtime)
    before = list(runtime.calls)
    sr.watchdog_restore(path)
    assert runtime.calls == before
    assert not sr.PENDING.exists()


def test_shared_cli_lock(runtime):
    with sr.route_lock():
        with pytest.raises(PolicyError, match='Уже выполняется'):
            with sr.route_lock():
                pass


def profile(name='primary'):
    return {'expected_ip': '203.0.113.2', 'outbound': {'name': name, 'type': 'socks5',
            'socks5': {'addr': '10.254.77.2:1080', 'username': 'root-exit-user', 'password': 'not-a-live-secret'}}}


def test_prepare_preserves_every_acl_and_ignores_unused_exit(monkeypatch):
    rules = ['reject(geoip:private)', 'local(all, udp/53, 127.0.0.1)', 'custom(complex, tcp/9000)', 'primary(all)']
    config = {'acl': {'inline': rules}, 'outbounds': [{'name': 'local', 'type': 'direct'}]}
    switch = SimpleNamespace(check_exit=Mock())
    a = SimpleNamespace(module_switch=lambda: switch)
    r = sr.Runtime(a)
    r.expected_ip = Mock(return_value='203.0.113.2')
    p = {'changes': [{'id': 'hysteria', 'before': 'primary', 'after': 'reserve', 'restart': True}]}
    output = r.prepare(p, {'config': config, 'raw_h': yaml.safe_dump(config), 'profiles': {'primary': profile(), 'reserve': profile('reserve')}})
    new = yaml.safe_load(output['hysteria']['after'])
    assert new['acl']['inline'][:-1] == rules[:-1]
    assert new['acl']['inline'][-1] == 'reserve(all)'
    assert switch.check_exit.call_count == 1
    assert switch.check_exit.call_args.args[0]['outbound']['name'] == 'reserve'
    assert config['acl']['inline'] == rules


def test_relay_splits_ru_cis_direct_and_everything_else_to_egress():
    c = tt.relay_config(profile())
    assert c['inbounds'][0]['listen'] == '127.0.0.1'
    assert c['outbounds'][0]['password'] == 'not-a-live-secret'
    rules, route = c['route']['rules'], c['route']
    assert rules[0] == {'port': 53, 'action': 'route', 'outbound': 'dns-direct'}
    # Forced exception precedes the national-zone bypass.
    assert rules.index({'domain_suffix': ['hostkey.ru'], 'action': 'route', 'outbound': 'egress'}) < \
        rules.index({'domain_suffix': ['ru', 'su', 'xn--p1ai'], 'action': 'route', 'outbound': 'dns-direct'})
    assert {'ip_is_private': True, 'action': 'reject'} in rules
    assert rules[-1] == {'rule_set': ['cis'], 'action': 'route', 'outbound': 'dns-direct'}
    assert route['final'] == 'egress'


def test_relay_reaches_loopback_trusttunnel_socks_through_bridge_with_credentials():
    p = profile()
    p['outbound']['socks5']['addr'] = '127.0.0.1:10810'
    out = tt.relay_config(p)['outbounds'][0]
    assert (out['server'], out['server_port'], out['username']) == ('172.18.0.1', 10810, 'root-exit-user')
    p['outbound']['socks5']['password'] = ''
    with pytest.raises(ValueError):
        tt.relay_config(p)


@pytest.mark.parametrize('address', ['localhost:1080', '[::1]:1080', '10.254.77.2:0', '10.254.77.2:65536'])
def test_relay_rejects_unsupported_addresses(address):
    p = profile()
    p['outbound']['socks5']['addr'] = address
    with pytest.raises(ValueError):
        tt.relay_config(p)


def test_direct_template_does_not_start_proxy(tmp_path, monkeypatch):
    monkeypatch.setattr(tt, 'CONFIG', tmp_path / 'config.json')
    monkeypatch.setattr(tt, 'RUNTIME', tmp_path / 'runtime')
    launch = Mock(side_effect=AssertionError('Must not start a process'))
    monkeypatch.setattr(tt.subprocess, 'Popen', launch)
    text = 'allow_private_network_connections = false\n[forward_protocol]\n[forward_protocol.direct]\n'
    assert tt.forward_template(text) == text
    assert not launch.called


def test_status_redacts_secrets_and_detects_drift(tmp_path, monkeypatch):
    config = tmp_path / 'route.json'
    config.write_text(json.dumps({'schema': 1, 'exit': 'reserve', 'relay': tt.relay_config(profile())}))
    monkeypatch.setattr(tt, 'CONFIG', config)
    monkeypatch.setattr(tt, 'RUNTIME', tmp_path / 'runtime')
    (tmp_path / 'vpn.toml').write_text('[forward_protocol.socks5]\naddress="127.0.0.1:11080"\nextended_auth=false')
    result = tt.status(tmp_path)
    assert result['actual_exit'] == 'custom'
    assert 'not-a-live-secret' not in json.dumps(result)
    assert 'root-exit-user' not in json.dumps(result)


def load_probe():
    spec = importlib.util.spec_from_file_location('route_probe_under_test', ROOT / 'scripts/trusttunnel-route-probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('extra', ['[listener.tun]\n', '[endpoint]\nskip_verification=true\n', 'vpn_mode="selective"\n', 'exclusions=["api.ipify.org"]\n'])
def test_native_probe_rejects_bypass_and_tun(extra):
    with pytest.raises(ValueError):
        load_probe().endpoint_config(extra)


def test_native_probe_copies_only_endpoint():
    raw = 'vpn_mode="general"\n[endpoint]\nhostname="vpn.example"\naddresses=["203.0.113.1:8443"]\nusername="sample"\npassword="sample"\n[listener.socks]\naddress="127.0.0.1:1080"'
    result = load_probe().endpoint_config(raw)
    assert result['addresses'] == ['203.0.113.1:8443']
    assert 'listener' not in result



def test_service_entrypoint_recognizes_direct_without_changing_legacy_agent(tmp_path, monkeypatch):
    import agent
    profiles = tmp_path / 'exits.json'
    profiles.write_text(json.dumps({'primary': profile()}))
    config = {'acl': {'inline': ['local(all)']}, 'outbounds': [{'name': 'local', 'type': 'direct'}]}
    monkeypatch.setattr(agent, 'EXITS', profiles)
    monkeypatch.setattr(agent, 'hui_config', lambda: config)
    monkeypatch.setattr(agent, 'module_switch', lambda: SimpleNamespace(get_config=lambda: yaml.safe_dump(config)))
    monkeypatch.setattr(sr, 'POLICY', tmp_path / 'policy.json')
    monkeypatch.setattr(sr, 'TT_CONFIG', tmp_path / 'tt.json')
    monkeypatch.setattr(sr, 'tt_status', lambda a: {'version': 0, 'actual_exit': 'direct'})
    assert agent.route_snapshot()['selected'] == 'custom'
    assert sr.Runtime(agent).snapshot()['selected'] == 'direct'


def test_legacy_updates_cannot_remove_managed_routing(tmp_path, monkeypatch):
    import routing_agent
    policy = tmp_path / 'policy.json'
    policy.write_text('{}')
    monkeypatch.setattr(sr, 'POLICY', policy)
    with pytest.raises(PolicyError, match='оператором'):
        routing_agent.dispatch('updates.server', {'package': 'candidate'})


def test_pending_blocks_legacy_rule_edit(tmp_path, monkeypatch):
    import routing_agent
    pending = tmp_path / 'pending.json'
    pending.write_text('{}')
    monkeypatch.setattr(sr, 'PENDING', pending)
    with pytest.raises(PolicyError, match='восстановление'):
        routing_agent.dispatch('routes.apply', {})


def test_installer_patch_produces_importable_endpoint(tmp_path):
    spec = importlib.util.spec_from_file_location('installer', ROOT / 'deploy/install-trusttunnel-routing.py')
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    binary = tmp_path / 'binary'
    binary.write_bytes(b'fixture')
    installer.build_context(tmp_path, binary)
    endpoint = tmp_path / 'endpoint.py'
    endpoint.write_text('_VPN_TOML_TEMPLATE = "[forward_protocol.direct]"\nvalue = _VPN_TOML_TEMPLATE.format(port=port)\n')
    patch = (tmp_path / 'patch.py').read_text().replace('/app/app/endpoint.py', str(endpoint))
    exec(compile(patch, 'patch.py', 'exec'), {})
    compile(endpoint.read_text(), str(endpoint), 'exec')
    assert 'trusttunnel_routing.forward_template' in endpoint.read_text()


@pytest.mark.parametrize('success', [True, False])
@pytest.mark.parametrize('early_exit', [True, False])
def test_native_probe_uses_bridge_and_cleans_container(monkeypatch, tmp_path, success, early_exit):
    import tomllib
    probe = load_probe()
    monkeypatch.setattr(probe, 'RUNTIME', tmp_path / 'runtime')
    process = Mock()
    process.poll.side_effect = ([1] if early_exit else []) + [None] * 40
    calls = []
    monkeypatch.setattr(probe.time, 'sleep', lambda _: None)
    ticks = iter(range(0, 1000, 2))
    monkeypatch.setattr(probe.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(probe.subprocess, 'check_output', lambda *a, **k: 'sha256:fixture\n')
    def launch(command, **kwargs):
        calls.append(command)
        mount = next(x for x in command if 'dst=/probe.toml' in x)
        path = mount.split('src=')[1].split(',')[0]
        assert Path(path).is_relative_to(probe.RUNTIME)
        settings = tomllib.loads(Path(path).read_text())
        assert settings['endpoint']['skip_verification'] is False
        assert settings['listener']['socks']['address'].startswith('0.0.0.0:')
        assert settings['listener']['socks']['password']
        return process
    monkeypatch.setattr(probe.subprocess, 'Popen', launch)
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0 if success else 97, stdout='203.0.113.10')
    monkeypatch.setattr(probe.subprocess, 'run', run)
    endpoint = {'hostname': 'vpn.example', 'addresses': ['203.0.113.1:8443'], 'username': 'user', 'password': 'secret'}
    if success:
        assert probe.probe(endpoint, 'http2') == '203.0.113.10'
    else:
        with pytest.raises(RuntimeError, match='egress'):
            probe.probe(endpoint, 'http2')
    assert sum(c[:2] == ['docker', 'run'] for c in calls) == (2 if early_exit else 1)
    command = calls[0]
    assert command[command.index('--network')+1] == 'bridge'
    assert command[command.index('-p')+1].startswith('127.0.0.1:')
    assert '--read-only' in command and '--cap-drop' in command
    assert 'secret' not in str(command)
    name = command[command.index('--name')+1]
    assert ['docker', 'rm', '-f', name] in calls
    process.terminate.assert_called_once()
