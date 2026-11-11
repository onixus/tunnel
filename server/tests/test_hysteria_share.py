"""Hysteria export must be importable by R-TrustTunnel, including port hopping."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'console'))
import agent


def test_hysteria_share_puts_port_set_in_the_address(monkeypatch):
    monkeypatch.setattr(agent, 'ORIGIN', 'https://vpn.example.invalid')
    monkeypatch.setattr(agent, 'hui_config', lambda: {
        'obfs': {'type': 'salamander', 'salamander': {'password': 'A+b&c'}},
    })
    monkeypatch.setattr(agent, 'read_db', lambda *args: [{'value': '20000-40000'}])
    shared = agent.hysteria_share({'con_pass': 'fixture-secret', 'username': 'Тест'})
    assert shared['content'].startswith(
        'hysteria2://fixture-secret@vpn.example.invalid:443,20000-40000/?')
    assert 'mport' not in shared['content']
    assert 'obfs-password=A%2Bb%26c' in shared['content']
    assert shared['yaml'].startswith('server: vpn.example.invalid:443,20000-40000\n')
    assert 'hopInterval: 15s' in shared['yaml']


def test_hysteria_share_without_hopping_stays_on_one_port(monkeypatch):
    monkeypatch.setattr(agent, 'ORIGIN', 'https://vpn.example.invalid')
    monkeypatch.setattr(agent, 'hui_config', lambda: {})
    monkeypatch.setattr(agent, 'read_db', lambda *args: [{'value': ''}])
    shared = agent.hysteria_share({'con_pass': 'fixture-secret', 'username': 'user'})
    assert '@vpn.example.invalid:443/?' in shared['content']
    assert 'hopInterval' not in shared['yaml']
