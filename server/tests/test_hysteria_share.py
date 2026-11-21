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
    assert ':443,20000-40000' in shared['content']
    assert 'mport' not in shared['content']
    assert 'obfs-password=A%2Bb%26c' in shared['content']
    assert 'maxIdleTimeout' not in shared['content']
    assert 'keepAlivePeriod' not in shared['content']
    assert shared['yaml'].startswith('server: vpn.example.invalid:443,20000-40000\n')
    assert 'hopInterval: 15s' in shared['yaml']
    assert 'maxIdleTimeout: 90s' in shared['yaml']
    assert 'keepAlivePeriod: 4s' in shared['yaml']
    assert 'udpIdleTimeout: 120s' in shared['yaml']


def test_hysteria_share_uses_the_configured_listen_port(monkeypatch):
    monkeypatch.setattr(agent, 'ORIGIN', 'https://vpn.example.invalid')
    monkeypatch.setattr(agent, 'hui_config', lambda: {'listen': '0.0.0.0:4443'})
    monkeypatch.setattr(agent, 'read_db', lambda *args: [{'value': '20000-40000'}])
    shared = agent.hysteria_share({'con_pass': 'fixture-secret', 'username': 'user'})
    assert '@vpn.example.invalid:4443,20000-40000/?' in shared['content']
    assert ':443' not in shared['content']


def test_hysteria_share_without_hopping_stays_on_one_port(monkeypatch):
    monkeypatch.setattr(agent, 'ORIGIN', 'https://vpn.example.invalid')
    monkeypatch.setattr(agent, 'hui_config', lambda: {})
    monkeypatch.setattr(agent, 'read_db', lambda *args: [{'value': ''}])
    shared = agent.hysteria_share({'con_pass': 'fixture-secret', 'username': 'user'})
    assert '@vpn.example.invalid:443/?' in shared['content']
    assert 'maxIdleTimeout' not in shared['content']
    assert 'keepAlivePeriod' not in shared['content']
    assert 'hopInterval' not in shared['yaml']
    assert 'maxIdleTimeout: 90s' in shared['yaml']
    assert 'keepAlivePeriod: 4s' in shared['yaml']
    assert 'udpIdleTimeout: 120s' in shared['yaml']


def test_hysteria_qr_encodes_the_port_set(monkeypatch):
    """QR is the export link; the port set must be in the bytes given to the renderer."""
    import types
    from config_qr import with_qr

    captured = []

    class FakeImage:
        def save(self, buffer):
            buffer.write(b'<svg xmlns="http://www.w3.org/2000/svg"/>')

    class FakeQR:
        def add_data(self, payload, optimize=0):
            captured.append(payload)
        def make(self, fit=True):
            return None
        def make_image(self, image_factory=None):
            return FakeImage()

    fake = types.ModuleType('qrcode')
    fake.QRCode = lambda **kwargs: FakeQR()
    fake.constants = types.SimpleNamespace(ERROR_CORRECT_M=0)
    fake.image = types.SimpleNamespace(svg=types.SimpleNamespace(SvgPathFillImage=object))
    monkeypatch.setitem(sys.modules, 'qrcode', fake)
    monkeypatch.setitem(sys.modules, 'qrcode.exceptions', types.SimpleNamespace(DataOverflowError=ValueError))
    monkeypatch.setitem(sys.modules, 'qrcode.image.svg', fake.image.svg)

    monkeypatch.setattr(agent, 'ORIGIN', 'https://vpn.example.invalid')
    monkeypatch.setattr(agent, 'hui_config', lambda: {})
    monkeypatch.setattr(agent, 'read_db', lambda *args: [{'value': '20000-40000'}])
    shared = agent.hysteria_share({'con_pass': 'fixture-secret', 'username': 'user'})
    rendered = with_qr(shared)
    assert rendered['qr_error'] is None
    assert captured == [shared['content'].encode()]
    assert b':443,20000-40000' in captured[0]


def test_hysteria_hold_needed_and_ensure_keep_neighbor_quic_keys():
    pinned = {
        'quic': {'maxIdleTimeout': '90s', 'disablePathMTUDiscovery': True},
        'udpIdleTimeout': '120s',
        'listen': ':443',
    }
    assert agent.hysteria_hold_needed(pinned) is False
    assert agent.hysteria_hold_needed({}) is True
    config = {'listen': ':443', 'quic': {'disablePathMTUDiscovery': True}}
    agent.ensure_hysteria_hold(config)
    assert config['quic']['disablePathMTUDiscovery'] is True
    assert config['quic']['maxIdleTimeout'] == '90s'
    assert config['udpIdleTimeout'] == '120s'
    assert config['listen'] == ':443'
    try:
        agent.ensure_hysteria_hold(None)
    except agent.Rejected:
        rejected = True
    else:
        rejected = False
    assert rejected
