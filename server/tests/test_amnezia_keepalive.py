"""Client keepalive holds a CGNAT UDP mapping; server peers have no Endpoint to ping."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'server/console'))
import amnezia


def _peer():
    return {'address': '10.8.1.2', 'private_key': 'c' * 43 + '=', 'psk': 'd' * 43 + '=',
            'public_key': 'e' * 43 + '=', 'enabled': True}


def _state():
    return {'port': 47443, 'private_key': 'a' * 43 + '=', 'public_key': 'b' * 43 + '=',
            'dns': ['1.1.1.1'], 'params': {key: 1 for key in amnezia.SHARED}, 'peers': [_peer()]}


def test_render_client_keepalive_fits_cgnat_window():
    assert amnezia.KEEPALIVE == 15
    conf = amnezia.render_client(_state(), _peer(), 'vpn.example.invalid')
    assert 'PersistentKeepalive = 15' in conf
    assert 'PersistentKeepalive = 25' not in conf


def test_server_peers_do_not_send_keepalive():
    rendered = amnezia.render_server(_state())
    assert '[Peer]' in rendered
    assert 'PersistentKeepalive' not in rendered
