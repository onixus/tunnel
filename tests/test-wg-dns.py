import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('refresh',str(Path(__file__).resolve().parents[1]/'scripts/wg-dns-refresh.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_backends(self):
  for backend in ['ufw','firewalld','nft']:
   with self.subTest(backend=backend),tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    def mapped(p):return root/str(p).lstrip('/')
    nft=mapped('/etc/nftables.conf');nft.parent.mkdir(parents=True);nft.write_text('ip saddr 139.100.233.173 udp dport 51830 accept comment "Hysteria private WireGuard"')
    wg=mapped('/etc/wireguard/wg-private.conf');wg.parent.mkdir();wg.write_text('PostUp = iptables ! -s 139.100.233.173')
    mapped('/var/lib').mkdir(parents=True)
    calls=[]
    def run(*a):
     calls.append(a)
     if a[:2]==('wg','show'):return 'existing-public-key'
     if a[0]=='nft' and a[1]=='-j':return json.dumps({'nftables':[{'rule':{'comment':'Hysteria private WireGuard','handle':42}}]})
     if a[:2]==('iptables','-S'):return '-A INPUT ! -s 139.100.233.173 --dport 51830 --comment wg-private -j DROP'
     return ''
    with patch.object(m,'Path',mapped),patch.object(m,'resolve',return_value='151.241.234.124'),patch.object(m,'run',side_effect=run):
     m.refresh(dict(hostname='node.duckdns.org',interface='wg-private',port=51830,firewall=backend,initial_ip='139.100.233.173'))
    self.assertEqual(calls[-1],('wg','set','wg-private','peer','existing-public-key','endpoint','151.241.234.124:51830'))
    self.assertEqual(json.loads(mapped('/var/lib/wg-dns-refresh/wg-private.json').read_text())['ip'],'151.241.234.124')
    if backend=='nft':self.assertNotIn('139.100.233.173',nft.read_text()+wg.read_text())
 def test_disabled_peer_changes_nothing(self):
  with patch.object(m,'resolve') as resolve,patch.object(m,'run') as run:
   m.refresh({'interface':'wg-private','enabled':False})
   resolve.assert_not_called();run.assert_not_called()
 def test_dns_failure_changes_nothing(self):
  with patch.object(m,'resolve',side_effect=OSError('DNS unavailable')),patch.object(m,'run') as run:
   with self.assertRaises(OSError):m.refresh({'hostname':'node.duckdns.org'})
   run.assert_not_called()
 def test_private_dns_rejected(self):
  with patch.object(m.socket,'getaddrinfo',return_value=[(None,None,None,None,('127.0.0.1',0))]):
   with self.assertRaises(RuntimeError):m.resolve('node.duckdns.org')
unittest.main()
