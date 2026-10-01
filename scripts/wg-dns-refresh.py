#!/usr/bin/python3
"""Refresh a single authenticated WireGuard peer and its source-IP firewall rule."""
import ipaddress,json,os,re,socket,subprocess
from pathlib import Path

def run(*args):return subprocess.check_output(args,text=True).strip()
def resolve(host):
 ips=sorted({x[4][0] for x in socket.getaddrinfo(host,None,socket.AF_INET,socket.SOCK_DGRAM)})
 if len(ips)!=1 or not ipaddress.ip_address(ips[0]).is_global:
  raise RuntimeError('Expected one public IPv4 address; retaining previous state')
 return ips[0]
def refresh(cfg):
 ip=resolve(cfg['hostname']);interface=cfg['interface'];port=int(cfg['port'])
 peers=run('wg','show',interface,'peers').splitlines()
 if len(peers)!=1:raise RuntimeError('Expected exactly one configured WireGuard peer')
 peer=peers[0]
 old=cfg['initial_ip'];state=Path('/var/lib/wg-dns-refresh/'+interface+'.json')
 if state.exists():old=json.loads(state.read_text())['ip']
 if ip!=old:
  if cfg['firewall']=='firewalld':
   def rule(addr):return f'rule family="ipv4" source address="{addr}" port port="{port}" protocol="udp" accept'
   for options in [[],['--permanent']]:
    run('firewall-cmd',*options,'--zone=public','--add-rich-rule='+rule(ip))
   for options in [[],['--permanent']]:
    run('firewall-cmd',*options,'--zone=public','--remove-rich-rule='+rule(old))
  elif cfg['firewall']=='ufw':
   run('ufw','allow','in','on','eth0','from',ip,'to','any','port',str(port),'proto','udp')
   run('ufw','--force','delete','allow','in','on','eth0','from',old,'to','any','port',str(port),'proto','udp')
  elif cfg['firewall']=='nft':
   rules=json.loads(run('nft','-j','list','chain','inet','fw','input'))['nftables']
   matches=[x['rule'] for x in rules if x.get('rule',{}).get('comment')=='Hysteria private WireGuard']
   if len(matches)!=1:raise RuntimeError('Ambiguous nft WireGuard rule')
   run('nft','replace','rule','inet','fw','input','handle',str(matches[0]['handle']),'ip','saddr',ip,'udp','dport',str(port),'accept','comment','"Hysteria private WireGuard"')
   rows=[x for x in run('iptables','-S','INPUT').splitlines() if x.startswith('-A ')]
   indexes=[i+1 for i,x in enumerate(rows) if '--comment wg-private' in x and '--dport '+str(port) in x]
   if len(indexes)!=1:raise RuntimeError('Ambiguous iptables WireGuard rule')
   run('iptables','-R','INPUT',str(indexes[0]),'!','-s',ip,'-p','udp','--dport',str(port),'-m','comment','--comment','wg-private','-j','DROP')
   p=Path('/etc/nftables.conf');text=p.read_text();text=re.sub(r'ip saddr [0-9.]+ udp dport '+str(port)+r' accept comment "Hysteria private WireGuard"',f'ip saddr {ip} udp dport {port} accept comment "Hysteria private WireGuard"',text);p.write_text(text)
   p=Path('/etc/wireguard')/(interface+'.conf');p.write_text(p.read_text().replace('! -s '+old,'! -s '+ip))
  else:raise RuntimeError('Unsupported firewall backend')
 # Always reapply desired endpoint, preserving the existing peer public key and AllowedIPs.
 run('wg','set',interface,'peer',peer,'endpoint',f'{ip}:{port}')
 state.parent.mkdir(mode=0o700,exist_ok=True);tmp=state.with_suffix('.tmp');tmp.write_text(json.dumps({'ip':ip}));os.chmod(tmp,0o600);tmp.replace(state)
 print(f'{interface}: {cfg["hostname"]} -> {ip}:{port}')
if __name__=='__main__':
 cfg=json.load(open('/etc/wg-dns-refresh.json'))
 for item in cfg if isinstance(cfg,list) else [cfg]:refresh(item)
