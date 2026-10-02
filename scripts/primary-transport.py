#!/usr/bin/python3
import fcntl,json,subprocess,sys
from pathlib import Path
mode=sys.argv[1] if len(sys.argv)>1 else ''
if mode not in ('trusttunnel','wireguard'):raise SystemExit('Usage: primary-transport trusttunnel|wireguard')
lock=open('/run/primary-transport.lock','w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
def run(*a):subprocess.run(a,check=True,timeout=120)
def remote(action):run('ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','IdentitiesOnly=yes','-o','UserKnownHostsFile=/etc/hysteria/primary-control-known-hosts','-i','/root/.ssh/primary-wg-control','root@onixus.duckdns.org',action)
def dns_enabled(enabled):
 p=Path('/etc/wg-dns-refresh.json');c=json.loads(p.read_text())
 for i in c:
  if i['interface']=='wg-private':i['enabled']=enabled
 p.write_text(json.dumps(c));p.chmod(0o600)
def monitor(wg):
 p=Path('/etc/vpn-report/smtp.json');c=json.loads(p.read_text());c['services']=['h-ui','fail2ban','wg-quick@wg-reserve','tt-primary']+(['wg-quick@wg-private'] if wg else []);p.write_text(json.dumps(c));p.chmod(0o600)
profiles=Path('/etc/hysteria/exits.json');old=profiles.read_text();target=json.loads(Path('/etc/hysteria/primary-'+mode+'.json').read_text());c=json.loads(old)
try:
 if mode=='wireguard':
  remote('enable');dns_enabled(True);run('systemctl','enable','--now','wg-quick@wg-private');run('systemctl','start','wg-dns-refresh.service')
 else:run('systemctl','start','tt-primary')
 c['primary']=target;profiles.write_text(json.dumps(c));profiles.chmod(0o600)
 run('/usr/local/sbin/hysteria-exit-switch','primary')
 if mode=='trusttunnel':
  dns_enabled(False);run('systemctl','disable','--now','wg-quick@wg-private');remote('disable')
 monitor(mode=='wireguard')
 Path('/etc/hysteria/primary-transport').write_text(mode+'\n')
 print('Primary transport:',mode)
except BaseException:
 profiles.write_text(old)
 # Keep clients on the independently working reserve while the failure is inspected.
 subprocess.run(['/usr/local/sbin/hysteria-exit-switch','reserve'],timeout=120)
 raise
