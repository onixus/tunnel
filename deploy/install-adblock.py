#!/usr/bin/env python3
"""Connect existing VPNs to private local DNS lists; preserve profile defaults."""
import datetime,fcntl,importlib.machinery,importlib.util,json,os,shutil,socket,subprocess,time
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
RULES=['local(all, udp/53, 127.0.0.1)','local(all, tcp/53, 127.0.0.1)']
def run(*args):return subprocess.check_output(args,text=True).strip()
def main():
    if os.geteuid()!=0:raise SystemExit('Run as root on ingress')
    os.umask(0o077)
    assert run('dig','@127.0.0.1','ads.example.invalid','+short')=='0.0.0.0'
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup=Path('/opt/vpn-console/backups')/('adblock-'+stamp);backup.mkdir(mode=0o700)
    compose=Path('/opt/trusttunnel-web/compose.yaml');oldcompose=compose.read_text();(backup/'compose.yaml').write_text(oldcompose)
    loader=importlib.machinery.SourceFileLoader('switch','/usr/local/sbin/hysteria-exit-switch')
    spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m)
    nft=Path('/etc/vpn-adblock-dns.nft');oldnft=nft.read_text() if nft.exists() else None
    if oldnft:(backup/'dns.nft').write_text(oldnft)
    net=json.loads(run('docker','network','inspect','trusttunnel-web_default'))[0]
    assert net['IPAM']['Config'][0]['Subnet']=='172.18.0.0/16'
    assert any(v['Name']=='vpn-adblock' and v['IPv4Address']=='172.18.0.53/16' for v in net['Containers'].values())
    with open('/run/hysteria-exit-switch.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old=m.get_config();(backup/'hysteria.yaml').write_text(old)
        cfg=yaml.safe_load(old);rules=cfg['acl']['inline'];assert rules[2]=='reject(geoip:private)'
        cfg['acl']['inline']=rules[:3]+RULES+[r for r in rules[3:] if r not in RULES]
        cfg['resolver']={'type':'udp','udp':{'addr':'127.0.0.1:53','timeout':'5s'}}
        cfg['sniff']={'enable':True,'timeout':'2s','rewriteDomain':False,'tcpPorts':'80,443','udpPorts':'443'}
        profiles=json.loads(Path('/etc/hysteria/exits.json').read_text())
        active=next(p for p in profiles.values() if rules[-1]==p['outbound']['name']+'(all)')
        expected=socket.gethostbyname(active.get('expected_host',active.get('expected_ip')))
        unit='vpn-adblock-rollback-'+stamp
        run('systemd-run','--quiet','--unit='+unit,'--on-active=180s','/usr/local/sbin/hysteria-exit-switch','_restore',str(backup/'hysteria.yaml'))
        try:
            for src,dst in [('vpn-adblock-dns.nft',str(nft)),('vpn-adblock-dns.service','/etc/systemd/system/vpn-adblock-dns.service')]:shutil.copy2(ROOT/'deploy/adblock'/src,dst)
            run('nft','--check','-f',str(nft));run('systemctl','daemon-reload');run('systemctl','enable','--now','vpn-adblock-dns');run('systemctl','restart','vpn-adblock-dns')
            if cfg!=yaml.safe_load(old):
                run('systemctl','stop','h-ui');m.write_config(yaml.safe_dump(cfg,sort_keys=False));run('systemctl','start','h-ui')
            m.probe_hysteria(expected)
            c=yaml.safe_load(oldcompose);service=c['services']['trusttunnel-web']
            if service.get('dns')!=['172.18.0.53']:
                service['dns']=['172.18.0.53'];compose.write_text(yaml.safe_dump(c,sort_keys=False))
                run('docker','compose','-f',str(compose),'up','-d','trusttunnel-web')
            for _ in range(30):
                if run('docker','inspect','trusttunnel-web','--format','{{.State.Health.Status}}')=='healthy':break
                time.sleep(2)
            else:raise RuntimeError('Portal unhealthy')
            run('docker','exec','trusttunnel-web','python','-c',
                'import socket,struct; q=bytes.fromhex("12340100000100000000000003616473076578616d706c6507696e76616c69640000010001"); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(q,("192.0.2.53",53));r=s.recv(4096);assert r[-4:]==bytes(4)')
        except BaseException:
            m.restore(backup/'hysteria.yaml');compose.write_text(oldcompose)
            run('docker','compose','-f',str(compose),'up','-d','trusttunnel-web')
            if oldnft:nft.write_text(oldnft);run('systemctl','restart','vpn-adblock-dns')
            else:run('systemctl','disable','--now','vpn-adblock-dns')
            raise
        finally:run('systemctl','stop',unit+'.timer')
    print('Local filtering integrated; profile DNS defaults preserved; backup:',backup)
if __name__=='__main__':main()
