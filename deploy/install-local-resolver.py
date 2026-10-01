#!/usr/bin/env python3
"""Install private local filtering resolver; no change to VPN profiles or VPN services."""
import crypt,json,os,secrets,shutil,subprocess,time,sys
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
HOME=Path('/opt/vpn-adblock')
IMAGE='vpn-adblock:0.107.79-nonroot'
def run(*args):return subprocess.check_output(args,text=True).strip()
def main():
    if os.geteuid()!=0:raise SystemExit('Run as root')
    os.umask(0o077);HOME.mkdir(mode=0o700,exist_ok=True)
    if (HOME/'conf/AdGuardHome.yaml').exists():raise SystemExit('Already installed: use updater; do not overwrite credentials')
    network=json.loads(run('docker','network','inspect','trusttunnel-web_default'))[0]
    assert network['IPAM']['Config'][0]['Subnet']=='172.18.0.0/16'
    assert all(not c['IPv4Address'].startswith('172.18.0.53/') for c in network['Containers'].values())
    shutil.copy2(ROOT/'deploy/adblock/policy.json',HOME/'policy.json')
    shutil.copy2(ROOT/'scripts/vpn-adblock-update.py',HOME/'update.py')
    run('python3',str(HOME/'update.py'),'--bootstrap')
    password=secrets.token_urlsafe(40)
    (HOME/'api.json').write_text(json.dumps({'username':'console','password':password}))
    for name in ('conf','work'):
        (HOME/name).mkdir();os.chown(HOME/name,10001,10001)
    upstreams=[l.split()[1] for l in Path('/run/systemd/resolve/resolv.conf').read_text().splitlines() if l.startswith('nameserver ')]
    assert upstreams and not any(x.startswith('127.') for x in upstreams)
    cfg={'schema_version':34,'http':{'address':'0.0.0.0:3000','doh':{'insecure_enabled':True}},
        'users':[{'name':'console','password':crypt.crypt(password,crypt.mksalt(crypt.METHOD_BLOWFISH))}],
        'dns':{'bind_hosts':['0.0.0.0'],'port':53,'upstream_dns':upstreams,'bootstrap_dns':upstreams,'fallback_dns':[],
               'ratelimit':0,'cache_size':4194304,'use_private_ptr_resolvers':False,'anonymize_client_ip':True},
        'tls':{'enabled':False},'querylog':{'enabled':False,'file_enabled':False},'statistics':{'enabled':False},
        'filtering':{'safe_fs_patterns':['/filters/current/rules.txt'],'protection_enabled':True,'filtering_enabled':True,'blocking_mode':'null_ip','filters_update_interval':0,
                     'safebrowsing_enabled':False,'parental_enabled':False,'safe_search':{'enabled':False}},
        'filters':[{'enabled':True,'url':'/filters/current/rules.txt','name':'Local multi-source + strict RU/SU','id':100}],
        'whitelist_filters':[]}
    conf=HOME/'conf/AdGuardHome.yaml';conf.write_text(yaml.safe_dump(cfg,sort_keys=False));os.chown(conf,10001,10001)
    run('docker','build','-f',str(ROOT/'deploy/adblock/resolver.Dockerfile'),'-t',IMAGE,str(ROOT))
    run('docker','run','-d','--name','vpn-adblock','--network','trusttunnel-web_default','--ip','172.18.0.53',
        '--restart','unless-stopped','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--sysctl','net.ipv4.ip_unprivileged_port_start=0','--read-only','--tmpfs','/tmp:size=32m',
        '-p','127.0.0.1:53:53/udp','-p','127.0.0.1:53:53/tcp','-p','127.0.0.1:3001:3000',
        '-v',str(HOME/'conf')+':/opt/adguardhome/conf','-v',str(HOME/'work')+':/opt/adguardhome/work',
        '-v',str(HOME/'filters')+':/filters:ro',IMAGE)
    sys.path.insert(0,str(HOME));import update
    for _ in range(30):
        try:update.refresh();break
        except Exception:time.sleep(1)
    else:raise RuntimeError('Initial filter loading failed')
    for _ in range(30):
        p=subprocess.run(['dig','@127.0.0.1','ads.example.invalid','+short','+time=1','+tries=1'],capture_output=True,text=True)
        if p.returncode==0 and p.stdout.strip()=='0.0.0.0':break
        time.sleep(1)
    else:raise RuntimeError('Local resolver failed; VPN paths remain unchanged')
    for name in ['vpn-adblock-update.service','vpn-adblock-update.timer']:shutil.copy2(ROOT/'deploy/adblock'/name,Path('/etc/systemd/system')/name)
    run('systemctl','daemon-reload');run('systemctl','enable','--now','vpn-adblock-update.timer')
    print('Private local filtering resolver ready; upstreams preserved:',upstreams)
if __name__=='__main__':main()
