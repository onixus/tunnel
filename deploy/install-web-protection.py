#!/usr/bin/env python3
"""Install ingress auth logging, Docker-aware fail2ban and console bot links as root."""
import datetime,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(*args):
    return subprocess.check_output(args,text=True).strip()
def main():
    if os.geteuid()!=0: raise SystemExit('Run as root on ingress')
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup=Path('/opt/vpn-console/backups')/('protection-'+stamp); backup.mkdir(mode=0o700)
    info=json.loads(run('docker','inspect','rtrust-portal-https'))[0]
    conf=Path(next(m['Source'] for m in info['Mounts'] if m['Destination']=='/etc/nginx/conf.d/default.conf'))
    destinations=['/etc/fail2ban/filter.d/vpn-web.conf','/etc/fail2ban/jail.d/vpn-web.local','/etc/logrotate.d/vpn-portal']
    for dst in destinations:
        if Path(dst).exists():shutil.copy2(dst,backup/Path(dst).name)
    old=conf.read_text(); shutil.copy2(conf,backup/'nginx.conf')
    bot=Path('/usr/local/sbin/vpn-telegram'); shutil.copy2(bot,backup/'vpn-telegram')
    logs=Path('/var/log/vpn-portal');logs.mkdir(mode=0o750,exist_ok=True)
    log=logs/'auth.log';log.touch(exist_ok=True);log.chmod(0o640)
    new=old
    if '# BEGIN VPN AUTH PROTECTION' not in old:
        new=(ROOT/'deploy/protection/nginx-auth.conf').read_text()+old.replace('server {','server {\n    access_log /var/log/vpn-auth/auth.log vpn_auth if=$vpn_auth_failed;',1)
    candidate=backup/'candidate.conf';candidate.write_text(new)
    mounts=[]
    for m in info['Mounts']:
        if m['Destination']=='/var/log/vpn-auth':continue
        source=str(candidate) if m['Destination']=='/etc/nginx/conf.d/default.conf' else m['Source']
        mounts+=['-v',source+':'+m['Destination']+('' if m['RW'] else ':ro')]
    mounts+=['-v',str(logs)+':/var/log/vpn-auth']
    run('docker','run','--rm','--network','trusttunnel-web_default',*mounts,info['Image'],'nginx','-t')
    conf.write_text(new) # Keep inode of existing bind mount.
    name='rtrust-portal-before-protection-'+stamp
    try:
        run('docker','stop','rtrust-portal-https');run('docker','rename','rtrust-portal-https',name)
        active_mounts=[str(conf)+x[len(str(candidate)):] if x.startswith(str(candidate)+':') else x for x in mounts]
        run('docker','run','-d','--name','rtrust-portal-https','--network','trusttunnel-web_default','--restart','unless-stopped',
            '--read-only','--tmpfs','/tmp','--tmpfs','/var/cache/nginx','--tmpfs','/var/run','-p','443:443',*active_mounts,info['Image'])
        run('docker','exec','rtrust-portal-https','nginx','-t')
        for src,dst in [('vpn-web.conf','/etc/fail2ban/filter.d/vpn-web.conf'),('vpn-web.local','/etc/fail2ban/jail.d/vpn-web.local'),('logrotate','/etc/logrotate.d/vpn-portal')]:
            p=Path(dst)
            if p.exists():shutil.copy2(p,backup/p.name)
            shutil.copy2(ROOT/'deploy/protection'/src,p)
        run('fail2ban-client','-t');run('fail2ban-client','reload')
        shutil.copy2(ROOT/'scripts/vpn-telegram.py',bot);bot.chmod(0o700)
        run('systemctl','restart','vpn-telegram')
    except BaseException:
        conf.write_text(old)
        if run('docker','ps','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'):
            subprocess.run(['docker','rm','-f','rtrust-portal-https'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            run('docker','rename',name,'rtrust-portal-https');run('docker','start','rtrust-portal-https')
        for dst in destinations:
            p=Path(dst); saved=backup/p.name
            if saved.exists():shutil.copy2(saved,p)
            else:p.unlink(missing_ok=True)
        subprocess.run(['fail2ban-client','reload','--restart','vpn-web'],capture_output=True)
        shutil.copy2(backup/'vpn-telegram',bot)
        run('systemctl','restart','vpn-telegram')
        raise
    print('Backup:',backup,'; previous proxy:',name)
    print(run('fail2ban-client','status','vpn-web'))
if __name__=='__main__':main()
