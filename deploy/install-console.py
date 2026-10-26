#!/usr/bin/env python3
"""Run from the uploaded repository subset as root. Additive sidecar + local agent."""
import json
import argparse
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import urllib.request
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server/console'))
import host_platform

os.umask(0o077)
ROOT=Path(__file__).resolve().parents[1]
DEST=Path('/opt/vpn-console')
STAMP=time.strftime('%Y%m%d-%H%M%S')
BACK=DEST/'backups'/STAMP
NGINX=Path('/opt/rtrust-releases/20260930-portal/portal-nginx.conf')
IMAGE='vpn-console:'+STAMP
AGENT_FILES=('agent.py','routing_agent.py','routing_policy.py','service_routes.py','trusttunnel_routing.py','amnezia.py','cdn.py','protocols.py','host_platform.py')
# Fixed, root-owned inputs for protocol installation from the console.
ASSETS={'amnezia/Dockerfile':'deploy/amnezia/Dockerfile','amnezia/entrypoint.sh':'deploy/amnezia/entrypoint.sh',
        'trusttunnel/Dockerfile':'deploy/trusttunnel/Dockerfile','xray/Dockerfile':'deploy/xray/Dockerfile','install-hysteria-host.py':'deploy/hysteria/install-host.py',
        'bootstrap-hui.py':'scripts/bootstrap-hui.py','h-ui.service':'examples/systemd/h-ui.service',
        'host_platform.py':'server/console/host_platform.py'}

def run(args):
    try:return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout
    except subprocess.CalledProcessError as exc:
        # Commands contain no credentials; keep build failures diagnosable.
        raise RuntimeError(exc.stderr[-8000:] or 'Command failed: '+args[0]) from exc

def main():
    global NGINX
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nginx', type=Path, default=NGINX)
    parser.add_argument('--origin', default='https://onixus-rf.duckdns.org')
    parser.add_argument('--local-health', action='store_true', help='HTTPS entry is loopback-only; verify locally')
    options=parser.parse_args()
    NGINX=options.nginx
    if os.geteuid()!=0:raise SystemExit('Run as root')
    BACK.mkdir(parents=True,mode=0o700)
    current=json.loads(run(['docker','inspect','trusttunnel-web']))[0]
    env=dict(v.split('=',1) for v in current['Config']['Env'])
    if not env.get('SECRET_KEY'):raise RuntimeError('Expected explicit portal SECRET_KEY; inspect before installing')
    agent_python=env.get('CONSOLE_AGENT_PYTHON','/usr/bin/python3')
    if agent_python not in ('/usr/bin/python3','/opt/vpn-console/venv/bin/python3'):
        raise RuntimeError('Unsupported root agent interpreter')
    selinux_type=env.get('CONSOLE_SELINUX_TYPE','')
    if selinux_type not in ('','vpn_console_t'):
        raise RuntimeError('Unsupported console SELinux process type')
    data=next(Path(m['Source']) for m in current['Mounts'] if m['Destination']=='/data')
    with sqlite3.connect(data/'trusttunnel-web.db') as source, sqlite3.connect(BACK/'portal.db') as dest:source.backup(dest)
    for name in ('.rtrust-profile-key','.secret_key'):
        if (data/name).is_file():shutil.copy2(data/name,BACK/name)
    shutil.copy2(NGINX,BACK/'nginx.conf')
    for p in AGENT_FILES+('root.pub','console.env'):
        if (DEST/p).exists():shutil.copy2(DEST/p,BACK/p)
    unit=Path('/etc/systemd/system/vpn-console-agent.service')
    if unit.exists():shutil.copy2(unit,BACK/'agent.service')
    previous=None
    p=subprocess.run(['docker','inspect','vpn-console'],capture_output=True,text=True)
    if p.returncode==0:previous=json.loads(p.stdout)[0];(BACK/'container.json').write_text(p.stdout)
    (BACK/'portal-container.json').write_text(json.dumps(current))
    pinned='vpn-console-base:'+current['Image'].removeprefix('sha256:')
    run(['docker','tag',current['Image'],pinned])
    run(['docker','build','--build-arg','BASE_IMAGE='+pinned,'-f',str(ROOT/'deploy/console.Dockerfile'),'-t',IMAGE,str(ROOT)])
    run(['docker','run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-e','DATA_DIR=/tmp/portal','-e','CONSOLE_DATA=/tmp/console',IMAGE,'python','-c','import routing_app, console_app; console_app.init(); print("Import and schema OK")'])
    state=DEST/'data';state.mkdir(mode=0o700,exist_ok=True);os.chown(state,10001,10001)
    if (state/'console.db').exists():
        with sqlite3.connect(state/'console.db') as source, sqlite3.connect(BACK/'console.db') as dest:source.backup(dest)
    (DEST/'packages').mkdir(mode=0o700,exist_ok=True)
    Path('/root/hysteria-route-backups').mkdir(mode=0o700,exist_ok=True)
    for name in AGENT_FILES:
        shutil.copy2(ROOT/'server/console'/name,DEST/name)
    for name,source in ASSETS.items():
        target=DEST/'assets'/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        shutil.copyfile(ROOT/source,target);target.chmod(0o755 if name.endswith('.sh') else 0o644)
    for path in (DEST/'build',DEST/'protocols',Path('/opt/amneziawg'),Path('/opt/xray-cdn')):path.mkdir(mode=0o700,exist_ok=True)
    # The agent's writable paths are fixed when it starts: a directory created later by a
    # protocol install from the console would stay read-only for the running agent.
    Path('/var/lib/h-ui').mkdir(mode=0o750,exist_ok=True)
    shutil.copy2(ROOT/'server/console/update-root.pub',DEST/'root.pub')
    shutil.copy2(ROOT/'deploy/vpn-console-agent.service',unit)
    unit.write_text(unit.read_text().replace('ExecStart=/usr/bin/python3 ', 'ExecStart='+agent_python+' '))
    # Persist only the inherited settings this service needs, never print their values.
    settings={k:env[k] for k in ('SECRET_KEY','SMTP_CONNECT_HOST','PUBLIC_ADDRESS','CLIENT_CA_FILE','CONSOLE_ORIGIN','CONSOLE_PUBLIC_ORIGIN','CONSOLE_USER_DOMAIN','CONSOLE_AGENT_PYTHON') if k in env}
    if any('\n' in v or '\r' in v for v in settings.values()):raise RuntimeError('Unsupported multiline environment')
    (DEST/'console.env').write_text(''.join(k+'='+v+'\n' for k,v in settings.items()))
    host_platform.restore_labels(data)
    host_platform.restore_labels(DEST)
    host_platform.restore_labels(unit)
    old_nginx=NGINX.read_text()
    try:
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','vpn-console-agent'])
        run(['systemctl','restart','vpn-console-agent'])
        for _ in range(20):
            if Path('/run/vpn-console/agent.sock').exists():break
            time.sleep(.2)
        if previous:
            run(['docker','stop','vpn-console']); run(['docker','rename','vpn-console','vpn-console-backup-'+STAMP])
        args=['docker','run','-d','--name','vpn-console','--network','trusttunnel-web_default','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--restart','unless-stopped','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--env-file',str(DEST/'console.env'),'-p','127.0.0.1:18090:8000','--mount',f'type=bind,src={data},dst=/data','--mount',f'type=bind,src={state},dst=/console-data','--mount','type=bind,src=/run/vpn-console,dst=/run/vpn-console,readonly']
        if selinux_type:args+=['--security-opt','label=type:'+selinux_type]
        cert=next(m['Source'] for m in current['Mounts'] if m['Destination']=='/certs')
        args+=['--mount',f'type=bind,src={cert},dst=/certs,readonly',IMAGE]
        run(args)
        # Cold imports on small VMs can exceed ten seconds. Wait for readiness,
        # and keep the failed candidate's startup log before rolling it back.
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            try:
                with urllib.request.urlopen('http://127.0.0.1:18090/console/healthz',timeout=2) as r:assert r.status==200
                break
            except Exception:time.sleep(1)
        else:raise RuntimeError('Console health failed')
        block='''    # BEGIN VPN CONSOLE
    location = /admin/dashboard { return 302 /console; }
    location = /console { return 302 /console/; }
    location ^~ /console/ {
        set $console http://vpn-console:8000;
        proxy_pass $console;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_cookie_flags ~ secure httponly samesite=strict;
        client_max_body_size 32k;
        proxy_read_timeout 35s;
    }
    # END VPN CONSOLE
'''
        import re
        clean=re.sub(r'    # BEGIN VPN CONSOLE\n.*?    # END VPN CONSOLE\n','',old_nginx,flags=re.S)
        if clean.count('    location / {')!=1:raise RuntimeError('Nginx anchor mismatch')
        NGINX.write_text(clean.replace('    location / {',block+'    location / {',1))
        run(['docker','exec','rtrust-portal-https','nginx','-t']);run(['docker','exec','rtrust-portal-https','nginx','-s','reload'])
        health='http://127.0.0.1:18090/console/healthz' if options.local_health else options.origin.rstrip('/')+'/console/healthz'
        with urllib.request.urlopen(health,timeout=10) as r:assert r.status==200
        print('Installed',IMAGE,'backup',BACK)
    except BaseException:
        logs=subprocess.run(['docker','logs','--tail','200','vpn-console'],capture_output=True,text=True)
        (BACK/'console-startup.log').write_text(logs.stdout+logs.stderr)
        NGINX.write_text(old_nginx)
        subprocess.run(['docker','exec','rtrust-portal-https','nginx','-t'],capture_output=True)
        subprocess.run(['docker','exec','rtrust-portal-https','nginx','-s','reload'],capture_output=True)
        subprocess.run(['docker','rm','-f','vpn-console'],capture_output=True)
        if previous:
            subprocess.run(['docker','rename','vpn-console-backup-'+STAMP,'vpn-console'],capture_output=True)
            subprocess.run(['docker','start','vpn-console'],capture_output=True)
        for name in AGENT_FILES+('root.pub','console.env'):
            if (BACK/name).exists():shutil.copy2(BACK/name,DEST/name)
            elif name in AGENT_FILES and name!='agent.py':(DEST/name).unlink(missing_ok=True)
        if (BACK/'agent.service').exists():
            shutil.copy2(BACK/'agent.service',unit)
            subprocess.run(['systemctl','daemon-reload'],capture_output=True)
            subprocess.run(['systemctl','restart','vpn-console-agent'],capture_output=True)
        else:
            # A first installation has no preceding agent to restore. Do not
            # leave its new unit restarting after its modules were rolled back.
            subprocess.run(['systemctl','disable','--now','vpn-console-agent'],capture_output=True)
            unit.unlink(missing_ok=True)
            subprocess.run(['systemctl','daemon-reload'],capture_output=True)
        # Existing VPN containers are never replaced by this installer.
        print('Installation failed; original nginx restored. Recovery files:',BACK)
        raise

if __name__=='__main__':main()
