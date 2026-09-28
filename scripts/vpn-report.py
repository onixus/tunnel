#!/usr/bin/python3
"""VPN health and email reports. Secrets are read only from root-owned JSON."""
import datetime,email.utils,fcntl,json,os,re,shutil,smtplib,socket,ssl,subprocess,sys,time
from pathlib import Path
BASE=Path('/var/lib/vpn-report'); BASE.mkdir(mode=0o700,exist_ok=True)
lock=open(BASE/'lock','w'); fcntl.flock(lock,fcntl.LOCK_EX)
CFG=json.load(open('/etc/vpn-report/smtp.json'))
ROLE=CFG.get('role','vpn'); NOW=time.time()
def cmd(args):
 try:
  r=subprocess.run(args,capture_output=True,text=True,timeout=12)
  return r.returncode,(r.stdout+r.stderr).strip()
 except Exception as e:return 1,type(e).__name__
def send(subject,body):
 from email.message import EmailMessage
 m=EmailMessage();m['From']=CFG['from'];m['To']=CFG['to'];m['Subject']=subject
 m['Date']=email.utils.formatdate(localtime=False);m['Message-ID']=email.utils.make_msgid(domain='onixus.ru');m.set_content(body)
 with smtplib.SMTP_SSL(CFG['host'],CFG['port'],timeout=20,context=ssl.create_default_context()) as s:
  s.login(CFG['user'],CFG['password']);s.send_message(m)
 print('SMTP accepted',m['Message-ID'])
def save(p,d):
 tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(d));os.chmod(tmp,0o600);tmp.replace(p)
def collect():
 issues=[];lines=[f'Узел: {socket.gethostname()} ({ROLE})',f'UTC: {datetime.datetime.now(datetime.timezone.utc).isoformat()}']
 mem={k:int(v.split()[0]) for k,v in (l.split(':',1) for l in Path('/proc/meminfo').read_text().splitlines())}
 used=100*(1-mem['MemAvailable']/mem['MemTotal']);disk=shutil.disk_usage('/');dp=100*disk.used/disk.total;load=os.getloadavg()
 lines += [f'RAM: {used:.1f}% занято; доступно {mem["MemAvailable"]//1024} MiB',f'Диск /: {dp:.1f}% занято; свободно {disk.free//2**30} GiB',f'Load average (1/5/15 min): {load}; CPU: {os.cpu_count()}']
 if used>=95:issues.append('RAM >=95%')
 if dp>=90:issues.append('Disk >=90%')
 if load[1]>2*(os.cpu_count() or 1):issues.append('5-minute load > 2 x CPU')
 services=['h-ui','fail2ban','wg-quick@wg-private','wg-quick@wg-reserve'] if ROLE=='vpn' else ['maddy','hysteria-exit','wg-quick@wg-private']
 for service in services:
  rc,out=cmd(['systemctl','is-active',service]);lines.append(f'{service}: {out}')
  if rc:issues.append(service+' inactive')
 if ROLE=='vpn':
  rc,out=cmd(['docker','inspect','trusttunnel-web','--format','{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}'])
  lines.append('TrustTunnel: '+out)
  if rc or out!='running healthy':issues.append('TrustTunnel unhealthy')
  # Kernel stats endpoint confirms that Hysteria itself, not just H UI, is alive.
  try:
   import sqlite3,yaml,urllib.request
   con=sqlite3.connect('file:/var/lib/h-ui/data/h_ui.db?mode=ro',uri=True)
   h=yaml.safe_load(con.execute('select value from config where key=?',('HYSTERIA2_CONFIG',)).fetchone()[0]);con.close()
   req=urllib.request.Request('http://127.0.0.1:9999/online',headers={'Authorization':h['trafficStats']['secret']})
   online=json.load(urllib.request.urlopen(req,timeout=5));lines.append('Hysteria online sessions: '+str(sum(online.values())))
  except Exception as e:issues.append('Hysteria stats unavailable');lines.append('Hysteria check: '+type(e).__name__)
 else:
  try:
   with socket.create_connection(('139.100.233.173',22),timeout=5) as s:
    if not s.recv(100).startswith(b'SSH-'):raise RuntimeError('SSH banner absent')
   lines.append('External check of VPN server: SSH reachable')
  except Exception:issues.append('VPN server unreachable from onixus.ru')
 rc,out=cmd(['wg','show','all','latest-handshakes'])
 if not rc:
  for line in out.splitlines():
   interface,key,stamp=line.split();age=int(NOW)-int(stamp);lines.append(f'{interface} handshake age: {age}s')
   if age>180:issues.append(interface+' handshake stale')
 if ROLE=='vpn':
  rc,out=cmd(['fail2ban-client','status','sshd']);lines += ['\nFail2ban sshd:',out]
 return sorted(issues),lines

def logs():
 # Only operational events; omit raw request URLs, authentication tokens and visited domains.
 out=['\nСобытия за последние 24 часа (UTC; без URL и секретов):']
 if ROLE=='vpn':
  cutoff=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=1);events=[];counts={}
  p=Path('/var/lib/h-ui/logs/hysteria2.log')
  if p.exists():
   for raw in p.open(errors='replace'):
    try:
     row=json.loads(raw);date=datetime.datetime.fromisoformat(row['time']).replace(tzinfo=datetime.timezone.utc)
     if date<cutoff:continue
     msg=row.get('msg',''); kind=next((x for x in ['client disconnected','client connected','TCP error','UDP error'] if x in msg),None)
     if not kind:continue
     counts[kind]=counts.get(kind,0)+1
     if kind in ('client disconnected','client connected'):
      reason=' timeout' if 'timeout' in msg else ''
      events.append(date.isoformat()+' '+kind+reason)
    except (ValueError,KeyError):continue
  out += ['Hysteria counts: '+json.dumps(counts),*events[-30:]]
  rc,text=cmd(['journalctl','-u','fail2ban','--since','24 hours ago','--no-pager','-o','short-iso'])
  out += ['Fail2ban Ban/Unban (last 30):']+[x for x in text.splitlines() if re.search(r'\b(?:Ban|Unban)\b',x)][-30:]
  p=Path('/var/log/fail2ban.log')
  if p.exists():
   with p.open(errors='replace') as f:
    out += [x.strip() for x in f if re.search(r'\b(?:Ban|Unban)\b',x) and x[:19]>=cutoff.strftime('%Y-%m-%d %H:%M:%S')][-30:]
 return out

def main():
 mode=sys.argv[1] if len(sys.argv)>1 else 'check';statepath=BASE/'state.json'
 state=json.loads(statepath.read_text()) if statepath.exists() else {}
 issues,lines=collect();prefix=f'[VPN {socket.gethostname()}] '
 if mode in ('daily','test'):
  send(prefix+('Ежедневная сводка' if mode=='daily' else 'Проверка уведомлений'),'\n'.join(lines+['\nПроблемы: '+(', '.join(issues) or 'нет')]+logs()));return
 old=state.get('issues',[]);alerted=state.get('alerted',[])
 # Service failures are immediate (timer resolution 1min). Resource/handshake warnings must persist twice.
 immediate=[i for i in issues if 'inactive' in i or 'unavailable' in i or 'unhealthy' in i or 'unreachable' in i]
 confirmed=sorted(set(immediate+[i for i in issues if i in old]))
 if confirmed and (confirmed!=alerted or NOW-state.get('sent',0)>=1800):
  send(prefix+'Сбой', '\n'.join(['Проблемы: '+', '.join(confirmed)]+lines+logs()));state['sent']=NOW;state['alerted']=confirmed
 elif not issues and alerted:
  send(prefix+'Работа восстановлена','\n'.join(lines));state['alerted']=[];state['sent']=NOW
 state['issues']=issues;save(statepath,state)
if __name__=='__main__':main()
