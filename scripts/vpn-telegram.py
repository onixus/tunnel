#!/usr/bin/python3
"""Private allowlisted VPN operations bot. No arbitrary shell execution."""
import datetime,json,os,secrets,sqlite3,subprocess,time,urllib.request,urllib.error
from pathlib import Path
CFG=Path('/etc/vpn-telegram/config.json')
STATE=Path('/var/lib/vpn-telegram/state.json')
PENDING={}
ID_REPLIES={}
PANEL_URL='https://onixus-rf.duckdns.org/console/'
def command(args,timeout=15):
 try:
  r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  return r.returncode,(r.stdout+r.stderr).strip()[:2500]
 except subprocess.TimeoutExpired:return 1,'Команда не завершилась вовремя.'
def api(method,data):
 req=urllib.request.Request('https://api.telegram.org/bot'+CONFIG['token']+'/'+method,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=40) as r:result=json.load(r)
 if not result.get('ok'):raise RuntimeError('Telegram API rejected request')
 return result.get('result')
def send(text,buttons=None):
 data={'chat_id':CONFIG['owner'],'text':text[:4000],'disable_web_page_preview':True}
 if buttons:data['reply_markup']={'inline_keyboard':buttons}
 return api('sendMessage',data)
def allowed(update):
 obj=update.get('message') or update.get('callback_query',{})
 chat=(obj.get('chat') or obj.get('message',{}).get('chat',{}))
 return obj.get('from',{}).get('id')==CONFIG['owner'] and chat.get('id')==CONFIG['owner'] and chat.get('type')=='private'
def status():
 lines=['VPN: '+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')]
 for name in ['h-ui','tt-primary','wg-quick@wg-private','wg-quick@wg-reserve','certbot.timer']:
  lines.append(name+': '+command(['systemctl','is-active',name])[1])
 lines.append('Console: '+command(['docker','inspect','vpn-console','--format','{{.State.Status}} / {{.State.Health.Status}}'])[1])
 lines.append('TrustTunnel: '+command(['docker','inspect','trusttunnel-web','--format','{{.State.Status}} / {{.State.Health.Status}}'])[1])
 lines.append(command(['uptime'])[1]);lines.append(command(['free','-m'])[1]);lines.append(command(['df','-h','/'])[1])
 lines.append(command(['/usr/local/sbin/hysteria-exit-switch','status'])[1])
 lines.append(command(['openssl','x509','-in','/etc/hysteria/server.crt','-noout','-enddate'])[1])
 return '\n'.join(lines)
ACTIONS={
 'route-primary':(['/usr/local/sbin/hysteria-exit-switch','primary'],'Переключить выход Hysteria на onixus.ru'),
 'route-reserve':(['/usr/local/sbin/hysteria-exit-switch','reserve'],'Переключить выход Hysteria на резервный узел'),
 'restart-hysteria':(['systemctl','restart','h-ui'],'Перезапустить Hysteria'),
 'restart-trusttunnel':(['docker','restart','trusttunnel-web'],'Перезапустить TrustTunnel'),
}
def confirm(action):
 if action not in ACTIONS:return
 nonce=secrets.token_hex(8);PENDING.clear();PENDING[nonce]=(action,time.time()+120)
 send(ACTIONS[action][1]+'? Клиенты могут кратко переподключиться. Подтверждение действует 2 минуты.',[[{'text':'Подтвердить','callback_data':'confirm:'+nonce},{'text':'Отмена','callback_data':'cancel'}]])
def tell_id(update):
 # Other users may only learn their own numeric ID, needed to receive configs from the console.
 msg=update.get('message') or {};chat=msg.get('chat',{});sender=msg.get('from',{}).get('id')
 text=(msg.get('text') or '').split();cmd=text[0].split('@')[0].lower() if text else ''
 if chat.get('type')!='private' or not isinstance(sender,int) or sender!=chat.get('id') or cmd not in ('/start','/id'):return
 if time.time()-msg.get('date',0)>180 or time.time()-ID_REPLIES.get(sender,0)<60:return
 if len(ID_REPLIES)>1000:ID_REPLIES.clear()
 ID_REPLIES[sender]=time.time()
 api('sendMessage',{'chat_id':sender,'text':f'Ваш Telegram ID: {sender}\nПередайте его администратору VPN, чтобы получать конфигурации в этот чат.'})
def handle(update):
 if not allowed(update):tell_id(update);return
 if 'callback_query' in update:
  cb=update['callback_query'];api('answerCallbackQuery',{'callback_query_id':cb['id']});data=cb.get('data','')
  if data=='cancel':PENDING.clear();send('Отменено.');return
  if data.startswith('select:'):confirm(data[7:]);return
  if data.startswith('confirm:'):
   pending=PENDING.pop(data[8:],None)
   if not pending or pending[1]<time.time():send('Подтверждение истекло или уже использовано.');return
   action=pending[0];send('Выполняю: '+ACTIONS[action][1])
   code,out=command(ACTIONS[action][0],timeout=150)
   send(('Выполнено. ' if code==0 else 'Ошибка. ')+out)
   return
  return
 text=update['message'].get('text','');parts=text.split();cmd=parts[0].split('@')[0].lower() if parts else ''
 # Ignore stale commands queued while bot was offline.
 if time.time()-update['message'].get('date',0)>180:return
 if cmd in ['/start','/help']:
  send('Управление VPN\n/status — службы, ресурсы, сертификат и маршрут\n/panel — единая панель управления\n/bans — блокировки SSH и веб-входа\n/route — выбор основного/резервного выхода Hysteria\n/restart — перезапуск VPN с подтверждением\nИзменения доступны только владельцу в личном чате.')
 elif cmd=='/status':send(status())
 elif cmd in ['/panel','/panels']:
  send('Единая VPN-панель: пользователи, ключи, обновления, рассылки и маршруты. Вход по учётной записи администратора TrustTunnel.',[[{'text':'Открыть панель','url':PANEL_URL}]])
 elif cmd=='/bans':
  send('\n\n'.join(command(['fail2ban-client','status',j])[1] for j in ['sshd','vpn-web']))
 elif cmd=='/route':send('Выход Hysteria. Исключения RU/РФ/СНГ сохраняются.',[[{'text':'Основной: onixus.ru','callback_data':'select:route-primary'},{'text':'Резервный','callback_data':'select:route-reserve'}]])
 elif cmd=='/restart':send('Выберите службу:',[[{'text':'Hysteria','callback_data':'select:restart-hysteria'},{'text':'TrustTunnel','callback_data':'select:restart-trusttunnel'}]])
def persist(offset):
 tmp=STATE.with_suffix('.tmp');tmp.write_text(json.dumps({'offset':offset}));os.chmod(tmp,0o600);tmp.replace(STATE)
def main():
 global CONFIG
 CONFIG=json.loads(CFG.read_text());assert isinstance(CONFIG['owner'],int) and CONFIG['owner']>0
 STATE.parent.mkdir(mode=0o700,exist_ok=True)
 me=api('getMe',{});print('Bot ready: '+me['username'],flush=True)
 api('setMyCommands',{'commands':[{'command':c,'description':d} for c,d in [('status','Статус VPN и ресурсы'),('panel','Единая VPN-панель'),('bans','Блокировки SSH и веб-входа'),('route','Переключить выход Hysteria'),('restart','Перезапустить VPN'),('help','Справка')]]})
 offset=json.loads(STATE.read_text()).get('offset',0) if STATE.exists() else 0
 while True:
  try:
   for update in api('getUpdates',{'offset':offset,'timeout':25,'allowed_updates':['message','callback_query']}):
    # Persist before execution: a crash cannot replay a mutation.
    offset=update['update_id']+1;persist(offset)
    try:handle(update)
    except Exception as e:print('Handler error: '+type(e).__name__,flush=True)
  except Exception as e:print('Polling error: '+type(e).__name__,flush=True);time.sleep(5)
if __name__=='__main__':main()
