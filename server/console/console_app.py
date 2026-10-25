"""Unified console sidecar. Reuses the portal identity; never starts a VPN endpoint."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from urllib.parse import urlsplit, parse_qs, urlencode
import http.client
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from config_qr import with_qr
import config_delivery
from app import config, db, security, webauth, mailer, conninfo

BASE=Path(__file__).parent
STATE=Path(os.environ.get('CONSOLE_DATA','/console-data'))
AGENT=os.environ.get('CONSOLE_SOCKET','/run/vpn-console/agent.sock')
PORTAL=os.environ.get('CONSOLE_PORTAL','http://trusttunnel-web:8000')
STOP=threading.Event()
WRITE_LOCK=threading.Lock()

@contextmanager
def connect():
    c=sqlite3.connect(STATE/'console.db',timeout=15); c.row_factory=sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    try:
        with c: yield c
    finally: c.close()

def init():
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT DEFAULT CURRENT_TIMESTAMP, actor INTEGER, action TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, actor INTEGER, action TEXT, payload TEXT, state TEXT, result TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP, updated TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS contacts(source TEXT, user_id INTEGER, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(source,user_id));
        CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, actor INTEGER, channel TEXT, subject TEXT, body TEXT, state TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS deliveries(campaign TEXT, recipient TEXT, state TEXT, error TEXT, PRIMARY KEY(campaign,recipient));
        CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY AUTOINCREMENT, nick TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS person_accounts(person INTEGER NOT NULL, source TEXT NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(source,user_id));
        ''')
        # Existing installations also need monotonic IDs: stale tabs/jobs retain person IDs.
        c.execute('BEGIN IMMEDIATE')
        schema=c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='people'").fetchone()[0]
        if 'AUTOINCREMENT' not in schema.upper():
            # Deleted IDs remain in the durable job history even when no live people remain.
            high_water=c.execute("SELECT MAX(COALESCE((SELECT MAX(id) FROM people),0),COALESCE((SELECT MAX(CAST(json_extract(payload,'$.id') AS INTEGER)) FROM jobs WHERE action='person.delete' AND json_valid(payload)),0))").fetchone()[0]
            c.execute("CREATE TABLE people_next(id INTEGER PRIMARY KEY AUTOINCREMENT, nick TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT, chat_id INTEGER, consent INTEGER NOT NULL DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP)")
            c.execute('INSERT INTO people_next SELECT id,nick,email,chat_id,consent,created FROM people')
            c.execute('DROP TABLE people')
            c.execute('ALTER TABLE people_next RENAME TO people')
            c.execute("DELETE FROM sqlite_sequence WHERE name='people'")
            c.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('people',?)",(high_water,))
        c.execute("UPDATE jobs SET state='unknown',result=? WHERE state='running'",(json.dumps({'message':'Сервис перезапущен. Проверьте состояние перед повтором.'}),))
        c.execute("UPDATE deliveries SET state='unknown',error='Прервано; автоматический повтор отключён' WHERE state='sending'")
        c.execute("UPDATE campaigns SET state='unknown' WHERE state='sending'")

def audit(actor,action,detail=''):
    with connect() as c: c.execute('INSERT INTO audit(actor,action,detail) VALUES(?,?,?)',(actor,action,detail))

def agent(op,data=None):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(240); sock.connect(AGENT); sock.sendall(json.dumps({'op':op,'data':data or {}}).encode()+b'\n')
        with sock.makefile('rb') as f: raw=f.readline(2*1024*1024)
    result=json.loads(raw)
    if not result.get('ok'): raise RuntimeError(result.get('error','Ошибка агента'))
    return result['result']

def actor(request,write=False):
    try: admin=webauth.current_admin(request)
    except (ValueError,KeyError,TypeError): admin=None
    if admin is None: raise HTTPException(401,'Войдите под администратором TrustTunnel')
    if write:
        csrf=hmac.new(config.SECRET_KEY.encode(),('console:'+request.cookies.get(webauth.ADMIN_COOKIE,'')).encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf): raise HTTPException(403,'Недействительный CSRF-токен')
        origin=request.headers.get('origin')
        if origin and origin!=os.environ.get('CONSOLE_ORIGIN','https://onixus-rf.duckdns.org'): raise HTTPException(403,'Недопустимый Origin')
    return admin['id']

async def body(request):
    raw=await request.body()
    if len(raw)>32768: raise HTTPException(413,'Слишком большой запрос')
    try: value=json.loads(raw)
    except (ValueError,UnicodeError): raise HTTPException(422,'Некорректный JSON')
    if not isinstance(value,dict): raise HTTPException(422,'Ожидается объект')
    return value

def legacy(actor_id,path,data):
    # Fixed paths constructed from checked integer IDs, session never saved in jobs.
    token=security.create_session_token(str(actor_id),'admin')
    origin=urlsplit(PORTAL)
    if origin.scheme!='http' or origin.hostname not in ('trusttunnel-web','127.0.0.1'):
        raise RuntimeError('Недопустимый внутренний адрес панели')
    client=http.client.HTTPConnection(origin.hostname,origin.port or 80,timeout=30)
    try:
        client.request('POST','/admin/'+path,body=urlencode(data),headers={'Cookie':webauth.ADMIN_COOKIE+'='+token,'Content-Type':'application/x-www-form-urlencoded'})
        r=client.getresponse(); dest=r.getheader('Location',''); r.read(1048576)
        query=parse_qs(urlsplit(dest).query)
        if r.status not in (302,303) or 'err' in query or '/login' in dest:
            raise RuntimeError('Панель TrustTunnel не подтвердила изменение')
    finally: client.close()
    return {'message':'Изменение TrustTunnel применено'}

def managed_device_revoke(actor_id,device_id):
    # The sidecar never starts an endpoint. Use the owning portal supervisor.
    token=security.create_session_token(str(actor_id),'admin')
    csrf=hmac.new(config.SECRET_KEY.encode(),('rtrust-admin-routes:'+token).encode(),hashlib.sha256).hexdigest()
    origin=urlsplit(PORTAL)
    if origin.scheme!='http' or origin.hostname not in ('trusttunnel-web','127.0.0.1'):
        raise RuntimeError('Недопустимый внутренний адрес панели')
    client=http.client.HTTPConnection(origin.hostname,origin.port or 80,timeout=30)
    try:
        client.request('POST',f'/admin/api/device-credentials/{device_id}/revoke',headers={'Cookie':webauth.ADMIN_COOKIE+'='+token,'X-CSRF-Token':csrf})
        response=client.getresponse();raw=response.read(1048576)
        if response.status!=200:raise RuntimeError('Портал не подтвердил отзыв устройства')
        result=json.loads(raw)
        revoke=next((op for op in result.get('operations',[]) if op['action']=='revoke'),None)
        if revoke and revoke['state']!='applied':
            raise RuntimeError('Отзыв записан, но endpoint не подтвердил применение. Повторите операцию после восстановления endpoint.')
        return {'message':'Отзыв отдельного VPN-пароля применён на endpoint' if revoke else 'Доступ к порталу отозван. Общие и внешние VPN-пароли остаются действующими.'}
    finally:client.close()

def source_user(source,id):
    if source=='trusttunnel':
        u=db.get_user(id)
        if not u: raise HTTPException(404,'Пользователь не найден')
        return dict(u)
    if source=='hysteria':
        users=agent('snapshot').get('hysteria_users',[])
        if isinstance(users,list):
            for u in users:
                if u['id']==id: return u
        raise HTTPException(404,'Пользователь не найден')
    if source in ('amnezia','cdn'):
        users=agent('snapshot').get(source+'_users',[])
        if isinstance(users,list):
            for u in users:
                if u['id']==id: return u
        raise HTTPException(404,'Пользователь не найден')
    raise HTTPException(422,'Неизвестный источник')

# One person (nick + contacts) owns at most one account per protocol. Accounts are
# linked explicitly, never merged by matching names; logins are derived from the nick.
NICK=re.compile(r'[a-z0-9][a-z0-9_-]{2,31}')
NAMES={'trusttunnel':'TrustTunnel','hysteria':'Hysteria','amnezia':'AmneziaWG','cdn':'CDN'}

def user_domain():
    return os.environ.get('CONSOLE_USER_DOMAIN') or urlsplit(os.environ.get('CONSOLE_ORIGIN','https://onixus-rf.duckdns.org')).hostname

def logins(nick,email=''):
    # Hysteria requires 6+ characters; TrustTunnel requires an e-mail-shaped login.
    return {'trusttunnel':email or f'{nick}@{user_domain()}','hysteria':nick if len(nick)>=6 else nick+'-vpn','amnezia':nick,'cdn':nick}

def person(id):
    with connect() as c:
        row=c.execute('SELECT * FROM people WHERE id=?',(id,)).fetchone()
        if not row: raise RuntimeError('Пользователь не найден')
        return dict(row,accounts={r['source']:r['user_id'] for r in c.execute('SELECT source,user_id FROM person_accounts WHERE person=?',(id,))})

def link(pid,source,uid):
    with connect() as c:
        p=c.execute('SELECT * FROM people WHERE id=?',(pid,)).fetchone()
        c.execute('INSERT INTO person_accounts VALUES(?,?,?)',(pid,source,uid))
        # Delivery and campaigns keep reading per-account contacts.
        c.execute('INSERT OR REPLACE INTO contacts VALUES(?,?,?,?,?)',(source,uid,p['email'] or '',p['chat_id'],p['consent']))

def unlink(source,uid):
    with connect() as c:
        c.execute('DELETE FROM person_accounts WHERE source=? AND user_id=?',(source,uid))
        c.execute('DELETE FROM contacts WHERE source=? AND user_id=?',(source,uid))

def create_account(source,p,admin):
    login=logins(p['nick'],p['email'] or '')[source]
    if source=='trusttunnel':
        legacy(admin,'users/create',{'email':login,'password':secrets.token_urlsafe(24)})
        uid=db.get_user_by_email(login)['id']
        legacy(admin,f'users/{uid}/configs',{'label':'Основной'})
        return uid
    uid=agent(source+'.create',{'username':login,'days':365,'devices':3} if source=='hysteria' else {'username':login}).get('id')
    if uid is None: raise RuntimeError(NAMES[source]+': учётка создана, но не найдена. Привяжите её вручную.')
    return uid

def delete_account(source,uid,admin):
    if source=='trusttunnel':
        if not db.get_user(uid): return unlink(source,uid)
        with db.connect() as c:
            devices=[r['id'] for r in c.execute('SELECT id FROM app_devices WHERE user_id=?',(uid,))]
            integrated=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rtrust_credential_operations'").fetchone()
        # Device credentials are revoked through their owner before the account disappears.
        for d in devices: managed_device_revoke(admin,d) if integrated else db.revoke_device(d)
        legacy(admin,f'users/{uid}/delete',{})
    else: agent(source+'.delete',{'id':uid})
    unlink(source,uid)

def each_account(p,fn):
    done,failed=[],[]
    for source,uid in sorted(p['accounts'].items()):
        try: fn(source,uid); done.append(NAMES[source])
        except Exception as exc: failed.append(NAMES[source]+': '+(str(exc) if isinstance(exc,RuntimeError) else 'ошибка'))
    return done,failed

def person_perform(action,data,admin):
    if action=='person.create':
        with connect() as c:
            pid=c.execute('INSERT INTO people(nick,email,chat_id,consent) VALUES(?,?,?,?)',(data['nick'],data['email'],data['chat_id'],int(data['consent']))).lastrowid
        p=person(pid); done,failed=[],[]
        for source in data['protocols']:
            try: link(pid,source,create_account(source,p,admin)); done.append(NAMES[source])
            except Exception as exc: failed.append(NAMES[source]+': '+(str(exc) if isinstance(exc,RuntimeError) else 'ошибка'))
        if failed: raise RuntimeError(f"Пользователь {data['nick']} создан частично. Готово: {', '.join(done) or 'ничего'}. Ошибки: {'; '.join(failed)}. Недостающие протоколы добавьте в карточке пользователя.")
        return {'message':f"Пользователь {data['nick']} создан: {', '.join(done)}",'id':pid}
    p=person(data['id'])
    if action=='person.add':
        if data['source'] in p['accounts']: raise RuntimeError('У пользователя уже есть учётка '+NAMES[data['source']])
        link(p['id'],data['source'],create_account(data['source'],p,admin))
        return {'message':NAMES[data['source']]+': учётка создана'}
    if action in ('person.block','person.unblock'):
        done,failed=each_account(p,lambda source,uid:perform(source+action[6:],{'id':uid},admin))
    elif action=='person.delete':
        done,failed=each_account(p,lambda source,uid:delete_account(source,uid,admin))
        if not failed:
            with connect() as c: c.execute('DELETE FROM people WHERE id=?',(p['id'],))
            return {'message':f"Пользователь {p['nick']} удалён вместе с учётками: {', '.join(done) or 'нет'}"}
    else: raise RuntimeError('Операция не поддерживается')
    if failed: raise RuntimeError('Выполнено не полностью. Готово: '+(', '.join(done) or 'ничего')+'. Ошибки: '+'; '.join(failed))
    return {'message':'Изменение применено: '+(', '.join(done) or 'нет учёток')}

def perform(action,data,admin):
    if action.startswith('person.'): return person_perform(action,data,admin)
    if action in ('hysteria.delete','amnezia.delete','cdn.delete','trusttunnel.delete'):
        source=action.split('.')[0]
        delete_account(source,data['id'],admin)
        return {'message':NAMES[source]+': учётка удалена'}
    if action.startswith(('routes.','updates.','hysteria.','adblock.','amnezia.','cdn.','protocols.')): return agent(action,data)
    if action=='trusttunnel.create':
        # Password is generated at execution, never stored in the job or audit.
        return legacy(admin,'users/create',{'email':data['email'],'password':secrets.token_urlsafe(24)})
    if action=='trusttunnel.password':
        u=source_user('trusttunnel',data['id'])
        # Admin supplies password only via a synchronous route; not job payload.
        raise RuntimeError('Используйте отдельную форму пароля')
    if action in ('trusttunnel.block','trusttunnel.unblock'):
        source_user('trusttunnel',data['id'])
        return legacy(admin,f"users/{data['id']}/status",{'status':'blocked' if action.endswith('.block') else 'active'})
    if action=='trusttunnel.device-revoke':
        with db.connect() as c: device=c.execute('SELECT * FROM app_devices WHERE id=?',(data['id'],)).fetchone()
        if not device: raise RuntimeError('Устройство не найдено')
        with db.connect() as c:
            integrated=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rtrust_credential_operations'").fetchone()
        if integrated:return managed_device_revoke(admin,device['id'])
        db.revoke_device(device['id']); user=db.get_user(device['user_id'])
        return legacy(admin,f"users/{user['id']}/status",{'status':user['status']})
    if action in ('trusttunnel.key-delete','trusttunnel.device-delete'):
        if action=='trusttunnel.key-delete':
            cfg=db.get_config(data['id'])
            if not cfg: raise RuntimeError('Ключ не найден')
            if cfg['device_id'] is not None: raise RuntimeError('Ключ принадлежит устройству: удалите устройство.')
            legacy(admin,f"configs/{cfg['id']}/delete",{})
            return {'message':'Ключ удалён'}
        device=db.get_device(data['id'])
        if not device: raise RuntimeError('Устройство не найдено')
        # Revocation reaches the endpoint first; only revoked rows are removed.
        # revoked_at records desired state, not confirmation that the endpoint applied it.
        perform('trusttunnel.device-revoke',{'id':device['id']},admin)
        with db.connect() as c:
            c.execute('DELETE FROM configs WHERE device_id=? AND revoked_at IS NOT NULL',(device['id'],))
            c.execute('DELETE FROM app_devices WHERE id=? AND revoked_at IS NOT NULL',(device['id'],))
        return {'message':'Устройство удалено'}
    if action=='trusttunnel.key':
        source_user('trusttunnel',data['id'])
        return legacy(admin,f"users/{data['id']}/configs",{'label':'Unified console'})
    if action in ('trusttunnel.rotate','trusttunnel.revoke'):
        cfg=db.get_config(data['id'])
        if not cfg or cfg['revoked_at']: raise RuntimeError('Ключ не найден или уже отозван')
        if cfg['device_id'] is not None:
            raise RuntimeError('Для ключа устройства используйте смену пароля или отзыв устройства в разделе профилей.')
        # Persist desired state first; if endpoint reload fails, job reports failure.
        with db.connect() as c:
            if action.endswith('.rotate'): c.execute('UPDATE configs SET tt_password=? WHERE id=?',(secrets.token_urlsafe(24),cfg['id']))
            else:
                c.execute("UPDATE configs SET revoked_at=datetime('now') WHERE id=?",(cfg['id'],))
                # A revoked config never becomes live again; drop its portal grants
                # in the same transaction (table exists only with the overlay).
                if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rtrust_grants'").fetchone():
                    c.execute('DELETE FROM rtrust_grants WHERE profile=?',('managed-'+str(cfg['id']),))
        u=db.get_user(cfg['user_id'])
        return legacy(admin,f"users/{cfg['user_id']}/status",{'status':u['status']})
    if action=='campaign.send': return send_campaign(data['id'])
    if action=='config.send': return send_config(data)
    raise RuntimeError('Операция не поддерживается')

def config_recipients(source,id,user):
    with connect() as c: row=c.execute('SELECT email,chat_id FROM contacts WHERE source=? AND user_id=?',(source,id)).fetchone()
    email=(row['email'] if row else '') or (user.get('email','') if source=='trusttunnel' else '')
    return {'email':email or None,'telegram':row['chat_id'] if row else None}

def send_config(data):
    source,id,channels=data['source'],data['id'],data['channels']
    try: user=source_user(source,id)
    except HTTPException: raise RuntimeError('Пользователь не найден')
    recipients=config_recipients(source,id,user)
    if any(not recipients[ch] for ch in channels): raise RuntimeError('Контакт изменился: адрес получателя не задан')
    try:
        bundle=(config_delivery.hysteria_bundle(user,lambda d:agent('hysteria.export',d)) if source=='hysteria'
                else config_delivery.amnezia_bundle(user,lambda d:agent('amnezia.export',d)) if source=='amnezia'
                else config_delivery.cdn_bundle(user,lambda d:agent('cdn.export',d)) if source=='cdn'
                else config_delivery.trusttunnel_bundle(user))
    except config_delivery.DeliveryError: raise
    except Exception: raise RuntimeError('Не удалось подготовить конфигурацию')
    status=config_delivery.deliver(bundle,recipients,channels,agent)
    names={'email':'E-mail','telegram':'Telegram'}
    summary='; '.join(names[ch]+(': принято' if st=='accepted' else ': ошибка') for ch,st in status.items())
    if 'failed' in status.values():
        # No automatic retry: a repeat may duplicate messages in channels that succeeded.
        raise RuntimeError('Конфигурация отправлена не во все каналы. '+summary+'. Проверьте контакт и SMTP/бота перед повтором.')
    return {'message':'Конфигурация отправлена. '+summary,'channels':status}

def work_once():
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        job=c.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created,id LIMIT 1").fetchone()
        if job is None: return False
        c.execute("UPDATE jobs SET state='running',updated=CURRENT_TIMESTAMP WHERE id=?",(job['id'],))
    try:
        with db.connect() as c:
            exists=c.execute('SELECT id FROM admins WHERE id=?',(job['actor'],)).fetchone()
        if not exists: raise RuntimeError('Администратор удалён; выполнение отменено')
        result=perform(job['action'],json.loads(job['payload']),job['actor']); state='success'
    except Exception as exc:
        # Do not persist arbitrary upstream exceptions, which can contain credentials.
        result={'message':str(exc) if isinstance(exc,RuntimeError) else 'Ошибка выполнения. Проверьте состояние перед повтором.'}; state='failed'
    with connect() as c: c.execute('UPDATE jobs SET state=?,result=?,updated=CURRENT_TIMESTAMP WHERE id=?',(state,json.dumps(result,ensure_ascii=False),job['id']))
    audit(job['actor'],job['action'],state)
    return True

def worker():
    while not STOP.is_set():
        if not work_once(): STOP.wait(.5)

@asynccontextmanager
async def lifespan(app):
    init(); STOP.clear(); t=threading.Thread(target=worker,daemon=True); t.start()
    yield
    STOP.set(); t.join(timeout=2)

app=FastAPI(title='VPN Console',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
app.mount('/console/static',StaticFiles(directory=BASE/'static'),name='static')
templates=Jinja2Templates(directory=BASE/'templates')

@app.middleware('http')
async def headers(request,call_next):
    if request.method=='POST':
        try:
            if int(request.headers.get('content-length','0'))>32768:
                return HTMLResponse('Request too large',413)
        except ValueError: return HTMLResponse('Invalid length',400)
    response=await call_next(request)
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
        'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response

@app.get('/console',response_class=HTMLResponse)
@app.get('/console/',response_class=HTMLResponse)
def index(request:Request):
    try: actor(request)
    except HTTPException: return RedirectResponse('/admin/login',302)
    token=hmac.new(config.SECRET_KEY.encode(),('console:'+request.cookies.get(webauth.ADMIN_COOKIE,'')).encode(),hashlib.sha256).hexdigest()
    return templates.TemplateResponse(request,'index.html',{'csrf':token})

@app.get('/console/api/state')
def state(request:Request):
    actor(request)
    try: snapshot=agent('snapshot')
    except Exception: snapshot={'error':'Агент недоступен. Операции с узлами недоступны.'}
    with db.connect() as c:
        users=[dict(r) for r in c.execute('SELECT id,email,status,created_at FROM users ORDER BY id')]
        keys=[dict(r) for r in c.execute('SELECT c.id,c.user_id,c.device_id,c.tt_username,c.label,c.created_at,c.revoked_at,u.email FROM configs c JOIN users u ON u.id=c.user_id ORDER BY c.id')]
        devices=[dict(r) for r in c.execute('SELECT id,user_id,name,platform,last_seen_at,revoked_at FROM app_devices ORDER BY id')]
    with connect() as c:
        snapshot.update(users=users,keys=keys,devices=devices,contacts=[dict(r) for r in c.execute('SELECT * FROM contacts')],
            jobs=[dict(r) for r in c.execute('SELECT id,action,state,result,created,updated FROM jobs ORDER BY created DESC,rowid DESC LIMIT 40')],
            campaigns=[dict(r) for r in c.execute('SELECT id,channel,subject,state,created FROM campaigns ORDER BY created DESC')],
            audit=[dict(r) for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 60')],smtp=mailer.is_configured(),
            people=[dict(r,accounts={a['source']:a['user_id'] for a in c.execute('SELECT source,user_id FROM person_accounts WHERE person=?',(r['id'],))}) for r in c.execute('SELECT * FROM people ORDER BY nick')],
            user_domain=user_domain())
    snapshot['observed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    return snapshot

ACTIONS={'adblock.refresh','routes.check','routes.apply','updates.promote','updates.server','updates.fetch','hysteria.create','hysteria.block','hysteria.unblock','hysteria.rotate',
         'trusttunnel.create','trusttunnel.block','trusttunnel.unblock','trusttunnel.key','trusttunnel.rotate','trusttunnel.revoke','trusttunnel.device-revoke','hysteria.update','campaign.send','config.send',
         'amnezia.create','amnezia.block','amnezia.unblock','amnezia.rotate','protocols.check','protocols.install','protocols.update',
         'cdn.create','cdn.block','cdn.unblock','cdn.rotate','cdn.configure',
         'hysteria.delete','trusttunnel.delete','amnezia.delete','cdn.delete','trusttunnel.key-delete','trusttunnel.device-delete',
         'person.create','person.add','person.block','person.unblock','person.delete'}
PROTOCOLS=('hysteria','trusttunnel','amnezia','cdn')
CDN_SETTINGS={'domain','address','client_port','origin_port','origin_tls','transport','path','regenerate_path'}

def check_logins(nick,email,protocols,check_nick=True):
    if check_nick:
        with connect() as c:
            if c.execute('SELECT 1 FROM people WHERE nick=?',(nick,)).fetchone(): raise HTTPException(409,f'Пользователь «{nick}» уже существует')
    names=logins(nick,email); busy=[]
    if 'trusttunnel' in protocols and db.get_user_by_email(names['trusttunnel']): busy.append('TrustTunnel ('+names['trusttunnel']+')')
    remote=[s for s in protocols if s!='trusttunnel']
    if remote:
        try: snapshot=agent('snapshot')
        except Exception: raise HTTPException(503,'Агент недоступен: нельзя проверить логины Hysteria/AmneziaWG/CDN') from None
        for source in remote:
            users=snapshot.get(source+'_users')
            if not isinstance(users,list): raise HTTPException(409,NAMES[source]+' сейчас недоступен. Снимите этот протокол или установите его в разделе «Протоколы».')
            if any(u.get('username','').lower()==names[source].lower() for u in users): busy.append(NAMES[source]+' ('+names[source]+')')
    if busy: raise HTTPException(409,'Логин уже занят: '+', '.join(busy)+'. Выберите другой ник или привяжите существующую учётку.')

def validate_action(action,data,*,check_state=True):
    if action not in ACTIONS: raise HTTPException(422,'Неизвестная операция')
    if action=='config.send':
        channels=data.get('channels')
        if set(data)!={'source','id','channels'} or data['source'] not in PROTOCOLS or type(data['id']) is not int or data['id']<=0: raise HTTPException(422,'Некорректные параметры')
        if not isinstance(channels,list) or not channels or len(set(channels))!=len(channels) or not set(channels)<=set(config_delivery.CHANNELS): raise HTTPException(422,'Выберите e-mail и/или Telegram')
        clean={'source':data['source'],'id':data['id'],'channels':sorted(channels)}
        if not check_state: return clean
        recipients=config_recipients(clean['source'],clean['id'],source_user(clean['source'],clean['id']))
        for ch in clean['channels']:
            if not recipients[ch]: raise HTTPException(422,('E-mail' if ch=='email' else 'Telegram ID')+' получателя не задан. Заполните контакт пользователя.')
        if 'email' in clean['channels'] and not mailer.is_configured(): raise HTTPException(409,'SMTP не настроен')
        return clean
    if action=='person.create':
        nick=str(data.get('nick','')).strip().lower(); email=str(data.get('email') or '').strip().lower(); chat=data.get('chat_id'); protocols=data.get('protocols')
        if not NICK.fullmatch(nick): raise HTTPException(422,'Ник: 3–32 символа — латиница в нижнем регистре, цифры, «-» и «_»')
        if email and not re.fullmatch(r'[^\s@<>\r\n]{1,100}@[^\s@<>\r\n]{1,150}\.[^\s@<>\r\n]{2,30}',email): raise HTTPException(422,'Некорректный e-mail')
        if chat is not None and (type(chat) is not int or not 0<chat<2**53): raise HTTPException(422,'Нужен положительный Telegram user ID')
        if not isinstance(protocols,list) or not protocols or len(set(protocols))!=len(protocols) or not set(protocols)<=set(PROTOCOLS): raise HTTPException(422,'Выберите хотя бы один протокол')
        clean={'nick':nick,'email':email,'chat_id':chat,'consent':data.get('consent') is True,'protocols':sorted(protocols)}
        if check_state: check_logins(nick,email,clean['protocols'])
        return clean
    if action=='person.add':
        if type(data.get('id')) is not int or data.get('source') not in PROTOCOLS or set(data)!={'id','source'}: raise HTTPException(422,'Некорректные параметры')
        if check_state:
            try: p=person(data['id'])
            except RuntimeError: raise HTTPException(404,'Пользователь не найден') from None
            if data['source'] in p['accounts']: raise HTTPException(409,'У пользователя уже есть учётка '+NAMES[data['source']])
            check_logins(p['nick'],p['email'] or '',[data['source']],check_nick=False)
        return {'id':data['id'],'source':data['source']}
    if action.endswith(('.block','.unblock','.rotate','.key','.revoke','.device-revoke','.delete','-delete')):
        if type(data.get('id')) is not int or data['id']<=0: raise HTTPException(422,'Некорректный ID')
        return {'id':data['id']}
    if action=='trusttunnel.create':
        email=data.get('email','').strip().lower()
        if not re.fullmatch(r'[^\s@<>\r\n]{1,100}@[^\s@<>\r\n]{1,150}\.[^\s@<>\r\n]{2,30}',email): raise HTTPException(422,'Некорректный e-mail')
        if check_state and db.get_user_by_email(email): raise HTTPException(409,'E-mail уже существует')
        return {'email':email}
    if action=='hysteria.create':
        if not re.fullmatch('[A-Za-z0-9_-]{6,32}',str(data.get('username',''))): raise HTTPException(422,'Логин Hysteria: 6–32 латинских символа')
        return {'username':data['username'],'days':365,'devices':3}
    if action=='amnezia.create':
        if not re.fullmatch('[A-Za-z0-9_-]{3,32}',str(data.get('username',''))): raise HTTPException(422,'Имя AmneziaWG: 3–32 латинских символа')
        return {'username':data['username']}
    if action=='cdn.create':
        if not re.fullmatch('[A-Za-z0-9_-]{3,32}',str(data.get('username',''))): raise HTTPException(422,'Имя CDN: 3–32 латинских символа')
        return {'username':data['username']}
    if action=='cdn.configure':
        # Types only; the agent checks domains, ports and paths at the privilege boundary.
        types={'domain':str,'address':str,'client_port':int,'origin_port':int,'origin_tls':bool,'transport':str,'path':str,'regenerate_path':bool}
        if not data or not set(data)<=CDN_SETTINGS or any(type(v) is not types[k] for k,v in data.items()): raise HTTPException(422,'Некорректные параметры CDN')
        if any(isinstance(v,str) and len(v)>253 for v in data.values()): raise HTTPException(422,'Слишком длинное значение')
        return data
    if action in ('protocols.install','protocols.update'):
        # Only a registry name and a version string; the agent resolves both against the developers' repositories.
        component=data.get('component'); clean={'component':component}
        if component not in PROTOCOLS or not set(data)<={'component','version','port'}: raise HTTPException(422,'Некорректные параметры')
        if 'version' in data:
            if not isinstance(data['version'],str) or not re.fullmatch(r'\d+(\.\d+){1,3}',data['version']): raise HTTPException(422,'Некорректная версия')
            clean['version']=data['version']
        elif action=='protocols.update': raise HTTPException(422,'Укажите версию')
        if action=='protocols.install' and component=='amnezia':
            if type(data.get('port')) is not int or not 1024<=data['port']<=65535: raise HTTPException(422,'Порт AmneziaWG: 1024–65535')
            clean['port']=data['port']
        elif 'port' in data: raise HTTPException(422,'Некорректные параметры')
        return clean
    if action=='updates.fetch':
        # Only a version string; the agent resolves it against releases it discovered itself.
        if set(data)!={'version'} or not isinstance(data['version'],str) or not re.fullmatch(r'\d+\.\d+\.\d+',data['version']): raise HTTPException(422,'Некорректная версия')
        return {'version':data['version']}
    if action=='hysteria.update':
        if set(data)!={'id','days','devices','quota_gb'} or any(type(data[k]) is not int for k in data): raise HTTPException(422,'Проверьте параметры')
        if data['id']<=0 or not 1<=data['days']<=3650 or not 1<=data['devices']<=100 or not -1<=data['quota_gb']<=100000: raise HTTPException(422,'Недопустимые лимиты')
        return data
    if action=='campaign.send':
        if not check_state: return {'id':data.get('id')}
        with connect() as c: row=c.execute('SELECT state FROM campaigns WHERE id=?',(data.get('id'),)).fetchone()
        if not row or row['state']!='draft': raise HTTPException(409,'Рассылка уже отправлялась или не существует')
        return {'id':data['id']}
    if action in ('routes.check','adblock.refresh','protocols.check'):
        if data: raise HTTPException(422,'Некорректные параметры')
        return {}
    # Agent repeats validation at the privilege boundary.
    allowed={'routes.apply':{'exit','rules','revision'},'updates.promote':{'sequence'},'updates.server':{'package'}}[action]
    if set(data)!=allowed: raise HTTPException(422,'Некорректные параметры')
    return data

@app.post('/console/api/jobs')
async def enqueue(request:Request):
    admin=actor(request,True); q=await body(request)
    if q.get('confirm') is not True: raise HTTPException(422,'Требуется подтверждение действия')
    action=q.get('action'); key=q.get('request_id',''); data=q.get('data',{})
    if not re.fullmatch('[a-zA-Z0-9-]{16,80}',key) or not isinstance(data,dict): raise HTTPException(422,'Некорректный идентификатор запроса')
    with WRITE_LOCK:
        with connect() as c: existing=c.execute('SELECT * FROM jobs WHERE id=?',(key,)).fetchone()
        if existing:
            if existing['actor']!=admin or existing['action']!=action: raise HTTPException(409,'Идентификатор уже используется')
            # Replays compare canonical inputs without rechecking mutable execution state.
            clean=validate_action(action,data,check_state=False)
            if json.loads(existing['payload'])!=clean: raise HTTPException(409,'Идентификатор уже используется')
            return {'id':key,'state':existing['state']}
        clean=validate_action(action,data)
        with connect() as c:
            if action=='config.send':
                recent=c.execute("SELECT 1 FROM jobs WHERE action='config.send' AND json_extract(payload,'$.source')=? AND json_extract(payload,'$.id')=? AND created>datetime('now','-60 seconds')",(clean['source'],clean['id'])).fetchone()
                if recent: raise HTTPException(429,'Конфигурация этому пользователю уже отправлялась меньше минуты назад')
            if action.startswith('protocols.') and c.execute("SELECT 1 FROM jobs WHERE action LIKE 'protocols.%' AND state IN ('queued','running')").fetchone():
                raise HTTPException(409,'Уже выполняется операция с протоколами')
            if action=='updates.fetch' and c.execute("SELECT 1 FROM jobs WHERE action='updates.fetch' AND state IN ('queued','running')").fetchone():
                raise HTTPException(409,'Релиз клиента уже выкладывается')
            if action=='campaign.send':
                if c.execute("SELECT 1 FROM jobs WHERE action='campaign.send' AND json_extract(payload,'$.id')=?",(clean['id'],)).fetchone(): raise HTTPException(409,'Рассылка уже поставлена в очередь')
            c.execute('INSERT INTO jobs(id,actor,action,payload,state) VALUES(?,?,?,?,?)',(key,admin,action,json.dumps(clean,sort_keys=True),'queued'))
    audit(admin,action,'queued')
    return {'id':key,'state':'queued'}

@app.post('/console/api/export')
async def export(request:Request):
    admin=actor(request,True); q=await body(request)
    if q.get('consent') is not True or type(q.get('id')) is not int or q['id'] <= 0: raise HTTPException(422,'Подтвердите раскрытие ключа')
    if type(q.get('qr', False)) is not bool: raise HTTPException(422,'Некорректный параметр QR')
    if q.get('source')=='hysteria': result=agent('hysteria.export',{'id':q['id']})
    elif q.get('source') in ('amnezia','cdn'):
        try: result=agent(q['source']+'.export',{'id':q['id']})
        except RuntimeError as exc: raise HTTPException(409,str(exc)) from None
    elif q.get('source')=='trusttunnel':
        cfg=db.get_config(q['id'])
        if not cfg or cfg['revoked_at']: raise HTTPException(404,'Ключ не найден')
        from app.rtrust_profiles import managed_document, codec
        document=managed_document(cfg)
        result=codec(document['content'],'tt')
    else: raise HTTPException(422,'Неизвестный источник')
    audit(admin,'key.export',q['source']+':'+str(q['id']))
    return await run_in_threadpool(with_qr, result) if q.get('qr') else result

ENROLL_TTL=180

def profile_device(device_id):
    if type(device_id) is not int: raise HTTPException(422,'Некорректный ID устройства')
    device=db.get_device(device_id)
    if not device or device['revoked_at']: raise HTTPException(404,'Действующее устройство не найдено')
    return device

@app.get('/console/api/device-profiles')
def device_profiles(request:Request,device_id:int):
    actor(request)
    from app import rtrust_profiles as exchange
    device=profile_device(device_id);owner=device['user_id']
    source_user('trusttunnel',owner)
    with db.connect() as c:
        c.execute('BEGIN')
        # Use the same bounded device grant scan as client synchronization.
        granted=set(exchange.device_live_ids(c,owner,device_id,exchange.SYNC_LIMIT_ERROR))
        profiles=[]
        for identifier in exchange.client_profile_ids(c,owner,None):
            row=exchange.live_row(c,owner,None,identifier)
            if row is None: continue
            if identifier.startswith('managed-'):
                if row['device_id'] is not None and row['device_id']!=device_id: continue
                name=row['label'] or row['tt_username']
            else:
                name=json.loads(row['summary']).get('name') or identifier
            profiles.append({'id':identifier,'name':name,'allowed':identifier in granted})
    return {'device':{'id':device_id,'name':device['name'],'user_id':owner},'profiles':profiles}

@app.post('/console/api/device-profile-grant')
async def device_profile_grant(request:Request):
    admin=actor(request,True);q=await body(request)
    if set(q)!={'device_id','profile_id','allow'} or not isinstance(q.get('profile_id'),str) or not 1<=len(q['profile_id'])<=80 or type(q.get('allow')) is not bool:
        raise HTTPException(422,'Некорректные параметры доступа')
    return await run_in_threadpool(apply_profile_grant,request,q,admin)

def apply_profile_grant(request,q,admin):
    from app import rtrust_profiles as exchange
    device=profile_device(q['device_id']);owner=device['user_id']
    user=source_user('trusttunnel',owner)
    if q['allow'] and user['status']!='active': raise HTTPException(409,'Пользователь заблокирован')
    # The existing transaction enforces owner isolation, device credential
    # binding, capacity and the same durable grants for both browser roles.
    result=exchange._grant(q['profile_id'],request,{'device_id':device['id'],'allow':q['allow']},(owner,'admin:'+str(admin),None))
    audit(admin,'device.profile-grant' if q['allow'] else 'device.profile-ungrant',
          json.dumps({'device_id':device['id'],'profile_id':q['profile_id']},separators=(',',':')))
    return result

@app.post('/console/api/enroll')
async def enroll(request:Request):
    admin=actor(request,True); q=await body(request)
    if type(q.get('id')) is not int: raise HTTPException(422,'Некорректный ID')
    user=source_user('trusttunnel',q['id'])
    if user['status']!='active': raise HTTPException(409,'Пользователь заблокирован: сначала включите доступ')
    # actor() already checked the browser Origin against the configured console.
    # Prefer it over a legacy portal_url that may still name an internal port.
    base=(request.headers.get('origin') or os.environ.get('CONSOLE_ORIGIN')
          or db.get_setting('portal_url') or 'https://onixus-rf.duckdns.org').rstrip('/')
    try:
        origin=urlsplit(base); port=origin.port
        valid=(base.isascii() and len(base)<=512 and origin.scheme=='https' and origin.hostname
               and origin.username is None and origin.password is None and not origin.path
               and not origin.query and not origin.fragment and port!=0 and not any(ch.isspace() for ch in base))
    except ValueError:
        valid=False
    if not valid: raise HTTPException(409,'Укажите корректный HTTPS-адрес портала без пути в настройках сервера')
    raw=security.new_token(24)
    expires=int(time.time())+ENROLL_TTL
    db.create_enroll_code(user['id'],security.hash_api_token(raw),ENROLL_TTL)
    # Current clients dispatch this JSON to v2 enrollment; legacy /e links are
    # otherwise interpreted as profile imports and fail profile-version checks.
    invitation={'kind':'rtrust_enrollment','version':1,'origin':base,'code':raw,'expires_at':expires}
    audit(admin,'device.enroll-code',str(user['id']))
    result=await run_in_threadpool(with_qr,{'content':json.dumps(invitation,separators=(',',':'))})
    return dict(result,origin=base,code=raw,expires_in=ENROLL_TTL)

@app.post('/console/api/people/contact')
async def person_contact(request:Request):
    admin=actor(request,True); q=await body(request)
    if type(q.get('id')) is not int: raise HTTPException(422,'Некорректный ID')
    try: p=person(q['id'])
    except RuntimeError: raise HTTPException(404,'Пользователь не найден') from None
    email=str(q.get('email') or '').strip(); chat=q.get('chat_id')
    if email and not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+',email): raise HTTPException(422,'Некорректный e-mail')
    if chat is not None and (type(chat) is not int or not 0<chat<2**53): raise HTTPException(422,'Нужен положительный Telegram user ID')
    consent=1 if q.get('consent') is True else 0
    with connect() as c:
        c.execute('UPDATE people SET email=?,chat_id=?,consent=? WHERE id=?',(email,chat,consent,p['id']))
        for source,uid in p['accounts'].items(): c.execute('INSERT OR REPLACE INTO contacts VALUES(?,?,?,?,?)',(source,uid,email,chat,consent))
    audit(admin,'person.contact',str(p['id'])); return {'message':'Контакт сохранён'}

@app.post('/console/api/people/link')
async def person_link(request:Request):
    # Attaches an existing protocol account; no VPN state changes, so it is synchronous.
    admin=actor(request,True); q=await body(request); source=q.get('source'); uid=q.get('user_id')
    if source not in PROTOCOLS or type(uid) is not int: raise HTTPException(422,'Некорректная учётка')
    user=source_user(source,uid)
    with connect() as c:
        if c.execute('SELECT 1 FROM person_accounts WHERE source=? AND user_id=?',(source,uid)).fetchone(): raise HTTPException(409,'Учётка уже привязана')
    if type(q.get('person')) is int:
        try: p=person(q['person'])
        except RuntimeError: raise HTTPException(404,'Пользователь не найден') from None
        if source in p['accounts']: raise HTTPException(409,'У пользователя уже есть учётка '+NAMES[source])
        pid=p['id']
    else:
        nick=str(q.get('nick','')).strip().lower()
        if not NICK.fullmatch(nick): raise HTTPException(422,'Ник: 3–32 символа — латиница в нижнем регистре, цифры, «-» и «_»')
        with connect() as c:
            if c.execute('SELECT 1 FROM people WHERE nick=?',(nick,)).fetchone(): raise HTTPException(409,f'Пользователь «{nick}» уже существует')
            # The account's existing contact becomes the person's contact.
            old=c.execute('SELECT * FROM contacts WHERE source=? AND user_id=?',(source,uid)).fetchone()
            email=(old['email'] if old else '') or (user.get('email','') if source=='trusttunnel' else '')
            pid=c.execute('INSERT INTO people(nick,email,chat_id,consent) VALUES(?,?,?,?)',(nick,email,old['chat_id'] if old else None,old['consent'] if old else 0)).lastrowid
    link(pid,source,uid)
    audit(admin,'person.link',f'{pid}:{source}:{uid}'); return {'message':'Учётка привязана','id':pid}

@app.post('/console/api/people/unlink')
async def person_unlink(request:Request):
    admin=actor(request,True); q=await body(request)
    if q.get('source') not in PROTOCOLS or type(q.get('user_id')) is not int: raise HTTPException(422,'Некорректная учётка')
    with connect() as c: c.execute('DELETE FROM person_accounts WHERE source=? AND user_id=?',(q['source'],q['user_id']))
    audit(admin,'person.unlink',f"{q['source']}:{q['user_id']}"); return {'message':'Учётка отвязана; доступ не изменён'}

@app.post('/console/api/password')
async def password(request:Request):
    admin=actor(request,True); q=await body(request)
    if type(q.get('id')) is not int or not isinstance(q.get('password'),str) or not 12<=len(q['password'])<=128: raise HTTPException(422,'Пароль: от 12 до 128 символов')
    source_user('trusttunnel',q['id']); result=legacy(admin,f"users/{q['id']}/password",{'password':q['password']})
    audit(admin,'user.password',str(q['id'])); return result

@app.post('/console/api/contacts')
async def contacts(request:Request):
    admin=actor(request,True); q=await body(request); source=q.get('source'); id=q.get('id')
    if type(id) is not int: raise HTTPException(422,'Некорректный ID')
    source_user(source,id); email=q.get('email','').strip(); chat=q.get('chat_id')
    if email and not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+',email): raise HTTPException(422,'Некорректный e-mail')
    if chat is not None and (type(chat) is not int or not 0<chat<2**53): raise HTTPException(422,'Нужен положительный Telegram user ID')
    with connect() as c: c.execute('INSERT OR REPLACE INTO contacts VALUES(?,?,?,?,?)',(source,id,email,chat,1 if q.get('consent') is True else 0))
    audit(admin,'contact.update',source+':'+str(id)); return {'message':'Контакт сохранён'}

@app.post('/console/api/campaigns')
async def campaign(request:Request):
    admin=actor(request,True); q=await body(request)
    channel=q.get('channel'); subject=q.get('subject','').strip(); text=q.get('body','').strip()
    if channel not in ('email','telegram') or not 1<=len(subject)<=160 or '\n' in subject or '\r' in subject or not 1<=len(text)<=3500: raise HTTPException(422,'Проверьте канал, тему и текст')
    if channel=='telegram' and len(subject+'\n\n'+text)>3500:
        raise HTTPException(422,'Telegram: тема и текст вместе с разделителем — не более 3500 символов')
    recipients=q.get('recipients')
    if not isinstance(recipients,list) or not 1<=len(recipients)<=500: raise HTTPException(422,'Выберите от 1 до 500 контактов')
    id=secrets.token_hex(16); selected=set()
    with connect() as c:
        for item in recipients:
            if not isinstance(item,dict) or type(item.get('id')) is not int: raise HTTPException(422,'Некорректный контакт')
            r=c.execute('SELECT * FROM contacts WHERE source=? AND user_id=? AND consent=1',(item.get('source'),item['id'])).fetchone()
            if not r or not r['email' if channel=='email' else 'chat_id']: raise HTTPException(422,'Нет адреса или согласия получателя')
            selected.add(str(r['email' if channel=='email' else 'chat_id']))
        c.execute('INSERT INTO campaigns(id,actor,channel,subject,body,state) VALUES(?,?,?,?,?,?)',(id,admin,channel,subject,text,'draft'))
        c.executemany('INSERT INTO deliveries(campaign,recipient,state) VALUES(?,?,?)',[(id,r,'pending') for r in selected])
    audit(admin,'campaign.draft',id)
    return {'id':id,'recipients':sorted(selected),'subject':subject,'body':text,'state':'draft'}

@app.get('/console/api/campaigns/{id}')
def campaign_detail(id:str,request:Request):
    actor(request)
    with connect() as c:
        row=c.execute('SELECT * FROM campaigns WHERE id=?',(id,)).fetchone()
        if not row: raise HTTPException(404,'Рассылка не найдена')
        return dict(row,deliveries=[dict(r) for r in c.execute('SELECT recipient,state,error FROM deliveries WHERE campaign=?',(id,))])

def send_campaign(id):
    with connect() as c:
        c.execute('BEGIN IMMEDIATE'); campaign=c.execute('SELECT * FROM campaigns WHERE id=?',(id,)).fetchone()
        if not campaign or campaign['state']!='draft': raise RuntimeError('Повторная отправка запрещена')
        c.execute("UPDATE campaigns SET state='sending' WHERE id=?",(id,))
        rows=c.execute('SELECT * FROM deliveries WHERE campaign=?',(id,)).fetchall()
    for row in rows:
        with connect() as c:
            field='email' if campaign['channel']=='email' else 'chat_id'
            consent=c.execute(f'SELECT 1 FROM contacts WHERE {field}=? AND consent=1',(row['recipient'],)).fetchone()
            if not consent:
                c.execute("UPDATE deliveries SET state='skipped',error='Согласие отозвано' WHERE campaign=? AND recipient=?",(id,row['recipient'])); continue
            c.execute("UPDATE deliveries SET state='sending' WHERE campaign=? AND recipient=?",(id,row['recipient']))
        try:
            if campaign['channel']=='email': mailer.send_mail(row['recipient'],campaign['subject'],campaign['body'])
            else: agent('telegram.send',{'chat_id':int(row['recipient']),'text':campaign['subject']+'\n\n'+campaign['body']})
            state,error='accepted',None
        except Exception: state,error='unknown','Доставка не подтверждена; автоматический повтор отключён'
        with connect() as c: c.execute('UPDATE deliveries SET state=?,error=? WHERE campaign=? AND recipient=?',(state,error,id,row['recipient']))
    with connect() as c:
        uncertain=c.execute("SELECT 1 FROM deliveries WHERE campaign=? AND state!='accepted'",(id,)).fetchone()
        c.execute('UPDATE campaigns SET state=? WHERE id=?',('partial' if uncertain else 'accepted',id))
    return {'message':'Обработка завершена. Проверьте статусы получателей; accepted означает принятие провайдером.'}

@app.get('/console/healthz')
def healthz():
    with connect() as c: c.execute('SELECT 1').fetchone()
    return {'status':'ok'}
