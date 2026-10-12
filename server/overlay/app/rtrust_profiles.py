"""Additive v2 profile exchange. Shared Rust codec; no endpoint mutation on import."""
import base64
import io
import hmac
from urllib.parse import urlsplit
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import stat
import subprocess
import time
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
import tempfile
from cryptography.fernet import Fernet, InvalidToken
from starlette.concurrency import run_in_threadpool
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from . import config, db, security, webauth, rtrust_credentials as credentials
from .templating import templates

router = APIRouter()
LIMIT = 1024 * 1024
CODEC = os.environ.get('RTRUST_CODEC', '/usr/local/bin/rtrust-codec')
HEADERS = {'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'}
# Profile `origin` labels are a client contract (docs/device-credentials.md):
# 1-80 printable ASCII bytes, compared byte-wise; Android/iOS reject the whole
# managed batch on anything else. Add new labels here only within that alphabet.
ORIGIN_MANAGED = 'portal_managed'
ORIGIN_STORED = 'external_stored'
ORIGIN_LABELS = (ORIGIN_MANAGED, ORIGIN_STORED)
# Client sync contract (docs/device-credentials.md): Android/iOS reject a whole
# managed batch above 64. The server never creates more and never truncates a
# historical excess: list/snapshot fail closed so clients keep their last set.
MAX_CLIENT_PROFILES = 64
SYNC_LIMIT_ERROR = 'Too many profiles for client sync'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS rtrust_profiles(id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,revision INTEGER NOT NULL,payload BLOB,summary TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS rtrust_imports(id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,actor TEXT NOT NULL,payload BLOB NOT NULL,expires INTEGER NOT NULL,result TEXT);
CREATE TABLE IF NOT EXISTS rtrust_grants(profile TEXT NOT NULL,device INTEGER NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,PRIMARY KEY(profile,device));
CREATE TABLE IF NOT EXISTS rtrust_tokens(hash TEXT PRIMARY KEY,device INTEGER NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_rates(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_route_groups(id INTEGER PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,policy TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_route_counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1),high_water INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_route_members(device INTEGER PRIMARY KEY REFERENCES app_devices(id) ON DELETE CASCADE,grp INTEGER NOT NULL REFERENCES rtrust_route_groups(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS rtrust_admin_route_groups(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,policy TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rtrust_admin_route_members(device INTEGER PRIMARY KEY REFERENCES app_devices(id) ON DELETE CASCADE,grp INTEGER NOT NULL REFERENCES rtrust_admin_route_groups(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS rtrust_route_delivery(device INTEGER PRIMARY KEY REFERENCES app_devices(id) ON DELETE CASCADE,revision TEXT,requested INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS rtrust_route_groups_owner ON rtrust_route_groups(owner);
CREATE INDEX IF NOT EXISTS rtrust_route_members_grp ON rtrust_route_members(grp);
'''

def init():
    with db.connect() as c:
        c.executescript(SCHEMA)
        c.execute('BEGIN IMMEDIATE')
        # Preserve legacy IDs and reserve deleted IDs recorded by earlier versions.
        high_water=c.execute("SELECT MAX(v) FROM (SELECT COALESCE(MAX(id),0) AS v FROM rtrust_route_groups UNION ALL SELECT COALESCE(MAX(CAST(object AS INTEGER)),0) AS v FROM rtrust_audit WHERE action IN ('route_group_create','route_group_delete'))").fetchone()[0]
        c.execute('INSERT INTO rtrust_route_counter VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET high_water=MAX(high_water,excluded.high_water)',(high_water,))
    cipher()
    credentials.init()

def install(application):
    """Call once from the existing portal main module, after constructing its app."""
    credentials.install()
    install_legacy_handlers(application)
    previous = application.router.lifespan_context
    @asynccontextmanager
    async def lifespan(app):
        import fcntl
        Path(config.DATA_DIR).mkdir(parents=True,exist_ok=True)
        # Acquire before upstream startup can spawn an endpoint. A second worker
        # must fail, rather than manage a different process with the same files.
        lock_fd=os.open(Path(config.DATA_DIR)/'.rtrust-endpoint-owner.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except Exception:
            os.close(lock_fd)
            raise RuntimeError('Portal requires one endpoint supervisor process')
        try:
            async with previous(app) as state:
                init()
                import threading
                stop = threading.Event()
                def retry():
                    while not stop.wait(5):
                        try: credentials.apply_pending()
                        except Exception: pass
                credentials.apply_pending()
                worker = threading.Thread(target=retry, name='device-credential-retry', daemon=True)
                worker.start()
                try: yield state
                finally:
                    stop.set()
                    worker.join()
        finally:
            os.close(lock_fd)
    application.router.lifespan_context = lifespan
    application.include_router(router)
    @application.middleware('http')
    async def private_responses(request, call_next):
        response = await call_next(request)
        if request.url.path in ('/profiles', '/admin/agent-routes') or request.url.path.startswith(('/portal/v2/', '/admin/api/agent-routes', '/admin/api/device-credentials')):
            response.headers.update(HEADERS)
            response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response


def install_legacy_handlers(application):
    """The additive overlay also owns offloading the installed settings writer."""
    from . import routes_admin
    # Older FastAPI copies included routes; newer releases retain the router.
    for route in [*application.routes, *routes_admin.router.routes]:
        if getattr(route, 'path', None) == '/admin/settings' and 'POST' in (getattr(route, 'methods', None) or set()):
            route.endpoint = legacy_settings_save
            route.dependant.call = legacy_settings_save


async def legacy_settings_save(request:Request):
    if not await run_in_threadpool(webauth.current_admin, request):
        return RedirectResponse('/admin/login',302)
    form = await request.form()
    return await run_in_threadpool(legacy_settings_apply, form)


def legacy_settings_apply(form):
    from .routes_admin import _SETTING_KEYS, _CHECKBOX_KEYS
    from . import endpoint
    updates = {}
    for key in _SETTING_KEYS:
        if key in _CHECKBOX_KEYS:
            updates[key] = '1' if form.get(key) else '0'
        elif key in form:
            updates[key] = str(form.get(key)).strip()
    db.set_settings(updates)
    endpoint.manager.apply_settings()
    return RedirectResponse('/admin/settings?msg=Настройки сохранены',302)

def cipher():
    path = Path(config.DATA_DIR) / '.rtrust-profile-key'
    if not path.exists():
        # Publish a complete key atomically; concurrent workers cannot read half a key.
        fd, temporary = tempfile.mkstemp(prefix='.rtrust-key-',dir=config.DATA_DIR)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(Fernet.generate_key()); f.flush(); os.fsync(f.fileno())
            try: os.link(temporary,path)
            except FileExistsError: pass
        finally: os.unlink(temporary)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise RuntimeError('Unsafe profile encryption key')
    key=path.read_bytes()
    if len(key)!=44: raise RuntimeError('Invalid profile encryption key')
    return Fernet(key)

def seal(owner, document):
    return cipher().encrypt(json.dumps({'owner':owner,'document':document},ensure_ascii=False).encode())

def unseal(owner, payload):
    try:
        value=json.loads(cipher().decrypt(payload))
        if value['owner']!=owner: raise ValueError()
        return value['document']
    except (InvalidToken,ValueError,KeyError): raise HTTPException(503,'Encrypted profile unavailable')

def codec(content, fmt='profile_json'):
    if not isinstance(content,str) or len(content.encode())>LIMIT: raise HTTPException(413,'Profile too large')
    if fmt not in ('profile_json','endpoint_toml','cli_toml','tt'): raise HTTPException(422,'Unknown format')
    try:
        r=subprocess.run([CODEC],input=json.dumps({'content':content,'format':fmt}).encode(),capture_output=True,timeout=5)
    except (OSError,subprocess.TimeoutExpired): raise HTTPException(503,'Profile codec unavailable')
    if r.returncode or len(r.stdout)>8*LIMIT: raise HTTPException(422,'Invalid or unsupported profile')
    try:return json.loads(r.stdout)
    except ValueError:raise HTTPException(503,'Invalid codec response')

def csrf(request):
    cookie=request.cookies.get(webauth.USER_COOKIE,'')
    return hmac.new(config.SECRET_KEY.encode(),('rtrust-csrf:'+cookie).encode(),hashlib.sha256).hexdigest()

def actor(request, mutate=False):
    auth=request.headers.get('authorization')
    if auth is not None:
        if not auth.startswith('Bearer ') or not 40<=len(auth[7:])<=128: raise HTTPException(401,'Invalid device token')
        with db.connect() as c:
            row=c.execute('SELECT d.id,d.user_id,u.status FROM rtrust_tokens t JOIN app_devices d ON d.id=t.device JOIN users u ON u.id=d.user_id WHERE t.hash=? AND t.expires>? AND d.revoked_at IS NULL',(security.hash_api_token(auth[7:]),int(time.time()))).fetchone()
        if row is None or row['status']!='active':raise HTTPException(401,'Device expired or revoked')
        return row['user_id'],f'd:{row["id"]}',row['id']
    user=webauth.current_user(request)
    if not user:raise HTTPException(401,'Login required')
    if mutate and not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf(request)):
        raise HTTPException(403,'CSRF check failed')
    session=hashlib.sha256(request.cookies[webauth.USER_COOKIE].encode()).hexdigest()
    return user['id'],f'u:{user["id"]}:{session}',None

def rate(bucket, limit=30):
    now=int(time.time())
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('DELETE FROM rtrust_rates WHERE expires<=?',(now,))
        r=c.execute('SELECT count FROM rtrust_rates WHERE bucket=?',(bucket,)).fetchone()
        if r and r['count']>=limit:raise HTTPException(429,'Rate limit',headers={'Retry-After':'60'})
        c.execute('INSERT INTO rtrust_rates VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1',(bucket,now+60))

def audit(c, identity, action, obj):
    c.execute('INSERT INTO rtrust_audit(actor,action,object,created) VALUES(?,?,?,?)',(identity,action,obj,int(time.time())))

async def body(request, allowed):
    data=bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data)>2*LIMIT:raise HTTPException(413,'Request too large')
    try: value=json.loads(data)
    except ValueError:raise HTTPException(422,'Invalid JSON')
    if not isinstance(value,dict) or set(value)-set(allowed):raise HTTPException(422,'Unknown request fields')
    return value

def managed_document(cfg,settings=None):
    # Freeze settings once, then use the same Rust serializer for every format.
    from . import endpoint
    settings=db.get_settings() if settings is None else settings
    hostname=endpoint.effective_domain(settings)
    address=(settings.get('conn_address') or '').strip() or hostname or config.PUBLIC_ADDRESS
    port=int(settings.get('conn_port') or '8443')
    if ':' in address and not address.startswith('['):address='['+address+']'
    raw={'schema_version':1,'name':cfg['label'] or cfg['tt_username'],'endpoint':{'hostname':hostname,'addresses':[f'{address}:{port}'],'username':cfg['tt_username'],'password':cfg['tt_password'],'custom_sni':settings.get('conn_sni') or '', 'has_ipv6':False,'anti_dpi':False,'upstream_protocol':'http3' if settings.get('conn_protocol')=='QUIC' else 'http2'}}
    ca_path=os.environ.get('CLIENT_CA_FILE')
    if ca_path:
        try:
            raw['endpoint']['certificate']=Path(ca_path).read_text(encoding='utf-8')
        except (OSError,UnicodeError):raise HTTPException(503,'Client trust certificate unavailable')
    return codec(json.dumps(raw))

def live_row(c, owner, device, identifier):
    # Same visibility rules as accessible(), without building documents.
    if device is not None and not c.execute('SELECT 1 FROM rtrust_grants WHERE profile=? AND device=?',(identifier,device)).fetchone():
        return None
    if identifier.startswith('managed-'):
        try: number=int(identifier[8:])
        except ValueError:return None
        row=c.execute('SELECT * FROM configs WHERE id=? AND user_id=? AND revoked_at IS NULL',(number,owner)).fetchone()
        if row is None or (device is not None and row['device_id'] is not None and row['device_id']!=device):return None
        return row
    return c.execute('SELECT * FROM rtrust_profiles WHERE id=? AND owner=? AND revoked=0',(identifier,owner)).fetchone()

def client_profile_ids(c, owner, device):
    """Profiles visible to this caller, in a stable order.

    Only device tokens sync clients, so only the device set is bound by the
    client limit: stale grants do not count, and a historical excess is an
    explicit 409, never a silently truncated (and thus destructive) set. The
    owner browser view is a management view and keeps its previous bounds."""
    if device is None:
        ids=[r[0] for r in c.execute('SELECT id FROM rtrust_profiles WHERE owner=? AND revoked=0 ORDER BY id LIMIT 100',(owner,))]
        ids += ['managed-'+str(r[0]) for r in c.execute('SELECT id FROM configs WHERE user_id=? AND revoked_at IS NULL ORDER BY id LIMIT 100',(owner,))]
        return ids
    ids=[r[0] for r in c.execute('SELECT profile FROM rtrust_grants WHERE device=? ORDER BY profile',(device,)) if live_row(c,owner,device,r[0]) is not None]
    if len(ids)>MAX_CLIENT_PROFILES:raise HTTPException(409,SYNC_LIMIT_ERROR)
    return ids

def require_device_capacity(c, owner, device, adding=1):
    """Refuse a mutation that would grow a device's sync set beyond the limit."""
    current=sum(1 for r in c.execute('SELECT profile FROM rtrust_grants WHERE device=?',(device,)).fetchall() if live_row(c,owner,device,r[0]) is not None)
    if current+adding>MAX_CLIENT_PROFILES:raise HTTPException(409,f'Device profile limit reached ({MAX_CLIENT_PROFILES})')

def accessible(c, owner, device, identifier,settings=None):
    if device is not None and not c.execute('SELECT 1 FROM rtrust_grants WHERE profile=? AND device=?',(identifier,device)).fetchone():
        raise HTTPException(404,'Profile not found')
    if identifier.startswith('managed-'):
        row=live_row(c,owner,device,identifier)
        if row is None:raise HTTPException(404,'Profile not found')
        result=managed_document(row,settings)
        revision=hashlib.sha256(result['content'].encode()).hexdigest()
        return {'id':identifier,'revision':revision,'summary':result['summary'],'origin':ORIGIN_MANAGED},result['content']
    row=c.execute('SELECT * FROM rtrust_profiles WHERE id=? AND owner=? AND revoked=0',(identifier,owner)).fetchone()
    if row is None:raise HTTPException(404,'Profile not found')
    return {'id':identifier,'revision':str(row['revision']),'summary':json.loads(row['summary']),'origin':ORIGIN_STORED},unseal(owner,row['payload'])

@router.get('/portal/v2/capabilities')
def capabilities():return JSONResponse({'version':2,'formats':['profile_json','endpoint_toml','cli_toml','tt'],'enrollment':['one_time_code','one_time_qr'],'max_profile_bytes':LIMIT,'max_client_profiles':MAX_CLIENT_PROFILES,'routing':1,'snapshot':1,'token_renewal':1,'offline_freshness':1,'managed_credentials':credentials.capabilities()},headers=HEADERS)

@router.get('/profiles',response_class=HTMLResponse)
def page(request:Request):
    user=webauth.current_user(request)
    if not user:return RedirectResponse('/login',302)
    return templates.TemplateResponse(request,'rtrust_profiles.html',{'user':user,'brand':db.get_setting('brand_name'),'csrf':csrf(request)},headers=HEADERS)

@router.post('/portal/v2/enrollment-codes')
async def enrollment_code(request:Request):
    context=await run_in_threadpool(actor,request,True)
    data=await body(request,["origin"])
    return await run_in_threadpool(_enrollment_code,request,data,context)

def _enrollment_code(request,data,context):
    owner,identity,device=context
    if device is not None:raise HTTPException(403,'Browser login required')
    rate(identity)
    origin=data.get('origin')
    if origin is not None:
        if not isinstance(origin,str) or len(origin)>512 or not origin.isascii() or origin!=request.headers.get('origin'):
            raise HTTPException(422,'Same browser origin required for QR')
        try:
            parsed=urlsplit(origin); port=parsed.port
        except ValueError:raise HTTPException(422,'Invalid HTTPS origin')
        if parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or port==0 or any(ch.isspace() for ch in origin):
            raise HTTPException(422,'HTTPS origin required for QR')
    expires=int(time.time())+180
    raw=secrets.token_urlsafe(24)
    db.create_enroll_code(owner,security.hash_api_token(raw),180)
    result={'code':raw,'expires_in':180,'expires_at':expires}
    if origin is not None:
        import qrcode
        from qrcode.image.svg import SvgPathFillImage
        invitation={'kind':'rtrust_enrollment','version':1,'origin':origin,'code':raw,'expires_at':expires}
        buffer=io.BytesIO()
        qrcode.make(json.dumps(invitation,separators=(',',':')),image_factory=SvgPathFillImage).save(buffer)
        result.update(invitation=invitation,qr_svg=base64.b64encode(buffer.getvalue()).decode('ascii'))
    return JSONResponse(result,headers=HEADERS)


@router.post('/portal/v2/enroll')
async def enroll(request:Request):
    context=await run_in_threadpool(_enroll_prepare, request)
    payload=await body(request,['code','name','platform'])
    return await run_in_threadpool(_enroll, request=request, payload=payload, context=context)

def _enroll_prepare(request:Request):
    rate('enroll:'+str(request.client.host if request.client else 'unknown'),10)
    return ()

def _enroll(request:Request, payload:dict, context:tuple):
    data=payload
    code=data.get('code');name=data.get('name');platform=data.get('platform')
    if not isinstance(code,str) or not 20<=len(code)<=128 or not isinstance(name,str) or not 1<=len(name)<=80 or platform not in ('windows','linux','macos','android','ios'):
        raise HTTPException(422,'Invalid enrollment')
    raw=secrets.token_urlsafe(32);now=int(time.time());hashed=security.hash_api_token(code)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT e.* FROM enroll_codes e JOIN users u ON e.user_id=u.id WHERE e.code_hash=? AND e.used_at IS NULL AND e.expires_at>datetime('now') AND u.status='active'",(hashed,)).fetchone()
        if row is None:raise HTTPException(401,'Enrollment code invalid or expired')
        device=c.execute('INSERT INTO app_devices(user_id,name,token_hash,platform) VALUES(?,?,?,?)',(row['user_id'],name,security.hash_api_token(secrets.token_urlsafe(32)),platform)).lastrowid
        c.execute("UPDATE enroll_codes SET used_at=datetime('now'),device_id=? WHERE id=?",(device,row['id']))
        c.execute('INSERT INTO rtrust_tokens VALUES(?,?,?)',(security.hash_api_token(raw),device,now+30*86400))
        audit(c,f'd:{device}','enroll',str(device))
    return JSONResponse({'token':raw,'device_id':device,'expires_in':30*86400},headers=HEADERS)


@router.get('/portal/v2/devices')
def devices(request:Request):
    owner,_,device=actor(request)
    if device is not None:raise HTTPException(403,'Browser login required')
    with db.connect() as c: rows=c.execute('SELECT DISTINCT d.id,d.name,d.platform FROM app_devices d JOIN rtrust_tokens t ON t.device=d.id WHERE d.user_id=? AND d.revoked_at IS NULL AND t.expires>?',(owner,int(time.time()))).fetchall()
    return JSONResponse({'devices':[dict(r) for r in rows]},headers=HEADERS)

@router.delete('/portal/v2/devices/{identifier}')
def revoke_device(identifier:int,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    with credentials.endpoint.manager._lock:
        with db.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            credentials.device_row(c,owner,identifier)
            credentials.revoke(c,owner,identifier)
            c.execute('DELETE FROM rtrust_tokens WHERE device=?',(identifier,))
            c.execute('DELETE FROM rtrust_grants WHERE device=?',(identifier,))
            c.execute('DELETE FROM rtrust_route_members WHERE device=?',(identifier,))
            c.execute('DELETE FROM rtrust_admin_route_members WHERE device=?',(identifier,))
            c.execute('DELETE FROM rtrust_route_delivery WHERE device=?',(identifier,))
            c.execute("UPDATE app_devices SET revoked_at=COALESCE(revoked_at,datetime('now')) WHERE id=?",(identifier,))
            audit(c,identity,'revoke_device',str(identifier))
        credentials.apply_pending()
    result=credentials.snapshot(owner,identifier)
    return JSONResponse({'revoked':True,'credentials':result},headers=HEADERS)

@router.get('/portal/v2/profiles')
def profiles(request:Request):
    owner,_,device=actor(request)
    with db.connect() as c:
        c.execute('BEGIN')
        ids=client_profile_ids(c,owner,device)
        result=[]
        for identifier in ids:
            try:meta,_=accessible(c,owner,device,identifier);result.append(meta)
            except HTTPException as e:
                if e.status_code!=404:raise
    return JSONResponse({'profiles':result},headers=HEADERS)

@router.post('/portal/v2/profiles/{identifier}/export')
async def export(identifier:str,request:Request):
    context=await run_in_threadpool(_export_prepare, request)
    payload=await body(request,['format','revision','include_secrets','accept_losses'])
    return await run_in_threadpool(_export, identifier=identifier, request=request, payload=payload, context=context)

def _export_prepare(request:Request):
    owner,identity,device=actor(request,True)
    return (owner, identity, device,)

def _export(identifier:str,request:Request, payload:dict, context:tuple):
    owner, identity, device=context
    data=payload
    if data.get('include_secrets') is not True:raise HTTPException(422,'Explicit secret export consent required')
    with db.connect() as c:
        meta,document=accessible(c,owner,device,identifier)
        if str(data.get('revision'))!=meta['revision']:raise HTTPException(409,'Profile revision changed')
        result=codec(document,data.get('format','profile_json'))
        if result['losses'] and data.get('accept_losses') is not True:
            return JSONResponse({'losses':result['losses'],'error':'Explicit format-loss consent required'},status_code=409,headers=HEADERS)
        audit(c,identity,'export',identifier)
    return JSONResponse(result,headers=HEADERS)


@router.post('/portal/v2/profile-imports/preview')
async def preview(request:Request):
    context=await run_in_threadpool(_preview_prepare, request)
    payload=await body(request,['content','intent'])
    return await run_in_threadpool(_preview, request=request, payload=payload, context=context)

def _preview_prepare(request:Request):
    owner,identity,_=actor(request,True);rate(identity)
    return (owner, identity, _,)

def _preview(request:Request, payload:dict, context:tuple):
    owner, identity, _=context
    data=payload
    if data.get('intent')!=ORIGIN_STORED:raise HTTPException(422,'Only external storage import is supported; endpoint credentials are unchanged')
    result=codec(data.get('content'))
    identifier=str(uuid.uuid4())
    with db.connect() as c:
        c.execute('DELETE FROM rtrust_imports WHERE expires<?',(int(time.time()),))
        c.execute('INSERT INTO rtrust_imports VALUES(?,?,?,?,?,NULL)',(identifier,owner,identity,seal(owner,result['content']),int(time.time())+600))
    return JSONResponse({'preview_id':identifier,'summary':result['summary'],'expires_in':600,'origin':ORIGIN_STORED,'secrets_present':True},headers=HEADERS)


@router.post('/portal/v2/profile-imports/{identifier}/commit')
async def commit(identifier:str,request:Request):
    context=await run_in_threadpool(_commit_prepare, request)
    payload=await body(request,['action','target_id','base_revision','consent'])
    return await run_in_threadpool(_commit, identifier=identifier, request=request, payload=payload, context=context)

def _commit_prepare(request:Request):
    owner,identity,device=actor(request,True)
    return (owner, identity, device,)

def _commit(identifier:str,request:Request, payload:dict, context:tuple):
    owner, identity, device=context
    data=payload
    if data.get('consent') is not True or data.get('action') not in ('create','replace'):raise HTTPException(422,'Explicit import consent and action required')
    signature=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT * FROM rtrust_imports WHERE id=? AND owner=? AND actor=?',(identifier,owner,identity)).fetchone()
        if row is None:raise HTTPException(404,'Preview not found')
        if row['result']:
            result=json.loads(row['result'])
            if result.pop('signature')!=signature:raise HTTPException(409,'Preview already committed with another action')
            return JSONResponse(result,headers=HEADERS)
        if row['expires']<=int(time.time()):raise HTTPException(410,'Preview expired')
        document=unseal(owner,row['payload']);summary=codec(document)['summary']
        if data['action']=='replace':
            target=data.get('target_id','')
            if not isinstance(target,str) or target.startswith('managed-'):raise HTTPException(403,'Managed credentials cannot be replaced')
            meta,_=accessible(c,owner,device,target)
            if str(data.get('base_revision'))!=meta['revision']:raise HTTPException(409,'Profile revision changed')
            revision=int(meta['revision'])+1
            c.execute('UPDATE rtrust_profiles SET revision=?,payload=?,summary=? WHERE id=?',(revision,seal(owner,document),json.dumps(summary),target))
        else:
            if c.execute('SELECT count(*) FROM rtrust_profiles WHERE owner=? AND revoked=0',(owner,)).fetchone()[0]>=100:raise HTTPException(409,'Profile limit reached')
            if device is not None:require_device_capacity(c,owner,device)
            target=str(uuid.uuid4());revision=1
            c.execute('INSERT INTO rtrust_profiles VALUES(?,?,?,?,?,0)',(target,owner,revision,seal(owner,document),json.dumps(summary)))
            if device is not None:c.execute('INSERT INTO rtrust_grants VALUES(?,?)',(target,device))
        result={'id':target,'revision':str(revision),'signature':signature}
        c.execute('UPDATE rtrust_imports SET result=?,payload=? WHERE id=?',(json.dumps(result),b'',identifier))
        audit(c,identity,data['action'],target)
    result.pop('signature')
    return JSONResponse(result,headers=HEADERS)


@router.post('/portal/v2/profiles/{identifier}/grants')
async def grant(identifier:str,request:Request):
    context=await run_in_threadpool(_grant_prepare, request)
    payload=await body(request,['device_id','allow'])
    return await run_in_threadpool(_grant, identifier=identifier, request=request, payload=payload, context=context)

def _grant_prepare(request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    return (owner, identity, device,)

def _grant(identifier:str,request:Request, payload:dict, context:tuple):
    owner, identity, device=context
    data=payload
    if type(data.get('device_id')) is not int or type(data.get('allow')) is not bool:raise HTTPException(422,'Invalid grant')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')  # serializes the capacity check with the insert
        accessible(c,owner,None,identifier)
        if not c.execute('SELECT 1 FROM app_devices WHERE id=? AND user_id=? AND revoked_at IS NULL',(data['device_id'],owner)).fetchone():raise HTTPException(404,'Device not found')
        if identifier.startswith('managed-'):
            cfg=c.execute('SELECT device_id FROM configs WHERE id=?',(int(identifier[8:]),)).fetchone()
            if cfg and cfg['device_id'] is not None and cfg['device_id']!=data['device_id']:raise HTTPException(409,'Device credential cannot be shared')
        if data['allow']:
            if not c.execute('SELECT 1 FROM rtrust_grants WHERE profile=? AND device=?',(identifier,data['device_id'])).fetchone():
                require_device_capacity(c,owner,data['device_id'])
            c.execute('INSERT OR IGNORE INTO rtrust_grants VALUES(?,?)',(identifier,data['device_id']))
        else:c.execute('DELETE FROM rtrust_grants WHERE profile=? AND device=?',(identifier,data['device_id']))
        audit(c,identity,'grant' if data['allow'] else 'ungrant',identifier)
    return JSONResponse({'updated':True},headers=HEADERS)


@router.delete('/portal/v2/profiles/{identifier}')
def delete(identifier:str,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None or identifier.startswith('managed-'):raise HTTPException(403,'Only owner can delete an external profile')
    with db.connect() as c:
        meta,_=accessible(c,owner,None,identifier)
        if request.headers.get('if-match')!=meta['revision']:raise HTTPException(409,'Profile revision changed')
        c.execute('UPDATE rtrust_profiles SET revoked=1,payload=NULL WHERE id=?',(identifier,))
        c.execute('DELETE FROM rtrust_grants WHERE profile=?',(identifier,))
        audit(c,identity,'delete',identifier)
    return JSONResponse({'revoked':True},headers=HEADERS)

# Split-tunnel routing for the desktop TUN mode, assigned to devices through owner-scoped groups.
def networks(value, low, high):
    if not isinstance(value,list) or not low<=len(value)<=high:raise HTTPException(422,f'Expected {low}..{high} IPv4 networks')
    result=[]
    for item in value:
        if not isinstance(item,str) or len(item)>32 or '/' not in item:raise HTTPException(422,'Invalid IPv4 network')
        try:network=str(ipaddress.IPv4Network(item.strip(),strict=True))
        except ValueError:raise HTTPException(422,'Invalid IPv4 network (host bits set or malformed): '+item[:32])
        if network not in result:result.append(network)
    return result

def route_policy(data):
    name=data.get('name')
    if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(ch)<32 or ord(ch)==127 for ch in name):raise HTTPException(422,'Group name must be 1..80 characters')
    if type(data.get('exclude_lan')) is not bool:raise HTTPException(422,'exclude_lan must be a boolean')
    return name.strip(),{'include':networks(data.get('include'),1,16),'exclude':networks(data.get('exclude'),0,64),'exclude_lan':data['exclude_lan']}

def browser(request, mutate=False):
    owner,identity,device=actor(request,mutate)
    if device is not None:raise HTTPException(403,'Browser login required')
    return owner,identity

def route_group(c, owner, identifier):
    row=c.execute('SELECT * FROM rtrust_route_groups WHERE id=? AND owner=?',(identifier,owner)).fetchone()
    if row is None:raise HTTPException(404,'Route group not found')
    return row

def route_groups(c, owner, identifier=None):
    rows=c.execute('SELECT * FROM rtrust_route_groups WHERE owner=? AND (? IS NULL OR id=?) ORDER BY id',(owner,identifier,identifier)).fetchall()
    members={}
    for r in c.execute('SELECT m.grp,m.device FROM rtrust_route_members m JOIN rtrust_route_groups g ON g.id=m.grp JOIN app_devices d ON d.id=m.device WHERE g.owner=? AND d.user_id=? AND d.revoked_at IS NULL ORDER BY m.device',(owner,owner)):
        members.setdefault(r['grp'],[]).append(r['device'])
    return [{'id':r['id'],'name':r['name'],**json.loads(r['policy']),'revision':r['revision'],'devices':members.get(r['id'],[])} for r in rows]

@router.get('/portal/v2/route-groups')
def list_route_groups(request:Request):
    owner,_=browser(request)
    with db.connect() as c:return JSONResponse({'groups':route_groups(c,owner)},headers=HEADERS)

@router.post('/portal/v2/route-groups')
async def create_route_group(request:Request):
    context=await run_in_threadpool(_create_route_group_prepare, request)
    payload=await body(request,['name','include','exclude','exclude_lan'])
    return await run_in_threadpool(_create_route_group, request=request, payload=payload, context=context)

def _create_route_group_prepare(request:Request):
    owner,identity=browser(request,True);rate('routes:'+identity,60)
    return (owner, identity,)

def _create_route_group(request:Request, payload:dict, context:tuple):
    owner, identity=context
    name,policy=route_policy(payload)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT count(*) FROM rtrust_route_groups WHERE owner=?',(owner,)).fetchone()[0]>=50:raise HTTPException(409,'Route group limit reached')
        # A deleted group must never share an ID/revision with its replacement.
        # Compare live IDs too, so an older application can be rolled back safely.
        c.execute('UPDATE rtrust_route_counter SET high_water=MAX(high_water,COALESCE((SELECT MAX(id) FROM rtrust_route_groups),0))+1 WHERE singleton=1')
        identifier=c.execute('SELECT high_water FROM rtrust_route_counter WHERE singleton=1').fetchone()[0]
        c.execute('INSERT INTO rtrust_route_groups(id,owner,name,policy,revision) VALUES(?,?,?,?,1)',(identifier,owner,name,json.dumps(policy)))
        audit(c,identity,'route_group_create',str(identifier))
        return JSONResponse(route_groups(c,owner,identifier)[0],headers=HEADERS)


@router.put('/portal/v2/route-groups/{identifier}')
async def update_route_group(identifier:int,request:Request):
    context=await run_in_threadpool(_update_route_group_prepare, request)
    payload=await body(request,['name','include','exclude','exclude_lan','revision'])
    return await run_in_threadpool(_update_route_group, identifier=identifier, request=request, payload=payload, context=context)

def _update_route_group_prepare(request:Request):
    owner,identity=browser(request,True);rate('routes:'+identity,60)
    return (owner, identity,)

def _update_route_group(identifier:int,request:Request, payload:dict, context:tuple):
    owner, identity=context
    data=payload
    name,policy=route_policy(data)
    if type(data.get('revision')) is not int:raise HTTPException(422,'Revision required')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=route_group(c,owner,identifier)
        if row['revision']!=data['revision']:raise HTTPException(409,'Route group revision changed')
        c.execute('UPDATE rtrust_route_groups SET name=?,policy=?,revision=? WHERE id=?',(name,json.dumps(policy),row['revision']+1,identifier))
        audit(c,identity,'route_group_update',str(identifier))
        return JSONResponse(route_groups(c,owner,identifier)[0],headers=HEADERS)


@router.delete('/portal/v2/route-groups/{identifier}')
def delete_route_group(identifier:int,request:Request):
    owner,identity=browser(request,True)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=route_group(c,owner,identifier)
        if request.headers.get('if-match')!=str(row['revision']):raise HTTPException(409,'Route group revision changed')
        c.execute('DELETE FROM rtrust_route_members WHERE grp=?',(identifier,))
        c.execute('DELETE FROM rtrust_route_groups WHERE id=?',(identifier,))
        audit(c,identity,'route_group_delete',str(identifier))
    return JSONResponse({'deleted':True},headers=HEADERS)

@router.post('/portal/v2/route-groups/{identifier}/members')
async def route_group_member(identifier:int,request:Request):
    context=await run_in_threadpool(_route_group_member_prepare, request)
    payload=await body(request,['device_id','member'])
    return await run_in_threadpool(_route_group_member, identifier=identifier, request=request, payload=payload, context=context)

def _route_group_member_prepare(request:Request):
    owner,identity=browser(request,True);rate('routes:'+identity,60)
    return (owner, identity,)

def _route_group_member(identifier:int,request:Request, payload:dict, context:tuple):
    owner, identity=context
    data=payload
    if type(data.get('device_id')) is not int or type(data.get('member')) is not bool:raise HTTPException(422,'Invalid membership')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        route_group(c,owner,identifier)
        if not c.execute('SELECT 1 FROM app_devices WHERE id=? AND user_id=? AND revoked_at IS NULL',(data['device_id'],owner)).fetchone():raise HTTPException(404,'Device not found')
        if data['member']:c.execute('INSERT INTO rtrust_route_members(device,grp) VALUES(?,?) ON CONFLICT(device) DO UPDATE SET grp=excluded.grp',(data['device_id'],identifier))
        else:c.execute('DELETE FROM rtrust_route_members WHERE device=? AND grp=?',(data['device_id'],identifier))
        audit(c,identity,'route_member_add' if data['member'] else 'route_member_remove',f'{identifier}:{data["device_id"]}')
        return JSONResponse(route_groups(c,owner,identifier)[0],headers=HEADERS)


@router.get('/portal/v2/routing')
def routing(request:Request):
    owner,_,device=actor(request)
    if device is None:raise HTTPException(403,'Device token required')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT g.* FROM rtrust_admin_route_members m JOIN rtrust_admin_route_groups g ON g.id=m.grp WHERE m.device=?',(device,)).fetchone()
        prefix='admin:'
        if row is None:
            row=c.execute('SELECT g.* FROM rtrust_route_members m JOIN rtrust_route_groups g ON g.id=m.grp WHERE m.device=? AND g.owner=?',(device,owner)).fetchone()
            prefix=''
        policy=None if row is None else {'group':row['name'],'revision':f'{prefix}{row["id"]}:{row["revision"]}',**json.loads(row['policy'])}
        c.execute('INSERT INTO rtrust_route_delivery(device,revision,requested) VALUES(?,?,?) ON CONFLICT(device) DO UPDATE SET revision=excluded.revision,requested=excluded.requested',(device,policy['revision'] if policy else None,int(time.time())))
    return JSONResponse({'policy':policy},headers=HEADERS)

# Administrative policy takes precedence over the user's group. Removing an
# administrative assignment restores the user's policy on the next client poll.
def admin_csrf(request):
    cookie=request.cookies.get(webauth.ADMIN_COOKIE,'')
    return hmac.new(config.SECRET_KEY.encode(),('rtrust-admin-routes:'+cookie).encode(),hashlib.sha256).hexdigest()

def route_admin(request, mutate=False):
    if request.headers.get('authorization') is not None:raise HTTPException(403,'Admin browser session required')
    admin=authenticated_admin(request)
    if mutate and not hmac.compare_digest(request.headers.get('x-csrf-token',''),admin_csrf(request)):
        raise HTTPException(403,'CSRF check failed')
    return 'admin:'+str(admin['id'])

def authenticated_admin(request):
    admin=webauth.current_admin(request)
    if admin is None:raise HTTPException(401,'Admin login required')
    return admin

@router.get('/admin/agent-routes',response_class=HTMLResponse)
def admin_routes_page(request:Request):
    if webauth.current_admin(request) is None:return RedirectResponse('/admin/login',302)
    return templates.TemplateResponse(request,'rtrust_admin_routes.html',{'brand':db.get_setting('brand_name'),'csrf':admin_csrf(request)},headers=HEADERS)

def admin_group(c, identifier):
    row=c.execute('SELECT * FROM rtrust_admin_route_groups WHERE id=?',(identifier,)).fetchone()
    if row is None:raise HTTPException(404,'Route group not found')
    return row

@router.get('/admin/api/agent-routes')
def admin_routes_state(request:Request):
    route_admin(request)
    with db.connect() as c:
        groups=[{'id':g['id'],'name':g['name'],'revision':g['revision'],**json.loads(g['policy'])} for g in c.execute('SELECT * FROM rtrust_admin_route_groups ORDER BY id')]
        devices=[dict(d) for d in c.execute("SELECT d.id,d.name,d.platform,u.email,u.status,d.revoked_at,m.grp AS group_id,t.revision AS fetched_revision,t.requested AS fetched_at,EXISTS(SELECT 1 FROM rtrust_tokens k WHERE k.device=d.id AND k.expires>?) AS token_active FROM app_devices d JOIN users u ON u.id=d.user_id LEFT JOIN rtrust_admin_route_members m ON m.device=d.id LEFT JOIN rtrust_route_delivery t ON t.device=d.id ORDER BY d.id DESC",(int(time.time()),))]
        users=[dict(u) for u in c.execute("SELECT id,email FROM users WHERE status='active' ORDER BY email")]
    return JSONResponse({'groups':groups,'devices':devices,'users':users},headers=HEADERS)

@router.post('/admin/api/agent-routes/enrollment-codes')
async def admin_routes_enroll(request:Request):
    context=await run_in_threadpool(_admin_routes_enroll_prepare, request)
    payload=await body(request,['user_id'])
    return await run_in_threadpool(_admin_routes_enroll, request=request, payload=payload, context=context)

def _admin_routes_enroll_prepare(request:Request):
    identity=route_admin(request,True);rate(identity)
    return (identity,)

def _admin_routes_enroll(request:Request, payload:dict, context:tuple):
    identity,=context
    data=payload
    if type(data.get('user_id')) is not int:raise HTTPException(422,'User required')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if not c.execute("SELECT 1 FROM users WHERE id=? AND status='active'",(data['user_id'],)).fetchone():raise HTTPException(404,'Active user not found')
        raw=secrets.token_urlsafe(24)
        c.execute("INSERT INTO enroll_codes(user_id,code_hash,expires_at) VALUES(?,?,datetime('now','+180 seconds'))",(data['user_id'],security.hash_api_token(raw)))
        audit(c,identity,'admin_route_enroll',str(data['user_id']))
    return JSONResponse({'code':raw,'expires_in':180},headers=HEADERS)


@router.post('/admin/api/agent-routes/groups')
async def admin_routes_create(request:Request):
    context=await run_in_threadpool(_admin_routes_create_prepare, request)
    payload=await body(request,['name','include','exclude','exclude_lan'])
    return await run_in_threadpool(_admin_routes_create, request=request, payload=payload, context=context)

def _admin_routes_create_prepare(request:Request):
    identity=route_admin(request,True);rate(identity,60)
    return (identity,)

def _admin_routes_create(request:Request, payload:dict, context:tuple):
    identity,=context
    name,policy=route_policy(payload)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT count(*) FROM rtrust_admin_route_groups').fetchone()[0]>=200:raise HTTPException(409,'Group limit reached')
        identifier=c.execute('INSERT INTO rtrust_admin_route_groups(name,policy,revision) VALUES(?,?,1)',(name,json.dumps(policy))).lastrowid
        audit(c,identity,'admin_route_create',str(identifier))
    return JSONResponse({'id':identifier},headers=HEADERS)


@router.put('/admin/api/agent-routes/groups/{identifier}')
async def admin_routes_update(identifier:int,request:Request):
    context=await run_in_threadpool(_admin_routes_update_prepare, request)
    payload=await body(request,['name','include','exclude','exclude_lan','revision'])
    return await run_in_threadpool(_admin_routes_update, identifier=identifier, request=request, payload=payload, context=context)

def _admin_routes_update_prepare(request:Request):
    identity=route_admin(request,True);rate(identity,60)
    return (identity,)

def _admin_routes_update(identifier:int,request:Request, payload:dict, context:tuple):
    identity,=context
    data=payload;name,policy=route_policy(data)
    if type(data.get('revision')) is not int:raise HTTPException(422,'Revision required')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE');row=admin_group(c,identifier)
        if row['revision']!=data['revision']:raise HTTPException(409,'Revision changed')
        c.execute('UPDATE rtrust_admin_route_groups SET name=?,policy=?,revision=revision+1 WHERE id=?',(name,json.dumps(policy),identifier))
        audit(c,identity,'admin_route_update',str(identifier))
    return JSONResponse({'updated':True},headers=HEADERS)


@router.delete('/admin/api/agent-routes/groups/{identifier}')
def admin_routes_delete(identifier:int,request:Request):
    identity=route_admin(request,True)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE');row=admin_group(c,identifier)
        if request.headers.get('if-match')!=str(row['revision']):raise HTTPException(409,'Revision changed')
        c.execute('DELETE FROM rtrust_admin_route_members WHERE grp=?',(identifier,))
        c.execute('DELETE FROM rtrust_admin_route_groups WHERE id=?',(identifier,))
        audit(c,identity,'admin_route_delete',str(identifier))
    return JSONResponse({'deleted':True},headers=HEADERS)

@router.put('/admin/api/agent-routes/devices/{identifier}')
async def admin_routes_assign(identifier:int,request:Request):
    context=await run_in_threadpool(_admin_routes_assign_prepare, request)
    payload=await body(request,['group_id','previous_group_id'])
    return await run_in_threadpool(_admin_routes_assign, identifier=identifier, request=request, payload=payload, context=context)

def _admin_routes_assign_prepare(request:Request):
    identity=route_admin(request,True);rate(identity,120)
    return (identity,)

def _admin_routes_assign(identifier:int,request:Request, payload:dict, context:tuple):
    identity,=context
    data=payload
    for key in ('group_id','previous_group_id'):
        if key not in data or (data[key] is not None and type(data[key]) is not int):raise HTTPException(422,'Group id or null required')
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        device=c.execute("SELECT d.* FROM app_devices d JOIN users u ON u.id=d.user_id WHERE d.id=? AND d.revoked_at IS NULL AND u.status='active' AND EXISTS(SELECT 1 FROM rtrust_tokens t WHERE t.device=d.id AND t.expires>?)",(identifier,int(time.time()))).fetchone()
        if device is None:raise HTTPException(404,'Active device not found')
        if device['platform'] not in ('windows','macos','linux'):raise HTTPException(422,'Desktop TUN only')
        previous=c.execute('SELECT grp FROM rtrust_admin_route_members WHERE device=?',(identifier,)).fetchone()
        if (previous['grp'] if previous else None)!=data['previous_group_id']:raise HTTPException(409,'Assignment changed')
        if data['group_id'] is None:c.execute('DELETE FROM rtrust_admin_route_members WHERE device=?',(identifier,))
        else:
            admin_group(c,data['group_id'])
            c.execute('INSERT INTO rtrust_admin_route_members(device,grp) VALUES(?,?) ON CONFLICT(device) DO UPDATE SET grp=excluded.grp',(identifier,data['group_id']))
        audit(c,identity,'admin_route_assign',f'{identifier}:{data["group_id"]}')
    return JSONResponse({'assigned':True},headers=HEADERS)



@router.get('/portal/v2/device-credentials')
def credential_list(request:Request):
    owner,_,device=actor(request)
    if device is not None:raise HTTPException(403,'Browser login required')
    with db.connect() as c:
        ids=[r[0] for r in c.execute('SELECT id FROM app_devices WHERE user_id=? ORDER BY id DESC LIMIT 200',(owner,))]
    return JSONResponse({'devices':[credentials.snapshot(owner,i) for i in ids]},headers=HEADERS)

@router.post('/portal/v2/devices/{identifier}/credentials/{action}')
def credential_change(identifier:int,action:str,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    if action not in ('provision','rotate'):raise HTTPException(404,'Operation not found')
    rate("credentials:"+identity,10)
    result=credentials.mutate(owner,identifier,action,request.headers.get('idempotency-key'),identity)
    return JSONResponse(result,headers=HEADERS)

@router.post('/portal/v2/devices/{identifier}/credentials-retry')
def credential_retry(identifier:int,request:Request):
    owner,identity,device=actor(request,True)
    if device is not None:raise HTTPException(403,'Browser login required')
    with db.connect() as c:credentials.device_row(c,owner,identifier)
    rate("credentials:"+identity,10)
    credentials.apply_pending()
    return JSONResponse(credentials.snapshot(owner,identifier),headers=HEADERS)

@router.post('/portal/v2/device-token/renew')
def renew_device_token(request:Request):
    owner,identity,device=actor(request,True)
    if device is None:raise HTTPException(403,'Device token required')
    rate('renew:'+identity,10)
    raw=secrets.token_urlsafe(32)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        credentials.device_row(c,owner,device,active=True)
        # Revalidate under the write lock: a concurrent renewal must not mint
        # another token after the old token has already been consumed.
        old=security.hash_api_token(request.headers['authorization'][7:])
        deleted=c.execute('DELETE FROM rtrust_tokens WHERE hash=? AND device=? AND expires>?',(old,device,int(time.time()))).rowcount
        if deleted!=1:raise HTTPException(401,'Device token expired or renewed')
        c.execute('INSERT INTO rtrust_tokens VALUES(?,?,?)',(security.hash_api_token(raw),device,int(time.time())+30*86400))
        audit(c,identity,'renew_token',str(device))
    return JSONResponse({'token':raw,'expires_in':30*86400},headers=HEADERS)


@router.post('/admin/api/device-credentials/{identifier}/revoke')
def admin_credential_revoke(identifier:int,request:Request):
    identity=route_admin(request,True)
    with credentials.endpoint.manager._lock:
        with db.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM app_devices WHERE id=?',(identifier,)).fetchone()
            if row is None:raise HTTPException(404,'Device not found')
            owner=row['user_id']
            credentials.revoke(c,owner,identifier)
            c.execute("UPDATE app_devices SET revoked_at=COALESCE(revoked_at,datetime('now')) WHERE id=?",(identifier,))
            for table in ('rtrust_tokens','rtrust_grants','rtrust_route_members','rtrust_admin_route_members','rtrust_route_delivery'):
                c.execute('DELETE FROM '+table+' WHERE device=?',(identifier,))
            audit(c,identity,'revoke_device',str(identifier))
        credentials.apply_pending()
    return JSONResponse(credentials.snapshot(owner,identifier),headers=HEADERS)

@router.post('/portal/v2/token/renew')
async def renew_token(request:Request):
    context=await run_in_threadpool(actor,request)
    data=await body(request,["consent"])
    return await run_in_threadpool(_renew_token,request,data,context)

def _renew_token(request,data,context):
    owner,identity,device=context
    if device is None:raise HTTPException(403,'Device token required')
    rate(identity)
    if data.get('consent') is not True:raise HTTPException(422,'Explicit renewal consent required')
    token=request.headers.get('authorization','')[7:]
    hashed=security.hash_api_token(token)
    with db.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        now=int(time.time())
        current=c.execute("SELECT t.device FROM rtrust_tokens t JOIN app_devices d ON d.id=t.device JOIN users u ON u.id=d.user_id WHERE t.hash=? AND t.device=? AND t.expires>? AND d.revoked_at IS NULL AND u.status='active' AND u.id=?",(hashed,device,now,owner)).fetchone()
        if current is None:raise HTTPException(401,'Device access expired or revoked')
        c.execute('UPDATE rtrust_tokens SET expires=? WHERE hash=?',(now+30*86400,hashed))
        audit(c,identity,'token_renew',str(device))
    return JSONResponse({'expires_in':30*86400,'scope':'portal_access_only'},headers=HEADERS)


def policy_for(c, owner, device):
    row=c.execute('SELECT g.* FROM rtrust_admin_route_members m JOIN rtrust_admin_route_groups g ON g.id=m.grp WHERE m.device=?',(device,)).fetchone()
    prefix='admin:'
    if row is None:
        row=c.execute('SELECT g.* FROM rtrust_route_members m JOIN rtrust_route_groups g ON g.id=m.grp WHERE m.device=? AND g.owner=?',(device,owner)).fetchone()
        prefix=''
    return None if row is None else {'group':row['name'],'revision':f'{prefix}{row["id"]}:{row["revision"]}',**json.loads(row['policy'])}


@router.post('/portal/v2/snapshot')
async def snapshot(request:Request):
    owner,identity,device=actor(request,True)
    if device is None:raise HTTPException(403,'Device token required')
    data=await body(request,['include_secrets','freshness_version'])
    if data.get('include_secrets') is not True:raise HTTPException(422,'Explicit secret export consent required')
    if 'freshness_version' in data and (type(data['freshness_version']) is not int or data['freshness_version']!=1):raise HTTPException(422,'Unsupported freshness contract')
    rate(identity,10)
    token=security.hash_api_token(request.headers['authorization'][7:])
    return await run_in_threadpool(device_snapshot, owner, device, token, data.get('freshness_version')==1)


def device_snapshot(owner, device, token, freshness=False):
    with db.connect() as c:
        # The token, grants, credentials, settings and policy share one SQLite
        # snapshot. A double read outside this transaction cannot detect ABA.
        c.execute('BEGIN')
        if not c.execute("SELECT 1 FROM rtrust_tokens t JOIN app_devices d ON d.id=t.device JOIN users u ON u.id=d.user_id WHERE t.hash=? AND t.device=? AND t.expires>? AND d.user_id=? AND d.revoked_at IS NULL AND u.status='active'",(token,device,int(time.time()),owner)).fetchone():
            raise HTTPException(401,'Device expired or revoked')
        settings=dict(c.execute('SELECT key,value FROM settings').fetchall())
        ids=client_profile_ids(c,owner,device)
        result=[];total=0;deadline=time.monotonic()+20
        for identifier in ids:
            if time.monotonic()>deadline:raise HTTPException(503,'Snapshot time limit reached')
            try:meta,document=accessible(c,owner,device,identifier,settings)
            except HTTPException as error:
                if error.status_code==404:continue
                raise
            total+=len(document.encode())
            if total>4*LIMIT:raise HTTPException(413,'Snapshot size limit exceeded')
            result.append({'metadata':meta,'content':document})
        value={'version':1,'profiles':result,'routing':{'policy':policy_for(c,owner,device)}}
        if freshness:
            try: max_age=int(os.environ.get('RTRUST_OFFLINE_MAX_AGE_SECONDS','86400'))
            except ValueError:raise HTTPException(503,'Invalid offline policy')
            if not 60<=max_age<=86400:raise HTTPException(503,'Invalid offline policy')
            current=c.execute('SELECT expires FROM rtrust_tokens WHERE hash=? AND device=?',(token,device)).fetchone()
            remaining=current['expires']-int(time.time()) if current else 0
            if remaining<=0:raise HTTPException(401,'Device expired or revoked')
            value['freshness']={'version':1,'max_age_seconds':max_age,'token_remaining_seconds':remaining}
        # Keyed revision avoids exposing a public password-derived fingerprint.
        encoded=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        value['revision']=hmac.new(config.SECRET_KEY.encode(),str(device).encode()+b'\0'+encoded,hashlib.sha256).hexdigest()
    if len(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode())>8*LIMIT:raise HTTPException(413,'Snapshot wire size limit exceeded')
    return JSONResponse(value,headers=HEADERS)
