"""Opt-in per-device TrustTunnel credentials and verified endpoint propagation.

A single portal supervisor owns the endpoint. Applying credentials restarts that
endpoint (all its sessions); other devices keep their own valid credentials.
No applied receipt is issued from a DB write, file hash, or process liveness.
"""
import fcntl
import hashlib
import json
import os
import secrets
import stat
import subprocess
import time
from pathlib import Path
from fastapi import HTTPException
from . import config, db

CHECKER = os.environ.get('RTRUST_ENDPOINT_CHECK', '/usr/local/bin/rtrust-endpoint-check')
SCHEMA = '''
CREATE TABLE IF NOT EXISTS rtrust_device_credentials(
 device INTEGER NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE, profile INTEGER NOT NULL REFERENCES configs(id) ON DELETE CASCADE,
 owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, generation INTEGER NOT NULL,
 payload BLOB, previous BLOB, desired TEXT NOT NULL CHECK(desired IN ('active','revoked')),
 state TEXT NOT NULL CHECK(state IN ('requested','pending','applied','failed')),
 legacy_shared INTEGER NOT NULL, receipt TEXT, PRIMARY KEY(device,profile));
CREATE TABLE IF NOT EXISTS rtrust_credential_operations(
 owner INTEGER NOT NULL, key TEXT NOT NULL, device INTEGER NOT NULL, profile INTEGER NOT NULL,
 base_generation INTEGER NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL,
 PRIMARY KEY(owner,key));
'''

def enabled():
    from . import endpoint
    try: info=Path(CHECKER).stat()
    except OSError:return False
    return os.environ.get('RTRUST_DEVICE_CREDENTIALS') == '1' and os.access(CHECKER, os.X_OK) and stat.S_ISREG(info.st_mode) and info.st_mode & 0o022 == 0 and info.st_uid in (0,os.geteuid()) and hasattr(endpoint.manager,'apply_device_credentials')

def init():
    with db.connect() as c: c.executescript(SCHEMA)
    # The original configs stay independent. Never remove shared/imported
    # credentials merely because a device now receives an individual one.
    if not getattr(db.active_credentials, '_rtrust_devices', False):
        original = db.active_credentials
        def credentials():
            result = original()
            from .rtrust_profiles import unseal
            with db.connect() as c:
                rows=c.execute("SELECT x.* FROM rtrust_device_credentials x JOIN app_devices d ON d.id=x.device JOIN users u ON u.id=x.owner JOIN configs p ON p.id=x.profile WHERE x.desired='active' AND d.revoked_at IS NULL AND p.revoked_at IS NULL AND u.status='active'").fetchall()
            for row in rows: result.append(unseal(row['owner'],row['payload']))
            return result
        credentials._rtrust_devices = True
        db.active_credentials = credentials

def number(identifier):
    if not identifier.startswith('managed-'): raise HTTPException(422,'External profiles are unmanaged')
    try: result=int(identifier[8:])
    except ValueError: raise HTTPException(422,'Invalid managed profile')
    if result<1: raise HTTPException(422,'Invalid managed profile')
    return result

def request(c, owner, device, profile, *, revoke=False, expected=None, key=None):
    from .rtrust_profiles import seal
    row=c.execute('SELECT * FROM rtrust_device_credentials WHERE device=? AND profile=? AND owner=?',(device,profile,owner)).fetchone()
    if key is not None:
        operation=c.execute('SELECT * FROM rtrust_credential_operations WHERE owner=? AND key=?',(owner,key)).fetchone()
        if operation:
            if (operation['device'],operation['profile'],operation['base_generation']) != (device,profile,expected):
                raise HTTPException(409,'Idempotency key belongs to another operation')
            return operation['generation']
    if expected is not None and (row is None or row['generation']!=expected): raise HTTPException(409,'Credential generation changed')
    if revoke and row is None: return None
    if revoke and expected is None and row["desired"] == "revoked": return row["generation"]
    if not revoke and expected is None and row is not None and row['desired']=='active': return row['generation']
    generation=1 if row is None else row['generation']+1
    if generation>=2**63: raise HTTPException(409,'Credential generation exhausted')
    legacy = int(c.execute('SELECT 1 FROM rtrust_grants WHERE device=? AND profile=?',(device,'managed-'+str(profile))).fetchone() is not None) if row is None else row['legacy_shared']
    # Preserve the last actually issued credentials across rapid pending rotates;
    # intermediate, never-applied credentials were never exportable.
    previous=None if row is None else row['payload'] if row['state']=='applied' else row['previous']
    if revoke and previous is None: previous=row['payload']
    payload=None if revoke else seal(owner,{'username':'rtrust-device-'+secrets.token_hex(16),'password':secrets.token_urlsafe(32)})
    c.execute("INSERT INTO rtrust_device_credentials VALUES(?,?,?,?,?,?,?,?,?,NULL) ON CONFLICT(device,profile) DO UPDATE SET generation=excluded.generation,payload=excluded.payload,previous=excluded.previous,desired=excluded.desired,state=excluded.state,receipt=NULL",(device,profile,owner,generation,payload,previous,'revoked' if revoke else 'active','requested',legacy))
    # Pending operations superseded before application cannot later claim pass.
    c.execute("UPDATE rtrust_credential_operations SET state='failed' WHERE device=? AND profile=? AND state IN ('requested','pending')",(device,profile))
    if key is not None: c.execute('INSERT INTO rtrust_credential_operations VALUES(?,?,?,?,?,?,?)',(owner,key,device,profile,expected,generation,'requested'))
    return generation

def revoke_device(c, owner, device):
    rows=c.execute('SELECT profile FROM rtrust_device_credentials WHERE device=? AND owner=?',(device,owner)).fetchall()
    for row in rows: request(c,owner,device,row['profile'],revoke=True)
    return bool(rows)

def status(owner, device):
    with db.connect() as c:
        if not c.execute('SELECT 1 FROM app_devices WHERE id=? AND user_id=?',(device,owner)).fetchone(): raise HTTPException(404,'Device not found')
        rows=c.execute('SELECT profile,generation,desired,state,legacy_shared,receipt FROM rtrust_device_credentials WHERE owner=? AND device=? ORDER BY profile',(owner,device)).fetchall()
    return {'schema':1,'session_policy':'restart_all_endpoint_sessions','profiles':[{
        'id':'managed-'+str(row['profile']), 'generation':row['generation'], 'desired':row['desired'], 'state':row['state'],
        'legacy_shared_access':'unmanaged' if row['legacy_shared'] else 'not_issued_by_this_flow',
        'receipt':json.loads(row['receipt']) if row['receipt'] else None,
    } for row in rows]}

def exported(c, owner, device, profile, cfg):
    from .rtrust_profiles import unseal
    row=c.execute('SELECT * FROM rtrust_device_credentials WHERE owner=? AND device=? AND profile=?',(owner,device,profile)).fetchone()
    if row is None:
        if enabled(): raise HTTPException(409,'Reissue the managed grant for individual device access')
        return cfg, 'portal_managed'
    if row['desired']!='active' or row['state']!='applied': raise HTTPException(503,'Managed credential propagation not confirmed')
    credentials=unseal(owner,row['payload']); value=dict(cfg)
    value.update(tt_username=credentials['username'],tt_password=credentials['password'])
    return value,'device_managed'

def probe(row, payload, protocol, *, deadline=None):
    from .rtrust_profiles import unseal, managed_document
    from . import endpoint
    credentials=unseal(row['owner'],payload)
    with db.connect() as c:
        cfg=c.execute('SELECT * FROM configs WHERE id=? AND user_id=?',(row['profile'],row['owner'])).fetchone()
    if cfg is None: return {'protocol':protocol,'outcome':'unavailable','elapsed_ms':None}
    cfg=dict(cfg); cfg.update(tt_username=credentials['username'],tt_password=credentials['password'])
    settings=db.get_settings(); document=json.loads(managed_document(cfg,settings)['content'])
    port=int(settings.get('conn_port') or '8443')
    # No caller-selected URL/address or remote management path. Preserve SNI and
    # trust this endpoint's configured certificate; do not disable TLS checks.
    document['endpoint']['addresses']=['127.0.0.1:'+str(port)]
    document['endpoint']['upstream_protocol']=protocol
    domain=endpoint.effective_domain(settings)
    certificate,_=endpoint.cert_paths(domain)
    document['endpoint']['certificate']=certificate.read_text()
    remaining=12 if deadline is None else min(12,deadline-time.monotonic())
    if remaining<=0: return {'protocol':protocol,'outcome':'unavailable','elapsed_ms':None}
    completed=subprocess.run([CHECKER],input=json.dumps(document).encode(),capture_output=True,timeout=remaining)
    if completed.returncode or len(completed.stdout)>4096: return {'protocol':protocol,'outcome':'unavailable','elapsed_ms':None}
    value=json.loads(completed.stdout)
    if value.get('schema')!=1 or value.get('scope')!='loopback_endpoint_authenticated_check' or value.get('outcome') not in ('authenticated','rejected','unavailable'):
        return {'protocol':protocol,'outcome':'unavailable','elapsed_ms':None}
    return {'protocol':protocol,'outcome':value['outcome'],'elapsed_ms':value.get('elapsed_ms')}

def reconcile(owner, device):
    if not enabled(): raise HTTPException(503,'Managed endpoint verifier is not configured')
    path=Path(config.DATA_DIR)/'.rtrust-device-credential-lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_nlink!=1:
            raise HTTPException(503,'Unsafe credential writer lock')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise HTTPException(409,'Endpoint credential writer is busy')
        with db.connect() as c:
            rows=c.execute("SELECT * FROM rtrust_device_credentials WHERE owner=? AND device=? AND state!='applied' ORDER BY profile LIMIT 4",(owner,device)).fetchall()
            for row in rows:
                c.execute("UPDATE rtrust_device_credentials SET state='pending' WHERE device=? AND profile=? AND generation=?",(device,row['profile'],row['generation']))
                c.execute("UPDATE rtrust_credential_operations SET state='pending' WHERE device=? AND profile=? AND generation=?",(device,row['profile'],row['generation']))
        if not rows: return status(owner,device)
        from . import endpoint
        try:
            # This uses the existing single owned process. Unlike SIGHUP, its
            # credential restart also terminates the old authenticated sessions.
            process_generation=endpoint.manager.apply_device_credentials()
            def checker_hash():
                digest=hashlib.sha256()
                with open(CHECKER,'rb') as stream:
                    for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
                return digest.hexdigest()
            verifier_sha256=checker_hash()
            deadline=time.monotonic()+25
            for row in rows:
                checks=[]
                # Both listeners share credentials. A single protocol pass must
                # not hide another still accepting the retired password.
                for protocol in ('http2','http3'):
                    if row['desired']=='active': checks.append(probe(row,row['payload'],protocol,deadline=deadline))
                    if row['previous'] is not None: checks.append(probe(row,row['previous'],protocol,deadline=deadline))
                expected=['authenticated' if row['desired']=='active' else None, 'rejected' if row['previous'] is not None else None]
                expected=[kind for _ in ('http2','http3') for kind in expected if kind is not None]
                passed=bool(checks) and [check['outcome'] for check in checks]==expected and endpoint.manager.credential_generation()==process_generation and checker_hash()==verifier_sha256
                receipt={'checked_at':int(time.time()),'generation':row['generation'],'verifier_sha256':verifier_sha256,'endpoint_generation':process_generation,'checks':checks,'scope':'managed_credentials_only_legacy_shared_access_unmanaged'}
                state='applied' if passed else 'failed'
                with db.connect() as c:
                    changed=c.execute('UPDATE rtrust_device_credentials SET state=?,receipt=?,previous=CASE WHEN ? THEN NULL ELSE previous END WHERE device=? AND profile=? AND generation=?',(state,json.dumps(receipt),passed,row['device'],row['profile'],row['generation'])).rowcount
                    if changed:c.execute('UPDATE rtrust_credential_operations SET state=? WHERE device=? AND profile=? AND generation=?',(state,row['device'],row['profile'],row['generation']))
        except Exception:
            with db.connect() as c:
                for row in rows:c.execute("UPDATE rtrust_device_credentials SET state='failed' WHERE device=? AND profile=? AND generation=? AND state='pending'",(row['device'],row['profile'],row['generation']))
            raise HTTPException(503,'Endpoint propagation could not be verified')
        return status(owner,device)
    finally: os.close(fd)
