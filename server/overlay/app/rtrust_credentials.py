"""Local TrustTunnel device credentials; durable desired state, serialized application.

Only the portal's single endpoint supervisor is supported. No remote endpoint or
external/shared profile is represented as revocable. A full restart disconnects
all sessions; other credentials remain unchanged.
"""
import json
import os
import secrets
import socket
import time
import uuid
from fastapi import HTTPException
from . import db, endpoint

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rtrust_credentials(
 device INTEGER PRIMARY KEY REFERENCES app_devices(id) ON DELETE CASCADE,
 config INTEGER UNIQUE REFERENCES configs(id) ON DELETE SET NULL,
 generation INTEGER NOT NULL, legacy_shared INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS rtrust_credential_operations(
 id TEXT PRIMARY KEY, device INTEGER NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,
 owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 action TEXT NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL,
 requested INTEGER NOT NULL, applied INTEGER, error TEXT);
CREATE INDEX IF NOT EXISTS rtrust_credential_operations_device
 ON rtrust_credential_operations(device,requested);
'''


def enabled():
    return os.environ.get('RTRUST_MANAGED_CREDENTIALS') == '1'


def capabilities():
    return {'version': 1, 'enabled': enabled(), 'endpoint': 'local_trusttunnel',
            'protocols': ['http2', 'http3'] if enabled() else [],
            'active_sessions': 'restart_all', 'application_observation_seconds': 2,
            'retry_interval_seconds': 5, 'healthy_apply_target_seconds': 15, 'propagation_sla': 'pending_until_applied',
            'offline': 'cached_credentials_until_endpoint_revocation',
            'legacy_shared': 'unmanaged', 'external': 'unmanaged'}


def init():
    with db.connect() as c:
        c.executescript(SCHEMA)


def device_row(c, owner, device, active=False):
    row = c.execute('SELECT d.*,u.status FROM app_devices d JOIN users u ON u.id=d.user_id WHERE d.id=? AND d.user_id=?', (device, owner)).fetchone()
    if row is None:
        raise HTTPException(404, 'Device not found')
    if active and (row['revoked_at'] is not None or row['status'] != 'active'):
        raise HTTPException(409, 'Device inactive')
    return row


def active_credentials():
    # Defense in depth: v1 revocation, user blocking and retained configs cannot
    # put a revoked device back in the generated endpoint file.
    with db.connect() as c:
        rows = c.execute('''SELECT c.tt_username AS username,c.tt_password AS password
          FROM configs c JOIN users u ON u.id=c.user_id
          LEFT JOIN app_devices d ON d.id=c.device_id
          WHERE c.revoked_at IS NULL AND u.status='active'
          AND (c.device_id IS NULL OR (d.revoked_at IS NULL AND d.user_id=c.user_id))
          ORDER BY c.id''').fetchall()
    return [dict(r) for r in rows]


def apply_pending():
    """Retry is an unconditional restart, including after file-write/start failure.

    BEGIN IMMEDIATE fences credential mutations while the supervisor reads the
    committed desired state. Lock ordering is always supervisor -> SQLite.
    The manager is single-process by deployment contract.
    """
    with endpoint.manager._lock:
        with db.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            pending = c.execute("SELECT id FROM rtrust_credential_operations WHERE state IN ('requested','pending','failed') AND COALESCE(error,'') NOT LIKE 'superseded%'").fetchall()
            if not pending:
                return
            ids = [r['id'] for r in pending]
            c.executemany("UPDATE rtrust_credential_operations SET state='pending',error=NULL WHERE id=?", [(i,) for i in ids])
        state, error = 'failed', 'endpoint_unavailable'
        attempt_started=time.monotonic()
        try:
            with db.connect() as fence:
                fence.execute('BEGIN IMMEDIATE')
                # Reconcile writes the full committed credentials set. Killing
                # first also removes sessions when a previous attempt wrote the
                # file but never restarted the old process.
                old = endpoint.manager._proc
                endpoint.manager._kill()
                if old is not None:
                    old.wait(timeout=1)
                settings=db.get_settings()
                domain=endpoint.effective_domain(settings)
                if not domain or not endpoint.cert_present(domain):
                    raise RuntimeError('Endpoint TLS configuration unavailable')
                issue=endpoint.ensure_letsencrypt
                def no_issue(*args):
                    raise RuntimeError('Certificate issuance unavailable during credential application')
                endpoint.ensure_letsencrypt=no_issue
                try:
                    endpoint.manager.reconcile()
                finally:
                    endpoint.ensure_letsencrypt=issue
                deadline=attempt_started+15
                ready_since=None
                while endpoint.manager._is_running() and time.monotonic()<deadline:
                    now=time.monotonic()
                    if listener_ready(int(settings.get('conn_port') or '8443')):
                        if ready_since is None:ready_since=now
                        if now-ready_since>=2:
                            state,error='applied',None
                            break
                    else:ready_since=None
                    time.sleep(.05)
                fence.executemany('UPDATE rtrust_credential_operations SET state=?,error=?,applied=? WHERE id=?',
                                  [(state, error, int(time.time()) if state == 'applied' else None, i) for i in ids])
        except Exception:
            # Never persist/log exception text: endpoint errors can contain secrets.
            with db.connect() as c:
                c.executemany("UPDATE rtrust_credential_operations SET state='failed',error='endpoint_unavailable',applied=NULL WHERE id=?", [(i,) for i in ids])


def operation(c, owner, device, action, generation, key, identity=None):
    c.execute("INSERT INTO rtrust_credential_operations VALUES(?,?,?,?,?,'requested',?,NULL,NULL)",
              (key, device, owner, action, generation, int(time.time())))
    from .rtrust_profiles import audit
    audit(c, identity or 'system:credential-reconcile', 'credential_' + action, key)


def snapshot(owner, device):
    with db.connect() as c:
        row = device_row(c, owner, device)
        binding = c.execute('SELECT * FROM rtrust_credentials WHERE device=?', (device,)).fetchone()
        operations = [dict(r) for r in c.execute('SELECT id,action,generation,state,requested,applied,error FROM rtrust_credential_operations WHERE device=? ORDER BY rowid DESC LIMIT 20', (device,))]
        # Shared profiles granted to this device remain usable independently.
        shared = c.execute("SELECT count(*) FROM rtrust_grants g JOIN configs c ON g.profile='managed-'||c.id WHERE g.device=? AND c.device_id IS NULL AND c.revoked_at IS NULL", (device,)).fetchone()[0]
    return {'device_id': device, 'revoked': row['revoked_at'] is not None,
            'profile_id': 'managed-' + str(binding['config']) if binding and binding['config'] else None,
            'generation': binding['generation'] if binding else None,
            'management': 'device_credentials' if binding else 'unmanaged',
            'shared_credentials_unmanaged': shared > 0 or bool(binding and binding['legacy_shared']), 'operations': operations}


def mutate(owner, device, action, key, identity=None):
    if not enabled():
        raise HTTPException(409, 'Managed credentials disabled')
    try:
        if str(uuid.UUID(key)) != key: raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(422, 'Idempotency-Key must be a canonical UUID')
    with endpoint.manager._lock:
        with db.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            device_row(c, owner, device)
            previous = c.execute('SELECT * FROM rtrust_credential_operations WHERE id=?', (key,)).fetchone()
            if previous:
                if (previous['owner'], previous['device'], previous['action']) != (owner, device, action):
                    raise HTTPException(409, 'Idempotency key conflict')
            else:
                row = device_row(c, owner, device, active=True)
                binding = c.execute('SELECT * FROM rtrust_credentials WHERE device=?', (device,)).fetchone()
                if action == 'provision' and binding:
                    raise HTTPException(409, 'Device already managed; rotate explicitly')
                if action == 'rotate' and (not binding or not binding['config']):
                    raise HTTPException(409, 'Device has no managed credential')
                generation = binding['generation'] + 1 if binding else 1
                if binding:
                    cfg = c.execute('SELECT * FROM configs WHERE id=? AND device_id=? AND user_id=? AND revoked_at IS NULL', (binding['config'], device, owner)).fetchone()
                    if cfg is None: raise HTTPException(409, 'Credential removed; revoke device')
                    c.execute('UPDATE configs SET tt_password=? WHERE id=?', (secrets.token_urlsafe(32), cfg['id']))
                    c.execute('UPDATE rtrust_credentials SET generation=? WHERE device=?', (generation, device))
                else:
                    # Migrate v1 device-owned credentials only. Never touch a
                    # legacy/shared config: neighboring devices keep access.
                    c.execute("UPDATE configs SET revoked_at=datetime('now') WHERE device_id=? AND user_id=? AND revoked_at IS NULL", (device, owner))
                    cfg_id = c.execute('INSERT INTO configs(user_id,device_id,tt_username,tt_password,label) VALUES(?,?,?,?,?)',
                                       (owner, device, 'd' + str(device) + '-' + secrets.token_hex(12), secrets.token_urlsafe(32), row['name'])).lastrowid
                    c.execute('INSERT INTO rtrust_credentials(device,config,generation,legacy_shared) VALUES(?,?,?,?)', (device, cfg_id, generation, int(c.execute("SELECT EXISTS(SELECT 1 FROM rtrust_grants g JOIN configs c ON g.profile='managed-'||c.id WHERE g.device=? AND c.device_id IS NULL AND c.revoked_at IS NULL)",(device,)).fetchone()[0])))
                    c.execute('INSERT OR IGNORE INTO rtrust_grants VALUES(?,?)', ('managed-' + str(cfg_id), device))
                c.execute("UPDATE rtrust_credential_operations SET state='failed',error='superseded_by_rotation' WHERE device=? AND state IN ('requested','pending','failed') AND action!='revoke'", (device,))
                operation(c, owner, device, action, generation, key, identity)
        apply_pending()
    return snapshot(owner, device)


def revoke(c, owner, device):
    """Called inside the portal revocation transaction; no endpoint I/O here."""
    binding = c.execute('SELECT * FROM rtrust_credentials WHERE device=?', (device,)).fetchone()
    owned = c.execute('SELECT 1 FROM configs WHERE device_id=? AND user_id=? AND revoked_at IS NULL', (device, owner)).fetchone()
    c.execute("UPDATE configs SET revoked_at=datetime('now') WHERE device_id=? AND user_id=? AND revoked_at IS NULL", (device, owner))
    if binding or owned:
        # Earlier un-applied provision/rotation is superseded, never reported as
        # applied after revocation removed its credential.
        c.execute("UPDATE rtrust_credential_operations SET state='failed',error='superseded_by_revoke' WHERE device=? AND state IN ('requested','pending','failed') AND action!='revoke'", (device,))
        if not c.execute("SELECT 1 FROM rtrust_credential_operations WHERE device=? AND action='revoke'", (device,)).fetchone():
            operation(c, owner, device, 'revoke', binding['generation'] if binding else 0, str(uuid.uuid4()))


def install():
    db.active_credentials = active_credentials
    endpoint.write_credentials_toml = write_credentials
    db.revoke_device = revoke_legacy
    if not getattr(endpoint.manager, '_rtrust_credentials_installed', False):
        original = endpoint.manager.reconcile
        def reconcile(restart_for_creds=False):
            return original(restart_for_creds=True)
        endpoint.manager.reconcile = reconcile
        endpoint.manager._rtrust_credentials_installed = True


def write_credentials(creds):
    """Secret file is mode 0600 and replaced atomically; escape legacy strings."""
    import tempfile
    from pathlib import Path
    path = Path(endpoint.config.ENDPOINT_WORKDIR) / 'credentials.toml'
    content = '\n'.join('[[client]]\nusername = ' + json.dumps(c['username'],ensure_ascii=False) + '\npassword = ' + json.dumps(c['password'],ensure_ascii=False) + '\n' for c in creds)
    try:
        if path.read_text(encoding='utf-8') == content:
            path.chmod(0o600)
            return False
    except FileNotFoundError:
        pass
    fd, name = tempfile.mkstemp(prefix='.credentials-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)
    return True



def revoke_legacy(device):
    with endpoint.manager._lock:
        with db.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM app_devices WHERE id=?',(device,)).fetchone()
            if row is None:return 0
            count=c.execute('SELECT count(*) FROM configs WHERE device_id=? AND revoked_at IS NULL',(device,)).fetchone()[0]
            revoke(c,row['user_id'],device)
            c.execute("UPDATE app_devices SET revoked_at=COALESCE(revoked_at,datetime('now')) WHERE id=?",(device,))
            for table in ('rtrust_tokens','rtrust_grants','rtrust_route_members','rtrust_admin_route_members','rtrust_route_delivery'):
                c.execute('DELETE FROM '+table+' WHERE device=?',(device,))
        apply_pending()
    return count



def listener_ready(port):
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=.2):
            return True
    except OSError:
        return False
