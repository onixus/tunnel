#!/usr/bin/env python3
"""Real endpoint lifecycle, only in a disposable container with no host network.

Requires RTRUST_ENDPOINT_CHECK, RTRUST_CODEC and ENDPOINT_BIN. Synthetic keys,
SQLite and certificates are temporary; no production portal or TUN is touched.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import base64

if not Path('/.dockerenv').exists():
    raise SystemExit('Run only in a disposable Docker container with --network none')

os.environ['RTRUST_DEVICE_CREDENTIALS'] = '1'
if len(sys.argv)==5 and sys.argv[1]=='--restart-fixture':
    # Fresh interpreter: no inherited active_credentials wrapper or supervisor.
    source=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(source/'upstream'))
    import app
    app.__path__.append(str(source/'overlay/app'))
    os.chdir(source/'upstream')
    from app import db, main, rtrust_profiles as exchange, device_credentials as credentials
    from fastapi.testclient import TestClient
    exchange.install(main.app)
    retired_payload=base64.b64decode(sys.stdin.buffer.read(4096),validate=True)
    with TestClient(main.app):
        with db.connect() as c:
            neighbor=c.execute('SELECT * FROM rtrust_device_credentials WHERE device=? AND profile=?',(int(sys.argv[2]),int(sys.argv[4]))).fetchone()
            revoked=c.execute('SELECT * FROM rtrust_device_credentials WHERE device=? AND profile=?',(int(sys.argv[3]),int(sys.argv[4]))).fetchone()
        assert neighbor['state']=='applied' and revoked['state']=='applied'
        for protocol in ('http2','http3'):
            assert credentials.probe(neighbor,neighbor['payload'],protocol)['outcome']=='authenticated', 'Persisted neighbor unavailable after startup'
            assert credentials.probe(revoked,retired_payload,protocol)['outcome']=='rejected', 'Revoked credentials restored after startup'
    print('PASS fresh process startup: persisted neighbor accepted and retired device rejected on H2/H3')
    raise SystemExit(0)
import test_exchange as fixture
from app import config, db, endpoint, device_credentials as credentials

test = fixture.ExchangeTests('runTest')
test.setUp()
with tempfile.TemporaryDirectory(prefix='rtrust-endpoint-credentials-') as directory:
    root=Path(directory)
    config.ENDPOINT_WORKDIR=str(root)
    config.CERT_DIR=str(root/'certificates')
    cert=root/'certificates/live/localhost'; cert.mkdir(parents=True)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                    '-keyout',str(cert/'privkey.pem'),'-out',str(cert/'fullchain.pem'),
                    '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                    '-addext','basicConstraints=critical,CA:FALSE'],
                   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    with db.connect() as c:
        c.execute("UPDATE settings SET value='localhost' WHERE key='panel_domain'")
        c.execute("UPDATE settings SET value='8443' WHERE key='conn_port'")
        profile=c.execute('INSERT INTO configs(user_id,tt_username,tt_password,label) VALUES(?,?,?,?)',
                          (test.owner,'independent','synthetic-independent-password','Fixture')).lastrowid
    device,auth=test.enrolled()
    name='managed-'+str(profile)
    def post(path,body):
        response=test.post(path,body)
        assert response.status_code==200, (path,response.status_code)
        return response.json()
    def apply(selected=device):
        value=post('devices/'+str(selected)+'/credentials/reconcile',{'consent_restart_endpoint':True})
        record=value['profiles'][0]
        assert record['state']=='applied', json.dumps(record)
        assert {check['protocol'] for check in record['receipt']['checks']}=={'http2','http3'}
        return record
    try:
        assert credentials.enabled(), 'Verifier unavailable'
        post('profiles/'+name+'/grants',{'device_id':device,'allow':True})
        issued=apply()
        neighbor,_=test.enrolled('neighbor')
        post('profiles/'+name+'/grants',{'device_id':neighbor,'allow':True})
        apply(neighbor)
        def check_neighbor():
            with db.connect() as c:
                row=c.execute('SELECT * FROM rtrust_device_credentials WHERE device=? AND profile=?',(neighbor,profile)).fetchone()
            assert all(credentials.probe(row,row['payload'],protocol)['outcome']=='authenticated' for protocol in ('http2','http3'))
        post('profiles/'+name+'/device-credentials',{'device_id':device,'expected_generation':1,
             'request_key':'real-endpoint-rotation-fixture','consent':True})
        rotated=apply()
        assert len(rotated['receipt']['checks'])==4
        with db.connect() as c:
            retired_payload=c.execute('SELECT payload FROM rtrust_device_credentials WHERE device=? AND profile=?',(device,profile)).fetchone()['payload']
        check_neighbor()
        response=test.client.delete('/portal/v2/devices/'+str(device),headers=test.headers)
        assert response.status_code==200
        revoked=apply()
        assert all(check['outcome']=='rejected' for check in revoked['receipt']['checks'])
        check_neighbor()
        assert test.client.get('/portal/v2/profiles',headers=auth).status_code==401
        endpoint.manager.stop()
        environment=dict(os.environ,DATA_DIR=str(config.DATA_DIR),DB_PATH=str(config.DB_PATH),
                         ENDPOINT_WORKDIR=config.ENDPOINT_WORKDIR,CERT_DIR=config.CERT_DIR)
        subprocess.run([sys.executable,str(Path(__file__).resolve()),'--restart-fixture',str(neighbor),str(device),str(profile)],
                       input=base64.b64encode(retired_payload),env=environment,check=True,timeout=60)
        print(json.dumps({'schema':1,'result':'passed','scope':'isolated_real_endpoint_credentials',
                          'protocols':['http2','http3'],'generations':[issued['generation'],rotated['generation'],revoked['generation']],
                          'neighbor_reconnect':'passed','fresh_process_restart':'passed','shared_credentials':'unmanaged','physical_acceptance':False}))
    finally:
        endpoint.manager.stop()
        test.client.close()
