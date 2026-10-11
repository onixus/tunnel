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

if not Path('/.dockerenv').exists():
    raise SystemExit('Run only in a disposable Docker container with --network none')

os.environ['RTRUST_DEVICE_CREDENTIALS'] = '1'
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
        check_neighbor()
        response=test.client.delete('/portal/v2/devices/'+str(device),headers=test.headers)
        assert response.status_code==200
        revoked=apply()
        assert all(check['outcome']=='rejected' for check in revoked['receipt']['checks'])
        check_neighbor()
        assert test.client.get('/portal/v2/profiles',headers=auth).status_code==401
        print(json.dumps({'schema':1,'result':'passed','scope':'isolated_real_endpoint_credentials',
                          'protocols':['http2','http3'],'generations':[issued['generation'],rotated['generation'],revoked['generation']],
                          'neighbor_reconnect':'passed','shared_credentials':'unmanaged','physical_acceptance':False}))
    finally:
        endpoint.manager.stop()
        test.client.close()
