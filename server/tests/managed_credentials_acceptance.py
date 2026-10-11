"""Real HTTP/2 + HTTP/3 revocation, isolated Docker endpoint, synthetic accounts.

Usage: RTRUST_CODEC=... python managed_credentials_acceptance.py ENDPOINT INSPECT
Only disposable test containers/files are changed. No production API is used.
The Docker process adapter replaces only process spawning; desired state and API
operations use the actual portal implementation and SQLite.
"""
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid
from unittest.mock import patch
from test_exchange import ExchangeTests, SANDBOX
from app import config, db, endpoint

binary=Path(sys.argv[1]).resolve()
inspect=Path(sys.argv[2]).resolve()
# Image acquisition is fixture setup, not endpoint application latency. A cold
# runner must not spend the two-second readiness window downloading an image.
if subprocess.run(['docker','image','inspect','debian:12-slim'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
    subprocess.run(['docker','pull','debian:12-slim'],check=True,timeout=180,stdout=subprocess.DEVNULL)
name='tunnel-credentials-test-'+uuid.uuid4().hex[:12]
work=Path(SANDBOX.name)
runtime=work/'runtime';runtime.mkdir()
certs=work/'certs/live/localhost';certs.mkdir(parents=True)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(certs/'privkey.pem'),'-out',str(certs/'fullchain.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
with socket.socket() as reserve:
    reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(b'OK')
    def log_message(self,*args):pass

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            while data:=self.request.recv(4096):self.request.sendall(data)
        except (OSError,TimeoutError):pass

http=http.server.ThreadingHTTPServer(('0.0.0.0',0),HTTP)
echo=socketserver.ThreadingTCPServer(('0.0.0.0',0),Echo);echo.daemon_threads=True
for server in (http,echo):threading.Thread(target=server.serve_forever,daemon=True).start()


def kill():
    subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    if endpoint.manager._proc is not None:
        endpoint.manager._proc.wait(timeout=10)
    endpoint.manager._proc=None


def spawn():
    endpoint.manager._proc=subprocess.Popen(['docker','run','--rm','--name',name,'--read-only',
        *(['--add-host','host.docker.internal:host-gateway'] if sys.platform=='linux' else []),
        '-p',f'127.0.0.1:{port}:{port}/tcp','-p',f'127.0.0.1:{port}:{port}/udp',
        '-v',f'{work}:{work}:ro','-v',f'{binary}:/fixture/endpoint:ro',
        '-w',str(runtime),'debian:12-slim','/fixture/endpoint','vpn.toml','hosts.toml','--jobs','2'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def profile(device, protocol):
    cfg=db.get_device_config(device)
    identifier='managed-'+str(cfg['id'])
    items=case.client.get('/portal/v2/profiles').json()['profiles']
    meta=next(item for item in items if item['id']==identifier)
    exported=case.post('profiles/'+identifier+'/export',{'format':'profile_json','revision':meta['revision'],'include_secrets':True})
    assert exported.status_code==200,exported.text
    result=json.loads(exported.json()['content'])
    assert result['endpoint']['certificate']==(certs/'fullchain.pem').read_text()
    result['endpoint']['upstream_protocol']=protocol
    return result


def probe(data, success=True):
    path=work/'probe.json';path.write_text(json.dumps(data));path.chmod(0o600)
    result=subprocess.run([str(inspect),str(path),'--probe-http',f'host.docker.internal:{http.server_port}'],capture_output=True,timeout=35)
    assert (result.returncode==0)==success, 'Unexpected authentication result (secret output withheld)'


def read(sock, size):
    data=b''
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk:raise EOFError()
        data+=chunk
    return data


@contextlib.contextmanager
def active_stream(data):
    path=work/'active.json';path.write_text(json.dumps(data));path.chmod(0o600)
    process=subprocess.Popen([str(inspect),str(path),'--serve-socks','0'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    try:
        # Bound readiness wait without blocking on stdout indefinitely.
        from queue import Queue
        lines=Queue()
        def receive():
            for line in process.stdout:lines.put(line)
            lines.put(None)
        threading.Thread(target=receive,daemon=True).start()
        address=None;deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            line=lines.get(timeout=35)
            if line is None:raise AssertionError('SOCKS process exited')
            if line.startswith('SOCKS5 '):address=line.strip().split()[1];break
        assert address
        host,p=address.rsplit(':',1)
        with socket.create_connection((host,int(p)),timeout=5) as sock:
            sock.sendall(b'\x05\x01\x00');assert read(sock,2)==b'\x05\x00'
            target=b'host.docker.internal'
            sock.sendall(b'\x05\x01\x00\x03'+bytes([len(target)])+target+struct.pack('!H',echo.server_address[1]))
            reply=read(sock,4);assert reply[1]==0
            read(sock,4 if reply[3]==1 else 16 if reply[3]==4 else read(sock,1)[0]);read(sock,2)
            sock.sendall(b'before');assert read(sock,6)==b'before'
            yield sock
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        process.stdout.close()

case=ExchangeTests();case.setUp()
db.set_settings({'panel_domain':'localhost','conn_address':'127.0.0.1','conn_port':str(port)})
try:
    with patch.dict(os.environ,RTRUST_MANAGED_CREDENTIALS='1',CLIENT_CA_FILE=str(certs/'fullchain.pem')),patch.object(config,'ENDPOINT_WORKDIR',str(runtime)),patch.object(config,'CERT_DIR',str(work/'certs')),patch.object(endpoint.manager,'_spawn',spawn),patch.object(endpoint.manager,'_kill',kill),patch.object(endpoint,'_VPN_TOML_TEMPLATE',endpoint._VPN_TOML_TEMPLATE.replace('allow_private_network_connections = false','allow_private_network_connections = true')):
        for protocol in ('http2','http3'):
            lost,auth=case.enrolled(protocol+' lost');neighbor,_=case.enrolled(protocol+' neighbor')
            def change(device,action):
                response=case.client.post(f'/portal/v2/devices/{device}/credentials/{action}',headers={**case.headers,'Idempotency-Key':str(uuid.uuid4())})
                assert response.status_code==200,response.text
                assert response.json()['operations'][0]['state']=='applied',response.text
            change(lost,'provision');change(neighbor,'provision')
            old=profile(lost,protocol);other=profile(neighbor,protocol)
            probe(old);probe(other)
            change(lost,'rotate');probe(old,False)
            saved=profile(lost,protocol);probe(saved);probe(other)
            with active_stream(saved) as active:
                started=time.monotonic()
                revoked=case.client.delete(f'/portal/v2/devices/{lost}',headers=case.headers)
                assert revoked.status_code==200,revoked.text
                assert revoked.json()['credentials']['operations'][0]['state']=='applied'
                active.settimeout(3)
                try:
                    active.sendall(b'after');data=active.recv(32)
                    assert data==b'', 'Revoked active tunnel still carries traffic'
                except (BrokenPipeError,ConnectionResetError,TimeoutError):pass
                elapsed=time.monotonic()-started
                assert elapsed<15, 'Revocation exceeded isolated acceptance bound'
            # Portal access is gone; saved credentials are tested without any API.
            assert case.client.get('/portal/v2/profiles',headers=auth).status_code==401
            probe(saved,False);probe(other)
            print(f'PASS {protocol}: distinct credentials, rotation denies old password, saved revoked password denied with portal token invalid, active server session terminated (client EOF or timeout), neighbor reconnects; revoke {elapsed:.2f}s',flush=True)
        print('PASS real isolated endpoint acceptance (no production changes)',flush=True)
finally:
    kill()
    for server in (http,echo):server.shutdown();server.server_close()
