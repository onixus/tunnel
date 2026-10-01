"""Isolated nginx fixture; binds only host loopback and does not call the portal."""
import pathlib,subprocess,tempfile,urllib.request,urllib.error
root=pathlib.Path(__file__).resolve().parent/'protection'
def run(*args):return subprocess.check_output(args,text=True).strip()
image=run('docker','inspect','rtrust-portal-https','--format','{{.Image}}')
with tempfile.TemporaryDirectory() as tmp:
    d=pathlib.Path(tmp);(d/'logs').mkdir()
    (d/'test.conf').write_text((root/'nginx-auth.conf').read_text()+'''server {
 listen 8080;
 access_log /testlogs/auth.log vpn_auth if=$vpn_auth_failed;
 location /admin/login { if ($arg_ok = 1) { return 200; } return 401; }
 location /login { return 403; }
 location / { return 401; }
}''')
    try:
        run('docker','run','-d','--name','vpn-auth-isolated-test','-p','127.0.0.1:18094:8080','-v',str(d/'test.conf')+':/etc/nginx/conf.d/default.conf:ro','-v',str(d/'logs')+':/testlogs',image)
        import time;time.sleep(1)
        for method,path in [('GET','/admin/login'),('POST','/admin/login?ok=1'),('POST','/login'),('POST','/unrelated'),('POST','/admin/login')]:
            req=urllib.request.Request('http://127.0.0.1:18094'+path,method=method,headers={'X-Forwarded-For':'192.0.2.99'})
            try:urllib.request.urlopen(req,timeout=3).close()
            except urllib.error.HTTPError:pass
        lines=(d/'logs/auth.log').read_text().splitlines()
        assert len(lines)==1 and '192.0.2.99' not in lines[0],lines
        print('PASS nginx logs only failed login POST, ignores forged forwarded IP')
    finally:run('docker','rm','-f','vpn-auth-isolated-test')
