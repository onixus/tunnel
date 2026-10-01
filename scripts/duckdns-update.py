#!/usr/bin/python3
import json,ipaddress,urllib.request,urllib.parse,socket,subprocess
from pathlib import Path
c=json.loads(Path('/etc/duckdns-update.json').read_text())
with urllib.request.urlopen('https://api.ipify.org',timeout=15) as r:ip=r.read().decode().strip()
if not ipaddress.ip_address(ip).is_global:raise SystemExit('External IP not public')
q=urllib.parse.urlencode({'domains':c['domain'].removesuffix('.duckdns.org'),'token':c['token'],'ip':ip})
try:
 with urllib.request.urlopen('https://www.duckdns.org/update?'+q,timeout=20) as r:result=r.read().decode().strip()
except Exception as e:raise SystemExit('DuckDNS request failed: '+type(e).__name__)
if result!='OK':raise SystemExit('DuckDNS rejected update; token/domain ownership must be checked')
print(c['domain']+' update accepted; IPv4 '+ip)

if c.get("update_local_panels"):
 subprocess.run(["/usr/local/sbin/vpn-local-address",ip],check=True,timeout=90)
