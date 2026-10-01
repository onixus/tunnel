"""Root-only live jail test using reserved addresses; removes both test bans."""
import datetime,pathlib,subprocess,time
p=pathlib.Path('/tmp/vpn-auth-fixture.log')
now=datetime.datetime.now(datetime.timezone.utc).strftime('[%Y-%m-%dT%H:%M:%S%z]')
p.write_text(now+' 192.0.2.123 vpn-auth-failed\n'+now+' 2001:db8::123 vpn-auth-failed\n'+now+' 192.0.2.124 GET /admin/login 200\n'+now+' 192.0.2.125 vpn-auth-failed injected\n')
r=subprocess.run(['fail2ban-regex',str(p),'/etc/fail2ban/filter.d/vpn-web.conf'],capture_output=True,text=True,check=True)
print(r.stdout)
assert '2 matched' in r.stdout
log=pathlib.Path('/var/log/vpn-portal/auth.log')
with log.open('a') as f:
    for ip in ['192.0.2.123','2001:db8::123']:
        for _ in range(5):f.write(now+' '+ip+' vpn-auth-failed\n')
time.sleep(3)
try:
    state=subprocess.check_output(['fail2ban-client','status','vpn-web'],text=True);print(state)
    assert '192.0.2.123' in state and '2001:db8::123' in state
    rules=subprocess.check_output(['nft','list','table','inet','vpn_web_bans'],text=True)
    assert 'tcp dport 443 ip saddr' in rules and 'tcp dport 443 ip6 saddr' in rules
    assert 'dport 22 ' not in rules
    print(rules)
finally:
    for ip in ['192.0.2.123','2001:db8::123']:subprocess.run(['fail2ban-client','set','vpn-web','unbanip',ip],check=True)
