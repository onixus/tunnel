#!/usr/bin/env python3
"""Compile bounded local DNS lists. All sources must pass; hot-reload with rollback."""
import argparse,base64,datetime,fcntl,hashlib,json,os,re,shutil,subprocess,sys,time,urllib.request
from pathlib import Path
HOME=Path('/opt/vpn-adblock')
LIMIT=24*1024*1024

def domain(value):
    value=value.strip().lower().rstrip('.')
    if len(value)>253 or '.' not in value:return None
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')):return None
    if re.fullmatch(r'[0-9.]+',value):return None
    return value

def parse(text,kind):
    blocked=set();allowed=set()
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(('#','!','[')):continue
        target=blocked
        if kind=='hosts':
            parts=line.split('#',1)[0].split()
            if len(parts)<2 or parts[0] not in ('0.0.0.0','127.0.0.1','::'):continue
            values=parts[1:]
        elif kind=='adblock':
            m=re.fullmatch(r'(@@)?\|\|([^\^/$*]+)\^(?:\$important)?',line)
            if not m:continue # Never widen path/resource/third-party rules to whole domains.
            if m[1]:target=allowed
            values=[m[2]]
        else:values=[line]
        for value in values:
            d=domain(value)
            if d:target.add(d)
    return blocked,allowed

def compile_lists(policy,fetch):
    deny=set(policy['deny']);allow=set(policy['allow']);sources=[]
    for s in policy['sources']:
        raw=fetch(s['url'])
        if len(raw)>LIMIT:raise ValueError('Source too large: '+s['id'])
        text=raw.decode('utf-8-sig',errors='strict')
        if '<html' in text[:1000].lower() or '<!doctype' in text[:1000].lower():raise ValueError('HTML source')
        blocks,exceptions=parse(text,s['format'])
        if s.get('suffixes'):
            blocks={d for d in blocks if d.rsplit('.',1)[-1] in s['suffixes']}
            exceptions={d for d in exceptions if d.rsplit('.',1)[-1] in s['suffixes']}
        if not s['min']<=len(blocks)<=1500000:raise ValueError('Unexpected rule count: '+s['id'])
        deny.update(blocks);allow.update(exceptions)
        sources.append({'id':s['id'],'url':s['url'],'domains':len(blocks),'sha256':hashlib.sha256(raw).hexdigest()})
    for d in deny|allow|set(policy['protected']):
        if domain(d)!=d:raise ValueError('Invalid policy domain')
    # Preserve infrastructure and site roots, while still blocking their tracker subdomains.
    deny={d for d in deny if not any(p==d or p.endswith('.'+d) for p in policy['protected'])}
    # Explicit local denies are stronger than upstream exceptions, but never infrastructure.
    allow={d for d in allow if not any(x==d or x.endswith('.'+d) for x in policy['deny'])}|set(policy['allow'])
    if not 10000<len(deny)<1800000:raise ValueError('Unexpected total count')
    rules='! Locally compiled DNS rules; no cosmetic/path rules\n'+'\n'.join('||'+d+'^' for d in sorted(deny))+'\n'+'\n'.join('@@||'+d+'^' for d in sorted(allow))+'\n'
    return rules,{'domains':len(deny),'ru_su_domains':sum(d.endswith(('.ru','.su')) for d in deny),'sources':sources}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None

def fetch(url):
    if not url.startswith('https://'):raise ValueError('HTTPS required')
    with urllib.request.build_opener(NoRedirect).open(url,timeout=40) as r:return r.read(LIMIT+1)

def api(path,data=None):
    cfg=json.loads((HOME/'api.json').read_text())
    auth=base64.b64encode((cfg['username']+':'+cfg['password']).encode()).decode()
    req=urllib.request.Request('http://127.0.0.1:3001/control/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=40) as r:
        content=r.read();return json.loads(content) if content else {}

def atomic_json(path,value):
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2));tmp.replace(path)

def refresh(canary="ads.example.invalid"):
    api('filtering/refresh',{'whitelist':False,'force':True})
    for _ in range(20):
        result=api('filtering/check_host?name='+canary)
        if result.get('reason','').startswith('Filtered') and any(r.get('text')=='||'+canary+'^' for r in result.get('rules',[])):return
        time.sleep(.3)
    raise RuntimeError('Local filtering health check failed')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bootstrap',action='store_true');args=parser.parse_args()
    HOME.mkdir(mode=0o700,exist_ok=True)
    with (HOME/'update.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        status=HOME/'status.json';previous=json.loads(status.read_text()) if status.exists() else {}
        old=None;switched=False
        try:
            policy=json.loads((HOME/'policy.json').read_text());rules,meta=compile_lists(policy,fetch)
            prior={s['id']:s['domains'] for s in previous.get('sources',[])}
            for s in meta['sources']:
                if s['id'] in prior and not .6*prior[s['id']]<=s['domains']<=2*prior[s['id']]:raise ValueError('Source changed too much: '+s['id'])
            canary='generation-'+hashlib.sha256(rules.encode()).hexdigest()[:24]+'.invalid'
            rules+='||'+canary+'^\n'
            digest=hashlib.sha256(rules.encode()).hexdigest()
            generation=HOME/'filters'/digest;generation.mkdir(parents=True,exist_ok=True);generation.chmod(0o755);generation.parent.chmod(0o755)
            (generation/'rules.txt').write_text(rules);(generation/'rules.txt').chmod(0o644)
            current=HOME/'filters/current';old=os.readlink(current) if current.is_symlink() else None
            nextlink=HOME/'filters/next';nextlink.unlink(missing_ok=True);nextlink.symlink_to(digest);nextlink.replace(current);switched=True
            if not args.bootstrap:refresh(canary)
            meta.update(last_success=datetime.datetime.now(datetime.timezone.utc).isoformat(),last_error=None,sha256=digest,mode='local',bootstrap=args.bootstrap,canary=canary)
            atomic_json(status,meta)
            # Keep current and previous generation only.
            for p in (HOME/'filters').iterdir():
                if p.is_dir() and not p.is_symlink() and p.name not in (digest,old):shutil.rmtree(p)
            print(json.dumps({'domains':meta['domains'],'ru_su_domains':meta['ru_su_domains'],'sha256':digest}))
        except BaseException as e:
            rollback_error=None
            if switched and old:
                nxt=HOME/'filters/rollback';nxt.unlink(missing_ok=True);nxt.symlink_to(old);nxt.replace(HOME/'filters/current')
                if not args.bootstrap:
                    try:refresh(previous.get("canary","ads.example.invalid"))
                    except Exception as rollback:rollback_error=type(rollback).__name__
            previous.update(last_error=type(e).__name__+': '+str(e)[:200]+(' (rollback unverified: '+rollback_error+')' if rollback_error else ''),last_attempt=datetime.datetime.now(datetime.timezone.utc).isoformat())
            atomic_json(status,previous);raise
if __name__=='__main__':main()
