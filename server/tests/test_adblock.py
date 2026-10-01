import importlib.util,unittest,json,tempfile,os
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('adblock',ROOT/'scripts/vpn-adblock-update.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class Lists(unittest.TestCase):
    def test_reject_tld_ip_wildcards_and_injection(self):
        for value in ['ru','su','com','1.2.3.4','a.ru/path','*.ru','a.ru\nlocal=/ru/']:self.assertIsNone(a.domain(value))
    def test_abp_does_not_widen_context_specific_rules(self):
        denied,allowed=a.parse('||ads.ru^\n||site.ru^$third-party\n||site.su/path.js\n@@||safe.ru^\n||tracker.su^$important\n','adblock')
        self.assertEqual(denied,{'ads.ru','tracker.su'});self.assertEqual(allowed,{'safe.ru'})
    def test_hosts_excludes_localhost_and_positive_mapping(self):
        self.assertEqual(a.parse('127.0.0.1 localhost\n0.0.0.0 ads.ru x.ads.ru # comment\n1.2.3.4 site.ru','hosts')[0],{'ads.ru','x.ads.ru'})
    def fixture(self):
        p={'sources':[{'id':'test','url':'https://example.invalid','format':'domains','min':1}], 'deny':[], 'allow':[], 'protected':['onixus-rf.duckdns.org','yandex.ru']}
        data=('\n'.join('ad'+str(i)+'.test' for i in range(10001))+'\nduckdns.org\nyandex.ru\nmc.yandex.ru\nads.su\n').encode()
        return p,data
    def test_protect_infrastructure_but_keep_tracker_subdomain(self):
        p,data=self.fixture();rules,meta=a.compile_lists(p,lambda _:data)
        self.assertNotIn('||duckdns.org^',rules);self.assertNotIn('||yandex.ru^',rules)
        self.assertIn('||mc.yandex.ru^',rules);self.assertEqual(meta['ru_su_domains'],2)
    def test_reject_partial_empty_or_html_source(self):
        p,data=self.fixture();p['sources'].append(dict(p['sources'][0],id='bad',url='https://bad.invalid'))
        for bad in [b'',b'<!doctype html><html>error</html>']:
            with self.assertRaises(ValueError):a.compile_lists(p,lambda url:data if url=='https://example.invalid' else bad)
    def test_explicit_operator_allow_overrides_local_deny(self):
        policy,data=self.fixture();policy['deny']=['ads.ru'];policy['allow']=['ads.ru']
        rules,_=a.compile_lists(policy,lambda _:data)
        self.assertIn('@@||ads.ru^',rules)

    def test_unchanged_update_never_rewrites_published_rules(self):
        policy,data=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);(home/'policy.json').write_text(json.dumps(policy))
            with patch.object(a,'HOME',home),patch.object(a,'fetch',return_value=data),patch.object(a,'refresh'),patch('sys.argv',['update']):
                a.main()
                current=home/'filters/current/rules.txt';before=current.read_bytes();inode=current.stat().st_ino
                original=Path.write_text
                def fail_rule_write(path,text,*args,**kwargs):
                    if path.name=='rules.txt':
                        with path.open('w') as f:f.write(text[:5])
                        raise OSError(28,'No space left on device')
                    return original(path,text,*args,**kwargs)
                with patch.object(Path,'write_text',fail_rule_write):
                    try:a.main()
                    except OSError:pass
                self.assertEqual(current.read_bytes(),before)
                self.assertEqual(current.stat().st_ino,inode)

    def test_new_generation_write_failure_preserves_current(self):
        policy,data=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);(home/'policy.json').write_text(json.dumps(policy))
            with patch.object(a,'HOME',home),patch.object(a,'fetch',return_value=data),patch.object(a,'refresh'),patch('sys.argv',['update']):
                a.main();current=home/'filters/current/rules.txt';before=current.read_bytes()
                generation=os.readlink(home/'filters/current')
                previous=json.loads((home/'status.json').read_text())['last_success']
                original=Path.write_text
                def fail_rule_write(path,text,*args,**kwargs):
                    if path.name=='rules.txt':
                        with path.open('w') as f:f.write(text[:5])
                        raise OSError(28,'No space left on device')
                    return original(path,text,*args,**kwargs)
                with patch.object(a,'fetch',return_value=data+b'new.ads.test\n'),patch.object(Path,'write_text',fail_rule_write):
                    with self.assertRaises(OSError):a.main()
                self.assertEqual(current.read_bytes(),before)
                self.assertEqual(os.readlink(home/'filters/current'),generation)
                self.assertEqual(json.loads((home/'status.json').read_text())['last_success'],previous)
                self.assertEqual({p.name for p in (home/'filters').iterdir()},{generation,'current'})

    def test_failed_activation_keeps_previous_generation(self):
        policy,data=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);(home/'policy.json').write_text(json.dumps(policy))
            (home/'filters/old').mkdir(parents=True);(home/'filters/old/rules.txt').write_text('old rules')
            (home/'filters/current').symlink_to('old')
            (home/'status.json').write_text(json.dumps({'last_success':'previous-success','canary':'old.invalid'}))
            with patch.object(a,'HOME',home),patch.object(a,'fetch',return_value=data),patch.object(a,'refresh',side_effect=[RuntimeError('reload failed'),None]) as refresh,patch('sys.argv',['update']):
                with self.assertRaises(RuntimeError):a.main()
                self.assertEqual(os.readlink(home/'filters/current'),'old')
                self.assertEqual((home/'filters/current/rules.txt').read_text(),'old rules')
                state=json.loads((home/'status.json').read_text())
                self.assertEqual(state['last_success'],'previous-success')
                self.assertIn('reload failed',state['last_error'])
                self.assertEqual(refresh.call_args.args[0],'old.invalid')
if __name__=='__main__':unittest.main()
