"""No network, production identities, or real Telegram deliveries."""
import importlib.util,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bot',ROOT/'scripts/vpn-telegram.py')
bot=importlib.util.module_from_spec(spec);spec.loader.exec_module(bot)
class BotTests(unittest.TestCase):
    def setUp(self):bot.CONFIG={'owner':123};bot.PENDING.clear()
    def update(self,text,owner=123,chat=123,kind='private',age=0):
        return {'message':{'from':{'id':owner},'chat':{'id':chat,'type':kind},'text':text,'date':time.time()-age}}
    def test_panel_aliases_use_https_button(self):
        with patch.object(bot,'send') as send:
            for cmd in ['/panel','/panels']:bot.handle(self.update(cmd))
            self.assertEqual(send.call_count,2)
            self.assertEqual(send.call_args.args[1][0][0]['url'],'https://onixus-rf.duckdns.org/console/')
    def test_foreign_group_and_stale_commands_are_ignored(self):
        with patch.object(bot,'send') as send:
            for kw in [{'owner':456},{'chat':456},{'kind':'group'},{'age':181}]:bot.handle(self.update('/panel',**kw))
            send.assert_not_called()
    def test_bans_include_both_jails(self):
        with patch.object(bot,'command',return_value=(0,'test')) as command,patch.object(bot,'send'):
            bot.handle(self.update('/bans'))
            self.assertEqual([c.args[0][-1] for c in command.call_args_list],['sshd','vpn-web'])
    def test_expired_confirmation_cannot_execute(self):
        bot.PENDING['old']=('restart-hysteria',time.time()-1)
        update={'callback_query':{'from':{'id':123},'message':{'chat':{'id':123,'type':'private'}},'id':'test','data':'confirm:old'}}
        with patch.object(bot,'api'),patch.object(bot,'send'),patch.object(bot,'command') as command:
            bot.handle(update);command.assert_not_called()
if __name__=='__main__':unittest.main()
