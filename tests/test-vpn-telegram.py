#!/usr/bin/python3
"""Bot authorization: strangers only learn their own ID, never reach owner commands."""
import importlib.machinery,importlib.util,time,unittest
from pathlib import Path
from unittest.mock import patch
loader=importlib.machinery.SourceFileLoader('vpn_telegram',str(Path(__file__).resolve().parents[1]/'scripts/vpn-telegram.py'))
spec=importlib.util.spec_from_loader('vpn_telegram',loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m)
OWNER=100
def msg(sender,text,chat=None,kind='private'):
 return {'update_id':1,'message':{'from':{'id':sender},'chat':{'id':chat or sender,'type':kind},'text':text,'date':time.time()}}
class Bot(unittest.TestCase):
 def setUp(self):
  m.CONFIG={'owner':OWNER,'token':'t'};m.ID_REPLIES.clear()
  self.api=patch.object(m,'api').start();self.addCleanup(patch.stopall)
 def test_stranger_start_gets_only_own_id_once_per_minute(self):
  m.handle(msg(555,'/start'));m.handle(msg(555,'/id'))
  self.api.assert_called_once();method,data=self.api.call_args[0]
  self.assertEqual((method,data['chat_id']),('sendMessage',555));self.assertIn('555',data['text']);self.assertNotIn(str(OWNER),data['text'])
 def test_stranger_commands_groups_and_spoofed_chats_ignored(self):
  with patch.object(m,'command') as command:
   for update in [msg(555,'/status'),msg(555,'/restart'),msg(555,'/start',chat=-5,kind='group'),msg(555,'/start',chat=777)]:m.handle(update)
   command.assert_not_called()
  self.api.assert_not_called()
 def test_owner_help_unchanged(self):
  m.handle(msg(OWNER,'/start'))
  self.assertEqual(self.api.call_args[0][1]['chat_id'],OWNER);self.assertIn('/status',self.api.call_args[0][1]['text'])
if __name__=='__main__':unittest.main(verbosity=2)
