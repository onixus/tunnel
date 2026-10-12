"""The sidecar sends revocation to the portal and never reports pending as applied."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock,patch
import test_exchange as fixture
sys.path.insert(0,str(fixture.ROOT/'server/console'))
import console_app as console

class ConsoleCredentialTests(unittest.TestCase):
    def test_sidecar_failure_and_applied_response(self):
        for state in ('requested','pending','failed','applied'):
            connection=MagicMock()
            response=connection.getresponse.return_value
            response.status=200
            response.read.return_value=json.dumps({'operations':[{'action':'revoke','state':state}]}).encode()
            with patch.object(console.http.client,'HTTPConnection',return_value=connection):
                if state=='applied':
                    result=console.managed_device_revoke(1,42)
                    self.assertIn('применён на endpoint',result['message'])
                else:
                    with self.assertRaisesRegex(RuntimeError,'не подтвердил применение'):
                        console.managed_device_revoke(1,42)
            args,kwargs=connection.request.call_args
            self.assertEqual(args,('POST','/admin/api/device-credentials/42/revoke'))
            self.assertIn('X-CSRF-Token',kwargs['headers'])
            self.assertIn('admin_token=',kwargs['headers']['Cookie'])
            connection.close.assert_called_once()

    def test_generic_console_key_rotation_cannot_bypass_device_lifecycle(self):
        case=fixture.ExchangeTests();case.setUp()
        device,_=case.enrolled()
        from app import db
        cfg=db.create_device_config(case.owner,device,'distinct','synthetic','Device')
        with self.assertRaisesRegex(RuntimeError,'ключа устройства'):
            console.perform('trusttunnel.rotate',{'id':cfg},1)
        self.assertEqual(db.get_config(cfg)['tt_password'],'synthetic')

if __name__=='__main__':unittest.main()
