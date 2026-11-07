"""Settings response does not leak tokens, passwords, or private URL components."""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'central'))
import server

class SettingsTests(unittest.TestCase):
    def test_safe_allowlist(self):
        with patch.dict(os.environ,{
            'TELEGRAM_TOKEN':'secret123456',
            'TELEGRAM_CHAT_ID':'-100123456789',
            'COMPASS_BOT_TOKEN':'abc-private',
            'COMPASS_GROUP_ID':'internal-room',
            'COMPASS_BASE_URL':'https://user:password@monitor.example.org:9443/private?token=should-never-expose',
            'CENTRAL_BLOCKLIST_INTERVAL':'600',
        }):
            output=server.readonly_environment()
            serial=json.dumps(output)
            for term in ('secret123456','-100123456789','abc-private','internal-room','password','should-never-expose'):
                self.assertNotIn(term,serial)
            self.assertEqual(next(x['value'] for x in output['entries'] if x['key']=='COMPASS_BASE_URL'),
                             'https://monitor.example.org:9443')
            self.assertEqual(next(x['value'] for x in output['entries'] if x['key']=='CENTRAL_BLOCKLIST_INTERVAL'),'600')
            self.assertTrue(output['notifications']['compass'])
    def test_bad_numeric_value_does_not_leak(self):
        with patch.dict(os.environ,{'CENTRAL_BLOCKLIST_INTERVAL':'secret-value'}):
            output=server.readonly_environment()
            self.assertEqual(next(x['value'] for x in output['entries'] if x['key']=='CENTRAL_BLOCKLIST_INTERVAL'),'300')

if __name__=='__main__':unittest.main()
