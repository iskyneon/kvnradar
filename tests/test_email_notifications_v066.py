import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central'))
import email_notifications as mail
import server

ENV = {
    'SMTP_HOST': 'mail.example.net', 'SMTP_PORT': '587',
    'SMTP_TLS_MODE': 'starttls', 'SMTP_USERNAME': 'mailer@example.net',
    'SMTP_PASSWORD': 'not-a-real-secret', 'SMTP_FROM': 'radar@example.net',
    'SMTP_TO': 'admin@example.net,ops@example.net', 'SMTP_TIMEOUT': '8',
    'SMTP_DASHBOARD_URL': 'https://radar.example.net:9443/#overview',
}

class FakeSMTP:
    instances = []
    def __init__(self, *args, **kwargs):
        self.args = args; self.kwargs=kwargs; self.calls=[]; FakeSMTP.instances.append(self)
    def __enter__(self):return self
    def __exit__(self, *a):return False
    def ehlo(self):self.calls.append('ehlo')
    def starttls(self, context):self.calls.append('starttls')
    def login(self, user, pwd):self.calls.append('login'); assert pwd == 'not-a-real-secret'
    def send_message(self, msg):self.calls.append('send');self.msg=msg

class EmailTests(unittest.TestCase):
    def test_disabled(self):
        with patch.dict(os.environ, {'SMTP_HOST':'','SMTP_FROM':'','SMTP_TO':''}):
            self.assertFalse(mail.enabled())
            self.assertIsNone(mail.send('test'))
    def test_html_escapes_user_fields_and_has_plain(self):
        with patch.dict(os.environ, ENV):
            subject,plain,html=mail.render('KVNRadar | STATUS CHANGE\nTarget: <script>bad</script>\nAgent: remote\nStatus: TCP_FAIL\nError: broken <b>')
            self.assertNotIn('<script>',html)
            self.assertIn('&lt;script&gt;',html)
            self.assertIn('Monitoring alert',subject)
            self.assertIn('TCP_FAIL',plain)
            self.assertIn('Open KVNRadar dashboard',html)
    def test_success_template(self):
        with patch.dict(os.environ, ENV):
            subject,_,html=mail.render('KVNRadar | RECOVERED\nTarget: api.example.org\nStatus: OK_TCP')
            self.assertIn('Service recovered',subject)
            self.assertIn('RESOLVED',html)
    def test_smtp_starttls_is_mandatory_before_auth(self):
        with patch.dict(os.environ, ENV):
            with patch.object(mail.smtplib,'SMTP',FakeSMTP):
                self.assertTrue(mail.send('KVNRadar | STATUS CHANGE\nTarget: example.org\nStatus: TCP_FAIL'))
                sent=FakeSMTP.instances[-1]
                self.assertEqual(sent.calls, ['ehlo','starttls','ehlo','login','send'])
                self.assertEqual(len(sent.msg.get_all('To')),1)
                self.assertIn('admin@example.net',str(sent.msg['To']))
                self.assertEqual(len(sent.msg.get_payload()),2)
    def test_smtp_ssl(self):
        with patch.dict(os.environ, dict(ENV,SMTP_TLS_MODE='ssl',SMTP_PORT='465')):
            with patch.object(mail.smtplib,'SMTP_SSL',FakeSMTP):
                self.assertTrue(mail.send('KVNRadar | RECOVERED\nTarget: example.org'))
                self.assertEqual(FakeSMTP.instances[-1].calls,['login','send'])
    def test_reject_plain_and_header_injection(self):
        with patch.dict(os.environ, dict(ENV,SMTP_TLS_MODE='plain')):
            with self.assertRaises(ValueError):mail.settings()
        with patch.dict(os.environ, dict(ENV,SMTP_TO='ok@example.org\nBcc:evil@example.org')):
            with self.assertRaises(ValueError):mail.settings()
    def test_settings_does_not_leak_password_recipient(self):
        with patch.dict(os.environ, ENV):
            data=server.readonly_environment()
            self.assertTrue(data['notifications']['email'])
            self.assertNotIn('not-a-real-secret',str(data))
            self.assertNotIn('admin@example.net',str(data))
            self.assertNotIn('mailer@example.net',str(data))
    def test_outbox_enqueues_email_when_configured(self):
        import sqlite3
        with patch.dict(os.environ, ENV):
            conn=sqlite3.connect(':memory:');conn.execute('CREATE TABLE outbox (channel TEXT,message TEXT)')
            server.enqueue(conn,'KVNRadar | STATUS CHANGE\nTarget: example.org')
            self.assertEqual([x[0] for x in conn.execute('SELECT channel FROM outbox')],['compass','telegram','email'])
            conn.close()

if __name__ == '__main__':unittest.main()
