import os
import sqlite3
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'central'))
import blocklists


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_state=blocklists.STATE
        blocklists.STATE=Path(self.tmp.name)
        self.addCleanup(lambda: setattr(blocklists,'STATE',self.old_state))
        self.addCleanup(lambda: setattr(blocklists,'_INDEX',None))
        blocklists._INDEX=None
        db=Path(self.tmp.name)/'test.sqlite'
        def conn():
            c=sqlite3.connect(db)
            c.row_factory=sqlite3.Row
            return c
        self.connect=conn
        with conn() as c: blocklists.schema(c)

    def seed(self,name,kind,values):
        (blocklists.STATE/(name+'.txt')).write_text('\n'.join(values)+'\n')
        with self.connect() as c:
            c.execute("UPDATE blocklist_sources SET records=?,status='ok' WHERE name=?",(len(values),name))
        blocklists._INDEX=None

    def test_parsers(self):
        self.assertEqual(blocklists.parse_feed('cidr',b'#hi\n1.2.3.4\n1.2.3.0/24\ninvalid\n'),['1.2.3.0/24','1.2.3.4/32'])
        self.assertIn('blocked.example',blocklists.parse_feed('domain',b'blocked.example\nhttps://blocked.example/a\n'))

    def test_local_match_and_disable(self):
        self.seed('antifilter-cidr','cidr',['203.0.113.0/24'])
        self.seed('antifilter-domains','domain',['blocked.example'])
        hits,ips=blocklists.match_host(self.connect,'sub.blocked.example',resolve=False)
        self.assertEqual(hits,[{'source':'antifilter-domains','match':'blocked.example','type':'domain'}])
        self.assertEqual(ips,[])
        hits,ips=blocklists.match_host(self.connect,'203.0.113.42',resolve=False)
        self.assertEqual(hits[0]['match'],'203.0.113.0/24')
        with self.connect() as c: c.execute("UPDATE blocklist_sources SET enabled=0 WHERE name='antifilter-cidr'")
        blocklists._index_changed()
        self.assertEqual(blocklists.match_host(self.connect,'203.0.113.42',resolve=False)[0],[])

    def test_source_add_edit_delete_and_no_reseed(self):
        blocklists.save_source(self.connect,'sample-domain','domain','https://example.com/hosts',False)
        with self.connect() as c:
            src=c.execute("SELECT * FROM blocklist_sources WHERE name='sample-domain'").fetchone()
        self.assertEqual(src['enabled'],0)
        blocklists.delete_source(self.connect,'antifilter-domains')
        with self.connect() as c: blocklists.schema(c)
        with self.connect() as c:
            self.assertIsNone(c.execute("SELECT 1 FROM blocklist_sources WHERE name='antifilter-domains'").fetchone())

    def test_download_rollback(self):
        rows='\n'.join(f'198.51.{n}.0/24' for n in range(12)).encode()
        with patch.object(blocklists,'_secure_fetch',return_value=rows):
            self.assertEqual(blocklists.update_one(self.connect,'antifilter-cidr','cidr',blocklists.DEFAULT_SOURCES[0][2]),12)
        original=(blocklists.STATE/'antifilter-cidr.txt').read_bytes()
        with patch.object(blocklists,'_secure_fetch',side_effect=OSError('temporary failure')):
            self.assertEqual(blocklists.update_one(self.connect,'antifilter-cidr','cidr',blocklists.DEFAULT_SOURCES[0][2]),0)
        self.assertEqual(original,(blocklists.STATE/'antifilter-cidr.txt').read_bytes())
        blocklists._INDEX=None
        self.assertEqual(len(blocklists.load_index(self.connect)[1][4]),12)

    def test_url_validation_blocks_private_or_insecure(self):
        for url in ('http://example.com/a','https://user:pass@example.com/a',
                    'https://example.com:8443/a','https://example.com/a#x'):
            with self.assertRaises(ValueError):
                blocklists.validate_source('example','domain',url)
        with patch.object(blocklists.socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,0,'',('127.0.0.1',443))]):
            with self.assertRaisesRegex(ValueError,'non-public'):
                blocklists._secure_fetch('https://example.com/list')


if __name__=='__main__':
    unittest.main()
