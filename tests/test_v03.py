import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT/'central'))
import blocklists

class FeedTests(unittest.TestCase):
    def test_parsers(self):
        self.assertEqual(blocklists.parse_feed('cidr',b'#hi\n1.2.3.4\n1.2.3.0/24\ninvalid\n'),['1.2.3.0/24','1.2.3.4/32'])
        self.assertIn('blocked.example',blocklists.parse_feed('domain',b'blocked.example\nhttps://blocked.example/a\n'))

    def test_local_match(self):
        with tempfile.TemporaryDirectory() as d:
            prev=blocklists.STATE
            try:
                blocklists.STATE=Path(d)
                (blocklists.STATE/'antifilter-cidr.txt').write_text('203.0.113.0/24\n')
                (blocklists.STATE/'antifilter-domains.txt').write_text('blocked.example\n')
                blocklists._INDEX=None
                hits,ips=blocklists.match_host('sub.blocked.example',resolve=False)
                self.assertEqual(len(hits),1)
                self.assertEqual(ips,[])
                hits,ips=blocklists.match_host('203.0.113.42',resolve=False)
                self.assertEqual(hits[0]['match'],'203.0.113.0/24')
            finally:
                blocklists.STATE=prev;blocklists._INDEX=None

    def test_download_rollback(self):
        import sqlite3
        from io import BytesIO
        with tempfile.TemporaryDirectory() as d:
            prev=blocklists.STATE
            try:
                blocklists.STATE=Path(d)
                db=Path(d)/'db.sqlite'
                def connect():
                    c=sqlite3.connect(db);c.row_factory=sqlite3.Row;return c
                with connect() as c:blocklists.schema(c)
                class Response(BytesIO):
                    status=200
                data='\n'.join(f'198.51.{n}.0/24' for n in range(12)).encode()
                with patch('blocklists.urllib.request.urlopen',return_value=Response(data)):
                    count=blocklists.update_one(connect,'antifilter-cidr','cidr','https://antifilter.download/list/allyouneed.lst')
                self.assertEqual(count,12)
                original=(blocklists.STATE/'antifilter-cidr.txt').read_bytes()
                with patch('blocklists.urllib.request.urlopen',side_effect=OSError('temporary failure')):
                    blocklists.update_one(connect,'antifilter-cidr','cidr','https://antifilter.download/list/allyouneed.lst')
                self.assertEqual(original,(blocklists.STATE/'antifilter-cidr.txt').read_bytes())
            finally:blocklists.STATE=prev;blocklists._INDEX=None

if __name__=='__main__':unittest.main()
