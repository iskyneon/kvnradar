import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'central'))
import blocklists
import server


class BlocklistAdminTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.orig_db=server.DB;self.orig_state=blocklists.STATE
        server.DB=str(Path(self.temp.name)/'test.db')
        blocklists.STATE=Path(self.temp.name)/'cache'
        blocklists.STATE.mkdir()
        self.addCleanup(lambda:setattr(server,'DB',self.orig_db))
        self.addCleanup(lambda:setattr(blocklists,'STATE',self.orig_state))
        self.addCleanup(lambda:setattr(blocklists,'_INDEX',None))
        server.initdb()

    def seed(self,name,kind,rows):
        (blocklists.STATE/(name+'.txt')).write_text('\n'.join(rows)+'\n')
        with server.connect() as c:
            c.execute("UPDATE blocklist_sources SET kind=?,status='ok',enabled=1,records=? WHERE name=?",(kind,len(rows),name))
        blocklists._index_changed()

    def add_resource(self,rid,host,exempt=0):
        with server.connect() as c:
            c.execute("INSERT INTO resources(id,name,host,rip_exempt,updated_at) VALUES(?,?,?,?,?)",(rid,rid,host,exempt,'now'))

    def read_status(self,rid):
        with server.connect() as c:
            return dict(c.execute('SELECT rip_status,rdo_status,rdo_matches FROM central_resource_checks WHERE resource_id=?',(rid,)).fetchone())

    def test_cidr_domain_combination_and_exempt(self):
        self.seed('antifilter-domains','domain',['blocked.example'])
        self.seed('antifilter-cidr','cidr',['203.0.113.0/24'])
        self.add_resource('a','blocked.example',1)
        self.add_resource('b','203.0.113.22',0)
        with patch.object(server.socket,'getaddrinfo',return_value=[]):
            server.scan_rip_rdo_once()
        status=self.read_status('a')
        self.assertEqual(status['rip_status'],'EXC')
        self.assertEqual(status['rdo_status'],'BAN')
        self.assertEqual(json.loads(status['rdo_matches'])[0]['source'],'antifilter-domains')
        self.assertEqual(self.read_status('b')['rip_status'],'BAN')
        with server.connect() as c:
            c.execute("UPDATE blocklist_sources SET enabled=0,status='disabled' WHERE name='antifilter-cidr'")
        blocklists._index_changed()
        server.scan_rip_rdo_once()
        self.assertEqual(self.read_status('b')['rip_status'],'UNKNOWN')
        self.assertEqual(self.read_status('a')['rdo_status'],'BAN')

    def test_multiple_sources_of_same_kind(self):
        blocklists.save_source(server.connect,'extra-domains','domain','https://example.org/domains',False)
        self.seed('antifilter-domains','domain',['blocked.example'])
        self.seed('extra-domains','domain',['other.example'])
        self.add_resource('x','other.example')
        server.scan_rip_rdo_once()
        self.assertEqual(self.read_status('x')['rdo_status'],'BAN')
        with server.connect() as c:
            c.execute("UPDATE blocklist_sources SET enabled=0,status='disabled' WHERE name='antifilter-domains'")
        blocklists._index_changed()
        server.scan_rip_rdo_once()
        self.assertEqual(self.read_status('x')['rdo_status'],'BAN')


if __name__=='__main__':unittest.main()
