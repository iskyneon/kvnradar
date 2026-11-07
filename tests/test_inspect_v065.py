"""Inspect one-shot queue regression tests; no network access or live agents."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'central'))
import blocklists
import kvn_inspect as inspect_jobs
import server

class InspectTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        old_db,old_state=server.DB,blocklists.STATE
        server.DB=str(Path(self.tmp.name)/'test.sqlite3')
        blocklists.STATE=Path(self.tmp.name)/'blocklists'
        blocklists.STATE.mkdir()
        self.addCleanup(lambda:setattr(server,'DB',old_db))
        self.addCleanup(lambda:setattr(blocklists,'STATE',old_state))
        self.addCleanup(lambda:setattr(blocklists,'_INDEX',None))
        server.initdb()
        (blocklists.STATE/'antifilter-domains.txt').write_text('blocked.example\n')
        (blocklists.STATE/'antifilter-cidr.txt').write_text('203.0.113.0/24\n')
        with server.connect() as c:
            c.execute("UPDATE blocklist_sources SET records=1,status='ok' WHERE kind='domain'")
            c.execute("UPDATE blocklist_sources SET records=1,status='ok' WHERE kind='cidr'")
        blocklists._index_changed()

    def test_central_only_rip_and_rdo(self):
        job=inspect_jobs.create(server.connect,{'host':'203.0.113.21','port':443,'use_agent':False},{'edge':'token'})
        self.assertEqual(job['state'],'complete')
        self.assertEqual(job['rip']['status'],'BAN')
        self.assertEqual(job['rdo']['status'],'UNKNOWN')
        with patch.object(blocklists.socket,'getaddrinfo',return_value=[]):
            job=inspect_jobs.create(server.connect,{'host':'blocked.example','port':8443,'use_agent':False},{})
        self.assertEqual(job['rdo']['status'],'BAN')

    def test_one_shot_agent_dispatch_and_event_isolation(self):
        job=inspect_jobs.create(server.connect,{'host':'203.0.113.22','port':8443,'use_agent':True,'agent':'edge','checks':['tcp','tls','https','dpi']},{'edge':'token'})
        self.assertEqual(job['state'],'queued')
        self.assertEqual(inspect_jobs.read_job(server.connect,job['id'])['results'],{})
        targets=inspect_jobs.dispatch(server.connect,'edge')
        self.assertEqual(len(targets),4)
        self.assertEqual(inspect_jobs.dispatch(server.connect,'edge'),[])
        mapping={x['id'].rsplit('__',1)[1]:x for x in targets}
        self.assertEqual(mapping['https']['type'],'http_status')
        self.assertEqual(mapping['dpi']['type'],'http_content')
        self.assertEqual(mapping['https']['url'],'https://203.0.113.22:8443/')
        self.assertEqual(mapping['dpi']['min_bytes'],65536)
        self.assertEqual(mapping['tls']['port'],8443)
        for i,kind in enumerate(('tcp','tls','https','dpi')):
            e={'id':f'evt-{i}','target':mapping[kind]['id'],'status':'OK_FULL' if kind=='dpi' else 'OK_TCP',
               'duration_ms':12,'bytes':65536 if kind=='dpi' else 0,'details':{'tcp_connect_ms':4}}
            with server.connect() as c:
                self.assertTrue(server.process(c,'edge',e))
                self.assertTrue(server.process(c,'edge',e))
        state=inspect_jobs.read_job(server.connect,job['id'])
        self.assertEqual(state['state'],'complete')
        self.assertEqual(len(state['results']),4)
        with server.connect() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM measurements').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],0)

    def test_security_invalid_request_and_wrong_agent(self):
        for host in ('https://example.org','example.org/path','foo@bar','', 'example.org:443'):
            with self.assertRaises(ValueError):
                inspect_jobs.valid_host(host)
        with self.assertRaises(ValueError):
            inspect_jobs.create(server.connect,{'host':'example.org','use_agent':True,'agent':'wrong','checks':['tcp']},{'edge':'token'})
        with self.assertRaises(ValueError):
            inspect_jobs.create(server.connect,{'host':'example.org','port':70000},{})
        job=inspect_jobs.create(server.connect,{'host':'203.0.113.22','use_agent':True,'agent':'edge','checks':['tcp']},{'edge':'token'})
        t=inspect_jobs.dispatch(server.connect,'edge')[0]
        with server.connect() as c:
            self.assertFalse(inspect_jobs.consume_event(c,'other',{'target':t['id'],'status':'OK_TCP'}))
        self.assertEqual(inspect_jobs.read_job(server.connect,job['id'])['results'],{})

    def test_pending_queue_bound(self):
        for _ in range(3):
            inspect_jobs.create(server.connect,{'host':'203.0.113.22','use_agent':True,'agent':'edge','checks':['tcp']},{'edge':'token'})
        with self.assertRaisesRegex(ValueError,'three pending'):
            inspect_jobs.create(server.connect,{'host':'203.0.113.22','use_agent':True,'agent':'edge','checks':['tcp']},{'edge':'token'})

if __name__=='__main__': unittest.main()
