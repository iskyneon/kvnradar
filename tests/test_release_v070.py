"""Regression coverage for agent revocation, manual scanning and Central Inspect."""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'central'))
import central_probes
import kvn_inspect
import server


class ImmediatePool:
    def submit(self,fn,*args):
        fn(*args)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        original=(server.DB,server.AGENTS,server.CONFIG)
        self.addCleanup(lambda:(setattr(server,'DB',original[0]),setattr(server,'AGENTS',original[1]),setattr(server,'CONFIG',original[2])))
        server.DB=str(Path(self.tmp.name)/'watch.sqlite3')
        server.AGENTS=str(Path(self.tmp.name)/'agents.json')
        server.CONFIG=str(Path(self.tmp.name)/'targets.json')
        Path(server.AGENTS).write_text('{"demo":"secret"}')
        Path(server.CONFIG).write_text('{"targets":[]}')
        server.initdb()
        with server.connect() as conn:
            conn.execute("INSERT INTO agent_seen(agent,last_seen) VALUES('demo',?)",(server.now(),))
            conn.execute("INSERT INTO resources(id,name,host,url,agents,checks,updated_at) VALUES(?,?,?,?,?,?,?)",
                         ('one','Server One','example.org','','["demo"]','{}',server.now()))

    def post(self,path,body):
        encoded=json.dumps(body).encode()
        handler=object.__new__(server.Handler)
        handler.path=path
        handler.headers={'X-KVNRadar-Admin':'1','Content-Length':str(len(encoded))}
        handler.rfile=io.BytesIO(encoded)
        handler.reply=lambda status,data,mime='application/json':(status,data)
        return handler.admin_post()

    def test_delete_agent_blocks_reregistration_and_retains_measurements(self):
        with server.connect() as conn:
            conn.execute("INSERT INTO measurements(agent,event_id,target,ts,status,bytes,duration_ms,details,received_at) VALUES(?,?,?,?,?,?,?,?,?)",
                         ('demo','evt','one--icmp',server.now(),'OK_ICMP',1,10,'{}',server.now()))
        status,_=self.post('/ui/api/agents/delete',{'agent':'demo','confirm':'DELETE_AGENT'})
        self.assertEqual(status,200)
        with server.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM revoked_agents WHERE agent='demo'").fetchone()[0],1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM agent_seen WHERE agent='demo'").fetchone()[0],0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM measurements').fetchone()[0],1)

    def test_manual_blocklist_scan_is_queued(self):
        previous=server.CENTRAL_SCAN_STATE['requested']
        status,_=self.post('/ui/api/blocklists/check-now',{})
        self.assertEqual(status,202)
        self.assertGreater(server.CENTRAL_SCAN_STATE['requested'],previous)
        self.assertTrue(server.RIP_WAKE.is_set())
        server.RIP_WAKE.clear()

    def test_central_inspect_saves_four_probe_results(self):
        def fake_probes(host,port,save):
            for kind in central_probes.KINDS:
                save(kind,central_probes.result('OK_TCP',0))
        with patch.object(kvn_inspect,'check_central',return_value=({'status':'OK'},{'status':'OK'})):
            with patch.object(central_probes,'POOL',ImmediatePool()),patch.object(central_probes,'run_all',fake_probes):
                job=kvn_inspect.create(server.connect,{'host':'example.org','port':443,'use_agent':False},{})
        self.assertEqual(job['state'],'complete')
        self.assertIsNone(job['agent'])
        self.assertEqual(set(job['results']),set(central_probes.KINDS))

    def test_central_probes_reject_private_addresses(self):
        with patch.object(central_probes.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):
                central_probes.resolve_public('localhost',443)
        with patch.object(central_probes.socket,'getaddrinfo',return_value=[(2,1,6,'',('1.1.1.1',443))]):
            self.assertEqual(central_probes.resolve_public('example.org',443),['1.1.1.1'])


if __name__=='__main__':
    unittest.main()
