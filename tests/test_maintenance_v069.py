"""Regression test for the v0.6.9 database maintenance release.
Run: python tests/test_maintenance_patch.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central'))
import server


def run():
    previous_db, previous_config = server.DB, server.CONFIG
    try:
        with tempfile.TemporaryDirectory() as directory:
            server.DB = str(Path(directory) / 'watch.sqlite3')
            server.CONFIG = str(Path(directory) / 'targets.json')
            Path(server.CONFIG).write_text('{"targets":[]}', encoding='utf-8')
            server.initdb()
            with server.connect() as c:
                c.execute("INSERT INTO resources(id,name,host,url,agents,checks,enabled,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                          ('29', 'Display Example', 'example.org', '', '[]', '{}', 1, server.now()))
                c.execute("INSERT INTO blocklist_sources(name,kind,url,enabled,status,records) VALUES(?,?,?,?,?,?)",
                          ('regression-cidr', 'cidr', 'https://example.org/list', 1, 'ok', 1))
                c.execute("INSERT INTO blocklist_hits(resource_id,source,match,checked_at) VALUES(?,?,?,?)",
                          ('29', 'regression-cidr', '85.137.248.0/23', server.now()))
                c.execute("INSERT INTO central_resource_checks(resource_id,rip_status,rdo_status,rip_matches,checked_at) VALUES(?,?,?,?,?)",
                          ('29', 'BAN', 'OK', json.dumps([{'cidr': '85.137.248.0/23', 'source': 'regression-cidr'}]), server.now()))
                c.execute("INSERT INTO measurements(agent,event_id,target,ts,status,bytes,duration_ms,details,received_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          ('a', 'evt', '29--icmp', server.now(), 'OK_ICMP', 1, 10, '{}', server.now()))
                c.execute("INSERT INTO central_resource_check_history(resource_id,rip_status,rdo_status,checked_at) VALUES(?,?,?,?)",
                          ('29', 'BAN', 'OK', server.now()))
            matches = server.central_blocklist_matches()
            assert len(matches) == 1 and matches[0]['resource_name'] == 'Display Example'
            assert matches[0]['type'] == 'RIP'
            assert server.readonly_environment()['maintenance']['history_counts']['measurements'] == 1
            removed = server.clear_history()
            assert removed['measurements'] == 1 and removed['central_resource_check_history'] == 1
            with server.connect() as c:
                assert c.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 1
                assert c.execute('SELECT COUNT(*) FROM central_resource_checks').fetchone()[0] == 1
                assert c.execute('SELECT COUNT(*) FROM blocklist_sources').fetchone()[0] >= 1
                assert c.execute('SELECT COUNT(*) FROM measurements').fetchone()[0] == 0
                assert any(row['name'] == 'measurements_recent' for row in c.execute('PRAGMA index_list(measurements)'))
    finally:
        server.DB, server.CONFIG = previous_db, previous_config


if __name__ == '__main__':
    run()
    print('PASS: blocklists names/types, retention of live data, clear history and index')
