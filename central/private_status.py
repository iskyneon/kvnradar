# KVNRADAR_HTTP_PORTS_V0413: add HTTP monitoring to aggregation and public matrix.
# KVNRADAR_DISABLE_SSL_VPN_0411
#!/usr/bin/env python3
"""KVNRadar private Overview status aggregation for the admin API."""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import agent_aliases

DATABASE = os.getenv('PUBLIC_DB', '/data/watch.sqlite3')
ALLOWED_STATES = {'healthy', 'degraded', 'outage', 'unknown'}


def parse_time(value):
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def state_for(status):
    s = str(status or '')
    if s == 'SHORT_RESPONSE' or s.startswith(('INCONCLUSIVE', 'NOT_TESTABLE')):
        return 'degraded'
    if s.startswith('OK_'):
        return 'healthy'
    return 'outage'


def worst(items):
    values = set(items)
    for x in ('outage', 'degraded', 'healthy'):
        if x in values:
            return x
    return 'unknown'


# Only these checks can establish actual reachability. DNS/traceroute failures
# alone must not classify the entire service as unavailable.
REACHABILITY_CHECKS = {'icmp', 'tcp', 'tls', 'http_plain', 'http_status', 'http_content', 'ssl_vpn'}
STRONG_REACHABILITY = {'tcp', 'tls', 'http_plain', 'http_status', 'http_content', 'ssl_vpn'}


def aggregate_service(checks, agents, pair_states):
    """Aggregate the current check-by-agent matrix conservatively.

    healthy: all expected fresh pairs succeeded.
    degraded: any failure, warning or missing expected measurement while some
              availability remains or an outage cannot be proved.
    outage: each expected agent has conclusive failure for *all* configured
            reachability probes and no reachable check succeeded anywhere.
    unknown: nothing with a fresh result / service not configured.
    """
    if not checks or not agents:
        return 'unknown'
    values = [pair_states.get((kind, agent), 'unknown')
              for kind in checks for agent in agents]
    if not any(v != 'unknown' for v in values):
        return 'unknown'
    if all(v == 'healthy' for v in values):
        return 'healthy'
    configured_strong = [k for k in checks if k in STRONG_REACHABILITY]
    reach = configured_strong or ([k for k in checks if k == 'icmp'])
    any_reachability_success = any(pair_states.get((kind, agent)) == 'healthy'
                                   for agent in agents for kind in checks
                                   if kind in REACHABILITY_CHECKS)
    if reach and not any_reachability_success and all(
            pair_states.get((kind, agent)) == 'outage'
            for agent in agents for kind in reach):
        return 'outage'
    return 'degraded'


def aggregate_overall(services):
    """Red only when *all* published services are confirmed unavailable."""
    states = [s['status'] for s in services]
    if not states or all(s == 'unknown' for s in states):
        return 'unknown'
    if all(s == 'healthy' for s in states):
        return 'healthy'
    if all(s == 'outage' for s in states):
        return 'outage'
    return 'degraded'


def collect(now=None, db_path=None):
    """Expose enabled resources inside the authenticated admin only. Names come exclusively from resources.name."""
    now = now or datetime.now(timezone.utc)
    db_path = db_path or DATABASE
    uri = Path(db_path).absolute().as_uri() + '?mode=ro'
    result = []
    with sqlite3.connect(uri, uri=True, timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA query_only=ON')
        resources = [dict(x) for x in conn.execute(
            'SELECT id,name,enabled,checks,agents,updated_at,rip_exempt FROM resources WHERE enabled=1 ORDER BY name COLLATE NOCASE LIMIT 101')]
        if len(resources) > 100:
            raise ValueError('Too many enabled resources')
        if not resources:
            return {'generated_at': now.isoformat(), 'overall': 'unknown', 'services': [], 'period': '24h'}
        ids=[r['id'] for r in resources]
        cutoff=(now-timedelta(hours=24)).isoformat(timespec='seconds')
        measurements = []
        # Do not use LIKE: '_' and '%' in IDs have special meaning there.
        # Filter by an exact target prefix in Python after bounded DB fetch.
        # Each chunk uses exact check IDs; never expose raw measurements.
        checks_by_id={}
        for r in resources:
            conf=json.loads(r['checks'])
            checks_by_id[r['id']]={k:v for k,v in conf.items() if isinstance(v,dict) and v.get('enabled') is True and k != 'ssl_vpn'}
        targets=[rid+'--'+kind for rid,checks in checks_by_id.items() for kind in checks]
        for pos in range(0,len(targets),350):
            sub=targets[pos:pos+350]
            marks=','.join('?' for _ in sub)
            measurements += list(conn.execute(
                'SELECT target,agent,status,received_at FROM measurements WHERE received_at>=? AND target IN ('+marks+') ORDER BY received_at DESC LIMIT 30000',
                [cutoff,*sub]))
        measurements.sort(key=lambda row: row['received_at'],reverse=True)
        agent_seen={r['agent']:parse_time(r['last_seen']) for r in conn.execute('SELECT agent,last_seen FROM agent_seen')}
        agent_short_names=agent_aliases.aliases_for_agents(conn, list(agent_seen))
        central_rows={x['resource_id']:dict(x) for x in conn.execute('SELECT resource_id,rip_status,rdo_status,checked_at FROM central_resource_checks WHERE resource_id IN ('+','.join('?' for _ in resources)+')',[r['id'] for r in resources])} if resources else {}
    start=now-timedelta(hours=24)
    for row in resources:
        rid=row['id']
        checks=checks_by_id[rid] if row['enabled'] else {}
        assigned=json.loads(row['agents']) if row['enabled'] else []
        updated=parse_time(row['updated_at'])
        statuses=[]
        active_kinds=set()
        points=[[] for _ in range(48)]
        seen_pairs=set()
        pair_states={}
        for m in measurements:
            target=m['target']
            if not target.startswith(rid+'--'):
                continue
            kind=target[len(rid)+2:]
            if kind not in checks or (assigned and m['agent'] not in assigned):
                continue
            timestamp=parse_time(m['received_at'])
            if not timestamp or (updated and timestamp < updated):
                continue
            status=state_for(m['status'])
            idx=int((timestamp-start).total_seconds() // (30*60))
            if 0 <= idx < 48:
                points[idx].append(status)
            key=(kind,m['agent'])
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            agent_time=agent_seen.get(m['agent'])
            interval=max(60,int(checks[kind].get('interval_sec',300)))
            age=max(900,3*interval+120)
            fresh = bool(agent_time and (now-agent_time).total_seconds() <= 600 and (now-timestamp).total_seconds() <= age and timestamp <= now+timedelta(seconds=60))
            pair_states[key] = status if fresh else 'unknown'
            if fresh:
                statuses.append(status)
                active_kinds.add(kind)
        # Expected agents are explicit assignments, or all agents registered
        # by the central server when the resource is unrestricted.
        expected_agents = list(dict.fromkeys(assigned if assigned else sorted(agent_seen)))
        current = aggregate_service(checks, expected_agents, pair_states) if row['enabled'] else 'unknown'
        # Public matrix: only short check/hosting codes and states.
        # Never expose actual IP/host, token, request URL or raw result.
        check_codes={'icmp':'PING','dns':'DNS','tcp':'TCP','tls':'TLS',
                     'http_plain':'HTTP','http_status':'HTTPS','http_content':'DPI',
                     'traceroute':'TRACE','ssl_vpn':'VPN'}
        def hosting_code(name):
            return agent_short_names.get(name, agent_aliases.default_short(name))
        names=assigned if assigned else sorted(agent_seen)
        # KVNRADAR_CENTRAL_RIP_RDO_PUBLIC_V0415: central-only badges, never duplicated per agent.
        cr=central_rows.get(rid,{})
        def central_state(v, *, rip_exempt=False):
            # RIP exemption is a persistent resource setting, not a scan result.
            # It must remain visible even when the periodic central scan is stale.
            if rip_exempt:
                return 'exc'
            checked=parse_time(cr.get('checked_at'))
            if not checked or (now-checked).total_seconds()>900:
                return 'unknown'
            return 'healthy' if v=='OK' else 'outage' if v=='BAN' else 'unknown'
        matrix=[
            {'code':'RIP','hosting':[{'code':'CENTRAL','status':central_state(cr.get('rip_status'),rip_exempt=bool(row.get('rip_exempt')))}]},
            {'code':'RDO','hosting':[{'code':'CENTRAL','status':central_state(cr.get('rdo_status'))}]},
        ]
        for kind in checks:
            hosts=[{'code':hosting_code(a), 'status':pair_states.get((kind,a),'unknown') if row['enabled'] else 'unknown'}
                   for a in names[:25]]
            matrix.append({'code':check_codes.get(kind,kind.upper()[:8]), 'hosting':hosts})
        result.append({'name':row['name'], 'description':'',
                       'status':current,
                       'checks':matrix,
                       'timeline':[worst(bucket) for bucket in points[:-1]] + [current],  # KVNRADAR_CURRENT_TICK_V0412
                       'last_24h_samples':sum(map(len,points))})
    overall=aggregate_overall(result)
    return {'generated_at':now.isoformat(),'overall':overall,'services':result,'period':'24h'}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            return self.response(200, {'ok': True})
        if self.path != '/api/status':
            return self.response(404, {'error': 'not found'})
        try:
            return self.response(200, collect())
        except Exception as exc:
            print('public status error:', type(exc).__name__, str(exc)[:100], flush=True)
            return self.response(503, {'error': 'temporarily unavailable'})

    def response(self, code, obj):
        payload = json.dumps(obj, ensure_ascii=False, separators=(',',':')).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store, max-age=0')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self.response(405, {'error': 'method not allowed'})


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
