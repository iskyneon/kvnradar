"""One-shot inspections: central cached RIP/RDO lookup and agent sync jobs.

Inspect results are intentionally separate from measurements, incidents and outbox.
Existing Go agents support these targets through the normal pull-only sync protocol.
"""
import ipaddress
import json
import re
import socket
import time
import uuid
from datetime import datetime, timezone

import blocklists

KINDS = {'tcp', 'tls', 'https', 'dpi'}
TTL_SEC = 1800
ID_PREFIX = '__kvn_inspect_'
TARGET_PATTERN = re.compile(r'^__kvn_inspect_([a-f0-9]{32})__(tcp|tls|https|dpi)$')
DOMAIN_PATTERN = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$')


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def schema(c):
    c.execute('''CREATE TABLE IF NOT EXISTS inspect_jobs (
      id TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL,
      agent TEXT, checks TEXT NOT NULL DEFAULT '[]',
      requested_at TEXT NOT NULL, expires_at INTEGER NOT NULL,
      state TEXT NOT NULL, dispatched_at TEXT,
      results TEXT NOT NULL DEFAULT '{}', rip TEXT NOT NULL DEFAULT '{}', rdo TEXT NOT NULL DEFAULT '{}'
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS inspect_jobs_created ON inspect_jobs(requested_at DESC)')


def valid_host(raw):
    if not isinstance(raw, str):
        raise ValueError('Host or IP is required')
    host = raw.strip().lower().rstrip('.')
    if not host or len(host) > 253 or any(x in host for x in ':/?#@\\') and ':' not in host:
        raise ValueError('Enter a hostname or IP address, not a URL')
    try:
        return str(ipaddress.ip_address(host.strip('[]')))
    except ValueError:
        if not DOMAIN_PATTERN.fullmatch(host):
            raise ValueError('Invalid hostname or IP address')
        return host


def check_central(dbconnect, host):
    """Use current in-memory cached lists (SQLite source config); no remote feed download."""
    host = valid_host(host)
    with dbconnect() as c:
        src = [dict(x) for x in c.execute('SELECT name,kind,records FROM blocklist_sources WHERE enabled=1 AND records>0')]
    domain_sources = any(x['kind'] == 'domain' for x in src)
    cidr_sources = any(x['kind'] == 'cidr' for x in src)
    try:
        hits, ips = blocklists.match_host(dbconnect, host, resolve=True)
    except Exception as exc:
        raise ValueError('Cannot read cached blocklists') from exc
    rip_hits = [x for x in hits if x['type'] == 'cidr']
    rdo_hits = [x for x in hits if x['type'] == 'domain']
    # No A/AAAA data means an IP verdict is not known, even with healthy feeds.
    rip_status = 'BAN' if rip_hits else 'OK' if cidr_sources and ips else 'UNKNOWN'
    try:
        ipaddress.ip_address(host)
        domain = False
    except ValueError:
        domain = True
    rdo_status = 'BAN' if rdo_hits else 'OK' if domain_sources and domain else 'UNKNOWN'
    return ({'status':rip_status,'matches':rip_hits,'ips':ips},
            {'status':rdo_status,'matches':rdo_hits})


def _validate_checks(checks):
    if not isinstance(checks, list) or not checks or len(checks) > 4:
        raise ValueError('Choose at least one check')
    if any(not isinstance(k, str) or k not in KINDS for k in checks) or len(set(checks)) != len(checks):
        raise ValueError('Invalid checks')
    return checks


def create(dbconnect, obj, configured_agents):
    host = valid_host(obj.get('host'))
    port = obj.get('port', 443)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Port must be 1..65535')
    use_agent = obj.get('use_agent', False)
    if type(use_agent) is not bool:
        raise ValueError('Invalid agent option')
    if use_agent:
        agent = obj.get('agent')
        if not isinstance(agent, str) or agent not in configured_agents:
            raise ValueError('Select a configured agent')
        checks = _validate_checks(obj.get('checks'))
    else:
        agent = None
        checks = []
    rip, rdo = check_central(dbconnect, host)
    run_id = uuid.uuid4().hex
    with dbconnect() as c:
        # Bound queued workload; prevents denial of service through admin UI.
        if use_agent:
            queued = c.execute("SELECT COUNT(*) FROM inspect_jobs WHERE agent=? AND state IN ('queued','dispatched') AND expires_at>?", (agent,int(time.time()))).fetchone()[0]
            if queued >= 3:
                raise ValueError('This agent already has three pending inspection jobs')
        c.execute('''INSERT INTO inspect_jobs
            (id,host,port,agent,checks,requested_at,expires_at,state,rip,rdo)
            VALUES(?,?,?,?,?,?,?,?,?,?)''',
            (run_id,host,port,agent,json.dumps(checks),utc(),int(time.time())+TTL_SEC,
             'queued' if use_agent else 'complete',json.dumps(rip),json.dumps(rdo)))
        c.execute("DELETE FROM inspect_jobs WHERE expires_at < ?",(int(time.time())-7*86400,))
    return read_job(dbconnect, run_id)


def _row(x):
    d = dict(x)
    for key in ('checks','results','rip','rdo'):
        d[key] = json.loads(d[key])
    return d


def read_job(dbconnect, run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r'[a-f0-9]{32}', run_id):
        return None
    with dbconnect() as c:
        row = c.execute('SELECT * FROM inspect_jobs WHERE id=?',(run_id,)).fetchone()
        if not row:
            return None
        job = _row(row)
        if job['state'] in ('queued','dispatched') and job['expires_at'] < time.time():
            c.execute("UPDATE inspect_jobs SET state='expired' WHERE id=?",(run_id,))
            job['state']='expired'
    return job


def recent_jobs(dbconnect):
    with dbconnect() as c:
        ids=[x[0] for x in c.execute('SELECT id FROM inspect_jobs ORDER BY requested_at DESC LIMIT 15')]
    return [j for rid in ids if (j:=read_job(dbconnect,rid))]


def dispatch(dbconnect, agent):
    """One-time assignment in the normal agent sync response; never sent twice."""
    now_sec=int(time.time())
    out=[]
    with dbconnect() as c:
        rows=c.execute("SELECT * FROM inspect_jobs WHERE agent=? AND state='queued' AND expires_at>? ORDER BY requested_at LIMIT 3",(agent,now_sec)).fetchall()
        for row in rows:
            job=_row(row)
            for kind in job['checks']:
                port=job['port']
                host=job['host']
                host_url='['+host+']' if ':' in host else host
                typ={'https':'http_status','dpi':'http_content'}.get(kind,kind)
                out.append({'id':f"{ID_PREFIX}{job['id']}__{kind}",'type':typ,'host':host,'port':port,
                            'url':f'https://{host_url}:{port}/' if kind in ('https','dpi') else '',
                            'interval_sec':60,'timeout_sec':25,'min_bytes':65536 if kind=='dpi' else 0,
                            'agents':[agent]})
            c.execute("UPDATE inspect_jobs SET state='dispatched',dispatched_at=? WHERE id=? AND state='queued'",(utc(),job['id']))
    return out


def consume_event(c, agent, event):
    """Returns None for regular measurements, bool for an inspect result."""
    target=event.get('target') if isinstance(event,dict) else None
    if not isinstance(target,str) or not target.startswith(ID_PREFIX):
        return None
    m=TARGET_PATTERN.fullmatch(target)
    if not m:
        return False
    rid,kind=m.groups()
    row=c.execute('SELECT * FROM inspect_jobs WHERE id=? AND agent=?',(rid,agent)).fetchone()
    if not row or row['state'] not in ('dispatched','complete') or row['expires_at'] < time.time():
        return False
    checks=json.loads(row['checks'])
    if kind not in checks or not isinstance(event.get('status'),str):
        return False
    results=json.loads(row['results'])
    # Idempotent with agent re-delivery; don't replace a completed measurement.
    if kind not in results:
        details=event.get('details',{})
        if not isinstance(details,dict): details={}
        selected={str(k)[:64]:v for k,v in list(details.items())[:20] if isinstance(v,(str,int,float,bool,type(None),dict))}
        metadata=selected if len(json.dumps(selected,ensure_ascii=False)) <= 3000 else {'note':'metadata truncated'}
        results[kind]={'status':str(event['status'])[:40],
                       'bytes':max(0,int(event.get('bytes',0))),
                       'expected_bytes':max(0,int(event.get('expected_bytes',0))),
                       'duration_ms':max(0,int(event.get('duration_ms',0))),
                       'http_code':event.get('http_code'),
                       'error':str(event.get('error',''))[:300],
                       'details':metadata,
                       'received_at':utc()}
    state='complete' if len(results)==len(checks) else 'dispatched'
    c.execute('UPDATE inspect_jobs SET results=?,state=? WHERE id=?',(json.dumps(results),state,rid))
    return True
