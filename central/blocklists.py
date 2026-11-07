"""Offline matching + independently scheduled full-feed updates.
Only feed URLs are fetched; monitored hostnames are never sent to data providers.
"""
import bisect
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCES = [
    ('antifilter-cidr', 'cidr', 'https://antifilter.download/list/allyouneed.lst'),
    ('antifilter-domains', 'domain', 'https://antifilter.download/list/domains.lst'),
]
MAX_DOWNLOAD = 256 * 1024 * 1024
INTERVAL = max(900, int(os.getenv('BLOCKLIST_UPDATE_SECONDS', '21600')))
STATE = Path(os.getenv('BLOCKLIST_STATE', '/data/blocklists'))
_LOCK = threading.RLock()
_INDEX = None


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def schema(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS blocklist_sources (
        name TEXT PRIMARY KEY, kind TEXT NOT NULL, url TEXT NOT NULL,
        updated_at TEXT, sha256 TEXT, records INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending', error TEXT NOT NULL DEFAULT '');
      CREATE TABLE IF NOT EXISTS blocklist_hits (
        resource_id TEXT NOT NULL, source TEXT NOT NULL, match TEXT NOT NULL,
        resolved_ips TEXT NOT NULL DEFAULT '[]', checked_at TEXT NOT NULL,
        PRIMARY KEY(resource_id,source,match));
      CREATE INDEX IF NOT EXISTS blocklist_hits_resource ON blocklist_hits(resource_id);
    ''')
    for name, kind, url in SOURCES:
        c.execute('INSERT OR IGNORE INTO blocklist_sources(name,kind,url) VALUES(?,?,?)', (name,kind,url))


def parse_feed(kind, content):
    found = set()
    for line in content.decode('utf-8-sig', errors='replace').splitlines():
        s = line.strip().split('#', 1)[0].strip()
        if not s: continue
        if kind == 'cidr':
            try:
                # Normalise to avoid indexing redundant forms of the same network.
                found.add(str(ipaddress.ip_network(s, strict=False)))
            except ValueError: continue
        else:
            s = s.lower().strip('.').removeprefix('*.')
            if s.startswith('http://') or s.startswith('https://'):
                from urllib.parse import urlsplit
                s = urlsplit(s).hostname or ''
            if len(s) <= 253 and re.fullmatch(r'[a-z0-9][a-z0-9.-]*[a-z0-9]', s): found.add(s)
    return sorted(found)


def update_one(dbconnect, name, kind, url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'KVNRadar/0.3 blocklist-fetcher','Accept':'text/plain'})
        with urllib.request.urlopen(req, timeout=35) as response:
            if response.status != 200: raise ValueError('Unexpected HTTP status')
            content = response.read(MAX_DOWNLOAD + 1)
        if len(content) > MAX_DOWNLOAD: raise ValueError('Feed exceeds 256 MiB')
        records = parse_feed(kind, content)
        if len(records) < 10: raise ValueError('Feed too small; keeping previous version')
        STATE.mkdir(parents=True,exist_ok=True)
        path = STATE / (name + '.txt')
        data = ('\n'.join(records)+'\n').encode()
        tmp = path.with_suffix('.tmp')
        tmp.write_bytes(data)
        os.replace(tmp, path)
        digest = hashlib.sha256(data).hexdigest()
        with dbconnect() as c:
            c.execute('UPDATE blocklist_sources SET updated_at=?,sha256=?,records=?,status=?,error=? WHERE name=?',
                      (utcnow(),digest,len(records),'ok','',name))
        with _LOCK:
            global _INDEX
            _INDEX = None
        return len(records)
    except Exception as e:
        with dbconnect() as c:
            c.execute('UPDATE blocklist_sources SET status=?,error=? WHERE name=?',('error',str(e)[:250],name))
        print('blocklist update error',name,repr(e),flush=True)
        return 0


def load_index():
    global _INDEX
    with _LOCK:
        if _INDEX is not None: return _INDEX
        domains = set()
        networks = {4: [], 6: []}
        for name,kind,_ in SOURCES:
            path = STATE/(name+'.txt')
            if not path.is_file(): continue
            for raw in path.read_text().splitlines():
                if kind=='domain': domains.add(raw)
                else:
                    try:
                        n = ipaddress.ip_network(raw,strict=False)
                        networks[n.version].append((int(n.network_address),int(n.broadcast_address),name,str(n)))
                    except ValueError: pass
        # Network sizes are modest; sorting allows early termination for small indexed scans.
        for ver in (4,6): networks[ver].sort(key=lambda p:p[0])
        _INDEX=(domains,networks)
        return _INDEX


def match_host(host, resolve=True):
    host = host.lower().strip().strip('.')
    domains, networks=load_index()
    hits=[]
    labels=host.split('.')
    for i in range(len(labels)):
        suffix='.'.join(labels[i:])
        if suffix in domains:
            hits.append({'source':'antifilter-domains','match':suffix,'type':'domain'})
    ips=[]
    try: ips.append(str(ipaddress.ip_address(host)))
    except ValueError:
        if resolve and host:
            try:
                # WARNING: DNS resolver is local-configured; domain lookup leaves host.
                ips=sorted(set(x[4][0] for x in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)))[:12]
            except (OSError,UnicodeError): pass
    for iptext in ips:
        try: addr=ipaddress.ip_address(iptext)
        except ValueError: continue
        val=int(addr)
        for start,end,source,network in networks[addr.version]:
            if start>val: break
            if val<=end:
                hits.append({'source':source,'match':network,'type':'cidr','ip':iptext})
    return hits,ips


def scan_resources(dbconnect):
    with dbconnect() as c:
        resources=[dict(r) for r in c.execute('SELECT id,host FROM resources WHERE enabled=1')]
    for r in resources:
        hits,ips=match_host(r['host'], resolve=os.getenv('BLOCKLIST_RESOLVE_DNS','0')=='1')
        with dbconnect() as c:
            old={(x['source'],x['match']) for x in c.execute('SELECT source,match FROM blocklist_hits WHERE resource_id=?',(r['id'],))}
            c.execute('DELETE FROM blocklist_hits WHERE resource_id=?',(r['id'],))
            for h in hits:
                c.execute('INSERT OR IGNORE INTO blocklist_hits(resource_id,source,match,resolved_ips,checked_at) VALUES(?,?,?,?,?)',
                          (r['id'],h['source'],h['match'],json.dumps(ips),utcnow()))
            new={(h['source'],h['match']) for h in hits}
            if new != old and (old or new):
                message=f'KVNRadar | BLOCKLIST CHANGE\nHost: {r["host"]}\nMatches: '+(', '.join(m for _,m in new) or 'none')
                for channel in ('compass','telegram'):
                    c.execute('INSERT INTO outbox(channel,message) VALUES(?,?)',(channel,message))


def snapshot(dbconnect):
    with dbconnect() as c:
        return {'sources':[dict(r) for r in c.execute('SELECT * FROM blocklist_sources ORDER BY name')],
                'hits':[dict(r) for r in c.execute('SELECT * FROM blocklist_hits ORDER BY resource_id,source')]}


def worker(dbconnect, lock):
    STATE.mkdir(parents=True,exist_ok=True)
    next_download = 0
    while True:
        try:
            if time.monotonic() >= next_download:
                for name,kind,url in SOURCES:
                    update_one(dbconnect,name,kind,url)
                next_download = time.monotonic() + INTERVAL
            scan_resources(dbconnect)
        except Exception as e: print('blocklist worker error',repr(e),flush=True)
        time.sleep(300)
