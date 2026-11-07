"""SQLite-configured remote blocklist feeds and locally cached matching.

Feeds use direct, pinned-address HTTPS: no redirects, proxies, credentials,
non-public IPs or DNS rebinding to internal services.
"""
import hashlib
import email_notifications
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_SOURCES = (
    ('antifilter-cidr', 'cidr', 'https://antifilter.download/list/allyouneed.lst'),
    ('antifilter-domains', 'domain', 'https://antifilter.download/list/domains.lst'),
)
MAX_DOWNLOAD = 256 * 1024 * 1024
INTERVAL = max(900, int(os.getenv('BLOCKLIST_UPDATE_SECONDS', '21600')))
STATE = Path(os.getenv('BLOCKLIST_STATE', '/data/blocklists'))
_LOCK = threading.RLock()
_INDEX = None
_WAKE = threading.Event()
_QUEUE = set()


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
    c.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    cols = {r[1] for r in c.execute('PRAGMA table_info(blocklist_sources)')}
    if 'enabled' not in cols:
        c.execute('ALTER TABLE blocklist_sources ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))')
    # One-time upgrade. Never silently restore an intentionally deleted default.
    if not c.execute("SELECT 1 FROM settings WHERE key='blocklist_sources_seeded_v062'").fetchone():
        for name, kind, url in DEFAULT_SOURCES:
            c.execute('INSERT OR IGNORE INTO blocklist_sources(name,kind,url,enabled) VALUES(?,?,?,1)', (name,kind,url))
        c.execute("INSERT INTO settings(key,value) VALUES('blocklist_sources_seeded_v062','1')")


def validate_source(name, kind, url):
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', name):
        raise ValueError('Source ID must contain 1–64 letters, digits, _ or -')
    if kind not in ('cidr', 'domain'):
        raise ValueError('Source type must be cidr or domain')
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('Invalid source URL')
    p = urlsplit(url)
    if (p.scheme != 'https' or not p.hostname or p.username is not None or
            p.password is not None or p.fragment or p.port not in (None, 443)):
        raise ValueError('Source must use HTTPS on port 443 without credentials or fragment')
    try:
        p.hostname.encode('idna')
    except UnicodeError as exc:
        raise ValueError('Invalid hostname') from exc
    return name, kind, url


def _index_changed():
    global _INDEX
    with _LOCK:
        _INDEX = None
    _WAKE.set()


def save_source(dbconnect, name, kind, url, enabled=True, original_name=None):
    validate_source(name, kind, url)
    if type(enabled) is not bool:
        raise ValueError('enabled must be a boolean')
    if original_name is not None and original_name != name:
        raise ValueError('Source ID cannot be renamed; delete and recreate it')
    with dbconnect() as c:
        row = c.execute('SELECT * FROM blocklist_sources WHERE name=?',(name,)).fetchone()
        changed = row is None or row['kind'] != kind or row['url'] != url
        if row:
            enabling = enabled and not row['enabled']
            status = ('disabled' if not enabled else 'pending' if changed or enabling else row['status'])
            c.execute("UPDATE blocklist_sources SET kind=?,url=?,enabled=?,status=?,error=?,records=?,updated_at=?,sha256=? WHERE name=?",
                      (kind,url,int(enabled),status,'' if changed or enabling else row['error'],
                       0 if changed else row['records'],None if changed else row['updated_at'],
                       None if changed else row['sha256'],name))
        else:
            c.execute('INSERT INTO blocklist_sources(name,kind,url,enabled,status) VALUES(?,?,?,?,?)',
                      (name,kind,url,int(enabled),'pending' if enabled else 'disabled'))
    if changed:
        # Cached content from another URL/type must never be reused.
        (STATE/(name+'.txt')).unlink(missing_ok=True)
    _index_changed()
    if enabled and (changed or (row is not None and not row['enabled'])):
        queue_update(name)
    return {'ok':True}


def delete_source(dbconnect, name):
    with dbconnect() as c:
        cur=c.execute('DELETE FROM blocklist_sources WHERE name=?',(name,))
        c.execute('DELETE FROM blocklist_hits WHERE source=?',(name,))
    (STATE/(name+'.txt')).unlink(missing_ok=True)
    _index_changed()
    return {'ok':True,'deleted':cur.rowcount}


def queue_update(name):
    with _LOCK:
        _QUEUE.add(name)
    _WAKE.set()


def parse_feed(kind, content):
    found = set()
    for line in content.decode('utf-8-sig', errors='replace').splitlines():
        s = line.strip().split('#', 1)[0].strip()
        if not s: continue
        if kind == 'cidr':
            try: found.add(str(ipaddress.ip_network(s, strict=False)))
            except ValueError: pass
        else:
            s = s.lower().strip('.').removeprefix('*.')
            if s.startswith(('https://','http://')):
                s = urlsplit(s).hostname or ''
            if len(s) <= 253 and re.fullmatch(r'[a-z0-9][a-z0-9.-]*[a-z0-9]',s): found.add(s)
    return sorted(found)


def _secure_fetch(url):
    # Pin the validated public DNS address to the actual TLS socket; never
    # allow HTTP redirects or proxy environment variables to change the peer.
    p=urlsplit(url)
    host=p.hostname
    addresses=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('Source hostname has no DNS records')
    permitted=[]
    for family,_,_,_,addr in addresses:
        ip=ipaddress.ip_address(addr[0])
        if not ip.is_global:
            raise ValueError('Source DNS contains a non-public IP address')
        if (family,str(ip)) not in permitted:
            permitted.append((family,str(ip)))
    request_path=p.path or '/'
    if p.query: request_path+='?'+p.query
    context=ssl.create_default_context()
    last_error=None
    for family,ip in permitted:
        conn=http.client.HTTPSConnection(host,443,timeout=35,context=context)
        try:
            sock=socket.socket(family,socket.SOCK_STREAM)
            sock.settimeout(35)
            try:
                sock.connect((ip,443))
                conn.sock=context.wrap_socket(sock,server_hostname=host)
            except BaseException:
                sock.close();raise
            conn.request('GET',request_path,headers={'Host':host,'User-Agent':'KVNRadar/0.6.2','Accept':'text/plain','Accept-Encoding':'identity'})
            res=conn.getresponse()
            if res.status!=200:
                raise ValueError('Source returned HTTP '+str(res.status)+'; redirects are not followed')
            data=res.read(MAX_DOWNLOAD+1)
            if len(data)>MAX_DOWNLOAD:
                raise ValueError('Source exceeds 256 MiB')
            return data
        except (OSError,ssl.SSLError) as e:
            last_error=e
        finally:
            conn.close()
    raise ValueError('Cannot connect to source: '+str(last_error)[:120])


def update_one(dbconnect, name, kind, url):
    try:
        validate_source(name,kind,url)
        content=_secure_fetch(url)
        records=parse_feed(kind,content)
        if len(records)<10: raise ValueError('Feed too small; keeping previous version')
        STATE.mkdir(parents=True,exist_ok=True)
        path=STATE/(name+'.txt')
        data=('\n'.join(records)+'\n').encode()
        temp=path.with_suffix('.tmp')
        temp.write_bytes(data)
        with dbconnect() as c:
            # Discard stale downloads when a user edits/removes/disables a feed.
            row=c.execute('SELECT kind,url,enabled FROM blocklist_sources WHERE name=?',(name,)).fetchone()
            if not row or not row['enabled'] or row['url']!=url or row['kind']!=kind:
                temp.unlink(missing_ok=True)
                return 0
            os.replace(temp,path)
            c.execute('UPDATE blocklist_sources SET updated_at=?,sha256=?,records=?,status=?,error=? WHERE name=?',
                      (utcnow(),hashlib.sha256(data).hexdigest(),len(records),'ok','',name))
        _index_changed()
        return len(records)
    except Exception as e:
        with dbconnect() as c:
            c.execute("UPDATE blocklist_sources SET status='error',error=? WHERE name=? AND kind=? AND url=? AND enabled=1",(str(e)[:250],name,kind,url))
        print('blocklist update error',name,type(e).__name__,str(e)[:180],flush=True)
        return 0


def load_index(dbconnect):
    global _INDEX
    with _LOCK:
        if _INDEX is not None: return _INDEX
        domains={}
        networks={4:[],6:[]}
        with dbconnect() as c:
            sources=[dict(r) for r in c.execute('SELECT name,kind FROM blocklist_sources WHERE enabled=1 AND records>0')]
        for src in sources:
            path=STATE/(src['name']+'.txt')
            if not path.is_file(): continue
            for raw in path.read_text().splitlines():
                if src['kind']=='domain': domains.setdefault(raw,set()).add(src['name'])
                else:
                    try:
                        n=ipaddress.ip_network(raw,strict=False)
                        networks[n.version].append((int(n.network_address),int(n.broadcast_address),src['name'],str(n)))
                    except ValueError: pass
        for ver in (4,6): networks[ver].sort(key=lambda x:x[0])
        _INDEX=(domains,networks)
        return _INDEX


def match_host(dbconnect, host, resolve=True):
    host=host.lower().strip().strip('.')
    domains,networks=load_index(dbconnect)
    hits=[]
    for i in range(len(host.split('.'))):
        suffix='.'.join(host.split('.')[i:])
        if suffix in domains:
            for source in sorted(domains[suffix]):
                hits.append({'source':source,'match':suffix,'type':'domain'})
    ips=[]
    try: ips=[str(ipaddress.ip_address(host))]
    except ValueError:
        if resolve and host:
            try: ips=sorted(set(x[4][0] for x in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)))[:12]
            except (OSError,UnicodeError): pass
    for iptext in ips:
        try: addr=ipaddress.ip_address(iptext)
        except ValueError: continue
        for start,end,source,network in networks[addr.version]:
            if start>int(addr): break
            if int(addr)<=end: hits.append({'source':source,'match':network,'type':'cidr','ip':iptext})
    return hits,ips


def scan_resources(dbconnect):
    with dbconnect() as c:
        resources=[dict(r) for r in c.execute('SELECT id,host,rip_exempt FROM resources WHERE enabled=1')]
    for r in resources:
        hits,ips=match_host(dbconnect,r['host'],resolve=os.getenv('BLOCKLIST_RESOLVE_DNS','0')=='1')
        if r['rip_exempt']:
            hits=[h for h in hits if h['type']!='cidr']
        with dbconnect() as c:
            old={(x['source'],x['match']) for x in c.execute('SELECT source,match FROM blocklist_hits WHERE resource_id=?',(r['id'],))}
            c.execute('DELETE FROM blocklist_hits WHERE resource_id=?',(r['id'],))
            for h in hits:
                c.execute('INSERT OR IGNORE INTO blocklist_hits(resource_id,source,match,resolved_ips,checked_at) VALUES(?,?,?,?,?)',
                          (r['id'],h['source'],h['match'],json.dumps(ips),utcnow()))
            new={(h['source'],h['match']) for h in hits}
            if new!=old and (old or new):
                message='KVNRadar | BLOCKLIST CHANGE\nHost: '+r['host']+'\nMatches: '+(', '.join(m for _,m in new) or 'none')
                for channel in (('compass','telegram','email') if email_notifications.enabled() else ('compass','telegram')):
                    c.execute('INSERT INTO outbox(channel,message) VALUES(?,?)',(channel,message))


def snapshot(dbconnect):
    with dbconnect() as c:
        return {'sources':[dict(r) for r in c.execute('SELECT * FROM blocklist_sources ORDER BY name')],
                'hits':[dict(r) for r in c.execute('SELECT * FROM blocklist_hits ORDER BY resource_id,source')]}


def worker(dbconnect, lock, on_update=None):
    STATE.mkdir(parents=True,exist_ok=True)
    next_download=0
    while True:
        try:
            with _LOCK:
                queued=set(_QUEUE)
                _QUEUE.clear()
            due=time.monotonic()>=next_download
            if due or queued:
                with dbconnect() as c:
                    sources=[dict(r) for r in c.execute('SELECT name,kind,url FROM blocklist_sources WHERE enabled=1')]
                for s in sources:
                    if due or s['name'] in queued:
                        update_one(dbconnect,s['name'],s['kind'],s['url'])
                if due: next_download=time.monotonic()+INTERVAL
                if on_update: on_update()
            scan_resources(dbconnect)
        except Exception as e:
            print('blocklist worker error',type(e).__name__,str(e)[:200],flush=True)
        _WAKE.wait(min(300,max(1,next_download-time.monotonic())))
        _WAKE.clear()
