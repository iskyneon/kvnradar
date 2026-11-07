#!/usr/bin/env python3
"""KVNRadar MVP coordinator; Python standard library, persistent SQLite."""
import base64
import hmac
import json
import ipaddress
import os
import sqlite3
import socket
import threading
import time
import urllib.request
from urllib.parse import urlparse, parse_qs
import urllib.error
import blocklists
import agent_aliases
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DB = os.getenv('DB_PATH', '/data/watch.sqlite3')
CONFIG = os.getenv('WATCH_CONFIG', '/app/config/targets.json')
AGENTS = os.getenv('AGENTS_FILE', '/app/config/agents.json')
LOCK = threading.RLock()
MAX_BODY = 1024 * 1024

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def readjson(path):
    with open(path, encoding='utf-8') as f: return json.load(f)
def connect():
    con = sqlite3.connect(DB, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA busy_timeout=15000')
    return con

def initdb():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS measurements (
          agent TEXT NOT NULL, event_id TEXT NOT NULL, target TEXT NOT NULL,
          ts TEXT NOT NULL, status TEXT NOT NULL, bytes INTEGER NOT NULL,
          duration_ms INTEGER NOT NULL, http_code INTEGER, error TEXT,
          expected_bytes INTEGER, details TEXT NOT NULL,
          received_at TEXT NOT NULL, PRIMARY KEY(agent,event_id));
        CREATE INDEX IF NOT EXISTS measurements_by_target ON measurements(target, received_at DESC);
        CREATE TABLE IF NOT EXISTS agent_seen (agent TEXT PRIMARY KEY, last_seen TEXT, remote_addr TEXT);
        CREATE TABLE IF NOT EXISTS agent_short_names (agent TEXT PRIMARY KEY, short_name TEXT NOT NULL UNIQUE CHECK(length(short_name)=2));
        CREATE TABLE IF NOT EXISTS resources (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
          url TEXT NOT NULL DEFAULT '', agents TEXT NOT NULL DEFAULT '[]',
          checks TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1,
          updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS incidents (
          agent TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
          changed_at TEXT NOT NULL, PRIMARY KEY(agent,target));
        CREATE TABLE IF NOT EXISTS rkn_matches (target TEXT PRIMARY KEY, matched TEXT NOT NULL, checked_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox (
          id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL,
          message TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          next_attempt INTEGER NOT NULL DEFAULT 0, delivered_at TEXT);
        ''')
        # LG1_PUBLIC_COLUMN_V048: opt-in publication; existing hosts stay private.
        if not any(col[1] == 'public' for col in c.execute('PRAGMA table_info(resources)')):
            c.execute('ALTER TABLE resources ADD COLUMN public INTEGER NOT NULL DEFAULT 0 CHECK(public IN (0,1))')
        # LG1_RIP_EXEMPT_V053: explicit per-resource exception; default remains false.
        if not any(col[1] == 'rip_exempt' for col in c.execute('PRAGMA table_info(resources)')):
            c.execute('ALTER TABLE resources ADD COLUMN rip_exempt INTEGER NOT NULL DEFAULT 0 CHECK(rip_exempt IN (0,1))')
        blocklists.schema(c)
        # LG1_CENTRAL_RIP_RDO_V0415: always-on central-only checks; no agent assignment.
        c.executescript("""
        CREATE TABLE IF NOT EXISTS central_resource_checks (
          resource_id TEXT PRIMARY KEY,
          rip_status TEXT NOT NULL DEFAULT 'UNKNOWN',
          rdo_status TEXT NOT NULL DEFAULT 'UNKNOWN',
          resolved_ips TEXT NOT NULL DEFAULT '[]',
          rip_matches TEXT NOT NULL DEFAULT '[]',
          rdo_matches TEXT NOT NULL DEFAULT '[]',
          checked_at TEXT NOT NULL DEFAULT '',
          error TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS central_resource_check_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          resource_id TEXT NOT NULL,
          rip_status TEXT NOT NULL,
          rdo_status TEXT NOT NULL,
          resolved_ips TEXT NOT NULL DEFAULT '[]',
          rip_matches TEXT NOT NULL DEFAULT '[]',
          rdo_matches TEXT NOT NULL DEFAULT '[]',
          checked_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS central_check_history_resource_time
          ON central_resource_check_history(resource_id,checked_at DESC);
        """)
        if not c.execute('SELECT 1 FROM settings WHERE key=?',('resources_imported',)).fetchone():
            try:
                legacy = readjson(CONFIG).get('targets', [])
                for t in legacy:
                    name = str(t.get('id','legacy'))[:80]
                    kind = str(t.get('type','http'))
                    if kind in ('http','https'):kind='http_content'
                    chk = {kind: {'enabled':True, 'port':t.get('port',443), 'min_bytes':t.get('min_bytes',65536),
                        'interval_sec':t.get('interval_sec',300),'timeout_sec':t.get('timeout_sec',25)}}
                    c.execute('INSERT OR IGNORE INTO resources(id,name,host,url,agents,checks,enabled,updated_at) VALUES(?,?,?,?,?,?,1,?)',
                        (name,name,str(t.get('host') or urlparse(t.get('url','')).hostname or ''),str(t.get('url','')),json.dumps(t.get('agents',[])),json.dumps(chk),now()))
            except Exception as e: print('legacy import failed',repr(e),flush=True)
            c.execute('INSERT INTO settings(key,value) VALUES(?,?)',('resources_imported','1'))

def enqueue(c, message):
    for channel in ('compass', 'telegram'):
        c.execute('INSERT INTO outbox(channel,message) VALUES(?,?)', (channel, message))

def process(c, agent, event):
    if not isinstance(event, dict): return False
    eid = str(event.get('id', ''))[:100]
    target = str(event.get('target', ''))[:200]
    status = str(event.get('status', ''))[:40]
    if not eid or not target or not status: return False
    try:
        bytes_n = max(0, int(event.get('bytes', 0)))
        ms = max(0, int(event.get('duration_ms', 0)))
        http_code = event.get('http_code')
        http_code = int(http_code) if http_code is not None else None
        expected = int(event.get('expected_bytes', 0))
    except (TypeError, ValueError): return False
    details = json.dumps(event.get('details', {}), ensure_ascii=False)[:3000]
    cur = c.execute('''INSERT OR IGNORE INTO measurements
      (agent,event_id,target,ts,status,bytes,duration_ms,http_code,error,expected_bytes,details,received_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''', (agent,eid,target,str(event.get('ts',now()))[:48],status,bytes_n,ms,http_code,
        str(event.get('error',''))[:300],expected,details,now()))
    if cur.rowcount == 0: return True
    # A buffered measurement may arrive after its check has been disabled.
    # Keep the historical measurement but do not reopen its incident or notify.
    if '--' in target:
        resource_id, kind = target.rsplit('--', 1)
        resource_row = c.execute('SELECT enabled,checks,agents FROM resources WHERE id=?',
                                 (resource_id,)).fetchone()
        if resource_row is not None:
            current_checks = json.loads(resource_row['checks'])
            assigned = json.loads(resource_row['agents'])
            if (not resource_row['enabled'] or
                not current_checks.get(kind, {}).get('enabled') or
                (assigned and agent not in assigned)):
                return True
    old = c.execute('SELECT status FROM incidents WHERE agent=? AND target=?',(agent,target)).fetchone()
    if old is None or old['status'] != status:
        c.execute('INSERT INTO incidents(agent,target,status,changed_at) VALUES(?,?,?,?) ON CONFLICT(agent,target) DO UPDATE SET status=excluded.status, changed_at=excluded.changed_at', (agent,target,status,now()))
        if status not in ('OK_FULL','OK_TCP','OK_DNS','OK_ICMP','OK_TLS','OK_HTTP','OK_VPN_PORTAL','OK_TRACE','SHORT_RESPONSE') or (old and old['status'] not in ('OK_FULL','OK_TCP','OK_DNS','OK_ICMP','OK_TLS','OK_HTTP','OK_VPN_PORTAL','OK_TRACE','SHORT_RESPONSE')):
            text = f'KVNRadar | {"RECOVERED" if status.startswith("OK_") else "STATUS CHANGE"}\nTarget: {target}\nAgent: {agent}\nStatus: {status}\nBytes: {bytes_n}/{expected}\nHTTP: {http_code}\nTime: {event.get("ts",now())}\nError: {str(event.get("error",""))[:180]}'
            enqueue(c, text)
    return True

def scan_blocklists():
    """Offline-only comparison: domain suffix and explicitly configured IP addresses.
    This is not proof of an RKN block and never uploads target names.
    """
    directory = Path(os.getenv('BLOCKLIST_DIR','/app/config/blocklists'))
    try:
        domains = set()
        cidrs = []
        for raw in (directory/'domains.txt').read_text().splitlines():
            value = raw.strip().lower().strip('.')
            if value and not value.startswith('#'): domains.add(value)
        for raw in (directory/'cidrs.txt').read_text().splitlines():
            value = raw.strip()
            if value and not value.startswith('#'):
                try: cidrs.append(ipaddress.ip_network(value, strict=False))
                except ValueError: print('invalid CIDR in blocklist',value[:100],flush=True)
        entries = compiled_targets()
        with LOCK,connect() as c:
            for target in entries:
                host = target.get('host') or urlparse(target.get('url','')).hostname or ''
                host = host.strip().lower().strip('.')
                matched = ''
                if host:
                    for suffix in domains:
                        if host == suffix or host.endswith('.'+suffix): matched = 'DOMAIN '+suffix;break
                    if not matched:
                        candidates=[host]+target.get('addresses',[])
                        for value in candidates:
                            try: ip=ipaddress.ip_address(value)
                            except ValueError: continue
                            for network in cidrs:
                                if ip in network: matched='CIDR '+str(network);break
                            if matched:break
                previous=c.execute('SELECT matched FROM rkn_matches WHERE target=?',(target['id'],)).fetchone()
                c.execute('INSERT INTO rkn_matches(target,matched,checked_at) VALUES(?,?,?) ON CONFLICT(target) DO UPDATE SET matched=excluded.matched,checked_at=excluded.checked_at',(target['id'],matched,now()))
                if previous and previous['matched']!=matched:
                    enqueue(c,f'KVNRadar | OFFLINE BLOCKLIST CHANGE\nTarget: {target["id"]}\nMatch: {matched or "none"}')
    except Exception as e: print('offline blocklist scan error',repr(e),flush=True)

# LG1_CENTRAL_RIP_RDO_V0415
CENTRAL_BLOCKLIST_INTERVAL = max(60, int(os.getenv('CENTRAL_BLOCKLIST_INTERVAL','300')))

def scan_rip_rdo_once():
    """Always check each enabled resource against local domain/CIDR feeds centrally.
    Hostnames are resolved by the central server's configured resolver only.
    No resource hostnames/IPs are sent to feed providers or agents.
    """
    try:
        domains, networks = blocklists.load_index()
        with LOCK, connect() as c:
            feed_rows={r['kind']:r['status'] for r in c.execute('SELECT kind,status FROM blocklist_sources')}
            resources=[dict(r) for r in c.execute('SELECT id,host,rip_exempt FROM resources WHERE enabled=1')]
        domain_ready=feed_rows.get('domain')=='ok' and bool(domains)
        cidr_ready=feed_rows.get('cidr')=='ok' and bool(networks[4] or networks[6])
        for resource in resources:
            host=(resource.get('host') or '').strip().lower().strip('.')
            ips=[]; rdo_matches=[]; rip_matches=[]; error=''
            try:
                literal=ipaddress.ip_address(host)
                ips=[str(literal)]
                rdo_status='NA'
            except ValueError:
                literal=None
                if domain_ready:
                    labels=host.split('.')
                    for i in range(len(labels)):
                        suffix='.'.join(labels[i:])
                        if suffix in domains:
                            rdo_matches.append(suffix)
                rdo_status=('BAN' if rdo_matches else 'OK') if domain_ready else 'UNKNOWN'
                try:
                    infos=socket.getaddrinfo(host,None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                    ips=sorted({str(ipaddress.ip_address(item[4][0].split('%')[0])) for item in infos})
                except (OSError,ValueError,UnicodeError) as exc:
                    error='DNS: '+str(exc)[:180]
            if resource.get('rip_exempt'):
                rip_status='EXC'
                rip_matches=[]
            elif cidr_ready and ips:
                for iptext in ips:
                    addr=ipaddress.ip_address(iptext)
                    for start,end,source,network in networks[addr.version]:
                        val=int(addr)
                        if start>val: break
                        if val<=end:
                            rip_matches.append({'ip':iptext,'source':source,'cidr':network})
                rip_status='BAN' if rip_matches else 'OK'
            else:
                rip_status='UNKNOWN'
                if not ips and not error: error='No A/AAAA records'
            checked=now()
            with LOCK, connect() as c:
                c.execute("""INSERT INTO central_resource_checks
                  (resource_id,rip_status,rdo_status,resolved_ips,rip_matches,rdo_matches,checked_at,error)
                  VALUES(?,?,?,?,?,?,?,?)
                  ON CONFLICT(resource_id) DO UPDATE SET rip_status=excluded.rip_status,
                  rdo_status=excluded.rdo_status,resolved_ips=excluded.resolved_ips,
                  rip_matches=excluded.rip_matches,rdo_matches=excluded.rdo_matches,
                  checked_at=excluded.checked_at,error=excluded.error""",
                  (resource['id'],rip_status,rdo_status,json.dumps(ips),json.dumps(rip_matches),
                   json.dumps(rdo_matches),checked,error))
                c.execute("""INSERT INTO central_resource_check_history
                  (resource_id,rip_status,rdo_status,resolved_ips,rip_matches,rdo_matches,checked_at)
                  VALUES(?,?,?,?,?,?,?)""",
                  (resource['id'],rip_status,rdo_status,json.dumps(ips),json.dumps(rip_matches),
                   json.dumps(rdo_matches),checked))
                c.execute("DELETE FROM central_resource_check_history WHERE checked_at < datetime('now','-90 days')")
        # Remove stale rows for resources that were deleted or disabled.
        with LOCK, connect() as c:
            c.execute('DELETE FROM central_resource_checks WHERE resource_id NOT IN (SELECT id FROM resources WHERE enabled=1)')
    except Exception as exc:
        print('central RIP/RDO scan error:',type(exc).__name__,str(exc)[:200],flush=True)

def central_rip_rdo_worker():
    while True:
        scan_rip_rdo_once()
        time.sleep(CENTRAL_BLOCKLIST_INTERVAL)

def scan_forever():
    while True:
        scan_blocklists()
        time.sleep(1800)

def notify(channel, msg):
    if channel == 'telegram':
        token = os.getenv('TELEGRAM_TOKEN','')
        chat = os.getenv('TELEGRAM_CHAT_ID','')
        if not token or not chat: return None
        base = os.getenv('TELEGRAM_API_BASE_URL', 'https://api.telegram.org').strip().rstrip('/')
        parsed = urlparse(base)
        if parsed.scheme != 'https' or not parsed.netloc or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise RuntimeError('TELEGRAM_API_BASE_URL must be a valid HTTPS base URL without credentials/query/fragment')
        url = base+'/bot'+token+'/sendMessage'
        body = {'chat_id': chat, 'text': msg[:4000]}
        headers = {'Content-Type':'application/json'}
    else:
        base = os.getenv('COMPASS_BASE_URL','').rstrip('/')
        token = os.getenv('COMPASS_BOT_TOKEN','')
        group = os.getenv('COMPASS_GROUP_ID','')
        if not base or not token or not group: return None
        url = base+'/userbot/api/v3/group/send'
        body = {'group_id':group,'type':'text','text':msg[:4000]}
        headers = {'Content-Type':'application/json','Authorization':'Bearer '+token}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=8) as response:
        result = response.read(4096)
        if response.status >= 300: raise RuntimeError('HTTP '+str(response.status))
        payload = json.loads(result)
        if channel == 'telegram' and not payload.get('ok'): raise RuntimeError('Telegram API error')
        if channel == 'compass' and payload.get('status') != 'ok': raise RuntimeError('Compass API error')
    return True

def dispatch_forever():
    while True:
        try:
            with LOCK, connect() as c:
                rows = c.execute('SELECT * FROM outbox WHERE delivered_at IS NULL AND next_attempt<=? ORDER BY id LIMIT 10',(int(time.time()),)).fetchall()
            for row in rows:
                try:
                    result = notify(row['channel'],row['message'])
                    with LOCK, connect() as c:
                        if result is None:
                            # Not configured: keep queued, revisit after configuration changes
                            c.execute('UPDATE outbox SET next_attempt=? WHERE id=?',(int(time.time())+3600,row['id']))
                        else:
                            c.execute('UPDATE outbox SET delivered_at=? WHERE id=?',(now(),row['id']))
                except Exception as e:
                    print('notification error:',row['channel'],str(e)[:160], flush=True)
                    with LOCK, connect() as c:
                        attempts = row['attempts']+1
                        c.execute('UPDATE outbox SET attempts=?,next_attempt=? WHERE id=?',(attempts,int(time.time())+min(3600,30*(2**min(attempts,7))),row['id']))
        except Exception as e: print('dispatcher error:',str(e),flush=True)
        time.sleep(10)

HTML = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KVNRadar</title><style>body{background:#10141c;color:#e9edf4;font:15px system-ui;margin:0}main{max-width:1200px;margin:45px auto;padding:0 24px}h1{font-size:30px}.muted{color:#a1adbf}table{width:100%;border-collapse:collapse;background:#19212d;border-radius:12px;overflow:hidden}td,th{padding:13px;text-align:left;border-bottom:1px solid #303a48}th{color:#aebdd0}code{color:#b8daff}.ok{color:#6ed89b}.bad{color:#ff9d83}.card{display:inline-block;background:#19212d;padding:18px 26px;border-radius:10px;margin:0 10px 20px 0}a{color:#a9cfff}</style><main><h1>KVNRadar</h1><p class="muted">Локальная система мониторинга · обновление каждые 30 секунд</p><section id="cards"></section><h2>Последние результаты</h2><table><thead><tr><th>Время</th><th>Агент</th><th>Ресурс</th><th>Статус</th><th>Байты</th><th>Время</th></tr></thead><tbody id="results"></tbody></table><h2>Агенты</h2><table><thead><tr><th>Агент</th><th>Последняя связь</th></tr></thead><tbody id="agents"></tbody></table><script>function safe(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}async function refresh(){try{let d=await(await fetch('/ui/data',{cache:'no-store'})).json();document.getElementById('cards').innerHTML='<div class="card">Агентов: <b>'+d.agents.length+'</b></div><div class="card">Последних измерений: <b>'+d.recent.length+'</b></div><div class="card">Неотправленных уведомлений: <b>'+d.pending+'</b></div>';document.getElementById('results').innerHTML=d.recent.map(x=>'<tr><td>'+safe(x.ts)+'</td><td>'+safe(x.agent)+'</td><td>'+safe(x.target)+'</td><td class="'+(x.status.startsWith('OK_')?'ok':'bad')+'">'+safe(x.status)+'</td><td>'+safe(x.bytes)+'</td><td>'+safe(x.duration_ms)+' ms</td></tr>').join('');document.getElementById('agents').innerHTML=d.agents.map(x=>'<tr><td>'+safe(x.agent)+'</td><td>'+safe(x.last_seen)+'</td></tr>').join('')}catch(e){console.warn(e)}}refresh();setInterval(refresh,30000)</script></main></html>'''

# LG1_DISABLE_SSL_VPN_0411: VPN probe retired; legacy rows retained as history.
# LG1_HTTP_PORTS_V0413: independent HTTP and HTTPS checks; existing agents use http_status.
CHECK_TYPES = ('icmp','dns','tcp','tls','http_plain','http_status','http_content','traceroute')

def list_resources():
    with LOCK,connect() as c:
        rows=[dict(r) for r in c.execute('SELECT * FROM resources ORDER BY name COLLATE NOCASE')]
    for r in rows:
        r['agents']=json.loads(r['agents']);r['checks']=json.loads(r['checks']);r['enabled']=bool(r['enabled']);r['public']=bool(r.get('public',0));r['rip_exempt']=bool(r.get('rip_exempt',0))
    return rows

def validate_resource(r):
    import re
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}',str(r.get('id',''))): return False,'Invalid resource ID'
    if not str(r.get('name','')).strip() or len(str(r['name']))>100:return False,'Invalid name'
    if not str(r.get('host','')).strip() or len(str(r['host']))>253:return False,'Invalid host'
    if type(r.get('public',False)) is not bool:return False,'Invalid public flag'
    if len(str(r.get('url','')))>2048:return False,'URL too long'
    if r.get('url') and urlparse(r['url']).scheme not in ('http','https'):return False,'Only HTTP(S) URLs'
    if not isinstance(r.get('agents',[]),list) or any(not isinstance(a,str) for a in r['agents']):return False,'Invalid agents'
    chk=r.get('checks')
    if not isinstance(chk,dict) or any(k not in CHECK_TYPES for k in chk):return False,'Invalid checks'
    for k,v in chk.items():
        if not isinstance(v,dict):return False,'Invalid check settings'
        if 'path' in v and (not isinstance(v['path'],str) or not v['path'].startswith('/') or v['path'].startswith('//') or len(v['path'])>512):return False,'Invalid HTTP path'
        for field,lo,hi in (('port',1,65535),('interval_sec',60,86400),('timeout_sec',1,120),('min_bytes',1,4194304)):
            if field in v and (type(v[field]) is not int or not lo<=v[field]<=hi):return False,'Invalid '+field
    return True,''

def compiled_targets():
    out=[]
    for r in list_resources():
        if not r['enabled']:continue
        for kind,options in r['checks'].items():
            if kind == 'ssl_vpn':continue  # retired, even before migration
            if not options.get('enabled'):continue
            x={'id':r['id']+'--'+kind, 'resource':r['id'], 'type':kind,
               'url':r['url'], 'host':r['host'], 'agents':r['agents'],
               'port':options.get('port',443),
               'min_bytes':options.get('min_bytes',65536),
               'interval_sec':options.get('interval_sec',300),
               'timeout_sec':options.get('timeout_sec',25)}
            # Per-check HTTP destinations. Never require a resource-level URL.
            # Target ID remains stable for existing HTTPS checks; plain HTTP gets a new ID.
            if kind in ('http_plain','http_status','http_content'):
                scheme = 'http' if kind == 'http_plain' else 'https'
                legacy = urlparse(r.get('url',''))
                legacy_same_scheme = legacy.scheme == scheme
                default_port = 80 if scheme == 'http' else 443
                # Backward compatible: old HTTPS URL port/path remain until user edits the check.
                try:
                    legacy_port = legacy.port if legacy_same_scheme else None
                except ValueError:
                    legacy_port = None
                port = options.get('port', legacy_port or default_port)
                path = options.get('path')
                if path is None:
                    path = (legacy.path or '/') if legacy_same_scheme else '/'
                    if legacy_same_scheme and legacy.query:
                        path += '?' + legacy.query
                if not isinstance(path,str) or not path.startswith('/') or path.startswith('//'):
                    path = '/'
                # IPv6 host needs brackets in the URL authority.
                host = r['host']
                authority = '[' + host + ']' if ':' in host and not host.startswith('[') else host
                x['url'] = f'{scheme}://{authority}:{port}{path}'
                x['port'] = int(port)
                # Go probe currently uses http_status to check status for both schemes.
                if kind == 'http_plain':
                    x['type'] = 'http_status'
            out.append(x)
    return out

# LG1_BLOCKLISTS_CENTRAL_MATCHES_V04151
def central_blocklist_matches():
    """Current RIP/RDO BANs, derived from the persisted central scan results."""
    out=[]
    with LOCK, connect() as c:
        rows=c.execute("""SELECT x.resource_id,r.name,r.host,x.rip_status,x.rdo_status,
            x.rip_matches,x.rdo_matches,x.checked_at
            FROM central_resource_checks x JOIN resources r ON r.id=x.resource_id
            WHERE r.enabled=1 AND (x.rip_status='BAN' OR x.rdo_status='BAN')
            ORDER BY r.name COLLATE NOCASE""").fetchall()
    for row in rows:
        x=dict(row)
        for code,status,key in (('RIP',x['rip_status'],'rip_matches'),('RDO',x['rdo_status'],'rdo_matches')):
            if status!='BAN':
                continue
            try: matches=json.loads(x.get(key) or '[]')
            except (TypeError,ValueError): matches=[]
            if not matches: matches=[{'match':'BAN detected; detail unavailable'}]
            for match in matches:
                if isinstance(match,dict):
                    detail=match.get('cidr') or match.get('domain') or match.get('ip') or match.get('match') or json.dumps(match,ensure_ascii=False)
                    source=match.get('source') or 'Local blocklist'
                else:
                    detail=str(match); source='Local blocklist'
                out.append({'resource_id':x['resource_id'],'resource_name':x['name'],
                    'hostname':x['host'],'type':code,'source':source,'match':detail,
                    'checked_at':x['checked_at']})
    return out

# Explicit allowlist: do not return os.environ, .env, token names or identifiers.
# Network endpoints are reduced to a safe hostname; any URL userinfo, path,
# query and fragment (which might contain credentials) are discarded.
def readonly_environment():
    from urllib.parse import urlsplit
    specs = [
        ('CENTRAL_BLOCKLIST_INTERVAL', '300', 'seconds'),
        ('BLOCKLIST_UPDATE_SECONDS', '21600', 'seconds'),
        ('BLOCKLIST_RESOLVE_DNS', '0', 'boolean'),
        ('PORT', '8080', 'port'),
    ]
    result = []
    for key, default, kind in specs:
        raw = os.environ.get(key, default)
        if kind in ('seconds','port'):
            try:
                val = str(int(raw)) if 0 <= int(raw) <= 864000 else default
            except (ValueError, TypeError):
                val = default
        else:
            val = 'enabled' if raw.strip().lower() in ('1','true','yes','on') else 'disabled'
        result.append({'key':key,'value':val,'source':'environment' if key in os.environ else 'default'})
    # No raw URLs: private endpoints can contain credentials in path/query/userinfo.
    for key in ('COMPASS_BASE_URL', 'TELEGRAM_API_BASE_URL'):
        raw = os.environ.get(key, '')
        try:
            parsed = urlsplit(raw)
            host = parsed.hostname
            if parsed.scheme in ('https','http') and host and len(host) <= 253:
                value = parsed.scheme + '://' + host + ((':' + str(parsed.port)) if parsed.port else '')
            else:
                value = 'not set'
        except (ValueError, TypeError):
            value = 'not set'
        result.append({'key':key,'value':value,'source':'environment' if raw else 'default'})
    return {'version':'0.6.1','entries':result,
            'notifications':{'compass':bool(os.getenv('COMPASS_BASE_URL') and os.getenv('COMPASS_BOT_TOKEN') and os.getenv('COMPASS_GROUP_ID')),
                             'telegram':bool(os.getenv('TELEGRAM_TOKEN') and os.getenv('TELEGRAM_CHAT_ID'))}}

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, fmt, *args): print('%s %s' %(self.address_string(),fmt%args),flush=True)
    def reply(self, status, body, mime='application/json'):
        raw = body if isinstance(body,bytes) else body.encode() if isinstance(body,str) else json.dumps(body,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime+'; charset=utf-8')
        self.send_header('Content-Length',str(len(raw)))
        self.send_header('Cache-Control','no-store')
        self.send_header('Connection','close')
        self.end_headers(); self.wfile.write(raw); self.close_connection=True
    def do_POST(self):
        if self.path.startswith('/ui/api/'):
            return self.admin_post()
        if self.path != '/api/sync': return self.reply(404, {'error':'not found'})
        try:
            length = int(self.headers.get('Content-Length','0'))
            if not 0 < length <= MAX_BODY: return self.reply(413,{'error':'invalid body size'})
            request = json.loads(self.rfile.read(length))
            agent = request.get('agent','')
            configured = readjson(AGENTS)
            key = configured.get(agent,'')
            bearer = self.headers.get('Authorization','').removeprefix('Bearer ')
            if not key or not hmac.compare_digest(key,bearer): return self.reply(401,{'error':'unauthorized'})
            events = request.get('events',[])
            if not isinstance(events,list) or len(events)>100: return self.reply(400,{'error':'invalid event count'})
            accepted=[]
            with LOCK,connect() as c:
                c.execute('INSERT INTO agent_seen(agent,last_seen,remote_addr) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET last_seen=excluded.last_seen,remote_addr=excluded.remote_addr',(agent,now(),self.headers.get('X-Real-IP',self.client_address[0])[:80]))
                for e in events:
                    if process(c,agent,e): accepted.append(str(e['id']))
            targets = [t for t in compiled_targets() if not t.get('agents') or agent in t['agents']]
            return self.reply(200, {'accepted':accepted,'targets':targets,'config_version':2,'server_time':now()})
        except (ValueError,KeyError,TypeError,json.JSONDecodeError) as e:
            return self.reply(400,{'error':'invalid request'})
        except Exception as e:
            print('sync error',repr(e),flush=True);return self.reply(500,{'error':'internal error'})
    def admin_post(self):
        if self.headers.get('X-KVNRadar-Admin') != '1': return self.reply(403,{'error':'admin header required'})
        try:
            if self.path not in ('/ui/api/resources/save','/ui/api/resources/delete','/ui/api/agents/short-name'):
                return self.reply(404,{'error':'not found'})
            length=int(self.headers.get('Content-Length','0'))
            if length <= 0 or length > 65536: return self.reply(413,{'error':'body too large'})
            obj=json.loads(self.rfile.read(length))
            if self.path == '/ui/api/agents/short-name':
                with LOCK, connect() as c:
                    short = agent_aliases.set_alias(c, obj.get('agent'), obj.get('short_name'))
                return self.reply(200, {'ok': True, 'short_name': short})
            rid=str(obj.get('id',''))
            if self.path.endswith('/delete'):
                with LOCK,connect() as c: c.execute('DELETE FROM resources WHERE id=?',(rid,))
                return self.reply(200,{'ok':True})
            valid,err=validate_resource(obj)
            if not valid: return self.reply(400,{'error':err})
            with LOCK,connect() as c:
                c.execute('''INSERT INTO resources(id,name,host,url,agents,checks,enabled,updated_at,public,rip_exempt)
                    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                    host=excluded.host,url=excluded.url,agents=excluded.agents,checks=excluded.checks,
                    enabled=excluded.enabled,updated_at=excluded.updated_at,public=excluded.public,
                    rip_exempt=excluded.rip_exempt''',
                    (rid,obj['name'],obj['host'],obj.get('url',''),json.dumps(obj.get('agents',[])),
                     json.dumps(obj['checks']),int(obj.get('enabled',True)),now(),int(obj.get('public',False)),int(obj.get('rip_exempt',False))))
            return self.reply(200,{'ok':True})
        except Exception as e:
            print('admin error',repr(e),flush=True)
            return self.reply(400,{'error':str(e)[:160]})

    def do_GET(self):
        if self.path in ("/ui/static/app.css", "/ui/static/app.js", "/ui/static/private-overview.js", "/ui/static/private-overview.css", "/ui/static/i18n.js", "/ui/static/settings.js"):
            name = self.path.rsplit("/", 1)[-1]
            path = Path("/app/static") / name
            try:
                content = path.read_bytes()
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "text/css; charset=utf-8" if name.endswith(".css")
                    else "application/javascript; charset=utf-8"
                )
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_error(404)
            return

        if self.path=='/ui/api/settings': return self.reply(200,readonly_environment())
        if self.path=='/ui/api/private-status':
            import private_status
            try:
                return self.reply(200, private_status.collect(db_path=DB))
            except Exception as exc:
                print('private overview API failed', repr(exc), flush=True)
                return self.reply(500, {'error':'status unavailable'})
        if self.path=='/health': return self.reply(200,{'ok':True})
        if self.path=='/': return self.reply(200,Path(__file__).with_name('ui.html').read_text(encoding='utf-8'),'text/html')
        if self.path=='/ui/api/resources': return self.reply(200,{'resources':list_resources()})
        if self.path=='/ui/api/blocklists':
            snap=blocklists.snapshot(connect)
            snap['central_matches']=central_blocklist_matches()
            return self.reply(200,snap)
        if self.path.startswith('/ui/api/results'):
            q=parse_qs(urlparse(self.path).query)
            rid=q.get('resource',[''])[0]
            with LOCK,connect() as c:
                if rid:
                    rows=[dict(x) for x in c.execute('SELECT * FROM measurements WHERE target LIKE ? ORDER BY received_at DESC,rowid DESC LIMIT 500',(rid+'--%',))]
                else:
                    rows=[dict(x) for x in c.execute('SELECT * FROM measurements ORDER BY received_at DESC,rowid DESC LIMIT 250')]
            return self.reply(200,{'results':rows})
        if self.path=='/ui/api/current':
            # A point-in-time result for EACH configured check and agent.
            # Unlike /ui/data, no global LIMIT 100 hides less frequent checks.
            configured = list_resources()
            targets = [r['id'] + '--' + kind
                       for r in configured if r.get('enabled')
                       for kind, opts in (r.get('checks') or {}).items()
                       if isinstance(opts, dict) and opts.get('enabled')]
            current = []
            if targets:
                # Fixed-size batches avoid SQLite's SQL variable limit.
                with LOCK, connect() as c:
                    for start in range(0, len(targets), 400):
                        part = targets[start:start + 400]
                        marks = ','.join('?' for _ in part)
                        query = ("SELECT agent,target,ts,status,bytes,duration_ms,received_at "
                                 "FROM (SELECT agent,target,ts,status,bytes,duration_ms,received_at, "
                                 "ROW_NUMBER() OVER (PARTITION BY target,agent "
                                 "ORDER BY received_at DESC,rowid DESC) AS rank "
                                 "FROM measurements WHERE target IN (" + marks + ")) "
                                 "WHERE rank=1")
                        current.extend(dict(x) for x in c.execute(query, part))
            return self.reply(200, {'current': current})
        if self.path=='/ui/data':
            with LOCK,connect() as c:
                recent=[dict(x) for x in c.execute('SELECT agent,target,ts,status,bytes,duration_ms FROM measurements ORDER BY received_at DESC,rowid DESC LIMIT 100')]
                agents=[dict(x) for x in c.execute('SELECT agent,last_seen FROM agent_seen ORDER BY agent')]
                agent_aliases_map=agent_aliases.aliases_for_agents(c, [a['agent'] for a in agents])
                pending=c.execute('SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL').fetchone()[0]
                blocks=[dict(x) for x in c.execute("SELECT target,matched,checked_at FROM rkn_matches WHERE matched <> '' ORDER BY target")]
            with LOCK,connect() as c:
                central_checks={x['resource_id']:dict(x) for x in c.execute('SELECT * FROM central_resource_checks')}
            return self.reply(200,{'recent':recent,'agents':agents,'agent_short_names':agent_aliases_map,'pending':pending,'blocklist_matches':blocks,'resources':list_resources(), 'blocklists':{**blocklists.snapshot(connect),'central_matches':central_blocklist_matches()}, 'central_checks':central_checks})
        return self.reply(404,{'error':'not found'})

if __name__=='__main__':
    initdb()
    threading.Thread(target=dispatch_forever,daemon=True).start()
    threading.Thread(target=blocklists.worker,args=(connect,LOCK),daemon=True).start()
    threading.Thread(target=central_rip_rdo_worker,daemon=True).start()
    port=int(os.getenv('PORT','8080'))
    print(f'KVNRadar listening on 127.0.0.1:{port} (proxy required)',flush=True)
    ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever()
