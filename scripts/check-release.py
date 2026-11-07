#!/usr/bin/env python3
"""Fail closed if a candidate GitHub source directory contains operational secrets."""
from pathlib import Path
import re,sys
root=Path(sys.argv[1] if len(sys.argv)>1 else Path(__file__).resolve().parents[1])
forbidden_names={'.env','agent.json','privkey.pem','fullchain.pem','users','watch.sqlite3'}
errors=[]
for p in root.rglob('*'):
    if not p.is_file(): continue
    rel=p.relative_to(root)
    if p.name in forbidden_names or any(x in rel.parts for x in ('backups','auth','certs','data','dist','__pycache__')):
        errors.append(f'forbidden file: {rel}')
    if p.suffix in ('.pem','.key','.p12','.pfx','.db','.sqlite','.sqlite3') or re.search(r'\.(?:sqlite3|db)-(?:wal|shm)$',p.name):
        errors.append(f'credential/database extension: {rel}')
    if p.suffix not in ('.py','.js','.go','.html','.css','.sh','.md','.json','.yaml','.yml','.txt','.example') and p.name not in ('.env.example','.gitignore','Dockerfile','go.mod','LICENSE'):
        continue
    try: text=p.read_text()
    except (UnicodeError, OSError): continue
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',text): errors.append(f'private key: {rel}')
    if any(h in text for h in ('.'.join(('watch','lg1','co')),'.'.join(('t','lg1','org')),'.'.join(('chat','lg1','org')),'.'.join(('www','lg1','org')))): errors.append(f'private deployment URL: {rel}')
if errors:
    print('RELEASE SECURITY CHECK FAILED:')
    for e in errors: print(' -',e)
    sys.exit(1)
print('Release directory security checks passed. Review history and all deployed credentials separately.')
