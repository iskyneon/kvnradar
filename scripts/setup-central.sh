#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p certs auth data
[ -f config/agents.json ] || cp config/agents.example.json config/agents.json
[ -f config/targets.json ] || cp config/targets.example.json config/targets.json
[ -e .env ] || cp .env.example .env
if [ ! -e certs/fullchain.pem ]; then
  echo 'Generating temporary self-signed TLS certificate; replace for production'
  openssl req -x509 -newkey rsa:3072 -nodes -days 14 \
    -keyout certs/privkey.pem -out certs/fullchain.pem -subj '/CN=radar.example.com' -addext 'subjectAltName=DNS:radar.example.com'
fi
if [ ! -e auth/users ]; then
  printf 'Dashboard username [admin]: '; read USERNAME
  USERNAME=${USERNAME:-admin}
  printf 'Dashboard password: '; stty -echo; read PASSWORD; stty echo; printf '\n'
  HASH=$(openssl passwd -6 "$PASSWORD")
  printf '%s:%s\n' "$USERNAME" "$HASH" > auth/users
fi
python3 - <<'PY'
import json,secrets
p='config/agents.json'
a=json.load(open(p))
for k,v in a.items():
 if v=='REPLACE_WITH_A_LONG_RANDOM_TOKEN': a[k]=secrets.token_urlsafe(32)
with open(p,'w') as f: json.dump(a,f,indent=2)
print('Agent tokens initialized in config/agents.json')
PY
chown 10001:10001 data
chmod 700 data
chmod 600 .env config/agents.json certs/privkey.pem auth/users
printf '\nConfigure targets.json and .env; replace the temporary certificate before exposing service.\n'
