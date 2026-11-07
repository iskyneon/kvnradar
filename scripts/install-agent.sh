#!/bin/sh
set -eu
# KVNRadar agent (local binary + config). Installs the native systemd service.
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root' >&2; exit 1; fi
if [ "$#" -ne 2 ]; then echo 'Usage: install-agent.sh /path/to/kvnradar-agent-linux-amd64 /path/to/agent.json' >&2; exit 2; fi
BIN="$(realpath "$1")"
CONFIG="$(realpath "$2")"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test -f "$BIN" && test -f "$CONFIG"
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 1; }
# Fail before making service changes on invalid agent config.
python3 - "$CONFIG" <<'PYCONFIG'
import json,sys
c=json.load(open(sys.argv[1]))
for key in ('agent','token','server'):
    if not isinstance(c.get(key),str) or not c[key]: raise SystemExit('Missing '+key)
PYCONFIG
id kvnradar >/dev/null 2>&1 || useradd --system --home-dir /var/lib/kvnradar-agent --shell /usr/sbin/nologin kvnradar
install -d -m 0700 -o kvnradar -g kvnradar /var/lib/kvnradar-agent
install -d -m 0750 -o root -g kvnradar /etc/kvnradar
# Set an isolated writable state directory for the service.
python3 - "$CONFIG" /etc/kvnradar/agent.json <<'PYCONFIG'
import json,sys,os
with open(sys.argv[1]) as f: d=json.load(f)
d['state_dir']='/var/lib/kvnradar-agent'
with open(sys.argv[2],'w') as f: json.dump(d,f,indent=2);f.write('\n')
PYCONFIG
chown root:kvnradar /etc/kvnradar/agent.json
chmod 0640 /etc/kvnradar/agent.json
install -m 0755 "$BIN" /usr/local/bin/kvnradar-agent
install -m 0644 "$ROOT/deploy/kvnradar-agent.service" /etc/systemd/system/kvnradar-agent.service
systemctl daemon-reload
systemctl enable kvnradar-agent.service >/dev/null
systemctl restart kvnradar-agent.service
if ! systemctl is-active --quiet kvnradar-agent.service; then
    journalctl -u kvnradar-agent.service --no-pager -n 30 >&2
    exit 1
fi
printf 'KVNRadar agent running: systemctl status kvnradar-agent.service\n'
