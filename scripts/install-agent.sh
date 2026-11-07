#!/bin/sh
set -eu
# KVNRadar agent (local binary + config). Installs systemd service and migrates legacy state.
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
# Avoid two instances probing and writing state simultaneously.
if systemctl list-unit-files lg1-watch-agent.service --no-legend 2>/dev/null | grep -q '^lg1-watch-agent.service'; then
    systemctl stop lg1-watch-agent.service || true
fi
# Copy pending measurements and counters only on first migration.
if [ ! -e /var/lib/kvnradar-agent/state.json ] && [ -f /var/lib/lg1-watch-agent/state.json ]; then
    install -m 0600 -o kvnradar -g kvnradar /var/lib/lg1-watch-agent/state.json /var/lib/kvnradar-agent/state.json
fi
# Override old state_dir so that the new unit can write under /var/lib/kvnradar-agent.
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
# Only disable the old unit after the new one has started successfully.
systemctl disable lg1-watch-agent.service >/dev/null 2>&1 || true
printf 'KVNRadar agent running: systemctl status kvnradar-agent.service\n'
