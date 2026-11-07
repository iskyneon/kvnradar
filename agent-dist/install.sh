#!/usr/bin/env bash
# KVNRadar remote agent bootstrap. Download via HTTPS, run as root.
set -Eeuo pipefail
umask 077
BASE_URL="${KVNRADAR_DIST_URL:-https://radar.example.com:18081/agent}"
SERVER_URL="${KVNRADAR_SERVER_URL:-https://radar.example.com:18080}"
AGENT_NAME=""
SYNC_SECONDS=300
usage() { printf 'Usage: bash install.sh --name AGENT [--server https://host:18080] [--dist https://host:18081/agent] [--sync 300]\n'; }
while (($#)); do
  case "$1" in
    --name) AGENT_NAME="${2:-}"; shift 2;;
    --server) SERVER_URL="${2:-}"; shift 2;;
    --dist) BASE_URL="${2:-}"; shift 2;;
    --sync) SYNC_SECONDS="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run as root (sudo bash).' >&2; exit 1; }
[[ "$AGENT_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ]] || { echo 'Invalid/missing --name (letters/numbers/_.- only).' >&2; exit 2; }
[[ "$SYNC_SECONDS" =~ ^[0-9]+$ ]] && ((SYNC_SECONDS>=60 && SYNC_SECONDS<=86400)) || { echo 'Bad --sync: 60..86400' >&2; exit 2; }
[[ "$BASE_URL" =~ ^https://[^/]+/agent/?$ ]] || { echo 'Distribution URL must be HTTPS and end with /agent' >&2; exit 2; }
[[ "$SERVER_URL" =~ ^https://[^/]+$ ]] || { echo 'Central API URL must be HTTPS host:port without path' >&2; exit 2; }
[[ -d /run/systemd/system ]] || { echo 'systemd is required.' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl required.' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'sha256sum required.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 required.' >&2; exit 1; }
command -v getent >/dev/null || { echo 'getent required.' >&2; exit 1; }
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ARCH=amd64;;
  Linux-aarch64|Linux-arm64) ARCH=arm64;;
  *) echo 'Supported: Linux x86_64 or arm64' >&2; exit 1;;
esac
BIN="kvnradar-agent-linux-$ARCH"
BASE_URL="${BASE_URL%/}"
TOKEN=""
if [[ ! -e /dev/tty ]]; then echo 'Interactive terminal needed for token input.' >&2; exit 1; fi
printf 'Central agent ID: %s\nCentral API: %s\n' "$AGENT_NAME" "$SERVER_URL"
printf 'Paste token for agent %s (will not echo): ' "$AGENT_NAME" > /dev/tty
IFS= read -r -s TOKEN < /dev/tty || { echo 'Unable to read token' >&2; exit 1; }
printf '\n' > /dev/tty
[[ -n "$TOKEN" && "$TOKEN" != *$'\n'* ]] || { echo 'Token is empty or invalid' >&2; exit 1; }
TMP="$(mktemp -d /tmp/kvnradar-install.XXXXXX)"
trap 'rm -rf -- "$TMP"; unset TOKEN' EXIT
printf 'Downloading %s over HTTPS...\n' "$BIN"
curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location --max-time 60 \
  "$BASE_URL/SHA256SUMS" -o "$TMP/SHA256SUMS"
curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location --max-time 90 \
  "$BASE_URL/$BIN" -o "$TMP/$BIN"
(cd "$TMP" && grep -F "  $BIN" SHA256SUMS | sha256sum --check --status) || { echo 'SHA256 mismatch - refusing to install' >&2; exit 1; }
printf 'SHA256 OK. Installing dependencies...\n'
if command -v apt-get >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iputils-ping traceroute ca-certificates >/dev/null
elif command -v dnf >/dev/null; then
  dnf install -y -q iputils traceroute ca-certificates
else
  echo 'Please install ping, traceroute and CA certificates manually.' >&2
fi
if ! getent passwd kvnradar >/dev/null; then
  useradd --system --home-dir /var/lib/kvnradar-agent --shell /usr/sbin/nologin kvnradar
fi
install -d -m 0750 -o kvnradar -g kvnradar /var/lib/kvnradar-agent
install -d -m 0750 -o root -g kvnradar /etc/kvnradar
# Config is generated from environment; token never appears in process args or shell history.
export KVNRADAR_AGENT_NAME="$AGENT_NAME" KVNRADAR_AGENT_TOKEN="$TOKEN" KVNRADAR_AGENT_SERVER="$SERVER_URL" KVNRADAR_SYNC_SECONDS="$SYNC_SECONDS"
python3 - <<'PY' > "$TMP/agent.json"
import json,os
print(json.dumps({"agent":os.environ['KVNRADAR_AGENT_NAME'], "token":os.environ['KVNRADAR_AGENT_TOKEN'],
                  "server":os.environ['KVNRADAR_AGENT_SERVER'], "ca_file":"",
                  "state_dir":"/var/lib/kvnradar-agent", "sync_seconds":int(os.environ['KVNRADAR_SYNC_SECONDS'])},indent=2))
PY
unset KVNRADAR_AGENT_TOKEN TOKEN
# Preserve previous KVNRadar configuration and binaries for local rollback.
if [[ -f /etc/kvnradar/agent.json ]]; then
  cp -p /etc/kvnradar/agent.json /etc/kvnradar/agent.json.bak
fi
if [[ -f /usr/local/bin/kvnradar-agent ]]; then
  cp -p /usr/local/bin/kvnradar-agent /usr/local/bin/kvnradar-agent.bak
fi
install -m 0755 "$TMP/$BIN" /usr/local/bin/kvnradar-agent
install -o root -g kvnradar -m 0640 "$TMP/agent.json" /etc/kvnradar/agent.json
cat > /etc/systemd/system/kvnradar-agent.service <<'UNIT'
[Unit]
Description=KVNRadar distributed monitoring agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=kvnradar
Group=kvnradar
ExecStart=/usr/local/bin/kvnradar-agent /etc/kvnradar/agent.json
Restart=always
RestartSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
StateDirectory=kvnradar-agent
StateDirectoryMode=0700
ReadWritePaths=/var/lib/kvnradar-agent
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now kvnradar-agent.service >/dev/null
systemctl restart kvnradar-agent.service
sleep 2
systemctl is-active --quiet kvnradar-agent.service || { journalctl -u kvnradar-agent -n 20 --no-pager >&2; exit 1; }
echo 'KVNRadar agent installed, enabled at boot and running.'
echo 'Inspect: journalctl -u kvnradar-agent -f'
