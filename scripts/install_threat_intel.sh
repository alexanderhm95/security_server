#!/bin/bash
set -euo pipefail

ENV_FILE="${THREAT_INTEL_ENV:-}"
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

THREAT_INTEL_SOURCES="${THREAT_INTEL_SOURCES:-spamhaus_drop}"
THREAT_INTEL_IGNORE_CIDRS="${THREAT_INTEL_IGNORE_CIDRS:-127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
ABUSEIPDB_CONFIDENCE_MINIMUM="${ABUSEIPDB_CONFIDENCE_MINIMUM:-90}"
SET_NAME="security_threat_ipv4"
CONF_DIR="/etc/security-stack"
ENV_OUT="${CONF_DIR}/threat-intel.env"
UPDATER="/usr/local/sbin/security-threat-intel-update"

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta como root: sudo $0"
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl ipset iptables ca-certificates python3

mkdir -p "$CONF_DIR"
cat > "$ENV_OUT" <<EOF
THREAT_INTEL_SOURCES="${THREAT_INTEL_SOURCES}"
THREAT_INTEL_IGNORE_CIDRS="${THREAT_INTEL_IGNORE_CIDRS}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY}"
ABUSEIPDB_CONFIDENCE_MINIMUM="${ABUSEIPDB_CONFIDENCE_MINIMUM}"
SET_NAME="${SET_NAME}"
EOF
chmod 0600 "$ENV_OUT"

cat > "$UPDATER" <<'EOF'
#!/bin/bash
set -euo pipefail

ENV_FILE="/etc/security-stack/threat-intel.env"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

THREAT_INTEL_SOURCES="${THREAT_INTEL_SOURCES:-spamhaus_drop}"
THREAT_INTEL_IGNORE_CIDRS="${THREAT_INTEL_IGNORE_CIDRS:-127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
ABUSEIPDB_CONFIDENCE_MINIMUM="${ABUSEIPDB_CONFIDENCE_MINIMUM:-90}"
SET_NAME="${SET_NAME:-security_threat_ipv4}"
TMP_SET="${SET_NAME}_tmp"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ipset create "$TMP_SET" hash:net family inet hashsize 4096 maxelem 262144 -exist
ipset flush "$TMP_SET"

is_ignored() {
  local entry="$1"
  python3 - "$entry" "$THREAT_INTEL_IGNORE_CIDRS" <<'PY'
import ipaddress
import sys

entry = sys.argv[1]
ignore = sys.argv[2].split()

try:
    entry_net = ipaddress.ip_network(entry, strict=False)
except ValueError:
    sys.exit(1)

for cidr in ignore:
    try:
        ignore_net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        continue
    if entry_net.version == ignore_net.version and entry_net.overlaps(ignore_net):
        sys.exit(0)

sys.exit(1)
PY
}

add_entry() {
  local entry="$1"
  [ -z "$entry" ] && return 0
  is_ignored "$entry" && return 0
  ipset add "$TMP_SET" "$entry" -exist 2>/dev/null || true
}

fetch_spamhaus_drop() {
  curl -fsSL --connect-timeout 10 https://www.spamhaus.org/drop/drop.txt \
    | awk '/^[0-9]/ {print $1}' \
    | while read -r cidr; do add_entry "$cidr"; done
}

fetch_abuseipdb() {
  [ -n "$ABUSEIPDB_API_KEY" ] || return 0
  curl -fsSL --connect-timeout 20 \
    -G https://api.abuseipdb.com/api/v2/blacklist \
    --data-urlencode "confidenceMinimum=${ABUSEIPDB_CONFIDENCE_MINIMUM}" \
    -H "Key: ${ABUSEIPDB_API_KEY}" \
    -H "Accept: text/plain" \
    | awk '/^[0-9]+\./ {print $1}' \
    | while read -r ip; do add_entry "$ip"; done
}

for source in $THREAT_INTEL_SOURCES; do
  case "$source" in
    spamhaus_drop) fetch_spamhaus_drop ;;
    abuseipdb) fetch_abuseipdb ;;
    *) echo "Fuente desconocida: $source" >&2 ;;
  esac
done

ipset create "$SET_NAME" hash:net family inet hashsize 4096 maxelem 262144 -exist
ipset swap "$TMP_SET" "$SET_NAME"
ipset destroy "$TMP_SET" 2>/dev/null || true

if ! iptables -C INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
  iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
fi

echo "Threat intel actualizado: $(ipset list "$SET_NAME" | awk '/Number of entries/ {print $4}') entradas"
EOF

chmod 0755 "$UPDATER"

cat > /etc/systemd/system/security-threat-intel.service <<EOF
[Unit]
Description=Update security threat intelligence ipset
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${UPDATER}
EOF

cat > /etc/systemd/system/security-threat-intel.timer <<'EOF'
[Unit]
Description=Run security threat intelligence updater periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now security-threat-intel.timer
"$UPDATER"

echo "Threat intelligence instalado. Ver: ipset list ${SET_NAME}"
