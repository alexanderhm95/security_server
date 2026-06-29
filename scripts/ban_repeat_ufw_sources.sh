#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
THRESHOLD="${THRESHOLD:-2}"
LOG_FILE="${LOG_FILE:-/var/log/ufw.log}"
STATE_FILE="${STATE_FILE:-/var/lib/security-server/ufw-auto-banned-ips.txt}"
TRUSTED_CIDRS="${TRUSTED_CIDRS:-127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4}"
ENV_FILE="${ENV_FILE:-}"
ENV_DIR=""

if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
  ENV_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

if [[ -n "$LOG_FILE" && "$LOG_FILE" != /* && -n "$ENV_DIR" ]]; then
  LOG_FILE="$ENV_DIR/$LOG_FILE"
fi

if [[ -n "$STATE_FILE" && "$STATE_FILE" != /* && -n "$ENV_DIR" ]]; then
  STATE_FILE="$ENV_DIR/$STATE_FILE"
fi

if [[ "$MODE" != "check" && "$MODE" != "--apply" ]]; then
  echo "Uso:"
  echo "  $0                 # muestra IPs candidatas"
  echo "  sudo $0 --apply    # agrega deny en UFW para IPs repetidas"
  echo
  echo "Variables opcionales:"
  echo "  THRESHOLD=3 LOG_FILE=/var/log/ufw.log TRUSTED_CIDRS=\"10.0.0.0/8 203.0.113.0/24\" sudo $0 --apply"
  exit 2
fi

if [[ "$MODE" == "--apply" && "${EUID}" -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo $0 --apply"
  exit 1
fi

if [[ "$MODE" == "--apply" ]]; then
  mkdir -p "$(dirname "$STATE_FILE")"
  touch "$STATE_FILE"
fi

STATE_READ="$STATE_FILE"
[[ -r "$STATE_READ" ]] || STATE_READ="/dev/null"

is_public_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  python3 - "$ip" "$TRUSTED_CIDRS" <<'PY'
import ipaddress
import sys

ip = ipaddress.ip_address(sys.argv[1])
trusted = sys.argv[2].split()

if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
    sys.exit(1)

for cidr in trusted:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        continue
    if ip.version == net.version and ip in net:
        sys.exit(1)

sys.exit(0)
PY
}

echo "== IPs repetidas en $LOG_FILE, umbral >= $THRESHOLD =="

mapfile -t candidates < <(
  awk '/UFW BLOCK/ {
    for (i=1; i<=NF; i++) {
      if ($i ~ /^SRC=/) {
        ip=substr($i,5)
        if (ip !~ /:/) count[ip]++
      }
    }
  }
  END {
    for (ip in count) {
      if (count[ip] >= threshold) print count[ip], ip
    }
  }' threshold="$THRESHOLD" "$LOG_FILE" 2>/dev/null | sort -nr
)

if [[ "${#candidates[@]}" -eq 0 ]]; then
  echo "No hay IPs repetidas que superen el umbral."
  exit 0
fi

for row in "${candidates[@]}"; do
  count="${row%% *}"
  ip="${row##* }"
  if ! is_public_ipv4 "$ip"; then
    continue
  fi
  if grep -qx "$ip" "$STATE_READ"; then
    echo "YA BANEADA  $count  $ip"
    continue
  fi
  if [[ "$MODE" == "--apply" ]]; then
    echo "BANEANDO    $count  $ip"
    ufw insert 1 deny from "$ip" to any comment "auto-ban ufw repeat $count"
    echo "$ip" >> "$STATE_FILE"
  else
    echo "CANDIDATA   $count  $ip"
  fi
done

if [[ "$MODE" == "--apply" ]]; then
  ufw reload
  echo "Listo. Estado guardado en $STATE_FILE"
else
  echo
  echo "No se aplico nada. Para banear:"
  echo "  sudo env THRESHOLD=$THRESHOLD $0 --apply"
fi
