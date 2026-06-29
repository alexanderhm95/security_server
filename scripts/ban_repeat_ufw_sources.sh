#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
THRESHOLD="${THRESHOLD:-2}"
LOG_FILE="${LOG_FILE:-/var/log/ufw.log}"
STATE_FILE="${STATE_FILE:-/var/lib/security-server/ufw-auto-banned-ips.txt}"
TRUSTED_CIDRS="${TRUSTED_CIDRS:-}"
TRUST_PRIVATE_CIDRS="${TRUST_PRIVATE_CIDRS:-yes}"
AUTO_BAN_BACKEND="${AUTO_BAN_BACKEND:-nft}"
AUTO_BAN_NFT_PREFIX="${AUTO_BAN_NFT_PREFIX:-32}"
BLOCK_NETWORKS_FILE="${BLOCK_NETWORKS_FILE:-}"
ENV_FILE="${ENV_FILE:-}"
ENV_DIR=""
BASE_TRUSTED_CIDRS="127.0.0.1/8 169.254.0.0/16 224.0.0.0/4"
PRIVATE_TRUSTED_CIDRS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
  ENV_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

if [[ "${TRUST_PRIVATE_CIDRS,,}" != "no" && "${TRUST_PRIVATE_CIDRS,,}" != "false" && "${TRUST_PRIVATE_CIDRS}" != "0" ]]; then
  BASE_TRUSTED_CIDRS="$BASE_TRUSTED_CIDRS $PRIVATE_TRUSTED_CIDRS"
fi

TRUSTED_CIDRS="$BASE_TRUSTED_CIDRS ${TRUSTED_CIDRS:-${THREAT_INTEL_IGNORE_CIDRS:-${PUBLIC_IGNORE_IPS:-${IGNORE_IPS:-}}}}"

if [[ -n "$LOG_FILE" && "$LOG_FILE" != /* && -n "$ENV_DIR" ]]; then
  LOG_FILE="$ENV_DIR/$LOG_FILE"
fi

if [[ -n "$STATE_FILE" && "$STATE_FILE" != /* && -n "$ENV_DIR" ]]; then
  STATE_FILE="$ENV_DIR/$STATE_FILE"
fi

if [[ -n "$BLOCK_NETWORKS_FILE" && "$BLOCK_NETWORKS_FILE" != /* && -n "$ENV_DIR" ]]; then
  BLOCK_NETWORKS_FILE="$ENV_DIR/$BLOCK_NETWORKS_FILE"
fi

if [[ -z "$BLOCK_NETWORKS_FILE" && -n "$ENV_DIR" ]]; then
  BLOCK_NETWORKS_FILE="$ENV_DIR/security-nft-blocks.txt"
fi

if [[ "$MODE" != "check" && "$MODE" != "--apply" ]]; then
  echo "Uso:"
  echo "  $0                 # muestra IPs candidatas"
  echo "  sudo $0 --apply    # bloquea IPs repetidas con AUTO_BAN_BACKEND"
  echo
  echo "Variables opcionales:"
  echo "  AUTO_BAN_BACKEND=nft|ufw"
  echo "  AUTO_BAN_NFT_PREFIX=32"
  echo "  THRESHOLD=3 LOG_FILE=/var/log/ufw.log TRUST_PRIVATE_CIDRS=no TRUSTED_CIDRS=\"10.10.0.0/24 203.0.113.0/24\" sudo $0 --apply"
  exit 2
fi

if [[ "$MODE" == "--apply" && "${EUID}" -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo $0 --apply"
  exit 1
fi

if [[ "$MODE" == "--apply" ]]; then
  mkdir -p "$(dirname "$STATE_FILE")"
  touch "$STATE_FILE"
  if [[ "$AUTO_BAN_BACKEND" == "nft" ]]; then
    if [[ -z "$BLOCK_NETWORKS_FILE" ]]; then
      echo "Define BLOCK_NETWORKS_FILE o ENV_FILE para usar AUTO_BAN_BACKEND=nft."
      exit 1
    fi
    mkdir -p "$(dirname "$BLOCK_NETWORKS_FILE")"
    touch "$BLOCK_NETWORKS_FILE"
  fi
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

ip_to_network() {
  local ip="$1"
  python3 - "$ip" "$AUTO_BAN_NFT_PREFIX" <<'PY'
import ipaddress
import sys

ip = ipaddress.ip_address(sys.argv[1])
prefix = int(sys.argv[2])
print(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
PY
}

network_in_file() {
  local network="$1"
  [[ -n "$BLOCK_NETWORKS_FILE" && -f "$BLOCK_NETWORKS_FILE" ]] || return 1
  sed 's/#.*$//' "$BLOCK_NETWORKS_FILE" | awk 'NF {print $1}' | grep -Fxq "$network"
}

echo "== IPs repetidas en $LOG_FILE, umbral >= $THRESHOLD =="
echo "== Backend: $AUTO_BAN_BACKEND =="
if [[ "$AUTO_BAN_BACKEND" == "nft" ]]; then
  echo "== Archivo nftables: ${BLOCK_NETWORKS_FILE:-no definido}, prefijo /$AUTO_BAN_NFT_PREFIX =="
fi

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

declare -A seen_networks=()

for row in "${candidates[@]}"; do
  count="${row%% *}"
  ip="${row##* }"
  if ! is_public_ipv4 "$ip"; then
    continue
  fi
  if [[ "$AUTO_BAN_BACKEND" == "ufw" ]] && grep -qx "$ip" "$STATE_READ"; then
    echo "YA BANEADA  $count  $ip"
    continue
  fi
  network=""
  if [[ "$AUTO_BAN_BACKEND" == "nft" ]]; then
    network="$(ip_to_network "$ip")"
    if [[ -n "${seen_networks[$network]:-}" ]]; then
      continue
    fi
    seen_networks["$network"]=1
  fi
  if [[ "$MODE" == "--apply" ]]; then
    case "$AUTO_BAN_BACKEND" in
      nft)
        if network_in_file "$network"; then
          echo "YA EN NFT   $count  $network"
          continue
        fi
        echo "NFT ADD     $count  $network"
        echo "$network" >> "$BLOCK_NETWORKS_FILE"
        ;;
      ufw)
        echo "UFW DENY    $count  $ip"
        ufw insert 1 deny from "$ip" to any comment "auto-ban ufw repeat $count"
        echo "$ip" >> "$STATE_FILE"
        ;;
      *)
        echo "AUTO_BAN_BACKEND invalido: $AUTO_BAN_BACKEND"
        exit 2
        ;;
    esac
  else
    if [[ "$AUTO_BAN_BACKEND" == "nft" ]]; then
      echo "CANDIDATA   $count  $network"
    else
      echo "CANDIDATA   $count  $ip"
    fi
  fi
done

if [[ "$MODE" == "--apply" ]]; then
  if [[ "$AUTO_BAN_BACKEND" == "nft" ]]; then
    ENV_FILE="$ENV_FILE" BLOCK_NETWORKS_FILE="$BLOCK_NETWORKS_FILE" "$SCRIPT_DIR/drop_hot_attackers_nft.sh" --apply
    echo "Listo. Bloqueos guardados en $BLOCK_NETWORKS_FILE"
  else
    ufw reload
    echo "Listo. Estado guardado en $STATE_FILE"
  fi
else
  echo
  echo "No se aplico nada. Para banear:"
  echo "  sudo env ENV_FILE=$ENV_FILE THRESHOLD=$THRESHOLD AUTO_BAN_BACKEND=$AUTO_BAN_BACKEND $0 --apply"
fi
