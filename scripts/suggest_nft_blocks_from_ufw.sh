#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${LOG_FILE:-/var/log/ufw.log}"
MIN_HITS="${MIN_HITS:-20}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
TRUSTED_CIDRS="${TRUSTED_CIDRS:-}"
TRUST_PRIVATE_CIDRS="${TRUST_PRIVATE_CIDRS:-yes}"
ENV_FILE="${ENV_FILE:-}"
ENV_DIR=""
BASE_TRUSTED_CIDRS="127.0.0.1/8 169.254.0.0/16 224.0.0.0/4"
PRIVATE_TRUSTED_CIDRS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
  ENV_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  if [[ -n "${BLOCK_NETWORKS_FILE:-}" && -z "$OUTPUT_FILE" ]]; then
    if [[ "$BLOCK_NETWORKS_FILE" = /* ]]; then
      OUTPUT_FILE="$BLOCK_NETWORKS_FILE"
    else
      OUTPUT_FILE="$ENV_DIR/$BLOCK_NETWORKS_FILE"
    fi
  fi
fi

if [[ "${TRUST_PRIVATE_CIDRS,,}" != "no" && "${TRUST_PRIVATE_CIDRS,,}" != "false" && "${TRUST_PRIVATE_CIDRS}" != "0" ]]; then
  BASE_TRUSTED_CIDRS="$BASE_TRUSTED_CIDRS $PRIVATE_TRUSTED_CIDRS"
fi

TRUSTED_CIDRS="$BASE_TRUSTED_CIDRS ${TRUSTED_CIDRS:-${THREAT_INTEL_IGNORE_CIDRS:-${PUBLIC_IGNORE_IPS:-${IGNORE_IPS:-}}}}"

if [[ -z "$OUTPUT_FILE" && -n "$ENV_DIR" ]]; then
  OUTPUT_FILE="$ENV_DIR/security-nft-blocks.txt"
fi

usage() {
  cat <<'EOF'
Sugiere redes /24 para nftables a partir de /var/log/ufw.log.

Uso:
  ./scripts/suggest_nft_blocks_from_ufw.sh
  sudo ENV_FILE=./security-stack.env MIN_HITS=20 OUTPUT_FILE=./security-nft-blocks.txt ./scripts/suggest_nft_blocks_from_ufw.sh --write

Variables:
  LOG_FILE=/var/log/ufw.log
  MIN_HITS=20
  OUTPUT_FILE=./security-nft-blocks.txt
  TRUSTED_CIDRS="127.0.0.1/8 10.0.0.0/8 ..."
  TRUST_PRIVATE_CIDRS=yes
  ENV_FILE=./security-stack.env
EOF
}

MODE="${1:-check}"
if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$MODE" != "check" && "$MODE" != "--write" ]]; then
  usage
  exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

awk '/UFW BLOCK/ {
  for (i=1; i<=NF; i++) {
    if ($i ~ /^SRC=/) {
      ip=substr($i,5)
      if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        split(ip,a,".")
        print a[1]"."a[2]"."a[3]".0/24"
      }
    }
  }
}' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -nr | awk -v min="$MIN_HITS" '$1 >= min {print $2}' > "$tmp"

python3 - "$tmp" "$TRUSTED_CIDRS" <<'PY'
import ipaddress
import sys

path = sys.argv[1]
trusted = []
for raw in sys.argv[2].split():
    try:
        trusted.append(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        pass

for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        net = ipaddress.ip_network(line, strict=False)
    except ValueError:
        continue
    if any(net.version == t.version and net.overlaps(t) for t in trusted):
        continue
    print(net)
PY

if [[ "$MODE" == "--write" ]]; then
  if [[ -z "$OUTPUT_FILE" ]]; then
    echo "Define OUTPUT_FILE o ENV_FILE con BLOCK_NETWORKS_FILE para escribir."
    exit 1
  fi
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  {
    echo "# Generado desde $LOG_FILE con MIN_HITS=$MIN_HITS el $(date -Is)"
    python3 - "$tmp" "$TRUSTED_CIDRS" <<'PY'
import ipaddress
import sys

path = sys.argv[1]
trusted = []
for raw in sys.argv[2].split():
    try:
        trusted.append(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        pass

for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        net = ipaddress.ip_network(line, strict=False)
    except ValueError:
        continue
    if any(net.version == t.version and net.overlaps(t) for t in trusted):
        continue
    print(net)
PY
  } > "$OUTPUT_FILE"
  echo "Escrito: $OUTPUT_FILE"
fi
