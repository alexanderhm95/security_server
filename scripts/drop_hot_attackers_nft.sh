#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
ENV_FILE="${ENV_FILE:-}"
BLOCK_NETWORKS_FILE="${BLOCK_NETWORKS_FILE:-}"
NFT_TABLE="${NFT_TABLE:-early_drop_attackers}"
NFT_SET="${NFT_SET:-blocked_v4}"
NFT_CHAIN="${NFT_CHAIN:-input_early_drop}"

DEFAULT_BLOCK_NETWORKS="${DEFAULT_BLOCK_NETWORKS:-}"
ENV_DIR=""

if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
  ENV_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

if [[ -n "$BLOCK_NETWORKS_FILE" && "$BLOCK_NETWORKS_FILE" != /* && -n "$ENV_DIR" ]]; then
  BLOCK_NETWORKS_FILE="$ENV_DIR/$BLOCK_NETWORKS_FILE"
fi

if [[ -z "$BLOCK_NETWORKS_FILE" && -n "$ENV_DIR" ]]; then
  BLOCK_NETWORKS_FILE="$ENV_DIR/security-nft-blocks.txt"
fi

usage() {
  cat <<'EOF'
Bloquea redes IPv4 temprano con nftables, antes de UFW.

Uso:
  ./scripts/drop_hot_attackers_nft.sh
  sudo ./scripts/drop_hot_attackers_nft.sh --apply
  sudo ./scripts/drop_hot_attackers_nft.sh --remove

Variables:
  BLOCK_NETWORKS_FILE="./security-nft-blocks.txt"
  DEFAULT_BLOCK_NETWORKS="1.2.3.0/24 5.6.7.8/32"
  NFT_TABLE="early_drop_attackers"
  ENV_FILE="./security-firewall.env"

Formato BLOCK_NETWORKS_FILE:
  Una red/IP por linea. Lineas vacias o con # se ignoran.
EOF
}

read_networks() {
  if [[ -n "$BLOCK_NETWORKS_FILE" && -f "$BLOCK_NETWORKS_FILE" ]]; then
    sed 's/#.*$//' "$BLOCK_NETWORKS_FILE" | awk 'NF {print $1}'
    return
  fi
  for net in $DEFAULT_BLOCK_NETWORKS; do
    printf '%s\n' "$net"
  done
}

if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$MODE" != "check" && "$MODE" != "--apply" && "$MODE" != "--remove" ]]; then
  usage
  exit 2
fi

if [[ "$MODE" != "check" && "${EUID}" -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo $0 $MODE"
  exit 1
fi

if [[ "$MODE" == "--remove" ]]; then
  nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  echo "Tabla $NFT_TABLE eliminada."
  exit 0
fi

mapfile -t networks < <(read_networks)

echo "== Redes/IPs a bloquear antes de UFW =="
if [[ "${#networks[@]}" -eq 0 ]]; then
  echo "No hay redes configuradas. Define BLOCK_NETWORKS_FILE o DEFAULT_BLOCK_NETWORKS."
  exit 0
fi
printf '%s\n' "${networks[@]}"

if [[ "$MODE" == "check" ]]; then
  echo
  echo "No se aplico nada. Para aplicar runtime:"
  echo "  sudo BLOCK_NETWORKS_FILE=$BLOCK_NETWORKS_FILE $0 --apply"
  exit 0
fi

tmp="$(mktemp)"
{
  echo "flush table inet $NFT_TABLE"
  echo "table inet $NFT_TABLE {"
  echo "  set $NFT_SET {"
  echo "    type ipv4_addr"
  echo "    flags interval"
  echo "    elements = {"
  for i in "${!networks[@]}"; do
    sep=","
    [[ "$i" -eq "$((${#networks[@]} - 1))" ]] && sep=""
    echo "      ${networks[$i]}$sep"
  done
  echo "    }"
  echo "  }"
  echo
  echo "  chain $NFT_CHAIN {"
  echo "    type filter hook input priority -300; policy accept;"
  echo "    ip saddr @$NFT_SET drop"
  echo "  }"
  echo "}"
} > "$tmp"

if ! nft -f "$tmp" 2>/dev/null; then
  sed "1s/^/add table inet $NFT_TABLE\n/" "$tmp" > "${tmp}.add"
  nft -f "${tmp}.add"
fi

rm -f "$tmp" "${tmp}.add"
echo "Aplicado. Verifica con:"
echo "  sudo nft list table inet $NFT_TABLE"
