#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-}"
BLOCK_NETWORKS_FILE="${BLOCK_NETWORKS_FILE:-}"
DEFAULT_BLOCK_NETWORKS="${DEFAULT_BLOCK_NETWORKS:-}"
NFT_TABLE="${NFT_TABLE:-early_drop_attackers}"
NFT_SET="${NFT_SET:-blocked_v4}"
NFT_CHAIN="${NFT_CHAIN:-input_early_drop}"
RULES_DIR="${RULES_DIR:-/etc/nftables.d}"
RULES_FILE="${RULES_FILE:-$RULES_DIR/${NFT_TABLE}.nft}"
NFT_CONF="${NFT_CONF:-/etc/nftables.conf}"
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

if [[ "${EUID}" -ne 0 ]]; then
  echo "Ejecuta con sudo:"
  echo "  sudo ENV_FILE=$ENV_FILE BLOCK_NETWORKS_FILE=$BLOCK_NETWORKS_FILE $0"
  exit 1
fi

read_networks() {
  if [[ -n "$BLOCK_NETWORKS_FILE" && -f "$BLOCK_NETWORKS_FILE" ]]; then
    sed 's/#.*$//' "$BLOCK_NETWORKS_FILE" | awk 'NF {print $1}'
    return
  fi
  for net in $DEFAULT_BLOCK_NETWORKS; do
    printf '%s\n' "$net"
  done
}

mapfile -t networks < <(read_networks)
if [[ "${#networks[@]}" -eq 0 ]]; then
  echo "No hay redes configuradas. Define BLOCK_NETWORKS_FILE o DEFAULT_BLOCK_NETWORKS."
  exit 1
fi

mkdir -p "$RULES_DIR"

tmp="$(mktemp)"
{
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

install -m 0644 "$tmp" "$RULES_FILE"
rm -f "$tmp"

if [[ ! -f "$NFT_CONF" ]]; then
  cat > "$NFT_CONF" <<NFT
#!/usr/sbin/nft -f

flush ruleset
include "$RULES_DIR/*.nft"
NFT
elif ! grep -qF "include \"$RULES_DIR/*.nft\"" "$NFT_CONF"; then
  cp -a "$NFT_CONF" "$NFT_CONF.bak-$(date +%Y%m%d%H%M%S)"
  printf '\ninclude "%s/*.nft"\n' "$RULES_DIR" >> "$NFT_CONF"
fi

nft -c -f "$NFT_CONF"
systemctl enable nftables
systemctl restart nftables

echo "Persistencia nftables instalada:"
echo "  $RULES_FILE"
echo "Verifica con:"
echo "  sudo nft list table inet $NFT_TABLE"
echo "  systemctl status nftables --no-pager"
