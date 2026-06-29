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
SERVICE_NAME="${SERVICE_NAME:-security-early-drop-nft.service}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/$SERVICE_NAME}"
DISABLE_NFTABLES_SERVICE="${DISABLE_NFTABLES_SERVICE:-auto}"
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

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Security early drop nftables table
DefaultDependencies=no
Before=network-pre.target ufw.service fail2ban.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet $NFT_TABLE
ExecStart=/usr/sbin/nft -f $RULES_FILE
ExecStop=-/usr/sbin/nft delete table inet $NFT_TABLE

[Install]
WantedBy=sysinit.target
EOF

nft -c -f "$RULES_FILE"
nft delete table inet "$NFT_TABLE" 2>/dev/null || true
nft -f "$RULES_FILE"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

if [[ "$DISABLE_NFTABLES_SERVICE" == "yes" ]] || {
  [[ "$DISABLE_NFTABLES_SERVICE" == "auto" ]] &&
  systemctl is-enabled nftables >/dev/null 2>&1 &&
  [[ -f /etc/nftables.conf ]] &&
  grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' /etc/nftables.conf
}; then
  systemctl disable nftables >/dev/null 2>&1 || true
  echo "Aviso: nftables.service fue deshabilitado para evitar flush ruleset sobre UFW/iptables."
fi

echo "Persistencia nftables instalada con servicio dedicado:"
echo "  $RULES_FILE"
echo "  $SERVICE_FILE"
echo "Verifica con:"
echo "  sudo nft list table inet $NFT_TABLE"
echo "  systemctl status $SERVICE_NAME --no-pager"
