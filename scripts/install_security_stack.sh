#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${PROJECT_DIR}/security-stack.env}"
ENV_DIR=""

trap 'echo "ERROR: instalacion interrumpida en ${BASH_SOURCE[0]}:${LINENO}. Revisa la salida anterior." >&2' ERR

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta como root: sudo $0"
  exit 1
fi

if [ -f "$ENV_FILE" ]; then
  ENV_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

SERVER_NAME="${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}"
IGNORE_IPS="${IGNORE_IPS:-127.0.0.1/8 ::1 10.10.0.0/24}"
PUBLIC_IGNORE_IPS="${PUBLIC_IGNORE_IPS:-$IGNORE_IPS}"
NGINX_ACCESS_LOG="${NGINX_ACCESS_LOG:-/var/log/nginx/access.log}"
NGINX_ERROR_LOG="${NGINX_ERROR_LOG:-/var/log/nginx/error.log}"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
ENABLE_UFW="${ENABLE_UFW:-yes}"
HTTP_ALLOW_CIDR="${HTTP_ALLOW_CIDR:-any}"
HTTPS_ALLOW_CIDR="${HTTPS_ALLOW_CIDR:-any}"
SSH_ALLOW_CIDR="${SSH_ALLOW_CIDR:-}"
ENABLE_WIREGUARD="${ENABLE_WIREGUARD:-auto}"
WIREGUARD_ALLOW_CIDR="${WIREGUARD_ALLOW_CIDR:-any}"
ENABLE_MODSECURITY="${ENABLE_MODSECURITY:-yes}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-yes}"
ENABLE_MONITOR_TOOLS="${ENABLE_MONITOR_TOOLS:-yes}"
ENABLE_THREAT_INTEL="${ENABLE_THREAT_INTEL:-yes}"
ENABLE_EARLY_DROP_NFT="${ENABLE_EARLY_DROP_NFT:-auto}"
BLOCK_NETWORKS_FILE="${BLOCK_NETWORKS_FILE:-${PROJECT_DIR}/security-nft-blocks.txt}"
DEFAULT_BLOCK_NETWORKS="${DEFAULT_BLOCK_NETWORKS:-}"
TRUSTED_CIDRS="${TRUSTED_CIDRS:-${THREAT_INTEL_IGNORE_CIDRS:-${PUBLIC_IGNORE_IPS:-$IGNORE_IPS}}}"
TRUST_PRIVATE_CIDRS="${TRUST_PRIVATE_CIDRS:-yes}"
PROMPT_IGNORE_RANGES="${PROMPT_IGNORE_RANGES:-auto}"

if [ -n "$BLOCK_NETWORKS_FILE" ] && [ "${BLOCK_NETWORKS_FILE#/}" = "$BLOCK_NETWORKS_FILE" ] && [ -n "$ENV_DIR" ]; then
  BLOCK_NETWORKS_FILE="${ENV_DIR}/${BLOCK_NETWORKS_FILE}"
fi

log() {
  printf '\n==> %s\n' "$*"
}

shell_quote_value() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\\\$}"
  value="${value//\`/\\\`}"
  printf '"%s"' "$value"
}

persist_env_var() {
  local key="$1"
  local value="$2"
  local quoted

  [ -n "$ENV_FILE" ] || return 0
  mkdir -p "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
  quoted="$(shell_quote_value "$value")"

  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${quoted}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$quoted" >> "$ENV_FILE"
  fi
}

append_unique_ranges() {
  local current="$1"
  local additions="$2"
  python3 - "$current" "$additions" <<'PY'
import sys

items = []
seen = set()
for raw in (sys.argv[1] + " " + sys.argv[2]).split():
    if raw in seen:
        continue
    seen.add(raw)
    items.append(raw)

print(" ".join(items))
PY
}

prompt_additional_ranges() {
  local prompt="$1"
  local default="$2"
  local answer

  printf '%s\n' "$prompt" >&2
  printf 'Actual: %s\n' "$default" >&2
  printf 'Agregar rangos/IPs, o Enter para conservar: ' >&2
  IFS= read -r answer
  if [ -n "$answer" ]; then
    append_unique_ranges "$default" "$answer"
  else
    printf '%s\n' "$default"
  fi
}

should_prompt_ignores() {
  case "$PROMPT_IGNORE_RANGES" in
    yes|true|1)
      return 0
      ;;
    no|false|0)
      return 1
      ;;
    auto)
      [ -t 0 ] && [ -t 1 ]
      return
      ;;
    *)
      echo "PROMPT_IGNORE_RANGES invalido: $PROMPT_IGNORE_RANGES"
      exit 1
      ;;
  esac
}

configure_ignore_ranges() {
  if ! should_prompt_ignores; then
    return 0
  fi

  log "Configurando rangos/IPs a ignorar"
  echo "Escribe rangos separados por espacios. Ejemplo:"
  echo "  127.0.0.1/8 ::1 10.10.0.0/24 172.26.0.0/24 190.96.96.0/21"
  echo

  IGNORE_IPS="$(prompt_additional_ranges "Fail2Ban global: IPs/rangos que nunca debe banear." "$IGNORE_IPS")"
  PUBLIC_IGNORE_IPS="$(prompt_additional_ranges "Fail2Ban web/publico: IPs/rangos que nunca deben banear las jails Nginx." "$PUBLIC_IGNORE_IPS")"
  THREAT_INTEL_IGNORE_CIDRS="$(prompt_additional_ranges "Threat intel: IPs/rangos locales que no debe bloquear." "${THREAT_INTEL_IGNORE_CIDRS:-$IGNORE_IPS}")"
  TRUSTED_CIDRS="$(prompt_additional_ranges "nftables/auto-ban: IPs/rangos que NO deben agregarse a security-nft-blocks.txt." "$TRUSTED_CIDRS")"

  printf 'Confiar automaticamente TODO RFC1918 para nftables/auto-ban? [yes/no]\n'
  printf 'Actual: %s\n' "$TRUST_PRIVATE_CIDRS"
  printf 'Nuevo valor, o Enter para conservar: '
  local trust_private_answer
  IFS= read -r trust_private_answer
  if [ -n "$trust_private_answer" ]; then
    TRUST_PRIVATE_CIDRS="$trust_private_answer"
  fi

  persist_env_var "IGNORE_IPS" "$IGNORE_IPS"
  persist_env_var "PUBLIC_IGNORE_IPS" "$PUBLIC_IGNORE_IPS"
  persist_env_var "THREAT_INTEL_IGNORE_CIDRS" "$THREAT_INTEL_IGNORE_CIDRS"
  persist_env_var "TRUSTED_CIDRS" "$TRUSTED_CIDRS"
  persist_env_var "TRUST_PRIVATE_CIDRS" "$TRUST_PRIVATE_CIDRS"

  echo
  echo "Rangos guardados en: $ENV_FILE"
}

install_packages() {
  log "Instalando paquetes base"
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Este instalador esta preparado para Debian/Ubuntu con apt-get."
    exit 1
  fi

  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx fail2ban curl git ca-certificates iptables ufw ipset nftables python3
}

configure_ufw() {
  [ "$ENABLE_UFW" = "yes" ] || return 0

  log "Configurando UFW con minimo publico"
  ufw default deny incoming
  ufw default allow outgoing

  if [ "$HTTP_ALLOW_CIDR" = "any" ]; then
    ufw allow 80/tcp comment "HTTP"
  else
    ufw allow from "$HTTP_ALLOW_CIDR" to any port 80 proto tcp comment "HTTP restricted"
  fi

  if [ "$HTTPS_ALLOW_CIDR" = "any" ]; then
    ufw allow 443/tcp comment "HTTPS"
  else
    ufw allow from "$HTTPS_ALLOW_CIDR" to any port 443 proto tcp comment "HTTPS restricted"
  fi

  if [ -n "$SSH_ALLOW_CIDR" ]; then
    ufw allow from "$SSH_ALLOW_CIDR" to any port 22 proto tcp comment "SSH restricted"
  else
    echo "SSH_ALLOW_CIDR vacio: no cambio reglas SSH para evitar cortar acceso."
  fi

  if [ "$ENABLE_WIREGUARD" = "yes" ] || { [ "$ENABLE_WIREGUARD" = "auto" ] && ss -lun | grep -q ':51820 '; }; then
    if [ "$WIREGUARD_ALLOW_CIDR" = "any" ]; then
      ufw allow 51820/udp comment "WireGuard"
    else
      ufw allow from "$WIREGUARD_ALLOW_CIDR" to any port 51820 proto udp comment "WireGuard restricted"
    fi
  fi

  ufw --force enable
  ufw status numbered
}

run_modsecurity() {
  [ "$ENABLE_MODSECURITY" = "yes" ] || return 0
  log "Instalando/configurando ModSecurity + OWASP CRS"
  MODSEC_ENV="$ENV_FILE" "$PROJECT_DIR/scripts/install_modsecurity_owasp.sh"
}

run_fail2ban() {
  [ "$ENABLE_FAIL2BAN" = "yes" ] || return 0
  log "Instalando/configurando Fail2Ban SP1"

  local args=(
    --ignore-ips "$IGNORE_IPS"
    --public-ignore-ips "$PUBLIC_IGNORE_IPS"
    --nginx-access-log "$NGINX_ACCESS_LOG"
    --nginx-error-log "$NGINX_ERROR_LOG"
  )

  if [ -n "$DISCORD_WEBHOOK_URL" ]; then
    args+=(--discord-webhook-url "$DISCORD_WEBHOOK_URL")
  else
    args+=(--no-discord)
  fi

  "$PROJECT_DIR/scripts/install_fail2ban_sp1.sh" "${args[@]}"
}

run_monitor_tools() {
  [ "$ENABLE_MONITOR_TOOLS" = "yes" ] || return 0
  log "Instalando comandos security-monitor y security-report"
  "$PROJECT_DIR/scripts/install_security_tools.sh"
}

run_threat_intel() {
  [ "$ENABLE_THREAT_INTEL" = "yes" ] || return 0
  log "Instalando threat intelligence blocklists"
  THREAT_INTEL_ENV="$ENV_FILE" "$PROJECT_DIR/scripts/install_threat_intel.sh"
}

has_nft_networks() {
  if [ -n "$DEFAULT_BLOCK_NETWORKS" ]; then
    return 0
  fi

  if [ -f "$BLOCK_NETWORKS_FILE" ] && sed 's/#.*$//' "$BLOCK_NETWORKS_FILE" | awk 'NF {found=1} END {exit !found}'; then
    return 0
  fi

  return 1
}

run_early_drop_nft() {
  case "$ENABLE_EARLY_DROP_NFT" in
    no|false|0)
      return 0
      ;;
    yes|true|1)
      if ! has_nft_networks; then
        echo "ENABLE_EARLY_DROP_NFT=yes, pero no hay redes en BLOCK_NETWORKS_FILE ni DEFAULT_BLOCK_NETWORKS."
        echo "Configura security-nft-blocks.txt o DEFAULT_BLOCK_NETWORKS para activar nftables early drop."
        echo "Puedes generar sugerencias con:"
        echo "  sudo ENV_FILE=$ENV_FILE MIN_HITS=20 $PROJECT_DIR/scripts/suggest_nft_blocks_from_ufw.sh --write"
        exit 1
      fi
      ;;
    auto)
      if ! has_nft_networks; then
        log "nftables early drop omitido: no hay redes configuradas"
        echo "Para activarlo, llena $BLOCK_NETWORKS_FILE o genera sugerencias con:"
        echo "  sudo ENV_FILE=$ENV_FILE MIN_HITS=20 $PROJECT_DIR/scripts/suggest_nft_blocks_from_ufw.sh --write"
        return 0
      fi
      ;;
    *)
      echo "ENABLE_EARLY_DROP_NFT invalido: $ENABLE_EARLY_DROP_NFT"
      exit 1
      ;;
  esac

  log "Instalando nftables early drop persistente"
  ENV_FILE="$ENV_FILE" "$PROJECT_DIR/scripts/install_early_drop_persistent.sh"
}

validate_stack() {
  log "Validando Nginx y servicios"
  nginx -t
  systemctl reload nginx
  systemctl enable nginx fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban || true

  if ! command -v security-report >/dev/null 2>&1; then
    echo "ERROR: security-report no quedo instalado. La instalacion no esta completa."
    exit 1
  fi

  echo
  echo "Puertos escuchando:"
  ss -tulpen | sed -n '1,80p'
}

configure_ignore_ranges
install_packages
configure_ufw
run_modsecurity
run_fail2ban
run_monitor_tools
run_threat_intel
run_early_drop_nft
validate_stack

cat <<EOF

Instalacion completada para: ${SERVER_NAME}

Comandos utiles:
  security-report
  security-monitor
  sudo attack-detect /var/log/nginx/access.log
  fail2ban-client status
  tail -f /var/log/modsec_audit.log /var/log/ufw.log /var/log/fail2ban.log
EOF
