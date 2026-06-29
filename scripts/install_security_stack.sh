#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${PROJECT_DIR}/security-stack.env}"

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta como root: sudo $0"
  exit 1
fi

if [ -f "$ENV_FILE" ]; then
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

log() {
  printf '\n==> %s\n' "$*"
}

install_packages() {
  log "Instalando paquetes base"
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Este instalador esta preparado para Debian/Ubuntu con apt-get."
    exit 1
  fi

  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx fail2ban curl git ca-certificates iptables ufw
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

validate_stack() {
  log "Validando Nginx y servicios"
  nginx -t
  systemctl reload nginx
  systemctl enable nginx fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban || true

  echo
  echo "Puertos escuchando:"
  ss -tulpen | sed -n '1,80p'
}

install_packages
configure_ufw
run_modsecurity
run_fail2ban
run_monitor_tools
validate_stack

cat <<EOF

Instalacion completada para: ${SERVER_NAME}

Comandos utiles:
  security-report
  security-monitor
  fail2ban-client status
  tail -f /var/log/modsec_audit.log /var/log/ufw.log /var/log/fail2ban.log
EOF
