#!/bin/bash
set -euo pipefail

IGNORE_IPS="127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21"
PUBLIC_IGNORE_IPS="127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21"
NGINX_ACCESS_LOG="/var/log/nginx/access.log"
NGINX_ERROR_LOG="/var/log/nginx/error.log"
BANACTION="iptables-multiport"
INSTALL_PACKAGES="yes"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
DISCORD_ENABLED="auto"
DISCORD_ENV_FILE="/etc/fail2ban/discord-webhook.env"

usage() {
  cat <<'EOF'
Instala configuracion Fail2Ban para SSH y Nginx.

Uso:
  sudo ./install_fail2ban_sp1.sh [opciones]

Opciones:
  --ignore-ips "IP1 IP2 CIDR"      IPs globales permitidas. Default: 127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21
  --public-ignore-ips "IP1 CIDR"   IPs/redes permitidas para jails Nginx. Default: 127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21
  --nginx-access-log RUTA          Log access Nginx. Default: /var/log/nginx/access.log
  --nginx-error-log RUTA           Log error Nginx. Default: /var/log/nginx/error.log
  --banaction ACCION               Accion Fail2Ban. Default: iptables-multiport
  --discord-webhook-url URL        Activa alertas Discord usando este webhook.
  --no-discord                     No instala ni usa alertas Discord.
  --no-install                     No instala paquetes, solo configura.
  -h, --help                       Muestra esta ayuda.

Ejemplo:
  sudo ./install_fail2ban_sp1.sh --public-ignore-ips "127.0.0.1/8 ::1 10.10.0.0/24 190.96.96.0/21"
  sudo DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..." ./install_fail2ban_sp1.sh
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ignore-ips)
      IGNORE_IPS="${2:-}"
      shift 2
      ;;
    --public-ignore-ips)
      PUBLIC_IGNORE_IPS="${2:-}"
      shift 2
      ;;
    --nginx-access-log)
      NGINX_ACCESS_LOG="${2:-}"
      shift 2
      ;;
    --nginx-error-log)
      NGINX_ERROR_LOG="${2:-}"
      shift 2
      ;;
    --banaction)
      BANACTION="${2:-}"
      shift 2
      ;;
    --discord-webhook-url)
      DISCORD_WEBHOOK_URL="${2:-}"
      DISCORD_ENABLED="yes"
      shift 2
      ;;
    --no-discord)
      DISCORD_ENABLED="no"
      shift
      ;;
    --no-install)
      INSTALL_PACKAGES="no"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Opcion desconocida: $1"
      usage
      exit 1
      ;;
  esac
done

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta como root: sudo $0"
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"

install_packages() {
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo "Fail2Ban ya esta instalado."
    return
  fi

  if [ "$INSTALL_PACKAGES" = "no" ]; then
    echo "Fail2Ban no esta instalado y --no-install fue indicado."
    exit 1
  fi

  echo "Instalando Fail2Ban..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban iptables curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y fail2ban iptables curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y epel-release || true
    yum install -y fail2ban iptables curl
  else
    echo "No encontre apt-get, dnf ni yum. Instala fail2ban manualmente."
    exit 1
  fi
}

backup_file() {
  local file="$1"
  if [ -f "$file" ]; then
    cp "$file" "${file}.bak.${timestamp}"
    echo "Backup: ${file}.bak.${timestamp}"
  fi
}

write_file() {
  local file="$1"
  local tmp
  mkdir -p "$(dirname "$file")"
  tmp="$(mktemp)"
  cat > "$tmp"

  if [ -f "$file" ] && cmp -s "$tmp" "$file"; then
    echo "Sin cambios: $file"
    rm -f "$tmp"
    return
  fi

  backup_file "$file"
  install -m 0644 "$tmp" "$file"
  rm -f "$tmp"
  echo "Actualizado: $file"
}

ensure_log_file() {
  local file="$1"
  if [ ! -e "$file" ]; then
    mkdir -p "$(dirname "$file")"
    touch "$file"
    chmod 0644 "$file"
    echo "Log creado para Fail2Ban: $file"
  else
    echo "Log existe: $file"
  fi
}

detect_existing_discord_webhook() {
  if [ -n "$DISCORD_WEBHOOK_URL" ]; then
    return
  fi

  if [ -f "$DISCORD_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$DISCORD_ENV_FILE"
    DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
  fi

  if [ -z "$DISCORD_WEBHOOK_URL" ] && [ -f /etc/fail2ban/scripts/discord-webhook.sh ]; then
    DISCORD_WEBHOOK_URL="$(grep -E '^DISCORD_WEBHOOK_URL=' /etc/fail2ban/scripts/discord-webhook.sh 2>/dev/null | head -1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  fi
}

install_discord_files() {
  if [ "$DISCORD_ENABLED" = "no" ]; then
    echo "Discord desactivado por parametro."
    return
  fi

  detect_existing_discord_webhook

  if [ -z "$DISCORD_WEBHOOK_URL" ]; then
    echo "Discord no configurado: pasa --discord-webhook-url o exporta DISCORD_WEBHOOK_URL."
    DISCORD_ENABLED="no"
    return
  fi

  DISCORD_ENABLED="yes"
  mkdir -p /etc/fail2ban/scripts

  write_file "$DISCORD_ENV_FILE" <<EOF
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL}"
EOF
  chmod 0600 "$DISCORD_ENV_FILE"

  write_file /etc/fail2ban/action.d/discord-webhook.conf <<'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = <script> <name> <ip>
actionunban =

[Init]
script = /etc/fail2ban/scripts/discord-webhook.sh
name = default
EOF

  write_file /etc/fail2ban/action.d/discord.conf <<'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = <script> <name> <ip>
actionunban =

[Init]
script = /etc/fail2ban/scripts/discord-webhook.sh
name = default
EOF

  write_file /etc/fail2ban/scripts/discord-webhook.sh <<'EOF'
#!/bin/bash
set -u

ENV_FILE="/etc/fail2ban/discord-webhook.env"
LOG_FILE="/var/log/fail2ban-discord.log"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

JAIL_NAME="${1:-unknown}"
IP_ADDRESS="${2:-unknown}"
HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

if [ -z "$DISCORD_WEBHOOK_URL" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S'): Discord webhook no configurado" >> "$LOG_FILE"
  exit 0
fi

case "$JAIL_NAME" in
  sshd)
    COLOR=16711680
    DESCRIPTION="Intento SSH fallido"
    ;;
  nginx-404)
    COLOR=16753920
    DESCRIPTION="Multiples errores HTTP detectados"
    ;;
  nginx-scanners)
    COLOR=16711680
    DESCRIPTION="Scanner automatico detectado"
    ;;
  nginx-badbots)
    COLOR=16753920
    DESCRIPTION="Bot sospechoso detectado"
    ;;
  nginx-master)
    COLOR=16711680
    DESCRIPTION="Ataque Nginx/WordPress detectado"
    ;;
  nginx-http-auth)
    COLOR=16711680
    DESCRIPTION="Intento de autenticacion HTTP fallido"
    ;;
  nginx-dos)
    COLOR=16753920
    DESCRIPTION="Posible abuso o rate limit detectado"
    ;;
  nginx-malformed)
    COLOR=16711680
    DESCRIPTION="Request HTTP vacio o malformado detectado"
    ;;
  *)
    COLOR=3447003
    DESCRIPTION="Actividad sospechosa detectada"
    ;;
esac

COUNTRY="Unknown"
ISP="Unknown"
if command -v curl >/dev/null 2>&1; then
  IP_INFO="$(curl -s --connect-timeout 2 "http://ip-api.com/json/${IP_ADDRESS}?fields=country,isp" 2>/dev/null || true)"
  COUNTRY="$(printf '%s' "$IP_INFO" | sed -n 's/.*"country":"\([^"]*\)".*/\1/p')"
  ISP="$(printf '%s' "$IP_INFO" | sed -n 's/.*"isp":"\([^"]*\)".*/\1/p')"
  COUNTRY="${COUNTRY:-Unknown}"
  ISP="${ISP:-Unknown}"
fi

JSON_PAYLOAD="$(python3 - "$JAIL_NAME" "$IP_ADDRESS" "$HOSTNAME" "$DESCRIPTION" "$COLOR" "$COUNTRY" "$ISP" <<'PY'
import datetime
import json
import sys

jail, ip, host, desc, color, country, isp = sys.argv[1:]
payload = {
    "username": f"Fail2Ban - {host}",
    "embeds": [
        {
            "title": f"Fail2Ban ban: {jail}",
            "description": desc,
            "color": int(color),
            "fields": [
                {"name": "IP bloqueada", "value": f"`{ip}`", "inline": True},
                {"name": "Jail", "value": f"`{jail}`", "inline": True},
                {"name": "Pais", "value": f"`{country}`", "inline": True},
                {"name": "ISP", "value": f"`{isp}`", "inline": False},
            ],
            "footer": {"text": f"Sistema: {host}"},
            "timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        }
    ],
}
print(json.dumps(payload))
PY
)"

echo "$(date '+%Y-%m-%d %H:%M:%S'): Enviando alerta Discord: ${JAIL_NAME} ${IP_ADDRESS}" >> "$LOG_FILE"

if command -v curl >/dev/null 2>&1; then
  curl -s -f -H "Content-Type: application/json" -X POST -d "$JSON_PAYLOAD" "$DISCORD_WEBHOOK_URL" >> "$LOG_FILE" 2>&1 || true
else
  echo "$(date '+%Y-%m-%d %H:%M:%S'): curl no instalado, no se envio alerta" >> "$LOG_FILE"
fi

exit 0
EOF
  chmod 0755 /etc/fail2ban/scripts/discord-webhook.sh
}

action_block() {
  local name="$1"
  printf '%s[name=%s, port="http,https", protocol=tcp]' "$BANACTION" "$name"
  if [ "$DISCORD_ENABLED" = "yes" ]; then
    printf '\n         discord-webhook[name=%s]' "$name"
  fi
}

sshd_action_block() {
  printf '%s[name=sshd, port="ssh", protocol=tcp]' "$BANACTION"
  if [ "$DISCORD_ENABLED" = "yes" ]; then
    printf '\n         discord-webhook[name=sshd]'
  fi
}

install_packages
install_discord_files

mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d

write_file /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 31536000
findtime = 3600
maxretry = 3
ignoreip = ${IGNORE_IPS}
action = %(action_)s
$(if [ "$DISCORD_ENABLED" = "yes" ]; then printf '         discord'; fi)

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 604800
findtime = 600
action = $(sshd_action_block)

[nginx-master]
enabled = true
backend = polling
port = http,https
filter = nginx-master
logpath = ${NGINX_ACCESS_LOG}
maxretry = 2
findtime = 600
bantime = 31536000
ignoreip = ${PUBLIC_IGNORE_IPS}
action = $(action_block nginx-master)
EOF

write_file /etc/fail2ban/jail.d/00-sp1-defaults.local <<EOF
[DEFAULT]
bantime = 31536000
findtime = 3600
maxretry = 3
backend = systemd
ignoreip = ${IGNORE_IPS}

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 1h
findtime = 10m
action = $(sshd_action_block)

[nginx-http-auth]
enabled = true
backend = polling
filter = nginx-http-auth
port = http,https
logpath = ${NGINX_ERROR_LOG}

[nginx-dos]
enabled = true
backend = polling
filter = nginx-dos
port = http,https
logpath = ${NGINX_ACCESS_LOG}
maxretry = 300
findtime = 300
bantime = 600
action = $(action_block nginx-dos)

[nginx-malformed]
enabled = true
backend = polling
filter = nginx-malformed
port = http,https
logpath = ${NGINX_ACCESS_LOG}
maxretry = 1
findtime = 600
bantime = 31536000
ignoreip = ${PUBLIC_IGNORE_IPS}
action = $(action_block nginx-malformed)
EOF

write_file /etc/fail2ban/jail.d/nginx-custom.local <<EOF
[nginx-404]
enabled = true
backend = polling
port = http,https
filter = nginx-404
logpath = ${NGINX_ACCESS_LOG}
maxretry = 5
findtime = 600
bantime = 31536000
ignoreip = ${PUBLIC_IGNORE_IPS}
action = $(action_block nginx-404)

[nginx-scanners]
enabled = true
backend = polling
port = http,https
filter = nginx-scanners
logpath = ${NGINX_ACCESS_LOG}
maxretry = 2
findtime = 600
bantime = 31536000
ignoreip = ${PUBLIC_IGNORE_IPS}
action = $(action_block nginx-scanners)

[nginx-badbots]
enabled = true
backend = polling
port = http,https
filter = nginx-badbots
logpath = ${NGINX_ACCESS_LOG}
maxretry = 2
findtime = 600
bantime = 31536000
ignoreip = ${PUBLIC_IGNORE_IPS}
action = $(action_block nginx-badbots)

[nginx-nohome]
enabled = true
backend = polling
port = http,https
filter = nginx-nohome
logpath = ${NGINX_ACCESS_LOG}
maxretry = 2
findtime = 600
bantime = 31536000
ignoreip = ${PUBLIC_IGNORE_IPS}
action = $(action_block nginx-nohome)
EOF

write_file /etc/fail2ban/filter.d/nginx-master.conf <<'EOF'
[Definition]
# Filtro maestro Nginx/WordPress.
# Mantenerlo estricto: no usar reglas genericas tipo "bot|crawl" ni buscar IPs dentro de la URL.

failregex = ^<HOST> - .* "(GET|POST|HEAD) [^"]*(\.\./|\.\.%%2f|%%2f\.\.|/etc/passwd|/proc/|/dev/|/root/|/var/www/)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/(\.env|\.git|\.svn|\.hg|\.DS_Store|wp-config\.php|config\.php|configuration\.php|settings\.php)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/[^"]*\.(sql|dump|bak|backup|old|orig|save|swp|zip|tar|tar\.gz|tgz|gz|rar|7z)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/(backup|backups|database|db|dump|mysql|phpmyadmin|pma|adminer|wp-admin/install\.php|readme\.html|license\.txt)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "POST /(wp-login\.php|authservice/?|xmlrpc\.php)[^"]* HTTP/[^"]+" (200|302|403|404|444) .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/xmlrpc\.php[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/autodiscover(/autodiscover)?\.xml[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/(wp-content|wp-includes|wp-admin)/[^"]*\.php[^"]* HTTP/[^"]+" (400|403|404|444) .*
            ^<HOST> - .* "(PUT|DELETE|TRACE|CONNECT) [^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*(union.*select|select.*from|insert.*into|update.*set|delete.*from|drop.*table|information_schema|concat\(|base64_decode|eval\(|system\(|shell_exec\(|passthru\(|<script|javascript:|onload=|alert\()[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* "(curl|wget|python-requests|python|nikto|nmap|wpscan|sqlmap|masscan|zgrab|Go-http-client|Apache-HttpClient|libwww-perl).*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*Mozlila/5\.0.*Bulid/NRD90M.*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*SM-G892A.*NRD90M.*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*Android 7\.0.*Chrome/60\.0.*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*Android7\.0.*Chrome/60\.0.*"

ignoreregex = ^(127\.0\.0\.1|::1) .*
              ^<HOST> - .* "(GET|HEAD) [^"]*\.(css|js|png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|eot|pdf|txt|mp4|webm|mp3)(\?[^"]*)? HTTP/[^"]+" .*
              ^<HOST> - .* "(GET|HEAD) /(favicon\.ico|robots\.txt|sitemap\.xml)(\?[^"]*)? HTTP/[^"]+" .*
              ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* "(Googlebot|bingbot|DuckDuckBot|Slurp|Baiduspider|YandexBot|facebookexternalhit|Facebot).*"
EOF

write_file /etc/fail2ban/filter.d/nginx-404.conf <<'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*" (404|444|403|400) .*$
ignoreregex =
EOF

write_file /etc/fail2ban/filter.d/nginx-scanners.conf <<'EOF'
[Definition]
failregex = ^<HOST> - .* "(GET|POST|HEAD) [^"]*/(\.env|\.git|\.svn|\.hg|\.htaccess|\.htpasswd|wp-config\.php|config\.php|configuration\.php|settings\.php)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/[^"]*\.(sql|dump|bak|backup|old|orig|save|swp|zip|tar|tar\.gz|tgz|gz|rar|7z)(\?[^"]*)? HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*/(backup|backups|database|db|dump|phpmyadmin|pma|adminer|server-status|actuator|vendor/phpunit)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "(GET|POST|HEAD) [^"]*(\.\./|\.\.%%2f|%%2e%%2e|/etc/passwd|/proc/self/environ|union.*select|select.*from|drop.*table|information_schema|cmd=|exec=|system=|eval=|shell_exec|passthru|base64_decode|onerror=|onload=|javascript:)[^"]* HTTP/[^"]+" .*
            ^<HOST> - .* "POST /login[^"]* HTTP/[^"]+" (401|403) .*
            ^<HOST> - .* "(PUT|DELETE|TRACE|CONNECT) [^"]* HTTP/[^"]+" .*
ignoreregex = ^<HOST> - .* "(GET|HEAD) [^"]*\.(css|js|png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|eot|pdf|txt|mp4|webm|mp3)(\?[^"]*)? HTTP/[^"]+" .*
EOF

write_file /etc/fail2ban/filter.d/nginx-badbots.conf <<'EOF'
[Definition]
failregex = ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* "(curl|wget|python-requests|python|nikto|nmap|wpscan|sqlmap|masscan|zgrab|Go-http-client|Apache-HttpClient|libwww-perl|Keydrop).*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*Mozlila/5\.0.*Bulid/NRD90M.*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*SM-G892A.*NRD90M.*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*Android 7\.0.*Chrome/60\.0.*"
            ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* ".*Android7\.0.*Chrome/60\.0.*"
ignoreregex = ^<HOST> - .* "(GET|POST|HEAD) [^"]* HTTP/[^"]+" .* "(Googlebot|bingbot|DuckDuckBot|Slurp|Baiduspider|YandexBot|facebookexternalhit|Facebot).*"
EOF

write_file /etc/fail2ban/filter.d/nginx-nohome.conf <<'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(/\.bash|/\.ssh|/\.config|/\.git).*" .*$
ignoreregex =
EOF

write_file /etc/fail2ban/filter.d/nginx-dos.conf <<'EOF'
[Definition]
failregex = ^<HOST> -.*".*" (429|444|503) .*$
ignoreregex =
EOF

write_file /etc/fail2ban/filter.d/nginx-malformed.conf <<'EOF'
[Definition]
# Requests vacios o basura binaria/protocolos ajenos entrando a Nginx.
# Ejemplos:
#   1.2.3.4 - - [date] "-" 400 0 "-" "-"
#   1.2.3.4 - - [date] "\x03\x00..." 400 ... "-" "-"
#   1.2.3.4 - - [date] "PROPFIND / HTTP/1.1" 405 ... "-" "-"
#   1.2.3.4 - - [date] "27;wget%20http://..." 400 ... "-" "-"
failregex = ^<HOST> - .* "-" (400|444) .*$
            ^<HOST> - .* "\\x[0-9A-Fa-f]{2}[^"]*" (400|444) .*$
            ^<HOST> - .* "[^"]*(mstshash=|wget%%20|chmod%%20|Mozi\.m|/bin/sh|/bin/busybox)[^"]*" (400|403|444) .*$
            ^<HOST> - .* "(PROPFIND|TRACK|PRI|MGLNDD_[^"]*|[^"]*wget%%20[^"]*)[^"]*" (400|405|444) .*$
ignoreregex =
EOF

ensure_log_file "$NGINX_ACCESS_LOG"
ensure_log_file "$NGINX_ERROR_LOG"

echo "Validando configuracion Fail2Ban..."
fail2ban-client -t

systemctl enable fail2ban
systemctl restart fail2ban

echo "Esperando a que Fail2Ban este listo..."
for _ in $(seq 1 20); do
  if fail2ban-client ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! fail2ban-client ping >/dev/null 2>&1; then
  echo "Fail2Ban no respondio a tiempo. Revisa: systemctl status fail2ban"
  exit 1
fi

echo
echo "Estado general:"
fail2ban-client status

echo
echo "Jails instalados:"
for jail in sshd nginx-http-auth nginx-dos nginx-malformed nginx-master nginx-404 nginx-scanners nginx-badbots nginx-nohome; do
  echo "---- ${jail} ----"
  fail2ban-client status "$jail" || true
done

echo
echo "Instalacion completada."
echo "Logs: /var/log/fail2ban.log"
