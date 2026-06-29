#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
ENV_FILE="${ENV_FILE:-}"
ALLOW_RULES_FILE="${ALLOW_RULES_FILE:-}"
DELETE_RULES_FILE="${DELETE_RULES_FILE:-}"
MONITORING_PORTS="${MONITORING_PORTS:-3000/tcp 3100/tcp 9090/tcp 9096/tcp 9099/tcp 9100/tcp 9115/tcp}"
UFW_LOGGING="${UFW_LOGGING:-low}"
ENV_DIR=""

if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
  ENV_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

resolve_env_path() {
  local value="$1"
  [[ -n "$value" ]] || return 0
  if [[ "$value" = /* || -z "$ENV_DIR" ]]; then
    printf '%s\n' "$value"
  else
    printf '%s/%s\n' "$ENV_DIR" "$value"
  fi
}

ALLOW_RULES_FILE="$(resolve_env_path "$ALLOW_RULES_FILE")"
DELETE_RULES_FILE="$(resolve_env_path "$DELETE_RULES_FILE")"

usage() {
  cat <<'EOF'
Endurece UFW de forma generica.

Uso:
  ./scripts/hardening_firewall.sh
  sudo ./scripts/hardening_firewall.sh --apply

Variables:
  MONITORING_PORTS="3000/tcp 9090/tcp"
  ALLOW_RULES_FILE="./security-firewall.allow"
  DELETE_RULES_FILE="./security-firewall.delete"
  UFW_LOGGING="low"
  ENV_FILE="./security-firewall.env"

Formato ALLOW_RULES_FILE / DELETE_RULES_FILE:
  Una regla UFW por linea, sin la palabra "ufw".
  Lineas vacias o con # se ignoran.

Ejemplo:
  allow from 10.88.0.0/24 to any port 22 proto tcp comment SSH VPN
  allow 443/tcp comment HTTPS publico
EOF
}

run() {
  if [[ "$MODE" == "--apply" ]]; then
    echo "+ $*"
    "$@"
  else
    printf 'DRY-RUN: %q ' "$@"
    printf '\n'
  fi
}

run_rule_file() {
  local file="$1"
  [[ -n "$file" && -f "$file" ]] || return 0

  while IFS= read -r rule || [[ -n "$rule" ]]; do
    rule="${rule%%#*}"
    rule="${rule#"${rule%%[![:space:]]*}"}"
    rule="${rule%"${rule##*[![:space:]]}"}"
    [[ -n "$rule" ]] || continue
    # shellcheck disable=SC2086
    run ufw $rule || true
  done < "$file"
}

if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$MODE" != "check" && "$MODE" != "--apply" ]]; then
  usage
  exit 2
fi

if [[ "$MODE" == "--apply" && "${EUID}" -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo $0 --apply"
  exit 1
fi

echo "== Estado actual =="
ss -ltnup | sed -n '1,160p' || true
echo

echo "== Reglas UFW propuestas =="
run ufw default deny incoming
run ufw default allow outgoing
run ufw default deny routed

echo
echo "== Reglas a eliminar =="
run_rule_file "$DELETE_RULES_FILE"

echo
echo "== Reglas permitidas =="
run_rule_file "$ALLOW_RULES_FILE"

echo
echo "== Bloqueo publico de puertos protegidos =="
for port in $MONITORING_PORTS; do
  proto="${port##*/}"
  number="${port%%/*}"
  [[ "$proto" == "$number" ]] && proto="tcp"
  run ufw deny from any to any port "$number" proto "$proto" comment "security protected $port"
done

run ufw logging "$UFW_LOGGING"
run ufw reload

echo
if [[ "$MODE" == "--apply" ]]; then
  echo "Listo. Revisa con: sudo ufw status verbose"
else
  echo "No se aplico nada. Para aplicar:"
  echo "  sudo ENV_FILE=$ENV_FILE ALLOW_RULES_FILE=$ALLOW_RULES_FILE DELETE_RULES_FILE=$DELETE_RULES_FILE $0 --apply"
fi
