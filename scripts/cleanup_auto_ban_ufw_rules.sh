#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
CLEANUP_CIDRS="${CLEANUP_CIDRS:-}"
STATE_FILE="${STATE_FILE:-/var/lib/security-server/ufw-auto-banned-ips.txt}"

usage() {
  cat <<'EOF'
Elimina de UFW las reglas creadas por ban_repeat_ufw_sources.sh en modo legacy.

Uso:
  ./scripts/cleanup_auto_ban_ufw_rules.sh
  sudo ./scripts/cleanup_auto_ban_ufw_rules.sh --apply

Solo toca reglas que tengan el comentario:
  auto-ban ufw repeat

Variables:
  CLEANUP_CIDRS="172.26.0.0/24"  # opcional, limpia solo IPs dentro de esas redes
  STATE_FILE="/var/lib/security-server/ufw-auto-banned-ips.txt"
EOF
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

mapfile -t rule_numbers < <(
  ufw status numbered \
    | python3 -c '
import ipaddress
import re
import sys

cidrs = []
for raw in sys.argv[1].split():
    try:
        cidrs.append(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        pass

for line in sys.stdin:
    if "auto-ban ufw repeat" not in line:
        continue
    match = re.match(r"\[\s*(\d+)\]\s+.*?\s+([0-9]+(?:\.[0-9]+){3})\s+", line)
    if not match:
        continue
    number, ip_raw = match.groups()
    if cidrs:
        ip = ipaddress.ip_address(ip_raw)
        if not any(ip.version == net.version and ip in net for net in cidrs):
            continue
    print(number)
' "$CLEANUP_CIDRS" \
    | sort -nr
)

if [[ "${#rule_numbers[@]}" -eq 0 ]]; then
  echo "No hay reglas UFW auto-ban para limpiar."
  exit 0
fi

if [[ -n "$CLEANUP_CIDRS" ]]; then
  echo "Reglas UFW auto-ban encontradas en $CLEANUP_CIDRS: ${rule_numbers[*]}"
else
  echo "Reglas UFW auto-ban encontradas: ${rule_numbers[*]}"
fi

if [[ "$MODE" == "check" ]]; then
  echo
  echo "No se elimino nada. Para limpiar:"
  if [[ -n "$CLEANUP_CIDRS" ]]; then
    echo "  sudo env CLEANUP_CIDRS=\"$CLEANUP_CIDRS\" $0 --apply"
  else
    echo "  sudo $0 --apply"
  fi
  exit 0
fi

for number in "${rule_numbers[@]}"; do
  echo "Eliminando regla UFW #$number"
  ufw --force delete "$number"
done

if [[ -n "$CLEANUP_CIDRS" && -f "$STATE_FILE" ]]; then
  tmp="$(mktemp)"
  python3 - "$CLEANUP_CIDRS" "$STATE_FILE" > "$tmp" <<'PY'
import ipaddress
import sys

cidrs = []
for raw in sys.argv[1].split():
    try:
        cidrs.append(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        pass

with open(sys.argv[2], encoding="utf-8") as fh:
    for raw in fh:
        line = raw.strip()
        if not line:
            continue
        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            print(line)
            continue
        if any(ip.version == net.version and ip in net for net in cidrs):
            continue
        print(line)
PY
  install -m 0644 "$tmp" "$STATE_FILE"
  rm -f "$tmp"
  echo "Estado limpiado en $STATE_FILE"
fi

ufw reload
echo "Listo. Revisa con: sudo ufw status numbered"
