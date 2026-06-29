#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_DETECT_SRC="${SCRIPT_DIR}/attack_detect.sh"

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta como root: sudo $0"
  exit 1
fi

cat > /usr/local/bin/security-monitor <<'EOF'
#!/bin/bash
clear
echo "==============================================================="
echo "  MONITOREO DE SEGURIDAD EN TIEMPO REAL"
echo "==============================================================="
echo
echo "FAIL2BAN - resumen:"
fail2ban-client status 2>/dev/null | sed 's/^/  /' || true
echo
echo "MODSECURITY - ultimos eventos:"
tail -20 /var/log/modsec_audit.log 2>/dev/null | grep -E "ModSecurity.*(denied|Warning)|Access denied" | tail -5 | sed 's/^/  /' || true
echo
echo "UFW - ultimos bloqueos:"
tail -10 /var/log/ufw.log 2>/dev/null | grep "BLOCK" | tail -5 | sed 's/^/  /' || true
echo
echo "NGINX:"
systemctl status nginx --no-pager 2>/dev/null | grep -E "Active|Main PID" | sed 's/^/  /' || true
EOF

cat > /usr/local/bin/security-report <<'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  exec sudo "$0" "$@"
fi

modsecurity_rule_count() {
  local nginx_test_output nginx_t_count notice_count total_count
  nginx_test_output="$(nginx -t 2>&1 || true)"
  nginx_t_count="$(nginx -T 2>/dev/null | grep -c '^[[:space:]]*SecRule' || true)"
  notice_count="$(printf '%s\n' "$nginx_test_output" | sed -n 's/.*rules loaded inline\/local\/remote: [0-9]\+\/\([0-9]\+\)\/[0-9]\+.*/\1/p' | tail -n 1)"
  total_count="$nginx_t_count"

  if [ -n "$notice_count" ] && [ "$notice_count" -gt "$total_count" ]; then
    total_count="$notice_count"
  fi

  printf '%s (nginx -T=%s, notice=%s)\n' "$total_count" "$nginx_t_count" "${notice_count:-0}"
}

echo "==============================================================="
echo "  REPORTE DE SEGURIDAD DEL SERVIDOR"
echo "==============================================================="
echo "Fecha: $(date)"
echo
echo "MODSECURITY"
echo "  Engine: $(nginx -T 2>/dev/null | awk '/SecRuleEngine/ {print $2; exit}')"
echo "  Reglas cargadas: $(modsecurity_rule_count)"
echo "  Audit log: /var/log/modsec_audit.log"
echo
echo "FAIL2BAN"
fail2ban-client status 2>/dev/null | sed 's/^/  /' || true
echo
echo "UFW"
ufw status 2>/dev/null | sed 's/^/  /' || true
echo
echo "THREAT INTEL"
if command -v ipset >/dev/null 2>&1 && ipset list security_threat_ipv4 >/dev/null 2>&1; then
  ipset list security_threat_ipv4 | awk '/Number of entries/ {print "  IPs/rangos cargados: " $4}'
  if iptables -C INPUT -m set --match-set security_threat_ipv4 src -j DROP 2>/dev/null; then
    echo "  Bloqueo firewall: activo en INPUT"
  else
    echo "  Bloqueo firewall: ipset existe, pero falta regla DROP en INPUT"
  fi
else
  echo "  No instalado"
fi
echo
echo "NFTABLES EARLY DROP"
if command -v nft >/dev/null 2>&1 && nft list table inet early_drop_attackers >/dev/null 2>&1; then
  echo "  Tabla early_drop_attackers: instalada"
  if systemctl list-unit-files security-early-drop-nft.service 2>/dev/null | grep -q '^security-early-drop-nft\.service'; then
    systemctl is-enabled security-early-drop-nft.service 2>/dev/null | sed 's/^/  Servicio dedicated enabled: /' || true
    systemctl is-active security-early-drop-nft.service 2>/dev/null | sed 's/^/  Servicio dedicated active: /' || true
  fi
  systemctl is-enabled nftables 2>/dev/null | sed 's/^/  nftables.service enabled: /' || true
  systemctl is-active nftables 2>/dev/null | sed 's/^/  nftables.service active: /' || true
  nft list table inet early_drop_attackers 2>/dev/null | awk '/elements =/ {capture=1} capture {print}' | head -20 | sed 's/^/  /'
else
  echo "  No instalado o sin tabla early_drop_attackers"
fi
echo
echo "PUERTOS ESCUCHANDO"
ss -tulpen 2>/dev/null | sed -n '1,40p'
echo
echo "ULTIMOS BLOQUEOS UFW"
tail -20 /var/log/ufw.log 2>/dev/null | grep "BLOCK" | tail -5 | sed 's/^/  /' || true
echo
echo "ATTACK DETECT"
if command -v attack-detect >/dev/null 2>&1; then
  echo "  Instalado: attack-detect"
  echo "  Uso: sudo attack-detect /var/log/nginx/access.log"
else
  echo "  No instalado"
fi
EOF

if [ -f "$ATTACK_DETECT_SRC" ]; then
  install -m 0755 "$ATTACK_DETECT_SRC" /usr/local/bin/attack-detect
  ln -sf /usr/local/bin/attack-detect /usr/local/bin/attack_detect
else
  echo "AVISO: no encontre $ATTACK_DETECT_SRC; no instalo attack-detect."
fi

chmod 0755 /usr/local/bin/security-monitor /usr/local/bin/security-report
echo "Instalados: security-monitor, security-report, attack-detect"
