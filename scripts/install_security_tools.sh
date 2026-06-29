#!/bin/bash
set -euo pipefail

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
echo "==============================================================="
echo "  REPORTE DE SEGURIDAD DEL SERVIDOR"
echo "==============================================================="
echo "Fecha: $(date)"
echo
echo "MODSECURITY"
echo "  Engine: $(nginx -T 2>/dev/null | awk '/SecRuleEngine/ {print $2; exit}')"
echo "  Reglas SecRule cargadas: $(nginx -T 2>/dev/null | grep -c '^[[:space:]]*SecRule' || true)"
echo "  Audit log: /var/log/modsec_audit.log"
echo
echo "FAIL2BAN"
fail2ban-client status 2>/dev/null | sed 's/^/  /' || true
echo
echo "UFW"
ufw status 2>/dev/null | sed 's/^/  /' || true
echo
echo "PUERTOS ESCUCHANDO"
ss -tulpen 2>/dev/null | sed -n '1,40p'
echo
echo "ULTIMOS BLOQUEOS UFW"
tail -20 /var/log/ufw.log 2>/dev/null | grep "BLOCK" | tail -5 | sed 's/^/  /' || true
EOF

chmod 0755 /usr/local/bin/security-monitor /usr/local/bin/security-report
echo "Instalados: security-monitor, security-report"
