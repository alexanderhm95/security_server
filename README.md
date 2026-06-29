# Security Stack SP1

Proyecto para replicar la seguridad base del servidor SP1 en otros servidores.

Incluye:

- UFW con politica `deny incoming`.
- Fail2Ban para SSH y patrones Nginx.
- ModSecurity para Nginx.
- OWASP Core Rule Set.
- Reglas locales contra scanners, user-agent vacio y rutas sensibles.
- Herramientas `security-monitor` y `security-report`.
- Threat intelligence con `ipset` para bloquear rangos/IPs conocidos.

## Uso Rapido

```bash
cd /home/administrador/security-stack-sp1
cp security-stack.env.example security-stack.env
nano security-stack.env
sudo ./scripts/install_security_stack.sh
```

Para SP1 puedes partir de:

```bash
cp security-stack.sp1.env.example security-stack.env
```

## Variables Importantes

- `IGNORE_IPS`: redes que nunca deben ser bloqueadas por Fail2Ban. Por defecto incluye `190.96.96.0/21`.
- `PUBLIC_IGNORE_IPS`: redes permitidas para jails web. Por defecto incluye `190.96.96.0/21`.
- `SSH_ALLOW_CIDR`: red/IP autorizada para SSH. Si queda vacia, el instalador no cambia SSH.
- `HTTP_ALLOW_CIDR` / `HTTPS_ALLOW_CIDR`: usa `any` o un CIDR especifico. Por defecto `80` queda limitado a `190.96.96.0/21` y `443` queda publico.
- `WIREGUARD_ALLOW_CIDR`: usa `any` o un CIDR especifico. Por defecto queda limitado a `190.96.96.0/21`.
- `DISCORD_WEBHOOK_URL`: opcional. No se guarda ningun webhook por defecto.
- `MODSEC_RULE_ENGINE`: `On` para bloquear, `DetectionOnly` para solo observar.
- `BUILD_MODSECURITY_FROM_SOURCE`: `auto` intenta paquete y compila si hace falta; `yes` fuerza compilacion; `no` exige paquete/modulo ya disponible.
- `ENABLE_THREAT_INTEL`: instala un `ipset` actualizado por systemd timer.
- `THREAT_INTEL_SOURCES`: por defecto `spamhaus_drop`; tambien soporta `abuseipdb` si defines `ABUSEIPDB_API_KEY`.

## Recomendacion Para Nuevos Servidores

1. Ejecutar primero con `MODSEC_RULE_ENGINE="DetectionOnly"` si el sitio ya tiene trafico sensible.
2. Revisar `/var/log/modsec_audit.log`.
3. Cambiar a `MODSEC_RULE_ENGINE="On"` cuando no haya falsos positivos criticos.

## Verificacion

```bash
sudo nginx -t
security-report
curl -k -A "masscan" https://localhost/ -s -o /dev/null -w "HTTP: %{http_code}\n"
curl -k "https://localhost/?q=<script>alert(1)</script>" -s -o /dev/null -w "HTTP: %{http_code}\n"
```

Los ataques de prueba deberian devolver `403` cuando `MODSEC_RULE_ENGINE="On"`.

## Threat Intel

Por defecto se carga Spamhaus DROP en un `ipset` llamado `security_threat_ipv4` y se inserta una regla al inicio de `INPUT`:

```bash
sudo ipset list security_threat_ipv4
sudo systemctl status security-threat-intel.timer
sudo security-threat-intel-update
```

Para AbuseIPDB agrega en `security-stack.env`:

```bash
THREAT_INTEL_SOURCES="spamhaus_drop abuseipdb"
ABUSEIPDB_API_KEY="TU_API_KEY"
ABUSEIPDB_CONFIDENCE_MINIMUM="90"
```

## Nota Sobre ModSecurity

En Ubuntu/Debian el modulo puede venir por paquete (`libnginx-mod-http-modsecurity`) o puede requerir compilacion manual. El instalador maneja ambos casos en modo `auto`:

1. Intenta instalar el modulo por paquete.
2. Si falta `libmodsecurity.so.3` o el modulo no carga, compila `libmodsecurity` y `ModSecurity-nginx`.
3. Registra `/usr/local/modsecurity/lib` en `ldconfig`.
