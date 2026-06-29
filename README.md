# Security Stack SP1

Proyecto para replicar la seguridad base del servidor SP1 en otros servidores.

Incluye:

- UFW con politica `deny incoming`.
- Fail2Ban para SSH y patrones Nginx.
- Jail `nginx-malformed` para requests vacios, basura binaria y metodos/protocolos ajenos a HTTP normal.
- ModSecurity para Nginx.
- OWASP Core Rule Set.
- Reglas locales contra scanners, user-agent vacio y rutas sensibles.
- Herramientas `security-monitor` y `security-report`.
- Analizador profesional `attack-detect` para revisar `access.log`, bots, rutas sensibles, puertos, hosts, UFW y acciones sugeridas.
- Threat intelligence con `ipset` para bloquear rangos/IPs conocidos.
- Endurecimiento generico para servidores: cierre de puertos UFW, reglas permitidas por archivo, bloqueo temprano con nftables y auto-ban de IPs repetidas en `/var/log/ufw.log`.

## Uso Rapido

```bash
cd /home/administrador/monitoreo/scripts/security-stack-sp1
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
- `PROMPT_IGNORE_RANGES`: `auto` hace que el instalador pregunte los ignores si corre en una terminal; usa `no` para automatizaciones.
  La primera pregunta acepta rangos comunes que se agregan a Fail2Ban, threat intel y nftables a la vez.
- `SSH_ALLOW_CIDR`: red/IP autorizada para SSH. Si queda vacia, el instalador no cambia SSH.
- `HTTP_ALLOW_CIDR` / `HTTPS_ALLOW_CIDR`: usa `any` o un CIDR especifico. Por defecto `80` queda limitado a `190.96.96.0/21` y `443` queda publico.
- `WIREGUARD_ALLOW_CIDR`: usa `any` o un CIDR especifico. Por defecto queda limitado a `190.96.96.0/21`.
- `DISCORD_WEBHOOK_URL`: opcional. No se guarda ningun webhook por defecto.
- `MODSEC_RULE_ENGINE`: `On` para bloquear, `DetectionOnly` para solo observar.
- `BUILD_MODSECURITY_FROM_SOURCE`: `auto` intenta paquete y compila si hace falta; `yes` fuerza compilacion; `no` exige paquete/modulo ya disponible.
- `ENABLE_THREAT_INTEL`: instala un `ipset` actualizado por systemd timer.
- `THREAT_INTEL_SOURCES`: por defecto `spamhaus_drop`; tambien soporta `abuseipdb` si defines `ABUSEIPDB_API_KEY`.
- `ENABLE_EARLY_DROP_NFT`: `auto` activa nftables early drop solo si hay redes en `security-nft-blocks.txt`; `yes` fuerza la etapa; `no` la omite.
- `BLOCK_NETWORKS_FILE`: archivo con redes/IPs para bloquear temprano con nftables. Por defecto `./security-nft-blocks.txt`.
- `TRUST_PRIVATE_CIDRS`: `yes` evita auto-bloquear redes privadas RFC1918; usa `no` si el borde/proveedor te entrega trafico externo con SRC privada visible en UFW, por ejemplo `172.26.x.x`.
- `TRUSTED_CIDRS`: redes/IPs que `suggest_nft_blocks_from_ufw.sh` y `ban_repeat_ufw_sources.sh` nunca deben agregar a `nftables`.
- `AUTO_BAN_BACKEND`: `nft` agrega repetidos a `BLOCK_NETWORKS_FILE` y recarga nftables; `ufw` queda solo como modo legacy.
- `AUTO_BAN_NFT_PREFIX`: prefijo usado al convertir IPs repetidas a redes nftables. Usa `32` para IP exacta o `24` para cortar subredes ruidosas.

## Recomendacion Para Nuevos Servidores

1. Ejecutar primero con `MODSEC_RULE_ENGINE="DetectionOnly"` si el sitio ya tiene trafico sensible.
2. Revisar `/var/log/modsec_audit.log`.
3. Cambiar a `MODSEC_RULE_ENGINE="On"` cuando no haya falsos positivos criticos.

## Verificacion

```bash
sudo nginx -t
security-report
sudo attack-detect /var/log/nginx/access.log
curl -k -A "masscan" https://localhost/ -s -o /dev/null -w "HTTP: %{http_code}\n"
curl -k "https://localhost/?q=<script>alert(1)</script>" -s -o /dev/null -w "HTTP: %{http_code}\n"
```

Los ataques de prueba deberian devolver `403` cuando `MODSEC_RULE_ENGINE="On"`.

## Endurecimiento Firewall Generico

Estos scripts ayudan a cerrar puertos sensibles, aplicar reglas permitidas por servidor y reducir ruido de scanners contra la IP publica. No tienen redes obligatorias quemadas: cada servidor debe usar su propio archivo `.env` y listas de reglas.

Flujo recomendado para cualquier servidor:

```bash
# 1. Copia y ajusta configuracion.
cp security-firewall.env.example security-firewall.env
cp security-firewall.allow.example security-firewall.allow
cp security-firewall.delete.example security-firewall.delete
cp security-nft-blocks.example.txt security-nft-blocks.txt
nano security-firewall.env
nano security-firewall.allow
nano security-nft-blocks.txt

# 2. Simula sin aplicar.
ENV_FILE=./security-firewall.env ./scripts/hardening_firewall.sh
ENV_FILE=./security-firewall.env ./scripts/drop_hot_attackers_nft.sh

# 3. Aplica UFW.
sudo ENV_FILE=./security-firewall.env ./scripts/hardening_firewall.sh --apply

# 4. Aplica bloqueo nftables runtime.
sudo ENV_FILE=./security-firewall.env ./scripts/drop_hot_attackers_nft.sh --apply

# Hace persistente el bloqueo nftables despues de reinicio.
sudo ENV_FILE=./security-firewall.env ./scripts/install_early_drop_persistent.sh

# Opcional: generar redes candidatas desde /var/log/ufw.log.
sudo env ENV_FILE=./security-stack.env MIN_HITS=20 ./scripts/suggest_nft_blocks_from_ufw.sh --write

# Banea IPs individuales repetidas vistas en /var/log/ufw.log.
sudo env ENV_FILE=./security-firewall.env THRESHOLD=20 ./scripts/ban_repeat_ufw_sources.sh --apply

# Si ves ataques con SRC privada en UFW BLOCK, como 172.26.x.x,
# usa TRUST_PRIVATE_CIDRS=no en el env o pasalo en la ejecucion.
sudo env ENV_FILE=./security-stack.env TRUST_PRIVATE_CIDRS=no MIN_HITS=5 ./scripts/suggest_nft_blocks_from_ufw.sh --write
sudo env ENV_FILE=./security-stack.env TRUST_PRIVATE_CIDRS=no THRESHOLD=5 ./scripts/ban_repeat_ufw_sources.sh --apply

# Si ya quedaron reglas auto-ban dentro de UFW por el modo anterior:
sudo ./scripts/cleanup_auto_ban_ufw_rules.sh --apply
```

Verificacion recomendada:

```bash
sudo ufw status verbose
sudo nft list table inet early_drop_attackers
systemctl status security-early-drop-nft --no-pager
ss -ltnup | grep -E ':(3000|3100|9090|9096|9099|9100|9115)\s'
```

Si Cockpit se usa en el servidor, mantenlo escuchando en `9090/tcp`, pero permite acceso solo desde VPN/red autorizada:

```bash
sudo ufw allow from 10.88.0.0/24 to any port 9090 proto tcp comment "Cockpit solo VPN"
sudo ufw deny from any to any port 9090 proto tcp comment "Cockpit protegido"
```

Ejemplo para SP2:

```bash
ENV_FILE=./examples/sp2-security-firewall.env ./scripts/hardening_firewall.sh
sudo ENV_FILE=./examples/sp2-security-firewall.env ./scripts/hardening_firewall.sh --apply
sudo ENV_FILE=./examples/sp2-security-firewall.env ./scripts/drop_hot_attackers_nft.sh --apply
sudo ENV_FILE=./examples/sp2-security-firewall.env ./scripts/install_early_drop_persistent.sh
sudo env ENV_FILE=./examples/sp2-security-firewall.env THRESHOLD=20 ./scripts/ban_repeat_ufw_sources.sh --apply
```

Notas:

- Los paquetes de scanners pueden seguir llegando a la IP publica; el objetivo es que se descarten antes de llegar a servicios.
- El trafico IPv6 `fe80::` hacia `ff02::1` es link-local/multicast, no ataque de Internet.
- `ban_repeat_ufw_sources.sh` guarda estado en `/var/lib/security-server/ufw-auto-banned-ips.txt` para no duplicar bloqueos.
- `install_early_drop_persistent.sh` usa un servicio dedicado llamado `security-early-drop-nft.service`; no modifica `/etc/nftables.conf` ni reinicia `nftables.service`, para no borrar reglas de UFW/iptables.
- El instalador principal (`install_security_stack.sh`) tambien ejecuta `install_early_drop_persistent.sh` cuando `ENABLE_EARLY_DROP_NFT` esta en `yes` o cuando esta en `auto` y existe una lista con redes. Si `security-early-drop-nft.service` no existe, normalmente significa que no habia redes configuradas para cargar.

## Monitor Y Reportes

El instalador deja tres comandos operativos:

- `security-report`: resumen del estado de Nginx, ModSecurity, Fail2Ban, UFW, threat intel, puertos y bloqueos recientes.
- `security-monitor`: vista rapida en consola para eventos recientes de Fail2Ban, ModSecurity, UFW y Nginx.
- `attack-detect`: analizador profundo de `/var/log/nginx/access.log`.

Uso recomendado:

```bash
security-report
security-monitor
sudo attack-detect /var/log/nginx/access.log
```

`attack-detect` revisa codigos HTTP, trafico por hora, metodos usados, ataques por puerto, hosts solicitados, top IPs con pais/ISP/ASN, rutas sensibles, scanners conocidos, user-agents sospechosos, ranking de riesgo por IP, bloqueos UFW y acciones manuales sugeridas.

El analizador no bloquea automaticamente. Sirve para monitoreo y decision operativa; los bloqueos automaticos quedan en Fail2Ban, ModSecurity, UFW y threat intel.

Fail2Ban bloquea requests vacios/malformados mediante la jail `nginx-malformed`. Cubre entradas como `"-" 400`, bytes `\x03...`, intentos RDP contra Nginx (`mstshash`), `PROPFIND`, `MGLNDD_...` y payloads tipo `wget%%20/Mozi`.

### Log Nginx Recomendado Para Attack Detect

Para que `attack-detect` pueda mostrar puerto y host, Nginx debe registrar `host` y `port`. Dentro de `http { ... }`:

```nginx
log_format attacklog '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent" '
                     'host="$host" port="$server_port"';
```

En cada `server { ... }` que quieras monitorear:

```nginx
access_log /var/log/nginx/access.log attacklog;
```

Aplica cambios:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

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
