# Checklist De Replica

Antes de ejecutar:

- Confirmar acceso por consola o una segunda sesion SSH.
- Definir `SSH_ALLOW_CIDR` si SSH debe quedar restringido.
- Confirmar dominio y certificados existentes.
- Confirmar que Nginx ya sirve el sitio correctamente.
- Copiar `security-stack.env.example` a `security-stack.env`.

Despues de ejecutar:

- `sudo nginx -t`
- `sudo systemctl status nginx fail2ban --no-pager`
- `sudo ufw status numbered`
- `security-report`
- `sudo ipset list security_threat_ipv4`
- Revisar `/var/log/modsec_audit.log`.
- Probar login, portal, formularios y subida de archivos si aplica.

Puertos publicos recomendados:

- `80/tcp`
- `443/tcp`
- `22/tcp` solo desde IP/VPN autorizada
- `51820/udp` solo si usa WireGuard

Servicios internos como backends en `8081` deben escuchar en `127.0.0.1`, no en `0.0.0.0`.
