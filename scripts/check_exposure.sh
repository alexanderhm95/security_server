#!/usr/bin/env bash
# Revisión LOCAL y de solo lectura: ¿este servidor entrega ficheros con secretos a quien entra por IP?
# No cambia nada. No muestra el contenido de ningún fichero, sólo el veredicto.
# Uso (en cada servidor):  sudo bash scripts/check_exposure.sh
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo"; exit 1; }

H=$(hostname); MALO=0; DUDAS=()
IP=$(hostname -I | awk '{print $1}')
echo "################ $H ($IP) ################"

# ---------- 1. nginx del sistema ----------
echo "== 1. nginx del sistema"
CONF=""
if command -v nginx >/dev/null; then
  if CONF=$(nginx -T 2>&1); then
    echo "   nginx -T OK: $(grep -c '^# configuration file' <<<"$CONF") ficheros, $(grep -cE '^[[:space:]]*server[[:space:]]*\{' <<<"$CONF") bloques server"
  else
    echo "   !!! nginx -T falló:"; head -5 <<<"$CONF" | sed 's/^/       /'
    DUDAS+=("nginx -T falló"); CONF=""
  fi
else
  echo "   no hay nginx instalado en el sistema"
fi

if [ -n "$CONF" ]; then
  echo "-- vhost que atiende por IP en cada puerto (explícito con default_server, o el PRIMERO del puerto)"
  awk '
    /^# configuration file/ {f=$4}
    /^[[:space:]]*server[[:space:]]*\{/ {inb=1; n++; ports=""; sn[n]=""; rt[n]=""; r444[n]=""; file[n]=f}
    inb && /^[[:space:]]*listen[[:space:]]/ {
        p=$2; gsub(/;/,"",p); sub(/.*:/,"",p); ports=ports" "p
        if ($0 ~ /default_server/) explicit[p]=n }
    inb && /^[[:space:]]*server_name[[:space:]]/ {sn[n]=$0; gsub(/^[[:space:]]+|;/,"",sn[n])}
    inb && /^[[:space:]]*root[[:space:]]/ && rt[n]=="" {rt[n]=$2; gsub(/;/,"",rt[n])}
    inb && /^[[:space:]]*return[[:space:]]+(444|301|302|403)/ && r444[n]=="" {r444[n]=$1" "$2}
    inb && /^\}/ {
        split(ports, ps, " ")
        for (i in ps) { q=ps[i]; if (q=="") continue
          if (!(q in first)) first[q]=n }
        inb=0 }
    END {
      for (q in first) { k = (q in explicit) ? explicit[q] : first[q]
        printf "   puerto %-5s -> %s  [%s]\n       %s\n       root: %s   %s\n", q,
          (q in explicit ? "default_server" : "IMPLÍCITO (primer bloque)"), file[k], sn[k],
          (rt[k]=="" ? "(ninguno)" : rt[k]), (r444[k]=="" ? "" : "<- " r444[k]) } }' <<<"$CONF"
fi

# ---------- 2. Docker ----------
echo "== 2. Contenedores web en Docker"
DOCKER_DIRS=()
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  while read -r id name img ports; do
    [ -n "$id" ] || continue
    echo "   $name ($img) $ports"
    while read -r src; do [ -d "$src" ] && DOCKER_DIRS+=("$src"); done < <(docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$id")
  done < <(docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Ports}}' | grep -iE 'nginx|apache|httpd|php|wordpress|caddy|traefik|web|front|app|api' )
  [ ${#DOCKER_DIRS[@]} -gt 0 ] && echo "   carpetas montadas: ${DOCKER_DIRS[*]}"
  [ ${#DOCKER_DIRS[@]} -gt 0 ] || echo "   (ningún contenedor web con carpetas montadas)"
else
  echo "   no hay Docker"
fi

# ---------- 3. Ficheros con secretos ----------
echo "== 3. Ficheros con secretos en carpetas web"
mapfile -t ROOTS < <(awk '/^[[:space:]]*root[[:space:]]/ {gsub(/;/,"",$2); print $2}' <<<"$CONF" | sort -u)
BUSCAR=("${ROOTS[@]}" /var/www /srv "${DOCKER_DIRS[@]}")
mapfile -t SECRETOS < <(for r in "${BUSCAR[@]}"; do
    [ -d "$r" ] && find "$r" -maxdepth 5 \( -name 'wp-config.php' -o -name '.env' -o -name '.env.*' \
       -o -name 'config.php' -o -name 'settings.py' -o -name '*.sql' -o -name '*.sql.gz' -o -path '*/.git/config' \) \
       -not -path '*/node_modules/*' -not -path '*/vendor/*' -not -path '*/site-packages/*' 2>/dev/null
  done | sort -u)
if [ ${#SECRETOS[@]} -eq 0 ]; then echo "   (ninguno en: ${BUSCAR[*]})"; else printf '   %s\n' "${SECRETOS[@]}"; fi

# ---------- 4. Prueba como atacante ----------
echo "== 4. Pedirlos por IP (http/https), siguiendo redirecciones"
PROBADOS=0
for fichero in "${SECRETOS[@]}"; do
  mapfile -t RUTAS < <(for r in /var/www/html /var/www "${ROOTS[@]}" "${DOCKER_DIRS[@]}"; do
      case "$fichero" in "${r%/}"/*) echo "${fichero#"${r%/}"}";; esac
    done | sort -u)
  for ruta in "${RUTAS[@]}"; do
    for base in "http://$IP" "https://$IP" "http://127.0.0.1"; do
      tmp=$(mktemp); PROBADOS=$((PROBADOS+1))
      code=$(curl -skL --max-redirs 3 -m 15 -A 'Mozilla/5.0' -o "$tmp" -w '%{http_code}' "$base$ruta" 2>/dev/null)
      if [ "$code" = 200 ] && grep -qE '<\?php|DB_PASSWORD|AUTH_KEY|APP_KEY|SECRET_KEY|PASSWORD *=|\[core\]|CREATE TABLE' "$tmp"; then
        echo "   !!! EXPUESTO: $base$ruta"; MALO=1
      else
        echo "   ok  $base$ruta -> $code"
      fi
      rm -f "$tmp"
    done
  done
done
[ $PROBADOS -gt 0 ] || echo "   (nada que probar)"

echo
if [ $MALO = 1 ]; then
  echo "RESULTADO $H: VULNERABLE — hay ficheros con secretos accesibles por IP"
elif [ ${#DUDAS[@]} -gt 0 ]; then
  echo "RESULTADO $H: NO CONCLUYENTE — ${DUDAS[*]}"
else
  echo "RESULTADO $H: sin exposición encontrada"
fi
