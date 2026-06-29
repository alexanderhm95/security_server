#!/bin/bash

# ==================================================
# ANALIZADOR PROFESIONAL DE ATAQUES NGINX
# Autor: Seguridad / Monitoreo
# Uso:
#   sudo ./attack_detect.sh
#   sudo ./attack_detect.sh /var/log/nginx/access.log
# ==================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

LOG_FILE="${1:-/var/log/nginx/access.log}"
LIMIT_TOP=20
IP_CACHE="/tmp/attack_detect_ip_cache.txt"
FAIL2BAN_BANNED_CACHE="/tmp/attack_detect_fail2ban_banned.txt"
FIREWALL_BLOCKED_CACHE="/tmp/attack_detect_firewall_blocked.txt"

mkdir -p "$(dirname "$IP_CACHE")"
touch "$IP_CACHE"

mostrar_seccion() {
    echo ""
    printf "${PURPLE}=== %s ===${NC}\n\n" "$1"
}

linea() {
    echo "--------------------------------------------------"
}

estado_ok() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

estado_revisar() {
    printf "${YELLOW}[REVISAR]${NC} %s\n" "$1"
}

estado_accion() {
    printf "${RED}[ACCION]${NC} %s\n" "$1"
}

estado_info() {
    printf "${CYAN}[INFO]${NC} %s\n" "$1"
}

requisito_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "🔐 Ejecuta con sudo:"
        echo "sudo $0"
        exit 1
    fi
}

validar_log() {
    if [ ! -f "$LOG_FILE" ]; then
        echo "❌ No existe el log: $LOG_FILE"
        exit 1
    fi
}

ip_info() {
    local ip="$1"

    if grep -q "^$ip|" "$IP_CACHE"; then
        grep "^$ip|" "$IP_CACHE" | head -1 | cut -d'|' -f2-
        return
    fi

    local data
    data=$(curl -s --connect-timeout 3 \
        "http://ip-api.com/line/$ip?fields=country,isp,org,as,query" 2>/dev/null | paste -sd '|' -)

    if [ -z "$data" ]; then
        data="N/A|N/A|N/A|N/A|$ip"
    fi

    echo "$ip|$data" >> "$IP_CACHE"
    echo "$data"
}

fail2ban_banned_ips() {
    : > "$FAIL2BAN_BANNED_CACHE"

    if ! command -v fail2ban-client >/dev/null 2>&1; then
        return
    fi

    fail2ban-client banned 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$FAIL2BAN_BANNED_CACHE" || true

    fail2ban-client status 2>/dev/null | awk -F: '/Jail list/ {gsub(/,/, "", $2); print $2}' | tr ' ' '\n' | while read jail; do
        [ -n "$jail" ] || continue
        fail2ban-client status "$jail" 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$FAIL2BAN_BANNED_CACHE" || true
    done

    sort -u "$FAIL2BAN_BANNED_CACHE" -o "$FAIL2BAN_BANNED_CACHE"
}

ip_ya_baneada() {
    local ip="$1"
    [ -s "$FAIL2BAN_BANNED_CACHE" ] && grep -qx "$ip" "$FAIL2BAN_BANNED_CACHE"
}

firewall_blocked_ips() {
    : > "$FIREWALL_BLOCKED_CACHE"

    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null | awk '/DENY|REJECT/ {for (i=1; i<=NF; i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) print $i}' >> "$FIREWALL_BLOCKED_CACHE" || true
    fi

    if command -v iptables >/dev/null 2>&1; then
        iptables -S 2>/dev/null | awk '/-j (DROP|REJECT)/ {for (i=1; i<=NF; i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]+)?$/) {sub(/\/[0-9]+$/, "", $i); print $i}}' >> "$FIREWALL_BLOCKED_CACHE" || true
    fi

    if command -v nft >/dev/null 2>&1; then
        nft list ruleset 2>/dev/null | awk '/drop|reject/ {for (i=1; i<=NF; i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) print $i}' >> "$FIREWALL_BLOCKED_CACHE" || true
    fi

    sort -u "$FIREWALL_BLOCKED_CACHE" -o "$FIREWALL_BLOCKED_CACHE"
}

ip_bloqueada_firewall() {
    local ip="$1"
    [ -s "$FIREWALL_BLOCKED_CACHE" ] && grep -qx "$ip" "$FIREWALL_BLOCKED_CACHE"
}

ip_en_red_permitida() {
    local ip="$1"
    awk -v ip="$ip" '
    function octets(value, a) {
        return split(value, a, ".") == 4
    }
    BEGIN {
        if (!octets(ip, o)) exit 1

        # Redes locales/reservadas y red publica propia configurada en install_fail2ban_sp1.sh.
        if (o[1] == 10) exit 0
        if (o[1] == 127) exit 0
        if (o[1] == 172 && o[2] >= 16 && o[2] <= 31) exit 0
        if (o[1] == 192 && o[2] == 168) exit 0
        if (o[1] == 169 && o[2] == 254) exit 0
        if (o[1] == 100 && o[2] >= 64 && o[2] <= 127) exit 0
        if (o[1] == 190 && o[2] == 96 && o[3] >= 96 && o[3] <= 103) exit 0

        exit 1
    }'
}

header() {
    clear
    echo "=================================================="
    echo "🛡️  ANALIZADOR PROFESIONAL DE ATAQUES NGINX"
    echo "=================================================="
    echo ""
    echo "📁 Log file: $LOG_FILE"
    echo "📊 Total entradas: $(wc -l < "$LOG_FILE")"
    echo "💾 Tamaño: $(du -h "$LOG_FILE" | awk '{print $1}')"
    echo "🕒 Fecha análisis: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    estado_info "Este informe analiza patrones del access.log. Una coincidencia no significa compromiso."
    estado_info "Las acciones sugeridas omiten IPs ya bloqueadas por Fail2Ban/firewall y redes permitidas."
}

analizar_codigos_estado() {
    mostrar_seccion "ESTADÍSTICAS HTTP CORREGIDAS"

    awk -F'"' '
    {
        request=$2;
        split($3,a," ");
        status=a[1];

        if (status ~ /^[0-9][0-9][0-9]$/) {
            codes[status]++;
        } else {
            invalid++;
        }

        if (request == "-") {
            empty_req++;
        }
    }
    END {
        for (c in codes) print codes[c], c;
        if (invalid > 0) print invalid, "INVALIDO";
        if (empty_req > 0) print empty_req, "REQUEST_VACIO";
    }' "$LOG_FILE" | sort -rn | while read count code; do
        case "$code" in
            200|201|204) color=$GREEN ;;
            301|302|304) color=$BLUE ;;
            400|401|403|404) color=$YELLOW ;;
            500|502|503|504) color=$RED ;;
            INVALIDO|REQUEST_VACIO) color=$PURPLE ;;
            *) color=$NC ;;
        esac

        printf "   ${color}%-15s${NC} - ${CYAN}%5s${NC} requests\n" "$code" "$count"
    done

    echo ""
    echo "ℹ️ REQUEST_VACIO = conexión sin petición HTTP válida."
    echo "ℹ️ Suele venir de scanners, bots, pruebas automáticas o tráfico basura."
}

analizar_por_hora() {
    mostrar_seccion "TRÁFICO POR HORA"

    awk -F'[' '{print $2}' "$LOG_FILE" | cut -d: -f1,2 | sort | uniq -c | while read count hora; do
        printf "🕒 ${CYAN}%-18s${NC} - ${GREEN}%4s${NC} requests\n" "$hora" "$count"
    done
}

analizar_top_ips() {
    mostrar_seccion "TOP IPS + PAÍS + ISP + ORG + ASN"

    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -"$LIMIT_TOP" | while read count ip; do
        info=$(ip_info "$ip")
        country=$(echo "$info" | cut -d'|' -f1)
        isp=$(echo "$info" | cut -d'|' -f2)
        org=$(echo "$info" | cut -d'|' -f3)
        asn=$(echo "$info" | cut -d'|' -f4)

        printf "🌐 ${RED}%-15s${NC} ${CYAN}%4s${NC} req | ${YELLOW}%s${NC}\n" "$ip" "$count" "${country:-N/A}"
        printf "   ISP: %s\n" "${isp:-N/A}"
        printf "   ORG: %s\n" "${org:-N/A}"
        printf "   ASN: %s\n\n" "${asn:-N/A}"
    done
}

analizar_por_puerto() {
    mostrar_seccion "ATAQUES POR PUERTO"

    if grep -q 'port="' "$LOG_FILE"; then
        grep -o 'port="[0-9]*"' "$LOG_FILE" | cut -d'"' -f2 | sort | uniq -c | sort -rn | while read count port; do
            printf "🔌 Puerto ${RED}%-6s${NC} - ${CYAN}%5s${NC} requests\n" "$port" "$count"
        done
    else
        echo "⚠️ El access.log actual no guarda puerto destino."
        echo ""
        echo "Para habilitarlo en Nginx:"
        echo ""
        cat <<'EOF'
sudo nano /etc/nginx/nginx.conf
EOF
        echo ""
        echo "Dentro de http { ... } agrega:"
        echo ""
        cat <<'EOF'
log_format attacklog '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent" '
                     'host="$host" port="$server_port"';
EOF
        echo ""
        echo "En tu server block agrega o cambia:"
        echo ""
        echo 'access_log /var/log/nginx/access.log attacklog;'
        echo ""
        echo "Luego ejecuta:"
        echo "sudo nginx -t && sudo systemctl reload nginx"
    fi
}

analizar_rutas_sensibles() {
    mostrar_seccion "INTENTOS A ARCHIVOS / RUTAS SENSIBLES"

    patrones=(
        "\.env"
        "\.git"
        "\.htaccess"
        "\.htpasswd"
        "wp-config.php"
        "config.php"
        "phpmyadmin"
        "admin"
        "login"
        "signin"
        "xmlrpc.php"
        "wp-login.php"
        "\.sql"
        "\.zip"
        "\.tar"
        "\.gz"
        "backup"
        "dump"
        "database"
        "etc/passwd"
        "proc/self/environ"
        "server-status"
        "actuator"
        "vendor/phpunit"
    )

    for p in "${patrones[@]}"; do
        count=$(grep -Eic "$p" "$LOG_FILE")
        if [ "$count" -gt 0 ]; then
            printf "📁 ${RED}%-24s${NC} - ${CYAN}%4s${NC} intentos\n" "$p" "$count"

            grep -Ei "$p" "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | while read c ip; do
                printf "   └─ %-15s %s veces\n" "$ip" "$c"
            done
            echo ""
        fi
    done
}

analizar_tipos_ataque() {
    mostrar_seccion "TIPOS DE ATAQUE DETECTADOS"

    declare -A ataques
    ataques["Exposición de credenciales"]="\.env|config\.php|wp-config\.php|\.htpasswd|\.htaccess"
    ataques["Exposición Git"]="\.git"
    ataques["Paneles administrativos"]="admin|login|signin|phpmyadmin|wp-login"
    ataques["SQL Injection"]="union|select.*from|insert.*into|drop.*table|information_schema|or[[:space:]]+1=1"
    ataques["Command Injection"]="cmd=|exec=|system=|eval=|shell_exec|passthru|base64_decode"
    ataques["XSS"]="script|alert\(|onerror=|onload=|javascript:"
    ataques["Path Traversal"]="\.\./|\.\.%2f|%2e%2e|etc/passwd"
    ataques["WordPress Scan"]="wp-admin|wp-login|xmlrpc\.php|wp-content|wp-includes"
    ataques["Bots / Crawlers"]="bot|crawler|spider|scan|shodan|censys|nikto|sqlmap|curl|wget|masscan"
    ataques["Backups / Dumps"]="backup|dump|database|\.sql|\.zip|\.tar|\.gz"
    ataques["Spring / Actuator"]="actuator|env|heapdump|jolokia"
    ataques["PHPUnit Exploit"]="vendor/phpunit|eval-stdin"

    for tipo in "${!ataques[@]}"; do
        count=$(grep -Eic "${ataques[$tipo]}" "$LOG_FILE")
        if [ "$count" -gt 0 ]; then
            printf "🚨 ${RED}%-30s${NC} - ${CYAN}%4s${NC} coincidencias\n" "$tipo" "$count"
        fi
    done
}

clasificar_user_agent() {
    local ua="$1"

    if echo "$ua" | grep -Eiq "shodan|censys"; then
        echo "Reconocimiento Internet"
    elif echo "$ua" | grep -Eiq "masscan|nmap|ivre"; then
        echo "Scanner de puertos"
    elif echo "$ua" | grep -Eiq "curl|wget|python|go-http"; then
        echo "Script automatizado"
    elif echo "$ua" | grep -Eiq "bot|crawler|spider"; then
        echo "Bot / crawler"
    elif [ "$ua" = "-" ] || [ -z "$ua" ]; then
        echo "Sin User-Agent"
    else
        echo "Navegador / Desconocido"
    fi
}

analizar_user_agents() {
    mostrar_seccion "USER AGENTS SOSPECHOSOS"

    grep -Ei "bot|crawl|scan|shodan|censys|sqlmap|nikto|curl|wget|python|go-http|masscan|ivre|nmap|zgrab|^.*\"-\"$" "$LOG_FILE" | \
    awk -F'"' '
    {
        split($1,a," ");
        ip=a[1];
        ua=$6;
        key=ip "|" ua;
        count[key]++;
    }
    END {
        for (key in count) print count[key] "|" key;
    }' | sort -t'|' -k1,1rn | head -12 | while IFS='|' read count ip ua; do
        tipo=$(clasificar_user_agent "$ua")

        printf "🤖 ${CYAN}%3s${NC} - ${RED}%-15s${NC} - ${YELLOW}%-24s${NC} - %.100s\n" \
            "$count" "$ip" "$tipo" "$ua"
    done
}

mostrar_requests_vacios() {
    mostrar_seccion "REQUESTS VACÍOS O MALFORMADOS"

    awk -F'"' '
    {
        split($1,a," ");
        ip=a[1];
        request=$2;

        if (request == "-") count[ip]++;
    }
    END {
        for (ip in count) print count[ip], ip;
    }' "$LOG_FILE" | sort -rn | head -20 | while read count ip; do
        printf "⚠️ ${RED}%-15s${NC} - ${CYAN}%4s${NC} requests vacíos\n" "$ip" "$count"
    done
}

calcular_riesgo_ips() {
    mostrar_seccion "RANKING DE RIESGO POR IP"

    awk -F'"' '
    function permitida(ip, o) {
        split(ip, o, ".")
        if (o[1] == 10) return 1
        if (o[1] == 127) return 1
        if (o[1] == 172 && o[2] >= 16 && o[2] <= 31) return 1
        if (o[1] == 192 && o[2] == 168) return 1
        if (o[1] == 169 && o[2] == 254) return 1
        if (o[1] == 100 && o[2] >= 64 && o[2] <= 127) return 1
        if (o[1] == 190 && o[2] == 96 && o[3] >= 96 && o[3] <= 103) return 1
        return 0
    }
    {
        split($1,ipdata," ");
        ip=ipdata[1];

        if (permitida(ip)) {
            allowed[ip]++;
            next
        }

        request=$2;
        split($3,statusdata," ");
        status=statusdata[1];
        ua=tolower($6);

        total[ip]++;

        if (status ~ /^400$/) bad400[ip]++;
        if (status ~ /^401$/) bad401[ip]++;
        if (status ~ /^403$/) bad403[ip]++;
        if (status ~ /^404$/) bad404[ip]++;
        if (status ~ /^5[0-9][0-9]$/) error500[ip]++;

        if (request == "-") malformed[ip]++;

        if (request ~ /\.env|\.git|wp-config|config\.php|phpmyadmin|etc\/passwd|xmlrpc\.php|admin|wp-login|server-status|actuator|vendor\/phpunit/) sensitive[ip]++;
        if (request ~ /^POST \/login/ && status ~ /^(401|403)$/) authfail[ip]++;

        if (request ~ /union|select.*from|drop.*table|cmd=|exec=|system=|eval=|onerror=|onload=|\.\.\//) exploit[ip]++;

        if (ua ~ /masscan|nmap|sqlmap|nikto|curl|wget|python|go-http|shodan|censys|ivre|zgrab/) botua[ip]++;
    }
    END {
        for (ip in total) {
            s = sensitive[ip] + 0;
            a = authfail[ip] + 0;
            e = exploit[ip] + 0;
            m = malformed[ip] + 0;
            b = botua[ip] + 0;
            f = bad403[ip] + bad404[ip] + bad400[ip] + bad401[ip];

            score = (s * 25) + (a * 15) + (e * 30) + (m * 10) + (b * 5) + (f * 3);

            if (score > 100) score=100;

            if (score >= 10) {
                printf "%s %s %s %s %s %s %s %s\n", score, total[ip], s, a, e, m, b, ip;
            }
        }
        allowed_total = 0;
        for (ip in allowed) allowed_total += allowed[ip];
        if (allowed_total > 0) {
            printf "__ALLOWED__ %s\n", allowed_total;
        }
    }' "$LOG_FILE" | sort -rn | head -20 | while read score total sensitive authfail exploit malformed botua ip; do
        if [ "$score" = "__ALLOWED__" ]; then
            printf "${GRAY}[INFO]${NC} omitidas %s entradas de redes permitidas/locales en el ranking.\n" "$total"
            continue
        fi

        if [ "$score" -ge 80 ]; then
            riesgo="ALTO"
            color=$RED
        elif [ "$score" -ge 40 ]; then
            riesgo="MEDIO"
            color=$YELLOW
        else
            riesgo="BAJO"
            color=$GREEN
        fi

        printf "🧨 ${RED}%-15s${NC} riesgo=${color}%-5s${NC} score=${YELLOW}%3s${NC} total=%s sensibles=%s login401=%s exploits=%s malformados=%s botUA=%s\n" \
            "$ip" "$riesgo" "$score" "$total" "$sensitive" "$authfail" "$exploit" "$malformed" "$botua"
    done
}

mostrar_ejemplos_sospechosos() {
    mostrar_seccion "EJEMPLOS DE REQUESTS SOSPECHOSOS"

    grep -Ei "\.env|\.git|config\.php|wp-config|phpmyadmin|admin|login|xmlrpc|union|select|cmd=|exec=|system=|eval=|\.\./|etc/passwd|actuator|server-status|vendor/phpunit" "$LOG_FILE" | \
    awk -F'"' '
    {
        split($1,a," ");
        ip=a[1];

        request=$2;

        split($3,b," ");
        status=b[1];

        ua=$6;

        printf "🚨 %-15s status=%-4s request=%s\n   UA: %.120s\n\n", ip, status, request, ua;
    }' | head -60
}

detectar_scanners_conocidos() {
    mostrar_seccion "SCANNERS / BOTS CONOCIDOS"

    declare -A conocidos
    conocidos["Shodan"]="shodan"
    conocidos["Censys"]="censys"
    conocidos["Masscan / IVRE"]="masscan|ivre"
    conocidos["Nmap"]="nmap"
    conocidos["SQLMap"]="sqlmap"
    conocidos["Nikto"]="nikto"
    conocidos["Curl scripts"]="curl"
    conocidos["Wget scripts"]="wget"
    conocidos["Python scripts"]="python"
    conocidos["Go HTTP client"]="go-http"
    conocidos["DuckDuckGo Bot"]="duckassist|duckduckgo"

    for nombre in "${!conocidos[@]}"; do
        count=$(grep -Eic "${conocidos[$nombre]}" "$LOG_FILE")
        if [ "$count" -gt 0 ]; then
            printf "🔎 ${YELLOW}%-22s${NC} - ${CYAN}%4s${NC} apariciones\n" "$nombre" "$count"

            grep -Ei "${conocidos[$nombre]}" "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | while read c ip; do
                printf "   └─ %-15s %s veces\n" "$ip" "$c"
            done
            echo ""
        fi
    done
}

analizar_metodos_http() {
    mostrar_seccion "MÉTODOS HTTP USADOS"

    awk -F'"' '
    {
        request=$2;
        split(request,a," ");
        method=a[1];

        if (method == "" || method == "-") method="VACIO";
        count[method]++;
    }
    END {
        for (m in count) print count[m], m;
    }' "$LOG_FILE" | sort -rn | while read count method; do
        printf "📌 ${CYAN}%-8s${NC} - ${GREEN}%5s${NC} requests\n" "$method" "$count"
    done
}

analizar_hosts() {
    mostrar_seccion "HOSTS / DOMINIOS SOLICITADOS"

    if grep -q 'host="' "$LOG_FILE"; then
        grep -o 'host="[^"]*"' "$LOG_FILE" | cut -d'"' -f2 | sort | uniq -c | sort -rn | head -20 | while read count host; do
            printf "🌍 ${CYAN}%-35s${NC} - ${GREEN}%5s${NC} requests\n" "$host" "$count"
        done
    else
        echo "⚠️ Tu log actual no guarda host=\"\"."
        echo "Activa el log_format attacklog sugerido para ver dominio y puerto."
    fi
}

analizar_ufw_bloqueos() {
    mostrar_seccion "BLOQUEOS UFW / FIREWALL"

    local syslog_file=""

    if [ -f "/var/log/ufw.log" ]; then
        syslog_file="/var/log/ufw.log"
    elif [ -f "/var/log/syslog" ]; then
        syslog_file="/var/log/syslog"
    else
        echo "⚠️ No encontré /var/log/ufw.log ni /var/log/syslog."
        return
    fi

    if grep -q "UFW BLOCK" "$syslog_file"; then
        echo "📁 Fuente: $syslog_file"
        echo ""

        grep "UFW BLOCK" "$syslog_file" | tail -200 | \
        grep -oE 'SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|DPT=[0-9]+' | \
        awk '
        /^SRC=/ {src=$0; gsub("SRC=","",src)}
        /^DPT=/ {dpt=$0; gsub("DPT=","",dpt); if(src!="") print src, dpt}
        ' | sort | uniq -c | sort -rn | head -20 | while read count ip port; do
            printf "🔥 ${RED}%-15s${NC} puerto=${YELLOW}%-6s${NC} bloqueos=${CYAN}%s${NC}\n" "$ip" "$port" "$count"
        done
    else
        echo "ℹ️ No hay bloqueos UFW recientes registrados."
    fi
}

comandos_bloqueo_sugeridos() {
    mostrar_seccion "ACCIONES MANUALES OPCIONALES"

    estado_info "No bloqueo automáticamente."
    estado_info "Solo aparecen IPs con evidencia accionable y que no figuran ya bloqueadas o permitidas."
    estado_info "Si el evento es histórico, Fail2Ban puede no banearlo retroactivamente."
    echo ""

    fail2ban_banned_ips
    firewall_blocked_ips

    awk -F'"' '
    {
        split($1,ipdata," ");
        ip=ipdata[1];

        request=$2;
        split($3,statusdata," ");
        status=statusdata[1];
        ua=tolower($6);

        total[ip]++;

        if (request ~ /\.env|\.git|wp-config|config\.php|phpmyadmin|etc\/passwd|xmlrpc\.php|vendor\/phpunit|server-status|actuator/) sensitive[ip]++;
        if (request ~ /backup|dump|database|\/db\/|\.sql|\.zip|\.tar|\.gz/) backup[ip]++;
        if (request ~ /union|select.*from|drop.*table|cmd=|exec=|system=|eval=|onerror=|onload=|\.\.\//) exploit[ip]++;
        if (request ~ /^POST \/login/ && status ~ /^(401|403)$/) authfail[ip]++;
        if (request == "-") malformed[ip]++;
        if (ua ~ /masscan|nmap|sqlmap|nikto|curl|wget|python|go-http|shodan|censys|ivre|zgrab/) botua[ip]++;

        score = 0;
    }
    END {
        for (ip in total) {
            actionable = (sensitive[ip] + backup[ip] + exploit[ip] + malformed[ip] + authfail[ip]);
            score = (sensitive[ip] * 25) + (backup[ip] * 20) + (exploit[ip] * 30) + (authfail[ip] * 15) + (malformed[ip] * 10) + (botua[ip] * 5);
            if (score >= 40 && actionable > 0) {
                printf "%s %s %s %s %s %s %s %s %s\n", score, ip, sensitive[ip]+0, backup[ip]+0, exploit[ip]+0, authfail[ip]+0, malformed[ip]+0, botua[ip]+0, total[ip];
            }
        }
    }' "$LOG_FILE" | sort -rn | head -20 | awk -v banned_file="$FAIL2BAN_BANNED_CACHE" -v firewall_file="$FIREWALL_BLOCKED_CACHE" '
        BEGIN {
            while ((getline banned_ip < banned_file) > 0) banned[banned_ip] = 1
            while ((getline blocked_ip < firewall_file) > 0) blocked[blocked_ip] = 1
        }
        function permitida(ip, o) {
            split(ip, o, ".")
            if (o[1] == 10) return 1
            if (o[1] == 127) return 1
            if (o[1] == 172 && o[2] >= 16 && o[2] <= 31) return 1
            if (o[1] == 192 && o[2] == 168) return 1
            if (o[1] == 169 && o[2] == 254) return 1
            if (o[1] == 100 && o[2] >= 64 && o[2] <= 127) return 1
            if (o[1] == 190 && o[2] == 96 && o[3] >= 96 && o[3] <= 103) return 1
            return 0
        }
        {
            if (banned[$2]) {
                skipped_banned++
                next
            }
            if (blocked[$2]) {
                skipped_blocked++
                next
            }
            if (permitida($2)) {
                skipped_allowed++
                next
            }
            shown++
            print
        }
        END {
            printf "__SUMMARY__ %d %d %d %d\n", shown+0, skipped_banned+0, skipped_blocked+0, skipped_allowed+0
        }
    ' | while read score ip sensitive backup exploit authfail malformed botua total; do
        if [ "$score" = "__SUMMARY__" ]; then
            echo ""
            printf "Resumen: acciones_pendientes=%s, ya_en_fail2ban=%s, ya_en_firewall=%s, redes_permitidas=%s\n" "$ip" "$sensitive" "$backup" "$exploit"
            continue
        fi

        if ip_en_red_permitida "$ip"; then
            continue
        elif ip_ya_baneada "$ip"; then
            continue
        elif ip_bloqueada_firewall "$ip"; then
            continue
        else
            estado_accion "Candidata pendiente: $ip"
            printf "sudo fail2ban-client set nginx-scanners banip %s\n" "$ip"
            printf "   Evidencia: rutas_sensibles=%s backups=%s exploits=%s login401=%s malformados=%s botUA=%s total_eventos=%s\n" \
                "$sensitive" "$backup" "$exploit" "$authfail" "$malformed" "$botua" "$total"
        fi
    done
}

recomendaciones() {
    mostrar_seccion "RECOMENDACIONES PROFESIONALES"

    echo "✅ Bloquea IPs que busquen .git, .env, config.php, phpmyadmin, wp-login o xmlrpc.php."
    echo "✅ Requests vacíos normalmente no son usuarios reales; suelen ser scanners."
    echo "✅ Shodan/Censys son reconocimiento de Internet; puedes bloquear si no deseas exposición."
    echo "✅ Masscan/IVRE indica escaneo automatizado de puertos o servicios."
    echo "✅ curl, wget, python y go-http-client suelen ser scripts automatizados."
    echo "✅ Para ver ataques por puerto real, activa server_port en Nginx y revisa UFW."
    echo "✅ No expongas SSH al mundo. Mantén UFW limitado por IP o VPN."
    echo "✅ Usa Fail2Ban para bloquear automáticamente patrones repetidos."
    echo ""
    echo "Comandos útiles:"
    echo "sudo ufw status numbered"
    echo "sudo ufw deny from IP_A_BLOQUEAR"
    echo "sudo grep 'UFW BLOCK' /var/log/ufw.log"
    echo "sudo tail -f /var/log/nginx/access.log"
}

main() {
    requisito_root
    validar_log

    header
    analizar_codigos_estado
    analizar_por_hora
    analizar_metodos_http
    analizar_por_puerto
    analizar_hosts
    analizar_top_ips
    analizar_rutas_sensibles
    analizar_tipos_ataque
    detectar_scanners_conocidos
    analizar_user_agents
    mostrar_requests_vacios
    calcular_riesgo_ips
    mostrar_ejemplos_sospechosos
    analizar_ufw_bloqueos
    comandos_bloqueo_sugeridos
    recomendaciones

    echo ""
    printf "${GREEN}✅ Análisis completado.${NC}\n"
}

main
