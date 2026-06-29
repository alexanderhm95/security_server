#!/bin/bash
set -euo pipefail

ENV_FILE="${MODSEC_ENV:-}"
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

MODSEC_RULE_ENGINE="${MODSEC_RULE_ENGINE:-On}"
CRS_INSTALL_DIR="${CRS_INSTALL_DIR:-/etc/nginx/owasp-modsecurity-crs}"
CRS_REPO="${CRS_REPO:-https://github.com/coreruleset/coreruleset.git}"
CRS_VERSION="${CRS_VERSION:-v4.12.0}"
BUILD_MODSECURITY_FROM_SOURCE="${BUILD_MODSECURITY_FROM_SOURCE:-auto}"
MODSECURITY_REPO="${MODSECURITY_REPO:-https://github.com/owasp-modsecurity/ModSecurity.git}"
MODSECURITY_VERSION="${MODSECURITY_VERSION:-v3/master}"
MODSECURITY_NGINX_REPO="${MODSECURITY_NGINX_REPO:-https://github.com/owasp-modsecurity/ModSecurity-nginx.git}"
NGINX_SOURCE_VERSION="${NGINX_SOURCE_VERSION:-auto}"
MODSEC_DIR="/etc/nginx/modsec"
NGINX_CONF="/etc/nginx/nginx.conf"
MODULE_LINE="load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;"
MODULE_PATH="/usr/lib/nginx/modules/ngx_http_modsecurity_module.so"

trap 'echo "ERROR: instalacion ModSecurity interrumpida en ${BASH_SOURCE[0]}:${LINENO}. Revisa la salida anterior." >&2' ERR

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta como root: sudo $0"
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"

backup_file() {
  local file="$1"
  if [ -f "$file" ]; then
    cp "$file" "${file}.bak.${timestamp}"
  fi
  return 0
}

write_file() {
  local file="$1"
  local tmp
  mkdir -p "$(dirname "$file")"
  tmp="$(mktemp)"
  cat > "$tmp"
  if [ -f "$file" ] && cmp -s "$tmp" "$file"; then
    rm -f "$tmp"
    echo "Sin cambios: $file"
    return
  fi
  backup_file "$file"
  install -m 0644 "$tmp" "$file"
  rm -f "$tmp"
  echo "Actualizado: $file"
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

nginx_version() {
  if [ "$NGINX_SOURCE_VERSION" != "auto" ]; then
    printf '%s\n' "$NGINX_SOURCE_VERSION"
    return
  fi
  nginx -v 2>&1 | sed -n 's#nginx version: nginx/\([0-9.]*\).*#\1#p'
}

module_loads() {
  [ -f "$MODULE_PATH" ] || return 1
  ldd "$MODULE_PATH" >/dev/null 2>&1 || return 1
  if nginx -t >/tmp/security-stack-nginx-test.log 2>&1; then
    return 0
  fi
  if grep -q "modsecurity_module.so" /tmp/security-stack-nginx-test.log; then
    return 1
  fi
  return 0
}

try_package_module() {
  echo "Intentando instalar ModSecurity para Nginx desde paquetes..."
  apt-get update
  if apt_install libnginx-mod-http-modsecurity modsecurity-crs; then
    return 0
  fi
  echo "No se pudo instalar ModSecurity por paquetes; se usara compilacion si esta habilitada."
  return 1
}

build_libmodsecurity() {
  if ldconfig -p | grep -q 'libmodsecurity.so.3'; then
    echo "libmodsecurity.so.3 ya esta registrada en ldconfig."
    return
  fi

  echo "Compilando libmodsecurity desde fuente..."
  apt_install \
    build-essential git automake autoconf libtool pkg-config curl wget ca-certificates \
    libcurl4-openssl-dev libyajl-dev libpcre2-dev libxml2-dev zlib1g-dev libssl-dev \
    libmaxminddb-dev liblmdb-dev liblua5.3-dev doxygen

  rm -rf /tmp/ModSecurity
  git clone --depth 1 --branch "$MODSECURITY_VERSION" "$MODSECURITY_REPO" /tmp/ModSecurity
  (
    cd /tmp/ModSecurity
    git submodule update --init --recursive
    ./build.sh
    ./configure --prefix=/usr/local/modsecurity
    make -j"$(nproc)"
    make install
  )

  echo "/usr/local/modsecurity/lib" > /etc/ld.so.conf.d/modsecurity.conf
  ldconfig
  ldconfig -p | grep -q 'libmodsecurity.so.3'
}

build_nginx_connector() {
  if [ -f "$MODULE_PATH" ] && ldd "$MODULE_PATH" >/dev/null 2>&1; then
    echo "Modulo Nginx ModSecurity ya existe: $MODULE_PATH"
    return
  fi

  local version source_dir tarball
  version="$(nginx_version)"
  if [ -z "$version" ]; then
    echo "No pude detectar version de Nginx."
    exit 1
  fi

  echo "Compilando conector ModSecurity-nginx para Nginx ${version}..."
  apt_install build-essential git wget ca-certificates libpcre3-dev zlib1g-dev libssl-dev

  rm -rf /tmp/ModSecurity-nginx "/tmp/nginx-${version}" "/tmp/nginx-${version}.tar.gz"
  git clone --depth 1 "$MODSECURITY_NGINX_REPO" /tmp/ModSecurity-nginx

  tarball="/tmp/nginx-${version}.tar.gz"
  wget -O "$tarball" "https://nginx.org/download/nginx-${version}.tar.gz"
  tar -xzf "$tarball" -C /tmp
  source_dir="/tmp/nginx-${version}"

  (
    cd "$source_dir"
    ./configure --with-compat --add-dynamic-module=/tmp/ModSecurity-nginx
    make modules
  )

  install -m 0755 "${source_dir}/objs/ngx_http_modsecurity_module.so" "$MODULE_PATH"
  ldd "$MODULE_PATH" >/dev/null
}

ensure_modsecurity_module() {
  if module_loads; then
    echo "Modulo ModSecurity ya carga correctamente."
    return
  fi

  if [ "$BUILD_MODSECURITY_FROM_SOURCE" != "yes" ]; then
    try_package_module && module_loads && return
  fi

  if [ "$BUILD_MODSECURITY_FROM_SOURCE" = "no" ]; then
    echo "ModSecurity no carga y BUILD_MODSECURITY_FROM_SOURCE=no."
    exit 1
  fi

  build_libmodsecurity
  build_nginx_connector

  echo "/usr/local/modsecurity/lib" > /etc/ld.so.conf.d/modsecurity.conf
  ldconfig
}

ensure_crs() {
  if [ -d "$CRS_INSTALL_DIR/rules" ] && [ -f "$CRS_INSTALL_DIR/crs-setup.conf" ]; then
    echo "OWASP CRS ya existe: $CRS_INSTALL_DIR"
    return
  fi

  rm -rf "$CRS_INSTALL_DIR"
  git clone --depth 1 --branch "$CRS_VERSION" "$CRS_REPO" "$CRS_INSTALL_DIR"

  if [ -f "$CRS_INSTALL_DIR/crs-setup.conf.example" ] && [ ! -f "$CRS_INSTALL_DIR/crs-setup.conf" ]; then
    cp "$CRS_INSTALL_DIR/crs-setup.conf.example" "$CRS_INSTALL_DIR/crs-setup.conf"
  fi
}

configure_nginx_module() {
  if [ -f "$MODULE_PATH" ] && ! grep -RqsF "$MODULE_LINE" "$NGINX_CONF" /etc/nginx/modules-enabled 2>/dev/null; then
    backup_file "$NGINX_CONF"
    sed -i "1i${MODULE_LINE}" "$NGINX_CONF"
    echo "Agregado modulo ModSecurity a $NGINX_CONF"
  fi

  if ! grep -q "modsecurity_rules_file ${MODSEC_DIR}/main.conf;" "$NGINX_CONF"; then
    backup_file "$NGINX_CONF"
    awk -v modsec_file="${MODSEC_DIR}/main.conf" '
      BEGIN { inserted=0 }
      /^[[:space:]]*http[[:space:]]*\{/ && inserted==0 {
        print
        print "    modsecurity on;"
        print "    modsecurity_rules_file " modsec_file ";"
        inserted=1
        next
      }
      { print }
    ' "$NGINX_CONF" > "${NGINX_CONF}.tmp"
    install -m 0644 "${NGINX_CONF}.tmp" "$NGINX_CONF"
    rm -f "${NGINX_CONF}.tmp"
    echo "Activado ModSecurity dentro de http {}"
  fi
}

install_modsecurity_files() {
  mkdir -p "$MODSEC_DIR"

  write_file "$MODSEC_DIR/main.conf" <<EOF
# Configuracion base de ModSecurity
Include ${MODSEC_DIR}/modsecurity.conf

# OWASP CRS
Include ${CRS_INSTALL_DIR}/crs-setup.conf
Include ${CRS_INSTALL_DIR}/rules/*.conf

# Reglas personalizadas locales
Include ${MODSEC_DIR}/custom-rules.conf
EOF

  write_file "$MODSEC_DIR/modsecurity.conf" <<EOF
SecRuleEngine ${MODSEC_RULE_ENGINE}
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 512
SecArgumentsLimit 1000

SecRule &ARGS "@ge 1000" "id:200007,phase:2,t:none,log,deny,status:400,msg:'Failed to fully parse request body due to large argument count',severity:2"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:200004,phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000
SecRule TX:/^MSC_/ "!@streq 0" "id:200005,phase:2,t:none,log,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"

SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial

SecTmpDir /tmp/
SecDataDir /tmp/

SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.log
EOF

  write_file "$MODSEC_DIR/custom-rules.conf" <<'EOF'
# Reglas locales SP1. IDs 1000001-1000099 reservados para este stack.

SecRule REQUEST_HEADERS:User-Agent "^$" \
    "id:1000001,phase:1,deny,status:403,msg:'User-Agent vacio detectado'"

SecRule REQUEST_HEADERS:User-Agent "@contains masscan" \
    "id:1000002,phase:1,deny,status:403,msg:'Scanner Masscan detectado'"

SecRule REQUEST_HEADERS:User-Agent "@contains visionheight" \
    "id:1000003,phase:1,deny,status:403,msg:'Scanner visionheight detectado'"

SecRule REQUEST_HEADERS:User-Agent "@contains nmap" \
    "id:1000004,phase:1,deny,status:403,msg:'Scanner Nmap detectado'"

SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \
    "id:1000005,phase:1,deny,status:403,msg:'Scanner SQLMap detectado'"

SecRule REQUEST_METHOD "^$" \
    "id:1000006,phase:1,deny,status:400,msg:'Metodo HTTP vacio detectado'"

SecRule REQUEST_URI "(?:\.git|\.env|config\.php|phpmyadmin|wp-login|xmlrpc\.php)" \
    "id:1000007,phase:2,deny,status:403,msg:'Intento a archivo sensible detectado'"
EOF

  touch /var/log/modsec_audit.log
  chmod 0640 /var/log/modsec_audit.log || true
}

verify_modsecurity_rules() {
  local count
  count="$(nginx -T 2>/dev/null | grep -c '^[[:space:]]*SecRule' || true)"
  if [ "$count" -lt 10 ]; then
    echo "ERROR: ModSecurity esta cargado, pero Nginx reporta solo ${count} reglas SecRule."
    echo "Esto normalmente significa que modsecurity_rules_file no apunta a ${MODSEC_DIR}/main.conf o que OWASP CRS no cargo."
    exit 1
  fi
  echo "ModSecurity reglas cargadas: ${count}"
}

ensure_crs
ensure_modsecurity_module
echo "Instalando archivos de configuracion ModSecurity..."
install_modsecurity_files
echo "Configurando Nginx para usar ${MODSEC_DIR}/main.conf..."
configure_nginx_module

echo "Validando Nginx..."
nginx -t
systemctl reload nginx
verify_modsecurity_rules

echo "ModSecurity + OWASP CRS listo."
