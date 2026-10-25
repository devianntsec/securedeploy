#!/usr/bin/env bash
# Prueba las reglas de Falco de SecureDeploy disparando cada una de forma SEGURA.
# Ejecutar EN EL HOST (EC2) con sudo, con el contenedor `securedeploy` corriendo:
#     sudo ./scripts/test_falco.sh            # todas
#     sudo ./scripts/test_falco.sh SD-C01     # solo una
# Salida: una línea PASS/FAIL por regla. Código de salida != 0 si alguna falla.
# Nada destructivo: usa ficheros *-falco-test que borra al terminar.
set -uo pipefail

EVENTS="${FALCO_EVENTS:-/var/log/falco/events.json}"
CTR="${SD_CONTAINER:-securedeploy}"
ONLY="${1:-}"
fail=0
declare -a SKIPPED=()

[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo (necesito leer $EVENTS)"; exit 2; }
[ -r "$EVENTS" ] || { echo "No existe $EVENTS: ¿Falco con file_output? (ver rol ansible falco)"; exit 2; }
systemctl is-active --quiet falco-modern-bpf || { echo "falco-modern-bpf no está activo"; exit 2; }
docker inspect "$CTR" >/dev/null 2>&1 || echo "AVISO: contenedor $CTR no encontrado; se omiten las pruebas SD-C*"

count() { grep -c "\"rule\":\"$1 " "$EVENTS" 2>/dev/null || true; }

# check <ID> <descripción> <comando...>
check() {
  local id="$1" desc="$2"; shift 2
  [ -n "$ONLY" ] && [ "$ONLY" != "$id" ] && return 0
  local before after
  before=$(count "$id")
  ( "$@" ) >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6; do          # Falco escribe de forma asíncrona: hasta ~6 s
    sleep 1; after=$(count "$id"); [ "$after" -gt "$before" ] && break
  done
  if [ "$after" -gt "$before" ]; then printf 'PASS  %-7s %s\n' "$id" "$desc"
  else printf 'FAIL  %-7s %s\n' "$id" "$desc"; fail=1; fi
}

ctr_up() { [ "$(docker inspect -f '{{.State.Running}}' "$CTR" 2>/dev/null)" = "true" ]; }
ctr() { docker exec "$CTR" "$@"; }

# --------------------------- CONTENEDOR ------------------------------------
if ctr_up; then
  check SD-C01 "shell en contenedor"            ctr sh -c 'id'
  check SD-C02 "proceso fuera de allowlist"     ctr ls /
  check SD-C03 "gestor de paquetes en contenedor" ctr apt-get --version
  check SD-C05 "escritura bloqueada (rootfs RO)" ctr python -c "open('/srv/falco-test','w')"
  check SD-C06 "salida a puerto no permitido"   ctr python -c "import socket;s=socket.socket();s.settimeout(2);s.connect_ex(('1.1.1.1',8080))"
  check SD-C07 "acceso a IMDS desde contenedor" ctr python -c "import socket;s=socket.socket();s.settimeout(2);s.connect_ex(('169.254.169.254',80))"
  check SD-C08 "lectura de /proc/self/environ"  ctr python -c "open('/proc/self/environ').read()"
  # C04 y C09 requieren un contenedor mal configurado (volumen escribible / privilegios): ver README
  SKIPPED+=("SD-C04 (requiere volumen escribible)" "SD-C09 (requiere --privileged/CAP_SYS_PTRACE)")
fi

# ------------------------------ HOST ---------------------------------------
check SD-H01 "contenedor privilegiado" \
  docker run --rm --privileged --name falco-test-priv --pull=never "$(docker inspect -f '{{.Config.Image}}' "$CTR" 2>/dev/null || echo none)" true
check SD-H02 "acceso a docker.sock por proceso ajeno" \
  python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/var/run/docker.sock')"
check SD-H03 "escritura en /etc/sudoers.d" \
  sh -c 'umask 0227; echo "# falco-test" > /etc/sudoers.d/zz-falco-test; rm -f /etc/sudoers.d/zz-falco-test'
check SD-H04 "escritura en authorized_keys" \
  sh -c 'd=$(mktemp -d); mkdir "$d/.ssh"; echo "# falco-test" > "$d/.ssh/authorized_keys"; rm -rf "$d"'
check SD-H05 "persistencia en /etc/cron.d" \
  sh -c 'echo "# falco-test" > /etc/cron.d/zz-falco-test; rm -f /etc/cron.d/zz-falco-test'
check SD-H06 "escritura en /usr/local/bin" \
  sh -c 'echo "#!/bin/sh" > /usr/local/bin/zz-falco-test; rm -f /usr/local/bin/zz-falco-test'
check SD-H07 "bit SUID" \
  sh -c 't=$(mktemp); chmod u+s "$t"; rm -f "$t"'
check SD-H08 "alta de usuario" \
  sh -c 'useradd --no-create-home --shell /usr/sbin/nologin zz-falco-test; userdel zz-falco-test'
if modinfo dummy >/dev/null 2>&1; then
  check SD-H09 "carga de módulo de kernel" sh -c 'modprobe dummy; modprobe -r dummy'
else SKIPPED+=("SD-H09 (módulo 'dummy' no disponible: prueba con un módulo propio)"); fi
check SD-H10 "intento de parar un servicio de seguridad" \
  systemctl stop falco-test-inexistente.service
check SD-H11 "truncado de log" \
  sh -c ': > /var/log/zz-falco-test.log; rm -f /var/log/zz-falco-test.log'
check SD-H12 "lectura de clave privada SSH" \
  sh -c 'mkdir -p /root/.ssh; f=/root/.ssh/id_zzfalcotest; echo x > $f; head -c1 $f >/dev/null; rm -f $f'
check SD-H13 "consulta IMDS desde proceso ajeno" \
  python3 -c "import socket;s=socket.socket();s.settimeout(2);s.connect_ex(('169.254.169.254',80))"
check SD-X01 "ejecución desde /var/tmp" \
  sh -c 'cp /bin/true /var/tmp/zz-falco-test; /var/tmp/zz-falco-test; rm -f /var/tmp/zz-falco-test'
check SD-X02 "stdio redirigido a socket (reverse shell)" \
  python3 -c "
import os, socket, threading
srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1)
threading.Thread(target=lambda: srv.accept(), daemon=True).start()
c = socket.socket(); c.connect(srv.getsockname())
os.dup2(c.fileno(), 1)
os._exit(0)"
check SD-X03 "proceso con nombre de minero" \
  sh -c 'cp /bin/true /usr/local/bin/xmrig 2>/dev/null || cp /bin/true /var/tmp/xmrig; /usr/local/bin/xmrig 2>/dev/null || /var/tmp/xmrig; rm -f /usr/local/bin/xmrig /var/tmp/xmrig'
check SD-X04 "conexión a puerto 4444" \
  python3 -c "import socket;s=socket.socket();s.settimeout(2);s.connect_ex(('1.1.1.1',4444))"

echo
if [ "${#SKIPPED[@]}" -gt 0 ]; then printf 'OMITIDA %s\n' "${SKIPPED[@]}"; fi
[ "$fail" -eq 0 ] && echo "Todas las pruebas ejecutadas PASARON" || echo "Hay reglas que NO dispararon: revisa 'journalctl -u falco-modern-bpf -n 50'"
exit "$fail"
