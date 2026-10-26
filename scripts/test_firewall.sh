#!/usr/bin/env bash
# Comprueba que el firewall del host filtra el puerto que Docker publica (cadena DOCKER-USER).
# Ejecutar EN EL HOST con sudo y el contenedor `securedeploy` corriendo:
#     sudo ./scripts/test_firewall.sh
# Crea un cliente "externo" en un namespace de red temporal (192.168.77.2) y comprueba:
#   1) un origen NO autorizado queda bloqueado        -> PASS si no recibe HTTP 200
#   2) ese mismo origen, autorizado a mano un momento -> PASS si recibe HTTP 200
# Código de salida != 0 si alguna falla. Todo lo temporal se limpia al terminar.
set -uo pipefail

PORT="${APP_PORT:-8000}"
NS=sdfw-ext
HOST_IP=192.168.77.1
CLIENT_IP=192.168.77.2
RULE=(-s "$CLIENT_IP" -p tcp -m conntrack --ctorigdstport "$PORT" --ctdir ORIGINAL -j RETURN)

[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo"; exit 2; }
for c in ip iptables curl docker; do command -v "$c" >/dev/null || { echo "Falta $c"; exit 2; }; done
docker inspect securedeploy >/dev/null 2>&1 || { echo "El contenedor securedeploy no está corriendo"; exit 2; }
iptables -S DOCKER-USER >/dev/null 2>&1 || { echo "No existe la cadena DOCKER-USER"; exit 2; }

cleanup() {
  iptables -D DOCKER-USER "${RULE[@]}" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del sdfw-h 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add "$NS"
ip link add sdfw-x type veth peer name sdfw-h
ip link set sdfw-x netns "$NS"
ip addr add "$HOST_IP/24" dev sdfw-h && ip link set sdfw-h up
ip netns exec "$NS" ip addr add "$CLIENT_IP/24" dev sdfw-x
ip netns exec "$NS" ip link set sdfw-x up
ip netns exec "$NS" ip route add default via "$HOST_IP"

code() { ip netns exec "$NS" curl -s -m 4 -o /dev/null -w '%{http_code}' "http://$HOST_IP:$PORT/health" 2>/dev/null || true; }
fail=0

c=$(code)
if [ "$c" = "200" ]; then echo "FAIL  origen no autorizado alcanzó el puerto $PORT (HTTP $c)"; fail=1
else echo "PASS  origen no autorizado bloqueado (HTTP ${c:-000})"; fi

iptables -I DOCKER-USER 1 "${RULE[@]}"
c=$(code)
if [ "$c" = "200" ]; then echo "PASS  origen autorizado alcanza el puerto $PORT (HTTP $c)"
else echo "FAIL  origen autorizado no pasó (HTTP ${c:-000}): ¿el contenedor responde en /health?"; fail=1; fi

[ "$fail" -eq 0 ] && echo "Firewall de Docker OK" || echo "Hay fallos en el firewall de Docker"
exit "$fail"
