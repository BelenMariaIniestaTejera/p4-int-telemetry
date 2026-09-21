#!/bin/bash
# watchdog_completo.sh
# --------------------------------------------------------------------------
# Vigila los 4 componentes de los que depende ver los datos de INT:
#   1. Contenedor InfluxDB (Docker, en el servidor)
#   2. Contenedor Grafana  (Docker, en el servidor)
#   3. socat               (dentro del contenedor 'int', puente hacia InfluxDB)
#   4. Colector INT        (dentro del contenedor 'int', python)
#
# Si detecta que alguno esta caido (o "zombi"), lo relanza solo.
#
# USO: en una terminal de tu servidor (vnxlab), NO dentro de docker exec:
#   bash watchdog_completo.sh &
#
# Se queda corriendo indefinidamente en segundo plano. Para pararlo:
#   pkill -f watchdog_completo.sh
# --------------------------------------------------------------------------

CHECK_INTERVAL=10   # segundos entre comprobaciones

echo "Vigilante completo arrancado (revisa cada ${CHECK_INTERVAL}s)"
echo "InfluxDB + Grafana + socat + colector INT"
echo ""

while true; do

    # --- 1. InfluxDB (contenedor Docker) ------------------------------
    if [ -z "$(docker ps -q -f name=^influxdb$)" ]; then
        echo "[$(date +%H:%M:%S)] InfluxDB caido -> arrancando..."
        docker start influxdb > /dev/null 2>&1
    fi

    # --- 2. Grafana (contenedor Docker) -------------------------------
    if [ -z "$(docker ps -q -f name=^grafana$)" ]; then
        echo "[$(date +%H:%M:%S)] Grafana caido -> arrancando..."
        docker start grafana > /dev/null 2>&1
    fi

    # Si el contenedor 'int' no existe, no tiene sentido comprobar lo de
    # dentro (socat/colector) - simplemente esperamos a la siguiente vuelta
    if [ -n "$(docker ps -q -f name=^int$)" ]; then

        # --- 3. socat (dentro de 'int') -------------------------------
        if ! docker exec int pgrep -f "TCP-LISTEN:8086" > /dev/null 2>&1; then
            echo "[$(date +%H:%M:%S)] socat caido/zombi (dentro de int) -> relanzando..."
            docker exec -d int socat TCP-LISTEN:8086,fork,reuseaddr TCP:172.17.0.1:8086
            sleep 1
        fi

        # --- 4. Colector INT (dentro de 'int') -------------------------
        if ! docker exec int pgrep -f "int_collector_influx.py" > /dev/null 2>&1; then
            echo "[$(date +%H:%M:%S)] Colector caido (dentro de int) -> relanzando..."
            docker exec int pkill -f int_collector_influx > /dev/null 2>&1
            docker exec -d int sh -c "ip netns exec ns_int python3 /tmp/utils/int_collector_influx.py -i 6000 -H 192.168.0.1:8086 -d 1 > /tmp/p4app_logs/int_collector_stdout.log 2>&1"
        fi
    fi

    sleep $CHECK_INTERVAL
done
