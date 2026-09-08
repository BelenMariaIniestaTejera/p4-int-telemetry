#!/bin/bash
# arrancar_todo.sh
#
# Arranca, en orden, todo lo necesario para el escenario INT + colector +
# InfluxDB + Grafana:
#   1. InfluxDB (crea el contenedor si no existe, lo arranca si esta parado)
#   2. Grafana   (igual)
#   3. Mininet/P4 (start_int1.0.sh) 

cd "$(dirname "$0")" || exit 1

echo "=== 1. InfluxDB ==="
bash start_influxdb.sh

echo ""
echo "=== 2. Grafana ==="
if [ "$(docker ps -q -f name=^grafana$)" ]; then
    echo "Grafana ya esta corriendo."
elif [ "$(docker ps -aq -f name=^grafana$)" ]; then
    echo "Grafana existe pero esta parado. Arrancando..."
    docker start grafana
else
    echo "Grafana no existe. Creando contenedor nuevo..."
    docker run -d --name grafana -p 3005:3000 --restart unless-stopped grafana/grafana:7.3.3
fi

echo ""
echo "Estado de los contenedores:"
docker ps -f name=influxdb -f name=grafana

echo ""
echo "Grafana estara disponible en: http://localhost:3005"
echo ""
echo "=== 3. Mininet / P4 (start_int1.0.sh) ==="
echo "Arrancando en unos segundos... (Ctrl+C para cancelar)"
sleep 3
sudo bash start_int1.0.sh
