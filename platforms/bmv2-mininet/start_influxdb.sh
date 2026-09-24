#!/bin/bash
# start_influxdb.sh
#
# Comprueba si el contenedor "influxdb" existe y esta corriendo.
# - Si no existe, lo crea.
# - Si existe pero esta parado, lo arranca.
# - Si ya esta corriendo, no hace nada.
#
# Uso: bash start_influxdb.sh
# Recomendado ejecutarlo ANTES de start_int1.0.sh

CONTAINER_NAME="influxdb"

if [ "$(docker ps -q -f name=^${CONTAINER_NAME}$)" ]; then
    echo "InfluxDB ya esta corriendo."
elif [ "$(docker ps -aq -f name=^${CONTAINER_NAME}$)" ]; then
    echo "InfluxDB existe pero esta parado. Arrancando..."
    docker start ${CONTAINER_NAME}
else
    echo "InfluxDB no existe. Creando contenedor nuevo..."
    docker run -d --name ${CONTAINER_NAME} --network host --restart unless-stopped influxdb:1.8
fi

echo ""
echo "Estado actual:"
docker ps -f name=${CONTAINER_NAME}
