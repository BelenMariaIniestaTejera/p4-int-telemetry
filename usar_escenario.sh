#!/bin/bash
# usar_escenario.sh
#
# Cambia la topologia activa (topo.txt + commands/) por la de un escenario
# guardado, sin tocar ni borrar los demas escenarios.
#
# Los escenarios viven en: int.p4app/escenarios/<nombre>/topo.txt
#                           int.p4app/escenarios/<nombre>/commands/
#
# USO:
#   bash usar_escenario.sh <nombre_escenario>
#   bash usar_escenario.sh --guardar <nombre_escenario>   (guarda el activo actual como nuevo escenario)
#   bash usar_escenario.sh --listar                        (lista los escenarios disponibles)
#
# Ejemplo para no olvidarlo:
#   bash usar_escenario.sh --guardar original     (la primera vez, para no perder lo que ya tengo)
#   bash usar_escenario.sh leafspine
#   bash usar_escenario.sh original

set -e
APP_DIR="int.p4app"
ESCENARIOS_DIR="$APP_DIR/escenarios"

if [ ! -d "$APP_DIR" ]; then
    echo "ERROR: no se encuentra la carpeta '$APP_DIR' desde aqui."
    echo "Ejecuta este script desde platforms/bmv2-mininet/"
    exit 1
fi

mkdir -p "$ESCENARIOS_DIR"

if [ "$1" == "--listar" ]; then
    echo "Escenarios guardados:"
    ls -1 "$ESCENARIOS_DIR" 2>/dev/null || echo "  (ninguno todavia)"
    exit 0
fi

if [ "$1" == "--guardar" ]; then
    NOMBRE="$2"
    if [ -z "$NOMBRE" ]; then
        echo "Uso: bash usar_escenario.sh --guardar <nombre>"
        exit 1
    fi
    DEST="$ESCENARIOS_DIR/$NOMBRE"
    if [ -d "$DEST" ]; then
        echo "Ya existe un escenario guardado como '$NOMBRE' en $DEST"
        echo "Si quieres sobrescribirlo, borralo primero: rm -rf $DEST"
        exit 1
    fi
    mkdir -p "$DEST"
    cp "$APP_DIR/topo.txt" "$DEST/topo.txt"
    cp -r "$APP_DIR/commands" "$DEST/commands"
    echo "Guardado el escenario ACTIVO actual como '$NOMBRE' en $DEST"
    exit 0
fi

NOMBRE="$1"
if [ -z "$NOMBRE" ]; then
    echo "Uso: bash usar_escenario.sh <nombre_escenario>"
    echo "     bash usar_escenario.sh --guardar <nombre_escenario>"
    echo "     bash usar_escenario.sh --listar"
    echo ""
    echo "Escenarios guardados:"
    ls -1 "$ESCENARIOS_DIR" 2>/dev/null || echo "  (ninguno todavia)"
    exit 1
fi

SRC="$ESCENARIOS_DIR/$NOMBRE"
if [ ! -d "$SRC" ]; then
    echo "ERROR: no existe el escenario '$NOMBRE' en $SRC"
    echo ""
    echo "Escenarios disponibles:"
    ls -1 "$ESCENARIOS_DIR" 2>/dev/null || echo "  (ninguno todavia)"
    exit 1
fi

cp "$SRC/topo.txt" "$APP_DIR/topo.txt"
rm -rf "$APP_DIR/commands"
cp -r "$SRC/commands" "$APP_DIR/commands"

echo "Escenario activo ahora: '$NOMBRE'"
echo "Ya puedes arrancar con: sudo bash start_int1.0.sh"
