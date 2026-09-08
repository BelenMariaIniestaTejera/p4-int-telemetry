#!/usr/bin/env python3
"""
monitor_link.py (ACTUALIZADO tras la Tarea 3 - paridad de hosts)
------------------------------------------------------------------
Vigila el estado de un enlace fisico (por defecto, el de s1 hacia s5) cada
X segundos. En cuanto detecta que se ha caido, borra en caliente (via
simple_switch_CLI) la regla de prioridad 1 en los switches implicados, para
que la regla de reserva (prioridad 2, ya precargada) tome el control sola.
Cuando el enlace vuelve, restaura la regla principal.

IMPORTANTE: los handles de abajo son validos SOLO mientras no se recarguen
las tablas con un orden distinto de lineas en commandsX.txt. Si vuelves a
tocar commands3.txt o commands5.txt, comprueba los handles reales con
"table_dump tb_forward" antes de fiarte de este script.

USO:
    docker exec -it int bash
    python3 /tmp/utils/monitor_link.py
"""

import subprocess
import sys
import time

CHECK_INTERVAL_SECONDS = 5
IFACE_TO_WATCH = "s1-eth3"

# Handles confirmados con table_dump el 07/08, tras el reinicio limpio
# posterior a la Tarea 3 (paridad de hosts).
SWITCHES = [
    {
        "name": "s3",
        "thrift_port": 22224,
        "on_down_cmd": "table_delete tb_forward 6",
        "on_up_cmd": "table_add tb_forward send_to_port 00:00:00:00:05:05&&&0xFFFFFFFFFFFF 1&&&0x1FF => 3 1",
    },
    {
        "name": "s5",
        "thrift_port": 22226,
        "on_down_cmd": "table_delete tb_forward 0",
        "on_up_cmd": "table_add tb_forward send_to_port 00:00:00:00:01:01&&&0xFFFFFFFFFFFF 1&&&0x1FF => 3 1",
    },
]


def link_is_up(iface):
    try:
        with open("/sys/class/net/%s/operstate" % iface) as f:
            return f.read().strip() == "up"
    except (FileNotFoundError, OSError):
        return False


def run_cli_command(thrift_port, command):
    try:
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=command + "\n",
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return result.stdout
    except Exception as e:
        print("  ! Error al hablar con el switch (puerto %d): %s" % (thrift_port, e))
        return ""


def main():
    print("Vigilando el enlace '%s' cada %d segundos..." % (IFACE_TO_WATCH, CHECK_INTERVAL_SECONDS))
    print("(Ctrl+C para parar)\n")

    link_was_down = False

    while True:
        up = link_is_up(IFACE_TO_WATCH)

        if not up and not link_was_down:
            print("[%s] Enlace '%s' CAIDO. Activando ruta alternativa..." %
                  (time.strftime("%H:%M:%S"), IFACE_TO_WATCH))
            for sw in SWITCHES:
                print("  -> %s: %s" % (sw["name"], sw["on_down_cmd"]))
                run_cli_command(sw["thrift_port"], sw["on_down_cmd"])
            link_was_down = True
            print("  Listo.\n")

        elif up and link_was_down:
            print("[%s] Enlace '%s' RECUPERADO. Restaurando ruta principal..." %
                  (time.strftime("%H:%M:%S"), IFACE_TO_WATCH))
            for sw in SWITCHES:
                print("  -> %s: %s" % (sw["name"], sw["on_up_cmd"]))
                run_cli_command(sw["thrift_port"], sw["on_up_cmd"])
            link_was_down = False
            print("  Listo.\n")

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMonitor detenido.")
        sys.exit(0)
