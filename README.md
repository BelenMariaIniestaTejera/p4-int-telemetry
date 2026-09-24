# P4 INT Telemetry

Este proyecto amplía y adapta una implementación existente de **In-band Network Telemetry (INT)** basada en P4 y BMv2. Ha sido desarrollado como parte del Trabajo Fin de Máster *"Desarrollo y análisis de una solución de In-Band Network Telemetry en redes con plano de datos programable"*, del Máster Universitario en Ingeniería de Redes y Servicios Telemáticos de la Universidad Politécnica de Madrid.

El trabajo incluye, entre otras aportaciones, la incorporación de soporte para tráfico ICMP, el rediseño del mecanismo de gestión de metadatos acumulados, la ampliación de la topología de red a un escenario *leaf-spine* con tolerancia a fallos y selección de caminos, la extensión de la información de telemetría INT con un nuevo campo de metadatos y la corrección de una anomalía en el cálculo de la latencia por salto.

## Reconocimientos y proyecto de partida

Este trabajo parte del repositorio [`int-platforms`](https://github.com/GEANT-DataPlaneProgramming/int-platforms), desarrollado por GÉANT Data Plane Programming, que proporciona una implementación de INT para plataformas con plano de datos programable como BMv2 y Tofino.

Este repositorio incluye únicamente el código base necesario para el desarrollo del trabajo, adaptado y ampliado con las funcionalidades implementadas en este TFM. La estructura del repositorio ha sido reorganizada específicamente para presentar los componentes utilizados y desarrollados durante el proyecto.

## Estructura del repositorio

```text
p4-int-telemetry/
├── p4/                              # Programa P4 modificado y ampliado
│   ├── int.p4
│   └── include/
│       ├── forward.p4
│       ├── headers.p4
│       ├── int_report.p4
│       ├── int_sink.p4
│       ├── int_source.p4
│       ├── int_transit.p4
│       ├── parser.p4
│       └── port_forward.p4
│
├── escenarios/                      # Topologías y configuración de los switches
│   ├── original/                    # Topología de partida de tres switches
│   │   ├── topo.txt
│   │   └── commands/
│   │       ├── commands1.txt
│   │       ├── commands2.txt
│   │       └── commands3.txt
│   │
│   └── leafspine/                  # Topología ampliada de cinco switches
│       ├── topo.txt
│       └── commands/
│           ├── commands1.txt
│           ├── commands2.txt
│           ├── commands3.txt
│           ├── commands4.txt
│           └── commands5.txt
│
├── mininet/                         # Arranque de la emulación
│   └── start_int1.0.sh
│
├── scripts/                         # Scripts auxiliares
│   ├── usar_escenario.sh
│   ├── monitor_link.py
│   └── watchdog_completo.sh
│
├── collector/                       # Colector de reportes INT
│   └── int_collector_influx.py
│
└── wireshark/                       # Disector de reportes INT para Wireshark
    └── int_report.lua
```

Los escenarios de red se encuentran separados de la implementación P4. Cada escenario contiene su propia topología (`topo.txt`) y los ficheros `commands` necesarios para configurar las tablas de los switches correspondientes.

## Requisitos

Para la ejecución y análisis del prototipo se utilizan las siguientes herramientas:

- [P4](https://p4.org/) / P4_16
- [BMv2](https://github.com/p4lang/behavioral-model) (`simple_switch` y `simple_switch_CLI`)
- [Mininet](https://mininet.org/)
- Python 3
- [InfluxDB](https://www.influxdata.com/) 1.8.x
- [Grafana](https://grafana.com/)
- [Wireshark](https://www.wireshark.org/) con soporte para plugins Lua
- Docker, utilizado para el despliegue de algunos componentes del entorno

## Inicio rápido

### 0. Arrancar los servicios de InfluxDB y Grafana

Antes de arrancar la emulación, es necesario que InfluxDB y Grafana estén en ejecución:

```bash
docker start influxdb
docker start grafana
```

### 1. Seleccionar el escenario

El escenario que se desea utilizar puede seleccionarse mediante el script `usar_escenario.sh`, ejecutado desde la raíz del repositorio.

Para utilizar la topología *leafspine*:

```bash
bash usar_escenario.sh leafspine
```

Para utilizar la topología original de tres switches:

```bash
bash usar_escenario.sh original
```

Para consultar los escenarios disponibles:

```bash
bash usar_escenario.sh --listar
```

Cada escenario contiene su propia definición de topología y los comandos necesarios para configurar las tablas de los switches.

### 2. Arrancar la emulación

Una vez seleccionado el escenario:

```bash
sudo bash mininet/start_int1.0.sh
```

Durante la inicialización se crea la topología correspondiente en Mininet y se ejecutan los switches BMv2. Las reglas de configuración de los switches, incluyendo las reglas de reenvío y la configuración de INT, se cargan automáticamente a partir del escenario activo.

El colector de telemetría (`collector/int_collector_influx.py`) se arranca también de forma automática durante este proceso, conectándose a InfluxDB.

### 3. Generar tráfico

Una vez iniciada la red, puede generarse tráfico entre los hosts desde la consola de Mininet. Por ejemplo:

```bash
mininet> h1 ping -c 3 h2
```

El tráfico configurado como monitorizable será procesado por los nodos INT correspondientes.

### 4. Consultar los reportes INT

Los reportes INT generados por el nodo *sink* pueden analizarse mediante diferentes mecanismos:

- Almacenamiento de los datos de telemetría en InfluxDB.
- Visualización de los datos almacenados mediante Grafana.
- Captura directa del tráfico de reportes (puerto UDP 6000) y análisis mediante Wireshark, utilizando el disector incluido en `wireshark/int_report.lua`.

### 5. Monitorización y recuperación ante fallos

En el escenario *leafspine* se incluyen scripts adicionales para monitorizar el estado de los enlaces y actuar sobre las reglas de reenvío cuando se detecta un fallo.

El script principal de monitorización puede ejecutarse, dentro del entorno de emulación, mediante:

```bash
python3 scripts/monitor_link.py
```

## Funcionalidades implementadas

Las principales funcionalidades incorporadas o modificadas durante el desarrollo del TFM son:

- **Soporte para tráfico ICMP**, no contemplado en la implementación de partida.
- **Rediseño del mecanismo de extracción de metadatos INT acumulados**, permitiendo procesar de forma dinámica la información correspondiente a los saltos anteriores.
- **Escenario de red leaf-spine de cinco switches**, con caminos redundantes.
- **Mecanismo de tolerancia a fallos**, basado en reglas de prioridad y recuperación automática mediante un script de monitorización.
- **Políticas de reenvío en función del host de origen**, utilizadas para seleccionar diferentes caminos a través de la topología.
- **Extensión de la implementación INT con el campo `pkt_len`**, que permite registrar el tamaño del paquete observado en cada nodo durante su recorrido.
- **Corrección del cálculo de `hop_latency`** en el nodo *sink*, evitando los valores anómalos observados durante las pruebas.
- **Adaptación del colector de telemetría**, incluyendo el procesamiento de la información añadida durante el desarrollo y su almacenamiento en InfluxDB.
- **Disector de Wireshark para reportes INT**, utilizado para facilitar la interpretación directa de la información de telemetría.
- **Visualización mediante Grafana**, incluyendo la representación de información obtenida a partir de los reportes INT.

## Limitaciones conocidas

- **Tráfico TCP**: aunque la implementación de partida ya incluía el parseo de tráfico TCP y durante el trabajo se configuró su selección como tráfico monitorizable, las pruebas realizadas mostraron que la instrumentación mediante INT no se aplicaba de forma fiable a los segmentos de datos TCP. La causa raíz no pudo determinarse de forma concluyente, por lo que su soporte completo queda como línea de trabajo futura.

## Autor

**Belén María Iniesta Tejera**  
Trabajo Fin de Máster  
Máster Universitario en Ingeniería de Redes y Servicios Telemáticos  
Universidad Politécnica de Madrid
