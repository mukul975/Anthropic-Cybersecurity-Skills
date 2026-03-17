---
name: performing-memory-forensics-with-volatility3
description: Analyze volatile memory dumps using Volatility 3 to extract running processes, network connections, loaded modules, and evidence of malicious activity.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-forensics, volatility, ram-analysis, malware-detection, incident-response]
mitre_attack: ["T1003", "T1055", "T1620", "T1574"]
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---

# Análisis Forense de Memoria con Volatility 3

## Cuándo Utilizar
- Al analizar un volcado de RAM de un sistema comprometido o sospechoso
- Durante la respuesta a incidentes para identificar malware en ejecución, código inyectado o rootkits
- Cuando se necesita extraer credenciales, claves de cifrado o conexiones de red desde la memoria
- Para detectar process hollowing, inyección de DLL o procesos ocultos
- Cuando el análisis forense de disco por sí solo es insuficiente y los datos volátiles son críticos

## Requisitos Previos
- Python 3.7+ instalado
- Framework Volatility 3 instalado (`pip install volatility3`)
- Volcado de memoria en formato raw, ELF o crash dump
- Tablas de símbolos apropiadas (archivos ISF) para la versión del sistema operativo objetivo
- Espacio en disco suficiente para la salida del análisis (2-3x el tamaño del volcado de memoria)
- Opcional: reglas YARA para escaneo de malware en memoria

## Flujo de Trabajo

### Paso 1: Adquirir el Volcado de Memoria e Instalar Volatility 3

```bash
# Instalar Volatility 3
pip install volatility3

# O instalar desde el código fuente para las últimas funcionalidades
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .

# Descargar tablas de símbolos de Windows (paquetes ISF)
# Colocar en el directorio volatility3/symbols/
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d /opt/volatility3/volatility3/symbols/

# Descargar paquetes de símbolos para Linux y Mac
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip

# Herramientas de adquisición de memoria (para sistemas en vivo):
# Windows: winpmem, DumpIt, FTK Imager
# Linux: LiME (Linux Memory Extractor)
sudo insmod lime-$(uname -r).ko "path=/cases/memory/linux_mem.lime format=lime"

# Verificar el volcado de memoria
file /cases/case-2024-001/memory/memory.raw
ls -lh /cases/case-2024-001/memory/memory.raw
```

### Paso 2: Identificar el Perfil del Sistema Operativo

```bash
# Ejecutar el plugin banners para identificar el SO
vol -f /cases/case-2024-001/memory/memory.raw banners

# Para Windows, identificar la versión del SO
vol -f /cases/case-2024-001/memory/memory.raw windows.info

# Ejemplo de salida:
# Variable        Value
# Kernel Base     0xf8047e200000
# DTB             0x1ad000
# Symbols         ntkrnlmp.pdb/GUID
# Is64Bit         True
# IsPAE           False
# primary layer   Intel32e
# KdVersionBlock  0xf8047ee232c0
# Major/Minor     15.19041
# Machine Type    34404
# KeNumberProcessors 4
# SystemTime      2024-01-18 14:32:15 UTC
# NtBuildLab      19041.1.amd64fre.vb_release.191206-1406
# NtProductType   NtProductWinNt
# NtSystemRoot    C:\WINDOWS
# PE MajorOperatingSystemVersion 10
# PE MinorOperatingSystemVersion 0

# Para volcados de memoria Linux
vol -f /cases/case-2024-001/memory/linux_mem.lime linux.info
```

### Paso 3: Enumerar Procesos y Detectar Anomalías

```bash
# Listar todos los procesos en ejecución
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | tee /cases/case-2024-001/analysis/pslist.txt

# Mostrar árbol de procesos (relaciones padre-hijo)
vol -f /cases/case-2024-001/memory/memory.raw windows.pstree | tee /cases/case-2024-001/analysis/pstree.txt

# Detectar procesos ocultos mediante análisis de vista cruzada
vol -f /cases/case-2024-001/memory/memory.raw windows.psscan | tee /cases/case-2024-001/analysis/psscan.txt

# Comparar pslist vs psscan para encontrar procesos ocultos
diff <(vol -f memory.raw windows.pslist | awk '{print $1}' | sort) \
     <(vol -f memory.raw windows.psscan | awk '{print $1}' | sort)

# Listar DLLs cargadas por un proceso sospechoso (PID 4532)
vol -f /cases/case-2024-001/memory/memory.raw windows.dlllist --pid 4532

# Verificar process hollowing e inyección
vol -f /cases/case-2024-001/memory/memory.raw windows.malfind | tee /cases/case-2024-001/analysis/malfind.txt

# Volcar la memoria del proceso sospechoso para análisis adicional
vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 4532 --dump \
   -o /cases/case-2024-001/analysis/dumps/
```

### Paso 4: Analizar Conexiones de Red y Registro

```bash
# Listar conexiones de red activas
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | tee /cases/case-2024-001/analysis/netscan.txt

# Filtrar conexiones establecidas
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep ESTABLISHED

# Filtrar puertos en escucha
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep LISTENING

# Extraer conexiones de red con mapeo de procesos
vol -f /cases/case-2024-001/memory/memory.raw windows.netstat | tee /cases/case-2024-001/analysis/netstat.txt

# Volcar hives del registro desde la memoria
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.hivelist

# Extraer claves de registro específicas
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.printkey \
   --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Verificar servicios
vol -f /cases/case-2024-001/memory/memory.raw windows.svcscan | tee /cases/case-2024-001/analysis/services.txt
```

### Paso 5: Extraer Credenciales y Datos Sensibles

```bash
# Volcar credenciales en caché (hashdump)
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump | tee /cases/case-2024-001/analysis/hashes.txt

# Extraer secretos LSA
vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump

# Volcar credenciales de dominio en caché
vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump

# Buscar cadenas de texto plano en la memoria del proceso
vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 4532 \
   | grep -iE '(password|credential|token|api.key)'

# Extraer historial de comandos de cmd.exe/powershell
vol -f /cases/case-2024-001/memory/memory.raw windows.cmdline | tee /cases/case-2024-001/analysis/cmdline.txt

# Extraer variables de entorno
vol -f /cases/case-2024-001/memory/memory.raw windows.envars --pid 4532
```

### Paso 6: Escanear en Busca de Malware con Reglas YARA

```bash
# Escanear memoria con reglas YARA
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/malware_index.yar | tee /cases/case-2024-001/analysis/yara_hits.txt

# Escanear memoria de un proceso específico
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/apt_rules.yar --pid 4532

# Verificar módulos del kernel cargados en busca de rootkits
vol -f /cases/case-2024-001/memory/memory.raw windows.modules | tee /cases/case-2024-001/analysis/modules.txt

# Detectar módulos desvinculados/ocultos
vol -f /cases/case-2024-001/memory/memory.raw windows.modscan | tee /cases/case-2024-001/analysis/modscan.txt

# Verificar hooks en la SSDT (System Service Descriptor Table)
vol -f /cases/case-2024-001/memory/memory.raw windows.ssdt | grep -v "ntoskrnl\|win32k"

# Volcar un ejecutable sospechoso desde la memoria
vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles --pid 4532 \
   -o /cases/case-2024-001/analysis/extracted/
```

### Paso 7: Compilar Hallazgos en un Informe

```bash
# Generar resumen de análisis completo
echo "=== INFORME DE ANÁLISIS FORENSE DE MEMORIA ===" > /cases/case-2024-001/analysis/memory_report.txt
echo "Imagen: memory.raw" >> /cases/case-2024-001/analysis/memory_report.txt
echo "SO: Windows 10 Build 19041" >> /cases/case-2024-001/analysis/memory_report.txt
echo "" >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Procesos Sospechosos ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/malfind.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Conexiones de Red ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/netscan.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Coincidencias YARA ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/yara_hits.txt >> /cases/case-2024-001/analysis/memory_report.txt

# Calcular hash del volcado de memoria para integridad
sha256sum /cases/case-2024-001/memory/memory.raw >> /cases/case-2024-001/analysis/memory_report.txt
```

## Conceptos Clave

| Concepto | Descripción |
|----------|-------------|
| Datos volátiles | Información que existe solo en RAM y se pierde cuando se corta la energía |
| Process hollowing | Técnica donde el malware reemplaza la memoria de un proceso legítimo con código malicioso |
| Inyección de DLL | Carga de DLLs no autorizadas en el espacio de direcciones de un proceso en ejecución |
| EPROCESS | Estructura del kernel de Windows que representa un proceso; base para el listado de procesos |
| Pool scanning | Búsqueda en memoria de firmas de objetos del kernel para encontrar artefactos ocultos |
| VAD (Virtual Address Descriptor) | Estructura de gestión de memoria que rastrea las regiones de memoria virtual del proceso |
| ISF (Intermediate Symbol Format) | Formato de tabla de símbolos de Volatility 3 para definiciones de estructuras específicas del SO |
| Malfind | Plugin que detecta código inyectado examinando permisos y contenido de los VAD |

## Herramientas y Sistemas

| Herramienta | Propósito |
|-------------|-----------|
| Volatility 3 | Framework principal de código abierto para análisis forense de memoria |
| LiME | Linux Memory Extractor para adquisición de volcados de RAM en Linux |
| WinPmem | Driver de adquisición de memoria física en Windows |
| DumpIt | Utilidad de Comae para volcado de memoria en Windows con un solo clic |
| YARA | Motor de coincidencia de patrones para escaneo de firmas de malware |
| Rekall | Framework alternativo de análisis forense de memoria (Google) |
| MemProcFS | Sistema de archivos de procesos en memoria para análisis de memoria |
| strings | Extracción de cadenas imprimibles de volcados de memoria binarios |

## Escenarios Comunes

**Escenario 1: Investigación de Malware Activo**
Adquirir memoria con DumpIt, ejecutar pslist/pstree para identificar procesos sospechosos, usar malfind para detectar código inyectado en svchost.exe, volcar el segmento de memoria inyectado, escanear con reglas YARA identificando un beacon de Cobalt Strike, extraer la IP del C2 desde netscan, correlacionar con los registros de red.

**Escenario 2: Robo de Credenciales Tras una Brecha**
Ejecutar hashdump y lsadump para extraer credenciales en caché, identificar la ejecución de mimikatz en la salida de cmdline, verificar volcados de memoria de lsass.exe en artefactos del sistema de archivos, correlacionar con evidencia de movimiento lateral en las conexiones de red.

**Escenario 3: Detección de Rootkits**
Comparar pslist (usa la lista enlazada EPROCESS) con psscan (pool scanning) para encontrar procesos desvinculados, verificar modules vs modscan para detectar drivers de kernel ocultos, examinar la SSDT en busca de hooks que redirijan llamadas al sistema, volcar módulos sospechosos para análisis estático.

**Escenario 4: Recuperación ante Incidente de Ransomware**
Extraer claves de cifrado de la memoria del proceso de ransomware antes del apagado del sistema, identificar la variante de ransomware usando YARA, encontrar el punto de ejecución inicial a través de artefactos de línea de comandos, mapear el movimiento lateral a través de conexiones de red.

## Formato de Salida

```
Análisis Forense de Memoria:
  Imagen:            memory.raw (16 GB)
  SO Identificado:   Windows 10 x64 Build 19041
  Hora de Captura:   2024-01-18 14:32:15 UTC

  Análisis de Procesos:
    Total de Procesos:     87
    Procesos Ocultos:      2 (PIDs: 4532, 6128)
    Procesos Inyectados:   3 (detecciones malfind)
    Sospechoso:            svchost.exe (PID 4532) - código inyectado en 0x7FFE0000

  Conexiones de Red:
    Total:        45
    Establecidas: 12
    Sospechosas:  3 (conexiones C2 a 185.xx.xx.xx:443)

  Credenciales Encontradas:
    Hashes NTLM:          4 cuentas
    Credenciales en Caché: 2 cuentas de dominio

  Coincidencias YARA:
    CobaltStrike_Beacon:  PID 4532 (3 coincidencias)
    Mimikatz_Memory:      PID 6128 (1 coincidencia)

  Artefactos Extraídos:   15 archivos volcados en /analysis/extracted/
```
