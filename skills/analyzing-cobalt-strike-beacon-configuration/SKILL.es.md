---
name: analyzing-cobalt-strike-beacon-configuration
description: Extract and analyze Cobalt Strike beacon configuration from PE files and memory dumps to identify C2 infrastructure, malleable profiles, and operator tradecraft.
domain: cybersecurity
subdomain: malware-analysis
tags: [cobalt-strike, beacon, c2, malware-analysis, config-extraction, threat-hunting, red-team-tools]
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---
# Análisis de Configuración de Beacon de Cobalt Strike

## Descripción General

Cobalt Strike es una herramienta comercial de simulación de adversarios ampliamente abusada por actores de amenazas para operaciones de post-explotación. Los payloads de beacon contienen datos de configuración embebidos que revelan direcciones de servidores C2, protocolos de comunicación, intervalos de sleep, valores de jitter, configuraciones de perfiles malleable C2, identificadores de watermark y claves de cifrado. Extraer esta configuración de archivos PE, shellcode o volcados de memoria es crítico para que los equipos de respuesta a incidentes mapeen la infraestructura del atacante y atribuyan campañas. La configuración del beacon está codificada con XOR usando un solo byte (0x69 para la versión 3, 0x2e para la versión 4) y se almacena en formato Type-Length-Value (TLV) dentro de la sección .data.

## Requisitos Previos

- Python 3.9+ con `dissect.cobaltstrike`, `pefile`, `yara-python`
- SentinelOne CobaltStrikeParser (`parse_beacon_config.py`)
- Editor hexadecimal (010 Editor, HxD) para inspección manual
- Comprensión del formato de archivos PE y codificación XOR
- Herramientas de adquisición de volcados de memoria (Volatility3, WinDbg)
- Herramientas de análisis de red (Wireshark) para correlación de tráfico C2

## Conceptos Clave

### Estructura de Configuración del Beacon

Los beacons de Cobalt Strike almacenan su configuración como un bloque de entradas TLV (Type-Length-Value) dentro de la sección .data del PE. Los beacons stageless cifran todo el código del beacon con una clave de 4 bytes. El bloque de configuración en sí usa una clave XOR de un solo byte. Cada entrada TLV contiene un identificador de tipo de 2 bytes (p. ej., 0x0001 para BeaconType, 0x0008 para C2Server), una longitud de 2 bytes y datos de longitud variable.

### Perfiles Malleable C2

La configuración del beacon codifica el perfil malleable C2 que dicta las transformaciones de solicitudes/respuestas HTTP, incluyendo rutas URI, encabezados, codificación de metadatos (Base64, NetBIOS) y transformaciones de datos. Analizar estas configuraciones revela cómo el beacon disfraza su tráfico para mezclarse con el tráfico web legítimo.

### Watermark e Identificación de Licencia

Cada licencia de Cobalt Strike embebe un watermark único (entero de 4 bytes) en los beacons generados. Extraer el watermark puede vincular múltiples beacons al mismo operador o licencia crackeada. Las bases de datos de watermarks conocidos mantenidas por proveedores de inteligencia de amenazas mapean watermarks a actores de amenazas específicos o claves de licencia filtradas.

## Pasos Prácticos

### Paso 1: Extraer Configuración con CobaltStrikeParser

```python
#!/usr/bin/env python3
"""Extraer configuración de beacon de Cobalt Strike desde PE o volcado de memoria."""
import sys
import json

# Usando CobaltStrikeParser de SentinelOne
# pip install dissect.cobaltstrike
from dissect.cobaltstrike.beacon import BeaconConfig

def extract_beacon_config(filepath):
    """Parsear configuración del beacon desde un archivo."""
    configs = list(BeaconConfig.from_path(filepath))

    if not configs:
        print(f"[-] No se encontró configuración de beacon en {filepath}")
        return None

    for i, config in enumerate(configs):
        print(f"\n[+] Configuración de Beacon #{i+1}")
        print(f"{'='*60}")

        settings = config.as_dict()

        # Campos críticos para respuesta a incidentes
        critical_fields = [
            "SETTING_C2_REQUEST",
            "SETTING_C2_RECOVER",
            "SETTING_PUBKEY",
            "SETTING_DOMAINS",
            "SETTING_BEACONTYPE",
            "SETTING_PORT",
            "SETTING_SLEEPTIME",
            "SETTING_JITTER",
            "SETTING_MAXGET",
            "SETTING_SPAWNTO_X86",
            "SETTING_SPAWNTO_X64",
            "SETTING_PIPENAME",
            "SETTING_WATERMARK",
            "SETTING_C2_VERB_GET",
            "SETTING_C2_VERB_POST",
            "SETTING_USERAGENT",
            "SETTING_PROTOCOL",
        ]

        for field in critical_fields:
            value = settings.get(field, "N/A")
            print(f"  {field}: {value}")

        return settings

    return None


def extract_c2_indicators(config):
    """Extraer indicadores C2 accionables de la configuración del beacon."""
    indicators = {
        "c2_domains": [],
        "c2_ips": [],
        "c2_urls": [],
        "user_agent": "",
        "named_pipes": [],
        "spawn_processes": [],
        "watermark": "",
    }

    if not config:
        return indicators

    # Extraer dominios C2
    domains = config.get("SETTING_DOMAINS", "")
    if domains:
        for domain in str(domains).split(","):
            domain = domain.strip().rstrip("/")
            if domain:
                indicators["c2_domains"].append(domain)

    # Extraer user agent
    indicators["user_agent"] = str(config.get("SETTING_USERAGENT", ""))

    # Extraer named pipes
    pipe = config.get("SETTING_PIPENAME", "")
    if pipe:
        indicators["named_pipes"].append(str(pipe))

    # Extraer procesos spawn-to
    for arch in ["SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64"]:
        proc = config.get(arch, "")
        if proc:
            indicators["spawn_processes"].append(str(proc))

    # Extraer watermark
    indicators["watermark"] = str(config.get("SETTING_WATERMARK", ""))

    return indicators


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <archivo_beacon_o_volcado>")
        sys.exit(1)

    config = extract_beacon_config(sys.argv[1])
    if config:
        indicators = extract_c2_indicators(config)
        print(f"\n[+] Indicadores C2 Extraídos:")
        print(json.dumps(indicators, indent=2))
```

### Paso 2: Descifrado Manual XOR de la Configuración del Beacon

```python
import struct

def find_and_decrypt_config(data):
    """Localizar y descifrar manualmente la configuración del beacon."""
    # Cobalt Strike 4.x usa 0x2e como clave XOR
    xor_keys = [0x2e, 0x69]  # v4, v3

    for xor_key in xor_keys:
        # Buscar los bytes mágicos de configuración después del XOR
        # La configuración comienza con 0x0001 (BeaconType) cifrado con XOR
        magic = bytes([0x00 ^ xor_key, 0x01 ^ xor_key,
                       0x00 ^ xor_key, 0x02 ^ xor_key])

        offset = data.find(magic)
        if offset == -1:
            continue

        print(f"[+] Configuración encontrada en offset 0x{offset:x} (clave XOR: 0x{xor_key:02x})")

        # Descifrar el bloque de configuración (típicamente 4096 bytes)
        config_size = 4096
        encrypted = data[offset:offset + config_size]
        decrypted = bytes([b ^ xor_key for b in encrypted])

        # Parsear entradas TLV
        entries = parse_tlv(decrypted)
        return entries

    return None


def parse_tlv(data):
    """Parsear entradas de configuración Type-Length-Value."""
    entries = {}
    offset = 0

    # Mapeo de tipos de campo TLV
    field_names = {
        0x0001: "BeaconType",
        0x0002: "Port",
        0x0003: "SleepTime",
        0x0004: "MaxGetSize",
        0x0005: "Jitter",
        0x0006: "MaxDNS",
        0x0007: "Deprecated_PublicKey",
        0x0008: "C2Server",
        0x0009: "UserAgent",
        0x000a: "PostURI",
        0x000b: "Malleable_C2_Instructions",
        0x000c: "Deprecated_HttpGet_Metadata",
        0x000d: "SpawnTo_x86",
        0x000e: "SpawnTo_x64",
        0x000f: "CryptoScheme",
        0x001a: "Watermark",
        0x001d: "C2_HostHeader",
        0x0024: "PipeName",
        0x0025: "Year",
        0x0026: "Month",
        0x0027: "Day",
        0x0036: "ProxyHostname",
    }

    while offset + 6 <= len(data):
        entry_type = struct.unpack(">H", data[offset:offset+2])[0]
        entry_len_type = struct.unpack(">H", data[offset+2:offset+4])[0]
        entry_len = struct.unpack(">H", data[offset+4:offset+6])[0]

        if entry_type == 0:
            break

        value_start = offset + 6
        value_end = value_start + entry_len
        value_data = data[value_start:value_end]

        field_name = field_names.get(entry_type, f"Unknown_0x{entry_type:04x}")

        if entry_len_type == 1:  # Short
            value = struct.unpack(">H", value_data[:2])[0]
        elif entry_len_type == 2:  # Int
            value = struct.unpack(">I", value_data[:4])[0]
        elif entry_len_type == 3:  # String/Blob
            value = value_data.rstrip(b'\x00').decode('utf-8', errors='replace')
        else:
            value = value_data.hex()

        entries[field_name] = value
        print(f"  {field_name}: {value}")

        offset = value_end

    return entries
```

### Paso 3: Regla YARA para Detección de Beacon

```python
import yara

cobalt_strike_rule = """
rule CobaltStrike_Beacon_Config {
    meta:
        description = "Detecta configuración de beacon de Cobalt Strike"
        author = "Equipo de Análisis de Malware"
        date = "2025-01-01"

    strings:
        // Marcador de configuración cifrado con XOR para CS 4.x (clave 0x2e)
        $config_v4 = { 2e 2f 2e 2c }

        // Marcador de configuración cifrado con XOR para CS 3.x (clave 0x69)
        $config_v3 = { 69 68 69 6b }

        // Cadenas comunes del beacon
        $str_pipe = "\\\\.\\pipe\\" ascii wide
        $str_beacon = "beacon" ascii nocase
        $str_sleeptime = "sleeptime" ascii nocase

        // Patrón del cargador reflectivo
        $reflective = { 4D 5A 41 52 55 48 89 E5 }

    condition:
        ($config_v4 or $config_v3) or
        (2 of ($str_*) and $reflective)
}
"""

def scan_for_beacons(filepath):
    """Escanear archivo con reglas YARA en busca de beacons de Cobalt Strike."""
    rules = yara.compile(source=cobalt_strike_rule)
    matches = rules.match(filepath)

    for match in matches:
        print(f"[+] Coincidencia YARA: {match.rule}")
        for string_match in match.strings:
            offset = string_match.instances[0].offset
            print(f"    Cadena: {string_match.identifier} en offset 0x{offset:x}")

    return matches
```

### Paso 4: Correlación de Tráfico de Red

```python
from dissect.cobaltstrike.c2 import HttpC2Config

def analyze_c2_profile(beacon_config):
    """Analizar perfil malleable C2 de la configuración del beacon."""
    print("\n[+] Análisis del Perfil Malleable C2")
    print("=" * 60)

    # Configuración HTTP GET
    get_verb = beacon_config.get("SETTING_C2_VERB_GET", "GET")
    get_uri = beacon_config.get("SETTING_C2_REQUEST", "")
    print(f"\n  Solicitud HTTP GET:")
    print(f"    Verbo: {get_verb}")
    print(f"    URI: {get_uri}")

    # Configuración HTTP POST
    post_verb = beacon_config.get("SETTING_C2_VERB_POST", "POST")
    post_uri = beacon_config.get("SETTING_C2_POSTREQ", "")
    print(f"\n  Solicitud HTTP POST:")
    print(f"    Verbo: {post_verb}")
    print(f"    URI: {post_uri}")

    # User Agent
    ua = beacon_config.get("SETTING_USERAGENT", "")
    print(f"\n  User-Agent: {ua}")

    # Encabezado Host
    host = beacon_config.get("SETTING_C2_HOSTHEADER", "")
    print(f"  Encabezado Host: {host}")

    # Sleep y jitter para el patrón de tráfico
    sleep_ms = beacon_config.get("SETTING_SLEEPTIME", 60000)
    jitter = beacon_config.get("SETTING_JITTER", 0)
    print(f"\n  Tiempo de Sleep: {sleep_ms}ms")
    print(f"  Jitter: {jitter}%")

    # Generar firmas Suricata/Snort
    print(f"\n[+] Firmas de Red Sugeridas:")
    if ua:
        print(f'  alert http any any -> any any (msg:"CS Beacon UA"; '
              f'content:"{ua}"; http_user_agent; sid:1000001; rev:1;)')
    if get_uri:
        print(f'  alert http any any -> any any (msg:"CS Beacon URI"; '
              f'content:"{get_uri}"; http_uri; sid:1000002; rev:1;)')
```

## Criterios de Validación

- Configuración del beacon extraída exitosamente del archivo PE o volcado de memoria
- Dominios/IPs del servidor C2 correctamente identificados con puerto y protocolo
- Parámetros del perfil malleable C2 decodificados mostrando las transformaciones HTTP
- Valor del watermark extraído para correlación de atribución
- Valores de sleep time y jitter coinciden con los intervalos de beacon observados en la red
- Las reglas YARA detectan el beacon tanto en muestras empaquetadas como desempaquetadas
- Firmas de red generadas a partir del perfil C2 extraído

## Referencias

- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [Biblioteca dissect.cobaltstrike](https://github.com/fox-it/dissect.cobaltstrike)
- [SentinelLabs - Análisis de Configuración de Beacon](https://www.sentinelone.com/labs/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/)
- [Extracción de Configuración de Cobalt Strike Stager](https://blog.securehat.co.uk/cobaltstrike/extracting-config-from-cobaltstrike-stager-shellcode)
- [MITRE ATT&CK - Cobalt Strike S0154](https://attack.mitre.org/software/S0154/)
