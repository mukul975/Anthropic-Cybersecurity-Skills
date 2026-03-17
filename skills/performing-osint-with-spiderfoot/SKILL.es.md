---
name: performing-osint-with-spiderfoot
description: Automate OSINT collection using SpiderFoot REST API and CLI for target profiling, module-based reconnaissance, and structured result analysis across 200+ data sources
domain: cybersecurity
subdomain: threat-intelligence
tags: [osint, spiderfoot, reconnaissance, threat-intelligence, attack-surface, target-profiling]
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---

# Recolección de OSINT con SpiderFoot

## Descripción General

SpiderFoot es una herramienta de automatización OSINT de código abierto con más de 200 módulos que se integra con fuentes de datos para inteligencia de amenazas y mapeo de superficie de ataque. Esta skill utiliza la API REST de SpiderFoot y la CLI (sf.py/spiderfoot-cli) para crear y gestionar escaneos, seleccionar módulos por caso de uso (footprint, investigate, passive), analizar resultados estructurados para dominios, IPs, direcciones de correo, credenciales filtradas y registros DNS, y generar perfiles de inteligencia del objetivo.

## Prerrequisitos

- SpiderFoot 4.0+ instalado o cuenta SpiderFoot HX en la nube
- Python 3.8+ con la librería requests
- Servidor SpiderFoot ejecutándose en el puerto predeterminado 5001
- Opcional: Claves API para módulos de VirusTotal, Shodan, HaveIBeenPwned

## Pasos

1. Conectar a la API REST de SpiderFoot o utilizar la interfaz CLI
2. Crear un nuevo escaneo con especificación del objetivo (dominio, IP, correo, nombre)
3. Seleccionar módulos de escaneo por caso de uso (all, footprint, investigate, passive)
4. Monitorear el progreso del escaneo mediante polling de la API
5. Recuperar y analizar resultados del escaneo por tipo de elemento de datos
6. Extraer hallazgos clave: subdominios, IPs, correos, credenciales filtradas
7. Generar reporte estructurado de inteligencia OSINT

## Resultado Esperado

Reporte JSON que contiene hallazgos OSINT organizados por tipo de dato (dominios, IPs, correos, credenciales, registros DNS), atribución de módulo fuente, y resumen del perfil del objetivo con indicadores de riesgo.
