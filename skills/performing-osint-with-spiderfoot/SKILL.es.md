---
name: performing-osint-with-spiderfoot
description: Automate OSINT collection using SpiderFoot REST API and CLI for target profiling, module-based reconnaissance, and structured result analysis across 200+ data sources
domain: cybersecurity
subdomain: threat-intelligence
tags:
  - osint
  - spiderfoot
  - reconnaissance
  - threat-intelligence
  - attack-surface
  - target-profiling
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---

# Reconocimiento OSINT con SpiderFoot

## Descripción General

SpiderFoot es una herramienta de automatización OSINT de código abierto con más de 200 módulos que se integra con fuentes de datos para inteligencia de amenazas y mapeo de superficie de ataque. Esta habilidad utiliza la API REST de SpiderFoot y su CLI (sf.py/spiderfoot-cli) para crear y gestionar escaneos, seleccionar módulos por caso de uso (footprint, investigación, pasivo), parsear resultados estructurados de dominios, IPs, direcciones de correo electrónico, credenciales filtradas y registros DNS, y generar perfiles de inteligencia de objetivos.

## Requisitos Previos

- SpiderFoot 4.0+ instalado o cuenta en SpiderFoot HX cloud
- Python 3.8+ con la biblioteca requests
- Servidor SpiderFoot ejecutándose en el puerto predeterminado 5001
- Opcional: claves API para los módulos de VirusTotal, Shodan, HaveIBeenPwned

## Pasos

1. Conectar a la API REST de SpiderFoot o usar la interfaz CLI
2. Crear un nuevo escaneo con especificación del objetivo (dominio, IP, correo electrónico, nombre)
3. Seleccionar módulos de escaneo por caso de uso (todos, footprint, investigación, pasivo)
4. Monitorear el progreso del escaneo mediante consultas periódicas a la API
5. Recuperar y parsear los resultados del escaneo por tipo de elemento de datos
6. Extraer hallazgos clave: subdominios, IPs, correos electrónicos, credenciales filtradas
7. Generar informe estructurado de inteligencia OSINT

## Salida Esperada

Informe JSON que contiene hallazgos OSINT organizados por tipo de dato (dominios, IPs, correos electrónicos, credenciales, registros DNS), atribución de la fuente del módulo, y resumen del perfil del objetivo con indicadores de riesgo.
