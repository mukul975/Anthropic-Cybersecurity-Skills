---
name: detecting-credential-dumping-techniques
description: Detect LSASS credential dumping, SAM database extraction, and NTDS.dit theft using Sysmon Event ID 10, Windows Security logs, and SIEM correlation rules
domain: cybersecurity
subdomain: threat-detection
tags:
  - credential-dumping
  - lsass
  - mimikatz
  - sysmon
  - active-directory
  - windows-security
  - defense-evasion
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---

# Detección de Técnicas de Volcado de Credenciales

## Descripción General

El volcado de credenciales (MITRE ATT&CK T1003) es una técnica de post-explotación donde los adversarios extraen credenciales de autenticación de la memoria del sistema operativo, hives del registro o bases de datos del controlador de dominio. Esta habilidad cubre la detección de acceso a la memoria de LSASS mediante Sysmon Event ID 10 (ProcessAccess), la exportación del hive del registro SAM mediante reg.exe, la extracción de NTDS.dit mediante ntdsutil/vssadmin, y el abuso de MiniDump con comsvcs.dll. Las reglas de detección analizan bitmasks de GrantedAccess, procesos invocantes sospechosos y firmas de herramientas conocidas.

## Requisitos Previos

- Sysmon v14+ desplegado con registro de ProcessAccess (Event ID 10) para lsass.exe
- Política de auditoría de seguridad de Windows habilitando la creación de procesos (Event ID 4688) con registro de línea de comandos
- SIEM Splunk o Elastic ingiriendo registros de Sysmon y de seguridad de Windows
- Python 3.8+ para análisis de registros

## Pasos

1. Configurar Sysmon para registrar eventos ProcessAccess dirigidos a lsass.exe
2. Reenviar Sysmon Event ID 10 y Windows Event ID 4688 al SIEM
3. Crear reglas de detección para patrones de GrantedAccess conocidos (0x1010, 0x1FFFFF)
4. Detectar MiniDump con comsvcs.dll y procdump.exe apuntando al PID de LSASS
5. Alertar sobre comandos de exportación de hives SAM/SECURITY/SYSTEM mediante reg.exe
6. Detectar creación de shadow copy con ntdsutil/vssadmin para robo de NTDS.dit
7. Correlacionar detecciones con contexto de usuario/host para puntuación de riesgo

## Salida Esperada

Informe JSON que contiene indicadores detectados de volcado de credenciales con clasificación de técnica, calificaciones de severidad, detalles del proceso, mapeo a MITRE ATT&CK, y consultas de detección para Splunk/Elastic.
