---
name: building-incident-response-dashboard
description: >
  Builds real-time incident response dashboards in Splunk, Elastic, or Grafana to provide SOC
  analysts and leadership with situational awareness during active incidents, tracking affected
  systems, containment status, IOC spread, and response timeline. Use when IR teams need unified
  visibility during incident coordination and post-incident reporting.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, dashboard, incident-response, splunk, visualization, situational-awareness, metrics]
version: "1.0"
author: mahipal
license: Apache-2.0
language: es
---
# Construcción de un Dashboard de Respuesta a Incidentes

## Cuándo Utilizar

Utilice esta habilidad cuando:
- Los equipos de IR necesitan dashboards en tiempo real durante incidentes activos para coordinación y seguimiento
- La dirección del SOC requiere dashboards operacionales que muestren el estado de incidentes y la carga de trabajo de los analistas
- Las revisiones post-incidente necesitan líneas de tiempo visuales y evaluaciones de impacto
- Las sesiones informativas ejecutivas requieren métricas de incidentes de alto nivel y análisis de tendencias

**No utilizar** para dashboards de monitoreo diario del SOC (use Incident Review en su lugar) — los dashboards de IR están diseñados para la coordinación de incidentes activos e informes de gestión.

## Requisitos Previos

- Plataforma SIEM (Splunk con Dashboard Studio, Elastic Kibana o Grafana)
- Datos de eventos notables e incidentes en el SIEM (índice incident_review de Splunk ES)
- Integración con sistema de tickets (ServiceNow, Jira) para seguimiento de remediación
- Tablas de búsqueda de activos e identidades para enriquecimiento de contexto
- Acceso de publicación de dashboards para el equipo SOC y distribución a la gerencia

## Flujo de Trabajo

### Paso 1: Diseñar el Layout del Dashboard de Incidente Activo

Construir un dashboard en Splunk Dashboard Studio para seguimiento de incidentes activos:

```xml
<dashboard version="2" theme="dark">
  <label>Active Incident Response Dashboard</label>
  <description>Real-time tracking for IR-2024-0450</description>

  <row>
    <panel>
      <title>Incident Summary</title>
      <single>
        <search>
          <query>
| makeresults
| eval incident_id="IR-2024-0450",
       status="CONTAINMENT",
       severity="Critical",
       affected_hosts=7,
       contained_hosts=5,
       iocs_identified=23,
       hours_elapsed=round((now()-strptime("2024-03-15 14:00","%Y-%m-%d %H:%M"))/3600,1)
| table incident_id, status, severity, affected_hosts, contained_hosts, iocs_identified, hours_elapsed
          </query>
        </search>
      </single>
    </panel>
  </row>
</dashboard>
```

### Paso 2: Construir el Panel de Sistemas Afectados en Tiempo Real

Rastrear sistemas afectados y su estado de contención:

```spl
| inputlookup ir_affected_systems.csv
| eval status_color = case(
    status="Contained", "#2ecc71",
    status="Compromised", "#e74c3c",
    status="Investigating", "#f39c12",
    status="Recovered", "#3498db",
    1=1, "#95a5a6"
  )
| stats count by status
| eval order = case(status="Compromised", 1, status="Investigating", 2,
                    status="Contained", 3, status="Recovered", 4)
| sort order
| table status, count

--- Tabla detallada de hosts
| inputlookup ir_affected_systems.csv
| lookup asset_lookup_by_cidr ip AS host_ip OUTPUT category, owner, priority
| table hostname, host_ip, category, owner, status, containment_time,
        compromise_vector, analyst_assigned
| sort status, hostname
```

### Paso 3: Construir el Panel de Seguimiento de IOCs

Monitorear la propagación de IOCs en el entorno:

```spl
--- IOCs identificados durante el incidente
index=* (src_ip IN ("185.234.218.50", "45.77.123.45") OR
         dest IN ("evil-c2.com", "malware-drop.com") OR
         file_hash IN ("a1b2c3d4...", "e5f6a7b8..."))
earliest="2024-03-14"
| stats count AS hits, dc(src_ip) AS unique_sources,
        dc(dest) AS unique_dests, latest(_time) AS last_seen
  by sourcetype
| sort - hits

--- Línea de tiempo de IOCs
index=* (src_ip IN ("185.234.218.50") OR dest="evil-c2.com")
earliest="2024-03-14"
| timechart span=1h count by sourcetype

--- Seguimiento de descubrimiento de nuevos IOCs
| inputlookup ir_ioc_list.csv
| stats count by ioc_type, source, discovery_time
| sort discovery_time
| table discovery_time, ioc_type, ioc_value, source, status
```

### Paso 4: Construir el Panel de Línea de Tiempo de Respuesta

Crear una línea de tiempo cronológica del incidente:

```spl
| inputlookup ir_timeline.csv
| sort _time
| eval phase = case(
    action_type="detection", "Detección",
    action_type="triage", "Triaje",
    action_type="containment", "Contención",
    action_type="eradication", "Erradicación",
    action_type="recovery", "Recuperación",
    1=1, "Otro"
  )
| eval phase_color = case(
    phase="Detección", "#e74c3c",
    phase="Triaje", "#f39c12",
    phase="Contención", "#e67e22",
    phase="Erradicación", "#2ecc71",
    phase="Recuperación", "#3498db"
  )
| table _time, phase, action, analyst, details
```

Ejemplo de datos de línea de tiempo:
```csv
_time,action_type,action,analyst,details
2024-03-15 14:00,detection,Alerta activada - Beacon de Cobalt Strike detectado,splunk_es,Evento notable NE-2024-08921
2024-03-15 14:12,triage,Alerta triada - verdadero positivo confirmado,analyst_jdoe,Puntuación VT 52/72 en hash del beacon
2024-03-15 14:23,containment,Host WORKSTATION-042 aislado,analyst_jdoe,Aislamiento de red con CrowdStrike
2024-03-15 14:35,containment,Dominio C2 bloqueado en firewall,analyst_msmith,Regla desplegada en Palo Alto
2024-03-15 15:00,eradication,Escaneo de IOCs a nivel empresarial iniciado,analyst_jdoe,Búsqueda en Splunk en todos los índices
2024-03-15 15:30,containment,3 hosts adicionales identificados y aislados,analyst_msmith,Movimiento lateral confirmado
2024-03-15 16:00,eradication,Malware eliminado de todos los hosts afectados,analyst_tier3,Limpieza con CrowdStrike RTR
2024-03-15 18:00,recovery,Sistemas restaurados y en monitoreo,analyst_msmith,Período de monitoreo de 72 horas iniciado
```

### Paso 5: Construir el Dashboard de Operaciones del SOC

Rastrear las métricas generales de rendimiento del SOC:

```spl
--- Volumen de incidentes por severidad (últimos 30 días)
index=notable earliest=-30d
| stats count by urgency
| eval order = case(urgency="critical", 1, urgency="high", 2, urgency="medium", 3,
                    urgency="low", 4, urgency="informational", 5)
| sort order

--- MTTD (Tiempo Medio de Detección)
index=notable earliest=-30d status_label="Resolved*"
| eval mttd_minutes = round((time_of_first_event - orig_time) / 60, 1)
| stats avg(mttd_minutes) AS avg_mttd, median(mttd_minutes) AS med_mttd,
        perc95(mttd_minutes) AS p95_mttd

--- MTTR (Tiempo Medio de Respuesta/Resolución)
index=notable earliest=-30d status_label="Resolved*"
| eval mttr_hours = round((status_end - _time) / 3600, 1)
| stats avg(mttr_hours) AS avg_mttr, median(mttr_hours) AS med_mttr by urgency

--- Distribución de carga de trabajo por analista
index=notable earliest=-7d
| stats count by owner
| sort - count

--- Desglose de disposición de alertas
index=notable earliest=-30d status_label IN ("Resolved*", "Closed*")
| stats count by disposition
| eval percentage = round(count / sum(count) * 100, 1)
| sort - count
```

### Paso 6: Construir el Dashboard de Sesión Informativa Ejecutiva

Crear un dashboard de alto nivel para la dirección durante incidentes mayores:

```spl
--- Panel de resumen ejecutivo
| makeresults
| eval metrics = "Impacto de Negocio: 1 servidor de archivos fuera de línea (depto. Finanzas), "
                ."Recuperación Estimada: 4 horas, "
                ."Riesgo de Pérdida de Datos: Bajo (respaldos verificados), "
                ."Impacto al Cliente: Ninguno, "
                ."Notificación Regulatoria: No requerida (sin exposición de PII confirmada)"

--- Comparación de tendencias (mes actual vs mes anterior)
index=notable earliest=-60d
| eval period = if(_time > relative_time(now(), "-30d"), "Mes Actual", "Mes Anterior")
| stats count by period, urgency
| chart sum(count) AS incidents by period, urgency

--- Principales categorías de amenazas
index=notable earliest=-30d
| top rule_name limit=10
| table rule_name, count, percent
```

### Paso 7: Automatizar las Actualizaciones del Dashboard

Usar búsquedas programadas de Splunk para mantener los datos del dashboard:

```spl
--- Búsqueda programada para actualizar la tabla de sistemas afectados (se ejecuta cada 5 minutos)
index=* (src_ip IN [| inputlookup ir_ioc_list.csv | search ioc_type="ip"
                    | fields ioc_value | rename ioc_value AS src_ip])
earliest=-1h
| stats latest(_time) AS last_seen, count AS event_count,
        values(sourcetype) AS data_sources by src_ip
| eval status = if(last_seen > relative_time(now(), "-15m"), "Activo", "Inactivo")
| outputlookup ir_affected_systems_auto.csv
```

## Conceptos Clave

| Término | Definición |
|---------|-----------|
| **Conciencia Situacional** | Comprensión en tiempo real del alcance del incidente, sistemas afectados y progreso de la respuesta |
| **MTTD** | Tiempo Medio de Detección — tiempo promedio desde la ocurrencia de la amenaza hasta la generación de la alerta del SOC |
| **MTTR** | Tiempo Medio de Respuesta — tiempo promedio desde la alerta hasta la resolución o contención del incidente |
| **Tasa de Contención** | Porcentaje de sistemas afectados aislados exitosamente en relación con el total de sistemas comprometidos |
| **Gráfico de Quema** | Seguimiento visual de las tareas de investigación abiertas restantes a lo largo del tiempo durante un incidente |
| **Sesión Informativa Ejecutiva** | Dashboard de resumen no técnico que muestra el impacto en el negocio, la línea de tiempo y el estado de recuperación |

## Herramientas y Sistemas

- **Splunk Dashboard Studio**: Framework moderno de dashboards con visualización de arrastrar y soltar y datos en tiempo real
- **Elastic Kibana Dashboard**: Plataforma de visualización con Lens, Maps y Canvas para dashboards de seguridad
- **Grafana**: Plataforma de visualización de código abierto que soporta múltiples fuentes de datos incluyendo Elasticsearch y Splunk
- **Microsoft Sentinel Workbooks**: Framework de dashboards nativo de Azure con visualización de analíticas basadas en Kusto
- **TheHive**: Plataforma de respuesta a incidentes de código abierto con seguimiento de casos integrado y dashboards de métricas

## Escenarios Comunes

- **Incidente de Ransomware Activo**: Dashboard que muestra la propagación del cifrado, estado de contención, verificación de respaldos, progreso de recuperación
- **Investigación de Brecha de Datos**: Dashboard que rastrea almacenes de datos afectados, volumen de exfiltración, requisitos de notificación
- **Respuesta a Campaña de Phishing**: Dashboard que muestra el conteo de destinatarios, tasa de clics, exposición de credenciales, estado de remediación
- **Informe Mensual del SOC**: Dashboard para la dirección con tendencias de incidentes, métricas MTTD/MTTR, rendimiento de analistas
- **Auditoría de Cumplimiento**: Dashboard que demuestra cobertura de detección, cumplimiento de SLA de respuesta y métricas de cierre de incidentes

## Formato de Salida

```text
DASHBOARD DE RESPUESTA A INCIDENTES — IR-2024-0450
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ESTADO: FASE DE CONTENCIÓN (6h 30m transcurridas)

Sistemas Afectados:         Progreso de Contención:
  Comprometidos:   2        [==========----------] 71%
  En Investigación: 1       5 de 7 sistemas contenidos
  Contenidos:      3
  Recuperados:     1

Resumen de IOCs:            Línea de Tiempo de Respuesta:
  IPs:      4               14:00 — Alerta activada
  Dominios: 2               14:12 — Confirmado como malicioso
  Hashes:   3               14:23 — Primer host aislado
  URLs:     5               15:00 — Escaneo empresarial iniciado
  Correos:  1               15:30 — 3 hosts más aislados

Métricas Clave:
  MTTD:    12 minutos
  MTTC:    23 minutos (primer host)
  Analistas Activos: 3 (Nivel 2: 2, Nivel 3: 1)

Impacto de Negocio: BAJO — Servidor de archivos de Finanzas fuera de línea, sin afectación a sistemas orientados al cliente
```
