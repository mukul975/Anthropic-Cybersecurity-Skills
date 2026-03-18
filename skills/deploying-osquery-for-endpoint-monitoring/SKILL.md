---
name: deploying-osquery-for-endpoint-monitoring
description: >
  Deploys and configures osquery for real-time endpoint monitoring using SQL-based queries to
  inspect running processes, open ports, installed software, and system configuration. Use when
  building visibility into endpoint state, threat hunting across fleet, or implementing
  compliance monitoring. Activates for requests involving osquery deployment, endpoint visibility,
  fleet management, or SQL-based endpoint querying.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, osquery, endpoint-monitoring, threat-hunting, fleet-management]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Deploying Osquery for Endpoint Monitoring

## When to Use

Use this skill when:
- Deploying osquery across Windows, macOS, and Linux endpoints for fleet-wide visibility
- Building threat hunting queries using osquery's SQL interface
- Monitoring endpoint compliance (installed software, open ports, running services)
- Integrating osquery data with SIEM or Kolide/Fleet for centralized management

**Do not use** for real-time alerting (osquery is periodic/on-demand; use EDR for real-time).

## Prerequisites

- Osquery package for target OS (https://osquery.io/downloads)
- Fleet management server (Kolide Fleet or FleetDM) for enterprise deployment
- TLS certificates for secure agent-to-server communication
- Log aggregation pipeline (Filebeat, Fluentd) for osquery result logs

## Workflow

### Step 1: Install Osquery

```bash
# Ubuntu/Debian
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
apt-get update && apt-get install osquery -y

# Windows (MSI)
# Download from https://osquery.io/downloads/official
msiexec /i osquery-5.12.1.msi /quiet

# macOS
brew install osquery
```

### Step 2: Configure Osquery

```json
// /etc/osquery/osquery.conf (Linux/macOS) or C:\ProgramData\osquery\osquery.conf
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "events_expiry": "3600",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true",
    "disable_events": "false",
    "disable_audit": "false",
    "audit_allow_config": "true",
    "host_identifier": "hostname",
    "enable_syslog": "true"
  },
  "schedule": {
    "process_monitor": {
      "query": "SELECT pid, name, path, cmdline, uid, parent FROM processes WHERE on_disk = 0;",
      "interval": 300,
      "description": "Detect processes running without on-disk binary (fileless)"
    },
    "listening_ports": {
      "query": "SELECT DISTINCT p.name, p.path, lp.port, lp.protocol, lp.address FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port != 0;",
      "interval": 600,
      "description": "Monitor listening network ports"
    },
    "persistence_check": {
      "query": "SELECT name, path, source FROM startup_items;",
      "interval": 3600,
      "description": "Monitor persistence mechanisms"
    },
    "installed_packages": {
      "query": "SELECT name, version, source FROM deb_packages;",
      "interval": 86400,
      "description": "Daily software inventory"
    },
    "users_and_groups": {
      "query": "SELECT u.username, u.uid, u.gid, u.shell, u.directory FROM users u WHERE u.uid >= 1000;",
      "interval": 3600
    },
    "crontab_monitor": {
      "query": "SELECT * FROM crontab;",
      "interval": 3600,
      "description": "Monitor scheduled tasks"
    },
    "suid_binaries": {
      "query": "SELECT path, username, permissions FROM suid_bin;",
      "interval": 86400,
      "description": "Detect SUID binaries"
    }
  },
  "packs": {
    "incident-response": "/usr/share/osquery/packs/incident-response.conf",
    "ossec-rootkit": "/usr/share/osquery/packs/ossec-rootkit.conf",
    "vuln-management": "/usr/share/osquery/packs/vuln-management.conf"
  }
}
```

### Step 3: Threat Hunting Queries

```sql
-- Detect processes with no on-disk binary (potential fileless malware)
SELECT pid, name, path, cmdline FROM processes WHERE on_disk = 0;

-- Find listening ports not associated with known services
SELECT lp.port, lp.protocol, p.name, p.path
FROM listening_ports lp JOIN processes p ON lp.pid = p.pid
WHERE lp.port NOT IN (22, 80, 443, 3306, 5432);

-- Detect unauthorized SSH keys
SELECT * FROM authorized_keys WHERE NOT key LIKE '%admin-team%';

-- Find recently modified system binaries
SELECT path, mtime, size FROM file
WHERE path LIKE '/usr/bin/%' AND mtime > (strftime('%s', 'now') - 86400);

-- Detect processes connecting to external IPs
SELECT DISTINCT p.name, p.path, pn.remote_address, pn.remote_port
FROM process_open_sockets pn JOIN processes p ON pn.pid = p.pid
WHERE pn.remote_address NOT LIKE '10.%'
  AND pn.remote_address NOT LIKE '172.16.%'
  AND pn.remote_address NOT LIKE '192.168.%'
  AND pn.remote_address != '127.0.0.1'
  AND pn.remote_address != '0.0.0.0';

-- Windows: Detect unsigned running executables
SELECT p.name, p.path, a.result AS signature_status
FROM processes p JOIN authenticode a ON p.path = a.path
WHERE a.result != 'trusted';
```

### Step 4: Deploy FleetDM for Centralized Management

```bash
# FleetDM provides centralized osquery management
# Deploy FleetDM server, configure agents to report to it
# Agents use TLS enrollment and config from Fleet

# Agent configuration for Fleet:
# --tls_hostname=fleet.corp.com
# --tls_server_certs=/etc/osquery/fleet.pem
# --enroll_secret_path=/etc/osquery/enroll_secret
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Osquery** | Open-source endpoint agent that exposes OS state as SQL tables for querying |
| **Schedule** | Periodic queries that run at defined intervals and log results |
| **Pack** | Collection of related queries grouped for specific use cases (IR, compliance) |
| **FleetDM** | Open-source osquery fleet management platform |
| **Differential Results** | Osquery logs only changes between query executions, reducing data volume |

## Tools & Systems

- **Osquery**: https://osquery.io/ - endpoint visibility agent
- **FleetDM**: https://fleetdm.com/ - centralized fleet management
- **Kolide**: Cloud-based osquery management with Slack integration
- **osquery-go**: Go client library for osquery extensions

## Common Pitfalls

- **Query performance**: Complex queries with large table scans impact endpoint performance. Use WHERE clauses and test query cost with `EXPLAIN`.
- **Schedule intervals too aggressive**: Running heavy queries every 60 seconds causes CPU spikes. Use 300-3600 second intervals for most queries.
- **Not using differential mode**: Without differential logging, osquery logs all results every interval. Differential mode logs only changes.
- **Missing event tables**: Some osquery tables require events framework enabled (process_events, socket_events). Enable with `--disable_events=false`.
