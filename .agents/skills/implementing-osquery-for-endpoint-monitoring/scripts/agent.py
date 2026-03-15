#!/usr/bin/env python3
"""Osquery Endpoint Monitoring Agent - Generates configs, deploys queries, and analyzes results."""

import json
import os
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SECURITY_QUERIES = {
    "process_not_on_disk": {
        "query": "SELECT pid, name, path, cmdline, uid FROM processes WHERE on_disk = 0;",
        "interval": 300,
        "description": "Detect processes running from deleted binaries",
    },
    "listening_ports": {
        "query": (
            "SELECT lp.pid, lp.port, lp.protocol, lp.address, p.name, p.path "
            "FROM listening_ports lp JOIN processes p ON lp.pid = p.pid "
            "WHERE lp.port NOT IN (22, 80, 443, 3306, 5432);"
        ),
        "interval": 600,
        "description": "Monitor unexpected listening ports",
    },
    "outbound_connections": {
        "query": (
            "SELECT pid, remote_address, remote_port, local_port, p.name, p.path "
            "FROM process_open_sockets pos JOIN processes p ON pos.pid = p.pid "
            "WHERE remote_address NOT IN ('0.0.0.0', '127.0.0.1', '::1', '') "
            "AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%';"
        ),
        "interval": 300,
        "description": "Monitor external outbound connections",
    },
    "cron_persistence": {
        "query": "SELECT * FROM crontab WHERE command NOT LIKE '%logrotate%' AND command NOT LIKE '%anacron%';",
        "interval": 3600,
        "description": "Detect new cron job persistence",
    },
    "suid_binaries": {
        "query": "SELECT path, mode, uid, gid FROM suid_bin WHERE path NOT LIKE '/usr/%' AND path NOT LIKE '/bin/%';",
        "interval": 3600,
        "description": "Detect SUID binaries outside standard paths",
    },
    "file_integrity_etc": {
        "query": (
            "SELECT path, mtime, size, sha256 FROM file "
            "WHERE path LIKE '/etc/%%' AND mtime > (SELECT CAST(strftime('%s', 'now', '-1 hour') AS INTEGER));"
        ),
        "interval": 600,
        "description": "Monitor file changes in /etc",
    },
    "kernel_modules": {
        "query": "SELECT name, size, status, address FROM kernel_modules WHERE status = 'Live';",
        "interval": 3600,
        "description": "Monitor loaded kernel modules",
    },
    "authorized_keys": {
        "query": "SELECT uid, algorithm, key, key_file FROM authorized_keys;",
        "interval": 3600,
        "description": "Monitor SSH authorized keys",
    },
    "startup_items": {
        "query": "SELECT name, path, source, status, username FROM startup_items;",
        "interval": 3600,
        "description": "Monitor startup/login items",
    },
    "shell_history": {
        "query": "SELECT uid, command, history_file FROM shell_history WHERE command LIKE '%curl%pipe%sh%' OR command LIKE '%wget%';",
        "interval": 1800,
        "description": "Detect suspicious shell history entries",
    },
}


def generate_osquery_config(queries, log_dir="/var/log/osquery"):
    """Generate osquery.conf with security monitoring queries."""
    config = {
        "options": {
            "logger_plugin": "filesystem",
            "logger_path": log_dir,
            "disable_logging": "false",
            "schedule_splay_percent": "10",
            "events_expiry": "3600",
            "database_path": "/var/osquery/osquery.db",
            "verbose": "false",
            "worker_threads": "2",
            "enable_monitor": "true",
        },
        "schedule": {},
        "file_paths": {
            "etc": ["/etc/%%"],
            "binaries": ["/usr/bin/%%", "/usr/sbin/%%", "/bin/%%", "/sbin/%%"],
            "tmp": ["/tmp/%%"],
        },
    }
    for name, query_def in queries.items():
        config["schedule"][name] = {
            "query": query_def["query"],
            "interval": query_def["interval"],
            "description": query_def["description"],
        }
    logger.info("Generated osquery config with %d scheduled queries", len(queries))
    return config


def parse_osquery_results(results_dir):
    """Parse osquery differential result logs from the results directory."""
    all_results = []
    for filename in sorted(os.listdir(results_dir)):
        if not filename.endswith(".log"):
            continue
        filepath = os.path.join(results_dir, filename)
        with open(filepath, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    all_results.append(entry)
                except json.JSONDecodeError:
                    continue
    logger.info("Parsed %d result entries from %s", len(all_results), results_dir)
    return all_results


def analyze_results(results):
    """Analyze osquery results for security findings."""
    findings = []
    for entry in results:
        name = entry.get("name", "")
        action = entry.get("action", "")
        columns = entry.get("columns", {})
        if name == "process_not_on_disk" and action == "added":
            findings.append({
                "type": "Process without binary",
                "severity": "critical",
                "details": columns,
                "query": name,
            })
        elif name == "listening_ports" and action == "added":
            port = int(columns.get("port", 0))
            if port > 1024:
                findings.append({
                    "type": "New listening port",
                    "severity": "high",
                    "details": columns,
                    "query": name,
                })
        elif name == "cron_persistence" and action == "added":
            findings.append({
                "type": "New cron job",
                "severity": "high",
                "details": columns,
                "query": name,
            })
        elif name == "suid_binaries" and action == "added":
            findings.append({
                "type": "New SUID binary",
                "severity": "critical",
                "details": columns,
                "query": name,
            })
        elif name == "authorized_keys" and action == "added":
            findings.append({
                "type": "New SSH authorized key",
                "severity": "high",
                "details": columns,
                "query": name,
            })
    logger.info("Analysis: %d security findings from %d results", len(findings), len(results))
    return findings


def generate_report(config, results, findings):
    """Generate osquery monitoring report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "scheduled_queries": len(config.get("schedule", {})),
        "total_results_parsed": len(results),
        "security_findings": len(findings),
        "critical_findings": len([f for f in findings if f["severity"] == "critical"]),
        "findings": findings[:50],
    }
    print(f"OSQUERY REPORT: {len(findings)} findings ({report['critical_findings']} critical)")
    return report


def main():
    parser = argparse.ArgumentParser(description="Osquery Endpoint Monitoring Agent")
    parser.add_argument("--generate-config", help="Output path for osquery.conf")
    parser.add_argument("--results-dir", help="Osquery results log directory")
    parser.add_argument("--output", default="osquery_report.json")
    args = parser.parse_args()

    config = generate_osquery_config(SECURITY_QUERIES)

    if args.generate_config:
        with open(args.generate_config, "w") as f:
            json.dump(config, f, indent=2)
        logger.info("Config saved to %s", args.generate_config)

    results = []
    findings = []
    if args.results_dir and os.path.isdir(args.results_dir):
        results = parse_osquery_results(args.results_dir)
        findings = analyze_results(results)

    report = generate_report(config, results, findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
