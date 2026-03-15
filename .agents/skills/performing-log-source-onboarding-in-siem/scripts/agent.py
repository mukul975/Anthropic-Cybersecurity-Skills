#!/usr/bin/env python3
"""Agent for performing log source onboarding in SIEM platforms."""

import json
import argparse
import socket
import re
from datetime import datetime
from pathlib import Path


SYSLOG_FACILITIES = {0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
                     6: "lpr", 7: "news", 10: "authpriv", 13: "audit", 16: "local0",
                     17: "local1", 18: "local2", 19: "local3", 20: "local4",
                     21: "local5", 22: "local6", 23: "local7"}

LOG_FORMAT_PATTERNS = {
    "syslog_rfc3164": re.compile(r"^<\d+>\w{3}\s+\d+\s+\d+:\d+:\d+"),
    "syslog_rfc5424": re.compile(r"^<\d+>\d+\s+\d{4}-\d{2}-\d{2}T"),
    "cef": re.compile(r"^CEF:\d+\|"),
    "leef": re.compile(r"^LEEF:\d+\.\d+\|"),
    "json": re.compile(r"^\s*\{"),
    "csv": re.compile(r"^[^,]+,[^,]+,[^,]+"),
    "windows_event": re.compile(r"EventID|EventRecordID"),
    "apache_combined": re.compile(r'^\S+ \S+ \S+ \[.+\] "\w+ .+ HTTP/'),
}


def detect_log_format(sample_file):
    """Detect log format from a sample file."""
    content = Path(sample_file).read_text(encoding="utf-8", errors="replace")
    lines = [l for l in content.splitlines() if l.strip()][:50]
    format_votes = {}
    for line in lines:
        for fmt, pattern in LOG_FORMAT_PATTERNS.items():
            if pattern.search(line):
                format_votes[fmt] = format_votes.get(fmt, 0) + 1
    if not format_votes:
        return {"format": "unknown", "sample_lines": lines[:5]}
    detected = max(format_votes, key=format_votes.get)
    return {
        "sample_file": sample_file,
        "detected_format": detected,
        "confidence": round(format_votes[detected] / len(lines) * 100, 1),
        "format_votes": format_votes,
        "total_lines": len(lines),
        "sample_lines": lines[:5],
    }


def validate_syslog_connectivity(host, port=514, protocol="udp"):
    """Test syslog connectivity to SIEM collector."""
    results = {"host": host, "port": port, "protocol": protocol}
    try:
        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            test_msg = f"<14>1 {datetime.utcnow().isoformat()} test-agent siem-onboard - - - Test syslog connectivity"
            sock.sendto(test_msg.encode(), (host, port))
            results["status"] = "SENT"
            results["message"] = "UDP message sent (delivery not guaranteed)"
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            test_msg = f"<14>1 {datetime.utcnow().isoformat()} test-agent siem-onboard - - - Test syslog connectivity\n"
            sock.send(test_msg.encode())
            results["status"] = "CONNECTED"
            results["message"] = "TCP connection established and test message sent"
        sock.close()
    except Exception as e:
        results["status"] = "FAILED"
        results["error"] = str(e)
    return results


def generate_parsing_config(log_format, source_type, fields=None):
    """Generate SIEM parsing configuration for common log formats."""
    configs = {
        "syslog_rfc3164": {
            "splunk": {
                "props_conf": f"[{source_type}]\nTIME_FORMAT = %b %d %H:%M:%S\nTIME_PREFIX = ^<\\d+>\nSHOULD_LINEMERGE = false\nLINE_BREAKER = ([\\r\\n]+)",
                "transforms_conf": f"[{source_type}_extract]\nREGEX = ^<(\\d+)>(\\w{{3}}\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(\\S+)\\s+(\\S+?)(?:\\[(\\d+)\\])?:\\s+(.*)\nFORMAT = priority::$1 timestamp::$2 host::$3 program::$4 pid::$5 message::$6",
            },
            "elastic": {
                "filebeat_module": {"module": "system", "syslog": {"enabled": True, "var.paths": ["/var/log/syslog"]}},
            },
        },
        "json": {
            "splunk": {
                "props_conf": f"[{source_type}]\nKV_MODE = json\nSHOULD_LINEMERGE = false\nTIME_FORMAT = %Y-%m-%dT%H:%M:%S",
            },
            "elastic": {
                "filebeat_input": {"type": "filestream", "parsers": [{"ndjson": {"keys_under_root": True, "add_error_key": True}}]},
            },
        },
        "cef": {
            "splunk": {
                "props_conf": f"[{source_type}]\nSHOULD_LINEMERGE = false\nTIME_FORMAT = %b %d %Y %H:%M:%S\nTRANSFORMS-cef = cef_header,cef_extension",
            },
            "elastic": {
                "logstash_filter": 'filter { if [type] == "cef" { grok { match => { "message" => "CEF:%{INT:cef_version}\\|%{DATA:vendor}\\|%{DATA:product}\\|%{DATA:version}\\|%{DATA:signature}\\|%{DATA:name}\\|%{INT:severity}\\|%{GREEDYDATA:extension}" } } } }',
            },
        },
    }
    config = configs.get(log_format, {})
    return {
        "log_format": log_format,
        "source_type": source_type,
        "configurations": config if config else {"note": f"No template for format: {log_format}"},
    }


def create_onboarding_checklist(source_name, log_format, siem_host, siem_port=514):
    """Generate a log source onboarding checklist."""
    return {
        "source_name": source_name,
        "log_format": log_format,
        "timestamp": datetime.utcnow().isoformat(),
        "checklist": [
            {"step": 1, "task": "Collect log samples (minimum 100 lines)", "status": "pending"},
            {"step": 2, "task": f"Validate format: {log_format}", "status": "pending"},
            {"step": 3, "task": f"Test connectivity to {siem_host}:{siem_port}", "status": "pending"},
            {"step": 4, "task": "Create source type / index configuration", "status": "pending"},
            {"step": 5, "task": "Configure field extraction / parsing rules", "status": "pending"},
            {"step": 6, "task": "Verify timestamp parsing and timezone", "status": "pending"},
            {"step": 7, "task": "Validate event flow (check event count)", "status": "pending"},
            {"step": 8, "task": "Create correlation rules / alerts", "status": "pending"},
            {"step": 9, "task": "Document source in CMDB", "status": "pending"},
            {"step": 10, "task": "Monitor for 48h and verify parsing accuracy", "status": "pending"},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="SIEM Log Source Onboarding Agent")
    sub = parser.add_subparsers(dest="command")
    d = sub.add_parser("detect", help="Detect log format")
    d.add_argument("--file", required=True)
    v = sub.add_parser("validate", help="Test syslog connectivity")
    v.add_argument("--host", required=True)
    v.add_argument("--port", type=int, default=514)
    v.add_argument("--protocol", default="udp", choices=["udp", "tcp"])
    p = sub.add_parser("parse-config", help="Generate parsing config")
    p.add_argument("--format", required=True, choices=list(LOG_FORMAT_PATTERNS.keys()))
    p.add_argument("--source-type", required=True)
    c = sub.add_parser("checklist", help="Generate onboarding checklist")
    c.add_argument("--source", required=True)
    c.add_argument("--format", required=True)
    c.add_argument("--siem-host", required=True)
    c.add_argument("--siem-port", type=int, default=514)
    args = parser.parse_args()
    if args.command == "detect":
        result = detect_log_format(args.file)
    elif args.command == "validate":
        result = validate_syslog_connectivity(args.host, args.port, args.protocol)
    elif args.command == "parse-config":
        result = generate_parsing_config(args.format, args.source_type)
    elif args.command == "checklist":
        result = create_onboarding_checklist(args.source, args.format, args.siem_host, args.siem_port)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
