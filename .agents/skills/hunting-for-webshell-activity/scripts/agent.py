#!/usr/bin/env python3
"""Agent for hunting web shell activity on web servers via process tree and log analysis."""

import json
import argparse
import re
from datetime import datetime
from collections import defaultdict
from pathlib import Path


WEB_SERVER_PROCESSES = [
    "w3wp.exe", "httpd", "apache2", "nginx", "tomcat", "java",
    "php-cgi", "php-fpm", "node", "iisexpress",
]

SHELL_SPAWNS = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh",
    "wscript.exe", "cscript.exe", "certutil.exe", "whoami.exe",
    "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe",
    "tasklist.exe", "nslookup.exe",
]

WEBSHELL_HTTP_PATTERNS = [
    r"POST\s+.*\.(asp|aspx|php|jsp|jspx)\s+",
    r"cmd=", r"exec=", r"command=", r"shell=",
    r"c99shell", r"r57shell", r"b374k", r"weevely",
    r"china\s*chopper", r"antsword",
]


def load_process_logs(log_path):
    """Load process creation logs (JSON lines)."""
    entries = []
    with open(log_path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def detect_webserver_child_shells(process_logs):
    """Detect shell processes spawned by web server processes."""
    findings = []
    for entry in process_logs:
        parent = entry.get("ParentImage", entry.get("parent_process", "")).lower()
        child = entry.get("Image", entry.get("process_name", "")).lower()
        is_web_parent = any(ws in parent for ws in WEB_SERVER_PROCESSES)
        is_shell_child = any(sh in child for sh in SHELL_SPAWNS)
        if is_web_parent and is_shell_child:
            cmd = entry.get("CommandLine", entry.get("command_line", ""))
            findings.append({
                "timestamp": entry.get("UtcTime", entry.get("timestamp", "")),
                "hostname": entry.get("Computer", entry.get("hostname", "")),
                "parent_process": parent,
                "child_process": child,
                "command_line": cmd[:500],
                "user": entry.get("User", ""),
                "severity": "CRITICAL",
                "technique": "T1505.003",
            })
    return findings


def analyze_web_access_logs(access_log_path):
    """Analyze web access logs for webshell indicators."""
    findings = []
    with open(access_log_path) as f:
        for i, line in enumerate(f, 1):
            for pattern in WEBSHELL_HTTP_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    ip_match = re.match(r"^(\S+)", line)
                    findings.append({
                        "line_number": i,
                        "source_ip": ip_match.group(1) if ip_match else "",
                        "log_entry": line.strip()[:500],
                        "pattern_matched": pattern,
                        "severity": "HIGH",
                    })
                    break
    return findings


def detect_file_creation_in_webroot(file_events, webroot_paths=None):
    """Detect new script files created in web server directories."""
    if webroot_paths is None:
        webroot_paths = [
            "/var/www", "/opt/lampp/htdocs", "inetpub/wwwroot",
            "/usr/share/nginx/html", "/srv/www",
        ]
    script_extensions = [".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi", ".cfm"]
    findings = []
    for event in file_events:
        filepath = event.get("TargetFilename", event.get("file_path", "")).lower()
        in_webroot = any(wr in filepath for wr in webroot_paths)
        is_script = any(filepath.endswith(ext) for ext in script_extensions)
        if in_webroot and is_script:
            findings.append({
                "timestamp": event.get("UtcTime", event.get("timestamp", "")),
                "file_path": filepath,
                "process": event.get("Image", event.get("process_name", "")),
                "hostname": event.get("Computer", event.get("hostname", "")),
                "severity": "CRITICAL",
                "reason": "script_created_in_webroot",
            })
    return findings


def detect_post_exploitation(process_logs):
    """Detect reconnaissance commands typically run through webshells."""
    recon_patterns = [
        (r"whoami", "user_discovery"),
        (r"ipconfig|ifconfig", "network_config"),
        (r"net\s+(user|group|localgroup)", "account_enum"),
        (r"systeminfo", "system_info"),
        (r"tasklist|ps\s+aux", "process_enum"),
        (r"netstat\s+-an", "connection_enum"),
        (r"dir\s+/s|find\s+/|ls\s+-la", "file_enum"),
    ]
    findings = []
    for entry in process_logs:
        parent = entry.get("ParentImage", entry.get("parent_process", "")).lower()
        if not any(ws in parent for ws in WEB_SERVER_PROCESSES):
            continue
        cmd = entry.get("CommandLine", entry.get("command_line", ""))
        for pattern, category in recon_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append({
                    "timestamp": entry.get("UtcTime", entry.get("timestamp", "")),
                    "command": cmd[:300],
                    "category": category,
                    "parent": parent,
                    "severity": "HIGH",
                })
                break
    return findings


def main():
    parser = argparse.ArgumentParser(description="Webshell Activity Hunter")
    parser.add_argument("--process-log", help="JSON lines process creation log")
    parser.add_argument("--access-log", help="Web server access log")
    parser.add_argument("--file-events", help="JSON lines file creation events")
    parser.add_argument("--output", default="webshell_hunt_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.process_log:
        logs = load_process_logs(args.process_log)
        shells = detect_webserver_child_shells(logs)
        report["findings"]["shell_spawns"] = shells
        print(f"[+] Web server shell spawns: {len(shells)}")
        recon = detect_post_exploitation(logs)
        report["findings"]["post_exploitation"] = recon
        print(f"[+] Post-exploitation commands: {len(recon)}")

    if args.access_log:
        hits = analyze_web_access_logs(args.access_log)
        report["findings"]["access_log_hits"] = hits
        print(f"[+] Access log webshell indicators: {len(hits)}")

    if args.file_events:
        events = load_process_logs(args.file_events)
        files = detect_file_creation_in_webroot(events)
        report["findings"]["webroot_files"] = files
        print(f"[+] Scripts created in webroot: {len(files)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
