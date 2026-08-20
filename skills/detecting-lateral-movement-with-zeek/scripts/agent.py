#!/usr/bin/env python3
"""Zeek lateral movement detection agent.

Parses Zeek conn.log, smb_mapping.log, smb_files.log, dce_rpc.log,
ntlm.log, and kerberos.log to detect lateral movement indicators:
admin share access, PsExec-style service creation, Pass-the-Hash,
and anomalous internal host-to-host connections.
"""

import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# Zeek TSV log field definitions per log type
CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
]

SMB_MAPPING_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "path", "service", "native_file_system", "share_type",
]

SMB_FILES_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "fuid", "action", "path", "name", "size", "prev_name", "times.modified",
    "times.accessed", "times.created", "times.changed",
]

DCE_RPC_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "rtt", "named_pipe", "endpoint", "operation",
]

NTLM_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "username", "hostname", "domainname", "server_nb_computer_name",
    "server_dns_computer_name", "server_tree_name", "success",
]

KERBEROS_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "request_type", "client", "service", "success", "error_msg",
    "from", "till", "cipher", "forwardable", "renewable", "client_cert_subject",
    "client_cert_fuid", "server_cert_subject", "server_cert_fuid",
]

# Internal RFC1918 ranges
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")

# Lateral movement ports
LATERAL_PORTS = {
    "445": "SMB",
    "135": "DCE/RPC",
    "139": "NetBIOS-SSN",
    "3389": "RDP",
    "5985": "WinRM-HTTP",
    "5986": "WinRM-HTTPS",
    "22": "SSH",
    "23": "Telnet",
}

# Admin shares indicating lateral movement
ADMIN_SHARES = re.compile(r"(C\$|ADMIN\$|IPC\$|D\$|E\$)", re.IGNORECASE)

# DCE/RPC endpoints associated with remote execution
SUSPICIOUS_ENDPOINTS = {
    "svcctl": "Service Control Manager (PsExec pattern)",
    "atsvc": "AT Scheduler Service (at.exe / schtasks)",
    "ITaskSchedulerService": "Task Scheduler (schtasks v2)",
    "winreg": "Remote Registry",
    "samr": "SAM Remote Protocol (user enumeration)",
    "lsarpc": "LSA Remote Protocol (policy enumeration)",
    "wkssvc": "Workstation Service (NetWkstaUserEnum)",
    "srvsvc": "Server Service (NetShareEnum/NetSessionEnum)",
    "epmapper": "Endpoint Mapper (RPC enumeration)",
}


def is_internal(ip):
    """Check if an IP address is in RFC1918 private ranges."""
    return any(ip.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def parse_zeek_tsv(filepath, field_names):
    """Parse a Zeek TSV log file, skipping comment/header lines."""
    records = []
    if not os.path.exists(filepath):
        return records
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#") or not line:
                continue
            parts = line.split("\t")
            record = {}
            for i, field in enumerate(field_names):
                record[field] = parts[i] if i < len(parts) else "-"
            records.append(record)
    return records


def parse_zeek_json(filepath):
    """Parse a Zeek JSON log file (one JSON object per line)."""
    records = []
    if not os.path.exists(filepath):
        return records
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def parse_zeek_log(filepath, field_names):
    """Auto-detect Zeek log format (TSV or JSON) and parse accordingly."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", errors="replace") as f:
        first_line = ""
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                first_line = line
                break
    if first_line.startswith("{"):
        return parse_zeek_json(filepath)
    return parse_zeek_tsv(filepath, field_names)


def ts_to_iso(ts_str):
    """Convert Zeek epoch timestamp string to ISO 8601."""
    try:
        epoch = float(ts_str)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, TypeError, OSError):
        return ts_str


def analyze_conn_log(log_dir):
    """Analyze conn.log for internal lateral movement connections."""
    records = parse_zeek_log(os.path.join(log_dir, "conn.log"), CONN_FIELDS)
    findings = []
    host_pair_counts = defaultdict(int)
    host_pair_bytes = defaultdict(int)

    for rec in records:
        orig = rec.get("id.orig_h", "")
        resp = rec.get("id.resp_h", "")
        resp_p = rec.get("id.resp_p", "")
        service = rec.get("service", "-")

        if not (is_internal(orig) and is_internal(resp)):
            continue
        if orig == resp:
            continue

        pair_key = f"{orig}->{resp}:{resp_p}"
        host_pair_counts[pair_key] += 1

        orig_bytes = rec.get("orig_bytes", "0")
        resp_bytes = rec.get("resp_bytes", "0")
        try:
            total = int(orig_bytes) + int(resp_bytes)
        except ValueError:
            total = 0
        host_pair_bytes[pair_key] += total

        if resp_p in LATERAL_PORTS:
            findings.append({
                "type": "lateral_port_connection",
                "timestamp": ts_to_iso(rec.get("ts", "")),
                "src": orig,
                "dst": resp,
                "port": resp_p,
                "service_label": LATERAL_PORTS[resp_p],
                "zeek_service": service,
                "uid": rec.get("uid", ""),
            })

    return findings, host_pair_counts, host_pair_bytes


def analyze_smb_mapping(log_dir):
    """Analyze smb_mapping.log for admin share access."""
    records = parse_zeek_log(
        os.path.join(log_dir, "smb_mapping.log"), SMB_MAPPING_FIELDS
    )
    findings = []
    for rec in records:
        path = rec.get("path", "")
        if ADMIN_SHARES.search(path):
            findings.append({
                "type": "admin_share_access",
                "severity": "HIGH",
                "timestamp": ts_to_iso(rec.get("ts", "")),
                "src": rec.get("id.orig_h", ""),
                "dst": rec.get("id.resp_h", ""),
                "share_path": path,
                "share_type": rec.get("share_type", ""),
                "uid": rec.get("uid", ""),
            })
    return findings


def analyze_smb_files(log_dir):
    """Analyze smb_files.log for file writes to network shares."""
    records = parse_zeek_log(
        os.path.join(log_dir, "smb_files.log"), SMB_FILES_FIELDS
    )
    findings = []
    suspicious_extensions = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr",
                             ".cmd", ".msi", ".hta", ".sys")
    for rec in records:
        action = rec.get("action", "")
        name = rec.get("name", "")
        if "WRITE" in action.upper():
            severity = "MEDIUM"
            if any(name.lower().endswith(ext) for ext in suspicious_extensions):
                severity = "CRITICAL"
            findings.append({
                "type": "smb_file_write",
                "severity": severity,
                "timestamp": ts_to_iso(rec.get("ts", "")),
                "src": rec.get("id.orig_h", ""),
                "dst": rec.get("id.resp_h", ""),
                "action": action,
                "path": rec.get("path", ""),
                "filename": name,
                "size": rec.get("size", "-"),
                "uid": rec.get("uid", ""),
            })
    return findings


def analyze_dce_rpc(log_dir):
    """Analyze dce_rpc.log for remote execution operations."""
    records = parse_zeek_log(
        os.path.join(log_dir, "dce_rpc.log"), DCE_RPC_FIELDS
    )
    findings = []
    for rec in records:
        endpoint = rec.get("endpoint", "").lower()
        operation = rec.get("operation", "")
        for sus_ep, description in SUSPICIOUS_ENDPOINTS.items():
            if sus_ep.lower() in endpoint:
                severity = "CRITICAL" if sus_ep in ("svcctl", "atsvc", "ITaskSchedulerService") else "HIGH"
                findings.append({
                    "type": "suspicious_dce_rpc",
                    "severity": severity,
                    "timestamp": ts_to_iso(rec.get("ts", "")),
                    "src": rec.get("id.orig_h", ""),
                    "dst": rec.get("id.resp_h", ""),
                    "endpoint": endpoint,
                    "operation": operation,
                    "description": description,
                    "named_pipe": rec.get("named_pipe", ""),
                    "uid": rec.get("uid", ""),
                })
                break
    return findings


def analyze_ntlm(log_dir):
    """Analyze ntlm.log for Pass-the-Hash and authentication anomalies."""
    records = parse_zeek_log(
        os.path.join(log_dir, "ntlm.log"), NTLM_FIELDS
    )
    findings = []
    user_source_map = defaultdict(set)
    failed_auths = defaultdict(int)

    for rec in records:
        username = rec.get("username", "-")
        orig = rec.get("id.orig_h", "")
        resp = rec.get("id.resp_h", "")
        success = rec.get("success", "")

        if username != "-" and username:
            user_source_map[username].add(orig)

        if success.upper() in ("F", "FALSE"):
            failed_auths[(orig, resp, username)] += 1

    # Detect one user authenticating from multiple source IPs (Pass-the-Hash indicator)
    for username, sources in user_source_map.items():
        if len(sources) > 2:
            findings.append({
                "type": "multi_source_ntlm_auth",
                "severity": "HIGH",
                "description": "Single user authenticating from multiple source IPs (possible PtH)",
                "username": username,
                "source_ips": sorted(sources),
                "source_count": len(sources),
            })

    # Detect brute force / credential spray
    for (orig, resp, username), count in failed_auths.items():
        if count >= 5:
            findings.append({
                "type": "ntlm_brute_force",
                "severity": "HIGH",
                "src": orig,
                "dst": resp,
                "username": username,
                "failed_attempts": count,
            })

    return findings


def analyze_kerberos(log_dir):
    """Analyze kerberos.log for ticket anomalies."""
    records = parse_zeek_log(
        os.path.join(log_dir, "kerberos.log"), KERBEROS_FIELDS
    )
    findings = []
    tgt_sources = defaultdict(set)

    for rec in records:
        request_type = rec.get("request_type", "")
        client = rec.get("client", "")
        orig = rec.get("id.orig_h", "")
        error_msg = rec.get("error_msg", "-")
        success = rec.get("success", "")

        if request_type == "AS":
            tgt_sources[client].add(orig)

        # Kerberos pre-auth failures (credential testing)
        if error_msg and "PREAUTH_FAILED" in error_msg.upper():
            findings.append({
                "type": "kerberos_preauth_failure",
                "severity": "MEDIUM",
                "timestamp": ts_to_iso(rec.get("ts", "")),
                "src": orig,
                "dst": rec.get("id.resp_h", ""),
                "client": client,
                "error": error_msg,
            })

    # Detect TGT requested from multiple IPs (possible Pass-the-Ticket)
    for client, sources in tgt_sources.items():
        if len(sources) > 2:
            findings.append({
                "type": "multi_source_tgt_request",
                "severity": "HIGH",
                "description": "TGT requested from multiple source IPs (possible Pass-the-Ticket)",
                "client": client,
                "source_ips": sorted(sources),
                "source_count": len(sources),
            })

    return findings


def detect_psexec_pattern(smb_findings, dce_findings):
    """Correlate SMB file writes with DCE/RPC svcctl to detect PsExec-style attacks."""
    correlated = []
    smb_writes = {}
    for f in smb_findings:
        if f["severity"] == "CRITICAL":
            key = (f["src"], f["dst"])
            smb_writes.setdefault(key, []).append(f)

    for f in dce_findings:
        if "svcctl" in f.get("endpoint", ""):
            key = (f["src"], f["dst"])
            if key in smb_writes:
                correlated.append({
                    "type": "psexec_pattern",
                    "severity": "CRITICAL",
                    "description": "SMB executable write followed by svcctl service creation (PsExec-style)",
                    "src": f["src"],
                    "dst": f["dst"],
                    "smb_writes": smb_writes[key],
                    "dce_rpc_operation": f["operation"],
                    "timestamp": f["timestamp"],
                })
    return correlated


def generate_report(all_findings, host_pair_counts, host_pair_bytes):
    """Generate a structured lateral movement report."""
    severity_counts = defaultdict(int)
    type_counts = defaultdict(int)
    for f in all_findings:
        severity_counts[f.get("severity", "INFO")] += 1
        type_counts[f.get("type", "unknown")] += 1

    # Top talkers by connection count
    top_pairs = sorted(host_pair_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    # Top talkers by bytes
    top_bytes = sorted(host_pair_bytes.items(), key=lambda x: x[1], reverse=True)[:20]

    report = {
        "summary": {
            "total_findings": len(all_findings),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
        },
        "top_connection_pairs": [
            {"pair": k, "connections": v} for k, v in top_pairs
        ],
        "top_data_transfer_pairs": [
            {"pair": k, "bytes": v, "megabytes": round(v / (1024 * 1024), 2)}
            for k, v in top_bytes
        ],
        "findings": all_findings,
    }
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Zeek Lateral Movement Detection Agent")
    print("conn.log, SMB, DCE/RPC, NTLM, Kerberos analysis")
    print("=" * 60)

    log_dir = sys.argv[1] if len(sys.argv) > 1 else "/opt/zeek/logs/current"

    if not os.path.isdir(log_dir):
        print(f"\n[ERROR] Log directory not found: {log_dir}")
        print("[DEMO] Usage: python agent.py <zeek_log_directory>")
        print("[*] Provide a directory containing Zeek log files (conn.log, smb_mapping.log, etc.)")
        sys.exit(1)

    print(f"\n[*] Analyzing Zeek logs in: {log_dir}")

    # Check which log files are available
    log_files = ["conn.log", "smb_mapping.log", "smb_files.log",
                 "dce_rpc.log", "ntlm.log", "kerberos.log"]
    for lf in log_files:
        path = os.path.join(log_dir, lf)
        status = "found" if os.path.exists(path) else "NOT FOUND"
        print(f"  {lf}: {status}")

    all_findings = []

    print("\n--- Connection Analysis (conn.log) ---")
    conn_findings, pair_counts, pair_bytes = analyze_conn_log(log_dir)
    lateral_conns = [f for f in conn_findings if f["type"] == "lateral_port_connection"]
    print(f"  Internal lateral-port connections: {len(lateral_conns)}")
    services = defaultdict(int)
    for f in lateral_conns:
        services[f["service_label"]] += 1
    for svc, count in sorted(services.items(), key=lambda x: -x[1]):
        print(f"    {svc}: {count}")

    print("\n--- SMB Admin Share Access (smb_mapping.log) ---")
    smb_map_findings = analyze_smb_mapping(log_dir)
    print(f"  Admin share accesses: {len(smb_map_findings)}")
    for f in smb_map_findings[:10]:
        print(f"  [!] {f['src']} -> {f['dst']} share={f['share_path']}")
    all_findings.extend(smb_map_findings)

    print("\n--- SMB File Writes (smb_files.log) ---")
    smb_file_findings = analyze_smb_files(log_dir)
    critical_writes = [f for f in smb_file_findings if f["severity"] == "CRITICAL"]
    print(f"  Total file writes: {len(smb_file_findings)}, Critical (executables): {len(critical_writes)}")
    for f in critical_writes[:10]:
        print(f"  [CRITICAL] {f['src']} -> {f['dst']} wrote {f['filename']} ({f['size']} bytes)")
    all_findings.extend(smb_file_findings)

    print("\n--- DCE/RPC Remote Execution (dce_rpc.log) ---")
    dce_findings = analyze_dce_rpc(log_dir)
    print(f"  Suspicious DCE/RPC operations: {len(dce_findings)}")
    for f in dce_findings[:10]:
        print(f"  [{f['severity']}] {f['src']} -> {f['dst']} "
              f"endpoint={f['endpoint']} op={f['operation']} ({f['description']})")
    all_findings.extend(dce_findings)

    print("\n--- NTLM Authentication Analysis (ntlm.log) ---")
    ntlm_findings = analyze_ntlm(log_dir)
    for f in ntlm_findings:
        if f["type"] == "multi_source_ntlm_auth":
            print(f"  [HIGH] PtH indicator: user '{f['username']}' from {f['source_count']} IPs: "
                  f"{', '.join(f['source_ips'][:5])}")
        elif f["type"] == "ntlm_brute_force":
            print(f"  [HIGH] Brute force: {f['src']} -> {f['dst']} "
                  f"user='{f['username']}' failures={f['failed_attempts']}")
    all_findings.extend(ntlm_findings)

    print("\n--- Kerberos Analysis (kerberos.log) ---")
    krb_findings = analyze_kerberos(log_dir)
    for f in krb_findings:
        if f["type"] == "multi_source_tgt_request":
            print(f"  [HIGH] PtT indicator: client '{f['client']}' TGT from {f['source_count']} IPs")
        elif f["type"] == "kerberos_preauth_failure":
            print(f"  [MEDIUM] Pre-auth failure: {f['src']} client={f['client']}")
    all_findings.extend(krb_findings)

    print("\n--- PsExec Pattern Correlation ---")
    psexec = detect_psexec_pattern(smb_file_findings, dce_findings)
    for p in psexec:
        print(f"  [CRITICAL] PsExec-style: {p['src']} -> {p['dst']} "
              f"(exe write + svcctl {p['dce_rpc_operation']})")
    all_findings.extend(psexec)

    report = generate_report(all_findings, pair_counts, pair_bytes)

    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {report['summary']['total_findings']} findings")
    for sev, count in sorted(report["summary"]["by_severity"].items()):
        print(f"  {sev}: {count}")

    if report["top_connection_pairs"]:
        print("\nTop internal connection pairs:")
        for p in report["top_connection_pairs"][:5]:
            print(f"  {p['pair']}: {p['connections']} connections")

    print(f"\n[*] Full report: {json.dumps(report['summary'], indent=2)}")
