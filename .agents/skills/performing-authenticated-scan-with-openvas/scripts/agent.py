#!/usr/bin/env python3
"""OpenVAS/GVM authenticated vulnerability scan orchestration agent."""

import json
import sys
import argparse
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
except ImportError:
    Gmp = None


def connect_gvm(socket_path, username, password):
    """Connect to GVM daemon via Unix socket."""
    if Gmp is None:
        return None, "Install: pip install python-gvm"
    connection = UnixSocketConnection(path=socket_path)
    transform = EtreeTransform()
    gmp = Gmp(connection=connection, transform=transform)
    gmp.authenticate(username, password)
    return gmp, None


def list_scan_configs(gmp):
    """List available scan configurations."""
    response = gmp.get_scan_configs()
    configs = []
    for config in response.findall(".//config"):
        configs.append({
            "id": config.get("id"),
            "name": config.findtext("name", ""),
            "type": config.findtext("type", ""),
            "family_count": config.findtext("family_count/growing", ""),
        })
    return configs


def list_credentials(gmp):
    """List configured scan credentials."""
    response = gmp.get_credentials()
    creds = []
    for cred in response.findall(".//credential"):
        creds.append({
            "id": cred.get("id"),
            "name": cred.findtext("name", ""),
            "type": cred.findtext("type", ""),
            "login": cred.findtext("login", ""),
        })
    return creds


def create_ssh_credential(gmp, name, login, password):
    """Create SSH credential for authenticated Linux scans."""
    response = gmp.create_credential(
        name=name,
        credential_type=gmp.types.CredentialType.USERNAME_PASSWORD,
        login=login,
        password=password,
    )
    return response.get("id")


def create_target(gmp, name, hosts, ssh_cred_id=None, smb_cred_id=None, port_list_id=None):
    """Create scan target with optional credentials."""
    kwargs = {"name": name, "hosts": hosts}
    if ssh_cred_id:
        kwargs["ssh_credential_id"] = ssh_cred_id
        kwargs["ssh_credential_port"] = 22
    if smb_cred_id:
        kwargs["smb_credential_id"] = smb_cred_id
    if port_list_id:
        kwargs["port_list_id"] = port_list_id
    response = gmp.create_target(**kwargs)
    return response.get("id")


def create_and_start_task(gmp, name, target_id, config_id, scanner_id):
    """Create and start a scan task."""
    response = gmp.create_task(
        name=name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    task_id = response.get("id")
    gmp.start_task(task_id)
    return task_id


def get_task_status(gmp, task_id):
    """Check scan task progress and status."""
    response = gmp.get_task(task_id)
    task = response.find(".//task")
    if task is None:
        return {"error": "Task not found"}
    return {
        "id": task_id,
        "name": task.findtext("name", ""),
        "status": task.findtext("status", ""),
        "progress": task.findtext("progress", "0"),
        "report_id": task.find(".//last_report/report").get("id", "") if task.find(".//last_report/report") is not None else "",
    }


def get_report_results(gmp, report_id, min_qod=70):
    """Fetch vulnerability results from a completed scan report."""
    response = gmp.get_report(
        report_id,
        filter_string=f"min_qod={min_qod} sort-reverse=severity",
        details=True,
    )
    results = []
    for result in response.findall(".//result"):
        nvt = result.find("nvt")
        results.append({
            "name": nvt.findtext("name", "") if nvt is not None else "",
            "oid": nvt.get("oid", "") if nvt is not None else "",
            "host": result.findtext("host", ""),
            "port": result.findtext("port", ""),
            "severity": result.findtext("severity", "0"),
            "threat": result.findtext("threat", ""),
            "qod": result.findtext("qod/value", ""),
            "description": result.findtext("description", "")[:200],
        })
    return results


def parse_openvas_xml_report(xml_path):
    """Parse an exported OpenVAS XML report file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = []
    for result in root.findall(".//result"):
        nvt = result.find("nvt")
        results.append({
            "name": nvt.findtext("name", "") if nvt is not None else "",
            "host": result.findtext("host", ""),
            "port": result.findtext("port", ""),
            "severity": float(result.findtext("severity", "0")),
            "threat": result.findtext("threat", ""),
            "description": result.findtext("description", "")[:200],
        })
    results.sort(key=lambda x: x["severity"], reverse=True)
    return results


def run_audit(args):
    """Execute OpenVAS scan audit and analysis."""
    print(f"\n{'='*60}")
    print(f"  OPENVAS AUTHENTICATED SCAN AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.xml_report:
        results = parse_openvas_xml_report(args.xml_report)
        report["vulnerabilities"] = results
        severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Log": 0}
        for r in results:
            threat = r.get("threat", "Log")
            severity_counts[threat] = severity_counts.get(threat, 0) + 1
        report["severity_distribution"] = severity_counts
        print(f"--- SCAN RESULTS ({len(results)} vulnerabilities) ---")
        print(f"  High: {severity_counts['High']} | Medium: {severity_counts['Medium']} | "
              f"Low: {severity_counts['Low']} | Log: {severity_counts['Log']}")
        print(f"\n--- TOP VULNERABILITIES ---")
        for r in results[:15]:
            print(f"  [{r['threat']}] {r['host']}:{r['port']} — {r['name'][:70]}")

    elif args.socket and args.gvm_user and args.gvm_pass:
        gmp, error = connect_gvm(args.socket, args.gvm_user, args.gvm_pass)
        if error:
            print(f"ERROR: {error}")
            return {"error": error}

        configs = list_scan_configs(gmp)
        report["scan_configs"] = configs
        print(f"--- SCAN CONFIGS ({len(configs)}) ---")
        for c in configs[:10]:
            print(f"  {c['name']} ({c['id'][:8]}...)")

        creds = list_credentials(gmp)
        report["credentials"] = creds
        print(f"\n--- CREDENTIALS ({len(creds)}) ---")
        for c in creds[:10]:
            print(f"  {c['name']}: type={c['type']} login={c['login']}")

        if args.task_id:
            status = get_task_status(gmp, args.task_id)
            report["task_status"] = status
            print(f"\n--- TASK STATUS ---")
            print(f"  {status.get('name','')}: {status.get('status','')} "
                  f"({status.get('progress','')}%)")

    return report


def main():
    parser = argparse.ArgumentParser(description="OpenVAS Authenticated Scan Agent")
    parser.add_argument("--socket", default="/run/gvmd/gvmd.sock",
                        help="GVM Unix socket path")
    parser.add_argument("--gvm-user", help="GVM admin username")
    parser.add_argument("--gvm-pass", help="GVM admin password")
    parser.add_argument("--task-id", help="Existing task ID to check status")
    parser.add_argument("--xml-report", help="OpenVAS XML report file to parse")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
