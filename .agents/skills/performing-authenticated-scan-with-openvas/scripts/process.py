#!/usr/bin/env python3
"""OpenVAS Authenticated Scan Automation.

Manages scan targets, credentials, tasks, and result export using
the Greenbone Management Protocol (GMP) via python-gvm.
"""

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
except ImportError:
    print("Install python-gvm: pip install python-gvm")
    sys.exit(1)

DEFAULT_SOCKET = "/run/gvmd/gvmd.sock"
FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
ALL_IANA_PORTS = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"


def connect_gmp(socket_path, username, password):
    """Establish authenticated GMP connection."""
    connection = UnixSocketConnection(path=socket_path)
    transform = EtreeCheckCommandTransform()
    gmp = Gmp(connection=connection, transform=transform)
    gmp.authenticate(username, password)
    return gmp


def create_ssh_credential(gmp, name, login, key_path=None, password=None):
    """Create SSH credential for Linux authenticated scanning."""
    if key_path:
        with open(key_path, "r") as f:
            private_key = f.read()
        credential = gmp.create_credential(
            name=name,
            credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY,
            login=login,
            key_phrase=password or "",
            private_key=private_key,
        )
    else:
        credential = gmp.create_credential(
            name=name,
            credential_type=gmp.types.CredentialType.USERNAME_PASSWORD,
            login=login,
            password=password,
        )
    cred_id = credential.get("id")
    print(f"[+] Created SSH credential: {name} (ID: {cred_id})")
    return cred_id


def create_smb_credential(gmp, name, login, password):
    """Create SMB credential for Windows authenticated scanning."""
    credential = gmp.create_credential(
        name=name,
        credential_type=gmp.types.CredentialType.USERNAME_PASSWORD,
        login=login,
        password=password,
    )
    cred_id = credential.get("id")
    print(f"[+] Created SMB credential: {name} (ID: {cred_id})")
    return cred_id


def create_target(gmp, name, hosts, ssh_cred_id=None, smb_cred_id=None, ssh_port=22):
    """Create scan target with associated credentials."""
    kwargs = {
        "name": name,
        "hosts": hosts if isinstance(hosts, list) else [hosts],
        "port_list_id": ALL_IANA_PORTS,
        "alive_test": gmp.types.AliveTest.ICMP_TCP_ACK_SERVICE_AND_ARP_PING,
    }
    if ssh_cred_id:
        kwargs["ssh_credential_id"] = ssh_cred_id
        kwargs["ssh_credential_port"] = ssh_port
    if smb_cred_id:
        kwargs["smb_credential_id"] = smb_cred_id

    target = gmp.create_target(**kwargs)
    target_id = target.get("id")
    print(f"[+] Created target: {name} (ID: {target_id})")
    return target_id


def create_scan_task(gmp, name, target_id, config_id=FULL_AND_FAST_CONFIG, schedule_id=None):
    """Create scan task with target and configuration."""
    kwargs = {
        "name": name,
        "config_id": config_id,
        "target_id": target_id,
        "scanner_id": OPENVAS_SCANNER,
    }
    if schedule_id:
        kwargs["schedule_id"] = schedule_id

    task = gmp.create_task(**kwargs)
    task_id = task.get("id")
    print(f"[+] Created task: {name} (ID: {task_id})")
    return task_id


def start_scan(gmp, task_id):
    """Start a scan task and return report ID."""
    response = gmp.start_task(task_id)
    report_id = response.find("report_id").text
    print(f"[+] Scan started. Report ID: {report_id}")
    return report_id


def get_task_status(gmp, task_id):
    """Check scan task progress."""
    task = gmp.get_task(task_id)
    status = task.find("task/status").text
    progress = task.find("task/progress")
    progress_pct = progress.text if progress is not None else "N/A"
    return {"status": status, "progress": progress_pct}


def export_report_csv(gmp, report_id, output_path):
    """Export scan report results to CSV."""
    report = gmp.get_report(
        report_id=report_id,
        report_format_id="c1645568-627a-11e3-a660-406186ea4fc5",
        ignore_pagination=True,
        details=True,
    )
    results = []
    for result in report.iter("result"):
        nvt = result.find("nvt")
        if nvt is None:
            continue
        host = result.find("host")
        port = result.find("port")
        severity = result.find("severity")
        cve_refs = nvt.find("cve")
        results.append({
            "host": host.text if host is not None else "",
            "port": port.text if port is not None else "",
            "nvt_name": nvt.findtext("name", ""),
            "nvt_oid": nvt.get("oid", ""),
            "severity": severity.text if severity is not None else "",
            "cve": cve_refs.text if cve_refs is not None else "",
            "description": result.findtext("description", "")[:500],
        })

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

    print(f"[+] Exported {len(results)} findings to {output_path}")
    return results


def check_auth_success(gmp, report_id):
    """Verify authentication was successful during scan."""
    report = gmp.get_report(report_id=report_id, ignore_pagination=True, details=True)
    auth_results = {
        "ssh_success": [],
        "ssh_failed": [],
        "smb_success": [],
        "smb_failed": [],
    }
    for result in report.iter("result"):
        nvt = result.find("nvt")
        if nvt is None:
            continue
        oid = nvt.get("oid", "")
        host = result.findtext("host", "")
        description = result.findtext("description", "")

        if oid == "1.3.6.1.4.1.25623.1.0.103591":
            if "successful" in description.lower():
                auth_results["ssh_success"].append(host)
            else:
                auth_results["ssh_failed"].append(host)
        elif oid == "1.3.6.1.4.1.25623.1.0.90023":
            if "successful" in description.lower():
                auth_results["smb_success"].append(host)
            else:
                auth_results["smb_failed"].append(host)

    print("[*] Authentication Results:")
    print(f"    SSH Success: {len(auth_results['ssh_success'])} hosts")
    print(f"    SSH Failed: {len(auth_results['ssh_failed'])} hosts")
    print(f"    SMB Success: {len(auth_results['smb_success'])} hosts")
    print(f"    SMB Failed: {len(auth_results['smb_failed'])} hosts")
    return auth_results


def main():
    parser = argparse.ArgumentParser(description="OpenVAS Authenticated Scan Automation")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="GVM socket path")
    parser.add_argument("--username", default="admin", help="GVM username")
    parser.add_argument("--password", required=True, help="GVM password")

    sub = parser.add_subparsers(dest="command")

    cred_parser = sub.add_parser("create-credential", help="Create scan credential")
    cred_parser.add_argument("--name", required=True)
    cred_parser.add_argument("--type", choices=["ssh", "smb"], required=True)
    cred_parser.add_argument("--login", required=True)
    cred_parser.add_argument("--cred-password")
    cred_parser.add_argument("--key-path")

    target_parser = sub.add_parser("create-target", help="Create scan target")
    target_parser.add_argument("--name", required=True)
    target_parser.add_argument("--hosts", required=True, help="Comma-separated hosts")
    target_parser.add_argument("--ssh-cred-id")
    target_parser.add_argument("--smb-cred-id")

    scan_parser = sub.add_parser("start-scan", help="Create and start scan")
    scan_parser.add_argument("--name", required=True)
    scan_parser.add_argument("--target-id", required=True)

    export_parser = sub.add_parser("export", help="Export scan report")
    export_parser.add_argument("--report-id", required=True)
    export_parser.add_argument("--output", default="openvas_results.csv")

    status_parser = sub.add_parser("status", help="Check scan task status")
    status_parser.add_argument("--task-id", required=True)

    auth_parser = sub.add_parser("check-auth", help="Verify authentication success")
    auth_parser.add_argument("--report-id", required=True)

    args = parser.parse_args()

    gmp = connect_gmp(args.socket, args.username, args.password)

    if args.command == "create-credential":
        if args.type == "ssh":
            create_ssh_credential(gmp, args.name, args.login, args.key_path, args.cred_password)
        else:
            create_smb_credential(gmp, args.name, args.login, args.cred_password)
    elif args.command == "create-target":
        hosts = args.hosts.split(",")
        create_target(gmp, args.name, hosts, args.ssh_cred_id, args.smb_cred_id)
    elif args.command == "start-scan":
        task_id = create_scan_task(gmp, args.name, args.target_id)
        start_scan(gmp, task_id)
    elif args.command == "export":
        export_report_csv(gmp, args.report_id, args.output)
    elif args.command == "status":
        status = get_task_status(gmp, args.task_id)
        print(f"Status: {status['status']}, Progress: {status['progress']}%")
    elif args.command == "check-auth":
        check_auth_success(gmp, args.report_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
