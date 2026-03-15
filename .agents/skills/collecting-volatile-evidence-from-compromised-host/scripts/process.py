#!/usr/bin/env python3
"""
Volatile Evidence Collection Script

Collects volatile forensic evidence from a live system following
RFC 3227 order of volatility. Runs from external media.

Collects:
- Network connections and state
- Running processes with command lines
- Logged-in users and sessions
- System configuration and state
- DNS cache, ARP table, routing table
- Hashes all evidence files

Requirements:
    pip install psutil
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Install psutil: pip install psutil")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("volatile_evidence")


class EvidenceCollector:
    """Collect volatile evidence from a live system."""

    def __init__(self, output_dir: str, case_id: str):
        self.case_id = case_id
        self.hostname = socket.gethostname()
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(output_dir, f"{self.hostname}_{self.timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        self.evidence_manifest = []
        self.collection_log = []

        # Start collection log
        self._log_action("Collection initiated", f"Case: {case_id}, Host: {self.hostname}")
        self._log_action("System time", datetime.now(timezone.utc).isoformat())
        self._log_action("Platform", f"{platform.system()} {platform.release()}")
        self._log_action("Collector", os.getenv("USERNAME", os.getenv("USER", "unknown")))

    def _log_action(self, action: str, details: str):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
        }
        self.collection_log.append(entry)
        logger.info(f"{action}: {details}")

    def _save_evidence(self, filename: str, content: str, category: str):
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        file_hash = self._hash_file(filepath)
        self.evidence_manifest.append({
            "filename": filename,
            "category": category,
            "sha256": file_hash,
            "size_bytes": os.path.getsize(filepath),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
        self._log_action(f"Evidence collected: {filename}", f"SHA256: {file_hash}")
        return filepath

    def _save_evidence_csv(self, filename: str, data: list, category: str):
        if not data:
            self._log_action(f"No data for {filename}", "Empty result set")
            return None
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        file_hash = self._hash_file(filepath)
        self.evidence_manifest.append({
            "filename": filename,
            "category": category,
            "sha256": file_hash,
            "size_bytes": os.path.getsize(filepath),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
        self._log_action(f"Evidence collected: {filename}", f"SHA256: {file_hash}, Rows: {len(data)}")
        return filepath

    @staticmethod
    def _hash_file(filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def collect_network_connections(self):
        """Collect active network connections with process information."""
        self._log_action("Collecting", "Network connections")
        connections = []
        for conn in psutil.net_connections(kind="all"):
            try:
                proc_name = psutil.Process(conn.pid).name() if conn.pid else "N/A"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "N/A"
            connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                "status": conn.status,
                "pid": conn.pid or "",
                "process_name": proc_name,
            })
        self._save_evidence_csv("network_connections.csv", connections, "network")

        # Also save in text format
        text_output = f"Network Connections - {datetime.now(timezone.utc).isoformat()}\n"
        text_output += f"{'='*80}\n"
        text_output += f"Total connections: {len(connections)}\n\n"
        for conn in connections:
            text_output += f"PID:{conn['pid']} ({conn['process_name']}) "
            text_output += f"{conn['local_address']} -> {conn['remote_address']} "
            text_output += f"[{conn['status']}]\n"
        self._save_evidence("network_connections.txt", text_output, "network")
        return connections

    def collect_arp_table(self):
        """Collect ARP cache."""
        self._log_action("Collecting", "ARP table")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=10)
            self._save_evidence("arp_cache.txt", result.stdout, "network")
        except Exception as e:
            self._log_action("ARP collection failed", str(e))

    def collect_routing_table(self):
        """Collect routing table."""
        self._log_action("Collecting", "Routing table")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["route", "print"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["ip", "route", "show"], capture_output=True, text=True, timeout=10)
            self._save_evidence("routing_table.txt", result.stdout, "network")
        except Exception as e:
            self._log_action("Routing table collection failed", str(e))

    def collect_dns_cache(self):
        """Collect DNS resolver cache."""
        self._log_action("Collecting", "DNS cache")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True, timeout=30)
                if result.stdout:
                    self._save_evidence("dns_cache.txt", result.stdout, "network")
            else:
                # Linux - attempt systemd-resolved
                result = subprocess.run(
                    ["systemd-resolve", "--statistics"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout:
                    self._save_evidence("dns_stats.txt", result.stdout, "network")
        except Exception as e:
            self._log_action("DNS cache collection failed", str(e))

    def collect_running_processes(self):
        """Collect detailed information about all running processes."""
        self._log_action("Collecting", "Running processes")
        processes = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "username", "cmdline", "exe",
             "create_time", "status", "cpu_percent", "memory_percent",
             "num_threads", "connections"]
        ):
            try:
                info = proc.info
                cmdline = " ".join(info["cmdline"]) if info["cmdline"] else ""
                create_time = datetime.fromtimestamp(info["create_time"]).isoformat() if info["create_time"] else ""
                num_conns = len(info["connections"]) if info["connections"] else 0
                processes.append({
                    "pid": info["pid"],
                    "ppid": info["ppid"],
                    "name": info["name"],
                    "username": info["username"] or "",
                    "command_line": cmdline[:500],
                    "executable": info["exe"] or "",
                    "create_time": create_time,
                    "status": info["status"],
                    "cpu_percent": info["cpu_percent"],
                    "memory_percent": round(info["memory_percent"] or 0, 2),
                    "threads": info["num_threads"],
                    "network_connections": num_conns,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._save_evidence_csv("running_processes.csv", processes, "processes")

        # Process tree text format
        tree_output = f"Process Tree - {datetime.now(timezone.utc).isoformat()}\n{'='*80}\n"
        tree_output += f"Total processes: {len(processes)}\n\n"
        for p in sorted(processes, key=lambda x: x["pid"]):
            tree_output += f"PID:{p['pid']} PPID:{p['ppid']} User:{p['username']} "
            tree_output += f"{p['name']} [{p['status']}]\n"
            if p["command_line"]:
                tree_output += f"  CMD: {p['command_line']}\n"
        self._save_evidence("process_tree.txt", tree_output, "processes")
        return processes

    def collect_open_files(self):
        """Collect open file handles for all processes."""
        self._log_action("Collecting", "Open file handles")
        open_files = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                for f in proc.open_files():
                    open_files.append({
                        "pid": proc.info["pid"],
                        "process_name": proc.info["name"],
                        "file_path": f.path,
                        "fd": f.fd,
                        "mode": getattr(f, "mode", ""),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if open_files:
            self._save_evidence_csv("open_files.csv", open_files, "processes")
        return open_files

    def collect_logged_in_users(self):
        """Collect information about currently logged-in users."""
        self._log_action("Collecting", "Logged-in users")
        users = []
        for user in psutil.users():
            users.append({
                "username": user.name,
                "terminal": user.terminal or "",
                "host": user.host or "",
                "started": datetime.fromtimestamp(user.started).isoformat(),
                "pid": getattr(user, "pid", ""),
            })
        self._save_evidence_csv("logged_in_users.csv", users, "users")

        # Text format
        text = f"Logged-in Users - {datetime.now(timezone.utc).isoformat()}\n{'='*80}\n"
        for u in users:
            text += f"User: {u['username']} | Terminal: {u['terminal']} | "
            text += f"Host: {u['host']} | Since: {u['started']}\n"
        self._save_evidence("logged_in_users.txt", text, "users")
        return users

    def collect_system_info(self):
        """Collect system configuration and state."""
        self._log_action("Collecting", "System information")
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        info = {
            "hostname": self.hostname,
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "boot_time": boot_time.isoformat(),
            "uptime_seconds": (datetime.now() - boot_time).total_seconds(),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "memory_used_percent": psutil.virtual_memory().percent,
            "disk_partitions": [
                {"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype}
                for p in psutil.disk_partitions()
            ],
            "network_interfaces": {
                name: [{"address": addr.address, "family": str(addr.family)}
                       for addr in addrs]
                for name, addrs in psutil.net_if_addrs().items()
            },
        }
        self._save_evidence(
            "system_info.json",
            json.dumps(info, indent=2),
            "system",
        )
        return info

    def collect_services(self):
        """Collect running services (platform-specific)."""
        self._log_action("Collecting", "Running services")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["sc", "queryex", "type=", "service", "state=", "all"],
                    capture_output=True, text=True, timeout=30,
                )
                self._save_evidence("services_all.txt", result.stdout, "system")
            else:
                result = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
                    capture_output=True, text=True, timeout=30,
                )
                self._save_evidence("systemd_services.txt", result.stdout, "system")
        except Exception as e:
            self._log_action("Service collection failed", str(e))

    def collect_scheduled_tasks(self):
        """Collect scheduled tasks / cron jobs."""
        self._log_action("Collecting", "Scheduled tasks")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV", "/v"],
                    capture_output=True, text=True, timeout=30,
                )
                self._save_evidence("scheduled_tasks.csv", result.stdout, "system")
            else:
                result = subprocess.run(
                    ["crontab", "-l"],
                    capture_output=True, text=True, timeout=10,
                )
                self._save_evidence("crontab.txt", result.stdout or "No crontab", "system")
        except Exception as e:
            self._log_action("Scheduled task collection failed", str(e))

    def collect_environment_variables(self):
        """Collect environment variables."""
        self._log_action("Collecting", "Environment variables")
        env_data = "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))
        self._save_evidence("environment_variables.txt", env_data, "system")

    def finalize(self):
        """Generate evidence manifest and collection log."""
        # Save collection log
        log_path = os.path.join(self.output_dir, "collection_log.json")
        with open(log_path, "w") as f:
            json.dump(self.collection_log, f, indent=2)

        # Save evidence manifest
        manifest_path = os.path.join(self.output_dir, "evidence_manifest.json")
        manifest = {
            "case_id": self.case_id,
            "hostname": self.hostname,
            "collection_start": self.collection_log[0]["timestamp"] if self.collection_log else "",
            "collection_end": datetime.now(timezone.utc).isoformat(),
            "total_evidence_items": len(self.evidence_manifest),
            "evidence": self.evidence_manifest,
        }
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        # Generate SHA256 manifest text file
        hash_manifest = os.path.join(self.output_dir, "sha256_manifest.txt")
        with open(hash_manifest, "w") as f:
            for item in self.evidence_manifest:
                f.write(f"{item['sha256']}  {item['filename']}\n")

        logger.info(f"Collection complete. Evidence directory: {self.output_dir}")
        logger.info(f"Total evidence items: {len(self.evidence_manifest)}")
        return self.output_dir


def main():
    parser = argparse.ArgumentParser(description="Volatile Evidence Collection Tool")
    parser.add_argument("--case-id", required=True, help="Case/incident ID")
    parser.add_argument("--output-dir", default="./evidence_collection", help="Output directory")
    parser.add_argument("--skip-memory", action="store_true", help="Skip memory dump (use dedicated tool)")
    parser.add_argument("--collect-all", action="store_true", help="Collect all available evidence types")

    args = parser.parse_args()

    collector = EvidenceCollector(args.output_dir, args.case_id)

    if not args.skip_memory:
        logger.info("NOTE: For memory acquisition, use dedicated tools (WinPmem/LiME) from forensic USB")

    # Collect in order of volatility
    collector.collect_network_connections()
    collector.collect_arp_table()
    collector.collect_dns_cache()
    collector.collect_routing_table()
    collector.collect_running_processes()
    collector.collect_open_files()
    collector.collect_logged_in_users()
    collector.collect_system_info()
    collector.collect_services()
    collector.collect_scheduled_tasks()
    collector.collect_environment_variables()

    evidence_dir = collector.finalize()
    print(f"\nEvidence collection complete")
    print(f"Output directory: {evidence_dir}")
    print(f"Total items: {len(collector.evidence_manifest)}")


if __name__ == "__main__":
    main()
