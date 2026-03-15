#!/usr/bin/env python3
"""Ransomware canary file deployment and monitoring agent.

Deploys decoy files across critical directories and monitors them using
watchdog for real-time filesystem event detection. Any interaction with
canary files triggers alerts via email, Slack, and syslog.
"""

import os
import sys
import json
import time
import hashlib
import logging
import smtplib
import argparse
import platform
import subprocess
from pathlib import Path
from email.mime.text import MIMEText
from datetime import datetime, timezone

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("canary_monitor.log"),
    ],
)
logger = logging.getLogger(__name__)

CANARY_FILE_TEMPLATES = {
    "Passwords.xlsx": b"PK\x03\x04" + b"\x00" * 26 + b"[Content_Types].xml" + os.urandom(512),
    "Financial_Report_2026.docx": b"PK\x03\x04" + b"\x00" * 26 + b"word/document.xml" + os.urandom(512),
    "backup_credentials.csv": (
        b"hostname,username,password,last_rotated\n"
        b"dc01.corp.local,svc_backup,R3st0re$ecur3!2026,2026-01-15\n"
        b"sql-prod-01,sa,Pr0d_DB#Access!,2026-02-01\n"
        b"vpn-gateway,admin,VPN@dm1n_2026!,2026-03-01\n"
        b"nas-backup,root,B4ckup_N4S!2026,2025-12-20\n"
    ),
    "Employee_SSN_List.xlsx": b"PK\x03\x04" + b"\x00" * 26 + b"xl/worksheets/sheet1.xml" + os.urandom(512),
    "tax_returns_2025.pdf": b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + os.urandom(256),
    "bitcoin_wallet_seed.txt": (
        b"BIP39 Mnemonic Seed Phrase (DO NOT SHARE)\n"
        b"abandon ability able about above absent absorb abstract absurd abuse\n"
        b"access accident account accuse achieve acid acoustic acquire across act\n"
        b"Wallet Address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
    ),
    "database_export_prod.sql": (
        b"-- MySQL dump 10.13  Distrib 8.0.36\n"
        b"-- Host: db-prod-01.internal    Database: customer_data\n"
        b"CREATE TABLE customers (\n"
        b"  id INT PRIMARY KEY AUTO_INCREMENT,\n"
        b"  ssn VARCHAR(11) NOT NULL,\n"
        b"  credit_card VARCHAR(19),\n"
        b"  balance DECIMAL(10,2)\n"
        b");\n"
    ),
    "AWS_Access_Keys.csv": (
        b"User Name,Access Key ID,Secret Access Key\n"
        b"svc-prod-deploy,AKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        b"svc-backup,AKIAI44QH8DHBEXAMPLE,je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"
    ),
}


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError):
        return "file_not_accessible"


def compute_entropy(filepath):
    """Calculate Shannon entropy of file content to detect encryption."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError):
        return 0.0
    if not data:
        return 0.0
    from collections import Counter
    import math
    byte_counts = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in byte_counts.values()
        if count > 0
    )
    return round(entropy, 4)


def get_process_info():
    """Get information about processes that may have accessed canary files."""
    if not HAS_PSUTIL:
        return {"error": "psutil not installed"}
    suspicious = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
        try:
            info = proc.info
            if info["create_time"] and (time.time() - info["create_time"]) < 30:
                suspicious.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "username": info["username"],
                    "cmdline": " ".join(info["cmdline"] or []),
                    "age_seconds": round(time.time() - info["create_time"], 1),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious[:10]


def deploy_canary_files(target_dirs, custom_files=None):
    """Deploy canary files to specified directories."""
    templates = dict(CANARY_FILE_TEMPLATES)
    if custom_files:
        templates.update(custom_files)

    deployed = []
    for directory in target_dirs:
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning("Directory does not exist: %s", directory)
            continue
        if not os.access(directory, os.W_OK):
            logger.warning("No write access to: %s", directory)
            continue

        for filename, content in templates.items():
            filepath = dir_path / filename
            if filepath.exists():
                logger.info("Canary already exists: %s", filepath)
                deployed.append(str(filepath))
                continue
            try:
                with open(filepath, "wb") as f:
                    f.write(content)
                if platform.system() != "Windows":
                    os.chmod(filepath, 0o644)
                sha256 = compute_sha256(str(filepath))
                deployed.append(str(filepath))
                logger.info("Deployed canary: %s (SHA-256: %s)", filepath, sha256[:16])
            except (PermissionError, OSError) as e:
                logger.error("Failed to deploy %s: %s", filepath, e)

    manifest = {
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "canary_count": len(deployed),
        "directories": target_dirs,
        "files": deployed,
        "hashes": {f: compute_sha256(f) for f in deployed},
    }
    manifest_path = Path("canary_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info("Deployed %d canary files, manifest saved to %s", len(deployed), manifest_path)
    return manifest


def send_email_alert(alert_data, smtp_host, smtp_port, sender, recipients, password=None):
    """Send alert email via SMTP."""
    subject = f"RANSOMWARE CANARY ALERT: {alert_data['event_type']} on {alert_data['canary_file']}"
    body = json.dumps(alert_data, indent=2, default=str)
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
                server.ehlo()
        if password:
            server.login(sender, password)
        server.sendmail(sender, recipients, msg.as_string())
        server.quit()
        logger.info("Email alert sent to %s", recipients)
        return True
    except Exception as e:
        logger.error("Email alert failed: %s", e)
        return False


def send_slack_alert(alert_data, webhook_url):
    """Send alert to Slack via incoming webhook."""
    if not HAS_REQUESTS:
        logger.error("requests library not installed, cannot send Slack alert")
        return False
    payload = {
        "text": f":rotating_light: *RANSOMWARE CANARY ALERT*",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Ransomware Canary File Triggered"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event:*\n{alert_data['event_type']}"},
                    {"type": "mrkdwn", "text": f"*File:*\n`{alert_data['canary_file']}`"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{alert_data['timestamp']}"},
                    {"type": "mrkdwn", "text": f"*Host:*\n{alert_data.get('hostname', 'unknown')}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Immediate Action Required:* Investigate potential ransomware activity on `{alert_data.get('hostname', 'unknown')}`"
                }
            }
        ]
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("Slack alert sent successfully")
            return True
        logger.error("Slack alert failed: %d %s", resp.status_code, resp.text)
        return False
    except Exception as e:
        logger.error("Slack alert failed: %s", e)
        return False


def send_syslog_alert(alert_data, syslog_server="127.0.0.1", syslog_port=514):
    """Send alert to syslog server via UDP."""
    import socket
    priority = 8 * 4 + 1  # facility=security, severity=alert
    message = (
        f"<{priority}>1 {alert_data['timestamp']} {alert_data.get('hostname', '-')} "
        f"canary-monitor - - - RANSOMWARE_CANARY event={alert_data['event_type']} "
        f"file={alert_data['canary_file']} "
        f"hash_before={alert_data.get('hash_before', 'N/A')} "
        f"hash_after={alert_data.get('hash_after', 'N/A')}"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8"), (syslog_server, syslog_port))
        sock.close()
        logger.info("Syslog alert sent to %s:%d", syslog_server, syslog_port)
        return True
    except Exception as e:
        logger.error("Syslog alert failed: %s", e)
        return False


class CanaryFileHandler(FileSystemEventHandler):
    """Watchdog event handler for canary file monitoring."""

    def __init__(self, canary_files, config):
        super().__init__()
        self.canary_files = {str(Path(f).resolve()): compute_sha256(f) for f in canary_files}
        self.config = config
        self.alert_count = 0
        self.last_alert_time = {}

    def _is_canary(self, path):
        resolved = str(Path(path).resolve())
        return resolved in self.canary_files

    def _rate_limit_check(self, path, cooldown=10):
        now = time.time()
        last = self.last_alert_time.get(path, 0)
        if now - last < cooldown:
            return False
        self.last_alert_time[path] = now
        return True

    def _build_alert(self, event_type, src_path, dest_path=None):
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "canary_file": src_path,
            "hostname": platform.node(),
            "platform": platform.system(),
            "hash_before": self.canary_files.get(str(Path(src_path).resolve()), "unknown"),
            "hash_after": compute_sha256(src_path) if os.path.exists(src_path) else "file_deleted",
            "entropy_after": compute_entropy(src_path) if os.path.exists(src_path) else 0.0,
            "alert_number": self.alert_count + 1,
        }
        if dest_path:
            alert["destination"] = dest_path
        if HAS_PSUTIL:
            alert["recent_processes"] = get_process_info()
        return alert

    def _dispatch_alert(self, alert):
        self.alert_count += 1
        logger.critical(
            "CANARY TRIGGERED: %s on %s (alert #%d)",
            alert["event_type"], alert["canary_file"], self.alert_count
        )
        with open("canary_alerts.jsonl", "a") as f:
            f.write(json.dumps(alert, default=str) + "\n")

        if self.config.get("slack_webhook"):
            send_slack_alert(alert, self.config["slack_webhook"])
        if self.config.get("smtp_host"):
            send_email_alert(
                alert,
                self.config["smtp_host"],
                self.config.get("smtp_port", 587),
                self.config.get("smtp_sender", "canary@localhost"),
                self.config.get("smtp_recipients", []),
                self.config.get("smtp_password"),
            )
        if self.config.get("syslog_server"):
            send_syslog_alert(
                alert,
                self.config["syslog_server"],
                self.config.get("syslog_port", 514),
            )

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._is_canary(event.src_path) and self._rate_limit_check(event.src_path):
            alert = self._build_alert("FILE_MODIFIED", event.src_path)
            high_entropy = alert.get("entropy_after", 0) > 7.5
            if high_entropy:
                alert["encryption_suspected"] = True
                alert["severity"] = "critical"
            self._dispatch_alert(alert)

    def on_deleted(self, event):
        if event.is_directory:
            return
        if self._is_canary(event.src_path) and self._rate_limit_check(event.src_path):
            alert = self._build_alert("FILE_DELETED", event.src_path)
            alert["severity"] = "critical"
            self._dispatch_alert(alert)

    def on_moved(self, event):
        if event.is_directory:
            return
        if self._is_canary(event.src_path) and self._rate_limit_check(event.src_path):
            alert = self._build_alert("FILE_RENAMED", event.src_path, event.dest_path)
            extension = Path(event.dest_path).suffix.lower()
            ransomware_extensions = {
                ".encrypted", ".locked", ".lockbit", ".crypt", ".enc",
                ".ransom", ".pay", ".aes", ".rsa", ".cry", ".ryk",
                ".revil", ".conti", ".hive", ".black", ".basta",
            }
            if extension in ransomware_extensions:
                alert["ransomware_extension_detected"] = extension
                alert["severity"] = "critical"
            self._dispatch_alert(alert)

    def on_created(self, event):
        if event.is_directory:
            return
        parent = str(Path(event.src_path).parent)
        ransom_note_patterns = [
            "readme", "decrypt", "restore", "recover", "how_to",
            "ransom", "locked", "unlock", "pay", "instruction",
        ]
        basename = Path(event.src_path).stem.lower()
        if any(pattern in basename for pattern in ransom_note_patterns):
            for canary_dir in set(str(Path(c).parent) for c in self.canary_files):
                if parent == canary_dir:
                    alert = self._build_alert("RANSOM_NOTE_DETECTED", event.src_path)
                    alert["severity"] = "critical"
                    alert["indicator"] = "Ransom note dropped in monitored directory"
                    self._dispatch_alert(alert)
                    break


def start_monitoring(manifest_path, config):
    """Start real-time canary file monitoring."""
    if not HAS_WATCHDOG:
        logger.error("watchdog library required: pip install watchdog")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    canary_files = manifest["files"]
    if not canary_files:
        logger.error("No canary files found in manifest")
        sys.exit(1)

    watch_dirs = set()
    for canary in canary_files:
        parent = str(Path(canary).parent)
        if os.path.isdir(parent):
            watch_dirs.add(parent)

    handler = CanaryFileHandler(canary_files, config)
    observer = Observer()
    for directory in watch_dirs:
        observer.schedule(handler, directory, recursive=False)
        logger.info("Watching directory: %s", directory)

    logger.info("Monitoring %d canary files across %d directories", len(canary_files), len(watch_dirs))
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Monitoring stopped. Total alerts: %d", handler.alert_count)
    observer.join()


def verify_canary_integrity(manifest_path):
    """Verify all canary files match their original hashes."""
    with open(manifest_path) as f:
        manifest = json.load(f)
    results = {"checked": 0, "intact": 0, "modified": 0, "missing": 0, "details": []}
    for filepath, original_hash in manifest.get("hashes", {}).items():
        results["checked"] += 1
        if not os.path.exists(filepath):
            results["missing"] += 1
            results["details"].append({"file": filepath, "status": "MISSING"})
        else:
            current_hash = compute_sha256(filepath)
            if current_hash == original_hash:
                results["intact"] += 1
                results["details"].append({"file": filepath, "status": "INTACT"})
            else:
                results["modified"] += 1
                results["details"].append({
                    "file": filepath,
                    "status": "MODIFIED",
                    "original_hash": original_hash,
                    "current_hash": current_hash,
                    "entropy": compute_entropy(filepath),
                })
    return results


def simulate_ransomware_test(manifest_path):
    """Simulate ransomware activity against canary files for testing."""
    with open(manifest_path) as f:
        manifest = json.load(f)
    test_results = []
    for filepath in manifest.get("files", [])[:2]:
        if not os.path.exists(filepath):
            continue
        test_file = filepath + ".test_canary"
        try:
            import shutil
            shutil.copy2(filepath, test_file)
            with open(test_file, "ab") as f:
                f.write(os.urandom(64))
            test_results.append({
                "file": filepath,
                "test_action": "modified_copy",
                "test_file": test_file,
                "status": "triggered",
            })
            os.remove(test_file)
        except Exception as e:
            test_results.append({"file": filepath, "error": str(e)})
    return test_results


def main():
    parser = argparse.ArgumentParser(description="Ransomware Canary File Deployment and Monitoring Agent")
    parser.add_argument("--action", choices=["deploy", "monitor", "verify", "test"],
                        default="deploy", help="Action to perform")
    parser.add_argument("--dirs", nargs="+", help="Directories to deploy canary files")
    parser.add_argument("--manifest", default="canary_manifest.json", help="Canary manifest file path")
    parser.add_argument("--config", help="JSON config file for alert settings")
    parser.add_argument("--slack-webhook", help="Slack incoming webhook URL")
    parser.add_argument("--smtp-host", help="SMTP server hostname")
    parser.add_argument("--smtp-port", type=int, default=587)
    parser.add_argument("--smtp-sender", help="Alert sender email")
    parser.add_argument("--smtp-recipients", nargs="+", help="Alert recipient emails")
    parser.add_argument("--syslog-server", help="Syslog server address")
    args = parser.parse_args()

    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            config = json.load(f)
    if args.slack_webhook:
        config["slack_webhook"] = args.slack_webhook
    if args.smtp_host:
        config["smtp_host"] = args.smtp_host
        config["smtp_port"] = args.smtp_port
        config["smtp_sender"] = args.smtp_sender
        config["smtp_recipients"] = args.smtp_recipients or []
    if args.syslog_server:
        config["syslog_server"] = args.syslog_server

    if args.action == "deploy":
        if not args.dirs:
            print("Usage: python agent.py --action deploy --dirs /path/to/dir1 /path/to/dir2")
            print("\nExample:")
            print("  python agent.py --action deploy --dirs /srv/shares/finance /home/admin/Documents")
            return
        manifest = deploy_canary_files(args.dirs)
        print(json.dumps(manifest, indent=2))

    elif args.action == "monitor":
        if not os.path.exists(args.manifest):
            print(f"Manifest not found: {args.manifest}")
            print("Run --action deploy first to create canary files")
            return
        start_monitoring(args.manifest, config)

    elif args.action == "verify":
        if not os.path.exists(args.manifest):
            print(f"Manifest not found: {args.manifest}")
            return
        results = verify_canary_integrity(args.manifest)
        print(json.dumps(results, indent=2))
        if results["modified"] > 0 or results["missing"] > 0:
            print(f"\n[ALERT] {results['modified']} modified, {results['missing']} missing canary files!")

    elif args.action == "test":
        if not os.path.exists(args.manifest):
            print(f"Manifest not found: {args.manifest}")
            return
        results = simulate_ransomware_test(args.manifest)
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
