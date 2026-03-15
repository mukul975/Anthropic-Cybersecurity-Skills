#!/usr/bin/env python3
"""Agent for performing IoT security assessment.

Automates IoT device reconnaissance, firmware extraction with binwalk,
network traffic analysis, and service scanning for security testing.
"""

import subprocess
import json
import sys
import re
import hashlib
from pathlib import Path


class IoTSecurityAgent:
    """Performs automated IoT device security assessments."""

    def __init__(self, target_ip, output_dir):
        self.target_ip = target_ip
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def scan_services(self):
        """Scan target for open services using nmap."""
        result = subprocess.run(
            ["nmap", "-sV", "-sC", "-p-", "-oJ", "-", self.target_ip],
            capture_output=True, text=True, timeout=300,
        )
        services = []
        for line in result.stdout.splitlines():
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    services.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": " ".join(parts[2:]),
                    })
        return {"target": self.target_ip, "services": services, "raw": result.stdout}

    def check_default_credentials(self):
        """Test common default credentials against discovered services."""
        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
            ("root", "root"), ("root", "admin"), ("root", "password"),
            ("admin", ""), ("user", "user"), ("guest", "guest"),
        ]
        results = []
        for username, password in default_creds:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-u", f"{username}:{password}",
                 f"http://{self.target_ip}/", "--max-time", "5"],
                capture_output=True, text=True,
            )
            status = result.stdout.strip()
            if status in ("200", "301", "302"):
                results.append({
                    "username": username,
                    "password": password,
                    "status": status,
                    "vulnerable": True,
                })
        return results

    def analyze_firmware(self, firmware_path):
        """Analyze firmware image with binwalk."""
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            return {"error": f"Firmware file not found: {firmware_path}"}

        sha256 = hashlib.sha256(fw_path.read_bytes()).hexdigest()
        scan_result = subprocess.run(
            ["binwalk", str(fw_path)], capture_output=True, text=True
        )
        extract_dir = self.output_dir / "firmware_extracted"
        subprocess.run(
            ["binwalk", "-eM", "-C", str(extract_dir), str(fw_path)],
            capture_output=True, text=True,
        )

        creds_found = []
        for root, dirs, files in (extract_dir).rglob("*") if extract_dir.exists() else []:
            pass

        if extract_dir.exists():
            grep_result = subprocess.run(
                ["grep", "-rn", "-i", "password\\|passwd\\|secret",
                 str(extract_dir)],
                capture_output=True, text=True,
            )
            for line in grep_result.stdout.splitlines()[:20]:
                creds_found.append(line.strip())

        return {
            "sha256": sha256,
            "size": fw_path.stat().st_size,
            "binwalk_scan": scan_result.stdout,
            "credentials_found": creds_found,
            "extract_dir": str(extract_dir),
        }

    def capture_traffic(self, interface="eth0", duration=30):
        """Capture network traffic from the IoT device."""
        pcap_path = self.output_dir / "iot_capture.pcap"
        subprocess.run(
            ["timeout", str(duration), "tcpdump", "-i", interface,
             f"host {self.target_ip}", "-w", str(pcap_path)],
            capture_output=True, timeout=duration + 10,
        )
        if pcap_path.exists():
            stats = subprocess.run(
                ["capinfos", str(pcap_path)], capture_output=True, text=True
            )
            return {"pcap": str(pcap_path), "stats": stats.stdout}
        return {"error": "Capture failed"}

    def check_tls_configuration(self, port=443):
        """Check TLS configuration on HTTPS services."""
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{self.target_ip}:{port}",
             "-brief"],
            input="", capture_output=True, text=True, timeout=10,
        )
        tls_info = {
            "raw": result.stdout + result.stderr,
            "self_signed": "self signed" in (result.stdout + result.stderr).lower(),
        }

        for line in (result.stdout + result.stderr).splitlines():
            if "Protocol" in line:
                tls_info["protocol"] = line.strip()
            if "Cipher" in line:
                tls_info["cipher"] = line.strip()
        return tls_info

    def check_upnp_exposure(self):
        """Check for UPnP service exposure."""
        result = subprocess.run(
            ["nmap", "-sU", "-p", "1900", "--script=upnp-info", self.target_ip],
            capture_output=True, text=True, timeout=30,
        )
        return {
            "upnp_detected": "upnp" in result.stdout.lower(),
            "output": result.stdout,
        }

    def check_mqtt(self, port=1883):
        """Check for unauthenticated MQTT access."""
        try:
            import paho.mqtt.client as mqtt
            connected = False
            topics = []

            def on_connect(client, userdata, flags, rc):
                nonlocal connected
                connected = rc == 0
                if connected:
                    client.subscribe("#")

            def on_message(client, userdata, msg):
                topics.append({"topic": msg.topic, "payload_len": len(msg.payload)})

            client = mqtt.Client()
            client.on_connect = on_connect
            client.on_message = on_message
            client.connect(self.target_ip, port, 5)
            client.loop_start()
            import time
            time.sleep(5)
            client.loop_stop()
            client.disconnect()

            return {
                "unauthenticated_access": connected,
                "topics_found": len(topics),
                "sample_topics": topics[:10],
            }
        except Exception as e:
            return {"error": str(e)}

    def generate_report(self, firmware_path=None):
        """Run full IoT security assessment and generate report."""
        report = {"target": self.target_ip, "findings": []}

        services = self.scan_services()
        report["services"] = services

        creds = self.check_default_credentials()
        if creds:
            report["findings"].append({
                "id": "IOT-001", "severity": "Critical",
                "title": "Default Credentials Accepted",
                "details": creds,
            })

        tls = self.check_tls_configuration()
        if tls.get("self_signed"):
            report["findings"].append({
                "id": "IOT-002", "severity": "Medium",
                "title": "Self-Signed TLS Certificate",
                "details": tls,
            })

        if firmware_path:
            fw = self.analyze_firmware(firmware_path)
            report["firmware_analysis"] = fw
            if fw.get("credentials_found"):
                report["findings"].append({
                    "id": "IOT-003", "severity": "Critical",
                    "title": "Hardcoded Credentials in Firmware",
                    "count": len(fw["credentials_found"]),
                })

        report_path = self.output_dir / "iot_assessment_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <target_ip> <output_dir> [firmware_path]")
        sys.exit(1)

    target_ip = sys.argv[1]
    output_dir = sys.argv[2]
    firmware_path = sys.argv[3] if len(sys.argv) > 3 else None

    agent = IoTSecurityAgent(target_ip, output_dir)
    agent.generate_report(firmware_path)


if __name__ == "__main__":
    main()
