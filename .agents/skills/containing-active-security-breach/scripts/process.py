#!/usr/bin/env python3
"""
Active Security Breach Containment Automation Script

Automates containment actions during an active security breach:
- Queries SIEM for scope assessment
- Isolates endpoints via EDR API
- Blocks IPs/domains at firewall
- Disables compromised AD accounts
- Generates containment action log

Requirements:
    pip install requests ldap3 python-dateutil pyyaml
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

try:
    from ldap3 import Server, Connection, MODIFY_REPLACE, ALL
except ImportError:
    ldap3_available = False
else:
    ldap3_available = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"containment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
    ],
)
logger = logging.getLogger("breach_containment")


class ContainmentActionLog:
    """Tracks all containment actions with timestamps for audit trail."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.actions = []
        self.start_time = datetime.now(timezone.utc)

    def log_action(self, action_type: str, target: str, result: str, details: str = ""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": self.incident_id,
            "action_type": action_type,
            "target": target,
            "result": result,
            "details": details,
            "operator": os.getenv("USERNAME", os.getenv("USER", "unknown")),
        }
        self.actions.append(entry)
        logger.info(f"[{action_type}] {target}: {result} - {details}")

    def export_csv(self, filepath: str):
        if not self.actions:
            logger.warning("No actions to export")
            return
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.actions[0].keys())
            writer.writeheader()
            writer.writerows(self.actions)
        logger.info(f"Containment log exported to {filepath}")

    def export_json(self, filepath: str):
        report = {
            "incident_id": self.incident_id,
            "containment_start": self.start_time.isoformat(),
            "containment_end": datetime.now(timezone.utc).isoformat(),
            "total_actions": len(self.actions),
            "actions": self.actions,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Containment report exported to {filepath}")


class CrowdStrikeContainment:
    """CrowdStrike Falcon endpoint containment via API."""

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None

    def authenticate(self):
        resp = requests.post(
            f"{self.base_url}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        self.token = resp.json()["access_token"]
        logger.info("Authenticated to CrowdStrike Falcon API")

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def get_device_id_by_hostname(self, hostname: str) -> Optional[str]:
        resp = requests.get(
            f"{self.base_url}/devices/queries/devices/v1",
            headers=self._headers(),
            params={"filter": f"hostname:'{hostname}'"},
        )
        resp.raise_for_status()
        resources = resp.json().get("resources", [])
        return resources[0] if resources else None

    def contain_host(self, device_id: str) -> dict:
        resp = requests.post(
            f"{self.base_url}/devices/entities/devices-actions/v2",
            headers=self._headers(),
            params={"action_name": "contain"},
            json={"ids": [device_id]},
        )
        resp.raise_for_status()
        return resp.json()

    def lift_containment(self, device_id: str) -> dict:
        resp = requests.post(
            f"{self.base_url}/devices/entities/devices-actions/v2",
            headers=self._headers(),
            params={"action_name": "lift_containment"},
            json={"ids": [device_id]},
        )
        resp.raise_for_status()
        return resp.json()

    def get_detections(self, severity: str = "Critical") -> list:
        resp = requests.get(
            f"{self.base_url}/detects/queries/detects/v1",
            headers=self._headers(),
            params={"filter": f"max_severity_displayname:'{severity}'+status:'new'", "limit": 100},
        )
        resp.raise_for_status()
        return resp.json().get("resources", [])


class SentinelOneContainment:
    """SentinelOne endpoint containment via API."""

    def __init__(self, api_token: str, base_url: str):
        self.base_url = base_url
        self.api_token = api_token

    def _headers(self):
        return {"Authorization": f"ApiToken {self.api_token}", "Content-Type": "application/json"}

    def disconnect_agent(self, agent_id: str) -> dict:
        resp = requests.post(
            f"{self.base_url}/web/api/v2.1/agents/actions/disconnect",
            headers=self._headers(),
            json={"filter": {"ids": [agent_id]}, "data": {}},
        )
        resp.raise_for_status()
        return resp.json()

    def reconnect_agent(self, agent_id: str) -> dict:
        resp = requests.post(
            f"{self.base_url}/web/api/v2.1/agents/actions/connect",
            headers=self._headers(),
            json={"filter": {"ids": [agent_id]}, "data": {}},
        )
        resp.raise_for_status()
        return resp.json()


class ActiveDirectoryContainment:
    """Active Directory account containment via LDAP."""

    def __init__(self, server_addr: str, domain: str, username: str, password: str):
        if not ldap3_available:
            raise ImportError("ldap3 package required: pip install ldap3")
        self.server = Server(server_addr, get_info=ALL)
        self.domain = domain
        self.conn = Connection(self.server, user=f"{domain}\\{username}", password=password, auto_bind=True)

    def disable_account(self, sam_account_name: str) -> bool:
        search_base = ",".join([f"DC={part}" for part in self.domain.split(".")])
        self.conn.search(
            search_base,
            f"(sAMAccountName={sam_account_name})",
            attributes=["userAccountControl", "distinguishedName"],
        )
        if not self.conn.entries:
            logger.warning(f"Account {sam_account_name} not found in AD")
            return False

        dn = self.conn.entries[0].distinguishedName.value
        current_uac = int(self.conn.entries[0].userAccountControl.value)
        # Set ACCOUNTDISABLE flag (bit 1, value 2)
        new_uac = current_uac | 0x0002
        self.conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [str(new_uac)])]})
        logger.info(f"Disabled AD account: {sam_account_name}")
        return True

    def reset_password(self, sam_account_name: str, new_password: str) -> bool:
        search_base = ",".join([f"DC={part}" for part in self.domain.split(".")])
        self.conn.search(search_base, f"(sAMAccountName={sam_account_name})", attributes=["distinguishedName"])
        if not self.conn.entries:
            return False
        dn = self.conn.entries[0].distinguishedName.value
        encoded_pw = f'"{new_password}"'.encode("utf-16-le")
        self.conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [encoded_pw])]})
        logger.info(f"Reset password for AD account: {sam_account_name}")
        return True


class FirewallContainment:
    """Block IPs and domains at network perimeter."""

    @staticmethod
    def block_ips_iptables(ip_list: list, chain: str = "INPUT") -> list:
        results = []
        for ip in ip_list:
            try:
                cmd = ["iptables", "-A", chain, "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                cmd_out = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
                subprocess.run(cmd_out, capture_output=True, text=True, check=True)
                results.append({"ip": ip, "status": "blocked", "method": "iptables"})
                logger.info(f"Blocked IP via iptables: {ip}")
            except subprocess.CalledProcessError as e:
                results.append({"ip": ip, "status": "failed", "error": str(e)})
                logger.error(f"Failed to block IP {ip}: {e}")
        return results

    @staticmethod
    def block_ips_windows_firewall(ip_list: list) -> list:
        results = []
        for ip in ip_list:
            try:
                rule_name = f"IR_Block_{ip.replace('.', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip}", "protocol=any",
                ]
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                cmd_out = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_out", "dir=out", "action=block",
                    f"remoteip={ip}", "protocol=any",
                ]
                subprocess.run(cmd_out, capture_output=True, text=True, check=True)
                results.append({"ip": ip, "status": "blocked", "method": "windows_firewall"})
                logger.info(f"Blocked IP via Windows Firewall: {ip}")
            except subprocess.CalledProcessError as e:
                results.append({"ip": ip, "status": "failed", "error": str(e)})
                logger.error(f"Failed to block IP {ip}: {e}")
        return results

    @staticmethod
    def block_domains_hosts_file(domain_list: list) -> list:
        results = []
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
        try:
            with open(hosts_path, "a") as f:
                for domain in domain_list:
                    f.write(f"\n0.0.0.0 {domain}  # IR Containment Block")
                    results.append({"domain": domain, "status": "sinkholed", "method": "hosts_file"})
                    logger.info(f"Sinkholed domain: {domain}")
        except PermissionError:
            logger.error("Insufficient permissions to modify hosts file. Run as administrator.")
            for domain in domain_list:
                results.append({"domain": domain, "status": "failed", "error": "permission_denied"})
        return results


class SplunkScopeAssessment:
    """Query Splunk SIEM for incident scope assessment."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.token = token

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def search(self, query: str, earliest: str = "-24h", latest: str = "now") -> dict:
        resp = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=self._headers(),
            data={
                "search": f"search {query}",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
            verify=False,
        )
        resp.raise_for_status()
        return resp.json()

    def find_related_hosts(self, attacker_ip: str) -> dict:
        query = f"""index=security (src_ip="{attacker_ip}" OR dest_ip="{attacker_ip}")
| stats count values(dest_ip) as targets values(src_ip) as sources by sourcetype
| sort -count"""
        return self.search(query)

    def find_compromised_accounts(self, host_list: list) -> dict:
        hosts_filter = " OR ".join([f'src="{h}"' for h in host_list])
        query = f"""index=security EventCode=4624 ({hosts_filter})
| stats count values(src) as source_hosts by Account_Name, Logon_Type
| where Logon_Type IN ("3","10")
| sort -count"""
        return self.search(query)


def collect_volatile_evidence(output_dir: str) -> dict:
    """Collect volatile evidence from current system before containment."""
    os.makedirs(output_dir, exist_ok=True)
    evidence = {}

    # Network connections
    try:
        if os.name == "nt":
            result = subprocess.run(["netstat", "-anob"], capture_output=True, text=True)
        else:
            result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
        netconn_file = os.path.join(output_dir, "network_connections.txt")
        with open(netconn_file, "w") as f:
            f.write(result.stdout)
        evidence["network_connections"] = {
            "file": netconn_file,
            "sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        }
    except Exception as e:
        logger.error(f"Failed to collect network connections: {e}")

    # Running processes
    try:
        if os.name == "nt":
            result = subprocess.run(["tasklist", "/V", "/FO", "CSV"], capture_output=True, text=True)
        else:
            result = subprocess.run(["ps", "auxwwf"], capture_output=True, text=True)
        proc_file = os.path.join(output_dir, "running_processes.txt")
        with open(proc_file, "w") as f:
            f.write(result.stdout)
        evidence["running_processes"] = {
            "file": proc_file,
            "sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        }
    except Exception as e:
        logger.error(f"Failed to collect process list: {e}")

    # DNS cache
    try:
        if os.name == "nt":
            result = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True)
        else:
            dns_cache_file = "/var/cache/nscd/hosts" if os.path.exists("/var/cache/nscd/hosts") else ""
            result = subprocess.run(["cat", dns_cache_file], capture_output=True, text=True) if dns_cache_file else None
        if result and result.stdout:
            dns_file = os.path.join(output_dir, "dns_cache.txt")
            with open(dns_file, "w") as f:
                f.write(result.stdout)
            evidence["dns_cache"] = {
                "file": dns_file,
                "sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            }
    except Exception as e:
        logger.error(f"Failed to collect DNS cache: {e}")

    # ARP table
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        arp_file = os.path.join(output_dir, "arp_table.txt")
        with open(arp_file, "w") as f:
            f.write(result.stdout)
        evidence["arp_table"] = {
            "file": arp_file,
            "sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        }
    except Exception as e:
        logger.error(f"Failed to collect ARP table: {e}")

    # Logged-in users
    try:
        if os.name == "nt":
            result = subprocess.run(["query", "user"], capture_output=True, text=True)
        else:
            result = subprocess.run(["who"], capture_output=True, text=True)
        users_file = os.path.join(output_dir, "logged_in_users.txt")
        with open(users_file, "w") as f:
            f.write(result.stdout)
        evidence["logged_in_users"] = {
            "file": users_file,
            "sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        }
    except Exception as e:
        logger.error(f"Failed to collect logged-in users: {e}")

    return evidence


def run_containment(args):
    """Execute the full containment workflow."""
    action_log = ContainmentActionLog(args.incident_id)
    logger.info(f"Starting containment for incident: {args.incident_id}")

    # Step 1: Collect volatile evidence if requested
    if args.collect_evidence:
        evidence_dir = os.path.join(args.output_dir, "evidence", args.incident_id)
        logger.info(f"Collecting volatile evidence to {evidence_dir}")
        evidence = collect_volatile_evidence(evidence_dir)
        for etype, edata in evidence.items():
            action_log.log_action("evidence_collection", etype, "collected", f"SHA256: {edata['sha256']}")

    # Step 2: Block IPs at firewall
    if args.block_ips:
        ip_list = [ip.strip() for ip in args.block_ips.split(",")]
        logger.info(f"Blocking {len(ip_list)} IPs at firewall")
        if os.name == "nt":
            results = FirewallContainment.block_ips_windows_firewall(ip_list)
        else:
            results = FirewallContainment.block_ips_iptables(ip_list)
        for r in results:
            action_log.log_action("ip_block", r["ip"], r["status"], r.get("method", r.get("error", "")))

    # Step 3: Block domains
    if args.block_domains:
        domain_list = [d.strip() for d in args.block_domains.split(",")]
        logger.info(f"Sinkholing {len(domain_list)} domains")
        results = FirewallContainment.block_domains_hosts_file(domain_list)
        for r in results:
            action_log.log_action("domain_block", r["domain"], r["status"], r.get("method", ""))

    # Step 4: Isolate endpoints via CrowdStrike
    if args.crowdstrike_isolate and args.cs_client_id and args.cs_client_secret:
        cs = CrowdStrikeContainment(args.cs_client_id, args.cs_client_secret)
        try:
            cs.authenticate()
            action_log.log_action("edr_auth", "crowdstrike", "success", "API authenticated")
            hostnames = [h.strip() for h in args.crowdstrike_isolate.split(",")]
            for hostname in hostnames:
                device_id = cs.get_device_id_by_hostname(hostname)
                if device_id:
                    cs.contain_host(device_id)
                    action_log.log_action("endpoint_isolation", hostname, "contained", f"Device ID: {device_id}")
                else:
                    action_log.log_action("endpoint_isolation", hostname, "failed", "Device not found in Falcon")
        except Exception as e:
            action_log.log_action("edr_auth", "crowdstrike", "failed", str(e))
            logger.error(f"CrowdStrike containment failed: {e}")

    # Step 5: Disable AD accounts
    if args.disable_accounts and args.ad_server and ldap3_available:
        try:
            ad = ActiveDirectoryContainment(
                args.ad_server, args.ad_domain, args.ad_username, args.ad_password
            )
            accounts = [a.strip() for a in args.disable_accounts.split(",")]
            for account in accounts:
                result = ad.disable_account(account)
                action_log.log_action(
                    "account_disable", account, "disabled" if result else "failed",
                    "AD account disabled" if result else "Account not found",
                )
        except Exception as e:
            action_log.log_action("account_disable", "AD", "failed", str(e))
            logger.error(f"AD containment failed: {e}")

    # Export containment action log
    os.makedirs(args.output_dir, exist_ok=True)
    csv_path = os.path.join(args.output_dir, f"containment_log_{args.incident_id}.csv")
    json_path = os.path.join(args.output_dir, f"containment_report_{args.incident_id}.json")
    action_log.export_csv(csv_path)
    action_log.export_json(json_path)

    logger.info(f"Containment workflow completed for {args.incident_id}")
    logger.info(f"Total actions taken: {len(action_log.actions)}")
    return action_log


def main():
    parser = argparse.ArgumentParser(description="Active Security Breach Containment Automation")
    parser.add_argument("--incident-id", required=True, help="Incident tracking ID (e.g., IR-2024-001)")
    parser.add_argument("--output-dir", default="./containment_output", help="Output directory for logs and reports")
    parser.add_argument("--collect-evidence", action="store_true", help="Collect volatile evidence before containment")
    parser.add_argument("--block-ips", help="Comma-separated list of IPs to block at firewall")
    parser.add_argument("--block-domains", help="Comma-separated list of domains to sinkhole")
    parser.add_argument("--crowdstrike-isolate", help="Comma-separated hostnames to isolate via CrowdStrike")
    parser.add_argument("--cs-client-id", default=os.getenv("CS_CLIENT_ID"), help="CrowdStrike API client ID")
    parser.add_argument("--cs-client-secret", default=os.getenv("CS_CLIENT_SECRET"), help="CrowdStrike API client secret")
    parser.add_argument("--disable-accounts", help="Comma-separated AD accounts to disable")
    parser.add_argument("--ad-server", default=os.getenv("AD_SERVER"), help="Active Directory server address")
    parser.add_argument("--ad-domain", default=os.getenv("AD_DOMAIN"), help="Active Directory domain")
    parser.add_argument("--ad-username", default=os.getenv("AD_USERNAME"), help="AD admin username")
    parser.add_argument("--ad-password", default=os.getenv("AD_PASSWORD"), help="AD admin password")

    args = parser.parse_args()
    run_containment(args)


if __name__ == "__main__":
    main()
