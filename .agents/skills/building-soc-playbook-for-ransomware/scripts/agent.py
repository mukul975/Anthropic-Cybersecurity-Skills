#!/usr/bin/env python3
"""Ransomware Playbook Automation Agent - Automates SOC ransomware response steps."""

import json
import logging
import argparse
import hashlib
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def check_id_ransomware(sample_path):
    """Upload encrypted file sample to ID Ransomware for variant identification."""
    url = "https://id-ransomware.malwarehunterteam.com/index.php"
    with open(sample_path, "rb") as f:
        files = {"sampleUpload": (sample_path, f)}
        resp = requests.post(url, files=files, timeout=60)
    logger.info("ID Ransomware response status: %d", resp.status_code)
    return resp.text


def query_nomoreransom(ransomware_family):
    """Check No More Ransom Project for available decryptors."""
    url = f"https://www.nomoreransom.org/en/decryption-tools.html"
    resp = requests.get(url, timeout=30)
    if ransomware_family.lower() in resp.text.lower():
        logger.info("Decryptor may be available for %s on No More Ransom", ransomware_family)
        return True
    logger.info("No decryptor found for %s", ransomware_family)
    return False


def query_malwarebazaar_hash(file_hash):
    """Query MalwareBazaar for IOC details by SHA-256 hash."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    resp = requests.post(url, data=data, timeout=30)
    result = resp.json()
    if result.get("query_status") == "ok":
        sample = result["data"][0]
        logger.info(
            "MalwareBazaar match: %s (family: %s)",
            sample.get("sha256_hash"),
            sample.get("signature"),
        )
        return sample
    return None


def isolate_host_crowdstrike(api_base, token, device_id):
    """Isolate a compromised host via CrowdStrike Falcon API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.post(
        f"{api_base}/devices/entities/devices-actions/v2?action_name=contain",
        headers=headers,
        json={"ids": [device_id]},
        timeout=30,
    )
    resp.raise_for_status()
    logger.info("Host %s isolated via CrowdStrike", device_id)
    return resp.json()


def search_iocs_splunk(splunk_url, session_key, ioc_list):
    """Search Splunk for IOC matches across the enterprise."""
    ioc_query = " OR ".join([f'"{ioc}"' for ioc in ioc_list])
    query = (
        f"search index=sysmon (EventCode=1 OR EventCode=11 OR EventCode=3) ({ioc_query}) "
        "| stats count by Computer, EventCode, Image, CommandLine | sort - count"
    )
    resp = requests.post(
        f"{splunk_url}/services/search/jobs",
        headers={"Authorization": f"Splunk {session_key}"},
        data={"search": f"search {query}", "output_mode": "json"},
        verify=False,
    )
    return resp.json()


def generate_ir_report(incident_id, variant, affected_hosts, containment_actions, iocs):
    """Generate a structured ransomware incident response report."""
    report = {
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "ransomware_variant": variant,
        "affected_hosts": affected_hosts,
        "containment_actions": containment_actions,
        "indicators_of_compromise": iocs,
        "phases": {
            "detection": "Completed",
            "containment": "Completed" if containment_actions else "Pending",
            "eradication": "Pending",
            "recovery": "Pending",
        },
    }
    print(json.dumps(report, indent=2))
    return report


def collect_iocs_from_sample(sample_path):
    """Extract IOCs from a ransomware sample file hash."""
    with open(sample_path, "rb") as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    logger.info("Sample SHA-256: %s", sha256)
    logger.info("Sample MD5: %s", md5)

    bazaar_info = query_malwarebazaar_hash(sha256)
    iocs = {"sha256": sha256, "md5": md5}
    if bazaar_info:
        iocs["family"] = bazaar_info.get("signature", "unknown")
        iocs["tags"] = bazaar_info.get("tags", [])
    return iocs


def main():
    parser = argparse.ArgumentParser(description="Ransomware Playbook Automation Agent")
    parser.add_argument("--incident-id", required=True, help="Incident ticket ID")
    parser.add_argument("--sample", help="Path to encrypted file sample")
    parser.add_argument("--device-id", help="CrowdStrike device ID for isolation")
    parser.add_argument("--cs-token", help="CrowdStrike API bearer token")
    parser.add_argument("--splunk-url", help="Splunk management URL")
    parser.add_argument("--splunk-key", help="Splunk session key")
    parser.add_argument("--output", default="ransomware_ir_report.json")
    args = parser.parse_args()

    iocs = {}
    variant = "Unknown"
    containment_actions = []

    if args.sample:
        iocs = collect_iocs_from_sample(args.sample)
        variant = iocs.get("family", "Unknown")
        query_nomoreransom(variant)

    if args.device_id and args.cs_token:
        isolate_host_crowdstrike(
            "https://api.crowdstrike.com", args.cs_token, args.device_id
        )
        containment_actions.append(f"Isolated device {args.device_id} via CrowdStrike")

    if args.splunk_url and args.splunk_key and iocs:
        search_iocs_splunk(args.splunk_url, args.splunk_key, [iocs.get("sha256", "")])

    report = generate_ir_report(
        args.incident_id, variant, [args.device_id] if args.device_id else [], containment_actions, iocs
    )
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("IR report saved to %s", args.output)


if __name__ == "__main__":
    main()
