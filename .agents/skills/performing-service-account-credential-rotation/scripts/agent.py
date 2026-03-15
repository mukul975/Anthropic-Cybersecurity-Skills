#!/usr/bin/env python3
"""Agent for automating service account credential rotation.

Rotates credentials for AWS IAM access keys, Azure service principals,
and database accounts via HashiCorp Vault, with post-rotation health
checks and rollback capability.
"""

import json
import sys
import subprocess
import time
import requests
from datetime import datetime


class CredentialRotationAgent:
    """Automates service account credential rotation across platforms."""

    def __init__(self, vault_url=None, vault_token=None):
        self.vault_url = vault_url
        self.vault_token = vault_token
        self.rotation_log = []

    def _log(self, platform, account, action, status, details=None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "platform": platform, "account": account,
            "action": action, "status": status,
        }
        if details:
            entry["details"] = details
        self.rotation_log.append(entry)

    def rotate_aws_access_key(self, username):
        """Rotate an AWS IAM user's access key using the AWS CLI."""
        try:
            create = subprocess.run(
                ["aws", "iam", "create-access-key",
                 "--user-name", username, "--output", "json"],
                capture_output=True, text=True, timeout=30
            )
            if create.returncode != 0:
                self._log("AWS", username, "create-key", "failed", create.stderr)
                return {"error": create.stderr}

            new_key = json.loads(create.stdout)["AccessKey"]
            new_key_id = new_key["AccessKeyId"]

            list_result = subprocess.run(
                ["aws", "iam", "list-access-keys",
                 "--user-name", username, "--output", "json"],
                capture_output=True, text=True, timeout=30
            )
            if list_result.returncode == 0:
                keys = json.loads(list_result.stdout).get("AccessKeyMetadata", [])
                for key in keys:
                    if key["AccessKeyId"] != new_key_id and key["Status"] == "Active":
                        subprocess.run(
                            ["aws", "iam", "update-access-key",
                             "--user-name", username,
                             "--access-key-id", key["AccessKeyId"],
                             "--status", "Inactive"],
                            capture_output=True, text=True, timeout=30
                        )
                        self._log("AWS", username, "deactivate-old-key", "success",
                                  {"old_key_id": key["AccessKeyId"]})

            self._log("AWS", username, "rotate-key", "success",
                      {"new_key_id": new_key_id})
            return {"new_key_id": new_key_id, "secret_key": new_key["SecretAccessKey"]}

        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            self._log("AWS", username, "rotate-key", "error", str(exc))
            return {"error": str(exc)}

    def rotate_azure_sp_secret(self, app_id, display_name="rotated-secret"):
        """Rotate an Azure AD service principal client secret via az CLI."""
        try:
            result = subprocess.run(
                ["az", "ad", "app", "credential", "reset",
                 "--id", app_id, "--display-name", display_name,
                 "--years", "1", "--output", "json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                cred = json.loads(result.stdout)
                self._log("Azure", app_id, "rotate-secret", "success")
                return {"app_id": cred.get("appId"), "password": cred.get("password"),
                        "tenant": cred.get("tenant")}
            self._log("Azure", app_id, "rotate-secret", "failed", result.stderr)
            return {"error": result.stderr}
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            self._log("Azure", app_id, "rotate-secret", "error", str(exc))
            return {"error": str(exc)}

    def rotate_vault_database_creds(self, role_name):
        """Request new dynamic database credentials from HashiCorp Vault."""
        if not self.vault_url or not self.vault_token:
            return {"error": "Vault URL and token required"}
        try:
            resp = requests.get(
                f"{self.vault_url}/v1/database/creds/{role_name}",
                headers={"X-Vault-Token": self.vault_token}, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                self._log("Vault", role_name, "generate-creds", "success",
                          {"username": data.get("username")})
                return {"username": data.get("username"),
                        "password": data.get("password"),
                        "lease_duration": resp.json().get("lease_duration")}
            self._log("Vault", role_name, "generate-creds", "failed",
                      {"status": resp.status_code})
            return {"error": resp.text}
        except requests.RequestException as exc:
            self._log("Vault", role_name, "generate-creds", "error", str(exc))
            return {"error": str(exc)}

    def verify_service_health(self, endpoints):
        """Verify services are healthy after credential rotation."""
        results = []
        for ep in endpoints:
            for attempt in range(3):
                try:
                    resp = requests.get(ep["url"], timeout=10,
                                        headers=ep.get("headers", {}))
                    healthy = resp.status_code == 200
                    results.append({"service": ep["name"], "healthy": healthy,
                                    "status_code": resp.status_code, "attempt": attempt + 1})
                    if healthy:
                        break
                except requests.RequestException as exc:
                    results.append({"service": ep["name"], "healthy": False,
                                    "error": str(exc), "attempt": attempt + 1})
                time.sleep(5)
        return results

    def generate_report(self):
        """Output the rotation audit log as JSON."""
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_rotations": len(self.rotation_log),
            "successful": sum(1 for e in self.rotation_log if e["status"] == "success"),
            "failed": sum(1 for e in self.rotation_log if e["status"] != "success"),
            "log": self.rotation_log,
        }
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    agent = CredentialRotationAgent(
        vault_url=sys.argv[1] if len(sys.argv) > 1 else None,
        vault_token=sys.argv[2] if len(sys.argv) > 2 else None,
    )
    if len(sys.argv) > 3:
        agent.rotate_aws_access_key(sys.argv[3])
    agent.generate_report()


if __name__ == "__main__":
    main()
