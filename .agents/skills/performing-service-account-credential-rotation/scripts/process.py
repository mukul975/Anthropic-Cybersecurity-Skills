#!/usr/bin/env python3
"""
Service Account Credential Rotation Automation

Manages credential rotation for service accounts across Active Directory,
AWS IAM, GCP, and databases. Includes dependency tracking, health verification,
and audit logging.

Requirements:
    pip install boto3 google-cloud-iam requests
"""

import json
import logging
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("credential_rotation")


class CredentialRotator:
    """Manages credential rotation across multiple platforms."""

    def __init__(self, config_file=None):
        self.rotation_log = []
        self.service_dependencies = {}
        if config_file:
            self._load_config(config_file)

    def _load_config(self, config_file):
        with open(config_file) as f:
            config = json.load(f)
        self.service_dependencies = config.get("dependencies", {})

    def generate_password(self, length=32):
        """Generate a cryptographically secure password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in "!@#$%^&*" for c in password)
            if has_upper and has_lower and has_digit and has_special:
                return password

    def rotate_aws_access_key(self, iam_username, profile_name=None):
        """Rotate AWS IAM user access key."""
        try:
            import boto3
        except ImportError:
            logger.error("boto3 not installed")
            return {"success": False, "error": "boto3 required"}

        session = boto3.Session(profile_name=profile_name)
        iam = session.client("iam")

        try:
            new_key = iam.create_access_key(UserName=iam_username)
            new_key_id = new_key["AccessKey"]["AccessKeyId"]
            new_secret = new_key["AccessKey"]["SecretAccessKey"]

            existing_keys = iam.list_access_keys(UserName=iam_username)
            old_keys_deactivated = []
            for key in existing_keys["AccessKeyMetadata"]:
                if key["AccessKeyId"] != new_key_id and key["Status"] == "Active":
                    iam.update_access_key(
                        UserName=iam_username,
                        AccessKeyId=key["AccessKeyId"],
                        Status="Inactive"
                    )
                    old_keys_deactivated.append(key["AccessKeyId"])

            result = {
                "success": True,
                "platform": "AWS IAM",
                "account": iam_username,
                "new_key_id": new_key_id,
                "old_keys_deactivated": old_keys_deactivated,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.rotation_log.append(result)
            logger.info(f"AWS key rotated for {iam_username}: {new_key_id}")
            return result

        except Exception as e:
            result = {
                "success": False,
                "platform": "AWS IAM",
                "account": iam_username,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.rotation_log.append(result)
            logger.error(f"AWS key rotation failed for {iam_username}: {e}")
            return result

    def rotate_gcp_service_account_key(self, service_account_email, project_id):
        """Rotate GCP service account key."""
        try:
            from google.cloud import iam_v1
        except ImportError:
            logger.error("google-cloud-iam not installed")
            return {"success": False, "error": "google-cloud-iam required"}

        try:
            client = iam_v1.IAMClient()
            resource = f"projects/{project_id}/serviceAccounts/{service_account_email}"

            new_key = client.create_service_account_key(
                request={"name": resource, "key_algorithm": "KEY_ALG_RSA_2048"}
            )

            keys = client.list_service_account_keys(request={"name": resource})
            old_keys_deleted = []
            for key in keys.keys:
                if key.name != new_key.name and "user-managed" in str(key.key_origin):
                    try:
                        client.delete_service_account_key(request={"name": key.name})
                        old_keys_deleted.append(key.name)
                    except Exception:
                        pass

            result = {
                "success": True,
                "platform": "GCP",
                "account": service_account_email,
                "new_key_name": new_key.name,
                "old_keys_deleted": old_keys_deleted,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.rotation_log.append(result)
            logger.info(f"GCP key rotated for {service_account_email}")
            return result

        except Exception as e:
            result = {
                "success": False,
                "platform": "GCP",
                "account": service_account_email,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.rotation_log.append(result)
            logger.error(f"GCP key rotation failed: {e}")
            return result

    def rotate_database_password(self, db_type, host, port, admin_user,
                                  admin_password, target_user):
        """Rotate a database user's password."""
        new_password = self.generate_password()

        try:
            if db_type == "postgresql":
                import psycopg2
                conn = psycopg2.connect(
                    host=host, port=port,
                    user=admin_user, password=admin_password,
                    dbname="postgres"
                )
                conn.autocommit = True
                cur = conn.cursor()
                cur.execute(
                    f"ALTER USER \"{target_user}\" WITH PASSWORD %s;",
                    (new_password,)
                )
                cur.close()
                conn.close()

            elif db_type == "mysql":
                import mysql.connector
                conn = mysql.connector.connect(
                    host=host, port=port,
                    user=admin_user, password=admin_password
                )
                cur = conn.cursor()
                cur.execute(
                    f"ALTER USER %s@'%%' IDENTIFIED BY %s;",
                    (target_user, new_password)
                )
                cur.execute("FLUSH PRIVILEGES;")
                cur.close()
                conn.close()

            else:
                return {"success": False, "error": f"Unsupported db_type: {db_type}"}

            result = {
                "success": True,
                "platform": f"Database ({db_type})",
                "account": target_user,
                "host": host,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.rotation_log.append(result)
            logger.info(f"Database password rotated for {target_user}@{host}")
            return result

        except Exception as e:
            result = {
                "success": False,
                "platform": f"Database ({db_type})",
                "account": target_user,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.rotation_log.append(result)
            logger.error(f"Database rotation failed for {target_user}: {e}")
            return result

    def verify_service_health(self, health_endpoints):
        """Verify services are healthy after credential rotation."""
        import requests
        results = []
        for endpoint in health_endpoints:
            try:
                resp = requests.get(endpoint["url"], timeout=10)
                healthy = resp.status_code == 200
                results.append({
                    "service": endpoint["name"],
                    "url": endpoint["url"],
                    "status_code": resp.status_code,
                    "healthy": healthy,
                })
            except requests.RequestException as e:
                results.append({
                    "service": endpoint["name"],
                    "url": endpoint["url"],
                    "healthy": False,
                    "error": str(e),
                })
        return results

    def export_rotation_log(self, output_path):
        """Export rotation audit log to JSON."""
        log_data = {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "total_rotations": len(self.rotation_log),
            "successful": sum(1 for r in self.rotation_log if r.get("success")),
            "failed": sum(1 for r in self.rotation_log if not r.get("success")),
            "rotations": self.rotation_log,
        }
        with open(output_path, "w") as f:
            json.dump(log_data, f, indent=2)
        logger.info(f"Rotation log exported to {output_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("Service Account Credential Rotation Tool")
    print("=" * 60)
    print()
    print("Usage:")
    print("  rotator = CredentialRotator()")
    print("  rotator.rotate_aws_access_key('svc-app-user', profile='prod')")
    print("  rotator.rotate_database_password('postgresql', 'db.example.com',")
    print("      5432, 'admin', 'admin_pw', 'svc_app_user')")
    print("  rotator.export_rotation_log('rotation_log.json')")
