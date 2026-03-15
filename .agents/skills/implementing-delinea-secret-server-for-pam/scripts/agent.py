#!/usr/bin/env python3
"""Delinea Secret Server PAM agent for privileged credential management."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class SecretServerClient:
    """Client for Delinea Secret Server REST API."""

    def __init__(self, base_url, username, password, domain=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token = self._authenticate(username, password, domain)
        self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def _authenticate(self, username, password, domain):
        """Authenticate and retrieve OAuth2 bearer token."""
        url = f"{self.base_url}/oauth2/token"
        data = {"grant_type": "password", "username": username, "password": password}
        if domain:
            data["domain"] = domain
        resp = self.session.post(url, data=data)
        resp.raise_for_status()
        return resp.json()["access_token"]

    def search_secrets(self, search_text=None, folder_id=None, secret_template_id=None):
        """Search for secrets with optional filters."""
        params = {}
        if search_text:
            params["filter.searchText"] = search_text
        if folder_id:
            params["filter.folderId"] = folder_id
        if secret_template_id:
            params["filter.secretTemplateId"] = secret_template_id
        resp = self.session.get(f"{self.base_url}/api/v1/secrets", params=params)
        resp.raise_for_status()
        return resp.json().get("records", [])

    def get_secret(self, secret_id):
        """Retrieve a secret by ID."""
        resp = self.session.get(f"{self.base_url}/api/v1/secrets/{secret_id}")
        resp.raise_for_status()
        return resp.json()

    def create_secret(self, name, template_id, folder_id, fields):
        """Create a new secret in the vault."""
        items = [{"fieldId": fid, "itemValue": val} for fid, val in fields.items()]
        data = {"name": name, "secretTemplateId": template_id,
                "folderId": folder_id, "items": items}
        resp = self.session.post(f"{self.base_url}/api/v1/secrets", json=data)
        resp.raise_for_status()
        return resp.json()

    def get_secret_templates(self):
        """List available secret templates."""
        resp = self.session.get(f"{self.base_url}/api/v1/secret-templates")
        resp.raise_for_status()
        return resp.json().get("records", [])

    def get_folders(self, parent_id=None):
        """List folders, optionally under a parent."""
        params = {}
        if parent_id:
            params["filter.parentFolderId"] = parent_id
        resp = self.session.get(f"{self.base_url}/api/v1/folders", params=params)
        resp.raise_for_status()
        return resp.json().get("records", [])

    def rotate_secret_password(self, secret_id):
        """Trigger password rotation for a secret (Remote Password Changing)."""
        resp = self.session.post(
            f"{self.base_url}/api/v1/secrets/{secret_id}/change-password")
        resp.raise_for_status()
        return resp.json()

    def get_secret_audit(self, secret_id):
        """Get audit trail for a specific secret."""
        resp = self.session.get(f"{self.base_url}/api/v1/secrets/{secret_id}/audits")
        resp.raise_for_status()
        return resp.json().get("records", [])

    def checkout_secret(self, secret_id):
        """Check out a secret for exclusive access."""
        resp = self.session.post(
            f"{self.base_url}/api/v1/secrets/{secret_id}/check-out")
        resp.raise_for_status()
        return resp.json()

    def checkin_secret(self, secret_id):
        """Check in a previously checked-out secret."""
        resp = self.session.post(
            f"{self.base_url}/api/v1/secrets/{secret_id}/check-in")
        resp.raise_for_status()
        return resp.json()

    def get_users(self):
        """List all users."""
        resp = self.session.get(f"{self.base_url}/api/v1/users")
        resp.raise_for_status()
        return resp.json().get("records", [])

    def get_roles(self):
        """List all roles."""
        resp = self.session.get(f"{self.base_url}/api/v1/roles")
        resp.raise_for_status()
        return resp.json().get("records", [])


def run_pam_audit(client):
    """Run a PAM security audit."""
    print(f"\n{'='*60}")
    print(f"  DELINEA SECRET SERVER PAM AUDIT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    templates = client.get_secret_templates()
    print(f"--- SECRET TEMPLATES ({len(templates)}) ---")
    for t in templates[:10]:
        print(f"  [{t['id']}] {t['name']}")

    folders = client.get_folders()
    print(f"\n--- FOLDERS ({len(folders)}) ---")
    for f in folders[:10]:
        print(f"  [{f['id']}] {f['folderName']}")

    secrets = client.search_secrets()
    print(f"\n--- SECRETS ({len(secrets)}) ---")
    for s in secrets[:10]:
        print(f"  [{s['id']}] {s['name']} (Template: {s.get('secretTemplateName', 'N/A')})")

    users = client.get_users()
    print(f"\n--- USERS ({len(users)}) ---")
    for u in users[:10]:
        print(f"  [{u['id']}] {u.get('userName', 'N/A')} - Enabled: {u.get('isDisabled', True)}")

    roles = client.get_roles()
    print(f"\n--- ROLES ({len(roles)}) ---")
    for r in roles[:10]:
        print(f"  [{r['id']}] {r['name']}")

    print(f"\n{'='*60}\n")
    return {"templates": len(templates), "folders": len(folders),
            "secrets": len(secrets), "users": len(users), "roles": len(roles)}


def main():
    parser = argparse.ArgumentParser(description="Delinea Secret Server PAM Agent")
    parser.add_argument("--url", required=True, help="Secret Server base URL")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--domain", help="AD domain (optional)")
    parser.add_argument("--audit", action="store_true", help="Run PAM audit")
    parser.add_argument("--search", help="Search secrets by keyword")
    parser.add_argument("--rotate", type=int, help="Rotate password for secret ID")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    client = SecretServerClient(args.url, args.username, args.password, args.domain)

    if args.audit:
        report = run_pam_audit(client)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
    elif args.search:
        results = client.search_secrets(search_text=args.search)
        for s in results:
            print(f"  [{s['id']}] {s['name']}")
    elif args.rotate:
        result = client.rotate_secret_password(args.rotate)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
