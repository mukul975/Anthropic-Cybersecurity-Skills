#!/usr/bin/env python3
"""Agent for performing entitlement review with SailPoint IdentityIQ.

Automates access certification campaigns, SOD violation detection,
and entitlement review reporting via the SailPoint IdentityIQ REST API.
"""

import requests
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict


class SailPointIIQAgent:
    """Interacts with SailPoint IdentityIQ REST API for entitlement reviews."""

    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def get_certifications(self, phase="Active"):
        """Retrieve certification campaigns filtered by phase."""
        url = f"{self.base_url}/identityiq/scim/v2/Certifications"
        params = {"filter": f'phase eq "{phase}"'}
        resp = self.session.get(url, params=params)
        resp.raise_for_status()
        return resp.json().get("Resources", [])

    def get_certification_items(self, cert_id):
        """Get individual certification items for a campaign."""
        url = f"{self.base_url}/identityiq/scim/v2/Certifications/{cert_id}/items"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json().get("Resources", [])

    def get_identities(self, query=None):
        """Search identities in IdentityIQ."""
        url = f"{self.base_url}/identityiq/scim/v2/Users"
        params = {}
        if query:
            params["filter"] = query
        resp = self.session.get(url, params=params)
        resp.raise_for_status()
        return resp.json().get("Resources", [])

    def get_entitlements(self, identity_id):
        """Get entitlements for a specific identity."""
        url = f"{self.base_url}/identityiq/scim/v2/Users/{identity_id}"
        params = {"attributes": "entitlements,roles,accounts"}
        resp = self.session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def check_sod_violations(self, identity_id):
        """Check for separation of duties violations on an identity."""
        url = f"{self.base_url}/identityiq/rest/identities/{identity_id}/policyViolations"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_campaign_statistics(self, cert_id):
        """Retrieve completion statistics for a certification campaign."""
        url = f"{self.base_url}/identityiq/rest/certifications/{cert_id}/statistics"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def make_certification_decision(self, cert_id, item_id, decision, comments=""):
        """Submit a certification decision (approve/revoke) for an item."""
        url = f"{self.base_url}/identityiq/rest/certifications/{cert_id}/items/{item_id}"
        payload = {
            "decision": decision,
            "comments": comments,
            "decisionDate": datetime.utcnow().isoformat() + "Z",
        }
        resp = self.session.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()

    def generate_review_report(self):
        """Generate a comprehensive entitlement review report."""
        active_certs = self.get_certifications("Active")
        completed_certs = self.get_certifications("End")
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "active_campaigns": [],
            "completed_campaigns": [],
            "summary": {},
        }
        total_items = 0
        total_revoked = 0
        total_approved = 0

        for cert in active_certs:
            stats = self.get_campaign_statistics(cert.get("id", ""))
            campaign_info = {
                "name": cert.get("name", "Unknown"),
                "type": cert.get("type", "Unknown"),
                "phase": cert.get("phase", "Unknown"),
                "due_date": cert.get("expiration", "N/A"),
                "total_items": stats.get("totalEntities", 0),
                "completed_items": stats.get("completedEntities", 0),
                "completion_pct": 0,
            }
            if campaign_info["total_items"] > 0:
                campaign_info["completion_pct"] = round(
                    campaign_info["completed_items"] / campaign_info["total_items"] * 100, 1
                )
            report["active_campaigns"].append(campaign_info)

        for cert in completed_certs:
            stats = self.get_campaign_statistics(cert.get("id", ""))
            approved = stats.get("approvedCount", 0)
            revoked = stats.get("revokedCount", 0)
            items = stats.get("totalEntities", 0)
            total_items += items
            total_revoked += revoked
            total_approved += approved
            report["completed_campaigns"].append({
                "name": cert.get("name", "Unknown"),
                "items_reviewed": items,
                "approved": approved,
                "revoked": revoked,
                "signed_off": cert.get("signedOff", False),
            })

        report["summary"] = {
            "total_campaigns": len(active_certs) + len(completed_certs),
            "active_campaigns": len(active_certs),
            "completed_campaigns": len(completed_certs),
            "total_items_reviewed": total_items,
            "total_approved": total_approved,
            "total_revoked": total_revoked,
            "revocation_rate": round(total_revoked / max(total_items, 1) * 100, 1),
        }
        return report


def main():
    if len(sys.argv) < 4:
        print("Usage: agent.py <iiq_url> <username> <password> [action]")
        print("Actions: report, active, sod-check <identity>")
        sys.exit(1)

    base_url, username, password = sys.argv[1], sys.argv[2], sys.argv[3]
    action = sys.argv[4] if len(sys.argv) > 4 else "report"

    agent = SailPointIIQAgent(base_url, username, password)

    if action == "report":
        report = agent.generate_review_report()
        print(json.dumps(report, indent=2))
    elif action == "active":
        certs = agent.get_certifications("Active")
        for cert in certs:
            print(f"Campaign: {cert.get('name')}")
            print(f"  Phase: {cert.get('phase')}")
            print(f"  Due: {cert.get('expiration', 'N/A')}")
    elif action == "sod-check" and len(sys.argv) > 5:
        violations = agent.check_sod_violations(sys.argv[5])
        print(json.dumps(violations, indent=2))
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
