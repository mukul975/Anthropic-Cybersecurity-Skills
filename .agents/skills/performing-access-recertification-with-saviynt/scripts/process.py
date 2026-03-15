#!/usr/bin/env python3
"""
Saviynt Access Recertification Campaign Manager

Manages access recertification campaigns via Saviynt REST API,
tracks campaign progress, and generates compliance reports.

Requirements:
    pip install requests pandas
"""

import json
import logging
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    print("[ERROR] requests required: pip install requests")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("saviynt_recert")


class SaviyntCampaignManager:
    """Manage Saviynt access recertification campaigns."""

    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip("/")
        self.token = self._authenticate(username, password)

    def _authenticate(self, username, password):
        """Authenticate and retrieve API token."""
        resp = requests.post(
            f"{self.base_url}/ECM/api/login",
            json={"username": username, "password": password},
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise Exception("Authentication failed: no token returned")
        logger.info("Authenticated to Saviynt EIC")
        return token

    def _api_call(self, method, endpoint, json_data=None):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}{endpoint}"
        resp = requests.request(method, url, headers=headers, json=json_data)
        resp.raise_for_status()
        return resp.json()

    def create_campaign(self, name, campaign_type, certifier_type,
                         due_days=14, scope=None):
        """Create a new certification campaign."""
        due_date = (datetime.now(timezone.utc) + timedelta(days=due_days)).strftime(
            "%Y-%m-%d"
        )
        payload = {
            "campaignname": name,
            "campaigntype": campaign_type,  # UserManager, EntitlementOwner, Application
            "certifier": certifier_type,
            "duedate": due_date,
            "reminderdays": "7,10,13",
            "autorevoke": True,
            "autorevokedays": due_days + 1,
            "status": "New",
        }
        if scope:
            payload["scope"] = scope

        result = self._api_call("POST", "/ECM/api/v5/createCampaign", payload)
        campaign_id = result.get("campaignId")
        logger.info(f"Campaign created: {name} (ID: {campaign_id})")
        return result

    def launch_campaign(self, campaign_id):
        """Launch an existing campaign, sending notifications to certifiers."""
        result = self._api_call(
            "POST", "/ECM/api/v5/launchCampaign",
            {"campaignId": campaign_id}
        )
        logger.info(f"Campaign {campaign_id} launched")
        return result

    def get_campaign_status(self, campaign_id):
        """Get campaign progress and statistics."""
        result = self._api_call(
            "GET", f"/ECM/api/v5/getCampaignDetails?campaignId={campaign_id}"
        )
        return {
            "campaign_id": campaign_id,
            "name": result.get("campaignname"),
            "status": result.get("status"),
            "total_items": result.get("totalLineItems", 0),
            "certified": result.get("certifiedCount", 0),
            "revoked": result.get("revokedCount", 0),
            "pending": result.get("pendingCount", 0),
            "completion_pct": result.get("completionPercentage", 0),
            "due_date": result.get("duedate"),
        }

    def get_all_campaigns(self, status=None):
        """List all certification campaigns."""
        params = {}
        if status:
            params["status"] = status
        result = self._api_call("GET", "/ECM/api/v5/getCampaigns")
        campaigns = result.get("campaigns", [])
        if status:
            campaigns = [c for c in campaigns if c.get("status") == status]
        return campaigns

    def get_certification_items(self, campaign_id, status_filter=None):
        """Get individual certification line items for a campaign."""
        result = self._api_call(
            "POST", "/ECM/api/v5/getCertificationDetails",
            {"campaignId": campaign_id, "max": 1000}
        )
        items = result.get("certifications", [])
        if status_filter:
            items = [i for i in items if i.get("status") == status_filter]
        return items

    def generate_compliance_report(self, campaign_id):
        """Generate a compliance-ready report for a completed campaign."""
        status = self.get_campaign_status(campaign_id)
        items = self.get_certification_items(campaign_id)

        certified_items = [i for i in items if i.get("decision") == "Certify"]
        revoked_items = [i for i in items if i.get("decision") == "Revoke"]
        pending_items = [i for i in items if not i.get("decision")]

        report = {
            "report_title": "Access Recertification Compliance Report",
            "campaign_name": status.get("name"),
            "campaign_id": campaign_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {
                "total_items_reviewed": status["total_items"],
                "certified": status["certified"],
                "revoked": status["revoked"],
                "pending": status["pending"],
                "completion_rate": f"{status['completion_pct']}%",
                "certification_rate": (
                    f"{(status['certified'] / status['total_items'] * 100):.1f}%"
                    if status["total_items"] else "N/A"
                ),
                "revocation_rate": (
                    f"{(status['revoked'] / status['total_items'] * 100):.1f}%"
                    if status["total_items"] else "N/A"
                ),
            },
            "findings": [],
        }

        if pending_items:
            report["findings"].append({
                "severity": "High",
                "finding": f"{len(pending_items)} items not reviewed by due date",
                "action": "Auto-revoke or manual follow-up required",
            })

        revoke_rate = status["revoked"] / status["total_items"] if status["total_items"] else 0
        if revoke_rate > 0.20:
            report["findings"].append({
                "severity": "Medium",
                "finding": f"High revocation rate ({revoke_rate:.0%}) suggests over-provisioning",
                "action": "Review provisioning policies and role definitions",
            })

        return report


class RecertificationScheduler:
    """Schedule recurring certification campaigns based on compliance needs."""

    def __init__(self):
        self.schedules = []

    def add_schedule(self, name, frequency_days, campaign_type,
                      certifier_type, scope=None):
        """Add a recurring certification schedule."""
        self.schedules.append({
            "name": name,
            "frequency_days": frequency_days,
            "campaign_type": campaign_type,
            "certifier_type": certifier_type,
            "scope": scope,
            "last_run": None,
        })

    def get_due_campaigns(self):
        """Check which campaigns are due to run."""
        now = datetime.now(timezone.utc)
        due = []
        for schedule in self.schedules:
            if schedule["last_run"] is None:
                due.append(schedule)
            else:
                next_run = schedule["last_run"] + timedelta(days=schedule["frequency_days"])
                if now >= next_run:
                    due.append(schedule)
        return due

    def export_schedule(self, output_path):
        """Export certification schedule for documentation."""
        with open(output_path, "w") as f:
            json.dump({
                "schedules": self.schedules,
                "exported_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2, default=str)
        logger.info(f"Schedule exported to {output_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("Saviynt Access Recertification Campaign Manager")
    print("=" * 60)
    print()
    print("Usage:")
    print("  mgr = SaviyntCampaignManager('https://tenant.saviyntcloud.com',")
    print("      'admin', 'password')")
    print("  mgr.create_campaign('Q1 Review', 'UserManager', 'Manager')")
    print("  mgr.launch_campaign(campaign_id)")
    print("  report = mgr.generate_compliance_report(campaign_id)")
