#!/usr/bin/env python3
"""
Device Posture Assessment - Compliance Audit Tool

Queries CrowdStrike ZTA scores, Microsoft Intune compliance status,
and generates a consolidated device posture compliance report.

Requirements:
    pip install requests msal pandas
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any

import requests


class DevicePostureAuditor:
    """Audit device posture compliance across EDR and MDM platforms."""

    def __init__(self, cs_client_id: str, cs_client_secret: str,
                 azure_tenant_id: str, azure_client_id: str, azure_client_secret: str):
        self.cs_client_id = cs_client_id
        self.cs_client_secret = cs_client_secret
        self.azure_tenant_id = azure_tenant_id
        self.azure_client_id = azure_client_id
        self.azure_client_secret = azure_client_secret
        self.cs_token = None
        self.azure_token = None

    def authenticate_crowdstrike(self):
        """Get CrowdStrike API bearer token."""
        resp = requests.post(
            "https://api.crowdstrike.com/oauth2/token",
            data={
                "client_id": self.cs_client_id,
                "client_secret": self.cs_client_secret
            },
            timeout=30
        )
        resp.raise_for_status()
        self.cs_token = resp.json()["access_token"]
        print("[AUTH] CrowdStrike authenticated")

    def authenticate_azure(self):
        """Get Microsoft Graph API token."""
        resp = requests.post(
            f"https://login.microsoftonline.com/{self.azure_tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self.azure_client_id,
                "client_secret": self.azure_client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials"
            },
            timeout=30
        )
        resp.raise_for_status()
        self.azure_token = resp.json()["access_token"]
        print("[AUTH] Microsoft Graph authenticated")

    def get_zta_scores(self) -> dict[str, Any]:
        """Get CrowdStrike ZTA score distribution."""
        print("\n[1/4] Querying CrowdStrike ZTA scores...")
        headers = {"Authorization": f"Bearer {self.cs_token}"}

        # Get all device AIDs with ZTA assessments
        resp = requests.get(
            "https://api.crowdstrike.com/zero-trust-assessment/queries/assessments/v1",
            headers=headers,
            params={"limit": 5000},
            timeout=60
        )
        resp.raise_for_status()
        device_ids = resp.json().get("resources", [])

        if not device_ids:
            print("  No ZTA assessments found")
            return {"total": 0, "distribution": {}}

        # Get detailed assessments in batches of 100
        scores = []
        for i in range(0, len(device_ids), 100):
            batch = device_ids[i:i+100]
            resp = requests.get(
                "https://api.crowdstrike.com/zero-trust-assessment/entities/assessments/v1",
                headers=headers,
                params={"ids": batch},
                timeout=60
            )
            if resp.status_code == 200:
                for resource in resp.json().get("resources", []):
                    assessment = resource.get("assessment", {})
                    scores.append({
                        "aid": resource.get("aid"),
                        "overall": assessment.get("overall", 0),
                        "os_score": assessment.get("os", 0),
                        "sensor_score": assessment.get("sensor_config", 0)
                    })

        # Calculate distribution
        distribution = {
            "critical_90_100": sum(1 for s in scores if s["overall"] >= 90),
            "high_80_89": sum(1 for s in scores if 80 <= s["overall"] < 90),
            "medium_65_79": sum(1 for s in scores if 65 <= s["overall"] < 80),
            "low_50_64": sum(1 for s in scores if 50 <= s["overall"] < 65),
            "blocked_below_50": sum(1 for s in scores if s["overall"] < 50),
        }
        avg_score = sum(s["overall"] for s in scores) / len(scores) if scores else 0

        print(f"  Total devices: {len(scores)}")
        print(f"  Average ZTA score: {avg_score:.1f}")
        print(f"  Distribution: {distribution}")

        return {
            "total": len(scores),
            "average_score": round(avg_score, 1),
            "distribution": distribution,
            "below_threshold_50": distribution["blocked_below_50"]
        }

    def get_intune_compliance(self) -> dict[str, Any]:
        """Get Microsoft Intune device compliance status."""
        print("\n[2/4] Querying Intune compliance status...")
        headers = {"Authorization": f"Bearer {self.azure_token}"}

        resp = requests.get(
            "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
            headers=headers,
            params={
                "$select": "id,deviceName,userPrincipalName,complianceState,"
                           "operatingSystem,osVersion,isEncrypted,lastSyncDateTime,"
                           "managementAgent",
                "$top": 999
            },
            timeout=60
        )
        resp.raise_for_status()
        devices = resp.json().get("value", [])

        stats = {
            "total": len(devices),
            "compliant": 0,
            "noncompliant": 0,
            "in_grace_period": 0,
            "unknown": 0,
            "os_distribution": {},
            "encryption_status": {"encrypted": 0, "not_encrypted": 0},
            "stale_devices": 0,
            "noncompliant_details": []
        }

        now = datetime.now(timezone.utc)
        for device in devices:
            compliance = device.get("complianceState", "unknown")
            os_name = device.get("operatingSystem", "unknown")
            encrypted = device.get("isEncrypted", False)

            stats["os_distribution"][os_name] = stats["os_distribution"].get(os_name, 0) + 1

            if encrypted:
                stats["encryption_status"]["encrypted"] += 1
            else:
                stats["encryption_status"]["not_encrypted"] += 1

            if compliance == "compliant":
                stats["compliant"] += 1
            elif compliance == "noncompliant":
                stats["noncompliant"] += 1
                stats["noncompliant_details"].append({
                    "device": device.get("deviceName"),
                    "user": device.get("userPrincipalName"),
                    "os": f"{os_name} {device.get('osVersion', '')}",
                    "encrypted": encrypted
                })
            elif compliance == "inGracePeriod":
                stats["in_grace_period"] += 1
            else:
                stats["unknown"] += 1

            # Check for stale devices (no sync in 30 days)
            last_sync = device.get("lastSyncDateTime")
            if last_sync:
                try:
                    sync_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                    if (now - sync_dt).days > 30:
                        stats["stale_devices"] += 1
                except (ValueError, TypeError):
                    pass

        compliance_rate = (stats["compliant"] / stats["total"] * 100) if stats["total"] else 0
        print(f"  Total: {stats['total']}, Compliant: {stats['compliant']} ({compliance_rate:.1f}%)")
        print(f"  Non-compliant: {stats['noncompliant']}, Grace period: {stats['in_grace_period']}")
        print(f"  Encryption: {stats['encryption_status']}")
        print(f"  Stale devices (>30d no sync): {stats['stale_devices']}")

        return stats

    def correlate_posture(self, zta: dict, intune: dict) -> dict[str, Any]:
        """Correlate ZTA and MDM compliance for overall posture score."""
        print("\n[3/4] Correlating posture signals...")

        total_devices = max(zta["total"], intune["total"])
        zta_passing = zta["total"] - zta.get("below_threshold_50", 0)
        intune_passing = intune["compliant"] + intune["in_grace_period"]

        overall_compliance = min(
            (zta_passing / zta["total"] * 100) if zta["total"] else 0,
            (intune_passing / intune["total"] * 100) if intune["total"] else 0
        )

        summary = {
            "estimated_total_devices": total_devices,
            "zta_passing_rate": round((zta_passing / zta["total"] * 100) if zta["total"] else 0, 1),
            "intune_passing_rate": round((intune_passing / intune["total"] * 100) if intune["total"] else 0, 1),
            "overall_compliance_rate": round(overall_compliance, 1),
            "risk_level": "LOW" if overall_compliance >= 90 else "MEDIUM" if overall_compliance >= 75 else "HIGH"
        }

        print(f"  ZTA passing: {summary['zta_passing_rate']}%")
        print(f"  Intune passing: {summary['intune_passing_rate']}%")
        print(f"  Overall compliance: {summary['overall_compliance_rate']}%")
        print(f"  Risk level: {summary['risk_level']}")

        return summary

    def generate_report(self, zta: dict, intune: dict, correlated: dict) -> str:
        """Generate consolidated posture report."""
        print("\n[4/4] Generating report...")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        report = f"""
Device Posture Compliance Report
{'=' * 55}
Generated: {now}

1. CROWDSTRIKE ZTA SCORES
   Total devices assessed:      {zta['total']}
   Average ZTA score:           {zta['average_score']}
   Score >= 90 (Critical OK):   {zta['distribution'].get('critical_90_100', 0)}
   Score 80-89 (High OK):       {zta['distribution'].get('high_80_89', 0)}
   Score 65-79 (Medium OK):     {zta['distribution'].get('medium_65_79', 0)}
   Score 50-64 (Low):           {zta['distribution'].get('low_50_64', 0)}
   Score < 50 (BLOCKED):        {zta['distribution'].get('blocked_below_50', 0)}

2. INTUNE COMPLIANCE
   Total managed devices:       {intune['total']}
   Compliant:                   {intune['compliant']}
   Non-compliant:               {intune['noncompliant']}
   In grace period:             {intune['in_grace_period']}
   Stale (>30d no sync):        {intune['stale_devices']}
   Encrypted:                   {intune['encryption_status']['encrypted']}
   Not encrypted:               {intune['encryption_status']['not_encrypted']}

3. OVERALL POSTURE
   ZTA passing rate:            {correlated['zta_passing_rate']}%
   Intune passing rate:         {correlated['intune_passing_rate']}%
   Combined compliance:         {correlated['overall_compliance_rate']}%
   Risk level:                  {correlated['risk_level']}

4. RECOMMENDATIONS
"""
        recs = []
        if zta["distribution"].get("blocked_below_50", 0) > 0:
            recs.append(f"   - {zta['distribution']['blocked_below_50']} devices below ZTA 50 - investigate immediately")
        if intune["encryption_status"]["not_encrypted"] > 0:
            recs.append(f"   - {intune['encryption_status']['not_encrypted']} devices lack encryption - enforce BitLocker/FileVault")
        if intune["stale_devices"] > 0:
            recs.append(f"   - {intune['stale_devices']} stale devices - verify active use or remove")
        if correlated["overall_compliance_rate"] < 95:
            recs.append(f"   - Overall compliance {correlated['overall_compliance_rate']}% below 95% target")
        if not recs:
            recs.append("   - All devices meet compliance requirements")
        report += "\n".join(recs)
        return report


def main():
    if len(sys.argv) < 6:
        print("Usage: python process.py <cs_client_id> <cs_client_secret> "
              "<azure_tenant_id> <azure_client_id> <azure_client_secret>")
        sys.exit(1)

    auditor = DevicePostureAuditor(*sys.argv[1:6])
    auditor.authenticate_crowdstrike()
    auditor.authenticate_azure()

    zta = auditor.get_zta_scores()
    intune = auditor.get_intune_compliance()
    correlated = auditor.correlate_posture(zta, intune)
    report = auditor.generate_report(zta, intune, correlated)
    print(report)

    filename = f"device_posture_report_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(filename, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {filename}")


if __name__ == "__main__":
    main()
