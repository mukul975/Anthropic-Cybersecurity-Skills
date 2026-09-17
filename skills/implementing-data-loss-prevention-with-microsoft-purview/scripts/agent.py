#!/usr/bin/env python3
# For authorized Microsoft 365 compliance administration only
"""Microsoft Purview DLP Management Agent - Automates DLP policy deployment and monitoring via Graph API."""

import json
import logging
import argparse
import csv
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class PurviewAuthClient:
    """Handles OAuth2 client credentials authentication for Microsoft Graph."""

    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expiry = None

    def get_token(self):
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        response = requests.post(token_url, data={
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }, timeout=30)
        response.raise_for_status()
        token_data = response.json()
        self.access_token = token_data["access_token"]
        self.token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=token_data.get("expires_in", 3600) - 300
        )
        logger.info("Obtained Graph API access token (expires in %d seconds)",
                     token_data.get("expires_in", 3600))
        return self.access_token

    def headers(self):
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json",
        }


def get_dlp_alerts(auth_client, days_back=7, severity=None, top=50):
    """Retrieve DLP alerts from Microsoft Graph Security API."""
    url = f"{GRAPH_BASE}/security/alerts_v2"
    start_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    filter_parts = [
        "serviceSource eq 'microsoftDataLossPrevention'",
        f"createdDateTime ge {start_date}",
    ]
    if severity:
        filter_parts.append(f"severity eq '{severity}'")
    params = {
        "$filter": " and ".join(filter_parts),
        "$top": top,
        "$orderby": "createdDateTime desc",
    }
    response = requests.get(url, headers=auth_client.headers(), params=params, timeout=60)
    response.raise_for_status()
    alerts = response.json().get("value", [])
    logger.info("Retrieved %d DLP alerts from last %d days", len(alerts), days_back)
    return alerts


def get_sensitivity_labels(auth_client):
    """Retrieve all sensitivity labels from the tenant."""
    url = f"{GRAPH_BETA}/security/informationProtection/sensitivityLabels"
    response = requests.get(url, headers=auth_client.headers(), timeout=30)
    response.raise_for_status()
    labels = response.json().get("value", [])
    logger.info("Retrieved %d sensitivity labels", len(labels))
    return labels


def evaluate_dlp_protection_scope(auth_client, user_id):
    """Evaluate DLP protection scope for a specific user."""
    url = f"{GRAPH_BETA}/users/{user_id}/security/informationProtection/policy/evaluateApplication"
    payload = {
        "contentInfo": {
            "@odata.type": "#microsoft.graph.security.contentInfo",
            "format@odata.type": "#microsoft.graph.security.contentFormat",
            "format": "default",
        }
    }
    response = requests.post(url, headers=auth_client.headers(), json=payload, timeout=30)
    if response.status_code == 200:
        return response.json()
    logger.warning("DLP evaluation for user %s returned status %d", user_id, response.status_code)
    return None


def generate_alert_summary(alerts):
    """Generate summary statistics from DLP alerts."""
    severity_counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    policy_counts = {}
    user_counts = {}
    status_counts = {"new": 0, "inProgress": 0, "resolved": 0}

    for alert in alerts:
        sev = alert.get("severity", "informational").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        title = alert.get("title", "Unknown Policy")
        policy_counts[title] = policy_counts.get(title, 0) + 1

        status = alert.get("status", "new")
        status_counts[status] = status_counts.get(status, 0) + 1

        user_states = alert.get("userStates", [])
        for user_state in user_states:
            upn = user_state.get("userPrincipalName", "Unknown")
            user_counts[upn] = user_counts.get(upn, 0) + 1

    top_policies = sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_alerts": len(alerts),
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "top_policies": [{"policy": p, "count": c} for p, c in top_policies],
        "top_users": [{"user": u, "count": c} for u, c in top_users],
    }


def generate_label_report(labels):
    """Generate a report of sensitivity label configuration."""
    report = []
    for label in labels:
        entry = {
            "id": label.get("id"),
            "name": label.get("name"),
            "description": label.get("description", ""),
            "color": label.get("color", ""),
            "sensitivity": label.get("sensitivity", 0),
            "is_active": label.get("isActive", False),
            "parent_id": label.get("parent", {}).get("id") if label.get("parent") else None,
            "content_formats": label.get("contentFormats", []),
            "has_protection": bool(label.get("protectionEnabled")),
        }
        report.append(entry)
    return sorted(report, key=lambda x: x.get("sensitivity", 0))


def check_policy_health(alerts, threshold_high=10, threshold_override_pct=20.0):
    """Analyze DLP policy health based on alert patterns."""
    findings = []

    high_severity = [a for a in alerts if a.get("severity", "").lower() == "high"]
    if len(high_severity) > threshold_high:
        findings.append({
            "finding": "HIGH_ALERT_VOLUME",
            "severity": "WARNING",
            "detail": f"{len(high_severity)} high-severity DLP alerts in the analysis period. "
                      f"Threshold: {threshold_high}. Investigate for data exfiltration patterns.",
            "recommendation": "Review top-triggered policies and affected users. Check for "
                              "compromised accounts or policy misconfiguration.",
        })

    policy_alert_counts = {}
    for alert in alerts:
        title = alert.get("title", "Unknown")
        policy_alert_counts[title] = policy_alert_counts.get(title, 0) + 1

    for policy, count in policy_alert_counts.items():
        if count > 100:
            findings.append({
                "finding": "NOISY_POLICY",
                "severity": "INFO",
                "detail": f"Policy '{policy}' generated {count} alerts. May indicate "
                          f"false positive issues or overly broad matching rules.",
                "recommendation": "Review SIT confidence thresholds and policy conditions. "
                                  "Consider increasing MinConfidence or adding exclusions.",
            })

    unresolved = [a for a in alerts if a.get("status") == "new"]
    if len(unresolved) > 50:
        findings.append({
            "finding": "UNRESOLVED_ALERT_BACKLOG",
            "severity": "WARNING",
            "detail": f"{len(unresolved)} DLP alerts in 'new' status. Alert fatigue risk.",
            "recommendation": "Assign alerts to compliance analysts. Configure auto-resolution "
                              "for low-severity informational alerts. Implement alert triage SOP.",
        })

    if not findings:
        findings.append({
            "finding": "HEALTHY",
            "severity": "INFO",
            "detail": "DLP policy health checks passed. No anomalies detected.",
            "recommendation": "Continue regular monitoring. Schedule quarterly policy review.",
        })

    return findings


def export_alerts_csv(alerts, output_path):
    """Export DLP alerts to CSV for compliance reporting."""
    fieldnames = [
        "id", "title", "severity", "status", "createdDateTime",
        "user", "description", "category",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            user_states = alert.get("userStates", [])
            upn = user_states[0].get("userPrincipalName", "N/A") if user_states else "N/A"
            writer.writerow({
                "id": alert.get("id", ""),
                "title": alert.get("title", ""),
                "severity": alert.get("severity", ""),
                "status": alert.get("status", ""),
                "createdDateTime": alert.get("createdDateTime", ""),
                "user": upn,
                "description": alert.get("description", ""),
                "category": alert.get("category", ""),
            })
    logger.info("Exported %d alerts to %s", len(alerts), output_path)


def generate_compliance_report(auth_client, days_back=30, output_dir="."):
    """Generate comprehensive DLP compliance report."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Generating DLP compliance report for last %d days", days_back)

    alerts = get_dlp_alerts(auth_client, days_back=days_back, top=500)
    alert_summary = generate_alert_summary(alerts)
    health_findings = check_policy_health(alerts)

    labels = get_sensitivity_labels(auth_client)
    label_report = generate_label_report(labels)

    report = {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "analysis_period_days": days_back,
        "alert_summary": alert_summary,
        "policy_health": health_findings,
        "sensitivity_labels": label_report,
        "alert_details": alerts[:100],
    }

    report_path = output_dir / "dlp_compliance_report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))
    logger.info("Compliance report saved to %s", report_path)

    csv_path = output_dir / "dlp_alerts_export.csv"
    export_alerts_csv(alerts, csv_path)

    print("\n" + "=" * 70)
    print("DLP COMPLIANCE REPORT SUMMARY")
    print("=" * 70)
    print(f"Report Period: Last {days_back} days")
    print(f"Total Alerts: {alert_summary['total_alerts']}")
    print(f"Severity: High={alert_summary['severity_breakdown']['high']}, "
          f"Medium={alert_summary['severity_breakdown']['medium']}, "
          f"Low={alert_summary['severity_breakdown']['low']}")
    print(f"Sensitivity Labels Configured: {len(label_report)}")
    print(f"\nPolicy Health Findings: {len(health_findings)}")
    for finding in health_findings:
        print(f"  [{finding['severity']}] {finding['finding']}: {finding['detail']}")
    print("\nTop Triggered Policies:")
    for entry in alert_summary.get("top_policies", [])[:5]:
        print(f"  - {entry['policy']}: {entry['count']} alerts")
    print("\nTop Affected Users:")
    for entry in alert_summary.get("top_users", [])[:5]:
        print(f"  - {entry['user']}: {entry['count']} alerts")
    print("=" * 70)
    print(f"Full report: {report_path}")
    print(f"Alert export: {csv_path}")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Microsoft Purview DLP Management Agent - Monitor and report on DLP policies"
    )
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True,
                        help="App registration client secret")
    parser.add_argument("--action", required=True,
                        choices=["alerts", "labels", "health", "report"],
                        help="Action to perform")
    parser.add_argument("--days", type=int, default=7,
                        help="Number of days to look back for alerts (default: 7)")
    parser.add_argument("--severity", choices=["high", "medium", "low", "informational"],
                        help="Filter alerts by severity")
    parser.add_argument("--output-dir", default=".",
                        help="Directory for output files (default: current directory)")
    parser.add_argument("--output", help="Output file path (overrides default naming)")
    args = parser.parse_args()

    auth_client = PurviewAuthClient(args.tenant_id, args.client_id, args.client_secret)

    if args.action == "alerts":
        alerts = get_dlp_alerts(auth_client, days_back=args.days, severity=args.severity)
        summary = generate_alert_summary(alerts)
        output = {"summary": summary, "alerts": alerts}
        out_path = args.output or Path(args.output_dir) / "dlp_alerts.json"
        Path(out_path).write_text(json.dumps(output, indent=2, default=str))
        logger.info("Alert report saved to %s (%d alerts)", out_path, len(alerts))

    elif args.action == "labels":
        labels = get_sensitivity_labels(auth_client)
        label_report = generate_label_report(labels)
        out_path = args.output or Path(args.output_dir) / "sensitivity_labels.json"
        Path(out_path).write_text(json.dumps(label_report, indent=2, default=str))
        logger.info("Label report saved to %s (%d labels)", out_path, len(labels))

    elif args.action == "health":
        alerts = get_dlp_alerts(auth_client, days_back=args.days, top=500)
        findings = check_policy_health(alerts)
        out_path = args.output or Path(args.output_dir) / "dlp_health.json"
        Path(out_path).write_text(json.dumps(findings, indent=2, default=str))
        logger.info("Health report saved to %s (%d findings)", out_path, len(findings))
        for finding in findings:
            level = logging.WARNING if finding["severity"] == "WARNING" else logging.INFO
            logger.log(level, "[%s] %s: %s", finding["severity"], finding["finding"],
                       finding["detail"])

    elif args.action == "report":
        generate_compliance_report(auth_client, days_back=args.days, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
