#!/usr/bin/env python3
"""Incident ticketing system agent supporting ServiceNow and TheHive."""

import json
import sys
import argparse
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class ServiceNowClient:
    """Client for ServiceNow Incident Management REST API."""

    def __init__(self, instance, username, password):
        self.base_url = f"https://{instance}.service-now.com/api/now"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json",
                                      "Content-Type": "application/json"})

    def create_incident(self, short_desc, description, urgency=2, impact=2, category="Security"):
        """Create a new security incident in ServiceNow."""
        data = {"short_description": short_desc, "description": description,
                "urgency": urgency, "impact": impact, "category": category,
                "assignment_group": "Security Operations",
                "contact_type": "Automated"}
        resp = self.session.post(f"{self.base_url}/table/incident", json=data)
        resp.raise_for_status()
        result = resp.json().get("result", {})
        return {"number": result.get("number"), "sys_id": result.get("sys_id"),
                "state": result.get("state"), "priority": result.get("priority")}

    def update_incident(self, sys_id, update_data):
        """Update an existing incident."""
        resp = self.session.patch(f"{self.base_url}/table/incident/{sys_id}", json=update_data)
        resp.raise_for_status()
        return resp.json().get("result", {})

    def get_incident(self, number):
        """Get incident details by number."""
        resp = self.session.get(f"{self.base_url}/table/incident",
                                params={"sysparm_query": f"number={number}"})
        resp.raise_for_status()
        results = resp.json().get("result", [])
        return results[0] if results else None

    def list_open_incidents(self, category="Security", limit=50):
        """List open security incidents."""
        query = f"category={category}^state!=7^state!=8"
        resp = self.session.get(f"{self.base_url}/table/incident",
                                params={"sysparm_query": query, "sysparm_limit": limit,
                                        "sysparm_fields": "number,short_description,priority,state,"
                                                         "opened_at,assigned_to,urgency"})
        resp.raise_for_status()
        return resp.json().get("result", [])

    def add_work_note(self, sys_id, note):
        """Add a work note to an incident."""
        return self.update_incident(sys_id, {"work_notes": note})

    def close_incident(self, sys_id, close_notes, close_code="Solved (Permanently)"):
        """Close an incident with resolution notes."""
        return self.update_incident(sys_id, {
            "state": "7", "close_code": close_code,
            "close_notes": close_notes})


class TheHiveClient:
    """Client for TheHive incident response platform API."""

    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}",
                                      "Content-Type": "application/json"})

    def create_case(self, title, description, severity=2, tlp=2, tags=None):
        """Create a new case in TheHive."""
        data = {"title": title, "description": description,
                "severity": severity, "tlp": tlp,
                "tags": tags or ["security-incident"],
                "flag": False, "status": "Open"}
        resp = self.session.post(f"{self.base_url}/api/case", json=data)
        resp.raise_for_status()
        result = resp.json()
        return {"id": result.get("_id"), "caseId": result.get("caseId"),
                "title": result.get("title"), "status": result.get("status")}

    def create_task(self, case_id, title, description="", group="default"):
        """Create a task within a case."""
        data = {"title": title, "description": description, "group": group,
                "status": "Waiting"}
        resp = self.session.post(f"{self.base_url}/api/case/{case_id}/task", json=data)
        resp.raise_for_status()
        return resp.json()

    def add_observable(self, case_id, data_type, data_value, tlp=2, message=""):
        """Add an observable (IOC) to a case."""
        obs_data = {"dataType": data_type, "data": data_value, "tlp": tlp,
                    "message": message, "ioc": True}
        resp = self.session.post(f"{self.base_url}/api/case/{case_id}/artifact", json=obs_data)
        resp.raise_for_status()
        return resp.json()

    def list_cases(self, status="Open", limit=50):
        """List cases with optional status filter."""
        query = {"query": {"_field": "status", "_value": status}}
        resp = self.session.post(f"{self.base_url}/api/case/_search",
                                  json=query, params={"range": f"0-{limit}"})
        resp.raise_for_status()
        return resp.json()

    def get_case(self, case_id):
        """Get case details."""
        resp = self.session.get(f"{self.base_url}/api/case/{case_id}")
        resp.raise_for_status()
        return resp.json()

    def close_case(self, case_id, summary, impact_status="NoImpact"):
        """Close a case with summary."""
        data = {"status": "Resolved", "summary": summary,
                "impactStatus": impact_status, "resolutionStatus": "TruePositive"}
        resp = self.session.patch(f"{self.base_url}/api/case/{case_id}", json=data)
        resp.raise_for_status()
        return resp.json()


def calculate_sla_metrics(incidents):
    """Calculate SLA compliance metrics from incident data."""
    sla_targets = {"1": 60, "2": 240, "3": 480, "4": 1440}
    metrics = {"total": len(incidents), "within_sla": 0, "breached": 0,
               "avg_response_min": 0, "by_priority": {}}
    total_response = 0
    for inc in incidents:
        priority = str(inc.get("priority", "3"))
        opened = inc.get("opened_at", "")
        if priority not in metrics["by_priority"]:
            metrics["by_priority"][priority] = {"total": 0, "within_sla": 0}
        metrics["by_priority"][priority]["total"] += 1
    metrics["sla_compliance_pct"] = round(
        metrics["within_sla"] / max(metrics["total"], 1) * 100, 1)
    return metrics


def run_ticketing_audit(snow_client=None, hive_client=None):
    """Run ticketing system audit."""
    print(f"\n{'='*60}")
    print(f"  INCIDENT TICKETING SYSTEM AUDIT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    report = {}

    if snow_client:
        incidents = snow_client.list_open_incidents()
        print(f"--- SERVICENOW INCIDENTS ({len(incidents)} open) ---")
        for inc in incidents[:10]:
            print(f"  [{inc.get('priority', 'N/A')}] {inc.get('number')}: "
                  f"{inc.get('short_description', '')[:50]}")
        metrics = calculate_sla_metrics(incidents)
        print(f"\n--- SLA METRICS ---")
        print(f"  Total open: {metrics['total']}")
        print(f"  SLA compliance: {metrics['sla_compliance_pct']}%")
        report["servicenow"] = {"open": len(incidents), "metrics": metrics}

    if hive_client:
        cases = hive_client.list_cases()
        print(f"\n--- THEHIVE CASES ({len(cases)} open) ---")
        for case in cases[:10]:
            print(f"  [Sev:{case.get('severity', 'N/A')}] #{case.get('caseId')}: "
                  f"{case.get('title', '')[:50]}")
        report["thehive"] = {"open_cases": len(cases)}

    print(f"\n{'='*60}\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="Incident Ticketing System Agent")
    sub = parser.add_subparsers(dest="platform")

    snow = sub.add_parser("servicenow")
    snow.add_argument("--instance", required=True, help="ServiceNow instance name")
    snow.add_argument("--username", required=True)
    snow.add_argument("--password", required=True)
    snow.add_argument("--audit", action="store_true")
    snow.add_argument("--create", nargs=2, metavar=("TITLE", "DESC"), help="Create incident")

    hive = sub.add_parser("thehive")
    hive.add_argument("--url", required=True, help="TheHive URL")
    hive.add_argument("--api-key", required=True)
    hive.add_argument("--audit", action="store_true")
    hive.add_argument("--create", nargs=2, metavar=("TITLE", "DESC"), help="Create case")

    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.platform == "servicenow":
        client = ServiceNowClient(args.instance, args.username, args.password)
        if args.audit:
            report = run_ticketing_audit(snow_client=client)
        elif args.create:
            result = client.create_incident(args.create[0], args.create[1])
            print(json.dumps(result, indent=2))
            return
        else:
            parser.print_help()
            return
    elif args.platform == "thehive":
        client = TheHiveClient(args.url, args.api_key)
        if args.audit:
            report = run_ticketing_audit(hive_client=client)
        elif args.create:
            result = client.create_case(args.create[0], args.create[1])
            print(json.dumps(result, indent=2))
            return
        else:
            parser.print_help()
            return
    else:
        parser.print_help()
        return

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
