#!/usr/bin/env python3
"""Agent for building and managing incident response dashboards in Splunk."""

import os
import json
import argparse
from datetime import datetime

import splunklib.client as client
import splunklib.results as results


def connect_splunk(host, port, username, password):
    """Connect to Splunk instance."""
    return client.connect(host=host, port=port, username=username, password=password)


def run_search(service, query, earliest="-24h", latest="now"):
    """Execute a Splunk search and return results."""
    kwargs = {"earliest_time": earliest, "latest_time": latest, "exec_mode": "blocking"}
    job = service.jobs.create(query, **kwargs)
    rows = []
    for result in results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            rows.append(result)
    return rows


def get_incident_summary(service, incident_id):
    """Get summary of a specific incident from notable events."""
    query = f"""
    search index=notable incident_id="{incident_id}"
    | stats count AS total_events, dc(src_ip) AS unique_sources,
            dc(dest) AS unique_destinations,
            min(_time) AS first_seen, max(_time) AS last_seen,
            values(urgency) AS severity
    | eval duration_hours = round((last_seen - first_seen) / 3600, 1)
    """
    return run_search(service, query)


def get_affected_systems(service, incident_id):
    """Track systems affected by an incident."""
    query = f"""
    search index=notable incident_id="{incident_id}"
    | stats count AS events, latest(_time) AS last_activity,
            values(rule_name) AS detections by dest
    | lookup asset_lookup_by_str dest OUTPUT category, owner, priority
    | eval status = case(
        last_activity > relative_time(now(), "-15m"), "Active",
        last_activity > relative_time(now(), "-1h"), "Recent",
        1=1, "Historical")
    | sort - events
    | table dest, category, owner, status, events, detections
    """
    return run_search(service, query)


def get_ioc_spread(service, iocs, earliest="-7d"):
    """Monitor IOC hits across the environment."""
    ip_list = [i for i in iocs if i.get("type") == "ip"]
    domain_list = [i for i in iocs if i.get("type") == "domain"]
    hash_list = [i for i in iocs if i.get("type") == "hash"]

    search_parts = []
    if ip_list:
        ips = " ".join(f'"{i["value"]}"' for i in ip_list)
        search_parts.append(f"src_ip IN ({ips}) OR dest_ip IN ({ips})")
    if domain_list:
        domains = " ".join(f'"{d["value"]}"' for d in domain_list)
        search_parts.append(f"query IN ({domains}) OR dest IN ({domains})")
    if hash_list:
        hashes = " ".join(f'"{h["value"]}"' for h in hash_list)
        search_parts.append(f"file_hash IN ({hashes})")

    condition = " OR ".join(search_parts)
    query = f"""
    search index=* ({condition})
    | stats count AS hits, dc(src_ip) AS sources,
            dc(dest) AS destinations, latest(_time) AS last_seen
      by sourcetype
    | sort - hits
    """
    return run_search(service, query, earliest=earliest)


def get_soc_metrics(service, days=30):
    """Calculate SOC operational metrics."""
    query = f"""
    search index=notable earliest=-{days}d status_label="Resolved*"
    | eval mttr_hours = round((status_end - _time) / 3600, 1)
    | eval mttd_minutes = round((time_of_first_event - orig_time) / 60, 1)
    | stats avg(mttr_hours) AS avg_mttr, median(mttr_hours) AS med_mttr,
            avg(mttd_minutes) AS avg_mttd, median(mttd_minutes) AS med_mttd,
            count AS resolved_count by urgency
    | sort urgency
    """
    return run_search(service, query, earliest=f"-{days}d")


def get_analyst_workload(service, days=7):
    """Get analyst workload distribution."""
    query = f"""
    search index=notable earliest=-{days}d
    | stats count AS assigned, dc(rule_name) AS rule_types,
            avg(eval(if(status_label="Resolved*", (status_end - _time)/3600, null()))) AS avg_resolve_hrs
      by owner
    | sort - assigned
    """
    return run_search(service, query, earliest=f"-{days}d")


def get_alert_disposition(service, days=30):
    """Get alert disposition breakdown."""
    query = f"""
    search index=notable earliest=-{days}d status_label IN ("Resolved*", "Closed*")
    | stats count by disposition
    | eventstats sum(count) AS total
    | eval percentage = round(count / total * 100, 1)
    | sort - count
    | table disposition, count, percentage
    """
    return run_search(service, query, earliest=f"-{days}d")


def get_incident_timeline(service, incident_id):
    """Build chronological incident timeline."""
    query = f"""
    search index=notable incident_id="{incident_id}"
    | sort _time
    | eval phase = case(
        action_type="detection", "Detection",
        action_type="triage", "Triage",
        action_type="containment", "Containment",
        action_type="eradication", "Eradication",
        action_type="recovery", "Recovery",
        1=1, "Other")
    | table _time, phase, action, analyst, details
    """
    return run_search(service, query)


def main():
    parser = argparse.ArgumentParser(description="Incident Response Dashboard Agent")
    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--username", default=os.getenv("SPLUNK_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD", ""))
    parser.add_argument("--incident-id", help="Specific incident ID to track")
    parser.add_argument("--output", default="ir_dashboard_report.json")
    parser.add_argument("--action", choices=[
        "summary", "systems", "iocs", "metrics", "workload", "timeline", "full_dashboard"
    ], default="full_dashboard")
    args = parser.parse_args()

    service = connect_splunk(args.host, args.port, args.username, args.password)
    report = {"generated_at": datetime.utcnow().isoformat(), "data": {}}

    if args.action in ("summary", "full_dashboard") and args.incident_id:
        report["data"]["summary"] = get_incident_summary(service, args.incident_id)
        print(f"[+] Incident summary loaded for {args.incident_id}")

    if args.action in ("systems", "full_dashboard") and args.incident_id:
        report["data"]["affected_systems"] = get_affected_systems(service, args.incident_id)
        print(f"[+] Affected systems: {len(report['data']['affected_systems'])}")

    if args.action in ("metrics", "full_dashboard"):
        report["data"]["soc_metrics"] = get_soc_metrics(service)
        print(f"[+] SOC metrics calculated")

    if args.action in ("workload", "full_dashboard"):
        report["data"]["analyst_workload"] = get_analyst_workload(service)
        print(f"[+] Analyst workload: {len(report['data']['analyst_workload'])} analysts")

    if args.action in ("timeline", "full_dashboard") and args.incident_id:
        report["data"]["timeline"] = get_incident_timeline(service, args.incident_id)
        print(f"[+] Timeline events: {len(report['data']['timeline'])}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Dashboard data saved to {args.output}")


if __name__ == "__main__":
    main()
