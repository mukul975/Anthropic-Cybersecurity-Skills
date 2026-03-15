#!/usr/bin/env python3
"""Agent for triaging security alerts in Splunk Enterprise Security."""

import splunklib.client as splunk_client
import splunklib.results as splunk_results
import json
import sys
import argparse
from datetime import datetime, timedelta


def connect_splunk(host, port, username, password):
    """Connect to Splunk Enterprise instance."""
    try:
        service = splunk_client.connect(
            host=host, port=port, username=username, password=password,
            autologin=True,
        )
        print(f"[*] Connected to Splunk {host}:{port}")
        return service
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)


def get_notable_events(service, status="new", limit=50):
    """Query notable events from Splunk ES Incident Review."""
    query = f"""| `notable`
| search status="{status}"
| sort - urgency
| table _time, rule_name, src, dest, user, urgency, status, event_id
| head {limit}"""
    print(f"\n[*] Fetching notable events (status={status})...")
    job = service.jobs.create(query, exec_mode="blocking")
    results = []
    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            results.append(result)
            print(f"  [{result.get('urgency', '?')}] {result.get('rule_name', 'Unknown')} "
                  f"| src={result.get('src', 'N/A')} dest={result.get('dest', 'N/A')}")
    print(f"[*] Retrieved {len(results)} notable events")
    return results


def investigate_brute_force(service, src_ip, hours=1):
    """Investigate brute force activity from a source IP."""
    query = f"""search index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
src_ip="{src_ip}" earliest=-{hours}h latest=now
| stats count by src_ip, dest, user, status
| where count > 5
| sort - count"""
    print(f"\n[*] Investigating brute force from {src_ip}...")
    job = service.jobs.create(query, exec_mode="blocking")
    results = []
    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            results.append(result)
            print(f"  {result.get('src_ip')} -> {result.get('dest')} "
                  f"user={result.get('user')} count={result.get('count')}")

    success_query = f"""search index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624
src_ip="{src_ip}" earliest=-{hours}h latest=now
| stats count by src_ip, dest, user
| where count > 0"""
    success_job = service.jobs.create(success_query, exec_mode="blocking")
    for result in splunk_results.JSONResultsReader(success_job.results(output_mode="json")):
        if isinstance(result, dict):
            print(f"  [!] SUCCESSFUL logon: {result.get('user')} on {result.get('dest')}")
    return results


def correlate_across_sources(service, src_ip, hours=24):
    """Correlate alerts across multiple data sources for a given IP."""
    query = f"""search (index=proxy OR index=firewall OR index=dns) src="{src_ip}" earliest=-{hours}h
| stats count by index, sourcetype, action, dest_port
| sort - count"""
    print(f"\n[*] Correlating across sources for {src_ip}...")
    job = service.jobs.create(query, exec_mode="blocking")
    results = []
    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            results.append(result)
            print(f"  {result.get('index')}/{result.get('sourcetype')}: "
                  f"action={result.get('action')} port={result.get('dest_port')} "
                  f"count={result.get('count')}")
    return results


def check_threat_intel(service, indicator, indicator_type="ip"):
    """Check an indicator against Splunk ES threat intelligence."""
    field_map = {"ip": "src", "domain": "url", "hash": "file_hash"}
    field = field_map.get(indicator_type, "src")
    query = f"""| `notable`
| search search_name="Threat*" {field}="{indicator}"
| lookup threat_intel_by_{indicator_type} {indicator_type} AS {field}
  OUTPUT threat_collection, threat_description, weight
| table _time, {field}, threat_collection, threat_description, weight
| where weight >= 1"""
    print(f"\n[*] Checking threat intelligence for {indicator}...")
    job = service.jobs.create(query, exec_mode="blocking")
    matches = []
    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            matches.append(result)
            print(f"  [!] TI Match: {result.get('threat_collection', 'Unknown')} "
                  f"(weight: {result.get('weight', '?')})")
    if not matches:
        print("  [+] No threat intelligence matches")
    return matches


def enrich_with_asset_identity(service, src_ip=None, username=None):
    """Enrich an alert with asset and identity context."""
    results = {}
    if src_ip:
        query = f"""| inputlookup asset_lookup_by_cidr
| where cidrmatch(cidr, "{src_ip}")
| table cidr, category, owner, priority, lat, long"""
        print(f"\n[*] Enriching asset info for {src_ip}...")
        job = service.jobs.create(query, exec_mode="blocking")
        for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
            if isinstance(result, dict):
                results["asset"] = result
                print(f"  Asset: {result.get('category', 'Unknown')} "
                      f"owner={result.get('owner', 'N/A')} priority={result.get('priority', 'N/A')}")

    if username:
        query = f"""| inputlookup identity_lookup_expanded
| search identity="{username}"
| table identity, first, last, department, managedBy, email"""
        print(f"[*] Enriching identity info for {username}...")
        job = service.jobs.create(query, exec_mode="blocking")
        for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
            if isinstance(result, dict):
                results["identity"] = result
                print(f"  User: {result.get('first', '')} {result.get('last', '')} "
                      f"dept={result.get('department', 'N/A')}")
    return results


def get_triage_metrics(service, days=30):
    """Get triage performance metrics."""
    query = f"""| `notable`
| where status_end > 0
| eval triage_time = status_end - _time
| stats avg(triage_time) AS avg_sec, median(triage_time) AS med_sec,
        count by rule_name, status_label
| eval avg_min = round(avg_sec/60, 1)
| sort - count
| head 20
| table rule_name, status_label, count, avg_min"""
    print(f"\n[*] Fetching triage metrics (last {days} days)...")
    job = service.jobs.create(query, exec_mode="blocking",
                               earliest_time=f"-{days}d", latest_time="now")
    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
        if isinstance(result, dict):
            print(f"  {result.get('rule_name', 'Unknown')}: "
                  f"{result.get('count', 0)} alerts, avg triage: {result.get('avg_min', '?')} min")


def generate_triage_report(notable, correlations, ti_matches, enrichment, output_path):
    """Generate a structured triage report."""
    report = {
        "triage_date": datetime.now().isoformat(),
        "notable_events": notable,
        "correlations": correlations,
        "threat_intel_matches": ti_matches,
        "enrichment": enrichment,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Triage report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Splunk ES Alert Triage Agent")
    parser.add_argument("action", choices=["queue", "investigate", "correlate", "threat-intel",
                                           "enrich", "metrics", "full-triage"])
    parser.add_argument("--host", default="localhost", help="Splunk host")
    parser.add_argument("--port", type=int, default=8089, help="Splunk management port")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--src-ip", help="Source IP to investigate")
    parser.add_argument("--user", help="Username to enrich")
    parser.add_argument("--indicator", help="IOC to check against threat intel")
    parser.add_argument("--status", default="new", help="Notable event status filter")
    parser.add_argument("-o", "--output", default="triage_report.json")
    args = parser.parse_args()

    service = connect_splunk(args.host, args.port, args.username, args.password)

    if args.action == "queue":
        get_notable_events(service, args.status)
    elif args.action == "investigate":
        investigate_brute_force(service, args.src_ip)
    elif args.action == "correlate":
        correlate_across_sources(service, args.src_ip)
    elif args.action == "threat-intel":
        check_threat_intel(service, args.indicator)
    elif args.action == "enrich":
        enrich_with_asset_identity(service, args.src_ip, args.user)
    elif args.action == "metrics":
        get_triage_metrics(service)
    elif args.action == "full-triage":
        notable = get_notable_events(service, args.status)
        corr = correlate_across_sources(service, args.src_ip) if args.src_ip else []
        ti = check_threat_intel(service, args.src_ip) if args.src_ip else []
        enrich = enrich_with_asset_identity(service, args.src_ip, args.user)
        generate_triage_report(notable, corr, ti, enrich, args.output)


if __name__ == "__main__":
    main()
