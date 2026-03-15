#!/usr/bin/env python3
"""WMI Persistence Detection Agent - hunts for malicious WMI event subscriptions via Sysmon and WMI queries."""

import json
import argparse
import logging
import subprocess
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
}

SUSPICIOUS_CONSUMERS = ["CommandLineEventConsumer", "ActiveScriptEventConsumer"]

KNOWN_GOOD_FILTERS = [
    "SCM Event Log Filter",
    "BVTFilter",
    "TSLogonFilter",
]


def query_sysmon_wmi_events(evtx_path=None, hours_back=72):
    """Query Sysmon Event IDs 19, 20, 21 for WMI persistence."""
    events = []
    for event_id in [19, 20, 21]:
        cmd = [
            "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
            "/q:*[System[EventID={}]]".format(event_id),
            "/f:xml", "/c:500",
        ]
        if evtx_path:
            cmd = ["wevtutil", "qe", evtx_path, "/lf:true",
                   "/q:*[System[EventID={}]]".format(event_id), "/f:xml", "/c:500"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        for event_xml in re.findall(r"<Event.*?</Event>", result.stdout, re.DOTALL):
            try:
                root = ET.fromstring(event_xml)
                ns = {"s": "http://schemas.microsoft.com/win/2004/08/events/event"}
                data = {}
                for el in root.findall(".//s:Data", ns):
                    data[el.get("Name", "")] = el.text or ""
                events.append({
                    "event_id": event_id,
                    "timestamp": root.findtext(".//s:TimeCreated/@SystemTime", "", ns),
                    "computer": root.findtext(".//s:Computer", "", ns),
                    "operation": data.get("Operation", ""),
                    "event_type": data.get("EventType", ""),
                    "consumer_type": data.get("Type", ""),
                    "name": data.get("Name", ""),
                    "destination": data.get("Destination", ""),
                    "query": data.get("Query", ""),
                    "user": data.get("User", ""),
                    "raw_data": data,
                })
            except ET.ParseError:
                continue
    logger.info("Parsed %d Sysmon WMI events (IDs 19/20/21)", len(events))
    return events


def enumerate_wmi_subscriptions():
    """Enumerate active WMI event subscriptions via PowerShell."""
    subscriptions = {"filters": [], "consumers": [], "bindings": []}
    ps_commands = {
        "filters": "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select Name, Query, QueryLanguage | ConvertTo-Json",
        "consumers": "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer | Select __CLASS, Name, CommandLineTemplate, ScriptText | ConvertTo-Json",
        "bindings": "Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Select Filter, Consumer | ConvertTo-Json",
    }
    for category, ps_cmd in ps_commands.items():
        cmd = ["powershell", "-Command", ps_cmd]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                subscriptions[category] = data
            except json.JSONDecodeError:
                pass
    return subscriptions


def analyze_suspicious_subscriptions(subscriptions):
    """Identify suspicious WMI subscriptions."""
    findings = []
    for consumer in subscriptions.get("consumers", []):
        consumer_class = consumer.get("__CLASS", "")
        name = consumer.get("Name", "")
        if consumer_class in SUSPICIOUS_CONSUMERS:
            severity = "critical"
            cmd_template = consumer.get("CommandLineTemplate", "")
            script_text = consumer.get("ScriptText", "")
            payload = cmd_template or script_text
            if any(kw in payload.lower() for kw in ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "certutil", "bitsadmin"]):
                severity = "critical"
            elif payload:
                severity = "high"
            findings.append({
                "type": "suspicious_consumer",
                "consumer_class": consumer_class,
                "name": name,
                "payload": payload[:500],
                "severity": severity,
                "mitre_technique": "T1546.003",
            })
    for filt in subscriptions.get("filters", []):
        name = filt.get("Name", "")
        query = filt.get("Query", "")
        if name not in KNOWN_GOOD_FILTERS:
            if any(kw in query.lower() for kw in ["win32_processstarttr", "__instancecreationevent", "win32_logonsession"]):
                findings.append({
                    "type": "suspicious_filter",
                    "name": name,
                    "wql_query": query,
                    "severity": "high",
                    "mitre_technique": "T1546.003",
                })
    return findings


def analyze_sysmon_events(events):
    """Analyze Sysmon WMI events for suspicious patterns."""
    findings = []
    for event in events:
        eid = event["event_id"]
        if eid == 20 and event.get("consumer_type") in SUSPICIOUS_CONSUMERS:
            destination = event.get("destination", "")
            suspicious_cmds = ["powershell", "cmd.exe", "wscript", "mshta", "certutil", "regsvr32"]
            if any(cmd in destination.lower() for cmd in suspicious_cmds):
                findings.append({
                    "type": "sysmon_suspicious_consumer",
                    "event_id": eid,
                    "consumer_type": event["consumer_type"],
                    "destination": destination[:500],
                    "computer": event["computer"],
                    "timestamp": event["timestamp"],
                    "user": event["user"],
                    "severity": "critical",
                })
        if eid == 19:
            query = event.get("query", "")
            if "__instancecreationevent" in query.lower() or "win32_processstarttr" in query.lower():
                findings.append({
                    "type": "sysmon_suspicious_filter",
                    "event_id": eid,
                    "wql_query": query,
                    "computer": event["computer"],
                    "timestamp": event["timestamp"],
                    "severity": "high",
                })
    return findings


def generate_report(sysmon_events, live_subscriptions, sysmon_findings, subscription_findings):
    """Generate comprehensive WMI persistence hunt report."""
    all_findings = sysmon_findings + subscription_findings
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "hunt_type": "WMI Event Subscription Persistence (T1546.003)",
        "sysmon_events_analyzed": len(sysmon_events),
        "live_subscriptions": {
            "filters": len(live_subscriptions.get("filters", [])),
            "consumers": len(live_subscriptions.get("consumers", [])),
            "bindings": len(live_subscriptions.get("bindings", [])),
        },
        "total_findings": len(all_findings),
        "critical_findings": sum(1 for f in all_findings if f.get("severity") == "critical"),
        "high_findings": sum(1 for f in all_findings if f.get("severity") == "high"),
        "findings": all_findings,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="WMI Persistence Detection Agent")
    parser.add_argument("--evtx", help="Path to exported Sysmon .evtx file (optional)")
    parser.add_argument("--skip-live", action="store_true", help="Skip live WMI enumeration")
    parser.add_argument("--output", default="wmi_persistence_report.json")
    args = parser.parse_args()

    sysmon_events = query_sysmon_wmi_events(args.evtx)
    sysmon_findings = analyze_sysmon_events(sysmon_events)

    live_subs = {}
    sub_findings = []
    if not args.skip_live:
        live_subs = enumerate_wmi_subscriptions()
        sub_findings = analyze_suspicious_subscriptions(live_subs)

    report = generate_report(sysmon_events, live_subs, sysmon_findings, sub_findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("WMI hunt: %d events, %d findings (%d critical)",
                len(sysmon_events), report["total_findings"], report["critical_findings"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
