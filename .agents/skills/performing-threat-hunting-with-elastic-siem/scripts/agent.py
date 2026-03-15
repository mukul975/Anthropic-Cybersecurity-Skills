#!/usr/bin/env python3
"""Threat hunting agent for Elastic SIEM using elasticsearch-py."""

import json
import sys
from datetime import datetime, timedelta

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("Install: pip install elasticsearch")
    sys.exit(1)


def get_es_client(host="https://localhost:9200", api_key=None, verify_certs=True):
    kwargs = {"hosts": [host], "verify_certs": verify_certs}
    if api_key:
        kwargs["api_key"] = api_key
    return Elasticsearch(**kwargs)


def hunt_lolbins(es, index="logs-endpoint.events.process-*", days=30):
    """Hunt for living-off-the-land binary abuse."""
    lolbins = [
        "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "cscript.exe", "wscript.exe", "bitsadmin.exe",
    ]
    suspicious_args = [
        "-urlcache", "-split", "-decode", "-encode", "javascript:",
        "scrobj.dll", "/transfer", "-encodedcommand", "-enc",
    ]
    query = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {"terms": {"process.name": lolbins}},
                    {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                ],
                "should": [{"match_phrase": {"process.args": arg}} for arg in suspicious_args],
                "minimum_should_match": 1,
                "must_not": [
                    {"terms": {"process.parent.name": ["ccmexec.exe", "sccm.exe"]}},
                ],
            }
        },
        "sort": [{"@timestamp": "desc"}],
    }
    result = es.search(index=index, body=query)
    hits = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        hits.append({
            "timestamp": src.get("@timestamp"),
            "host": src.get("host", {}).get("name"),
            "user": src.get("user", {}).get("name"),
            "process": src.get("process", {}).get("name"),
            "args": src.get("process", {}).get("args"),
            "parent": src.get("process", {}).get("parent", {}).get("name"),
        })
    return {"hunt": "LOLBin Abuse", "total_hits": result["hits"]["total"]["value"], "findings": hits}


def hunt_credential_dumping(es, index="logs-endpoint.events.process-*", days=30):
    """Hunt for credential dumping activity (T1003)."""
    query = {
        "size": 50,
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                "should": [
                    {"bool": {"must": [
                        {"terms": {"process.name": ["procdump.exe", "procdump64.exe", "rundll32.exe"]}},
                        {"match_phrase": {"process.args": "lsass"}},
                    ]}},
                    {"bool": {"must": [
                        {"term": {"process.name": "mimikatz.exe"}},
                    ]}},
                    {"bool": {"must": [
                        {"term": {"process.name": "powershell.exe"}},
                        {"match_phrase": {"process.args": "sekurlsa"}},
                    ]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    result = es.search(index=index, body=query)
    hits = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        hits.append({
            "timestamp": src.get("@timestamp"),
            "host": src.get("host", {}).get("name"),
            "process": src.get("process", {}).get("name"),
            "args": src.get("process", {}).get("args"),
        })
    return {"hunt": "Credential Dumping (T1003)", "total_hits": result["hits"]["total"]["value"], "findings": hits}


def hunt_lateral_movement(es, index="logs-endpoint.events.*", days=14):
    """Hunt for lateral movement patterns (T1021)."""
    query = {
        "size": 50,
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                "should": [
                    {"term": {"process.name": "psexesvc.exe"}},
                    {"bool": {"must": [
                        {"term": {"process.name": "powershell.exe"}},
                        {"match_phrase": {"process.args": "invoke-command"}},
                    ]}},
                    {"bool": {"must": [
                        {"term": {"event.action": "network_flow"}},
                        {"terms": {"destination.port": [445, 135, 5985, 5986]}},
                    ]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    result = es.search(index=index, body=query)
    hits = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        hits.append({
            "timestamp": src.get("@timestamp"),
            "host": src.get("host", {}).get("name"),
            "process": src.get("process", {}).get("name"),
            "source_ip": src.get("source", {}).get("ip"),
            "dest_ip": src.get("destination", {}).get("ip"),
            "dest_port": src.get("destination", {}).get("port"),
        })
    return {"hunt": "Lateral Movement (T1021)", "total_hits": result["hits"]["total"]["value"], "findings": hits}


def hunt_persistence(es, index="logs-endpoint.events.*", days=30):
    """Hunt for persistence mechanisms (T1053, T1547)."""
    query = {
        "size": 50,
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                "should": [
                    {"bool": {"must": [
                        {"term": {"process.name": "schtasks.exe"}},
                        {"match_phrase": {"process.args": "/create"}},
                    ]}},
                    {"bool": {"must": [
                        {"term": {"process.name": "reg.exe"}},
                        {"match_phrase": {"process.args": "CurrentVersion\\Run"}},
                    ]}},
                    {"bool": {"must": [
                        {"term": {"event.action": "registry_value_set"}},
                        {"wildcard": {"registry.path": "*CurrentVersion\\Run*"}},
                    ]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    result = es.search(index=index, body=query)
    hits = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        hits.append({
            "timestamp": src.get("@timestamp"),
            "host": src.get("host", {}).get("name"),
            "process": src.get("process", {}).get("name"),
            "args": src.get("process", {}).get("args"),
        })
    return {"hunt": "Persistence (T1053/T1547)", "total_hits": result["hits"]["total"]["value"], "findings": hits}


def create_detection_rule(es, kibana_url, name, query, severity="high", risk_score=73):
    """Deploy a detection rule to Elastic Security via API."""
    import requests
    rule = {
        "name": name,
        "description": f"Detection rule created from threat hunt: {name}",
        "risk_score": risk_score,
        "severity": severity,
        "type": "query",
        "query": query,
        "index": ["logs-endpoint.events.process-*"],
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "tags": ["Hunting", "Auto-generated"],
    }
    return rule


def run_all_hunts(es, days=30):
    hunts = []
    hunts.append(hunt_lolbins(es, days=days))
    hunts.append(hunt_credential_dumping(es, days=days))
    hunts.append(hunt_lateral_movement(es, days=min(days, 14)))
    hunts.append(hunt_persistence(es, days=days))
    return hunts


def print_hunt_report(hunts):
    print("THREAT HUNT REPORT")
    print("=" * 50)
    print(f"Date: {datetime.now().isoformat()}")
    total_findings = sum(h["total_hits"] for h in hunts)
    print(f"Total Findings: {total_findings}\n")
    for hunt in hunts:
        print(f"--- {hunt['hunt']} ---")
        print(f"Hits: {hunt['total_hits']}")
        for f in hunt["findings"][:5]:
            print(f"  {f.get('timestamp', 'N/A')} | {f.get('host', 'N/A')} | "
                  f"{f.get('process', 'N/A')} | {f.get('args', '')}")
        if hunt["total_hits"] > 5:
            print(f"  ... and {hunt['total_hits'] - 5} more")
        print()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:9200"
    es = get_es_client(host=host, verify_certs=False)
    results = run_all_hunts(es)
    print_hunt_report(results)
