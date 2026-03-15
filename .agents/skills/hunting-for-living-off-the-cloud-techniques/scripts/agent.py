#!/usr/bin/env python3
"""Agent for hunting living-off-the-cloud (LOTC) techniques using cloud service logs."""

import json
import argparse
import re
from datetime import datetime, timedelta

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

CLOUD_C2_DOMAINS = [
    "*.blob.core.windows.net", "*.s3.amazonaws.com", "*.storage.googleapis.com",
    "*.azurewebsites.net", "*.cloudfront.net", "*.execute-api.amazonaws.com",
    "*.cloudfunctions.net", "*.run.app", "*.appspot.com",
    "pastebin.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
    "discord.com/api/webhooks", "hooks.slack.com", "api.telegram.org",
    "notion.so", "docs.google.com", "drive.google.com",
    "*.firebaseio.com", "*.azureedge.net", "*.ngrok.io",
]

SUSPICIOUS_PATTERNS = {
    "azure_storage_exfil": {
        "description": "Large uploads to Azure Blob Storage",
        "query": {"bool": {"must": [
            {"match": {"event.action": "PutBlob"}},
            {"range": {"http.request.bytes": {"gte": 10485760}}}
        ]}},
    },
    "aws_s3_staging": {
        "description": "Unusual S3 bucket creation or large PutObject",
        "query": {"bool": {"must": [
            {"terms": {"event.action": ["CreateBucket", "PutObject"]}},
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
    },
    "saas_c2_channel": {
        "description": "Outbound connections to SaaS APIs used for C2",
        "query": {"bool": {"must": [
            {"terms": {"dns.question.name": [
                "api.telegram.org", "discord.com", "hooks.slack.com",
                "pastebin.com", "notion.so"
            ]}},
            {"match": {"process.name": {"query": "powershell.exe cmd.exe rundll32.exe", "operator": "or"}}}
        ]}},
    },
    "cloud_function_invoke": {
        "description": "Suspicious invocation of cloud functions for payload delivery",
        "query": {"bool": {"must": [
            {"regexp": {"url.domain": ".*\\.(cloudfunctions\\.net|execute-api\\.amazonaws\\.com|azurewebsites\\.net)"}},
            {"terms": {"process.name": ["certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"]}}
        ]}},
    },
    "github_raw_download": {
        "description": "Downloads from raw GitHub content indicating payload staging",
        "query": {"bool": {"must": [
            {"wildcard": {"url.domain": "*githubusercontent.com"}},
            {"terms": {"process.name": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]}}
        ]}},
    },
}


def hunt_lotc_elastic(es_host, es_index, api_key=None, hours=24):
    """Run LOTC hunting queries against Elasticsearch/Elastic SIEM."""
    if Elasticsearch is None:
        return {"error": "elasticsearch-py not installed"}
    kwargs = {"hosts": [es_host]}
    if api_key:
        kwargs["api_key"] = api_key
    es = Elasticsearch(**kwargs)
    results = {"timestamp": datetime.utcnow().isoformat(), "hunts": [], "total_hits": 0}
    for hunt_name, hunt_def in SUSPICIOUS_PATTERNS.items():
        body = {"query": hunt_def["query"], "size": 100, "sort": [{"@timestamp": "desc"}]}
        resp = es.search(index=es_index, body=body)
        hits = resp["hits"]["total"]["value"]
        events = []
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            events.append({
                "timestamp": src.get("@timestamp"),
                "host": src.get("host", {}).get("name"),
                "process": src.get("process", {}).get("name"),
                "command_line": src.get("process", {}).get("command_line"),
                "destination": src.get("url", {}).get("domain") or src.get("dns", {}).get("question", {}).get("name"),
                "user": src.get("user", {}).get("name"),
            })
        results["hunts"].append({
            "name": hunt_name,
            "description": hunt_def["description"],
            "hits": hits,
            "events": events,
        })
        results["total_hits"] += hits
    return results


def analyze_dns_logs(log_file):
    """Analyze DNS query logs for cloud C2 domain patterns."""
    findings = []
    cloud_regex = re.compile(
        r"(blob\.core\.windows\.net|s3\.amazonaws\.com|storage\.googleapis\.com|"
        r"cloudfunctions\.net|execute-api\.amazonaws\.com|azurewebsites\.net|"
        r"ngrok\.io|firebaseio\.com|pastebin\.com|githubusercontent\.com|"
        r"api\.telegram\.org|discord\.com|hooks\.slack\.com)", re.I
    )
    with open(log_file, "r") as f:
        for line_num, line in enumerate(f, 1):
            match = cloud_regex.search(line)
            if match:
                findings.append({
                    "line": line_num,
                    "matched_domain": match.group(0),
                    "raw": line.strip()[:200],
                })
    return {
        "file": str(log_file),
        "total_matches": len(findings),
        "findings": findings[:500],
        "cloud_services_detected": list(set(f["matched_domain"] for f in findings)),
    }


def main():
    parser = argparse.ArgumentParser(description="Hunt for Living-off-the-Cloud (LOTC) techniques")
    sub = parser.add_subparsers(dest="command")

    hunt = sub.add_parser("hunt", help="Run LOTC hunts against Elasticsearch")
    hunt.add_argument("--es-host", required=True, help="Elasticsearch host URL")
    hunt.add_argument("--index", default="logs-*", help="Index pattern")
    hunt.add_argument("--api-key", help="Elasticsearch API key")
    hunt.add_argument("--hours", type=int, default=24, help="Lookback hours")

    dns = sub.add_parser("dns", help="Analyze DNS logs for cloud C2 domains")
    dns.add_argument("--log-file", required=True, help="Path to DNS query log file")

    args = parser.parse_args()
    if args.command == "hunt":
        result = hunt_lotc_elastic(args.es_host, args.index, args.api_key, args.hours)
    elif args.command == "dns":
        result = analyze_dns_logs(args.log_file)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
