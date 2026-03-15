#!/usr/bin/env python3
"""SOC Metrics and KPI Tracking Agent - Collects and reports SOC performance metrics."""

import json
import time
import logging
import argparse
from datetime import datetime, timedelta

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SPLUNK_BASE = "https://localhost:8089"
HEADERS = {"Content-Type": "application/json"}


def authenticate_splunk(base_url, username, password):
    """Authenticate to Splunk and return session key."""
    resp = requests.post(
        f"{base_url}/services/auth/login",
        data={"username": username, "password": password},
        verify=False,
    )
    resp.raise_for_status()
    session_key = resp.json()["sessionKey"]
    logger.info("Authenticated to Splunk successfully")
    return {"Authorization": f"Splunk {session_key}"}


def run_splunk_search(base_url, headers, query, earliest="-30d", latest="now"):
    """Execute a Splunk search and return results."""
    search_body = {
        "search": f"search {query}",
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": "json",
    }
    resp = requests.post(
        f"{base_url}/services/search/jobs",
        headers=headers,
        data=search_body,
        verify=False,
    )
    resp.raise_for_status()
    sid = resp.json()["sid"]

    for _ in range(120):
        status = requests.get(
            f"{base_url}/services/search/jobs/{sid}",
            headers=headers,
            params={"output_mode": "json"},
            verify=False,
        ).json()
        if status["entry"][0]["content"]["isDone"]:
            break
        time.sleep(2)

    results = requests.get(
        f"{base_url}/services/search/jobs/{sid}/results",
        headers=headers,
        params={"output_mode": "json", "count": 0},
        verify=False,
    ).json()
    return results.get("results", [])


def collect_mttd_metrics(base_url, headers):
    """Collect Mean Time to Detect metrics from Splunk ES notable events."""
    query = (
        'index=notable earliest=-30d status_label="Resolved*" '
        "| eval mttd_seconds = _time - orig_time "
        "| where mttd_seconds > 0 AND mttd_seconds < 86400 "
        "| stats avg(mttd_seconds) AS avg_mttd, median(mttd_seconds) AS med_mttd, "
        "perc90(mttd_seconds) AS p90_mttd by urgency "
        "| eval avg_mttd_min = round(avg_mttd / 60, 1)"
    )
    results = run_splunk_search(base_url, headers, query)
    logger.info("MTTD metrics collected: %d urgency levels", len(results))
    return results


def collect_mttr_metrics(base_url, headers):
    """Collect Mean Time to Respond metrics."""
    query = (
        'index=notable earliest=-30d status_label="Resolved*" '
        "| eval mttr_seconds = status_end - _time "
        "| where mttr_seconds > 0 AND mttr_seconds < 604800 "
        "| stats avg(mttr_seconds) AS avg_mttr, median(mttr_seconds) AS med_mttr by urgency "
        "| eval avg_mttr_hours = round(avg_mttr / 3600, 1)"
    )
    return run_splunk_search(base_url, headers, query)


def collect_alert_quality(base_url, headers):
    """Collect alert disposition and quality metrics."""
    query = (
        "index=notable earliest=-30d "
        "| stats count AS total, "
        'sum(eval(if(status_label="Resolved - True Positive", 1, 0))) AS tp, '
        'sum(eval(if(status_label="Resolved - False Positive", 1, 0))) AS fp '
        "| eval tp_rate = round(tp / total * 100, 1) "
        "| eval fp_rate = round(fp / total * 100, 1) "
        "| eval signal_noise = round(tp / (fp + 0.01), 2)"
    )
    return run_splunk_search(base_url, headers, query)


def collect_analyst_productivity(base_url, headers):
    """Collect per-analyst productivity metrics."""
    query = (
        'index=notable earliest=-30d status_label="Resolved*" '
        "| stats count AS alerts_resolved, "
        "avg(eval((status_end - status_transition_time) / 60)) AS avg_triage_min "
        "by owner "
        "| eval alerts_per_day = round(alerts_resolved / 30, 1) "
        "| sort - alerts_resolved"
    )
    return run_splunk_search(base_url, headers, query)


def generate_report(mttd, mttr, quality, productivity):
    """Generate formatted SOC performance report."""
    report_date = datetime.utcnow().strftime("%B %Y")
    lines = [
        f"SOC PERFORMANCE REPORT - {report_date}",
        "=" * 50,
        "",
        "KEY METRICS (MTTD):",
    ]
    for row in mttd:
        lines.append(
            f"  {row.get('urgency', 'N/A'):15s} Avg: {row.get('avg_mttd_min', 'N/A')} min"
        )

    lines.append("\nKEY METRICS (MTTR):")
    for row in mttr:
        lines.append(
            f"  {row.get('urgency', 'N/A'):15s} Avg: {row.get('avg_mttr_hours', 'N/A')} hrs"
        )

    lines.append("\nALERT QUALITY:")
    for row in quality:
        lines.append(f"  Total Alerts:       {row.get('total', 'N/A')}")
        lines.append(f"  True Positive Rate:  {row.get('tp_rate', 'N/A')}%")
        lines.append(f"  False Positive Rate: {row.get('fp_rate', 'N/A')}%")
        lines.append(f"  Signal-to-Noise:     {row.get('signal_noise', 'N/A')}")

    lines.append("\nANALYST PRODUCTIVITY:")
    for row in productivity:
        lines.append(
            f"  {row.get('owner', 'N/A'):20s} {row.get('alerts_per_day', 'N/A')} alerts/day  "
            f"Avg triage: {row.get('avg_triage_min', 'N/A')} min"
        )

    report = "\n".join(lines)
    print(report)
    return report


def main():
    parser = argparse.ArgumentParser(description="SOC Metrics and KPI Tracking Agent")
    parser.add_argument("--splunk-url", default=SPLUNK_BASE, help="Splunk base URL")
    parser.add_argument("--username", default="admin", help="Splunk username")
    parser.add_argument("--password", required=True, help="Splunk password")
    parser.add_argument("--output", default="soc_metrics_report.json", help="Output JSON file")
    args = parser.parse_args()

    headers = authenticate_splunk(args.splunk_url, args.username, args.password)

    mttd = collect_mttd_metrics(args.splunk_url, headers)
    mttr = collect_mttr_metrics(args.splunk_url, headers)
    quality = collect_alert_quality(args.splunk_url, headers)
    productivity = collect_analyst_productivity(args.splunk_url, headers)

    generate_report(mttd, mttr, quality, productivity)

    output = {
        "generated_at": datetime.utcnow().isoformat(),
        "mttd_metrics": mttd,
        "mttr_metrics": mttr,
        "alert_quality": quality,
        "analyst_productivity": productivity,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
