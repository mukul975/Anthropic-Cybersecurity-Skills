#!/usr/bin/env python3
"""Attack path analysis agent using XM Cyber REST API for exposure management."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    sys.exit("requests required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class XMCyberClient:
    """Client for XM Cyber Continuous Exposure Management API."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def get_scenarios(self) -> List[dict]:
        """List all attack scenarios."""
        resp = self.session.get(f"{self.base_url}/api/v1/scenarios", timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def get_attack_paths(self, scenario_id: str) -> List[dict]:
        """Get attack paths for a specific scenario."""
        resp = self.session.get(
            f"{self.base_url}/api/v1/scenarios/{scenario_id}/attack-paths", timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def get_choke_points(self, scenario_id: str) -> List[dict]:
        """Get choke points where multiple attack paths converge."""
        resp = self.session.get(
            f"{self.base_url}/api/v1/scenarios/{scenario_id}/choke-points", timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def get_critical_assets(self) -> List[dict]:
        """List critical assets defined in the platform."""
        resp = self.session.get(f"{self.base_url}/api/v1/critical-assets", timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def get_entities_at_risk(self, scenario_id: str) -> List[dict]:
        """Get entities at risk of compromise in a scenario."""
        resp = self.session.get(
            f"{self.base_url}/api/v1/scenarios/{scenario_id}/entities-at-risk", timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def get_remediation_actions(self, scenario_id: str) -> List[dict]:
        """Get recommended remediation actions prioritized by impact."""
        resp = self.session.get(
            f"{self.base_url}/api/v1/scenarios/{scenario_id}/remediations", timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])


def analyze_choke_points(choke_points: List[dict]) -> dict:
    """Analyze choke points to identify highest-impact remediation targets."""
    sorted_cp = sorted(choke_points, key=lambda c: c.get("paths_through", 0), reverse=True)
    return {
        "total_choke_points": len(choke_points),
        "top_choke_points": [
            {"entity": cp.get("entity_name", ""), "type": cp.get("entity_type", ""),
             "paths_through": cp.get("paths_through", 0),
             "techniques": cp.get("techniques", [])}
            for cp in sorted_cp[:10]
        ],
    }


def compute_risk_score(attack_paths: List[dict], critical_assets: List[dict]) -> dict:
    """Compute risk score based on attack path complexity and critical asset exposure."""
    reachable = set()
    for path in attack_paths:
        target = path.get("target_asset", "")
        if target:
            reachable.add(target)
    critical_names = {a.get("name", "") for a in critical_assets}
    compromised = reachable & critical_names
    pct = (len(compromised) / len(critical_names) * 100) if critical_names else 0
    return {
        "total_paths": len(attack_paths),
        "unique_targets": len(reachable),
        "critical_assets_reachable": len(compromised),
        "critical_asset_exposure_pct": round(pct, 1),
    }


def generate_report(client: XMCyberClient) -> dict:
    """Generate comprehensive attack path analysis report."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "scenarios": []}
    scenarios = client.get_scenarios()
    critical_assets = client.get_critical_assets()
    report["critical_assets_count"] = len(critical_assets)

    for scenario in scenarios[:5]:
        sid = scenario.get("id", "")
        paths = client.get_attack_paths(sid)
        choke = client.get_choke_points(sid)
        remediations = client.get_remediation_actions(sid)
        report["scenarios"].append({
            "id": sid, "name": scenario.get("name", ""),
            "attack_paths": len(paths),
            "choke_point_analysis": analyze_choke_points(choke),
            "risk_score": compute_risk_score(paths, critical_assets),
            "top_remediations": remediations[:5],
        })
    return report


def main():
    parser = argparse.ArgumentParser(description="XM Cyber Attack Path Analysis Agent")
    parser.add_argument("--url", required=True, help="XM Cyber platform URL")
    parser.add_argument("--api-key", required=True, help="API key")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--output", default="attack_path_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    client = XMCyberClient(args.url, args.api_key)
    report = generate_report(client)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
