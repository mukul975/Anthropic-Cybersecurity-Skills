#!/usr/bin/env python3
"""Threat Intelligence Platform evaluation agent for MISP, OpenCTI, and ThreatConnect."""

import json
import sys
import urllib.request
import urllib.parse
import ssl
from datetime import datetime


class TIPEvaluator:
    """Evaluate and test TIP platform capabilities."""

    EVALUATION_CRITERIA = {
        "core_functions": {
            "stix_support": {"weight": 10, "description": "STIX 2.1 import/export support"},
            "taxii_server": {"weight": 8, "description": "TAXII 2.1 server capability"},
            "rest_api": {"weight": 9, "description": "RESTful API for automation"},
            "deduplication": {"weight": 7, "description": "Indicator deduplication and TTL management"},
            "tlp_enforcement": {"weight": 8, "description": "TLP classification enforcement"},
            "attack_mapping": {"weight": 6, "description": "MITRE ATT&CK integration"},
            "graph_viz": {"weight": 5, "description": "Graph visualization of relationships"},
        },
        "integrations": {
            "siem_integration": {"weight": 9, "description": "SIEM bi-directional integration"},
            "edr_integration": {"weight": 7, "description": "EDR IOC push capability"},
            "soar_integration": {"weight": 7, "description": "SOAR playbook integration"},
            "firewall_integration": {"weight": 6, "description": "Firewall blocklist export"},
            "feed_ingestion": {"weight": 8, "description": "Multiple feed source support"},
        },
        "operations": {
            "analyst_workflow": {"weight": 7, "description": "Investigation workflow tools"},
            "reporting": {"weight": 6, "description": "Report generation and export"},
            "sharing": {"weight": 7, "description": "Community/ISAC sharing support"},
            "rbac": {"weight": 5, "description": "Role-based access control"},
            "audit_logging": {"weight": 4, "description": "Audit trail for compliance"},
        },
    }

    def score_platform(self, platform_name, scores):
        """Calculate weighted score for a TIP platform.

        scores: dict of criterion_name -> score (0-10)
        """
        total_weight = 0
        weighted_score = 0
        details = []

        for category, criteria in self.EVALUATION_CRITERIA.items():
            for criterion, info in criteria.items():
                score = scores.get(criterion, 0)
                weight = info["weight"]
                total_weight += weight
                weighted_score += score * weight
                details.append({
                    "category": category,
                    "criterion": criterion,
                    "description": info["description"],
                    "score": score,
                    "weight": weight,
                    "weighted": score * weight,
                })

        final_score = round(weighted_score / total_weight, 1) if total_weight > 0 else 0
        return {
            "platform": platform_name,
            "overall_score": final_score,
            "max_possible": 10,
            "total_weight": total_weight,
            "details": sorted(details, key=lambda x: x["weighted"], reverse=True),
            "evaluation_date": datetime.utcnow().isoformat() + "Z",
        }

    def compare_platforms(self, evaluations):
        """Compare multiple TIP platform evaluations side by side."""
        comparison = []
        for eval_result in evaluations:
            comparison.append({
                "platform": eval_result["platform"],
                "overall_score": eval_result["overall_score"],
            })
        comparison.sort(key=lambda x: x["overall_score"], reverse=True)
        return {"ranking": comparison, "count": len(comparison)}


def test_misp_api(misp_url, api_key, verify_ssl=False):
    """Test MISP API connectivity and basic operations."""
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    results = {}
    endpoints = {
        "version": "/servers/getVersion.json",
        "statistics": "/attributes/attributeStatistics/type/percentage.json",
        "feeds": "/feeds/index.json",
    }

    for name, path in endpoints.items():
        url = f"{misp_url.rstrip('/')}{path}"
        req = urllib.request.Request(url, headers={
            "Authorization": api_key,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                results[name] = {
                    "status": resp.status,
                    "data": json.loads(resp.read().decode()),
                }
        except Exception as e:
            results[name] = {"status": "error", "message": str(e)}

    return {"platform": "MISP", "url": misp_url, "tests": results}


def test_opencti_api(opencti_url, api_token, verify_ssl=False):
    """Test OpenCTI GraphQL API connectivity."""
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    query = '{"query": "{ about { version } }"}'
    url = f"{opencti_url.rstrip('/')}/graphql"
    req = urllib.request.Request(
        url,
        data=query.encode(),
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            return {
                "platform": "OpenCTI",
                "url": opencti_url,
                "status": resp.status,
                "data": json.loads(resp.read().decode()),
            }
    except Exception as e:
        return {"platform": "OpenCTI", "url": opencti_url, "status": "error", "message": str(e)}


def generate_evaluation_template():
    """Generate an evaluation scoring template for a TIP assessment."""
    evaluator = TIPEvaluator()
    template = {"instructions": "Score each criterion 0-10", "criteria": {}}
    for category, criteria in evaluator.EVALUATION_CRITERIA.items():
        template["criteria"][category] = {}
        for name, info in criteria.items():
            template["criteria"][category][name] = {
                "description": info["description"],
                "weight": info["weight"],
                "score": 0,
            }
    return template


def generate_comparison_report():
    """Generate a sample comparison report for common TIP platforms."""
    evaluator = TIPEvaluator()

    misp_scores = {
        "stix_support": 9, "taxii_server": 7, "rest_api": 9, "deduplication": 7,
        "tlp_enforcement": 9, "attack_mapping": 6, "graph_viz": 5,
        "siem_integration": 7, "edr_integration": 5, "soar_integration": 6,
        "firewall_integration": 7, "feed_ingestion": 9,
        "analyst_workflow": 5, "reporting": 5, "sharing": 10,
        "rbac": 6, "audit_logging": 5,
    }

    opencti_scores = {
        "stix_support": 10, "taxii_server": 9, "rest_api": 9, "deduplication": 8,
        "tlp_enforcement": 9, "attack_mapping": 10, "graph_viz": 10,
        "siem_integration": 7, "edr_integration": 6, "soar_integration": 7,
        "firewall_integration": 6, "feed_ingestion": 8,
        "analyst_workflow": 8, "reporting": 7, "sharing": 8,
        "rbac": 8, "audit_logging": 7,
    }

    threatconnect_scores = {
        "stix_support": 8, "taxii_server": 8, "rest_api": 9, "deduplication": 9,
        "tlp_enforcement": 8, "attack_mapping": 8, "graph_viz": 8,
        "siem_integration": 9, "edr_integration": 8, "soar_integration": 9,
        "firewall_integration": 8, "feed_ingestion": 9,
        "analyst_workflow": 9, "reporting": 9, "sharing": 7,
        "rbac": 9, "audit_logging": 9,
    }

    results = [
        evaluator.score_platform("MISP (Open Source)", misp_scores),
        evaluator.score_platform("OpenCTI (Open Source)", opencti_scores),
        evaluator.score_platform("ThreatConnect (Commercial)", threatconnect_scores),
    ]

    comparison = evaluator.compare_platforms(results)
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "comparison": comparison,
        "detailed_evaluations": results,
    }


if __name__ == "__main__":
    import os
    action = sys.argv[1] if len(sys.argv) > 1 else "compare"
    if action == "compare":
        print(json.dumps(generate_comparison_report(), indent=2, default=str))
    elif action == "template":
        print(json.dumps(generate_evaluation_template(), indent=2))
    elif action == "test-misp":
        url = os.environ.get("MISP_URL", sys.argv[2] if len(sys.argv) > 2 else "")
        key = os.environ.get("MISP_KEY", sys.argv[3] if len(sys.argv) > 3 else "")
        if url and key:
            print(json.dumps(test_misp_api(url, key), indent=2, default=str))
        else:
            print("Set MISP_URL and MISP_KEY env vars or pass as arguments")
    elif action == "test-opencti":
        url = os.environ.get("OPENCTI_URL", sys.argv[2] if len(sys.argv) > 2 else "")
        token = os.environ.get("OPENCTI_TOKEN", sys.argv[3] if len(sys.argv) > 3 else "")
        if url and token:
            print(json.dumps(test_opencti_api(url, token), indent=2, default=str))
        else:
            print("Set OPENCTI_URL and OPENCTI_TOKEN env vars or pass as arguments")
    else:
        print("Usage: agent.py [compare|template|test-misp [url key]|test-opencti [url token]]")
