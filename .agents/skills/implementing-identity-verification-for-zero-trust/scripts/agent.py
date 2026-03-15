#!/usr/bin/env python3
"""Agent for assessing identity verification controls in zero trust architecture."""

import json
import argparse
from datetime import datetime
from collections import Counter


CISA_ZT_IDENTITY_LEVELS = {
    "traditional": {
        "description": "Password-based auth, static policies",
        "score": 1,
    },
    "initial": {
        "description": "MFA deployed, basic conditional access",
        "score": 2,
    },
    "advanced": {
        "description": "Phishing-resistant MFA, risk-based access",
        "score": 3,
    },
    "optimal": {
        "description": "Continuous verification, passwordless, behavioral analytics",
        "score": 4,
    },
}


def assess_authentication_methods(auth_config):
    """Assess authentication method strength against zero trust requirements."""
    findings = []
    methods = auth_config.get("methods", auth_config.get("authentication", {}))

    if isinstance(methods, dict):
        mfa_enabled = methods.get("mfa_enabled", False)
        phishing_resistant = methods.get("phishing_resistant_mfa", False)
        passwordless = methods.get("passwordless", False)
        fido2 = methods.get("fido2_enabled", False)
        sso = methods.get("sso_enabled", False)

        if not mfa_enabled:
            findings.append({"control": "MFA", "status": "MISSING",
                             "severity": "CRITICAL"})
        elif not phishing_resistant:
            findings.append({"control": "Phishing-resistant MFA", "status": "MISSING",
                             "severity": "HIGH",
                             "recommendation": "Deploy FIDO2 or certificate-based auth"})

        if not fido2:
            findings.append({"control": "FIDO2/WebAuthn", "status": "NOT_DEPLOYED",
                             "severity": "MEDIUM"})
        if not passwordless:
            findings.append({"control": "Passwordless authentication",
                             "status": "NOT_DEPLOYED", "severity": "MEDIUM"})
        if not sso:
            findings.append({"control": "SSO", "status": "NOT_DEPLOYED",
                             "severity": "HIGH"})
    return findings


def assess_conditional_access(policies_path):
    """Assess conditional access policies for zero trust alignment."""
    with open(policies_path) as f:
        policies = json.load(f)
    items = policies if isinstance(policies, list) else policies.get("policies", [])
    findings = []
    required_signals = ["device_compliance", "location", "risk_level",
                        "application", "user_group"]
    covered_signals = set()

    for policy in items:
        conditions = policy.get("conditions", {})
        for signal in required_signals:
            if conditions.get(signal) or signal in str(conditions):
                covered_signals.add(signal)
        if policy.get("grant_controls", {}).get("operator") == "OR":
            findings.append({
                "policy": policy.get("name", ""),
                "issue": "Grant controls use OR (should be AND)",
                "severity": "HIGH",
            })
        if not policy.get("state", "").lower() in ("enabled", "on"):
            findings.append({
                "policy": policy.get("name", ""),
                "issue": "Policy not enabled",
                "severity": "MEDIUM",
            })

    missing = set(required_signals) - covered_signals
    for signal in missing:
        findings.append({
            "control": f"Conditional access signal: {signal}",
            "status": "NOT_COVERED",
            "severity": "HIGH",
        })
    return {"findings": findings, "covered_signals": list(covered_signals),
            "missing_signals": list(missing)}


def assess_identity_maturity(config):
    """Assess identity pillar maturity against CISA Zero Trust Maturity Model."""
    scores = {}
    categories = {
        "authentication": {
            "checks": ["mfa_enforced", "phishing_resistant_mfa", "passwordless",
                        "continuous_auth"],
        },
        "identity_stores": {
            "checks": ["centralized_idp", "cloud_identity", "directory_sync",
                        "identity_federation"],
        },
        "risk_assessment": {
            "checks": ["risk_based_access", "behavioral_analytics",
                        "impossible_travel_detection", "session_risk_scoring"],
        },
        "visibility": {
            "checks": ["identity_audit_logging", "real_time_monitoring",
                        "identity_analytics_dashboard", "automated_anomaly_detection"],
        },
    }

    for category, info in categories.items():
        implemented = sum(1 for check in info["checks"]
                          if config.get(category, {}).get(check, False))
        total = len(info["checks"])
        ratio = implemented / total if total else 0
        if ratio >= 0.9:
            level = "optimal"
        elif ratio >= 0.6:
            level = "advanced"
        elif ratio >= 0.3:
            level = "initial"
        else:
            level = "traditional"
        scores[category] = {
            "implemented": implemented,
            "total": total,
            "ratio": round(ratio, 2),
            "maturity_level": level,
            "score": CISA_ZT_IDENTITY_LEVELS[level]["score"],
        }

    avg_score = sum(s["score"] for s in scores.values()) / len(scores) if scores else 0
    for level_name, level_info in CISA_ZT_IDENTITY_LEVELS.items():
        if level_info["score"] >= avg_score:
            overall_level = level_name
            break
    else:
        overall_level = "traditional"

    return {"categories": scores, "overall_score": round(avg_score, 1),
            "overall_level": overall_level}


def analyze_auth_events(events_path):
    """Analyze authentication events for zero trust insights."""
    with open(events_path) as f:
        events = json.load(f)
    items = events if isinstance(events, list) else events.get("events", [])

    by_method = Counter(e.get("auth_method", "unknown") for e in items)
    by_result = Counter(e.get("result", "unknown") for e in items)
    risky = [e for e in items if e.get("risk_level", "").lower() in ("high", "critical")]
    mfa_bypassed = [e for e in items if e.get("mfa_bypassed", False)]

    return {
        "total_events": len(items),
        "by_method": dict(by_method),
        "by_result": dict(by_result),
        "high_risk_events": len(risky),
        "mfa_bypass_events": len(mfa_bypassed),
        "password_only_rate": round(
            by_method.get("password", 0) / len(items) * 100, 1) if items else 0,
    }


def main():
    parser = argparse.ArgumentParser(description="Zero Trust Identity Verification Agent")
    parser.add_argument("--auth-config", help="Authentication config JSON")
    parser.add_argument("--policies", help="Conditional access policies JSON")
    parser.add_argument("--maturity-config", help="Identity maturity assessment config JSON")
    parser.add_argument("--auth-events", help="Authentication events log JSON")
    parser.add_argument("--action", choices=["auth", "policies", "maturity", "events", "full"],
                        default="full")
    parser.add_argument("--output", default="zt_identity_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("auth", "full") and args.auth_config:
        with open(args.auth_config) as f:
            config = json.load(f)
        findings = assess_authentication_methods(config)
        report["results"]["auth_assessment"] = findings
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        print(f"[+] Auth findings: {len(findings)}, {critical} critical")

    if args.action in ("policies", "full") and args.policies:
        result = assess_conditional_access(args.policies)
        report["results"]["conditional_access"] = result
        print(f"[+] Missing signals: {result['missing_signals']}")

    if args.action in ("maturity", "full") and args.maturity_config:
        with open(args.maturity_config) as f:
            config = json.load(f)
        result = assess_identity_maturity(config)
        report["results"]["maturity"] = result
        print(f"[+] Identity maturity: {result['overall_level']} (score: {result['overall_score']})")

    if args.action in ("events", "full") and args.auth_events:
        result = analyze_auth_events(args.auth_events)
        report["results"]["events"] = result
        print(f"[+] Auth events: {result['total_events']}, password-only: {result['password_only_rate']}%")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
