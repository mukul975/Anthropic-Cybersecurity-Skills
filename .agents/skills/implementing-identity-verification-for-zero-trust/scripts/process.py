#!/usr/bin/env python3
"""
Identity Verification Assessment Tool for Zero Trust

Analyzes identity configurations, evaluates MFA strength, assesses
conditional access policies, and generates identity maturity reports.
"""

import json
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Optional


def assess_mfa_strength(mfa_config: dict) -> dict:
    """Evaluate MFA configuration against zero trust requirements."""
    findings = []
    score = 100

    methods = mfa_config.get("enabled_methods", [])
    phishing_resistant = {"fido2", "webauthn", "certificate", "windows_hello", "platform_authenticator"}
    phishable = {"sms", "voice", "email_otp"}
    moderate = {"totp", "push_notification", "authenticator_app"}

    enabled_phishing_resistant = set(methods) & phishing_resistant
    enabled_phishable = set(methods) & phishable

    if not enabled_phishing_resistant:
        findings.append({
            "severity": "critical",
            "finding": "No phishing-resistant MFA methods enabled",
            "recommendation": "Deploy FIDO2 security keys or platform authenticators",
            "reference": "NIST SP 800-63B AAL3, CISA ZT Identity Pillar (Advanced)"
        })
        score -= 40

    if enabled_phishable:
        findings.append({
            "severity": "high",
            "finding": f"Phishable MFA methods still enabled: {', '.join(enabled_phishable)}",
            "recommendation": "Disable SMS, voice, and email OTP methods",
            "reference": "CISA Phishing-Resistant MFA Guidance"
        })
        score -= 20

    if not mfa_config.get("enforced_for_all_users"):
        findings.append({
            "severity": "critical",
            "finding": "MFA not enforced for all users",
            "recommendation": "Enable MFA requirement for all user accounts",
            "reference": "CISA ZT Identity Pillar (Initial)"
        })
        score -= 30

    if not mfa_config.get("number_matching_enabled") and "push_notification" in methods:
        findings.append({
            "severity": "high",
            "finding": "Push notification MFA without number matching",
            "recommendation": "Enable number matching to prevent MFA fatigue attacks",
            "reference": "Microsoft MFA fatigue defense guidance"
        })
        score -= 10

    enrollment_rate = mfa_config.get("enrollment_rate_percent", 0)
    if enrollment_rate < 95:
        findings.append({
            "severity": "warning",
            "finding": f"MFA enrollment rate is {enrollment_rate}% (target: 95%+)",
            "recommendation": "Launch enrollment campaign for remaining users",
            "reference": "CISA ZT Identity Pillar (Advanced)"
        })
        score -= 10

    return {
        "mfa_score": max(score, 0),
        "phishing_resistant_methods": list(enabled_phishing_resistant),
        "phishable_methods": list(enabled_phishable),
        "findings": findings,
        "maturity_level": (
            "optimal" if score >= 90 else
            "advanced" if score >= 70 else
            "initial" if score >= 50 else
            "traditional"
        )
    }


def assess_conditional_access(policies: list) -> dict:
    """Evaluate conditional access policies for zero trust alignment."""
    findings = []
    coverage = {
        "legacy_auth_blocked": False,
        "mfa_required_all": False,
        "device_compliance_required": False,
        "location_restrictions": False,
        "session_controls": False,
        "risk_based_policies": False,
        "privileged_access_secured": False,
    }

    for policy in policies:
        conditions = policy.get("conditions", {})
        grant_controls = policy.get("grant_controls", {})
        session_controls = policy.get("session_controls", {})

        if policy.get("blocks_legacy_auth"):
            coverage["legacy_auth_blocked"] = True

        if grant_controls.get("require_mfa") and conditions.get("users") == "all":
            coverage["mfa_required_all"] = True

        if grant_controls.get("require_compliant_device"):
            coverage["device_compliance_required"] = True

        if conditions.get("locations") and conditions["locations"].get("excluded_trusted"):
            coverage["location_restrictions"] = True

        if session_controls.get("sign_in_frequency") or session_controls.get("persistent_browser"):
            coverage["session_controls"] = True

        if conditions.get("user_risk") or conditions.get("sign_in_risk"):
            coverage["risk_based_policies"] = True

        if conditions.get("roles") and "privileged" in str(conditions.get("roles", [])).lower():
            coverage["privileged_access_secured"] = True

    if not coverage["legacy_auth_blocked"]:
        findings.append({
            "severity": "critical",
            "finding": "Legacy authentication protocols not blocked",
            "recommendation": "Create policy blocking basic auth, IMAP, POP3, SMTP AUTH",
        })

    if not coverage["mfa_required_all"]:
        findings.append({
            "severity": "critical",
            "finding": "MFA not required for all users",
            "recommendation": "Create policy requiring MFA for all user sign-ins",
        })

    if not coverage["device_compliance_required"]:
        findings.append({
            "severity": "high",
            "finding": "Device compliance not required for access",
            "recommendation": "Require managed and compliant devices for sensitive apps",
        })

    if not coverage["risk_based_policies"]:
        findings.append({
            "severity": "high",
            "finding": "No risk-based conditional access policies",
            "recommendation": "Enable user risk and sign-in risk based policies",
        })

    if not coverage["session_controls"]:
        findings.append({
            "severity": "warning",
            "finding": "No session lifetime controls configured",
            "recommendation": "Configure sign-in frequency and browser session persistence",
        })

    covered = sum(1 for v in coverage.values() if v)
    total = len(coverage)

    return {
        "coverage": coverage,
        "coverage_score": round((covered / total) * 100),
        "policies_evaluated": len(policies),
        "findings": findings,
    }


def analyze_sign_in_logs(logs: list) -> dict:
    """Analyze sign-in logs for identity security insights."""
    stats = {
        "total_sign_ins": len(logs),
        "successful": 0,
        "failed": 0,
        "mfa_challenged": 0,
        "risk_events": [],
        "locations": defaultdict(int),
        "devices": defaultdict(int),
        "applications": defaultdict(int),
        "auth_methods": defaultdict(int),
        "risky_sign_ins": [],
    }

    for log in logs:
        if log.get("status") == "success":
            stats["successful"] += 1
        else:
            stats["failed"] += 1

        if log.get("mfa_required"):
            stats["mfa_challenged"] += 1

        location = log.get("location", {}).get("country", "unknown")
        stats["locations"][location] += 1

        device = log.get("device", {}).get("os", "unknown")
        stats["devices"][device] += 1

        app = log.get("application", "unknown")
        stats["applications"][app] += 1

        method = log.get("auth_method", "password")
        stats["auth_methods"][method] += 1

        risk_level = log.get("risk_level", "none")
        if risk_level in ("medium", "high"):
            stats["risky_sign_ins"].append({
                "user": log.get("user", "unknown"),
                "risk_level": risk_level,
                "risk_detail": log.get("risk_detail", ""),
                "location": location,
                "timestamp": log.get("timestamp", ""),
                "application": app,
            })

    stats["locations"] = dict(stats["locations"])
    stats["devices"] = dict(stats["devices"])
    stats["applications"] = dict(stats["applications"])
    stats["auth_methods"] = dict(stats["auth_methods"])
    stats["mfa_coverage_percent"] = round(
        (stats["mfa_challenged"] / max(stats["total_sign_ins"], 1)) * 100, 1
    )

    return stats


def detect_impossible_travel(sign_ins: list, max_speed_kmh: int = 900) -> list:
    """Detect impossible travel scenarios from sign-in logs."""
    alerts = []
    user_logins = defaultdict(list)

    for si in sign_ins:
        user = si.get("user", "")
        if user and si.get("location", {}).get("latitude"):
            user_logins[user].append(si)

    for user, logins in user_logins.items():
        sorted_logins = sorted(logins, key=lambda x: x.get("timestamp", ""))

        for i in range(1, len(sorted_logins)):
            prev = sorted_logins[i - 1]
            curr = sorted_logins[i]

            lat1 = prev["location"].get("latitude", 0)
            lon1 = prev["location"].get("longitude", 0)
            lat2 = curr["location"].get("latitude", 0)
            lon2 = curr["location"].get("longitude", 0)

            import math
            R = 6371
            dlat = math.radians(lat2 - lat1)
            dlon = math.radians(lon2 - lon1)
            a = (math.sin(dlat / 2) ** 2 +
                 math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
                 math.sin(dlon / 2) ** 2)
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
            distance_km = R * c

            try:
                t1 = datetime.fromisoformat(prev.get("timestamp", "").replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(curr.get("timestamp", "").replace("Z", "+00:00"))
                time_diff_hours = (t2 - t1).total_seconds() / 3600
            except (ValueError, TypeError):
                continue

            if time_diff_hours > 0:
                required_speed = distance_km / time_diff_hours
                if required_speed > max_speed_kmh and distance_km > 100:
                    alerts.append({
                        "user": user,
                        "severity": "high",
                        "type": "impossible_travel",
                        "from_location": prev["location"],
                        "to_location": curr["location"],
                        "distance_km": round(distance_km),
                        "time_diff_hours": round(time_diff_hours, 2),
                        "required_speed_kmh": round(required_speed),
                        "from_time": prev.get("timestamp"),
                        "to_time": curr.get("timestamp"),
                    })

    return alerts


def generate_identity_maturity_report(config: dict) -> dict:
    """Generate a comprehensive identity maturity assessment."""
    report = {
        "generated": datetime.now().isoformat(),
        "overall_maturity": "traditional",
        "pillars": {},
    }

    mfa_assessment = assess_mfa_strength(config.get("mfa", {}))
    report["pillars"]["mfa"] = mfa_assessment

    ca_assessment = assess_conditional_access(config.get("conditional_access_policies", []))
    report["pillars"]["conditional_access"] = ca_assessment

    governance = config.get("governance", {})
    gov_score = 0
    if governance.get("automated_provisioning"): gov_score += 25
    if governance.get("access_reviews_enabled"): gov_score += 25
    if governance.get("jit_access_enabled"): gov_score += 25
    if governance.get("lifecycle_automation"): gov_score += 25
    report["pillars"]["governance"] = {"score": gov_score}

    monitoring = config.get("monitoring", {})
    mon_score = 0
    if monitoring.get("siem_integration"): mon_score += 25
    if monitoring.get("ueba_enabled"): mon_score += 25
    if monitoring.get("identity_threat_detection"): mon_score += 25
    if monitoring.get("cae_enabled"): mon_score += 25
    report["pillars"]["monitoring"] = {"score": mon_score}

    avg_score = (
        mfa_assessment["mfa_score"] +
        ca_assessment["coverage_score"] +
        gov_score +
        mon_score
    ) / 4

    report["overall_score"] = round(avg_score)
    report["overall_maturity"] = (
        "optimal" if avg_score >= 90 else
        "advanced" if avg_score >= 70 else
        "initial" if avg_score >= 50 else
        "traditional"
    )

    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Identity Verification Assessment Tool")
    parser.add_argument("--config", type=str, help="Path to identity configuration JSON")
    parser.add_argument("--logs", type=str, help="Path to sign-in logs JSON")
    parser.add_argument("--action", choices=["assess", "analyze-logs", "detect-travel", "report"],
                        default="report")
    parser.add_argument("--output", type=str, default="identity_report.json")
    args = parser.parse_args()

    if args.action == "assess" and args.config:
        with open(args.config) as f:
            config = json.load(f)
        mfa_result = assess_mfa_strength(config.get("mfa", {}))
        ca_result = assess_conditional_access(config.get("conditional_access_policies", []))
        result = {"mfa": mfa_result, "conditional_access": ca_result}
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"MFA Score: {mfa_result['mfa_score']}, CA Coverage: {ca_result['coverage_score']}%")

    elif args.action == "analyze-logs" and args.logs:
        with open(args.logs) as f:
            logs = json.load(f)
        stats = analyze_sign_in_logs(logs)
        with open(args.output, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"Analyzed {stats['total_sign_ins']} sign-ins, {len(stats['risky_sign_ins'])} risky")

    elif args.action == "detect-travel" and args.logs:
        with open(args.logs) as f:
            logs = json.load(f)
        alerts = detect_impossible_travel(logs)
        with open(args.output, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"Detected {len(alerts)} impossible travel events")

    elif args.action == "report" and args.config:
        with open(args.config) as f:
            config = json.load(f)
        report = generate_identity_maturity_report(config)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Identity Maturity: {report['overall_maturity']} (Score: {report['overall_score']})")

    else:
        parser.print_help()

    if args.output and Path(args.output).exists():
        print(f"Output saved to {args.output}")


if __name__ == "__main__":
    main()
