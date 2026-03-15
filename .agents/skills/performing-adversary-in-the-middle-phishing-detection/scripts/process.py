#!/usr/bin/env python3
"""
AiTM Phishing Detection Engine

Analyzes Azure AD sign-in logs and session data to detect
Adversary-in-the-Middle phishing attacks including session
cookie replay and impossible travel patterns.

Usage:
    python process.py detect --signin-log signins.json
    python process.py check-session --session-log sessions.json
    python process.py analyze-domain --domain suspicious-login.com
"""

import argparse
import json
import re
import sys
import math
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class AiTMIndicator:
    """An AiTM detection indicator."""
    indicator_type: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    user: str = ""
    timestamp: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class AiTMAnalysis:
    """Complete AiTM analysis result."""
    total_signins: int = 0
    suspicious_signins: int = 0
    session_replays_detected: int = 0
    impossible_travel_detected: int = 0
    post_compromise_indicators: int = 0
    indicators: list = field(default_factory=list)
    affected_users: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)


# Known AiTM infrastructure patterns
AITM_DOMAIN_PATTERNS = [
    r'login.*microsoft.*\.(top|xyz|info|click|online)',
    r'auth.*office.*\.(top|xyz|info|click|online)',
    r'sso.*\.(top|xyz|info|click|online)',
    r'verify.*account.*\.(top|xyz|info|click|online)',
    r'.*\.workers\.dev$',
    r'.*\.pages\.dev$',
    r'.*-login-.*\.(com|net|org)',
]

# Known PhaaS hosting patterns
PHAAS_INFRA = [
    'cloudflare-ipfs.com',
    'workers.dev',
    'pages.dev',
    'web.app',
    'firebaseapp.com',
    'glitch.me',
    'netlify.app',
    'vercel.app',
]


def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate distance in km between two coordinates."""
    R = 6371  # Earth radius in km
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2)
    c = 2 * math.asin(math.sqrt(a))
    return R * c


def detect_aitm_signins(signins: list) -> AiTMAnalysis:
    """Analyze sign-in logs for AiTM indicators."""
    analysis = AiTMAnalysis()
    analysis.total_signins = len(signins)

    user_signins = defaultdict(list)
    for signin in signins:
        user = signin.get("userPrincipalName", "")
        user_signins[user].append(signin)

    affected = set()

    for user, events in user_signins.items():
        sorted_events = sorted(events, key=lambda x: x.get("createdDateTime", ""))

        for i in range(len(sorted_events)):
            event = sorted_events[i]
            ip = event.get("ipAddress", "")
            location = event.get("location", {})
            risk_level = event.get("riskLevelDuringSignIn", "none")
            is_interactive = event.get("isInteractive", True)
            app = event.get("appDisplayName", "")
            timestamp = event.get("createdDateTime", "")

            # Check for anonymous proxy
            if event.get("isFromAnonymousProxy", False):
                analysis.indicators.append(AiTMIndicator(
                    indicator_type="anonymous_proxy",
                    description=f"Sign-in from anonymous proxy/VPN",
                    severity="high",
                    confidence=0.7,
                    user=user,
                    timestamp=timestamp,
                    details={"ip": ip}
                ))
                analysis.suspicious_signins += 1
                affected.add(user)

            # Check for impossible travel
            if i > 0:
                prev = sorted_events[i - 1]
                prev_loc = prev.get("location", {})
                prev_time = prev.get("createdDateTime", "")

                if (location.get("geoCoordinates") and
                        prev_loc.get("geoCoordinates")):
                    lat1 = prev_loc["geoCoordinates"].get("latitude", 0)
                    lon1 = prev_loc["geoCoordinates"].get("longitude", 0)
                    lat2 = location["geoCoordinates"].get("latitude", 0)
                    lon2 = location["geoCoordinates"].get("longitude", 0)

                    distance = haversine_distance(lat1, lon1, lat2, lon2)

                    try:
                        t1 = datetime.fromisoformat(prev_time.replace('Z', '+00:00'))
                        t2 = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        hours = (t2 - t1).total_seconds() / 3600

                        if hours > 0 and distance > 0:
                            speed = distance / hours
                            if speed > 900:  # Faster than commercial flight
                                analysis.indicators.append(AiTMIndicator(
                                    indicator_type="impossible_travel",
                                    description=(
                                        f"Impossible travel: {distance:.0f}km in "
                                        f"{hours:.1f}h ({speed:.0f}km/h)"
                                    ),
                                    severity="high",
                                    confidence=0.85,
                                    user=user,
                                    timestamp=timestamp,
                                    details={
                                        "from_ip": prev.get("ipAddress"),
                                        "to_ip": ip,
                                        "distance_km": round(distance),
                                        "speed_kmh": round(speed)
                                    }
                                ))
                                analysis.impossible_travel_detected += 1
                                affected.add(user)
                    except (ValueError, TypeError):
                        pass

            # Check for session from different IP shortly after auth
            if i < len(sorted_events) - 1:
                next_event = sorted_events[i + 1]
                next_ip = next_event.get("ipAddress", "")
                next_time = next_event.get("createdDateTime", "")

                if ip and next_ip and ip != next_ip:
                    try:
                        t1 = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        t2 = datetime.fromisoformat(next_time.replace('Z', '+00:00'))
                        minutes = (t2 - t1).total_seconds() / 60

                        if 0 < minutes < 10:
                            analysis.indicators.append(AiTMIndicator(
                                indicator_type="session_ip_switch",
                                description=(
                                    f"Session IP changed within {minutes:.0f}min "
                                    f"({ip} -> {next_ip})"
                                ),
                                severity="critical",
                                confidence=0.9,
                                user=user,
                                timestamp=timestamp,
                                details={
                                    "auth_ip": ip,
                                    "session_ip": next_ip,
                                    "time_delta_min": round(minutes)
                                }
                            ))
                            analysis.session_replays_detected += 1
                            affected.add(user)
                    except (ValueError, TypeError):
                        pass

    analysis.affected_users = list(affected)
    if affected:
        analysis.recommended_actions = [
            "Revoke all sessions for affected users",
            "Force password reset with phishing-resistant MFA",
            "Check for inbox forwarding rules created post-compromise",
            "Review OAuth app consents for affected accounts",
            "Block source IPs at firewall",
            "Retract phishing email from all mailboxes"
        ]

    return analysis


def analyze_domain(domain: str) -> dict:
    """Check if domain matches known AiTM/PhaaS patterns."""
    result = {
        "domain": domain,
        "is_suspicious": False,
        "indicators": [],
        "risk_score": 0
    }

    domain_lower = domain.lower()

    for pattern in AITM_DOMAIN_PATTERNS:
        if re.search(pattern, domain_lower):
            result["indicators"].append(f"Matches AiTM domain pattern: {pattern}")
            result["risk_score"] += 30
            result["is_suspicious"] = True

    for infra in PHAAS_INFRA:
        if domain_lower.endswith(infra):
            result["indicators"].append(f"Hosted on known PhaaS infrastructure: {infra}")
            result["risk_score"] += 25
            result["is_suspicious"] = True

    # Check for brand impersonation in domain
    brands = ['microsoft', 'office', 'outlook', 'google', 'okta', 'azure']
    for brand in brands:
        if brand in domain_lower and not domain_lower.endswith(f'.{brand}.com'):
            result["indicators"].append(f"Contains brand name '{brand}' in non-official domain")
            result["risk_score"] += 20
            result["is_suspicious"] = True

    result["risk_score"] = min(result["risk_score"], 100)
    return result


def main():
    parser = argparse.ArgumentParser(description="AiTM Phishing Detection")
    subparsers = parser.add_subparsers(dest="command")

    detect_parser = subparsers.add_parser("detect", help="Detect AiTM in sign-in logs")
    detect_parser.add_argument("--signin-log", required=True)

    domain_parser = subparsers.add_parser("analyze-domain", help="Check domain for AiTM")
    domain_parser.add_argument("--domain", required=True)

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "detect":
        with open(args.signin_log) as f:
            signins = json.load(f)
        result = detect_aitm_signins(signins)
        if args.json:
            print(json.dumps(asdict(result), indent=2, default=str))
        else:
            print(f"Total sign-ins: {result.total_signins}")
            print(f"Suspicious: {result.suspicious_signins}")
            print(f"Session replays: {result.session_replays_detected}")
            print(f"Impossible travel: {result.impossible_travel_detected}")
            print(f"Affected users: {len(result.affected_users)}")
            for ind in result.indicators:
                print(f"  [{ind.severity.upper()}] {ind.description} (user: {ind.user})")

    elif args.command == "analyze-domain":
        result = analyze_domain(args.domain)
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
