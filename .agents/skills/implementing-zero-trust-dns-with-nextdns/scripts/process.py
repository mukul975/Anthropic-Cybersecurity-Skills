#!/usr/bin/env python3
"""
NextDNS Zero Trust DNS Configuration and Monitoring.

Manages NextDNS profiles, analyzes DNS logs for threats,
and generates compliance reports for DNS security posture.
"""

import json
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import math


@dataclass
class DNSPolicy:
    name: str
    security_features: list = field(default_factory=list)
    privacy_blocklists: list = field(default_factory=list)
    native_tracking: list = field(default_factory=list)
    allowlist: list = field(default_factory=list)
    denylist: list = field(default_factory=list)
    log_retention_days: int = 90


@dataclass
class DNSQueryLog:
    timestamp: str
    domain: str
    query_type: str
    status: str  # "allowed", "blocked"
    blocked_reason: str = ""
    device: str = ""
    client_ip: str = ""


class NextDNSPolicyGenerator:
    """Generate NextDNS configuration profiles."""

    SECURITY_FEATURES = [
        "threat_intelligence_feeds",
        "ai_driven_threat_detection",
        "google_safe_browsing",
        "cryptojacking_protection",
        "dns_rebinding_protection",
        "idn_homograph_attacks",
        "typosquatting_protection",
        "dga_protection",
        "nrd_protection",
        "ddns_blocking",
        "parked_domains",
        "csam_blocking",
    ]

    PRIVACY_BLOCKLISTS = [
        "nextdns_recommended",
        "oisd_full",
        "easyprivacy",
        "adguard_dns_filter",
        "hagezi_pro",
        "steven_black_unified",
    ]

    NATIVE_TRACKING = [
        "windows", "apple", "samsung", "xiaomi",
        "huawei", "roku", "sonos", "alexa",
    ]

    def create_enterprise_policy(self, name: str) -> DNSPolicy:
        return DNSPolicy(
            name=name,
            security_features=self.SECURITY_FEATURES.copy(),
            privacy_blocklists=["nextdns_recommended", "oisd_full", "easyprivacy"],
            native_tracking=["windows", "apple"],
            log_retention_days=90,
        )

    def create_strict_policy(self, name: str) -> DNSPolicy:
        return DNSPolicy(
            name=name,
            security_features=self.SECURITY_FEATURES.copy(),
            privacy_blocklists=self.PRIVACY_BLOCKLISTS.copy(),
            native_tracking=self.NATIVE_TRACKING.copy(),
            log_retention_days=365,
        )

    def create_minimal_policy(self, name: str) -> DNSPolicy:
        return DNSPolicy(
            name=name,
            security_features=[
                "threat_intelligence_feeds",
                "cryptojacking_protection",
                "dns_rebinding_protection",
                "dga_protection",
                "nrd_protection",
            ],
            privacy_blocklists=["nextdns_recommended"],
            native_tracking=[],
            log_retention_days=30,
        )

    def export_policy(self, policy: DNSPolicy, output_path: str):
        config = {
            "name": policy.name,
            "security": {
                "features_enabled": policy.security_features,
            },
            "privacy": {
                "blocklists": policy.privacy_blocklists,
                "native_tracking_protection": policy.native_tracking,
                "block_cname_cloaking": True,
            },
            "allowlist": policy.allowlist,
            "denylist": policy.denylist,
            "logging": {
                "enabled": True,
                "retention_days": policy.log_retention_days,
                "storage_location": "US",
            },
        }
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
        return config


class DNSLogAnalyzer:
    """Analyze DNS query logs for security threats."""

    def __init__(self):
        self.logs: list[DNSQueryLog] = []
        self.findings: list[dict] = []

    def add_log(self, log: DNSQueryLog):
        self.logs.append(log)

    def calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of a domain name (DNS tunneling indicator)."""
        label = domain.split(".")[0]
        if not label:
            return 0.0
        freq = {}
        for c in label:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(label)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def detect_dns_tunneling(self, threshold: float = 4.0) -> list[dict]:
        """Detect potential DNS tunneling based on subdomain entropy and length."""
        suspects = []
        for log in self.logs:
            if log.status == "blocked":
                continue
            subdomain = log.domain.split(".")[0]
            entropy = self.calculate_entropy(log.domain)
            if entropy > threshold and len(subdomain) > 20:
                suspects.append({
                    "domain": log.domain,
                    "entropy": round(entropy, 2),
                    "subdomain_length": len(subdomain),
                    "device": log.device,
                    "timestamp": log.timestamp,
                })
        if suspects:
            self.findings.append({
                "type": "dns_tunneling_suspect",
                "severity": "HIGH",
                "count": len(suspects),
                "details": suspects[:20],
            })
        return suspects

    def detect_dga_domains(self) -> list[dict]:
        """Detect domain generation algorithm patterns."""
        suspects = []
        for log in self.logs:
            parts = log.domain.split(".")
            if len(parts) >= 2:
                sld = parts[-2]
                entropy = self.calculate_entropy(sld + "." + parts[-1])
                if entropy > 3.5 and len(sld) > 8 and not any(
                    c in sld for c in ["-", "_"]
                ):
                    digits = sum(1 for c in sld if c.isdigit())
                    if digits / len(sld) > 0.3:
                        suspects.append({
                            "domain": log.domain,
                            "entropy": round(entropy, 2),
                            "digit_ratio": round(digits / len(sld), 2),
                        })
        if suspects:
            self.findings.append({
                "type": "dga_domain_suspect",
                "severity": "HIGH",
                "count": len(suspects),
                "details": suspects[:20],
            })
        return suspects

    def get_blocked_summary(self) -> dict:
        """Summarize blocked queries by reason."""
        blocked = [l for l in self.logs if l.status == "blocked"]
        by_reason = {}
        for log in blocked:
            reason = log.blocked_reason or "unknown"
            by_reason[reason] = by_reason.get(reason, 0) + 1

        by_domain = {}
        for log in blocked:
            by_domain[log.domain] = by_domain.get(log.domain, 0) + 1

        top_blocked = sorted(by_domain.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "total_blocked": len(blocked),
            "total_allowed": len(self.logs) - len(blocked),
            "block_rate": round(len(blocked) / len(self.logs) * 100, 2) if self.logs else 0,
            "by_reason": by_reason,
            "top_blocked_domains": dict(top_blocked),
        }

    def generate_report(self) -> dict:
        return {
            "report_date": datetime.datetime.now().isoformat(),
            "total_queries": len(self.logs),
            "blocked_summary": self.get_blocked_summary(),
            "security_findings": self.findings,
            "unique_devices": len(set(l.device for l in self.logs if l.device)),
            "unique_domains": len(set(l.domain for l in self.logs)),
        }


def main():
    """Demonstrate NextDNS policy generation and DNS log analysis."""
    # Generate policies
    gen = NextDNSPolicyGenerator()
    enterprise = gen.create_enterprise_policy("Enterprise Standard")
    enterprise.allowlist = ["login.microsoftonline.com", "graph.microsoft.com", "*.company.com"]
    enterprise.denylist = ["malware-c2.example.com", "data-exfil.example.com"]

    config = gen.export_policy(enterprise, "nextdns_enterprise_policy.json")
    print("Enterprise DNS Policy:")
    print(json.dumps(config, indent=2))

    # Analyze sample DNS logs
    analyzer = DNSLogAnalyzer()
    sample_logs = [
        DNSQueryLog("2024-01-15T10:00:00Z", "google.com", "A", "allowed", device="laptop-1"),
        DNSQueryLog("2024-01-15T10:00:01Z", "malware.example.com", "A", "blocked",
                    "threat_intelligence", "laptop-2"),
        DNSQueryLog("2024-01-15T10:00:02Z", "aHR0cHM6Ly9leGFtcGxlLmNvbQ.tunnel.evil.com",
                    "TXT", "allowed", device="server-1"),
        DNSQueryLog("2024-01-15T10:00:03Z", "x8k3m9p2q5.botnet.com", "A", "blocked",
                    "dga_protection", "laptop-3"),
        DNSQueryLog("2024-01-15T10:00:04Z", "office.com", "A", "allowed", device="laptop-1"),
        DNSQueryLog("2024-01-15T10:00:05Z", "ads.tracker.com", "A", "blocked",
                    "ad_blocker", "laptop-1"),
    ]

    for log in sample_logs:
        analyzer.add_log(log)

    analyzer.detect_dns_tunneling()
    analyzer.detect_dga_domains()

    report = analyzer.generate_report()
    print("\n" + "=" * 60)
    print("DNS Security Analysis Report")
    print("=" * 60)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
