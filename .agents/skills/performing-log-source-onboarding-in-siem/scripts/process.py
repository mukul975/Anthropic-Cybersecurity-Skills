#!/usr/bin/env python3
"""
SIEM Log Source Onboarding Manager

Tracks log source onboarding progress, validates data quality,
and generates configuration templates for common SIEM platforms.
"""

import json
from datetime import datetime
from typing import Optional


class LogSource:
    """Represents a log source to be onboarded into a SIEM."""

    def __init__(self, name: str, source_type: str, log_format: str,
                 estimated_eps: int, avg_event_size_bytes: int = 500,
                 security_tier: str = "medium", collection_method: str = "syslog"):
        self.name = name
        self.source_type = source_type
        self.log_format = log_format
        self.estimated_eps = estimated_eps
        self.avg_event_size_bytes = avg_event_size_bytes
        self.security_tier = security_tier
        self.collection_method = collection_method
        self.status = "pending"
        self.cim_fields_mapped = []
        self.validation_results = {}

    def estimate_daily_volume_gb(self) -> float:
        return round(self.estimated_eps * self.avg_event_size_bytes * 86400 / 1_073_741_824, 2)

    def estimate_monthly_volume_gb(self) -> float:
        return round(self.estimate_daily_volume_gb() * 30, 2)

    def validate_cim_compliance(self, required_fields: list) -> dict:
        mapped = set(self.cim_fields_mapped)
        required = set(required_fields)
        missing = required - mapped
        coverage = round(len(mapped & required) / max(1, len(required)) * 100, 1)
        self.validation_results["cim_compliance"] = {
            "coverage_pct": coverage,
            "mapped_fields": list(mapped & required),
            "missing_fields": list(missing),
            "compliant": coverage >= 80,
        }
        return self.validation_results["cim_compliance"]

    def generate_splunk_inputs_conf(self) -> str:
        templates = {
            "syslog": f"""[udp://514]
connection_host = ip
sourcetype = {self.source_type}
index = main
disabled = false""",
            "windows_event": f"""[WinEventLog://Security]
disabled = 0
index = wineventlog
sourcetype = {self.source_type}
evt_resolve_ad_obj = 1
checkpointInterval = 5""",
            "file_monitor": f"""[monitor:///var/log/{self.name}/*.log]
disabled = false
sourcetype = {self.source_type}
index = main
crcSalt = <SOURCE>""",
            "http_event_collector": f"""# Configure via Splunk HEC
# POST to https://splunk:8088/services/collector/event
# Headers: Authorization: Splunk <HEC_TOKEN>
# Body: {{"event": "<log_data>", "sourcetype": "{self.source_type}", "index": "main"}}""",
        }
        return templates.get(self.collection_method, "# Unknown collection method")


class OnboardingTracker:
    """Tracks the onboarding status of multiple log sources."""

    ONBOARDING_STEPS = [
        "discovery",
        "planning",
        "collection_configured",
        "parser_built",
        "cim_mapped",
        "validation_passed",
        "detection_rules_enabled",
        "documentation_complete",
        "production_released",
    ]

    def __init__(self):
        self.sources = []
        self.step_completion = {}

    def add_source(self, source: LogSource):
        self.sources.append(source)
        self.step_completion[source.name] = {step: False for step in self.ONBOARDING_STEPS}

    def complete_step(self, source_name: str, step: str):
        if source_name in self.step_completion and step in self.step_completion[source_name]:
            self.step_completion[source_name][step] = True
            # Update status
            for src in self.sources:
                if src.name == source_name:
                    completed = sum(1 for v in self.step_completion[source_name].values() if v)
                    total = len(self.ONBOARDING_STEPS)
                    if completed == total:
                        src.status = "completed"
                    elif completed > 0:
                        src.status = "in_progress"

    def get_progress_report(self) -> dict:
        report = {
            "total_sources": len(self.sources),
            "completed": sum(1 for s in self.sources if s.status == "completed"),
            "in_progress": sum(1 for s in self.sources if s.status == "in_progress"),
            "pending": sum(1 for s in self.sources if s.status == "pending"),
            "total_daily_volume_gb": sum(s.estimate_daily_volume_gb() for s in self.sources),
            "total_monthly_volume_gb": sum(s.estimate_monthly_volume_gb() for s in self.sources),
            "sources": [],
        }
        for source in self.sources:
            steps = self.step_completion.get(source.name, {})
            completed_steps = sum(1 for v in steps.values() if v)
            report["sources"].append({
                "name": source.name,
                "type": source.source_type,
                "status": source.status,
                "progress": f"{completed_steps}/{len(self.ONBOARDING_STEPS)}",
                "daily_volume_gb": source.estimate_daily_volume_gb(),
                "security_tier": source.security_tier,
                "next_step": next((s for s, v in steps.items() if not v), "complete"),
            })
        return report


CIM_REQUIRED_FIELDS = {
    "Network_Traffic": ["src_ip", "dest_ip", "dest_port", "action", "bytes", "protocol", "transport"],
    "Authentication": ["src_ip", "user", "action", "app", "dest"],
    "Endpoint": ["dest", "process", "process_id", "user", "action"],
    "Web": ["url", "http_method", "status", "src_ip", "dest_ip", "http_user_agent"],
    "Email": ["src_user", "recipient", "subject", "action", "file_name"],
}


if __name__ == "__main__":
    tracker = OnboardingTracker()

    sources = [
        LogSource("Palo Alto Firewall", "pan:traffic", "syslog-CEF", 500, 600, "critical", "syslog"),
        LogSource("Windows Domain Controllers", "WinEventLog:Security", "windows-xml", 200, 800, "critical", "windows_event"),
        LogSource("Squid Web Proxy", "squid:access", "squid-native", 1000, 400, "high", "file_monitor"),
        LogSource("Custom App Server", "app:custom", "json", 50, 300, "medium", "http_event_collector"),
    ]

    for src in sources:
        tracker.add_source(src)

    # Simulate progress
    tracker.complete_step("Palo Alto Firewall", "discovery")
    tracker.complete_step("Palo Alto Firewall", "planning")
    tracker.complete_step("Palo Alto Firewall", "collection_configured")
    tracker.complete_step("Palo Alto Firewall", "parser_built")
    tracker.complete_step("Palo Alto Firewall", "cim_mapped")

    tracker.complete_step("Windows Domain Controllers", "discovery")
    tracker.complete_step("Windows Domain Controllers", "planning")
    tracker.complete_step("Windows Domain Controllers", "collection_configured")

    tracker.complete_step("Squid Web Proxy", "discovery")

    # CIM validation
    sources[0].cim_fields_mapped = ["src_ip", "dest_ip", "dest_port", "action", "bytes", "protocol"]
    cim_result = sources[0].validate_cim_compliance(CIM_REQUIRED_FIELDS["Network_Traffic"])

    print("=" * 70)
    print("SIEM LOG SOURCE ONBOARDING TRACKER")
    print("=" * 70)

    report = tracker.get_progress_report()
    print(f"\nTotal Sources: {report['total_sources']}")
    print(f"Completed: {report['completed']} | In Progress: {report['in_progress']} | Pending: {report['pending']}")
    print(f"Total Daily Volume: {report['total_daily_volume_gb']} GB")
    print(f"Total Monthly Volume: {report['total_monthly_volume_gb']} GB")

    print(f"\n{'Source':<30} {'Status':<15} {'Progress':<10} {'Volume/Day':<12} {'Next Step'}")
    print("-" * 85)
    for s in report["sources"]:
        print(f"{s['name']:<30} {s['status']:<15} {s['progress']:<10} {s['daily_volume_gb']:<12} {s['next_step']}")

    print(f"\nCIM Compliance - Palo Alto Firewall:")
    print(f"  Coverage: {cim_result['coverage_pct']}%")
    print(f"  Compliant: {cim_result['compliant']}")
    print(f"  Missing: {cim_result['missing_fields']}")

    print(f"\nSample inputs.conf for Palo Alto Firewall:")
    print(sources[0].generate_splunk_inputs_conf())
