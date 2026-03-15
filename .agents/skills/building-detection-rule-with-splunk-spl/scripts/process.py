#!/usr/bin/env python3
"""
Splunk SPL Detection Rule Builder and Validator

Generates, validates, and manages Splunk SPL detection rules
for SOC correlation searches. Supports MITRE ATT&CK mapping
and rule quality scoring.
"""

import json
import re
import hashlib
from datetime import datetime
from typing import Optional


MITRE_TECHNIQUES = {
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1048": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Protocol", "tactic": "Exfiltration"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1078.002": {"name": "Domain Accounts", "tactic": "Defense Evasion"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1036.005": {"name": "Match Legitimate Name", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
}


class SplunkDetectionRule:
    """Represents a Splunk SPL detection rule with metadata and validation."""

    def __init__(
        self,
        name: str,
        description: str,
        spl_query: str,
        mitre_techniques: list,
        severity: str = "medium",
        schedule_cron: str = "*/15 * * * *",
        time_window: str = "-20m",
        data_sources: Optional[list] = None,
        false_positive_notes: Optional[list] = None,
    ):
        self.name = name
        self.description = description
        self.spl_query = spl_query
        self.mitre_techniques = mitre_techniques
        self.severity = severity
        self.schedule_cron = schedule_cron
        self.time_window = time_window
        self.data_sources = data_sources or []
        self.false_positive_notes = false_positive_notes or []
        self.created = datetime.utcnow().isoformat()
        self.rule_id = self._generate_rule_id()

    def _generate_rule_id(self) -> str:
        hash_input = f"{self.name}:{self.spl_query}"
        return f"SPL-{hashlib.sha256(hash_input.encode()).hexdigest()[:12].upper()}"

    def validate(self) -> dict:
        """Validate the SPL detection rule for common issues."""
        issues = []
        score = 100

        # Check for missing time constraint
        if "earliest=" not in self.spl_query and "span=" not in self.spl_query:
            issues.append("WARNING: No time constraint in query - may scan too much data")
            score -= 10

        # Check for wildcard-heavy searches
        wildcard_count = self.spl_query.count("*")
        if wildcard_count > 5:
            issues.append(f"WARNING: {wildcard_count} wildcards detected - may impact performance")
            score -= 5 * min(wildcard_count - 5, 4)

        # Check for aggregation
        agg_commands = ["stats", "eventstats", "streamstats", "tstats", "chart", "timechart"]
        has_aggregation = any(cmd in self.spl_query.lower() for cmd in agg_commands)
        if not has_aggregation:
            issues.append("WARNING: No aggregation command - rule may generate excessive alerts")
            score -= 15

        # Check for threshold
        if "where" not in self.spl_query.lower():
            issues.append("WARNING: No where clause - rule has no threshold filtering")
            score -= 15

        # Check for enrichment
        if "lookup" not in self.spl_query.lower():
            issues.append("INFO: No lookup enrichment - consider adding asset/identity context")
            score -= 5

        # Check MITRE mapping
        if not self.mitre_techniques:
            issues.append("WARNING: No MITRE ATT&CK technique mapped")
            score -= 10

        for tech_id in self.mitre_techniques:
            if tech_id not in MITRE_TECHNIQUES:
                issues.append(f"WARNING: Unknown MITRE technique ID: {tech_id}")
                score -= 5

        # Check severity is valid
        valid_severities = ["informational", "low", "medium", "high", "critical"]
        if self.severity not in valid_severities:
            issues.append(f"ERROR: Invalid severity '{self.severity}' - must be one of {valid_severities}")
            score -= 20

        # Check for eval description
        if "eval description" not in self.spl_query.lower() and "eval rule_description" not in self.spl_query.lower():
            issues.append("INFO: No description field in output - analysts will lack context")
            score -= 5

        # Check for CIM data model usage
        if "datamodel=" in self.spl_query.lower() or "tstats" in self.spl_query.lower():
            score += 5  # Bonus for using CIM-accelerated searches

        return {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "valid": score >= 60,
            "quality_score": max(0, min(100, score)),
            "issues": issues,
            "issue_count": len(issues),
        }

    def to_splunk_savedsearch_conf(self) -> str:
        """Generate Splunk savedsearches.conf stanza for the rule."""
        mitre_str = ", ".join(self.mitre_techniques)
        stanza = f"""[{self.name}]
search = {self.spl_query}
description = {self.description}
dispatch.earliest_time = {self.time_window}
dispatch.latest_time = now
cron_schedule = {self.schedule_cron}
is_scheduled = 1
enableSched = 1
alert.severity = {self._severity_to_int()}
alert.suppress = 1
alert.suppress.period = 1h
alert.suppress.fields = src_ip
action.notable = 1
action.notable.param.rule_title = {self.name}
action.notable.param.rule_description = {self.description}
action.notable.param.severity = {self.severity}
action.notable.param.security_domain = threat
action.notable.param.drilldown_name = View triggering events
action.notable.param.drilldown_search = {self.spl_query}
action.notable.param.mitre_attack = {mitre_str}
"""
        return stanza

    def _severity_to_int(self) -> int:
        mapping = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        return mapping.get(self.severity, 3)

    def to_json(self) -> str:
        return json.dumps(
            {
                "rule_id": self.rule_id,
                "name": self.name,
                "description": self.description,
                "spl_query": self.spl_query,
                "mitre_techniques": self.mitre_techniques,
                "severity": self.severity,
                "schedule_cron": self.schedule_cron,
                "time_window": self.time_window,
                "data_sources": self.data_sources,
                "false_positive_notes": self.false_positive_notes,
                "created": self.created,
            },
            indent=2,
        )


class DetectionRuleLibrary:
    """Manages a collection of Splunk detection rules."""

    def __init__(self):
        self.rules = []

    def add_rule(self, rule: SplunkDetectionRule):
        self.rules.append(rule)

    def validate_all(self) -> dict:
        results = {"total_rules": len(self.rules), "valid_rules": 0, "invalid_rules": 0, "details": []}
        for rule in self.rules:
            validation = rule.validate()
            results["details"].append(validation)
            if validation["valid"]:
                results["valid_rules"] += 1
            else:
                results["invalid_rules"] += 1
        return results

    def get_mitre_coverage(self) -> dict:
        coverage = {}
        for rule in self.rules:
            for tech_id in rule.mitre_techniques:
                if tech_id not in coverage:
                    coverage[tech_id] = {
                        "technique": MITRE_TECHNIQUES.get(tech_id, {}).get("name", "Unknown"),
                        "tactic": MITRE_TECHNIQUES.get(tech_id, {}).get("tactic", "Unknown"),
                        "rules": [],
                    }
                coverage[tech_id]["rules"].append(rule.name)
        return {
            "techniques_covered": len(coverage),
            "total_known_techniques": len(MITRE_TECHNIQUES),
            "coverage_percentage": round(len(coverage) / len(MITRE_TECHNIQUES) * 100, 1),
            "coverage_map": coverage,
        }

    def export_savedsearches_conf(self) -> str:
        output = "# Auto-generated Splunk savedsearches.conf\n"
        output += f"# Generated: {datetime.utcnow().isoformat()}\n"
        output += f"# Total Rules: {len(self.rules)}\n\n"
        for rule in self.rules:
            output += rule.to_splunk_savedsearch_conf() + "\n"
        return output


def build_sample_detection_library() -> DetectionRuleLibrary:
    """Build a sample detection rule library with common SOC use cases."""
    library = DetectionRuleLibrary()

    library.add_rule(
        SplunkDetectionRule(
            name="Brute Force - Multiple Failed Logins",
            description="Detects brute force attacks with multiple failed login attempts from a single source",
            spl_query=(
                '| tstats summariesonly=true count from datamodel=Authentication '
                'where Authentication.action=failure by Authentication.src, Authentication.user, _time span=5m '
                '| rename "Authentication.*" as * '
                '| stats count as total_failures dc(user) as unique_users values(user) as targeted_users by src '
                '| where total_failures > 20 AND unique_users > 3 '
                '| lookup asset_lookup ip as src OUTPUT priority as asset_priority '
                '| eval severity=case(unique_users > 10, "critical", unique_users > 5, "high", true(), "medium") '
                '| eval description="Brute force detected from ".src." targeting ".unique_users." accounts"'
            ),
            mitre_techniques=["T1110.001"],
            severity="high",
            schedule_cron="*/5 * * * *",
            time_window="-10m",
            data_sources=["Windows Security Event Log", "Linux Auth Log"],
            false_positive_notes=["Service accounts with expired passwords", "Misconfigured applications"],
        )
    )

    library.add_rule(
        SplunkDetectionRule(
            name="Suspicious PowerShell Execution",
            description="Detects encoded or obfuscated PowerShell commands indicating potential malicious activity",
            spl_query=(
                'index=wineventlog sourcetype=WinEventLog:Security EventCode=4104 '
                '| where match(ScriptBlockText, "(?i)(encodedcommand|invoke-expression|iex|downloadstring|frombase64string|net\\.webclient|invoke-mimikatz)") '
                '| stats count values(ScriptBlockText) as commands by Computer, UserName '
                '| where count > 0 '
                '| lookup identity_lookup identity as UserName OUTPUT department, manager '
                '| eval severity="high" '
                '| eval description="Suspicious PowerShell on ".Computer." by ".UserName'
            ),
            mitre_techniques=["T1059.001", "T1027"],
            severity="high",
            data_sources=["Windows PowerShell Script Block Logging"],
            false_positive_notes=["IT automation scripts using encoded commands", "SCCM deployment scripts"],
        )
    )

    library.add_rule(
        SplunkDetectionRule(
            name="Lateral Movement - Multiple Host Access",
            description="Detects a user or source IP accessing an unusual number of hosts via network logon",
            spl_query=(
                '| tstats summariesonly=true dc(Authentication.dest) as unique_hosts '
                'from datamodel=Authentication where Authentication.action=success Authentication.Logon_Type=3 '
                'by Authentication.src, Authentication.user, _time span=1h '
                '| rename "Authentication.*" as * '
                '| where unique_hosts > 5 '
                '| lookup asset_lookup ip as src OUTPUT asset_name, asset_category '
                '| eval severity=case(unique_hosts > 20, "critical", unique_hosts > 10, "high", true(), "medium") '
                '| eval description=user." accessed ".unique_hosts." hosts from ".src." in 1 hour"'
            ),
            mitre_techniques=["T1021.002", "T1078.002"],
            severity="high",
            data_sources=["Windows Security Event Log"],
            false_positive_notes=["Vulnerability scanners", "IT management tools", "Software deployment systems"],
        )
    )

    return library


if __name__ == "__main__":
    library = build_sample_detection_library()

    print("=" * 70)
    print("SPLUNK SPL DETECTION RULE LIBRARY")
    print("=" * 70)

    # Validate all rules
    validation = library.validate_all()
    print(f"\nTotal Rules: {validation['total_rules']}")
    print(f"Valid Rules: {validation['valid_rules']}")
    print(f"Invalid Rules: {validation['invalid_rules']}")

    for detail in validation["details"]:
        print(f"\n--- {detail['rule_name']} ---")
        print(f"  Rule ID: {detail['rule_id']}")
        print(f"  Quality Score: {detail['quality_score']}/100")
        print(f"  Valid: {detail['valid']}")
        for issue in detail["issues"]:
            print(f"  {issue}")

    # MITRE coverage
    coverage = library.get_mitre_coverage()
    print(f"\nMITRE ATT&CK Coverage: {coverage['techniques_covered']}/{coverage['total_known_techniques']} ({coverage['coverage_percentage']}%)")
    for tech_id, info in coverage["coverage_map"].items():
        print(f"  {tech_id} ({info['technique']}): {', '.join(info['rules'])}")

    # Export savedsearches.conf
    conf = library.export_savedsearches_conf()
    print(f"\n{'=' * 70}")
    print("GENERATED savedsearches.conf")
    print("=" * 70)
    print(conf)
