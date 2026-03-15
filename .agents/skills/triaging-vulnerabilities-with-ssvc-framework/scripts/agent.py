#!/usr/bin/env python3
"""Agent for triaging vulnerabilities with the SSVC framework.

Implements CISA's Stakeholder-Specific Vulnerability Categorization
decision tree to produce actionable priorities: Track, Track*,
Attend, or Act based on exploitation status, technical impact,
automatability, and mission prevalence.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class ExploitationStatus:
    NONE = "none"
    POC = "poc"
    ACTIVE = "active"


class TechnicalImpact:
    PARTIAL = "partial"
    TOTAL = "total"


class Automatability:
    NO = "no"
    YES = "yes"


class MissionPrevalence:
    MINIMAL = "minimal"
    SUPPORT = "support"
    ESSENTIAL = "essential"


class SSVCDecision:
    TRACK = "Track"
    TRACK_STAR = "Track*"
    ATTEND = "Attend"
    ACT = "Act"


SSVC_DECISION_TREE = {
    (ExploitationStatus.ACTIVE, TechnicalImpact.TOTAL): SSVCDecision.ACT,
    (ExploitationStatus.ACTIVE, TechnicalImpact.PARTIAL, Automatability.YES): SSVCDecision.ACT,
    (ExploitationStatus.ACTIVE, TechnicalImpact.PARTIAL, Automatability.NO, MissionPrevalence.ESSENTIAL): SSVCDecision.ACT,
    (ExploitationStatus.ACTIVE, TechnicalImpact.PARTIAL, Automatability.NO, MissionPrevalence.SUPPORT): SSVCDecision.ATTEND,
    (ExploitationStatus.ACTIVE, TechnicalImpact.PARTIAL, Automatability.NO, MissionPrevalence.MINIMAL): SSVCDecision.ATTEND,
    (ExploitationStatus.POC, TechnicalImpact.TOTAL, Automatability.YES): SSVCDecision.ATTEND,
    (ExploitationStatus.POC, TechnicalImpact.TOTAL, Automatability.NO): SSVCDecision.TRACK_STAR,
    (ExploitationStatus.POC, TechnicalImpact.PARTIAL): SSVCDecision.TRACK_STAR,
    (ExploitationStatus.NONE, TechnicalImpact.TOTAL): SSVCDecision.TRACK_STAR,
    (ExploitationStatus.NONE, TechnicalImpact.PARTIAL): SSVCDecision.TRACK,
}


class SSVCTriageAgent:
    """Triages vulnerabilities using the SSVC decision tree."""

    def __init__(self, output_dir="./ssvc_triage"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = []

    def check_cisa_kev(self, cve_id):
        """Check if CVE is in CISA Known Exploited Vulnerabilities catalog."""
        if not requests:
            return None
        resp = None
        try:
            resp = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=15,
            )
        except Exception:
            return None
        if resp and resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    return {
                        "in_kev": True,
                        "vendor": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "date_added": vuln.get("dateAdded"),
                        "due_date": vuln.get("dueDate"),
                    }
        return {"in_kev": False}

    def get_epss_score(self, cve_id):
        """Get EPSS probability score from FIRST API."""
        if not requests:
            return None
        try:
            resp = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    return {
                        "cve": cve_id,
                        "epss": float(data[0].get("epss", 0)),
                        "percentile": float(data[0].get("percentile", 0)),
                    }
        except Exception:
            pass
        return None

    def determine_exploitation(self, cve_id):
        """Determine exploitation status using KEV and EPSS."""
        kev = self.check_cisa_kev(cve_id)
        if kev and kev.get("in_kev"):
            return ExploitationStatus.ACTIVE, kev
        epss = self.get_epss_score(cve_id)
        if epss and epss.get("epss", 0) > 0.5:
            return ExploitationStatus.POC, epss
        if epss and epss.get("epss", 0) > 0.1:
            return ExploitationStatus.POC, epss
        return ExploitationStatus.NONE, epss

    def evaluate_decision(self, exploitation, technical_impact, automatability=None,
                          mission_prevalence=None):
        """Walk the SSVC decision tree to produce a prioritization."""
        if (exploitation, technical_impact) in SSVC_DECISION_TREE:
            return SSVC_DECISION_TREE[(exploitation, technical_impact)]
        if automatability:
            key = (exploitation, technical_impact, automatability)
            if key in SSVC_DECISION_TREE:
                return SSVC_DECISION_TREE[key]
            if mission_prevalence:
                key = (exploitation, technical_impact, automatability, mission_prevalence)
                if key in SSVC_DECISION_TREE:
                    return SSVC_DECISION_TREE[key]
        return SSVCDecision.TRACK

    def triage_cve(self, cve_id, technical_impact=TechnicalImpact.PARTIAL,
                   automatability=Automatability.NO,
                   mission_prevalence=MissionPrevalence.SUPPORT):
        """Full SSVC triage for a single CVE."""
        exploitation, enrichment = self.determine_exploitation(cve_id)
        decision = self.evaluate_decision(exploitation, technical_impact,
                                          automatability, mission_prevalence)
        result = {
            "cve_id": cve_id,
            "exploitation_status": exploitation,
            "technical_impact": technical_impact,
            "automatability": automatability,
            "mission_prevalence": mission_prevalence,
            "decision": decision,
            "enrichment": enrichment,
            "remediation_timeline": self._get_timeline(decision),
        }
        self.results.append(result)
        return result

    def _get_timeline(self, decision):
        timelines = {
            SSVCDecision.ACT: "Immediate - remediate within 24-48 hours",
            SSVCDecision.ATTEND: "Urgent - remediate within 1-2 weeks",
            SSVCDecision.TRACK_STAR: "Scheduled - remediate in next patch cycle",
            SSVCDecision.TRACK: "Monitor - include in regular vulnerability management",
        }
        return timelines.get(decision, "Unknown")

    def triage_batch(self, cves, defaults=None):
        """Triage a list of CVEs with optional default parameters."""
        defaults = defaults or {}
        for cve in cves:
            self.triage_cve(
                cve,
                technical_impact=defaults.get("technical_impact", TechnicalImpact.PARTIAL),
                automatability=defaults.get("automatability", Automatability.NO),
                mission_prevalence=defaults.get("mission_prevalence", MissionPrevalence.SUPPORT),
            )
        return self.results

    def generate_report(self, cves=None):
        if cves:
            self.triage_batch(cves)
        by_decision = {}
        for r in self.results:
            d = r["decision"]
            by_decision[d] = by_decision.get(d, 0) + 1

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "framework": "SSVC (CISA Stakeholder-Specific Vulnerability Categorization)",
            "total_triaged": len(self.results),
            "by_decision": by_decision,
            "triage_results": self.results,
        }
        out = self.output_dir / "ssvc_triage_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <CVE-ID> [CVE-ID2 ...] [--impact total|partial]")
        sys.exit(1)
    cves = [a for a in sys.argv[1:] if a.startswith("CVE-")]
    impact = TechnicalImpact.PARTIAL
    if "--impact" in sys.argv:
        val = sys.argv[sys.argv.index("--impact") + 1]
        impact = TechnicalImpact.TOTAL if val == "total" else TechnicalImpact.PARTIAL
    agent = SSVCTriageAgent()
    agent.generate_report(cves)


if __name__ == "__main__":
    main()
