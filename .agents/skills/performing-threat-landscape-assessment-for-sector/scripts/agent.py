#!/usr/bin/env python3
"""Agent for sector-specific threat landscape assessment.

Uses the attackcti library to query MITRE ATT&CK for threat groups
targeting a sector, analyzes common techniques, maps attack vectors,
and generates a strategic threat landscape report.
"""

import json
import sys
from datetime import datetime
from collections import Counter

try:
    from attackcti import attack_client
    HAS_ATTACKCTI = True
except ImportError:
    HAS_ATTACKCTI = False


SECTOR_GROUPS = {
    "financial": ["FIN7", "FIN8", "FIN11", "Carbanak", "Lazarus Group",
                  "Cobalt Group", "TA505"],
    "healthcare": ["FIN12", "Wizard Spider", "Vice Society", "Conti"],
    "energy": ["Sandworm Team", "Dragonfly", "TEMP.Veles", "XENOTIME"],
    "government": ["APT29", "APT28", "Turla", "Gamaredon Group",
                   "Mustang Panda", "APT41"],
    "manufacturing": ["APT41", "TEMP.Veles", "Dragonfly", "HEXANE"],
    "technology": ["APT41", "Lazarus Group", "APT10", "Winnti Group"],
    "retail": ["FIN7", "FIN8", "Carbanak", "Magecart"],
}

SECTOR_VECTORS = {
    "financial": {
        "primary": ["Spearphishing (T1566)", "Exploit Public-Facing App (T1190)",
                     "Valid Accounts (T1078)", "Supply Chain (T1195)"],
        "emerging": ["MFA Fatigue", "QR Phishing", "BEC", "API Key Theft"],
    },
    "healthcare": {
        "primary": ["Spearphishing (T1566)", "Exploit Public-Facing App (T1190)",
                     "External Remote Services (T1133)", "Valid Accounts (T1078)"],
        "emerging": ["IoMT Exploitation", "Telehealth Attacks",
                     "EHR Supply Chain"],
    },
    "energy": {
        "primary": ["Spearphishing (T1566)", "Supply Chain (T1195)",
                     "External Remote Services (T1133)"],
        "emerging": ["OT/ICS Protocol Exploitation", "SCADA Remote Access",
                     "Vendor VPN Exploitation"],
    },
}


class ThreatLandscapeAgent:
    """Conducts sector-specific cyber threat landscape assessment."""

    def __init__(self, sector):
        self.sector = sector.lower()
        self.client = attack_client() if HAS_ATTACKCTI else None
        self.actor_profiles = []
        self.technique_ranking = []

    def profile_sector_actors(self):
        """Query ATT&CK for groups known to target this sector."""
        target_names = SECTOR_GROUPS.get(self.sector, [])
        if not self.client:
            return [{"name": n, "source": "static_mapping"} for n in target_names]

        all_groups = self.client.get_groups()
        for group_name in target_names:
            group = next(
                (g for g in all_groups
                 if g.get("name", "").lower() == group_name.lower()
                 or group_name.lower() in
                 [a.lower() for a in g.get("aliases", [])]),
                None)
            if not group:
                self.actor_profiles.append({"name": group_name, "found": False})
                continue

            attack_id = ""
            for ref in group.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id", "")
                    break

            techniques = []
            if attack_id:
                techs = self.client.get_techniques_used_by_group(attack_id)
                for t in techs:
                    for ref in t.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            techniques.append({
                                "id": ref.get("external_id", ""),
                                "name": t.get("name", ""),
                            })
                            break

            self.actor_profiles.append({
                "name": group.get("name", ""),
                "attack_id": attack_id,
                "aliases": group.get("aliases", [])[:5],
                "description": (group.get("description", "") or "")[:300],
                "technique_count": len(techniques),
                "techniques": techniques[:25],
            })
        return self.actor_profiles

    def rank_techniques(self):
        """Rank techniques by how many sector actors use them."""
        counter = Counter()
        for actor in self.actor_profiles:
            for tech in actor.get("techniques", []):
                key = f"{tech['id']}|{tech['name']}"
                counter[key] += 1

        self.technique_ranking = [
            {"technique_id": k.split("|")[0],
             "name": k.split("|")[1] if "|" in k else "",
             "actor_count": count,
             "actors": [a["name"] for a in self.actor_profiles
                        if any(t["id"] == k.split("|")[0]
                               for t in a.get("techniques", []))]}
            for k, count in counter.most_common(20)
        ]
        return self.technique_ranking

    def get_attack_vectors(self):
        """Return known attack vectors for this sector."""
        return SECTOR_VECTORS.get(self.sector, {
            "primary": ["Spearphishing (T1566)",
                         "Exploit Public-Facing App (T1190)"],
            "emerging": ["Supply Chain Compromise"],
        })

    def generate_report(self):
        """Generate sector threat landscape report."""
        self.profile_sector_actors()
        self.rank_techniques()

        report = {
            "sector": self.sector,
            "report_date": datetime.utcnow().isoformat(),
            "threat_actors": len(self.actor_profiles),
            "actor_profiles": self.actor_profiles,
            "top_techniques": self.technique_ranking[:15],
            "attack_vectors": self.get_attack_vectors(),
            "recommendations": [
                "Prioritize detections for top 10 techniques",
                "Conduct threat-informed red team exercises",
                "Join sector ISAC for real-time sharing",
                "Map defenses to MITRE ATT&CK Navigator",
                "Monitor sector-specific threat advisories",
            ],
        }

        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    sector = sys.argv[1] if len(sys.argv) > 1 else "financial"
    agent = ThreatLandscapeAgent(sector)
    agent.generate_report()


if __name__ == "__main__":
    main()
