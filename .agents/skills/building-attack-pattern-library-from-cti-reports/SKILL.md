---
name: building-attack-pattern-library-from-cti-reports
description: Extract and catalog attack patterns from cyber threat intelligence reports into a structured STIX-based library mapped to MITRE ATT&CK for detection engineering and threat-informed defense.
domain: cybersecurity
subdomain: threat-intelligence
tags: [attack-pattern, cti-reports, mitre-attack, stix, detection-engineering, threat-intelligence, nlp, extraction]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Building Attack Pattern Library from CTI Reports

## Overview

Cyber threat intelligence (CTI) reports from vendors like Mandiant, CrowdStrike, Talos, and Microsoft contain detailed descriptions of adversary behaviors that can be extracted, normalized, and cataloged into a structured attack pattern library. This skill covers parsing CTI reports to extract adversary techniques, mapping behaviors to MITRE ATT&CK technique IDs, creating STIX 2.1 Attack Pattern objects, building a searchable library indexed by tactic, technique, and threat actor, and generating detection rule templates from documented patterns.

## Prerequisites

- Python 3.9+ with `stix2`, `mitreattack-python`, `spacy`, `requests` libraries
- Collection of CTI reports (PDF, HTML, or text format)
- MITRE ATT&CK STIX data (local or via TAXII)
- Understanding of ATT&CK technique structure and naming conventions
- Familiarity with detection engineering concepts (Sigma, YARA)

## Key Concepts

### Attack Pattern Extraction

CTI reports describe adversary behaviors in natural language. Extraction involves identifying action verbs and technical terms that map to ATT&CK techniques, recognizing tool names and malware families, identifying infrastructure indicators, and mapping sequences of behaviors to attack chains (kill chain phases).

### STIX 2.1 Attack Pattern Objects

STIX defines Attack Pattern as a Structured Domain Object (SDO) that describes ways threat actors attempt to compromise targets. Each pattern links to ATT&CK via external references, includes kill chain phases (tactics), and can be related to Intrusion Sets, Malware, and Tool objects.

### Detection Rule Generation

Extracted attack patterns inform detection engineering by providing: specific procedure examples for Sigma rule creation, behavioral sequences for correlation rules, IOC patterns for YARA and Snort rules, and data source requirements for telemetry gaps.

## Practical Steps

### Step 1: Parse CTI Reports and Extract Behaviors

```python
import re
import json
from collections import defaultdict

class CTIReportParser:
    """Parse CTI reports to extract adversary behaviors."""

    BEHAVIOR_INDICATORS = [
        "used", "executed", "deployed", "leveraged", "exploited",
        "established", "created", "modified", "downloaded", "uploaded",
        "exfiltrated", "injected", "enumerated", "spawned", "dropped",
        "persisted", "escalated", "moved laterally", "collected",
        "encrypted", "compressed", "encoded", "obfuscated",
    ]

    TOOL_PATTERNS = [
        r'\b(Cobalt Strike|Mimikatz|PsExec|BloodHound|Rubeus|Impacket)\b',
        r'\b(PowerShell|cmd\.exe|WMI|WMIC|certutil|bitsadmin)\b',
        r'\b(Metasploit|Empire|Covenant|Sliver|Brute Ratel)\b',
        r'\b(Lazagne|SharpHound|ADFind|Sharphound|Invoke-Obfuscation)\b',
    ]

    TECHNIQUE_KEYWORDS = {
        "spearphishing": "T1566",
        "phishing attachment": "T1566.001",
        "phishing link": "T1566.002",
        "powershell": "T1059.001",
        "command line": "T1059.003",
        "scheduled task": "T1053.005",
        "registry run key": "T1547.001",
        "process injection": "T1055",
        "dll side-loading": "T1574.002",
        "credential dumping": "T1003",
        "lsass": "T1003.001",
        "kerberoasting": "T1558.003",
        "pass the hash": "T1550.002",
        "remote desktop": "T1021.001",
        "smb": "T1021.002",
        "winrm": "T1021.006",
        "data staging": "T1074",
        "exfiltration over c2": "T1041",
        "dns tunneling": "T1071.004",
        "web shell": "T1505.003",
    }

    def parse_report(self, text, report_metadata=None):
        """Parse a CTI report and extract behaviors."""
        sentences = re.split(r'[.!?]\s+', text)
        behaviors = []

        for sentence in sentences:
            sentence_lower = sentence.lower()
            # Check for behavior indicators
            for indicator in self.BEHAVIOR_INDICATORS:
                if indicator in sentence_lower:
                    behavior = {
                        "sentence": sentence.strip(),
                        "action": indicator,
                        "tools": self._extract_tools(sentence),
                        "technique_hints": self._match_techniques(sentence_lower),
                    }
                    if behavior["technique_hints"]:
                        behaviors.append(behavior)
                    break

        print(f"[+] Extracted {len(behaviors)} behavioral indicators from report")
        return behaviors

    def _extract_tools(self, text):
        """Extract tool/malware names from text."""
        tools = set()
        for pattern in self.TOOL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            tools.update(matches)
        return list(tools)

    def _match_techniques(self, text):
        """Match text to ATT&CK technique hints."""
        matches = []
        for keyword, tech_id in self.TECHNIQUE_KEYWORDS.items():
            if keyword in text:
                matches.append({"keyword": keyword, "technique_id": tech_id})
        return matches

parser = CTIReportParser()
sample_report = """
The threat actor used spearphishing attachments with macro-enabled documents to
gain initial access. Once inside, they executed PowerShell scripts to download
additional tooling. The actor leveraged Mimikatz to dump credentials from LSASS
memory. They then used pass the hash techniques for lateral movement via SMB
to multiple systems. Data was staged in a compressed archive and exfiltrated
over the existing C2 channel. The actor established persistence through
scheduled tasks and registry run keys.
"""
behaviors = parser.parse_report(sample_report)
```

### Step 2: Map Behaviors to ATT&CK Techniques

```python
from attackcti import attack_client

class ATTACKMapper:
    def __init__(self):
        self.lift = attack_client()
        self.techniques = {}
        self._load_techniques()

    def _load_techniques(self):
        """Load all ATT&CK techniques for mapping."""
        all_techs = self.lift.get_enterprise_techniques()
        for tech in all_techs:
            tech_id = ""
            for ref in tech.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    break
            if tech_id:
                self.techniques[tech_id] = {
                    "name": tech.get("name", ""),
                    "description": tech.get("description", "")[:500],
                    "tactics": [p.get("phase_name") for p in tech.get("kill_chain_phases", [])],
                    "platforms": tech.get("x_mitre_platforms", []),
                    "data_sources": tech.get("x_mitre_data_sources", []),
                }
        print(f"[+] Loaded {len(self.techniques)} ATT&CK techniques")

    def map_behaviors(self, behaviors):
        """Map extracted behaviors to ATT&CK techniques."""
        mapped = []
        for behavior in behaviors:
            for hint in behavior.get("technique_hints", []):
                tech_id = hint["technique_id"]
                if tech_id in self.techniques:
                    tech_info = self.techniques[tech_id]
                    mapped.append({
                        "technique_id": tech_id,
                        "technique_name": tech_info["name"],
                        "tactics": tech_info["tactics"],
                        "source_sentence": behavior["sentence"],
                        "tools_observed": behavior["tools"],
                        "keyword_matched": hint["keyword"],
                        "data_sources": tech_info["data_sources"],
                    })
        print(f"[+] Mapped {len(mapped)} behaviors to ATT&CK techniques")
        return mapped

mapper = ATTACKMapper()
mapped_behaviors = mapper.map_behaviors(behaviors)
```

### Step 3: Create STIX 2.1 Attack Pattern Library

```python
from stix2 import AttackPattern, Relationship, Bundle, TLP_GREEN
from datetime import datetime

class AttackPatternLibrary:
    def __init__(self):
        self.patterns = []
        self.relationships = []

    def add_pattern_from_mapping(self, mapping, report_source="CTI Report"):
        """Create STIX Attack Pattern from mapped behavior."""
        pattern = AttackPattern(
            name=mapping["technique_name"],
            description=f"Observed: {mapping['source_sentence']}\n\n"
                        f"Tools: {', '.join(mapping['tools_observed']) or 'None identified'}\n"
                        f"Source: {report_source}",
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": mapping["technique_id"],
                "url": f"https://attack.mitre.org/techniques/{mapping['technique_id'].replace('.', '/')}/",
            }],
            kill_chain_phases=[{
                "kill_chain_name": "mitre-attack",
                "phase_name": tactic,
            } for tactic in mapping["tactics"]],
            object_marking_refs=[TLP_GREEN],
        )
        self.patterns.append(pattern)
        return pattern

    def build_library(self, mapped_behaviors, report_source="CTI Report"):
        """Build complete attack pattern library from mappings."""
        seen_techniques = set()
        for mapping in mapped_behaviors:
            tech_id = mapping["technique_id"]
            if tech_id not in seen_techniques:
                self.add_pattern_from_mapping(mapping, report_source)
                seen_techniques.add(tech_id)

        bundle = Bundle(objects=self.patterns + self.relationships)
        print(f"[+] Library: {len(self.patterns)} attack patterns")
        return bundle

    def export_library(self, output_file="attack_pattern_library.json"):
        bundle = Bundle(objects=self.patterns + self.relationships)
        with open(output_file, "w") as f:
            f.write(bundle.serialize(pretty=True))
        print(f"[+] Library exported to {output_file}")

    def generate_detection_templates(self, mapped_behaviors):
        """Generate Sigma rule templates from attack patterns."""
        templates = []
        for mapping in mapped_behaviors:
            template = {
                "title": f"Detection: {mapping['technique_name']} ({mapping['technique_id']})",
                "status": "experimental",
                "description": f"Detects {mapping['technique_name']} based on CTI report observation",
                "references": [
                    f"https://attack.mitre.org/techniques/{mapping['technique_id'].replace('.', '/')}/",
                ],
                "tags": [
                    f"attack.{mapping['tactics'][0]}" if mapping['tactics'] else "attack.unknown",
                    f"attack.{mapping['technique_id'].lower()}",
                ],
                "data_sources": mapping.get("data_sources", []),
                "observed_tools": mapping.get("tools_observed", []),
                "source_context": mapping["source_sentence"],
            }
            templates.append(template)

        with open("detection_templates.json", "w") as f:
            json.dump(templates, f, indent=2)
        print(f"[+] Generated {len(templates)} detection templates")
        return templates

library = AttackPatternLibrary()
bundle = library.build_library(mapped_behaviors, "Sample CTI Report")
library.export_library()
templates = library.generate_detection_templates(mapped_behaviors)
```

## Validation Criteria

- CTI report parsed and behavioral indicators extracted
- Behaviors mapped to ATT&CK techniques with confidence
- STIX 2.1 Attack Pattern objects created with proper references
- Library searchable by tactic, technique, and threat actor
- Detection templates generated from documented patterns
- Library exportable as STIX bundle for sharing

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.1 Attack Pattern SDO](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy)
- [CISA: Best Practices for ATT&CK Mapping](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)
- [attackcti Python Library](https://github.com/OTRF/ATTACK-Python-Client)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK STIX Data](https://github.com/mitre/cti)
