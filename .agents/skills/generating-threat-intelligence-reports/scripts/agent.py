#!/usr/bin/env python3
"""Threat intelligence report generation agent using jinja2 for template-based reporting."""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

try:
    from jinja2 import Environment, BaseLoader
except ImportError:
    sys.exit("jinja2 required: pip install jinja2")

TLP_LEVELS = {
    "RED": "Named recipients only; do not share outside the briefing room",
    "AMBER+STRICT": "Organization only; no sharing with partners or subsidiaries",
    "AMBER": "Organization and trusted partners with need-to-know",
    "GREEN": "Community-wide sharing (ISAC members, sector peers)",
    "CLEAR": "Public distribution; no restrictions",
}

CONFIDENCE_MAP = {
    "high": "We assess with high confidence",
    "medium": "We assess",
    "low": "Evidence suggests",
}

REPORT_TEMPLATES = {
    "strategic": """
# {{ title }}
**TLP:{{ tlp }}** | {{ date }} | {{ org }}

## Executive Summary
{% for point in executive_summary %}
- {{ point }}
{% endfor %}

## Threat Landscape Overview
{{ threat_overview }}

## Business Impact Assessment
{{ impact_assessment }}

## Key Judgments
{% for judgment in key_judgments %}
{{ loop.index }}. {{ confidence_label(judgment.confidence) }} that {{ judgment.statement }}
   - Evidence: {{ judgment.evidence }}
{% endfor %}

## Recommended Strategic Actions
{% for action in recommendations %}
- **{{ action.priority }}** ({{ action.timeframe }}): {{ action.description }}
{% endfor %}

## Intelligence Gaps
{% for gap in intelligence_gaps %}
- {{ gap }}
{% endfor %}

---
Classification: TLP:{{ tlp }} - {{ tlp_description }}
""",
    "operational": """
# {{ title }}
**TLP:{{ tlp }}** | {{ date }} | {{ org }}

## Executive Summary
{% for point in executive_summary %}
- {{ point }}
{% endfor %}

## Active Campaign Analysis
### Adversary Profile
- **Name**: {{ adversary.name }}
- **Motivation**: {{ adversary.motivation }}
- **Sophistication**: {{ adversary.sophistication }}
- **Target Sectors**: {{ adversary.target_sectors | join(', ') }}

### TTPs (MITRE ATT&CK)
| Tactic | Technique ID | Technique Name | Observed |
|--------|-------------|----------------|----------|
{% for ttp in ttps %}
| {{ ttp.tactic }} | {{ ttp.technique_id }} | {{ ttp.name }} | {{ ttp.observed }} |
{% endfor %}

## Key Judgments
{% for judgment in key_judgments %}
{{ loop.index }}. {{ confidence_label(judgment.confidence) }} that {{ judgment.statement }}
{% endfor %}

## Defensive Recommendations
{% for action in recommendations %}
### {{ action.priority }}: {{ action.description }}
- **Owner**: {{ action.owner }}
- **Timeframe**: {{ action.timeframe }}
- **Details**: {{ action.details }}
{% endfor %}

## IOC Summary
| Type | Value | Context | Confidence |
|------|-------|---------|------------|
{% for ioc in iocs %}
| {{ ioc.type }} | {{ ioc.value }} | {{ ioc.context }} | {{ ioc.confidence }} |
{% endfor %}

---
Classification: TLP:{{ tlp }} - {{ tlp_description }}
""",
    "tactical": """
# {{ title }}
**TLP:{{ tlp }}** | {{ date }} | {{ org }}

## Summary
{{ summary }}

## Indicators of Compromise
| Type | Value | Context | Confidence |
|------|-------|---------|------------|
{% for ioc in iocs %}
| {{ ioc.type }} | `{{ ioc.value }}` | {{ ioc.context }} | {{ ioc.confidence }} |
{% endfor %}

## Detection Rules
{% for rule in detection_rules %}
### {{ rule.name }} ({{ rule.format }})
```
{{ rule.content }}
```
{% endfor %}

## MITRE ATT&CK Mapping
{% for ttp in ttps %}
- **{{ ttp.technique_id }}** - {{ ttp.name }}: {{ ttp.description }}
{% endfor %}

## Patching Guidance
{% for patch in patches %}
- **{{ patch.cve }}**: {{ patch.description }} ({{ patch.severity }})
{% endfor %}

---
Classification: TLP:{{ tlp }} - {{ tlp_description }}
""",
    "flash": """
# FLASH: {{ title }}
**TLP:{{ tlp }}** | {{ date }} | IMMEDIATE ACTION REQUIRED

## What Is Happening
{{ what_is_happening }}

## Immediate Risk
{{ immediate_risk }}

## What To Do Right Now
{% for action in immediate_actions %}
{{ loop.index }}. {{ action }}
{% endfor %}

## Indicators of Compromise
{% for ioc in iocs %}
- {{ ioc.type }}: `{{ ioc.value }}`
{% endfor %}

## Additional Context
{{ context }}

---
Classification: TLP:{{ tlp }} - {{ tlp_description }}
Disseminated: {{ date }}
""",
}


def confidence_label(level: str) -> str:
    """Map confidence level to ICD 203 language."""
    return CONFIDENCE_MAP.get(level.lower(), "Evidence suggests")


def render_report(report_type: str, data: dict) -> str:
    """Render a threat intelligence report from template and data."""
    template_str = REPORT_TEMPLATES.get(report_type)
    if not template_str:
        raise ValueError(f"Unknown report type: {report_type}. Available: {list(REPORT_TEMPLATES.keys())}")

    data.setdefault("date", datetime.utcnow().strftime("%Y-%m-%d"))
    data.setdefault("org", "Security Operations")
    data.setdefault("tlp", "AMBER")
    data["tlp_description"] = TLP_LEVELS.get(data["tlp"], "")

    env = Environment(loader=BaseLoader())
    env.globals["confidence_label"] = confidence_label
    template = env.from_string(template_str)
    return template.render(**data)


def validate_report_data(report_type: str, data: dict) -> List[str]:
    """Validate that required fields are present for the report type."""
    errors = []
    required_all = ["title", "tlp"]
    for field in required_all:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    if data.get("tlp") and data["tlp"] not in TLP_LEVELS:
        errors.append(f"Invalid TLP level: {data['tlp']}. Valid: {list(TLP_LEVELS.keys())}")

    type_required = {
        "strategic": ["executive_summary", "threat_overview", "key_judgments", "recommendations"],
        "operational": ["executive_summary", "adversary", "ttps", "recommendations"],
        "tactical": ["summary", "iocs"],
        "flash": ["what_is_happening", "immediate_risk", "immediate_actions"],
    }
    for field in type_required.get(report_type, []):
        if field not in data:
            errors.append(f"Missing field for {report_type} report: {field}")
    return errors


def quality_check(rendered: str) -> List[str]:
    """Run quality checks on rendered report."""
    issues = []
    if len(rendered) < 200:
        issues.append("Report is very short; may lack sufficient detail")
    if "TLP:" not in rendered:
        issues.append("Missing TLP classification marker")
    unqualified = 0
    for keyword in ["will", "is certain", "definitely", "undoubtedly"]:
        if keyword in rendered.lower():
            unqualified += 1
    if unqualified > 0:
        issues.append(f"Found {unqualified} statements that may need confidence qualifiers")
    return issues


def generate_report(report_type: str, data_path: str, output_dir: str) -> dict:
    """Load data, validate, render, and save the report."""
    with open(data_path, "r") as f:
        data = json.load(f)

    validation_errors = validate_report_data(report_type, data)
    if validation_errors:
        logger.warning("Validation issues: %s", validation_errors)

    rendered = render_report(report_type, data)
    quality_issues = quality_check(rendered)
    if quality_issues:
        logger.warning("Quality issues: %s", quality_issues)

    report_filename = f"{report_type}_report_{datetime.utcnow().strftime('%Y%m%d')}.md"
    report_path = os.path.join(output_dir, report_filename)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    logger.info("Report saved to %s", report_path)

    return {
        "report_type": report_type,
        "output_path": report_path,
        "tlp": data.get("tlp", "AMBER"),
        "validation_errors": validation_errors,
        "quality_issues": quality_issues,
        "rendered_length": len(rendered),
    }


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Report Generator")
    parser.add_argument("--type", required=True, choices=list(REPORT_TEMPLATES.keys()),
                        help="Report type: strategic, operational, tactical, flash")
    parser.add_argument("--data", required=True, help="Path to JSON data file with report content")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--output", default="report_meta.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    result = generate_report(args.type, args.data, args.output_dir)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    logger.info("Metadata saved to %s", out_path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
