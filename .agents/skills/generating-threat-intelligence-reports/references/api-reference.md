# API Reference: Threat Intelligence Report Generator Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| jinja2 | >=3.1 | Template rendering for report generation |

## CLI Usage

```bash
python scripts/agent.py \
  --type operational \
  --data /cases/intel_data.json \
  --output-dir /cases/reports/ \
  --output report_meta.json
```

## Report Types

| Type | Audience | Length | Frequency |
|------|----------|--------|-----------|
| strategic | C-suite, board, risk committee | 1-3 pages | Monthly/Quarterly |
| operational | CISO, security directors, IR leads | 3-8 pages | Weekly |
| tactical | SOC analysts, threat hunters | 1-2 pages | Daily/as-needed |
| flash | All security staff | 1 page max | Urgent/as-needed |

## Functions

### `confidence_label(level) -> str`
Maps confidence levels to ICD 203 language: "high" -> "We assess with high confidence", "medium" -> "We assess", "low" -> "Evidence suggests".

### `render_report(report_type, data) -> str`
Renders a Jinja2 template with the provided data dict. Sets defaults for date, org, tlp.

### `validate_report_data(report_type, data) -> list`
Validates required fields per report type. Returns list of error strings.

### `quality_check(rendered) -> list`
Checks rendered report for: minimum length, TLP marker presence, unqualified confidence statements.

### `generate_report(report_type, data_path, output_dir) -> dict`
Full pipeline: load JSON data, validate, render template, run quality checks, save Markdown output.

## TLP Levels

| Level | Sharing Scope |
|-------|---------------|
| RED | Named recipients only |
| AMBER+STRICT | Organization only |
| AMBER | Organization and trusted partners |
| GREEN | Community-wide (ISAC, sector peers) |
| CLEAR | Public distribution |

## Input Data Schema (Operational Example)

```json
{
  "title": "APT29 Campaign Targeting Financial Sector",
  "tlp": "AMBER",
  "org": "Security Operations Center",
  "executive_summary": ["APT29 actively targeting financial institutions..."],
  "adversary": {
    "name": "APT29 / Cozy Bear",
    "motivation": "Espionage",
    "sophistication": "Advanced",
    "target_sectors": ["Financial", "Government"]
  },
  "ttps": [{"tactic": "Initial Access", "technique_id": "T1566.001", "name": "Spearphishing", "observed": "2025-03-01"}],
  "key_judgments": [{"confidence": "high", "statement": "APT29 will continue targeting...", "evidence": "..."}],
  "recommendations": [{"priority": "Critical", "description": "...", "owner": "SOC", "timeframe": "24h", "details": "..."}],
  "iocs": [{"type": "domain", "value": "evil[.]com", "context": "C2", "confidence": "high"}]
}
```

## Output

The agent produces two files:
1. `{type}_report_{date}.md` - Rendered Markdown report with TLP headers
2. `report_meta.json` - Metadata including validation errors and quality issues
