---
name: performing-ai-driven-osint-correlation
description: >-
  Use AI and LLM-based reasoning to correlate findings across multiple OSINT
  sources—username enumeration, email lookups, social media profiles, domain
  records, breach databases, and dark-web mentions—into unified intelligence
  profiles with confidence scoring and link analysis.
domain: cybersecurity
subdomain: threat-intelligence
tags:
  - osint
  - ai-correlation
  - threat-intelligence
  - reconnaissance
  - link-analysis
  - target-profiling
  - sherlock
  - theharvester
  - spiderfoot
  - maltego
version: "1.0"
author: juliosuas
license: Apache-2.0
---

# Performing AI-Driven OSINT Correlation

## When to Use

- You have collected raw OSINT data from multiple tools and sources but need to identify connections, contradictions, and patterns across them.
- You need to build a unified intelligence profile for a target entity (person, organization, or infrastructure) from fragmented data.
- Traditional manual correlation is too slow or error-prone for the volume of data collected.
- You want confidence-scored assessments of identity linkage across platforms rather than simple keyword matching.

## Prerequisites

- Python 3.10+ with `requests`, `json`, and `csv` libraries
- [Sherlock](https://github.com/sherlock-project/sherlock) installed (`pip install sherlock-project`)
- [theHarvester](https://github.com/laramies/theHarvester) installed (`pip install theHarvester`)
- [SpiderFoot](https://github.com/smicallef/spiderfoot) 4.0+ running on localhost:5001
- Access to an LLM API (OpenAI, Anthropic, or local model via Ollama)
- Optional: Maltego CE for graph visualization of correlation results
- Optional: API keys for Shodan, VirusTotal, HaveIBeenPwned, Hunter.io

## Workflow

### Phase 1 — Multi-Source OSINT Collection

1. **Enumerate usernames across platforms with Sherlock:**

   ```bash
   sherlock "targetusername" --output /tmp/osint/sherlock-results.txt --csv
   ```

2. **Harvest emails, subdomains, and hosts with theHarvester:**

   ```bash
   theHarvester -d targetdomain.com -b all -f /tmp/osint/harvester-results.json
   ```

3. **Run a SpiderFoot passive scan via REST API:**

   ```bash
   curl -s http://localhost:5001/api/scan/start \
     -d "scanname=target-recon&scantarget=targetdomain.com&usecase=passive" \
     | jq '.scanid'
   ```

4. **Export SpiderFoot results when scan completes:**

   ```bash
   SCAN_ID="<scanid_from_step_3>"
   curl -s "http://localhost:5001/api/scan/${SCAN_ID}/results?type=all" \
     -o /tmp/osint/spiderfoot-results.json
   ```

5. **Query breach databases for email exposure (example with HIBP API):**

   ```bash
   curl -s -H "hibp-api-key: ${HIBP_KEY}" \
     "https://haveibeenpwned.com/api/v3/breachedaccount/target@example.com" \
     -o /tmp/osint/breach-results.json
   ```

### Phase 2 — Data Normalization

6. **Normalize all collected data into a common schema.** Create a unified JSON structure that tags each finding with its source, timestamp, and data type:

   ```bash
   cat > /tmp/osint/normalize.py << 'EOF'
   import json, csv, sys, os
   from datetime import datetime

   findings = []

   # Normalize Sherlock CSV results
   sherlock_path = "/tmp/osint/sherlock-results.csv"
   if os.path.exists(sherlock_path):
       with open(sherlock_path) as f:
           for row in csv.DictReader(f):
               findings.append({
                   "source": "sherlock",
                   "type": "social_profile",
                   "platform": row.get("name", ""),
                   "url": row.get("url_user", ""),
                   "username": row.get("username", ""),
                   "status": row.get("status", ""),
                   "collected_at": datetime.utcnow().isoformat()
               })

   # Normalize theHarvester JSON results
   harvester_path = "/tmp/osint/harvester-results.json"
   if os.path.exists(harvester_path):
       with open(harvester_path) as f:
           data = json.load(f)
           for email in data.get("emails", []):
               findings.append({
                   "source": "theHarvester",
                   "type": "email",
                   "value": email,
                   "collected_at": datetime.utcnow().isoformat()
               })
           for host in data.get("hosts", []):
               findings.append({
                   "source": "theHarvester",
                   "type": "hostname",
                   "value": host,
                   "collected_at": datetime.utcnow().isoformat()
               })

   # Normalize SpiderFoot results
   sf_path = "/tmp/osint/spiderfoot-results.json"
   if os.path.exists(sf_path):
       with open(sf_path) as f:
           for item in json.load(f):
               findings.append({
                   "source": "spiderfoot",
                   "type": item.get("type", "unknown"),
                   "value": item.get("data", ""),
                   "module": item.get("module", ""),
                   "collected_at": datetime.utcnow().isoformat()
               })

   with open("/tmp/osint/normalized-findings.json", "w") as f:
       json.dump(findings, f, indent=2)

   print(f"Normalized {len(findings)} findings from {len(set(f['source'] for f in findings))} sources")
   EOF
   python3 /tmp/osint/normalize.py
   ```

### Phase 3 — AI-Driven Correlation

7. **Send normalized findings to an LLM for cross-source correlation analysis:**

   ```bash
   cat > /tmp/osint/correlate.py << 'PYEOF'
   import json, os
   from openai import OpenAI  # or anthropic, ollama, etc.

   client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

   with open("/tmp/osint/normalized-findings.json") as f:
       findings = json.load(f)

   correlation_prompt = f"""You are an OSINT analyst. Analyze these findings collected
   from multiple sources and produce a correlation report.

   For each identity or entity you detect:
   1. List all linked accounts/profiles with the evidence connecting them.
   2. Assign a confidence score (0.0-1.0) for each linkage based on:
      - Exact username match across platforms (high)
      - Similar usernames with shared metadata (medium)
      - Same email in breach data and registration (high)
      - Co-occurring infrastructure (IP, domain) (medium)
      - Temporal correlation of account creation dates (low-medium)
   3. Identify contradictions or potential false positives.
   4. Flag high-risk exposures (breached credentials, PII leaks, infrastructure overlaps).
   5. Produce a structured JSON report.

   Raw findings:
   {json.dumps(findings[:500], indent=2)}
   """

   response = client.chat.completions.create(
       model="gpt-4o",
       messages=[
           {"role": "system", "content": "You are an expert OSINT analyst specializing in identity correlation and link analysis."},
           {"role": "user", "content": correlation_prompt}
       ],
       temperature=0.1,
       response_format={"type": "json_object"}
   )

   report = json.loads(response.choices[0].message.content)

   with open("/tmp/osint/correlation-report.json", "w") as f:
       json.dump(report, f, indent=2)

   print(json.dumps(report, indent=2))
   PYEOF
   python3 /tmp/osint/correlate.py
   ```

8. **Perform entity resolution — deduplicate and merge related identities:**

   ```bash
   cat > /tmp/osint/resolve.py << 'PYEOF'
   import json

   with open("/tmp/osint/correlation-report.json") as f:
       report = json.load(f)

   # Extract entities and build a link graph
   entities = report.get("entities", [])
   print(f"Identified {len(entities)} distinct entities")
   for entity in entities:
       name = entity.get("identifier", "unknown")
       confidence = entity.get("confidence", 0)
       links = entity.get("linked_accounts", [])
       risk = entity.get("risk_level", "unknown")
       print(f"  [{confidence:.0%}] {name} — {len(links)} linked accounts — risk: {risk}")
   PYEOF
   python3 /tmp/osint/resolve.py
   ```

### Phase 4 — Reporting and Visualization

9. **Generate a final intelligence profile in Markdown:**

   ```bash
   cat > /tmp/osint/report.py << 'PYEOF'
   import json
   from datetime import datetime

   with open("/tmp/osint/correlation-report.json") as f:
       report = json.load(f)

   md = f"# OSINT Correlation Report\n\n"
   md += f"**Generated:** {datetime.utcnow().isoformat()}Z\n\n"
   md += "## Entity Profiles\n\n"

   for entity in report.get("entities", []):
       eid = entity.get("identifier", "Unknown")
       conf = entity.get("confidence", 0)
       md += f"### {eid} (Confidence: {conf:.0%})\n\n"
       md += "| Source | Platform | Evidence |\n|--------|----------|----------|\n"
       for link in entity.get("linked_accounts", []):
           md += f"| {link.get('source','')} | {link.get('platform','')} | {link.get('evidence','')} |\n"
       md += f"\n**Risk Level:** {entity.get('risk_level', 'N/A')}\n\n"
       for flag in entity.get("flags", []):
           md += f"- ⚠️ {flag}\n"
       md += "\n"

   with open("/tmp/osint/intelligence-profile.md", "w") as f:
       f.write(md)

   print("Report written to /tmp/osint/intelligence-profile.md")
   PYEOF
   python3 /tmp/osint/report.py
   ```

10. **Optional — Import correlation graph into Maltego for visualization:**

    ```bash
    # Export entities as Maltego-compatible CSV for manual import
    cat > /tmp/osint/maltego_export.py << 'PYEOF'
    import json, csv

    with open("/tmp/osint/correlation-report.json") as f:
        report = json.load(f)

    with open("/tmp/osint/maltego-import.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Entity Type", "Value", "Linked To", "Link Label", "Confidence"])
        for entity in report.get("entities", []):
            for link in entity.get("linked_accounts", []):
                writer.writerow([
                    link.get("type", "Alias"),
                    link.get("value", ""),
                    entity.get("identifier", ""),
                    link.get("evidence", ""),
                    link.get("confidence", "")
                ])

    print("Maltego CSV exported to /tmp/osint/maltego-import.csv")
    PYEOF
    python3 /tmp/osint/maltego_export.py
    ```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Cross-Source Correlation | Matching identifiers (usernames, emails, IPs) across independent OSINT sources to establish entity linkage |
| Confidence Scoring | Assigning probabilistic confidence (0.0–1.0) to each linkage based on evidence strength and corroboration |
| Entity Resolution | Deduplicating and merging records that refer to the same real-world entity across fragmented datasets |
| False Positive Detection | Using AI reasoning to identify coincidental matches versus genuine identity links |
| Multi-Vector Intelligence | Combining findings from social media, DNS, breach data, and infrastructure into a single threat picture |
| Link Analysis | Graph-based examination of relationships between entities, accounts, and infrastructure |

## Tools & Systems

| Tool | Role in Workflow |
|------|-----------------|
| Sherlock | Username enumeration across 400+ social platforms |
| theHarvester | Email, subdomain, and host discovery from public sources |
| SpiderFoot | Automated OSINT collection across 200+ modules |
| Maltego | Graph-based visualization of entity relationships |
| LLM API (GPT-4, Claude, Ollama) | Cross-source reasoning, pattern detection, and confidence scoring |
| HaveIBeenPwned | Breach exposure and credential leak detection |

## Common Scenarios

- **Threat Actor Attribution:** Correlate a suspicious username found in a phishing campaign with social media profiles, domain registrations, and breach data to build an attribution profile.
- **Attack Surface Mapping:** Link discovered subdomains, emails, and employee social accounts to understand an organization's full external exposure.
- **Insider Threat Investigation:** Cross-reference an employee's known accounts with dark web marketplace activity and breach databases.
- **Brand Impersonation Detection:** Identify accounts across platforms mimicking a target brand by correlating registration patterns, naming conventions, and temporal signals.

## Output Format

The final output is a structured JSON correlation report and a Markdown intelligence profile containing:

```json
{
  "meta": {
    "target": "targetdomain.com",
    "sources_used": ["sherlock", "theHarvester", "spiderfoot", "hibp"],
    "total_findings": 247,
    "generated_at": "2025-01-15T14:30:00Z"
  },
  "entities": [
    {
      "identifier": "john.target",
      "confidence": 0.92,
      "linked_accounts": [
        {
          "source": "sherlock",
          "platform": "GitHub",
          "value": "john.target",
          "evidence": "Exact username match, bio references targetdomain.com",
          "confidence": 0.95
        }
      ],
      "risk_level": "high",
      "flags": [
        "Credentials exposed in 2 breaches (2022, 2023)",
        "Admin email for targetdomain.com found in public WHOIS"
      ]
    }
  ],
  "contradictions": [],
  "recommendations": []
}
```

## Verification

- Confirm that each linked account has been independently verified against at least two sources before assigning confidence > 0.8.
- Cross-check AI-generated correlations manually for a random sample (10–20%) to validate accuracy.
- Verify that no false positives from common usernames (e.g., "admin", "test") inflated entity profiles.
- Ensure breach data timestamps are current and from reputable aggregators.
- Validate that the final report does not include stale or retracted OSINT data.
