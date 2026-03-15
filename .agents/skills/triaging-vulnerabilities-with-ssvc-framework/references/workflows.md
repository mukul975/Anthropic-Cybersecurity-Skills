# Workflows - SSVC Vulnerability Triage

## Workflow 1: Initial SSVC Triage Pipeline

### Trigger
New vulnerability scan results imported from Nessus, Qualys, OpenVAS, or other scanner.

### Steps

1. **Ingest Scan Results**
   - Parse scanner output (CSV, XML, or JSON format)
   - Extract CVE identifiers, affected hosts, CVSS vectors, and descriptions
   - Deduplicate findings by CVE + host combination

2. **Enrich with External Intelligence**
   - Query CISA KEV catalog JSON feed for exploitation status
   - Query FIRST EPSS API for exploitation probability scores
   - Query NVD API v2 for CVSS v3.1/v4.0 vectors and CWE mappings
   - Cache API responses to avoid rate limiting (NVD: 5 requests/30s without key, 50/30s with key)

3. **Evaluate SSVC Decision Points**
   - **Exploitation**: Map KEV membership to "Active", EPSS > 0.5 to "PoC", otherwise "None"
   - **Technical Impact**: Parse CVSS vector; if Scope:Changed or CIA all High, mark "Total"
   - **Automatability**: Network vector + Low complexity + No user interaction = "Yes"
   - **Mission Prevalence**: Cross-reference affected assets with CMDB criticality tags
   - **Public Well-Being**: Map asset function to safety impact categories

4. **Apply Decision Tree**
   - Walk the CISA SSVC decision tree with evaluated decision points
   - Assign outcome: Track, Track*, Attend, or Act

5. **Generate Prioritized Report**
   - Sort vulnerabilities by SSVC outcome (Act > Attend > Track* > Track)
   - Within each category, secondary sort by EPSS score descending
   - Output JSON report and CSV summary for ticketing integration

## Workflow 2: Continuous SSVC Monitoring

### Trigger
Daily scheduled job (cron or CI/CD pipeline).

### Steps

1. **Refresh CISA KEV Catalog**
   ```bash
   curl -s -o /tmp/kev_catalog.json \
     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
   ```

2. **Check Previously Tracked CVEs Against Updated KEV**
   - Compare current open vulnerabilities against latest KEV additions
   - If a previously "Track" or "Track*" CVE appears in KEV, re-evaluate to "Attend" or "Act"

3. **Refresh EPSS Scores**
   ```bash
   curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-3400,CVE-2024-21887" | \
     python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['data'], indent=2))"
   ```

4. **Update SSVC Outcomes**
   - Re-run decision tree for all open vulnerabilities with refreshed data
   - Flag any outcome changes (e.g., Track -> Attend)

5. **Send Notifications**
   - Slack/Teams webhook for any new "Act" or "Attend" outcomes
   - Email digest for "Track*" changes
   - Update Jira/ServiceNow tickets with new SSVC classification

## Workflow 3: Asset-Context SSVC Enrichment

### Trigger
New asset onboarded or asset criticality classification updated.

### Steps

1. **Import Asset Inventory**
   - Pull from CMDB (ServiceNow, Snipe-IT, or similar)
   - Map each asset to mission prevalence category:
     - Minimal: development, test environments
     - Support: backup systems, monitoring infrastructure
     - Essential: production databases, authentication servers, customer-facing apps

2. **Map Public Well-Being Impact**
   - Healthcare systems, SCADA/ICS, transportation: Irreversible
   - Public web services, financial processing: Material
   - Internal tools, development systems: Minimal

3. **Re-Evaluate Open Vulnerabilities**
   - Apply updated asset context to all open vulnerability SSVC evaluations
   - Generate delta report showing outcome changes

## Workflow 4: SSVC Metrics and Reporting

### Trigger
Weekly/monthly reporting cycle.

### Metrics to Track

| Metric | Calculation | Target |
|--------|------------|--------|
| Mean Time to Remediate (Act) | Avg days from Act classification to closure | < 2 days |
| Mean Time to Remediate (Attend) | Avg days from Attend classification to closure | < 14 days |
| SLA Breach Rate | % of vulns not remediated within SLA | < 5% |
| Act Backlog | Count of open Act-classified vulnerabilities | 0 |
| Attend Backlog | Count of open Attend-classified vulnerabilities | < 10 |
| Coverage Rate | % of vulnerabilities processed through SSVC | > 95% |

### Report Generation
```bash
python3 scripts/process.py \
  --mode report \
  --input ssvc_results.json \
  --period weekly \
  --output ssvc_metrics_report.html
```
