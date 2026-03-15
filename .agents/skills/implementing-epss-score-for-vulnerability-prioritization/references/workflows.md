# Workflows - EPSS Vulnerability Prioritization

## Workflow 1: Daily EPSS Enrichment Pipeline

### Steps
1. Download full EPSS dataset from https://epss.cyentia.com/epss_scores-current.csv.gz
2. Load into local database for fast lookups
3. Query open vulnerabilities from vulnerability management platform
4. Enrich each CVE with current EPSS score and percentile
5. Apply priority matrix combining EPSS and CVSS scores
6. Update priority fields in DefectDojo/Jira/tracking system
7. Alert on any CVEs that crossed EPSS threshold (e.g., jumped above 0.4)

## Workflow 2: EPSS Spike Detection

### Steps
1. Compare today's EPSS scores against yesterday's scores for all open CVEs
2. Identify CVEs with EPSS increase > 0.2 in past 24 hours
3. Cross-reference spike CVEs with asset inventory
4. Send high-priority alert for spiking CVEs affecting production assets
5. Automatically escalate to P1 if EPSS crosses 0.7 threshold

## Workflow 3: Prioritized Remediation Report

### Steps
1. Pull all open vulnerabilities from scanner
2. Enrich with EPSS scores and CISA KEV membership
3. Apply combined EPSS + CVSS + KEV priority matrix
4. Group by priority tier (P0-P4)
5. Within each tier, sort by EPSS score descending
6. Generate report showing estimated risk reduction per remediation action
7. Distribute to asset owners with assigned remediation timelines
