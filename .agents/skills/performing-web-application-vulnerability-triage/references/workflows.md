# Workflows - Web Application Vulnerability Triage

## Workflow 1: DAST Finding Triage
1. Import DAST scan results (ZAP XML/JSON, Burp XML)
2. Auto-classify findings by OWASP Top 10 category via CWE mapping
3. Filter out known false positive patterns (missing headers on non-sensitive pages, etc.)
4. Flag confirmed exploitation findings as true positives
5. Queue remaining findings for manual validation
6. Security analyst validates with manual testing in Burp/ZAP
7. Assign OWASP risk rating to validated findings
8. Push validated findings to DefectDojo/Jira

## Workflow 2: SAST Finding Triage
1. Import SAST scan results (Semgrep JSON, SonarQube)
2. Filter out findings in test files, example code, and dead code
3. Cross-reference against data flow analysis for injection findings
4. Review code context to validate exploitability
5. Assign severity based on data sensitivity and exposure
6. Create development tickets for validated findings

## Workflow 3: Combined Triage and Deduplication
1. Import both DAST and SAST findings for same application
2. Correlate SAST code findings with DAST runtime findings
3. Findings confirmed by both DAST and SAST get elevated priority
4. Deduplicate findings pointing to same root cause
5. Generate unified triage report with remediation priority
