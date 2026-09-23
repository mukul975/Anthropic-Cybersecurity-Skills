---
name: performing-web-application-security-assessment-with-owasp-zap
description: >-
  Runs an end-to-end OWASP ZAP assessment of an authorized web application:
  define the scope in a context, spider the attack surface, run passive
  scanning, run a bounded active scan through the Automation Framework
  (zap.sh -cmd -autorun), deduplicate alerts with evidence, rate severity,
  and produce a remediation report in Markdown, JSON or HTML. Use when you
  must security-test a web application you are contracted to assess, confirm
  each ZAP finding by replaying it with curl, or turn ZAP alerts into a
  client-ready vulnerability report. Keywords: OWASP ZAP, zap.sh,
  zap-baseline.py, zap-full-scan.py, zap-api-scan.py, autorun, spider, active
  scan, passive scan, alert, pluginid, riskcode, evidence, remediation. Do
  not use for wiring ZAP into a CI/CD release gate - use
  integrating-dast-with-owasp-zap-in-pipeline; quick web-server config
  checks with Nikto - use performing-web-application-scanning-with-nikto;
  rating findings already collected from any scanner - use
  performing-web-application-vulnerability-triage.
domain: cybersecurity
subdomain: web-application-security
tags:
- owasp-zap
- security-assessment
- zap-automation-framework
- active-scanning
- passive-scanning
- vulnerability-reporting
version: "1.0"
author: rubenmarcus
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.IM-01
mitre_attack:
- T1190
---

# Performing Web Application Security Assessment with OWASP ZAP

## Overview

OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner.
This skill covers the full assessment loop on a live, authorized target:
scoping, spidering, passive scanning, a bounded active scan, evidence-based
triage of every alert, and a structured report. All commands run ZAP from the
official Docker image, so the only host dependency is Docker.

**Authorization gate.** Run nothing against a host without written permission
from its owner. Scope, dates, and intensity (passive-only vs active) belong in
that authorization. If you cannot name the document that authorizes the scan,
stop.

## When to Use

- Assessing a web application the client or employer owns and has authorized in writing
- Producing a vulnerability report with evidence, severity and remediation for each finding
- Re-testing after fixes: re-run the same plan and diff the alert sets
- One-shot passive check of a deployed site before a deeper, agreed active scan

## Prerequisites

- Docker, and curl
- Written authorization covering every in-scope URL
- The target URL plus any test credentials (for an authenticated scan)
- Basic HTTP literacy: methods, parameters, cookies, status codes

## Workflow

### Step 0: Record scope and set up a work directory

```bash
mkdir vulnapp-assessment && cd vulnapp-assessment
# Record what is authorized, before any traffic is sent:
cat > scope.txt <<'EOF'
target: http://target.example.com
authorized-by: Jane Doe, CTO, 2026-01-15 (email in thread)
window: 2026-01-16 to 2026-01-17, 09:00-17:00 UTC
mode: passive + active (Default Policy), no DoS rules
exclusions: /admin, anything matching .*logout.*
EOF
```

### Step 1: Confirm the toolchain

```bash
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap.sh -version
```

Output starts with the JVM banner and prints the ZAP version; record it in
the report (the runs in this skill used ZAP 2.17.0, which every JSON report
also carries in its `@version` field).

### Step 2: Passive-only baseline scan

The packaged `zap-baseline.py` spiders the target and reports passive-scan
alerts without sending any attack payloads:

```bash
docker run --rm -v "$(pwd)":/zap/wrk:rw -i \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://target.example.com/ -J baseline.json -I
```

- `-J baseline.json` writes a JSON report to the mounted directory
- `-I` makes the exit code 0 unless the tool itself errors, so CI does not
  fail on warnings
- The summary line counts alerts: `FAIL-NEW: 0 ... WARN-NEW: 9 ... PASS: 58`

**Gotcha, verified the hard way:** `zap-baseline.py` writes its own generated
plan to `/zap/wrk/zap.yaml`, silently overwriting a file of that name in your
work directory. Keep your Automation Framework plan in a differently named
file, e.g. `assessment.yaml`.

### Step 3: Write the assessment plan

Create `assessment.yaml` (Automation Framework format). This verified plan
spiders, waits for passive scanning to drain, runs a time-bounded active scan
with the shipped `Default Policy`, and writes three report formats:

```yaml
env:
  contexts:
    - name: vulnapp
      urls:
        - http://host.docker.internal:8000
  parameters:
    failOnError: true

jobs:
  - type: spider
    name: assessment-spider
    parameters:
      context: vulnapp
      maxDuration: 2

  - type: passiveScan-wait
    parameters:
      maxDuration: 60

  - type: activeScan
    name: authorized-active-scan
    parameters:
      context: vulnapp
      policy: Default Policy
      maxRuleDurationInMins: 2
      maxScanDurationInMins: 10

  - type: report
    parameters:
      template: traditional-html
      reportDir: /zap/wrk
      reportFile: zap-report.html
      reportTitle: OWASP ZAP assessment report - VulnApp

  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk
      reportFile: zap-report.json
      reportTitle: OWASP ZAP assessment report - VulnApp

  - type: report
    parameters:
      template: traditional-md
      reportDir: /zap/wrk
      reportFile: zap-report.md
      reportTitle: OWASP ZAP assessment report - VulnApp
```

Notes, all verified against `ghcr.io/zaproxy/zaproxy:stable`:

- URLs in the context define in-scope targets; the scanner stays inside them
- `policy` takes a policy **file name**, not a threshold. Shipped policies:
  `Default Policy`, `API-Minimal`, and the `St-<Strength>-Th-<Threshold>` grid
  such as `St-Med-Th-Low` (list them with `ls` inside the image:
  `/zap/policies/`)
- `maxRuleDurationInMins` and `maxScanDurationInMins` bound the blast radius;
  `maxRuleDuration`/`maxScanDuration` are silently rejected as unrecognised
- When the target runs on your host, `host.docker.internal` reaches it from
  the container (macOS/Windows Docker Desktop; on Linux add
  `--add-host=host.docker.internal:host-gateway`)

### Step 4: Run the plan

```bash
docker run --rm -v "$(pwd)":/zap/wrk:rw \
  ghcr.io/zaproxy/zaproxy:stable zap.sh -cmd -autorun /zap/wrk/assessment.yaml
```

A successful run ends with `Automation plan succeeded!` and exit code 0.
Each job logs its accepted parameters; any `Unrecognised parameter` line means
that setting was ignored: fix it before trusting the scan.

### Step 5: Deduplicate findings with evidence

Raw ZAP reports repeat one alert per URL/parameter. The helper script merges
instances of the same rule on the same parameter, sorts by risk, and prints
the attack string and evidence needed for verification:

```bash
python3 scripts/zap_alerts_report.py --report zap-report.json --output findings.md
```

Output (abridged, from a verified run against a deliberately vulnerable
local app):

```markdown
| # | Risk | Confidence | Finding | Plugin | CWE | Param | Instances |
|---|------|------------|---------|--------|-----|-------|-----------|
| 1 | High | High | Cross Site Scripting (DOM Based) | 40026 | 79 | - | 1 |
| 2 | High | High | Cross Site Scripting (DOM Based) | 40026 | 79 | q | 1 |
| 3 | High | Medium | Cross Site Scripting (Reflected) | 40012 | 79 | q | 1 |
| 4 | Medium | High | Content Security Policy (CSP) Header Not Set | 10038 | 693 | - | 3 |
| 7 | Medium | Medium | Missing Anti-clickjacking Header | 10020 | 1021 | x-frame-options | 3 |

## 3. Cross Site Scripting (Reflected) (High)

- Plugin ID: 40012 (alertRef 40012)
- Confidence: Medium

**Evidence (verify each before reporting):**

- `GET` `http://host.docker.internal:8000/search`
  - Param: `q`
  - Attack: `</h1><scrIpt>alert(1);</scRipt><h1>`
```

### Step 6: Verify every finding before it enters the report

A scanner alert is a lead, never a finding. For each row in `findings.md`,
replay the attack outside the scanner and capture the response:

```bash
# Reflected XSS lead from the table above: does the input come back unencoded?
curl -s "http://target.example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
  | grep -F "<script>alert(1)</script>"
# Missing-header lead: the response headers are the evidence:
curl -sI http://target.example.com/ | grep -iE "content-security-policy|x-frame-options"
```

If the replay does not reproduce the effect the alert claims, mark the finding
**false positive**, keep the alert row in an appendix, and say why. Report only
reproduced findings with their curl one-liner as evidence.

Scanners also miss real bugs. On the verified test app above, the `/item?id=`
parameter was injectable (`1 OR 1=1` returned every row) yet the
`Default Policy` active scan flagged only the two XSS rules. Treat the active
scan as one input to the assessment, and manually exercise every parameter the
spider found:

```bash
curl -s "http://target.example.com/item?id=1+OR+1%3D1" | grep -c widget
```

### Step 7: Rate, remediate, retest

For each verified finding, fill one entry in the report template
(`assets/report-template.md`): severity, affected endpoint, evidence, impact,
remediation, and the verification step you will re-run after the fix. Prefer
the remediation text ZAP attaches to each alert (`solution` field in the JSON
report) adapted to the codebase; cite the CWE. After fixes ship, re-run
Step 4 with the same `assessment.yaml` and show the alert gone.

## Key Concepts

| Concept | Meaning |
|---------|---------|
| Context | The in-scope set of URLs; scans cannot leave it |
| Spider | Crawls links and forms to map the attack surface |
| Passive scan | Inspects traffic only; sends no attack payloads |
| Active scan | Sends attack payloads to in-scope parameters |
| Alert | One scanner detection; `pluginid` identifies the rule |
| Risk code | 0 Informational, 1 Low, 2 Medium, 3 High (`riskcode`) |
| Confidence | Scanner's certainty; Low-confidence alerts need the most verification |
| Evidence | Response snippet proving the finding; the basis for the report |
| Scan policy | Per-rule threshold/strength bundle, e.g. `Default Policy`, `St-Med-Th-Low` |
| Automation Framework | YAML plan engine driving ZAP (`-autorun`) |

## Tools & Systems

- OWASP ZAP: official Docker image `ghcr.io/zaproxy/zaproxy:stable`
- Automation Framework: `assessment.yaml` plan (spider, passiveScan-wait, activeScan, report jobs)
- Packaged scanners: `zap-baseline.py` (passive), `zap-full-scan.py` (spider+active), `zap-api-scan.py` (OpenAPI/SOAP specs)
- `scripts/zap_alerts_report.py`: alert deduplication and evidence extraction
- curl: evidence replay
- OWASP Top 10 2021, CWE: finding categorisation

## Common Scenarios

### Scenario: passive-only first pass on production

Authorization covers passive only. Run Step 2 with `-J baseline.json`, verify
the header findings with `curl -sI`, and report those. Propose an active-scan
window as follow-up work.

### Scenario: authenticated scan

Define the credentials in the context so the spider and scanner see logged-in
pages. Verified shape for a form login (Automation Framework):

```yaml
contexts:
  - name: vulnapp
    urls: ["http://host.docker.internal:8000"]
    authentication:
      method: form
      parameters:
        loginPageUrl: http://target.example.com/login
        loginRequestUrl: http://target.example.com/login
        loginRequestData: "u={%username%}&p={%password%}"
      verification:
        method: response
        loggedInRegex: "Welcome"
        loggedOutRegex: "Bad credentials"
    sessionManagement:
      method: cookie
      parameters: {}
    users:
      - name: tester
        credentials:
          username: admin
          password: "use a dedicated test account"
```

Then pass `user: tester` to the spider and activeScan jobs (note: `user`,
not `userName`, which is silently rejected). The packaged scanners take the
same context as a file plus `-U tester`. Verify login worked: the report must
contain URLs only reachable when authenticated, or responses matching
`loggedInRegex`. Never scan with a real user's credentials.

### Scenario: API target

For a machine-readable API, `zap-api-scan.py` imports the spec and scans its
endpoints:

```bash
docker run --rm -v "$(pwd)":/zap/wrk:rw -i \
  ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t https://target.example.com/openapi.json -f openapi \
  -J api-scan.json -I
```

### Scenario: retest after remediation

Keep `assessment.yaml` under version control with the report. Re-run Step 4,
generate `findings.md` again, and diff the two tables: fixed findings
disappear; anything new is highlighted. The report's Retest section links each
closed finding to the exact rerun output.

## Output Format

Deliver (template in `assets/report-template.md`):

1. **Executive summary**: scope, dates, scan type, counts by severity, top risks in prose
2. **Findings table**: deduplicated, one row per verified finding
3. **Finding detail**: per finding: severity, endpoint, evidence (curl + response snippet), impact, remediation, retest command
4. **Retest log**: rerun outputs proving fixed findings stayed fixed
5. **Appendix**: full ZAP alert list including dismissed false positives, with dismissal reasons
