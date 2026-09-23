# Web application security assessment report

Fill one copy per engagement. Every finding must carry the curl command that
reproduces it and the response snippet that proves it; a finding without
reproducible evidence goes to the appendix as an unverified lead.

The bracketed example values come from a verified run against a deliberately
vulnerable local test application (reflected XSS on `/search?q=`); replace
them with your own observed output.

## 1. Executive summary

- **Client / system owner:** [Acme Corp]
- **Target:** [http://target.example.com (staging, build 2026-01-14)]
- **Authorization:** [Jane Doe, CTO, email 2026-01-15; window 2026-01-16/17 09:00-17:00 UTC]
- **Scan type:** spider + passive scan + active scan (`Default Policy`), ZAP [2.17.0]
- **Result:** [2 High, 4 Medium, 2 Low findings, all reproduced with curl; 1 scanner
  alert dismissed as false positive]
- **Top risks in prose:** [Unvalidated reflection of the `q` parameter allows
  stored-session theft; combined with the missing CSP header there is no
  mitigating browser control.]

## 2. Findings table

| # | Severity | Finding | Endpoint | CWE | Status |
|---|----------|---------|----------|-----|--------|
| 1 | High | Reflected XSS in search parameter | `/search?q=` | CWE-79 | Verified |
| 2 | Medium | CSP header not set | all pages | CWE-693 | Verified |
| 3 | Low | Server version disclosure | all responses | CWE-497 | Verified |

## 3. Finding detail

### Finding 1: Reflected XSS in search parameter

- **Severity:** High (ZAP riskcode 3, confidence Medium; manual reproduction: yes)
- **Endpoint:** `GET /search` with parameter `q`
- **Evidence:**

  ```bash
  curl -s "http://target.example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" |
    grep -F "<script>alert(1)</script>"
  # <h1>Results for: <script>alert(1)</script></h1>
  ```

- **Impact:** An attacker-supplied link executes script in the victim's browser
  session on this origin: cookie theft (session cookie lacks HttpOnly), key
  logging, forged requests.
- **Remediation:** HTML-encode `q` on output (context-aware encoding for
  element content), keep the CSP header fix from Finding 2 as defense in depth.
- **Retest command:** the curl above must return no unencoded `<script>` after
  the fix.

### Finding 2: [next finding, same fields]

## 4. Retest log

| Finding | Retest date | Command | Result |
|---------|-------------|---------|--------|
| 1 | 2026-01-22 | curl grep (above) | no reflection; closed |

## 5. Appendix: dismissed alerts

| Alert | Plugin ID | Dismissal reason |
|-------|-----------|------------------|
| [Authentication Request Identified] | 10111 | informational detection, not a vulnerability |
