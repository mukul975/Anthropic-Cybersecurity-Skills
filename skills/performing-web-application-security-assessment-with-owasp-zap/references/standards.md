# Standards and references

Real, current references used when categorising and remediating ZAP findings.

## OWASP

- OWASP Top 10:2021 - https://owasp.org/Top10/ (map: XSS to A03 Injection,
  broken access control to A01, security misconfiguration headers to A05)
- OWASP Web Security Testing Guide (WSTG) v4.2 -
  https://owasp.org/www-project-web-security-testing-guide/
  (ZAP active scanning automates parts of WSTG-INV, WSTG-INPV)

## CWE

ZAP alerts carry a `cweid`. Resolve and cite at
https://cwe.mitre.org/data/index.html - common ones in ZAP output:
CWE-79 (XSS), CWE-89 (SQL injection), CWE-352 (CSRF), CWE-693 (protection
mechanism failure, used for missing headers), CWE-1004 (sensitive cookie
without HttpOnly).

## OWASP ZAP

- Documentation - https://www.zaproxy.org/docs/
- Automation Framework - https://www.zaproxy.org/docs/desktop/addons/automation-framework/
  (job and parameter reference for `assessment.yaml`)
- Scan Policies - https://www.zaproxy.org/docs/desktop/addons/scan-policies/
- Alerts and scan rules - https://www.zaproxy.org/docs/alerts/
  (every `pluginid` cited in a report resolves to a page here)
- Docker images - https://www.zaproxy.org/docs/docker/

## Authorization and scope

- Rules of engagement: get scope, window, intensity and escalation contacts in
  writing before the first request. See
  https://owasp.org/www-project-web-security-testing-guide/latest/2-Introduction/README
  (section on engagement requirements).
