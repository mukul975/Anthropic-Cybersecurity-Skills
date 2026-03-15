---
name: implementing-web-application-logging-with-modsecurity
description: >
  Configure ModSecurity WAF with OWASP Core Rule Set (CRS) for web application logging,
  tune rules to reduce false positives, analyze audit logs for attack detection, and
  implement custom SecRules for application-specific threats. The analyst configures
  SecRuleEngine, SecAuditEngine, and CRS paranoia levels to balance security coverage
  with operational stability. Activates for requests involving WAF configuration,
  ModSecurity rule tuning, web application audit logging, or CRS deployment.
domain: cybersecurity
subdomain: web-application-security
tags: [modsecurity, waf, crs, owasp, web-security, audit-logging, rule-tuning]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Web Application Logging with ModSecurity

## Overview

ModSecurity is an open-source WAF engine that works with Apache, Nginx, and IIS. The OWASP
Core Rule Set (CRS) provides generic attack detection rules covering SQL injection, XSS,
RCE, LFI, and other OWASP Top 10 attacks. ModSecurity logs full request/response data in
audit logs for forensic analysis and generates alerts that feed into SIEM platforms.

## Prerequisites

- Web server (Apache 2.4+ or Nginx) with ModSecurity v3 module
- OWASP CRS v4.x installed
- Log aggregation infrastructure (ELK, Splunk, or Wazuh)

## Steps

1. Install ModSecurity and configure SecRuleEngine in DetectionOnly mode
2. Deploy OWASP CRS v4 and set paranoia level (PL1-PL4)
3. Configure SecAuditEngine for relevant-only logging
4. Tune false positives with SecRuleRemoveById and rule exclusions
5. Switch to blocking mode (SecRuleEngine On) after tuning period
6. Forward audit logs to SIEM for correlation and alerting

## Expected Output

```
ModSecurity: Warning. Pattern match "(?:union\s+select)" [file "/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]
```
