---
name: hunting-for-webshells-in-web-servers
description: >-
  Detect webshells planted on web servers by scanning for high-entropy files,
  suspicious PHP/JSP/ASP patterns (eval, base64_decode, system, passthru),
  recently modified files in web roots, and anomalous file sizes. Uses Shannon
  entropy calculation to flag obfuscated payloads and regex pattern matching
  against known webshell signatures.
domain: cybersecurity
subdomain: security-operations
tags: [hunting, for, webshells, web]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install yara-python`
2. Identify web server document roots to scan (e.g., `/var/www/html`, `/opt/lampp/htdocs`).
3. Run the agent to scan for webshells:
   - Shannon entropy analysis flags files with entropy > 5.5
   - Pattern matching detects eval(), base64_decode(), system(), passthru(), shell_exec()
   - File modification time analysis finds recently changed files
   - Extension filtering targets .php, .jsp, .asp, .aspx, .cgi, .py files

```bash
python scripts/agent.py --webroot /var/www/html --output webshell_report.json
```

## Examples

### High-Entropy PHP Webshell Detection
```
File: /var/www/html/uploads/img_thumb.php
Entropy: 6.12 (threshold: 5.5)
Patterns matched: eval(), base64_decode(), str_rot13()
Last modified: 2025-12-01 03:42:00 (outside business hours)
Verdict: SUSPICIOUS - likely obfuscated webshell
```
