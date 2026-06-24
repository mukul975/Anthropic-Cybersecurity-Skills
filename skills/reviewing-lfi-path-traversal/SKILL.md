---
name: reviewing-lfi-path-traversal
description: >-
  Detect Path Traversal and Local File Inclusion (LFI) vulnerabilities. Triggered when 
  an application reads, downloads, or previews files based on user-controlled input 
  without sufficient path normalization or whitelisting.
domain: cybersecurity
subdomain: web-application-security
tags: [path-traversal, lfi, arbitrary-file-read, penetration-testing]
mitre_attack: [T1190]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Analyzing Path Traversal & LFI Vulnerabilities

## When to Use

- When an endpoint reads, downloads, or previews files and accepts a parameter that dictates the target file.
- When you observe URL patterns like `?file=`, `?path=`, `?doc=`, `?template=`, or `/api/logs/{name}`.
- When an application proxies images, loads templates, or provides a static file server `/static/*`.
- **Note**: Do not filter solely by parameter names. Any endpoint whose semantic backend behavior is "open a file based on input" (even if the parameter is named `id` or `attachment`) is a candidate.

## Prerequisites

- An interception proxy (Burp Suite, ZAP).
- Knowledge of safe target files to verify traversal without disrupting the system:
  - Linux: `/etc/passwd`, `/etc/hostname`
  - Windows: `C:\Windows\win.ini`

## Workflow

1. Initialize and execute the testing sequence.

```bash
# Verification block
echo test
```




### Step 1: Baseline and Endpoint Enumeration
1. Identify all candidate endpoints. Do not limit yourself to static file servers; actively look for business logic endpoints (e.g., ticket attachments, avatar proxies).
2. Send a normal request to observe the baseline response (HTTP status, Content-Type, Body length).
3. Observe the pattern of the parameter: is it a relative path, an absolute path, or just a filename?

### Step 2: Path Traversal Probing
Systematically test traversal payloads to attempt to break out of the intended directory:
- **Basic Traversal**: `../../../etc/passwd`
- **Absolute Path Bypass**: `/etc/passwd` (if the server simply appends input to a base directory without validation).
- **URL Encoding Bypass**: `..%2f..%2f..%2fetc/passwd`
- **Double Encoding Bypass**: `..%252f..%252f..%252fetc/passwd`
- **Filter Evasion (Stripping `../`)**: `....//....//....//etc/passwd`
- **Windows Specific**: `..\..\..\Windows\win.ini` or mixed slashes `....\/....\/....\/etc/passwd`

### Step 3: Local File Inclusion (LFI) Feasibility (PHP Environments)
If the backend is executing the file (e.g., `include($_GET['view'])`) rather than just reading it, you have an LFI.
- Attempt to read source code using PHP wrappers: `php://filter/convert.base64-encode/resource=index`.
- If possible, attempt to escalate to Remote Code Execution (RCE) by including log files that contain poisoned payloads (Log Poisoning), though actual exploitation of RCE is out of scope unless explicitly authorized.

### Step 4: Verification
Confirm the vulnerability by examining the response. The response must contain the actual contents of the target file (e.g., the user list format of `/etc/passwd`). A simple difference in HTTP status code or response length is a strong indicator (Suspected), but is not definitive proof.

## Key Concepts

| Term | Definition |
|------|------------|
| **Path Traversal (Directory Traversal)** | An attack aiming to access files and directories that are stored outside the web root folder. |
| **Local File Inclusion (LFI)** | An attack where a web application includes a file, usually leading to source code disclosure or Remote Code Execution (RCE) if the included file contains executable code. |
| **Path Normalization** | The process of resolving relative path references (like `../`) into an absolute, canonical path to ensure the final destination resides within a safe boundary. |


## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Negative - Focusing only on Static Servers
**Context**: You test the `/static/` file server with `../../../etc/passwd` and it is blocked. You conclude the application is safe.
**Analysis**: Frameworks often secure their built-in static file servers (like Go's `http.FileServer` which automatically sanitizes paths). However, custom business logic endpoints like `GET /api/downloadAttachment?file=...` often manually concatenate paths without validation.
**Action**: Test both static asset endpoints and business logic file-handling endpoints independently.

### Scenario: False Positive - Blind Parameter Appending
**Context**: You inject `../../../../etc/passwd` and the server responds with a 200 OK, but the body is empty or contains generic text.
**Analysis**: The parameter might be sanitized, or the server might return a default error page disguised as a 200 OK.
**Action**: You must see the *actual contents* of the target file to confirm the vulnerability.

### Scenario: Insufficient Validation (`filepath.Clean`)
**Context**: A developer uses a path sanitization function like `filepath.Clean` in Go to strip `../`.
**Analysis**: `Clean` removes relative traversal strings, but it does *not* prevent absolute paths.
**Action**: If the developer appends the cleaned string without checking if it resides within the allowed directory, an absolute path payload like `/etc/passwd` will still succeed.

## Output Format

Document confirmed vulnerabilities with evidence of file retrieval:

```json
{
  "id": "lfi-001",
  "title": "Path Traversal in Document Download Endpoint",
  "severity": "high",
  "cwe": "CWE-22",
  "endpoint": "GET /api/v1/documents/download?file=...",
  "status": "confirmed",
  "evidence": {
    "payload": "GET /api/v1/documents/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
    "execution_proof": "The server returned HTTP 200 with the contents of the /etc/passwd file, starting with 'root:x:0:0:root:/root:/bin/bash'."
  },
  "description": "The application's document download endpoint takes a file parameter and blindly concatenates it with the base upload directory. By utilizing URL encoded traversal sequences, an attacker can escape the base directory and read sensitive system files."
}
```
