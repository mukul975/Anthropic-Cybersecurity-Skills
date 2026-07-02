---
name: reviewing-insecure-file-uploads
description: >-
  Comprehensive detection for file upload vulnerabilities covering extension bypasses, 
  MIME type forgery, magic number mismatches, and parsing exploits (e.g., SVG XSS, 
  SVG/Office XXE, Zip Slip, and path traversal overwrites).
domain: cybersecurity
subdomain: web-application-security
tags: [file-upload, rce, lfi, xxe, penetration-testing]
mitre_attack: [T1190, T1059]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Reviewing Insecure File Uploads

## When to Use

- When an application accepts file uploads via `multipart/form-data`, JSON base64-encoded payloads, or embedded rich-text editor components.
- When an endpoint accepts a `filename` or `path` parameter that dictates where an uploaded file is stored.
- When evaluating avatars, document imports, backup restorations, or template uploads.
- When an application processes uploaded files asynchronously (e.g., extracting ZIPs, transcoding videos, or parsing OCR text).

## Prerequisites

- An interception proxy (Burp Suite, ZAP) to manipulate HTTP requests.
- A collection of benign sentinel payloads (e.g., a PHP file that only outputs a timestamp instead of executing arbitrary commands) to safely verify execution without causing damage.

## Workflow

### Step 1: Baseline and Constraints
1. Upload a completely benign file (e.g., a valid `.jpg`).
2. Record the application's response. Does it return the file path? Does the file process successfully?
3. Retrieve the file by navigating to the returned URL. Verify if the server delivers the file and note the `Content-Type`.

### Step 2: Bypassing Extension and Content-Type Filters
Identify the validation layer and attempt to bypass it:
- **MIME Type Bypass**: Send a malicious PHP file but change the `Content-Type` header in the multipart form data to `image/jpeg`.
- **Extension Bypasses**: 
  - Try alternative extensions: `.php5`, `.phtml`, `.phar`, `.jspx`, `.aspx`, `.shtml`.
  - Try double extensions: `shell.php.jpg` (exploits Apache `mod_mime` misconfigurations).
  - Try null byte or URL encoding injections: `shell.php%00.jpg`, `shell%2ephp`.
- **Magic Byte Forgery**: Prepend the file content with valid magic bytes (e.g., `GIF89a`) before the PHP payload to bypass file signature checks.

### Step 3: Server Configuration Overwrites
If you cannot upload executable scripts directly, try uploading configuration files that alter the server's parsing behavior for the current directory:
- **Apache**: Upload an `.htaccess` file containing `AddType application/x-httpd-php .jpg`.
- **IIS**: Upload a `web.config` to map `.jpg` to ASP.NET execution.
- **PHP-FPM / Nginx**: Upload a `.user.ini` containing `auto_prepend_file=shell.jpg`.

### Step 4: Exploiting File Parsers (Secondary Triggers)
If the application stores files safely but parses their content, test parser vulnerabilities:
- **SVG XSS**: Upload an `.svg` containing `<script>alert(1)</script>`. This triggers when another user views the SVG directly in the browser.
- **SVG/Office XXE**: Upload an SVG or a maliciously crafted `.docx`/`.xlsx` file containing an XML External Entity (XXE) payload pointing to your OOB listener or `/etc/passwd`.
- **Zip Slip**: Upload a ZIP archive containing files with directory traversal paths (`../../../../tmp/evil.sh`). If the server extracts the archive without validating paths, it will overwrite files outside the intended directory.

### Step 5: Path Traversal and Overwrites
If the application accepts a `filename` parameter (e.g., `{"filename": "avatar.png", "data": "..."}`), change the filename to `../../var/www/html/shell.php` to attempt arbitrary file write.

### Verification and Validation Phase
1. Establish target environment baseline and identify endpoint parameters.
2. Execute realistic detection payload to evaluate vulnerability exposure:

```bash
curl -i -s -X POST "https://target.example.com/api/v1/upload" \
     -F "file=@payload.php;filename=shell.php;type=application/x-httpd-php"
```

3. Analyze HTTP response status, reflected headers, and execution timing to confirm finding.

## Key Concepts

| Term | Definition |
|------|------------|
| **Polyglot File** | A file that is perfectly valid as two different file types (e.g., a valid JPEG image that is also a valid PHP script). |
| **MIME Type** | A string sent in the HTTP header indicating the nature of the file (e.g., `image/png`). It is easily manipulated by attackers. |
| **Magic Number / File Signature** | The first few bytes of a file that uniquely identify its true format, regardless of the extension or MIME type. |

## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: False Positive - Upload Success, No Execution
**Context**: You upload `shell.php`. The server responds `Upload Successful` and returns `/uploads/shell.php`.
**Analysis**: You navigate to `/uploads/shell.php` and the browser downloads the file or displays the PHP source code in plaintext.
**Action**: This is not Remote Code Execution (RCE). The server correctly stored the file but its web server configuration is secure (it does not execute PHP scripts in the upload directory).

### Scenario: False Negative - Ignored JSON Base64 Uploads
**Context**: An application endpoint receives `POST /api/profile` with `{"avatar_b64": "iVBORw0KGgo..."}`.
**Analysis**: Because it doesn't use `multipart/form-data`, automated scanners might miss it.
**Action**: Manually decode the base64 string, replace it with a malicious payload, re-encode to base64, and test for parsing vulnerabilities.

### Scenario: Cross-Identity Read
**Context**: A user uploads a confidential tax document to `/uploads/user-100/tax.pdf`.
**Analysis**: You switch to User 101's account and try to access `/uploads/user-100/tax.pdf`.
**Action**: If the document loads successfully without authentication checks, it is an Insecure Direct Object Reference (IDOR) via predictable file upload paths.

## Output Format

Document confirmed vulnerabilities with proof of execution or manipulation:

```json
{
  "id": "upl-001",
  "title": "Unrestricted File Upload leading to RCE",
  "severity": "critical",
  "cwe": "CWE-434",
  "parameter": "profile_image (multipart/form-data)",
  "status": "confirmed",
  "evidence": {
    "payload": "Filename: shell.phtml, Content-Type: image/jpeg",
    "execution_proof": "Navigating to /uploads/shell.phtml executed the script, returning the output 'sastx_sentinel_1719139000'."
  },
  "description": "The application only verifies the Content-Type header. By spoofing the Content-Type to image/jpeg, an attacker can upload a .phtml script which the Apache server executes, leading to Remote Code Execution."
}
```
