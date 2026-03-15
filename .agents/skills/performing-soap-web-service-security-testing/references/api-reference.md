# API Reference: SOAP Web Service Security Testing

## WSDL Namespaces

| Prefix | URI | Purpose |
|--------|-----|---------|
| `wsdl` | `http://schemas.xmlsoap.org/wsdl/` | WSDL 1.1 definitions |
| `soap` | `http://schemas.xmlsoap.org/wsdl/soap/` | SOAP 1.1 binding |
| `soap12` | `http://schemas.xmlsoap.org/wsdl/soap12/` | SOAP 1.2 binding |
| `xsd` | `http://www.w3.org/2001/XMLSchema` | XML Schema types |
| `wsse` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd` | WS-Security |

## SOAP Request Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Content-Type` | `text/xml; charset=utf-8` | SOAP 1.1 content type |
| `Content-Type` | `application/soap+xml; charset=utf-8` | SOAP 1.2 content type |
| `SOAPAction` | `"http://example.com/Operation"` | Target operation URI |

## Common Test Payloads

| Test | Category | Severity |
|------|----------|----------|
| XXE file read (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) | XML Injection | Critical |
| Billion Laughs (`<!ENTITY` expansion) | DoS | High |
| SQL injection in parameters | Injection | Critical |
| SOAPAction header mismatch | Authorization Bypass | High |
| Missing WS-Security token | Authentication Bypass | Critical |
| XPath injection (`' or '1'='1`) | Injection | High |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Send raw SOAP HTTP requests |
| `lxml` | >=4.9 | Parse WSDL/XML with namespace support |
| `zeep` | >=4.2 | Full SOAP client with WSDL parsing |
| `suds-community` | >=1.1 | Alternative SOAP client |

## lxml Key Methods

| Method | Description |
|--------|-------------|
| `etree.fromstring(xml_bytes)` | Parse XML from bytes |
| `root.find(xpath, namespaces)` | Find single element |
| `root.findall(xpath, namespaces)` | Find all matching elements |
| `element.get(attr)` | Get attribute value |

## References

- OWASP SOAP Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- zeep Documentation: https://docs.python-zeep.org/en/master/
- WS-Security Specification: https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf
