# API Reference: QR Code Phishing Detection

## pyzbar — QR/Barcode Decoding

### Installation
```bash
pip install pyzbar Pillow
# On Linux: apt-get install libzbar0
```

### Core Functions
```python
from pyzbar.pyzbar import decode
from PIL import Image

results = decode(Image.open("qr.png"))
for r in results:
    print(r.type)     # "QRCODE"
    print(r.data)     # b"https://..."
    print(r.rect)     # Rect(left=40, top=40, width=200, height=200)
```

### Decoded Object Attributes
| Attribute | Type | Description |
|-----------|------|-------------|
| `data` | bytes | Decoded content |
| `type` | str | Barcode type (QRCODE, EAN13, etc.) |
| `rect` | Rect | Bounding rectangle |
| `polygon` | list | Corner points |
| `quality` | int | Decode quality score |

## Python email Module — EML Parsing

### Parsing an EML file
```python
import email
from email import policy

with open("message.eml", "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

subject = msg["Subject"]
sender = msg["From"]
```

### Walking MIME Parts
```python
for part in msg.walk():
    ctype = part.get_content_type()
    if ctype.startswith("image/"):
        payload = part.get_payload(decode=True)
        filename = part.get_filename()
```

## URL Analysis Indicators

### Suspicious TLD List
`.xyz`, `.top`, `.club`, `.work`, `.buzz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`

### Phishing URL Patterns
| Pattern | Risk |
|---------|------|
| IP address in domain | High |
| Domain > 40 chars | Medium |
| HTTP (no TLS) | Medium |
| 3+ subdomains | Medium |
| URL shortener | High |
| Base64 in path | High |

## Microsoft Defender for Office 365 — Safe Links API

### Check URL reputation
```http
POST https://graph.microsoft.com/v1.0/security/tiIndicators
Content-Type: application/json
Authorization: Bearer {token}

{
  "targetProduct": "Azure Sentinel",
  "threatType": "Phishing",
  "url": "https://suspicious-domain.xyz/login"
}
```

## VirusTotal URL Scan API

### Submit URL
```http
POST https://www.virustotal.com/api/v3/urls
x-apikey: {API_KEY}
Content-Type: application/x-www-form-urlencoded

url=https://suspicious-domain.xyz
```

### Response Fields
| Field | Description |
|-------|-------------|
| `data.attributes.last_analysis_stats.malicious` | Engines flagging as malicious |
| `data.attributes.last_analysis_stats.harmless` | Engines flagging as clean |
| `data.attributes.categories` | URL categorization |
