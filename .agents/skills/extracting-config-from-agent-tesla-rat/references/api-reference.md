# API Reference: Agent Tesla RAT Configuration Extraction

## Agent Tesla Overview
- **Type**: .NET RAT / Information Stealer
- **Exfiltration**: SMTP, FTP, Telegram, HTTP POST
- **Capabilities**: Keylogging, clipboard, screenshots, credential theft

## String Extraction

### Python Regex for ASCII Strings
```python
re.finditer(rb'[\x20-\x7e]{6,}', binary_data)
```

### Wide Strings (UTF-16LE)
```python
re.finditer(rb'(?:[\x20-\x7e]\x00){6,}', binary_data)
```

## Configuration Indicators

### SMTP Exfiltration
| Field | Pattern |
|-------|---------|
| Server | `smtp.gmail.com`, `smtp.yandex.com` |
| Port | 587, 465, 25 |
| Email | `[\w.+-]+@[\w-]+\.[\w.]+` |
| Password | Base64 or XOR encoded |

### FTP Exfiltration
| Field | Pattern |
|-------|---------|
| Server | `ftp.\w+\.\w+` |
| URI | `ftp://user:pass@host/path` |

### Telegram Bot
| Field | Pattern |
|-------|---------|
| Bot Token | `\d{8,12}:[A-Za-z0-9_-]{35}` |
| Chat ID | `\d{9,13}` |
| API URL | `api.telegram.org/bot{token}/sendDocument` |

## .NET Decompilation

### dnSpy
```bash
# Open sample in dnSpy
# Navigate to namespace: AgentTesla / WebMonitor / etc.
# Look for hardcoded credentials in static fields
```

### ILSpy / dotPeek
Alternative .NET decompilers for config extraction.

## YARA Rule

```yara
rule AgentTesla {
    meta:
        description = "Agent Tesla keylogger/RAT"
    strings:
        $smtp = "SmtpPort" ascii wide
        $hook = "KeyboardHook" ascii wide
        $clip = "GetClipboardData" ascii wide
        $ns1 = "AgentTesla" ascii
        $ns2 = "WebMonitor" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
```

## File Hashing

### Python hashlib
```python
import hashlib
sha256 = hashlib.sha256(open(path, 'rb').read()).hexdigest()
```

## VirusTotal API — Sample Lookup
```http
GET https://www.virustotal.com/api/v3/files/{sha256}
x-apikey: {API_KEY}
```

### Response Fields
| Field | Description |
|-------|-------------|
| `data.attributes.popular_threat_classification` | Malware family |
| `data.attributes.last_analysis_stats` | AV detection counts |
| `data.attributes.sandbox_verdicts` | Sandbox analysis results |

## Sandbox Analysis
- **ANY.RUN**: Interactive analysis
- **Hybrid Analysis**: Automated report
- **Joe Sandbox**: Deep behavioral analysis
