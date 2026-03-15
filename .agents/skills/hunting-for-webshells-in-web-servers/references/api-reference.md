# API Reference: Hunting for Webshells in Web Servers

## Shannon Entropy Calculation

```python
import math

def shannon_entropy(data: bytes) -> float:
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

# Thresholds: > 5.5 suspicious, > 6.5 likely obfuscated
```

## Webshell Detection Patterns

| Pattern | Language | Risk |
|---------|----------|------|
| `eval()` | PHP | HIGH |
| `base64_decode()` | PHP | HIGH |
| `system()` / `passthru()` | PHP | CRITICAL |
| `shell_exec()` / `exec()` | PHP | CRITICAL |
| `$_GET/$_POST` + `eval` | PHP | CRITICAL |
| `Runtime.getRuntime().exec` | JSP | CRITICAL |
| `Server.CreateObject` | ASP | HIGH |

## YARA Rule for Webshells

```yara
rule webshell_php_generic {
    meta:
        description = "Generic PHP webshell"
    strings:
        $eval = "eval(" ascii nocase
        $b64 = "base64_decode(" ascii nocase
        $system = "system(" ascii nocase
        $input = /\$_(GET|POST|REQUEST)\s*\[/ ascii
    condition:
        $input and ($eval or $b64 or $system)
}
```

## File System Scanning

```python
from pathlib import Path
SCRIPT_EXTS = {".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi"}
for f in Path("/var/www/html").rglob("*"):
    if f.suffix.lower() in SCRIPT_EXTS:
        entropy = shannon_entropy(f.read_bytes())
```

## NeoPI (Webshell Detection Tool)

```bash
python neopi.py /var/www/html -a  # Run all tests
# Tests: entropy, longest word, index of coincidence, signature
```

### References

- MITRE T1505.003: https://attack.mitre.org/techniques/T1505/003/
- NeoPI: https://github.com/Neohapsis/NeoPI
- YARA: https://yara.readthedocs.io/
