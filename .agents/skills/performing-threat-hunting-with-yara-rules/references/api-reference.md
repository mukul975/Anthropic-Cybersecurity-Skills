# API Reference: Threat Hunting with YARA Rules

## yara-python Library

### Installation
```bash
pip install yara-python
```

### Compile and Scan
```python
import yara

# Compile from source string
rules = yara.compile(source='rule test { strings: $a = "malware" condition: $a }')

# Compile from file
rules = yara.compile(filepath='/path/to/rules.yar')

# Compile from directory (multiple files)
rules = yara.compile(filepaths={'ns1': '/rules/rule1.yar', 'ns2': '/rules/rule2.yar'})

# Scan file
matches = rules.match('/path/to/suspect.exe')
for m in matches:
    print(m.rule, m.meta, m.strings, m.tags)

# Scan data (bytes)
matches = rules.match(data=open('/path/to/file', 'rb').read())

# Scan with timeout (seconds)
matches = rules.match('/path/to/file', timeout=60)
```

## YARA CLI
```bash
# Scan file with single rule
yara rule.yar suspect.exe

# Scan directory recursively
yara -r rules.yar /path/to/directory/

# Show matching strings
yara -s rule.yar suspect.exe

# Show metadata
yara -e rule.yar suspect.exe

# Compile rules to binary
yarac rules.yar compiled.yarc
yara compiled.yarc suspect.exe

# Scan with tag filter
yara -t malware rules.yar /path/
```

## YARA Rule Structure
```yara
rule Example_Rule {
    meta:
        author = "analyst"
        description = "Detects example pattern"
        severity = "high"
        reference = "https://example.com"
    strings:
        $text = "suspicious_string" ascii nocase
        $hex = { 4D 5A 90 00 }
        $regex = /eval\(base64_decode/
    condition:
        uint16(0) == 0x5A4D and 2 of ($text, $hex, $regex)
}
```

## Match Object Fields
| Field | Description |
|-------|------------|
| rule | Rule name that matched |
| meta | Dict of meta key-value pairs |
| strings | List of (offset, identifier, data) tuples |
| tags | List of rule tags |
| namespace | Rule namespace |

## Community Rule Sources
| Source | URL |
|--------|-----|
| YARA-Rules | https://github.com/Yara-Rules/rules |
| Elastic YARA | https://github.com/elastic/protections-artifacts |
| Malpedia | https://malpedia.caad.fkie.fraunhofer.de |
| ThreatHunting Keywords | https://github.com/mthcht/ThreatHunting-Keywords-yara-rules |
