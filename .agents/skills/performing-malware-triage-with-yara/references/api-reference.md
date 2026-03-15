# API Reference: Malware Triage with YARA

## yara-python API

```python
import yara

# Compile from files
rules = yara.compile(filepaths={"ns1": "rules.yar"})

# Compile from string
rules = yara.compile(source='rule test { condition: true }')

# Scan file
matches = rules.match("/path/to/sample")

# Scan data
matches = rules.match(data=open("sample", "rb").read())
```

## Match Object Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `match.rule` | str | Name of the matching rule |
| `match.namespace` | str | Rule file namespace |
| `match.tags` | list | Tags from the rule definition |
| `match.meta` | dict | Meta fields (author, description, hash) |
| `match.strings` | list | Matched strings: (offset, identifier, data) |

## YARA CLI

| Command | Description |
|---------|-------------|
| `yara rules.yar sample.exe` | Scan file against rules |
| `yara -r rules.yar /dir/` | Recursive directory scan |
| `yara -s rules.yar sample.exe` | Show matching strings |
| `yarac rules.yar compiled.yarc` | Compile rules for faster loading |
| `yara -C rules.yar` | Check rule syntax |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `yara-python` | >=4.3 | YARA rule compilation and scanning |
| `hashlib` | stdlib | Sample hashing (SHA-256, MD5) |

## References

- YARA documentation: https://yara.readthedocs.io/
- yara-python: https://github.com/VirusTotal/yara-python
- YARA-Rules community: https://github.com/Yara-Rules/rules
- Signature-base: https://github.com/Neo23x0/signature-base
- yarGen rule generator: https://github.com/Neo23x0/yarGen
