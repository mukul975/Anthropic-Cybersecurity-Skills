# API Reference: YARA Rule Development for Detection

## yara-python API

| Method | Description |
|--------|-------------|
| `yara.compile(filepath=path)` | Compile rule from file |
| `yara.compile(source=string)` | Compile rule from string |
| `yara.compile(filepaths={ns: path})` | Compile with namespaces |
| `rules.match(filepath=path)` | Scan file against compiled rules |
| `rules.match(data=bytes)` | Scan bytes in memory |
| `rules.match(filepath, timeout=30)` | Scan with timeout |

## Match Object Attributes

| Attribute | Description |
|-----------|-------------|
| `match.rule` | Name of matching rule |
| `match.namespace` | Rule namespace |
| `match.tags` | Rule tags list |
| `match.meta` | Rule metadata dict |
| `match.strings` | List of (offset, identifier, data) |

## YARA Rule Structure

```
rule RuleName : tag1 tag2 {
    meta:
        description = "..."
        author = "..."
        date = "2025-01-01"
        hash = "sha256_of_sample"
    strings:
        $s1 = "string" ascii
        $s2 = "wide_string" wide
        $h1 = { 4D 5A 90 00 }
        $r1 = /regex[0-9]+/
    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
```

## Condition Operators

| Operator | Description |
|----------|-------------|
| `X of ($s*)` | X or more strings match |
| `all of ($s*)` | All strings match |
| `any of ($s*)` | At least one matches |
| `uint16(0) == 0x5A4D` | PE file magic bytes |
| `filesize < 10MB` | File size constraint |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `yara-python` | >=4.3 | Compile and scan YARA rules |
| `hashlib` | stdlib | SHA256 of samples |
| `re` | stdlib | String extraction |

## References

- YARA Documentation: https://yara.readthedocs.io/en/stable/
- yara-python: https://github.com/VirusTotal/yara-python
- YARA Rules Repository: https://github.com/Yara-Rules/rules
- VirusTotal Hunting: https://www.virustotal.com/gui/hunting-overview
