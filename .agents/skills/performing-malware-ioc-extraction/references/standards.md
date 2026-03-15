# Standards and Frameworks Reference

## IOC Types and Classification

### File-Based IOCs
| Type | Description | Example |
|------|-------------|---------|
| MD5 | 128-bit hash | d41d8cd98f00b204e9800998ecf8427e |
| SHA-1 | 160-bit hash | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA-256 | 256-bit hash | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| Imphash | Import hash | PE import table hash for family grouping |
| SSDeep | Fuzzy hash | Context-triggered piecewise hash for similarity |
| TLSH | Trend Micro LSH | Locality-sensitive hash for near-duplicate detection |

### Network IOCs
| Type | Description | Example |
|------|-------------|---------|
| IPv4 Address | C2 server IP | 192.0.2.1 |
| Domain | C2 domain | malware-c2.example.com |
| URL | Full URL path | https://evil.com/payload.exe |
| JA3/JA3S | TLS fingerprint | Client/server TLS handshake hash |
| JARM | TLS server fingerprint | Active TLS server scanning fingerprint |
| User-Agent | HTTP User-Agent | Custom UA strings in beacons |

### Host-Based IOCs
| Type | Description | Example |
|------|-------------|---------|
| Mutex | Named mutex | Global\{GUID} |
| Registry Key | Registry modification | HKLM\SOFTWARE\...\Run |
| Scheduled Task | Persistence task | schtasks /create ... |
| Service Name | Malicious service | Malicious service installation |
| Named Pipe | IPC mechanism | \\.\pipe\name |
| PDB Path | Debug path | C:\Users\dev\project.pdb |

## STIX 2.1 Indicator Patterns

### Pattern Syntax
```
[file:hashes.'SHA-256' = 'abc123...']
[ipv4-addr:value = '1.2.3.4']
[domain-name:value = 'evil.com']
[url:value = 'https://evil.com/payload']
[file:name = 'malware.exe']
[email-addr:value = 'attacker@evil.com']
[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_port = 443]
```

## YARA Rule Structure

```
rule RuleName {
    meta:
        author = "Analyst"
        description = "Detection rule"
        reference = "URL"
        date = "YYYY-MM-DD"
        hash = "SHA256"
        tlp = "white"
    strings:
        $text = "string" ascii wide nocase
        $hex = { 4D 5A 90 00 }
        $regex = /pattern[0-9]+/
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and any of them
}
```

## PE File Format
- **DOS Header**: MZ signature (0x5A4D)
- **PE Header**: PE signature, machine type, timestamp
- **Optional Header**: Entry point, image base, subsystem
- **Section Table**: .text, .data, .rdata, .rsrc, .reloc
- **Import Table**: DLLs and functions used
- **Export Table**: Functions exported (DLLs)
- **Resource Table**: Embedded resources (icons, strings, configs)

## References
- [STIX 2.1 Patterning](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e8slinrhxcc9)
- [YARA Documentation](https://yara.readthedocs.io/en/stable/)
- [PE Format Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MalwareBazaar Database](https://bazaar.abuse.ch/)
