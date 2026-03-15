# Malware IOC Extraction Report Template

## Sample Information
| Field | Value |
|-------|-------|
| Filename | |
| File Size | |
| File Type | PE32/PE32+/ELF/Mach-O |
| MD5 | |
| SHA-1 | |
| SHA-256 | |
| Imphash | |
| SSDeep | |
| First Seen | |

## PE Analysis

| Attribute | Value |
|-----------|-------|
| Compile Time | |
| Entry Point | |
| Machine Type | |
| Subsystem | |
| Is DLL | |
| Digital Signature | Valid/Invalid/None |

### Sections
| Name | Virtual Size | Raw Size | Entropy | Suspicious |
|------|-------------|----------|---------|------------|
| .text | | | | |
| .data | | | | |
| .rsrc | | | | |

### Suspicious API Imports
| DLL | Function | Purpose |
|-----|----------|---------|
| kernel32.dll | VirtualAlloc | Memory allocation (code injection) |
| kernel32.dll | CreateRemoteThread | Process injection |
| wininet.dll | InternetOpenA | Network communication |

## Network IOCs

### IP Addresses
| IP | Context | Confidence |
|----|---------|-----------|
| | C2 Server | High/Med/Low |

### Domains
| Domain | Context | Confidence |
|--------|---------|-----------|
| | C2 Domain | High/Med/Low |

### URLs
| URL | Context | Confidence |
|-----|---------|-----------|
| | Payload Download | High/Med/Low |

## Host IOCs

### Registry Keys
| Key Path | Value | Purpose |
|----------|-------|---------|
| HKLM\...\Run | | Persistence |

### Mutexes
| Mutex Name | Purpose |
|-----------|---------|
| | Infection marker |

### File System Artifacts
| Path | Description |
|------|------------|
| | Dropped payload |

## YARA Matches
| Rule | Tags | Description |
|------|------|------------|
| | | |

## VirusTotal Results
| Metric | Value |
|--------|-------|
| Detection Ratio | X / Y |
| Threat Label | |
| First Submission | |
| Community Score | |

## MITRE ATT&CK Mapping
| Technique | Name | Evidence |
|-----------|------|----------|
| T1059.001 | PowerShell | Embedded PS commands |
| T1547.001 | Registry Run Keys | HKLM Run key modification |
| T1071.001 | Web Protocols | HTTP C2 communication |

## Recommendations
1. **Block**: Add network IOCs to firewall/proxy blocklists
2. **Detect**: Deploy YARA rules on endpoints and email gateways
3. **Hunt**: Search for host IOCs across the environment
4. **Share**: Upload IOCs to MISP with TLP classification
