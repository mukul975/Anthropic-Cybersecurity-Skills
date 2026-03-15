# Standards and References - EZ Tools Windows Forensics

## Industry Standards

### NIST SP 800-86 - Guide to Integrating Forensic Techniques
- Framework for collecting, examining, and analyzing digital evidence
- Defines procedures for forensic acquisition and chain of custody
- EZ Tools align with NIST evidence handling and analysis guidelines

### ISO/IEC 27037 - Digital Evidence Collection
- International standard for identification, collection, acquisition, and preservation
- KAPE collection follows ISO 27037 acquisition methodology
- Timeline Explorer output supports ISO-compliant reporting

### SWGDE Best Practices for Computer Forensics
- Scientific Working Group on Digital Evidence guidelines
- Defines validation requirements for forensic tools
- EZ Tools undergo community-driven validation testing

## Tool References

### EZ Tools Suite Components
| Tool | Version | Purpose |
|------|---------|---------|
| KAPE | 1.3+ | Artifact collection and processing orchestration |
| MFTECmd | 1.2+ | NTFS Master File Table parser |
| PECmd | 1.5+ | Windows Prefetch file parser |
| RECmd | 2.0+ | Registry hive parser with batch processing |
| EvtxECmd | 1.5+ | Windows Event Log parser with maps |
| LECmd | 1.5+ | LNK shortcut file parser |
| JLECmd | 1.5+ | Jump List parser |
| SBECmd | 2.0+ | Shellbag parser |
| Timeline Explorer | 2.0+ | CSV analysis and visualization |
| Registry Explorer | 2.0+ | GUI registry hive viewer |
| ShellBags Explorer | 2.0+ | GUI shellbag viewer |
| AmcacheParser | 1.5+ | Amcache.hve parser |
| AppCompatCacheParser | 1.5+ | ShimCache parser |
| WxTCmd | 1.0+ | Windows Timeline database parser |
| RBCmd | 1.5+ | Recycle Bin artifact parser |
| bstrings | 1.5+ | Binary string extraction |

### SANS Training Courses
- FOR500: Windows Forensic Analysis
- FOR508: Advanced Incident Response, Threat Hunting, and Digital Forensics
- FOR498: Battlefield Forensics & Data Acquisition
- FOR610: Reverse-Engineering Malware

### MITRE ATT&CK Relevance
- T1070 - Indicator Removal: Timestomping detection via MFT analysis
- T1547 - Boot or Logon Autostart Execution: Registry persistence detection
- T1053 - Scheduled Task/Job: Task scheduler artifact analysis
- T1059 - Command and Scripting Interpreter: Prefetch execution evidence
- T1021 - Remote Services: Lateral movement via event log analysis

## Official Resources
- Eric Zimmerman's GitHub: https://ericzimmerman.github.io/
- KAPE GitHub Targets/Modules: https://github.com/EricZimmerman/KapeFiles
- EZ Tools Changelog: https://ericzimmerman.github.io/#!index.md
- SANS DFIR Blog: https://www.sans.org/blog/?focus-area=digital-forensics
