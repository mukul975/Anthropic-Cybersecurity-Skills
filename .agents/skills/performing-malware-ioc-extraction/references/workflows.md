# Malware IOC Extraction Workflows

## Workflow 1: Static Analysis Pipeline

```
[Malware Sample] --> [Hash Generation] --> [PE Parsing] --> [String Extraction] --> [IOC Filtering]
                                                                                        |
                                                                                        v
                                                                               [YARA Scanning]
                                                                                        |
                                                                                        v
                                                                               [STIX Bundle]
```

### Steps:
1. **Sample Acquisition**: Obtain sample from MalwareBazaar, VirusTotal, or incident response
2. **Hash Calculation**: Generate MD5, SHA-1, SHA-256, imphash, ssdeep hashes
3. **PE Analysis**: Parse headers, sections, imports, exports, resources, timestamps
4. **String Extraction**: Extract ASCII/Unicode strings, apply IOC regex patterns
5. **IOC Filtering**: Remove false positives (private IPs, common DLLs, benign domains)
6. **YARA Classification**: Scan with community and custom YARA rules
7. **Output**: Generate STIX 2.1 bundle with extracted indicators

## Workflow 2: Dynamic Analysis Pipeline

```
[Malware Sample] --> [Sandbox Submission] --> [Detonation] --> [Artifact Collection]
                                                                       |
                                                          +------------+------------+
                                                          |            |            |
                                                          v            v            v
                                                    [Network]    [File Sys]   [Registry]
                                                    [PCAPs]      [Changes]    [Changes]
                                                          |            |            |
                                                          +------------+------------+
                                                                       |
                                                                       v
                                                              [IOC Consolidation]
```

### Steps:
1. **Sandbox Setup**: Configure isolated VM with network monitoring
2. **Sample Submission**: Submit to CAPE/Cuckoo sandbox with execution parameters
3. **Execution Monitoring**: Monitor for 3-5 minutes of runtime behavior
4. **Network Capture**: Extract DNS queries, HTTP/HTTPS traffic, raw connections
5. **File System Analysis**: Identify created, modified, and deleted files
6. **Registry Analysis**: Capture registry key changes for persistence indicators
7. **Process Analysis**: Document spawned processes, injections, privilege escalation
8. **Consolidation**: Merge static and dynamic IOCs into unified report

## Workflow 3: Automated IOC Pipeline

```
[Feed/Alert] --> [Auto-Download] --> [Static Analysis] --> [Sandbox] --> [Enrichment] --> [Share]
                                                                              |
                                                                              v
                                                                     [VirusTotal Check]
                                                                              |
                                                                              v
                                                                     [MISP/OpenCTI Upload]
```

### Steps:
1. **Trigger**: New sample from malware feed, email gateway, or EDR alert
2. **Download**: Retrieve sample securely to analysis infrastructure
3. **Static Scan**: Automated PE parsing, string extraction, YARA scanning
4. **Dynamic Analysis**: Submit to sandbox for behavioral analysis
5. **Enrichment**: Check hashes against VirusTotal, cross-reference with TI platforms
6. **Deduplication**: Remove already-known IOCs from output
7. **Sharing**: Upload new IOCs to MISP/OpenCTI for team consumption
