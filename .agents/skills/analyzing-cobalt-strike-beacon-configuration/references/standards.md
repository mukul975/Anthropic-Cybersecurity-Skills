# Standards and Frameworks Reference

## Cobalt Strike Beacon Configuration Fields

### Configuration TLV Types
| Type ID | Field Name | Data Type | Description |
|---------|-----------|-----------|-------------|
| 0x0001 | BeaconType | Short | 0=HTTP, 1=Hybrid HTTP/DNS, 8=HTTPS, 10=TCP Bind |
| 0x0002 | Port | Short | C2 communication port |
| 0x0003 | SleepTime | Int | Beacon callback interval in milliseconds |
| 0x0005 | Jitter | Short | Percentage of sleep time randomization (0-99) |
| 0x0008 | C2Server | String | Comma-separated C2 domains/IPs |
| 0x0009 | UserAgent | String | HTTP User-Agent header value |
| 0x000a | PostURI | String | URI for HTTP POST requests |
| 0x000d | SpawnTo_x86 | String | 32-bit process to spawn for post-ex |
| 0x000e | SpawnTo_x64 | String | 64-bit process to spawn for post-ex |
| 0x001a | Watermark | Int | License watermark identifier |
| 0x0024 | PipeName | String | Named pipe for SMB beacon |
| 0x001d | HostHeader | String | HTTP Host header value |
| 0x0032 | ProxyHostname | String | Proxy server address |

### XOR Encoding Scheme
- **Cobalt Strike 3.x**: XOR key = 0x69
- **Cobalt Strike 4.x**: XOR key = 0x2e
- Configuration blob size: 4096 bytes (typical)
- Encoding: Single-byte XOR across entire config blob

### Stageless Beacon Structure
- PE with beacon code in .data section
- 4-byte XOR key applied to .data section content
- Configuration embedded after beacon code
- Reflective DLL loader prepended to beacon

## MITRE ATT&CK Mappings

### Cobalt Strike Techniques (S0154)
| Technique | ID | Description |
|-----------|-----|------------|
| Application Layer Protocol | T1071.001 | HTTP/HTTPS C2 communication |
| Encrypted Channel | T1573.002 | AES-256 encrypted C2 |
| Ingress Tool Transfer | T1105 | Download additional payloads |
| Process Injection | T1055 | Inject into spawned processes |
| Named Pipes | T1570 | SMB beacon lateral movement |
| Service Execution | T1569.002 | PSExec-style lateral movement |
| Reflective Code Loading | T1620 | In-memory beacon loading |

## Malleable C2 Profile Structure

### HTTP GET Block
```
http-get {
    set uri "/path";
    client {
        header "Accept" "text/html";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "text/html";
        output {
            print;
        }
    }
}
```

### HTTP POST Block
```
http-post {
    set uri "/submit";
    client {
        id {
            uri-append;
        }
        output {
            base64;
            print;
        }
    }
    server {
        output {
            print;
        }
    }
}
```

## References
- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/)
- [Malleable C2 Profile Reference](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [MITRE ATT&CK Cobalt Strike](https://attack.mitre.org/software/S0154/)
