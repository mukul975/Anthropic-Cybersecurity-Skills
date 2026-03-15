# API Reference: Cobalt Strike Beacon Configuration Analysis

## Beacon Config TLV Format

### Structure
```
[Field ID: 2 bytes][Type: 2 bytes][Value: variable]
Type 1 = short (2 bytes), Type 2 = int (4 bytes), Type 3 = string/blob (2-byte length + data)
```

### XOR Encoding
| Version | XOR Key |
|---------|---------|
| CS 3.x | `0x69` |
| CS 4.x | `0x2E` |

### Key Configuration Fields
| ID | Name | Description |
|----|------|-------------|
| 1 | BeaconType | 0=HTTP, 1=Hybrid, 2=SMB, 8=HTTPS |
| 2 | Port | C2 communication port |
| 3 | SleepTime | Beacon interval (ms) |
| 5 | Jitter | Random sleep variation (%) |
| 7 | PublicKey | RSA public key for encryption |
| 8 | C2Server | Command and control server(s) |
| 9 | UserAgent | HTTP User-Agent string |
| 10 | PostURI | POST callback URI |
| 37 | Watermark | License watermark (operator ID) |
| 54 | PipeName | Named pipe for SMB beacons |

## 1768.py (Didier Stevens) - Config Extractor

### Syntax
```bash
python 1768.py <beacon_file>           # Extract config
python 1768.py -j <beacon_file>        # JSON output
python 1768.py -r <beacon_file>        # Raw config dump
```

## CobaltStrikeParser (SentinelOne)

### Syntax
```bash
python parse_beacon_config.py <file>
python parse_beacon_config.py --json <file>
```

### Output Fields
```
BeaconType:        HTTPS
Port:              443
SleepTime:         60000
Jitter:            37
C2Server:          update.microsoft-cdn.com,/api/v2
UserAgent:         Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Watermark:         305419896
SpawnToX86:        %windir%\syswow64\dllhost.exe
SpawnToX64:        %windir%\sysnative\dllhost.exe
```

## JARM Fingerprinting

### Cobalt Strike Default JARM
```bash
# Default CS JARM hash (pre-4.7)
07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1

# Scan with JARM
python jarm.py <target_ip> -p 443
```

## Known Watermark Values
| Watermark | Attribution |
|-----------|------------|
| 0 | Trial/cracked version |
| 305419896 | Common cracked version |
| 1359593325 | Known threat actor toolkit |
| 1580103824 | Known APT usage |

## Detection Signatures

### Suricata
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Cobalt Strike Beacon";
    content:"/submit.php"; http_uri;
    content:"Cookie:"; http_header;
    pcre:"/Cookie:\s[A-Za-z0-9+/=]{60,}/H";
    sid:2028591; rev:1;)
```

### YARA
```yara
rule CobaltStrike_Beacon {
    strings:
        $config_v3 = { 00 01 00 01 00 02 ?? ?? 00 01 00 02 }
        $magic = "MSSE-%d-server"
        $pipe = "\\\\.\\pipe\\msagent_"
    condition:
        uint16(0) == 0x5A4D and any of them
}
```

## Malleable C2 Profile Elements
| Element | Description |
|---------|-------------|
| `http-get` | GET request profile (URI, headers, metadata transform) |
| `http-post` | POST request profile (URI, body transform) |
| `set sleeptime` | Default beacon interval |
| `set jitter` | Randomization percentage |
| `set useragent` | HTTP User-Agent |
| `set pipename` | SMB named pipe name |
