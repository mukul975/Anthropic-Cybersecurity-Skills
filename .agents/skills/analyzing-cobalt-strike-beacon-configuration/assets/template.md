# Cobalt Strike Beacon Analysis Report Template

## Report Metadata
| Field | Value |
|-------|-------|
| Report ID | CS-BEACON-YYYY-NNNN |
| Date | YYYY-MM-DD |
| Sample Hash (SHA-256) | |
| Classification | TLP:AMBER |
| Analyst | |

## Beacon Configuration Summary

| Setting | Value |
|---------|-------|
| Beacon Type | HTTP / HTTPS / SMB / DNS |
| C2 Server(s) | |
| Port | |
| Sleep Time | ms |
| Jitter | % |
| User-Agent | |
| Watermark | |
| SpawnTo (x86) | |
| SpawnTo (x64) | |
| Named Pipe | |
| Host Header | |
| Crypto Scheme | |

## C2 Infrastructure

| Indicator | Type | Value | Context |
|-----------|------|-------|---------|
| C2 Domain | domain | | Primary callback |
| C2 IP | ip | | Resolved address |
| URI Path (GET) | uri | | Beacon check-in |
| URI Path (POST) | uri | | Data exfiltration |

## Malleable C2 Profile

### HTTP GET Configuration
| Parameter | Value |
|-----------|-------|
| URI | |
| Verb | |
| Headers | |
| Metadata Encoding | |

### HTTP POST Configuration
| Parameter | Value |
|-----------|-------|
| URI | |
| Verb | |
| ID Encoding | |
| Output Encoding | |

## Watermark Attribution

| Watermark | Known Association | Confidence |
|-----------|------------------|------------|
| | Cracked / Licensed / Threat Actor | High/Med/Low |

## Network Detection Signatures

```
# Suricata signature for beacon C2 traffic
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Cobalt Strike Beacon C2 Communication";
    content:"[USER_AGENT]"; http_user_agent;
    content:"[URI_PATH]"; http_uri;
    sid:1000001; rev:1;
)
```

## YARA Detection Rule

```yara
rule CobaltStrike_Beacon_[CAMPAIGN] {
    meta:
        description = "Detects Cobalt Strike beacon from [CAMPAIGN]"
        hash = "[SHA256]"
    strings:
        $c2 = "[C2_DOMAIN]" ascii
        $pipe = "[NAMED_PIPE]" ascii
        $ua = "[USER_AGENT]" ascii
    condition:
        2 of them
}
```

## Recommendations

1. **Block**: Add C2 domains/IPs to firewall deny lists
2. **Hunt**: Search for named pipe and spawn-to process in endpoint logs
3. **Detect**: Deploy YARA and network signatures to detection stack
4. **Correlate**: Check watermark against threat intelligence databases
