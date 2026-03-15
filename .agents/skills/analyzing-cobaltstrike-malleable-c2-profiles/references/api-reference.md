# CobaltStrike Malleable C2 Profile Analysis API Reference

## Installation

```bash
pip install dissect.cobaltstrike
pip install 'dissect.cobaltstrike[full]'   # With PCAP support
pip install pyMalleableC2                   # Alternative parser
```

## dissect.cobaltstrike API

### Parse Beacon Configuration
```python
from dissect.cobaltstrike.beacon import BeaconConfig

bconfig = BeaconConfig.from_path("beacon.bin")
print(hex(bconfig.watermark))     # 0x5109bf6d
print(bconfig.protocol)           # https
print(bconfig.version)            # BeaconVersion(...)
print(bconfig.settings)           # Full config dict
```

### Parse Malleable C2 Profile
```python
from dissect.cobaltstrike.c2profile import C2Profile

profile = C2Profile.from_path("amazon.profile")
config = profile.as_dict()
print(config["useragent"])
print(config["http-get.uri"])
print(config["sleeptime"])
```

### PCAP Analysis
```bash
# Extract beacons from PCAP
beacon-pcap --extract-beacons traffic.pcap

# Decrypt traffic with private key
beacon-pcap -p team_server.pem traffic.pcap --beacon beacon.bin
```

## pyMalleableC2 API

```python
from malleableC2 import Profile

profile = Profile.from_file("amazon.profile")
print(profile.sleeptime)
print(profile.useragent)
print(profile.http_get.uri)
print(profile.http_post.uri)
```

## Key Profile Settings

| Setting | Description | Detection Value |
|---------|-------------|-----------------|
| `sleeptime` | Callback interval (ms) | Low values = aggressive beaconing |
| `jitter` | Sleep randomization % | Timing analysis evasion |
| `useragent` | HTTP User-Agent string | Network signature |
| `http-get.uri` | GET request URI path | URI-based detection |
| `http-post.uri` | POST request URI path | URI-based detection |
| `spawnto_x86` | 32-bit spawn process | Process creation detection |
| `spawnto_x64` | 64-bit spawn process | Process creation detection |
| `pipename` | Named pipe pattern | Named pipe monitoring |
| `dns_idle` | DNS idle IP address | DNS beacon detection |
| `watermark` | License watermark | Operator attribution |

## Suricata Rule Format

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"MALWARE CobaltStrike C2 URI";
  flow:established,to_server;
  http.uri; content:"/api/v1/status";
  http.header; content:"User-Agent: Mozilla/5.0";
  sid:9000001; rev:1;
)
```

## CLI Usage

```bash
python agent.py --input profile.profile --output report.json
python agent.py --input parsed_config.json --output report.json
```

## References

- dissect.cobaltstrike: https://github.com/fox-it/dissect.cobaltstrike
- pyMalleableC2: https://github.com/byt3bl33d3r/pyMalleableC2
- Unit42 Analysis: https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/
- Config Extractor: https://github.com/strozfriedberg/cobaltstrike-config-extractor
