# Cobalt Strike Beacon Analysis Workflows

## Workflow 1: PE File Configuration Extraction

```
[Suspicious PE] --> [Unpack if packed] --> [Locate .data section] --> [XOR Decrypt]
                                                                          |
                                                                          v
                                                                  [Parse TLV Config]
                                                                          |
                                                                          v
                                                              [Extract C2 Indicators]
```

### Steps:
1. **Triage**: Identify file as potential Cobalt Strike beacon via YARA or AV detection
2. **Unpacking**: If packed, unpack using appropriate tool (UPX, custom unpacker)
3. **Section Analysis**: Locate .data section containing XOR'd beacon code
4. **XOR Key Discovery**: Try known keys (0x2e, 0x69) or brute-force 4-byte key
5. **Config Parsing**: Parse decrypted TLV entries for C2 and operational settings
6. **IOC Extraction**: Extract domains, IPs, URIs, user agents, watermarks

## Workflow 2: Memory Dump Beacon Extraction

```
[Memory Dump] --> [Volatility3 malfind] --> [Dump Injected Regions] --> [Parse Config]
                                                                            |
                                                                            v
                                                                   [C2 Infrastructure Map]
```

### Steps:
1. **Acquisition**: Capture memory dump from compromised system
2. **Process Scan**: Use Volatility3 to identify suspicious processes
3. **Injection Detection**: Use malfind to find RWX memory regions
4. **Region Extraction**: Dump injected memory regions to files
5. **Config Search**: Scan dumps for beacon configuration signatures
6. **Infrastructure Mapping**: Correlate extracted C2 with network logs

## Workflow 3: Watermark Attribution

```
[Multiple Beacons] --> [Extract Watermarks] --> [Cluster by Watermark] --> [Attribution]
                                                                               |
                                                                               v
                                                                     [Campaign Correlation]
```

### Steps:
1. **Collection**: Gather beacon samples from incident or threat intel feeds
2. **Watermark Extraction**: Extract watermark value from each sample
3. **Database Lookup**: Check watermark against known databases
4. **Clustering**: Group beacons sharing the same watermark
5. **Infrastructure Overlap**: Correlate C2 infrastructure across cluster
6. **Attribution Assessment**: Link to known threat actor or cracked license

## Workflow 4: C2 Traffic Detection

```
[Beacon Config] --> [Extract C2 Profile] --> [Generate Signatures] --> [Deploy to NIDS]
                                                                            |
                                                                            v
                                                                   [Monitor Network Traffic]
```

### Steps:
1. **Profile Extraction**: Parse malleable C2 profile from beacon config
2. **Pattern Identification**: Identify unique HTTP headers, URIs, and encoding
3. **Signature Creation**: Write Suricata/Snort rules matching C2 patterns
4. **Deployment**: Deploy signatures to network detection infrastructure
5. **Validation**: Test signatures against captured beacon traffic
6. **Monitoring**: Alert on matching network flows for active beacons
