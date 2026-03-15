# Palo Alto NGFW Deployment Template

## Pre-Deployment Checklist

- [ ] Network topology documented with zone boundaries
- [ ] IP addressing scheme finalized for all interfaces
- [ ] HA pair hardware matched (same model, same licenses)
- [ ] Management network access configured
- [ ] DNS and NTP servers available
- [ ] Active Directory credentials for User-ID agent
- [ ] Internal CA certificate generated for SSL Forward Proxy
- [ ] License keys activated (Threat Prevention, URL Filtering, WildFire)
- [ ] Syslog/SIEM endpoint configured and reachable
- [ ] Change management ticket approved

## Zone Definitions Template

| Zone Name | Interfaces | Trust Level | Description |
|-----------|-----------|-------------|-------------|
| Trust | eth1/1 | High | Corporate LAN |
| Untrust | eth1/2 | None | Internet |
| DMZ | eth1/3 | Medium | Public-facing servers |
| Guest | eth1/4 | Low | Guest wireless |
| DC | eth1/5 | High | Data center servers |

## Security Profile Group Template

```
Group: Standard-Security-Profiles
├── Anti-Virus: default
├── Anti-Spyware: strict (sinkhole enabled)
├── Vulnerability: strict
├── URL Filtering: corporate-policy
├── File Blocking: block-dangerous-types
└── WildFire: forward-all-files
```

## Security Policy Template

| # | Name | From | To | Source | Destination | Application | Action | Profile |
|---|------|------|----|--------|-------------|-------------|--------|---------|
| 1 | Allow-DNS | Trust | Untrust | Any | DNS-Servers | dns | Allow | Standard |
| 2 | Allow-Web | Trust | Untrust | Any | Any | web-browsing,ssl | Allow | Standard |
| 3 | Allow-Business | Trust | Untrust | Any | Any | office365,salesforce | Allow | Standard |
| 4 | Block-HighRisk | Any | Any | Any | Any | bittorrent,tor | Deny | N/A |
| 5 | DMZ-Inbound | Untrust | DMZ | Any | Web-Servers | web-browsing,ssl | Allow | Standard |
| 6 | Deny-All | Any | Any | Any | Any | Any | Deny | N/A |

## Post-Deployment Validation

- [ ] All zones show correct interface assignments
- [ ] Traffic logs show App-ID classification working
- [ ] Threat Prevention blocking EICAR test file
- [ ] URL Filtering blocking test malware URLs
- [ ] SSL decryption certificate trusted by endpoints
- [ ] User-ID mapping active users correctly
- [ ] HA failover tested successfully
- [ ] SIEM receiving forwarded logs
- [ ] Zone Protection profiles applied to all zones
- [ ] No shadowed or unused rules in policy
