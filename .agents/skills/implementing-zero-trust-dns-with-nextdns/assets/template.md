# NextDNS Zero Trust DNS Deployment Template

## Configuration
- **NextDNS Config ID**: _______________
- **Plan**: [ ] Free [ ] Pro [ ] Business [ ] Enterprise
- **Log Retention**: _____ days
- **Log Storage Region**: [ ] US [ ] EU [ ] UK [ ] Switzerland

## Security Settings Checklist
- [ ] Threat Intelligence Feeds enabled
- [ ] AI-Driven Threat Detection enabled
- [ ] Google Safe Browsing enabled
- [ ] Cryptojacking Protection enabled
- [ ] DNS Rebinding Protection enabled
- [ ] IDN Homograph Attack Protection enabled
- [ ] Typosquatting Protection enabled
- [ ] DGA Protection enabled
- [ ] NRD Protection (< 30 days) enabled
- [ ] DDNS Blocking enabled
- [ ] Parked Domains blocking enabled

## Privacy Settings Checklist
- [ ] Blocklists configured (list: ___)
- [ ] Native Tracking Protection enabled
- [ ] CNAME Cloaking Protection enabled

## Deployment Targets

| Target | Method | Status | Config Verified |
|---|---|---|---|
| Router | DoT/DoH | [ ] Complete | [ ] Verified |
| Windows endpoints | NextDNS CLI | [ ] Complete | [ ] Verified |
| macOS endpoints | NextDNS CLI | [ ] Complete | [ ] Verified |
| Linux servers | systemd-resolved | [ ] Complete | [ ] Verified |
| iOS devices | MDM profile | [ ] Complete | [ ] Verified |
| Android devices | Private DNS | [ ] Complete | [ ] Verified |

## Network Controls
- [ ] Plaintext DNS (port 53) blocked at firewall
- [ ] Unauthorized DoH endpoints blocked
- [ ] Split DNS configured for internal domains
- [ ] Browser DoH disabled in favor of system DNS
