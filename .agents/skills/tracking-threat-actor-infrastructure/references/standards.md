# Standards and Frameworks Reference

## STIX 2.1 Infrastructure Object
```json
{
  "type": "infrastructure",
  "name": "C2 Server",
  "infrastructure_types": ["command-and-control"],
  "description": "Cobalt Strike TeamServer at 198.51.100.1",
  "first_seen": "2025-01-01T00:00:00Z",
  "last_seen": "2025-06-01T00:00:00Z"
}
```

## Diamond Model of Intrusion Analysis
- **Adversary**: Threat actor or group
- **Capability**: Tools, techniques, and malware
- **Infrastructure**: C2 servers, domains, hosting
- **Victim**: Targeted organization or individual

## Infrastructure Types (STIX vocabulary)
- command-and-control, botnet, exfiltration, hosting-malware
- hosting-target-lists, phishing, staging, undefined

## Network Fingerprinting Methods
| Method | Type | Description |
|--------|------|-------------|
| JARM | Active | TLS server fingerprint from 10 TLS handshakes |
| JA3S | Passive | Server Hello hash from TLS negotiation |
| JA3 | Passive | Client Hello hash for client fingerprinting |
| Favicon Hash | Active | HTTP favicon file hash |
| HTTP Headers | Active/Passive | Server banner and header fingerprinting |
| SSH Key | Active | SSH host key fingerprint |

## Passive DNS Record Types
- A/AAAA: Domain to IP mapping
- CNAME: Domain alias
- MX: Mail server records
- NS: Nameserver records
- TXT: Text records (SPF, DKIM, verification)

## References
- [Diamond Model Paper](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [STIX Infrastructure](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_jo3k1o6lr9)
- [JARM](https://github.com/salesforce/jarm)
- [JA3/JA3S](https://github.com/salesforce/ja3)
