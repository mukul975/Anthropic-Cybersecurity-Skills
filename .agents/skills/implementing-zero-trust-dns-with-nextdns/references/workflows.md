# Workflows: Zero Trust DNS with NextDNS

## Workflow 1: Initial NextDNS Deployment

```
Step 1: Create NextDNS Configuration Profile
  - Sign up at nextdns.io
  - Create configuration profile with unique ID
  - Configure security settings (all threat protection enabled)
  - Configure privacy settings (blocklists, native tracking)
  - Set log retention policy

Step 2: Deploy to Network Infrastructure
  - Configure router-level DNS (DoH/DoT)
  - Block plaintext DNS (port 53) at firewall for bypass prevention
  - Configure split DNS for internal domains
  - Test resolution of allowed and blocked domains

Step 3: Deploy to Endpoints
  - Install NextDNS CLI on managed endpoints
  - Configure mobile devices via app or Private DNS
  - Deploy MDM profile for iOS devices
  - Verify per-device identification in NextDNS dashboard

Step 4: Monitor and Tune
  - Review blocked domains for false positives
  - Add necessary allowlist entries
  - Monitor query patterns for anomalies
  - Adjust blocklists based on organizational needs
```

## Workflow 2: DNS Security Policy Enforcement

```
Step 1: Define DNS Security Policy
  - Mandatory security protections (threat intel, DGA, NRD)
  - Privacy protections (tracker blocking, telemetry)
  - Compliance-specific blocking categories
  - Exception handling process

Step 2: Block Plaintext DNS Bypass
  - Firewall rule: Block outbound port 53 UDP/TCP
  - Exception: Only NextDNS CLI or approved resolvers
  - Block known DoH endpoints not managed by organization
  - Disable browser-level DoH in favor of system DNS

Step 3: Implement Monitoring
  - Set up API integration for log export
  - Forward DNS logs to SIEM
  - Create alerts for suspicious DNS patterns
  - Monitor for DNS tunneling indicators
```

## Workflow 3: Incident Response with DNS Logs

```
Step 1: Detect Suspicious Activity
  - Alert on high-frequency queries to single domain
  - Alert on queries to known C2 domains (auto-blocked)
  - Alert on DGA-like domain patterns
  - Alert on DNS tunneling indicators (high entropy, long subdomains)

Step 2: Investigate
  - Query NextDNS API for device-level DNS logs
  - Correlate blocked domains with threat intelligence
  - Identify affected devices and users
  - Determine scope of potential compromise

Step 3: Respond
  - Add malicious domains to denylist for immediate blocking
  - Isolate affected endpoints
  - Update firewall rules as needed
  - Document findings for incident report
```
