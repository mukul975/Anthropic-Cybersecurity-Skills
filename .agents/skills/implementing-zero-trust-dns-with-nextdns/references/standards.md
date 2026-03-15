# Standards Reference: Zero Trust DNS with NextDNS

## DNS Security Standards

### RFC 8484: DNS Queries over HTTPS (DoH)
- Encrypts DNS queries over HTTPS on port 443
- Prevents DNS eavesdropping and manipulation
- Browser and OS-level support

### RFC 7858: DNS over Transport Layer Security (DoT)
- Encrypts DNS queries over TLS on port 853
- Dedicated port enables network-level policy control
- Supported by Android 9+, systemd-resolved, Unbound

### RFC 9250: DNS over Dedicated QUIC Connections (DoQ)
- Lower latency than DoH/DoT
- Multiplexed queries without head-of-line blocking
- Supported by NextDNS and Adguard

### NIST SP 800-81-2: Secure Domain Name System Deployment Guide
- DNS infrastructure security requirements
- DNSSEC validation recommendations
- DNS monitoring and logging guidance

## Zero Trust DNS Standards

### Microsoft ZTDNS (Windows 11)
- Enforces that endpoints only use approved DNS resolvers
- Windows Firewall blocks traffic to domains not resolved through protected DNS
- Integration with Windows Defender for endpoint protection

### CISA ZTMM - Network Pillar
- DNS encryption requirement for zero trust compliance
- DNS monitoring for visibility and analytics
- DNS filtering as network security control

## Compliance Mapping

### NIST SP 800-53
- SC-20: Secure Name/Address Resolution Service (Authoritative Source)
- SC-21: Secure Name/Address Resolution Service (Recursive or Caching Resolver)
- SC-22: Architecture and Provisioning for Name/Address Resolution Service
- SI-4: Information System Monitoring (DNS logging)

### CIS Controls v8
- Control 9.2: Use DNS Filtering Services
- Control 9.3: Maintain and Enforce Network-Based URL Filters
- Control 13.3: Deploy Network Intrusion Detection (DNS monitoring)
