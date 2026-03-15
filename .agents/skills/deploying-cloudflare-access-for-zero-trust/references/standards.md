# Cloudflare Access Zero Trust - Standards & References

## NIST SP 800-207: Zero Trust Architecture
- **Section 2**: ZTA Tenets - Cloudflare Access implements per-request identity verification
- **Section 3.2**: Enhanced Identity Governance - Access policies enforce continuous authorization
- **Section 4.2**: Cloud-Based SDP - Cloudflare Tunnel maps to software-defined perimeter architecture
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-207/final

## CISA Zero Trust Maturity Model v2.0
- **Identity**: SSO with MFA via integrated IdP support
- **Device**: WARP client posture checks for OS, encryption, EDR
- **Network**: Cloudflare Tunnel eliminates inbound firewall rules
- **Application**: Per-application Access policies with session controls
- **URL**: https://www.cisa.gov/zero-trust-maturity-model

## Cloudflare Documentation
- **Cloudflare One Overview**: https://developers.cloudflare.com/cloudflare-one/
- **Cloudflare Access**: https://developers.cloudflare.com/cloudflare-one/policies/access/
- **Cloudflare Tunnel**: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
- **WARP Deployment**: https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/
- **Device Posture**: https://developers.cloudflare.com/cloudflare-one/identity/devices/
- **Logpush**: https://developers.cloudflare.com/logs/about/
- **Zero Trust Reference Architecture**: https://developers.cloudflare.com/reference-architecture/implementation-guides/zero-trust/

## SOC 2 Type II
- Cloudflare maintains SOC 2 Type II certification
- Access audit logs provide evidence for CC6.1 (Logical Access), CC6.3 (Role-Based Access)
- **URL**: https://www.cloudflare.com/trust-hub/compliance-resources/

## GDPR
- Cloudflare processes data per EU GDPR requirements
- Data localization options for EU-based traffic
- **URL**: https://www.cloudflare.com/trust-hub/gdpr/
