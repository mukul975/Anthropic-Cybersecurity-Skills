# Zscaler Private Access ZTNA - Standards & References

## NIST SP 800-207: Zero Trust Architecture
- **Section 2.1**: Zero Trust Tenets - ZPA implements "never trust, always verify" with per-session application access
- **Section 3.1**: Policy Engine / Policy Administrator - maps to ZPA access policy engine
- **Section 3.3**: Agent/Gateway Model - maps to Zscaler Client Connector + App Connector architecture
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-207/final

## CISA Zero Trust Maturity Model v2.0
- **Network Pillar**: Application micro-segmentation - ZPA application segments eliminate network-level access
- **Identity Pillar**: Continuous validation - ZPA evaluates identity and posture per session
- **URL**: https://www.cisa.gov/zero-trust-maturity-model

## Zscaler Documentation
- **ZPA Admin Guide**: https://help.zscaler.com/zpa
- **Step-by-Step Configuration**: https://help.zscaler.com/zpa/step-step-configuration-guide-zpa
- **App Connector Deployment**: https://help.zscaler.com/zpa/about-app-connectors
- **Access Policy Configuration**: https://help.zscaler.com/zpa/configuring-access-policies
- **Browser Access**: https://help.zscaler.com/zpa/about-browser-access
- **Log Streaming Service**: https://help.zscaler.com/zpa/about-log-streaming-service
- **ZPA Reference Architecture (AWS)**: https://help.zscaler.com/downloads/zpa/reference-architecture

## NIST SP 800-63-3: Digital Identity Guidelines
- **Section 4-6**: Identity assurance levels relevant to ZPA IdP integration
- **URL**: https://pages.nist.gov/800-63-3/

## SOX Compliance (Sarbanes-Oxley)
- **Section 302/404**: Access controls for financial systems - ZPA provides auditable per-application access
- Application-level access logging satisfies audit trail requirements

## Gartner ZTNA Market Guide
- ZPA classified as agent-based ZTNA with service-initiated architecture
- Reference: Gartner Market Guide for Zero Trust Network Access (2024)
