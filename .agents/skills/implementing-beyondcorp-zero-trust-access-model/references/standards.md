# BeyondCorp Zero Trust Standards & References

## NIST SP 800-207: Zero Trust Architecture
- **Section 2**: Zero Trust Tenets - defines the core principles BeyondCorp implements
- **Section 3.1**: Policy Engine (PE) and Policy Administrator (PA) - maps to IAP and Access Context Manager
- **Section 3.2**: Trust Algorithm - corresponds to Access Levels evaluation
- **Section 4.1**: Device Agent/Gateway-Based Deployment - matches BeyondCorp connector model
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-207/final

## CISA Zero Trust Maturity Model v2.0 (April 2023)
- **Identity Pillar**: MFA enforcement, continuous validation - maps to IAP re-authentication
- **Device Pillar**: Device health monitoring, compliance enforcement - maps to Endpoint Verification
- **Network Pillar**: Micro-segmentation, encrypted traffic - maps to IAP tunnel encryption
- **Application Pillar**: Application access authorization - maps to per-service IAP policies
- **Data Pillar**: Data access governance, DLP - maps to Chrome Enterprise Premium DLP
- **URL**: https://www.cisa.gov/zero-trust-maturity-model

## Google BeyondCorp Papers
- **BeyondCorp: A New Approach to Enterprise Security** (2014)
  - Describes the original BeyondCorp architecture eliminating the privileged intranet
  - URL: https://research.google/pubs/pub43231/
- **BeyondCorp: Design to Deployment at Google** (2016)
  - Details the migration strategy from VPN to BeyondCorp
  - URL: https://research.google/pubs/pub44860/
- **BeyondCorp: The Access Proxy** (2017)
  - Describes the access proxy component that became IAP
  - URL: https://research.google/pubs/pub45728/
- **Migrating to BeyondCorp** (2018)
  - Covers the phased migration approach and lessons learned
  - URL: https://research.google/pubs/pub46134/

## Google Cloud IAP Documentation
- **IAP Overview**: https://cloud.google.com/iap/docs/concepts-overview
- **IAP for Compute Engine**: https://cloud.google.com/iap/docs/enabling-compute-howto
- **IAP for App Engine**: https://cloud.google.com/iap/docs/app-engine-quickstart
- **Access Context Manager**: https://cloud.google.com/access-context-manager/docs
- **Endpoint Verification**: https://cloud.google.com/endpoint-verification/docs
- **BeyondCorp Enterprise**: https://cloud.google.com/beyondcorp-enterprise/docs

## NIST SP 800-63-3: Digital Identity Guidelines
- **Section 4**: Defines identity assurance levels (IAL1-3) relevant to access level design
- **URL**: https://pages.nist.gov/800-63-3/

## DoD Zero Trust Reference Architecture v2.0
- **Section 3.4**: Identity, Credential, and Access Management pillar
- **Section 3.5**: Device pillar - endpoint compliance requirements
- **URL**: https://dodcio.defense.gov/Portals/0/Documents/Library/ZTRAv2.0.pdf
