# Google Cloud IAP - Standards & References

## NIST SP 800-207: Zero Trust Architecture
- **Section 3.1**: Policy Engine - IAP evaluates identity and context per request
- **Section 3.2**: Trust Algorithm - Access Levels compute trust score
- **Section 4.2**: SDP Gateway Model - IAP acts as application-layer gateway
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-207/final

## CISA Zero Trust Maturity Model v2.0
- **Identity Pillar**: Per-request identity verification via IAP
- **Application Pillar**: Application-level access controls
- **URL**: https://www.cisa.gov/zero-trust-maturity-model

## Google Cloud Documentation
- **IAP Overview**: https://cloud.google.com/iap/docs/concepts-overview
- **Enabling IAP for Compute Engine**: https://cloud.google.com/iap/docs/enabling-compute-howto
- **Enabling IAP for App Engine**: https://cloud.google.com/iap/docs/app-engine-quickstart
- **Enabling IAP for Cloud Run**: https://cloud.google.com/iap/docs/enabling-cloud-run
- **IAP TCP Forwarding**: https://cloud.google.com/iap/docs/using-tcp-forwarding
- **Context-Aware Access**: https://cloud.google.com/iap/docs/cloud-iap-context-aware-access-howto
- **Managing Access**: https://cloud.google.com/iap/docs/managing-access
- **Access Context Manager**: https://cloud.google.com/access-context-manager/docs
- **Programmatic Authentication**: https://cloud.google.com/iap/docs/authentication-howto

## Google BeyondCorp Papers
- **BeyondCorp: A New Approach to Enterprise Security** (2014): https://research.google/pubs/pub43231/
- **BeyondCorp: The Access Proxy** (2017): https://research.google/pubs/pub45728/

## FedRAMP
- Google Cloud IAP operates within FedRAMP High boundary
- **URL**: https://cloud.google.com/security/compliance/fedramp
