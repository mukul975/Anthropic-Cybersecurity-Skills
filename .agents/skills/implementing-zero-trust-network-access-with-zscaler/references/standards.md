# Standards and Frameworks Reference

## NIST SP 800-207: Zero Trust Architecture

### Core Tenets Applicable to ZTNA
1. **All data sources and computing services are considered resources** - Every application behind ZPA is treated as a discrete resource requiring explicit access grants
2. **All communication is secured regardless of network location** - ZPA encrypts all tunnels end-to-end regardless of whether users are on-premises or remote
3. **Access to individual enterprise resources is granted on a per-session basis** - ZPA evaluates policy for each connection request rather than granting persistent network access
4. **Access to resources is determined by dynamic policy** - ZPA policies incorporate identity, device posture, location, and behavioral signals
5. **The enterprise monitors and measures the integrity and security posture of all owned and associated assets** - Device posture checks validate endpoint compliance before granting access
6. **All resource authentication and authorization are dynamic and strictly enforced before access is allowed** - ZPA requires authentication through IdP and authorization through policy engine for every session

### NIST ZTA Deployment Models
- **Enhanced Identity Governance**: ZPA implements this model by using identity as the primary decision factor combined with device trust signals
- **Micro-Segmentation**: ZPA application segments function as software-defined microsegments at the application layer
- **Software Defined Perimeters**: ZPA directly implements the SDP model with its broker-based architecture

### NIST SP 800-207A: Zero Trust Architecture Model for Cloud-Native Applications
- Extends zero trust principles to multi-cloud environments
- ZPA App Connectors can be deployed across AWS, Azure, GCP, and on-premises
- Supports workload-to-workload zero trust with ZPA for workloads

## CISA Zero Trust Maturity Model v2.0

### Network Pillar
| Maturity Level | Capability | ZPA Implementation |
|---|---|---|
| Traditional | Macro-segmentation with static rules | Legacy VPN replaced by ZPA |
| Initial | Define network architecture with isolation | App Connectors isolate segments |
| Advanced | Micro-perimeters with identity-based access | Per-app segments with IdP integration |
| Optimal | Dynamic microsegmentation with continuous verification | Real-time posture + behavioral analytics |

### Identity Pillar
| Maturity Level | Capability | ZPA Implementation |
|---|---|---|
| Traditional | Password-based, agency-managed | Basic IdP integration |
| Initial | MFA for privileged users, federated identity | SAML/OIDC with IdP, SCIM provisioning |
| Advanced | MFA for all users, phishing-resistant | Conditional access with posture checks |
| Optimal | Continuous validation, risk-based authentication | ZPA + CrowdStrike/UEBA integration |

### Devices Pillar
| Maturity Level | Capability | ZPA Implementation |
|---|---|---|
| Traditional | Limited device visibility | Manual device inventory |
| Initial | Compliance enforcement for some devices | Basic posture profiles |
| Advanced | Real-time device analytics | CrowdStrike ZTA score integration |
| Optimal | Continuous diagnostics and mitigation | EDR-driven dynamic access decisions |

## CSA Software-Defined Perimeter Specification v2.0

### SDP Architecture Mapping to ZPA
| SDP Component | ZPA Equivalent |
|---|---|
| SDP Controller | ZPA Service Edge + Policy Engine |
| Initiating Host (IH) | Client Connector |
| Accepting Host (AH) | App Connector |
| SDP Gateway | ZPA Service Edge |

### SDP Deployment Models
- **Client-to-Gateway**: Standard ZPA deployment (user to application via Service Edge)
- **Client-to-Server**: ZPA Browser Access (direct browser connection through Service Edge)
- **Server-to-Server**: ZPA Workload-to-Workload (App Connector to App Connector)
- **Client-to-Server-to-Client**: Not directly supported in ZPA

## DoD Zero Trust Reference Architecture v2.0

### Pillar Alignment
- ZPA maps to the **Network & Environment** pillar through application-layer microsegmentation
- ZPA maps to the **User** pillar through IdP integration and continuous authentication
- ZPA maps to the **Device** pillar through endpoint posture assessment
- ZPA maps to the **Application & Workload** pillar through per-application access control
- Visibility & Analytics pillar addressed through ZPA log streaming and analytics dashboards

## Compliance Mapping

| Regulation | Requirement | ZPA Capability |
|---|---|---|
| NIST 800-53 AC-4 | Information flow enforcement | Application segment policies |
| NIST 800-53 AC-17 | Remote access | ZTNA replaces VPN |
| PCI DSS 4.0 Req 1 | Network security controls | Microsegmentation per cardholder segment |
| HIPAA 164.312(e) | Transmission security | End-to-end encrypted tunnels |
| SOX Section 404 | Access controls over financial systems | Auditable per-session access logs |
| FedRAMP | Continuous monitoring | ZPA FedRAMP Moderate authorized |
