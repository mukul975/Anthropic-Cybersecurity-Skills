# SDP Deployment Workflows

## Workflow 1: SDP Connection Establishment

```
┌────────────┐     ┌──────────────┐     ┌────────────┐
│ IH (Client) │     │ SDP Controller│     │ AH (Gateway)│
└──────┬─────┘     └──────┬───────┘     └──────┬─────┘
       │                   │                     │
       │ 1. Authenticate   │                     │
       │──────────────────>│                     │
       │                   │                     │
       │ 2. Validate ID,   │                     │
       │    device, policy │                     │
       │                   │                     │
       │ 3. Auth response  │                     │
       │<──────────────────│                     │
       │  (SPA key, AH IP) │                     │
       │                   │ 4. Notify AH to     │
       │                   │    expect IH        │
       │                   │────────────────────>│
       │                   │                     │
       │ 5. Send SPA packet│                     │
       │─────────────────────────────────────────>│
       │                   │                     │
       │                   │  6. Validate SPA    │
       │                   │     Open port       │
       │                   │                     │
       │ 7. mTLS handshake │                     │
       │<════════════════════════════════════════>│
       │                   │                     │
       │ 8. Application    │                     │
       │    traffic flows  │                     │
       │<═══════════════════════════════════════=>│
```

## Workflow 2: SDP Deployment Lifecycle

```
Phase 1: Planning (Weeks 1-2)
├── Inventory protected applications
├── Map user-to-application access requirements
├── Design PKI infrastructure for mTLS
├── Select SDP solution (open-source or commercial)
└── Plan network architecture changes

Phase 2: Controller Setup (Weeks 3-4)
├── Deploy SDP controller with HA
├── Integrate with IdP (SAML/OIDC)
├── Configure PKI and certificate templates
├── Define application catalog and policies
└── Test controller authentication flow

Phase 3: Gateway Deployment (Weeks 5-6)
├── Deploy gateways in each app environment
├── Configure default-drop firewall rules
├── Enable SPA listeners
├── Register applications with controller
└── Verify gateway invisibility (port scan test)

Phase 4: Client Rollout (Weeks 7-10)
├── Package SDP client with certificates
├── Deploy to pilot user group
├── Validate end-to-end connectivity
├── Expand to all user groups
└── Decommission legacy VPN access

Phase 5: Operations (Ongoing)
├── Monitor SDP controller and gateway health
├── Rotate certificates on schedule
├── Review and update access policies
├── Conduct quarterly penetration tests
└── Update SDP components for security patches
```

## Workflow 3: SPA Validation

```
Incoming Packet to Gateway
    │
    v
┌─────────────────────┐
│ Is it a SPA packet?  │
│ (Check magic bytes)  │
└───┬──────────┬──────┘
    │          │
   YES        NO
    │          │
    v          v
┌──────────┐  ┌──────────┐
│ Decrypt  │  │ DROP     │
│ SPA data │  │ silently │
└────┬─────┘  └──────────┘
     v
┌─────────────────────┐
│ Validate timestamp   │
│ (within 60s window)  │
└───┬──────────┬──────┘
   VALID    EXPIRED
    │          │
    v          v
┌──────────┐  ┌──────────┐
│ Check    │  │ DROP +   │
│ HMAC     │  │ Log      │
└────┬─────┘  └──────────┘
     v
┌─────────────────────┐
│ Verify replay        │
│ (check sequence DB)  │
└───┬──────────┬──────┘
   NEW      REPLAY
    │          │
    v          v
┌──────────┐  ┌──────────┐
│ Open port │  │ DROP +   │
│ for src IP│  │ Alert    │
│ (30s TTL) │  └──────────┘
└──────────┘
```
