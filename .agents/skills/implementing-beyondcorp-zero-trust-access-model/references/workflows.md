# BeyondCorp Zero Trust Implementation Workflow

## Phase 1: Discovery and Planning (Weeks 1-2)

### 1.1 Application Inventory
1. Enumerate all internal applications accessed via VPN or corporate network
2. Classify each application by:
   - Hosting environment: GCP (App Engine, GKE, Compute Engine, Cloud Run), on-premises, SaaS
   - Protocol: HTTPS, TCP, SSH, RDP
   - Authentication method: SAML, OIDC, Kerberos, LDAP, custom
   - Sensitivity: Public, Internal, Confidential, Restricted
3. Document current access patterns: which groups access which applications
4. Identify applications that cannot be proxied (raw UDP, custom protocols)

### 1.2 Device Inventory
1. Enumerate all corporate-managed and BYOD devices
2. Document OS distribution: Windows, macOS, ChromeOS, Linux, iOS, Android
3. Verify device management coverage: Intune, Jamf, Chrome Enterprise
4. Identify gaps in device management enrollment

### 1.3 Access Level Design
1. Define trust tiers based on organizational risk appetite:
   - **Tier 1 (Basic)**: Any authenticated user from any device
   - **Tier 2 (Standard)**: Authenticated user from enrolled device with screen lock
   - **Tier 3 (Enhanced)**: Authenticated user from compliant device with disk encryption
   - **Tier 4 (High)**: Authenticated user from managed device with EDR, specific geography
2. Map applications to required trust tiers
3. Define exception process for access level overrides

## Phase 2: Infrastructure Setup (Weeks 3-4)

### 2.1 Google Cloud Configuration
1. Enable required APIs: IAP, Access Context Manager, BeyondCorp Enterprise, Cloud Audit Logs
2. Configure OAuth consent screen and IAP OAuth clients
3. Set up IAP service accounts with minimal permissions
4. Configure Cloud DNS for IAP-protected applications

### 2.2 Access Context Manager Setup
1. Create access policy at the organization level
2. Define access levels using basic conditions (device policy, IP ranges, regions)
3. Define custom access levels using CEL expressions for complex conditions
4. Test access levels with a pilot group before broad deployment

### 2.3 Endpoint Verification Deployment
1. Deploy Endpoint Verification Chrome extension via Google Admin Console policy
2. Configure extension settings: data collection scope, reporting frequency
3. Allow 1-2 weeks for device inventory population
4. Validate device attribute collection against access level requirements

## Phase 3: Application Migration (Weeks 5-10)

### 3.1 GCP-Hosted HTTPS Applications
1. Ensure applications are behind an HTTPS Load Balancer
2. Enable IAP on each backend service
3. Configure IAM bindings with access level conditions
4. Test access with pilot users before expanding
5. Monitor IAP access logs for false denials

### 3.2 On-Premises Applications
1. Deploy BeyondCorp Enterprise connectors in on-premises DMZ
2. Create app connections mapping external DNS to internal endpoints
3. Configure IAP tunnels for TCP-based applications
4. Validate network connectivity from connector to internal applications
5. Test end-to-end access through IAP connector

### 3.3 SaaS Applications
1. Configure SAML/OIDC federation from Google Workspace to SaaS apps
2. Apply conditional access policies at the IdP level
3. Enable session controls and re-authentication requirements

## Phase 4: Policy Enforcement (Weeks 11-12)

### 4.1 Gradual Enforcement
1. Start with audit-only mode: log but do not block non-compliant access
2. Review audit logs to identify users/devices that would be blocked
3. Communicate requirements and provide remediation guidance
4. Enable enforcement in stages: Tier 2 first, then Tier 3, then Tier 4

### 4.2 Re-authentication Configuration
1. Set session duration per application based on sensitivity:
   - General applications: 8-hour session
   - Sensitive applications: 4-hour session
   - Critical applications: 1-hour session
2. Configure re-authentication method: LOGIN (full re-auth) or SECURE_KEY (FIDO2 touch)

## Phase 5: VPN Decommission (Weeks 13-16)

### 5.1 Parallel Operation
1. Run VPN and BeyondCorp in parallel for 30 days
2. Monitor VPN usage to identify remaining dependencies
3. Migrate stragglers and address edge cases
4. Document break-glass procedures for BeyondCorp failure scenarios

### 5.2 VPN Retirement
1. Disable new VPN connections
2. Notify all users of VPN decommission date
3. Remove VPN client from managed devices
4. Decommission VPN infrastructure
5. Redirect VPN DNS entries to BeyondCorp access portal

## Phase 6: Continuous Monitoring (Ongoing)

### 6.1 Access Analytics
1. Build BigQuery dashboards for access pattern analysis
2. Configure alerting for anomalous access patterns:
   - Access from new geographies
   - Access outside business hours
   - Repeated authentication failures
   - Device compliance changes
3. Perform monthly access reviews of IAP bindings

### 6.2 Policy Optimization
1. Review access level effectiveness quarterly
2. Adjust device posture requirements based on threat landscape
3. Update session duration policies based on incident trends
4. Validate break-glass procedures monthly
