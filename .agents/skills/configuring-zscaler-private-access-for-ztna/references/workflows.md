# ZPA ZTNA Configuration Workflow

## Phase 1: Planning and Prerequisites (Week 1)

### 1.1 Architecture Design
1. Map current VPN access patterns: which users access which applications
2. Identify all internal applications by FQDN, IP, and port
3. Group applications into logical segments by business function and sensitivity
4. Design App Connector placement: minimum 2 connectors per data center for HA
5. Plan DNS resolution: App Connectors must resolve all application FQDNs

### 1.2 Identity Provider Integration
1. Configure SAML 2.0 or OIDC integration with corporate IdP (Okta, Entra ID, Ping)
2. Map IdP user groups to ZPA access policy groups
3. Configure SCIM provisioning for automated user/group sync
4. Test SSO authentication flow end-to-end

## Phase 2: Infrastructure Deployment (Week 2-3)

### 2.1 App Connector Deployment
1. Provision Linux VMs (CentOS/RHEL/Ubuntu) meeting minimum specs (2 vCPU, 4GB RAM)
2. Ensure outbound HTTPS (443) to ZPA cloud domains (*.private.zscaler.com, *.zpath.net)
3. Generate provisioning keys in ZPA Admin Portal (one per App Connector Group)
4. Install and configure App Connector packages
5. Verify connector enrollment and health status in portal
6. Deploy second connector per group for high availability

### 2.2 Server Group and Application Segment Configuration
1. Create server groups mapping to App Connector groups
2. Add application servers with FQDNs and ports to server groups
3. Create application segments grouping related applications
4. Configure health monitoring for each segment
5. Test application reachability from App Connector

## Phase 3: Policy Configuration (Week 3-4)

### 3.1 Access Policy Design
1. Create allow rules ordered from most specific to least specific
2. Map IdP groups to application segments in each rule
3. Add device posture profile requirements to rules
4. Configure time-based restrictions for contractor access
5. Create default deny rule as the last policy rule
6. Test each policy rule with representative users

### 3.2 Device Posture Configuration
1. Define posture profiles for each device category (managed, developer, BYOD)
2. Integrate CrowdStrike ZTA scores for real-time posture
3. Configure OS version, encryption, and firewall requirements
4. Test posture evaluation with compliant and non-compliant devices

## Phase 4: User Migration (Week 4-6)

### 4.1 Client Connector Deployment
1. Deploy Zscaler Client Connector via MDM (Intune, Jamf, SCCM)
2. Configure auto-enrollment with IdP authentication
3. Test client connectivity to ZPA cloud
4. Validate application access through Client Connector

### 4.2 Phased Rollout
1. Phase 1: IT/Security team (50 users) - validate all segments
2. Phase 2: Engineering (200 users) - validate developer tools
3. Phase 3: Business users (remaining) - validate general applications
4. Monitor access logs for denials and policy gaps at each phase

## Phase 5: Browser Access Configuration (Week 5)

1. Enable Browser Access for applications requiring clientless access
2. Configure custom domains and TLS certificates
3. Set session timeout and clipboard/file transfer policies
4. Test with contractor accounts

## Phase 6: VPN Decommission (Week 7-8)

1. Run VPN and ZPA in parallel for 2-3 weeks
2. Monitor VPN usage to identify remaining dependencies
3. Migrate remaining applications and users
4. Disable VPN and redirect users to ZPA
5. Decommission VPN infrastructure
