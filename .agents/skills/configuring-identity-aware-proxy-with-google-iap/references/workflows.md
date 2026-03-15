# Google IAP Configuration Workflow

## Phase 1: Prerequisites (Day 1)
1. Enable IAP API: `gcloud services enable iap.googleapis.com`
2. Enable Access Context Manager API
3. Configure OAuth consent screen with organization branding
4. Create OAuth client credentials for IAP
5. Verify applications are behind HTTPS Load Balancer or Cloud Run/App Engine

## Phase 2: IAP Enablement (Day 2-3)

### Compute Engine / GKE Backend Services
1. Enable IAP on each backend service with OAuth credentials
2. Configure health checks to work through IAP
3. Verify backend service firewall rules allow only load balancer and IAP ranges
4. Block direct access to backend instances (remove external IPs, restrict firewall)

### App Engine
1. Enable IAP on App Engine with OAuth credentials
2. Verify no App Engine firewall rules bypass IAP
3. Test authentication flow with pilot users

### Cloud Run
1. Grant IAP service account Cloud Run Invoker role
2. Configure Cloud Run service with `--no-allow-unauthenticated`
3. Enable IAP on the backend service fronting Cloud Run
4. Test end-to-end request flow

### TCP Forwarding (SSH/RDP)
1. Grant IAP Tunnel Resource Accessor role to user groups
2. Remove public IP addresses from VMs
3. Configure firewall rules to allow only IAP tunnel IP ranges (35.235.240.0/20)
4. Test SSH/RDP access through IAP tunnel

## Phase 3: Access Control (Day 4-5)
1. Create IAM bindings mapping Google Groups to backend services
2. Add access level conditions for sensitive applications
3. Configure time-based conditions for admin access
4. Set up path-based conditions for API access
5. Test each binding with authorized and unauthorized users

## Phase 4: Access Levels (Day 6-7)
1. Create basic access levels for device posture (encryption, OS, screen lock)
2. Create IP-based access levels for corporate network
3. Create custom access levels with CEL for complex conditions
4. Apply access levels as conditions on IAM bindings
5. Validate with compliant and non-compliant devices

## Phase 5: Session and Re-auth (Day 8)
1. Configure session duration per application tier
2. Set re-authentication method (LOGIN or SECURE_KEY)
3. Test session expiry and re-authentication flow
4. Document expected user experience

## Phase 6: Audit and Monitoring (Day 9-10)
1. Enable data access audit logs for IAP
2. Create log-based metrics for access denials
3. Set up alerting for anomalous patterns
4. Build dashboard for IAP access analytics
5. Test break-glass access procedures
