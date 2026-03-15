# MFA with Duo Workflows

## Workflow 1: Duo Authentication Proxy Deployment
1. Install Duo Authentication Proxy on dedicated server
2. Configure authproxy.cfg with AD/LDAP primary auth
3. Add Duo API credentials (ikey, skey, api_host)
4. Set failmode=safe for initial testing, change to secure for production
5. Start Duo proxy service, verify connectivity
6. Configure VPN/application to use proxy as RADIUS server
7. Test with pilot group before full deployment

## Workflow 2: User Enrollment
1. Admin creates Duo user (manual or AD sync)
2. User receives enrollment email/link
3. User installs Duo Mobile app
4. User scans QR code to link device
5. User completes test authentication
6. Admin verifies enrollment status in Admin Panel

## Workflow 3: MFA Fatigue Attack Response
1. Detect multiple rapid push notifications to single user
2. Alert security team via SIEM integration
3. Temporarily lock user's Duo account
4. Contact user to verify if they initiated authentication
5. If unauthorized: reset credentials, investigate source
6. If authorized: educate user, enable Verified Push
7. Update policy to require Verified Push for affected group

## Workflow 4: Duo Failover and Emergency Access
1. Duo cloud service becomes unreachable
2. Authentication Proxy checks failmode setting
3. If failmode=secure: deny all access (most secure)
4. If failmode=safe: allow primary auth only (business continuity)
5. Admin monitors Duo status page for resolution
6. After restoration: review all authentications during outage
7. Investigate any suspicious access during failover period
