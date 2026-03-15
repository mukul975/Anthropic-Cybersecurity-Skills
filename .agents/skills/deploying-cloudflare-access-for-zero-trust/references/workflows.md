# Cloudflare Access Zero Trust Deployment Workflow

## Phase 1: Account Setup (Day 1)

1. Create Cloudflare account and navigate to Zero Trust dashboard
2. Select team name (organization identifier for WARP enrollment)
3. Choose subscription plan based on user count
4. Configure authentication: add primary IdP (Okta, Entra ID, Google Workspace)
5. Add secondary IdP for contractors or partners if needed
6. Enable MFA requirements at the IdP level

## Phase 2: Tunnel Deployment (Day 2-3)

### 2.1 Install cloudflared
1. Install `cloudflared` on a server within the private network
2. Authenticate with `cloudflared tunnel login`
3. Create named tunnel: `cloudflared tunnel create <name>`
4. Configure ingress rules in `config.yml` mapping hostnames to internal services
5. Route DNS: `cloudflared tunnel route dns <tunnel> <hostname>`

### 2.2 High Availability
1. Deploy multiple `cloudflared` instances for redundancy
2. Use `cloudflared tunnel run --protocol quic` for better performance
3. Configure systemd service for automatic restart
4. Monitor tunnel health via Cloudflare dashboard

### 2.3 Private Network Routing
1. Add private network routes: `cloudflared tunnel route ip add 10.0.0.0/8 <tunnel-id>`
2. Configure split tunnel in WARP device settings
3. Set up DNS fallback domains for private DNS resolution

## Phase 3: Access Application Configuration (Day 4-5)

1. Create Access applications for each internal service
2. Define access policies per application:
   - Include rules: email domains, IdP groups, service tokens
   - Require rules: device posture, country restrictions
   - Exclude rules: specific users or IPs
3. Configure session duration per application sensitivity
4. Enable purpose justification for sensitive applications
5. Test access with pilot users

## Phase 4: WARP Client Deployment (Week 2)

1. Create device enrollment policies with email domain restrictions
2. Deploy WARP client via MDM (Intune, Jamf, SCCM)
3. Install Cloudflare root certificate for TLS inspection
4. Configure split tunnel settings for private network access
5. Enable device posture checks: OS version, disk encryption, firewall

## Phase 5: Gateway and DLP Configuration (Week 3)

1. Enable DNS filtering with block categories (malware, phishing)
2. Configure HTTP inspection policies
3. Set up DLP profiles for sensitive data detection
4. Enable browser isolation for high-risk web categories
5. Configure CASB for SaaS application monitoring

## Phase 6: Monitoring and Optimization (Ongoing)

1. Enable Logpush to SIEM (S3, Splunk, Datadog)
2. Monitor Access audit logs for denied requests
3. Review tunnel health metrics
4. Optimize split tunnel configuration
5. Conduct quarterly access policy reviews
