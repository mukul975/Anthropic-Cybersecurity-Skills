---
name: configuring-identity-aware-proxy-with-google-iap
description: >
  Configuring Google Cloud Identity-Aware Proxy (IAP) to enforce per-request identity
  verification for Compute Engine, App Engine, Cloud Run, and GKE services using
  access levels, context-aware policies, and programmatic access with service accounts.
domain: cybersecurity
subdomain: zero-trust-architecture
tags: [google-iap, identity-aware-proxy, gcp, zero-trust, access-context-manager, cloud-run, app-engine]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Configuring Identity-Aware Proxy with Google IAP

## When to Use

- When protecting Google Cloud applications (App Engine, Cloud Run, GKE, Compute Engine) with identity-based access
- When implementing context-aware access requiring device posture and location verification
- When providing secure access to internal tools without VPN or public IP exposure
- When needing per-request authentication and authorization for web applications and TCP services
- When configuring programmatic access to IAP-protected resources using service accounts

**Do not use** for non-HTTP applications that cannot be placed behind an HTTPS load balancer, for public-facing applications that need unauthenticated access, or when applications handle their own authentication and IAP would conflict with existing auth flows.

## Prerequisites

- Google Cloud project with billing enabled
- IAP API enabled (`gcloud services enable iap.googleapis.com`)
- Application deployed behind HTTPS Load Balancer, App Engine, or Cloud Run
- Cloud Identity or Google Workspace for user management
- Access Context Manager API enabled for access levels
- OAuth consent screen configured for the project

## Workflow

### Step 1: Enable IAP on Backend Services

Configure IAP for different GCP compute platforms.

```bash
# Enable required APIs
gcloud services enable iap.googleapis.com
gcloud services enable accesscontextmanager.googleapis.com

# Create OAuth consent screen
gcloud iap oauth-brands create \
  --application_title="Internal Applications" \
  --support_email=security@company.com

# Create OAuth client
gcloud iap oauth-clients create \
  projects/PROJECT_ID/brands/BRAND_ID \
  --display_name="IAP Web Client"

# === Enable IAP on Compute Engine Backend Service ===
gcloud compute backend-services update my-backend-service \
  --iap=enabled,oauth2-client-id=CLIENT_ID,oauth2-client-secret=CLIENT_SECRET \
  --global

# === Enable IAP on App Engine ===
gcloud iap web enable \
  --resource-type=app-engine \
  --oauth2-client-id=CLIENT_ID \
  --oauth2-client-secret=CLIENT_SECRET

# === Enable IAP on Cloud Run ===
# First grant IAP service account the Cloud Run Invoker role
gcloud run services add-iam-policy-binding my-service \
  --member="serviceAccount:service-PROJECT_NUM@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region=us-central1

# Enable IAP on the Cloud Run backend service
gcloud compute backend-services update my-cloud-run-backend \
  --iap=enabled,oauth2-client-id=CLIENT_ID,oauth2-client-secret=CLIENT_SECRET \
  --global

# === Enable IAP TCP Forwarding for SSH/RDP ===
# No load balancer needed - uses IAP tunnel
gcloud compute instances add-iam-policy-binding my-vm \
  --member="group:developers@company.com" \
  --role="roles/iap.tunnelResourceAccessor" \
  --zone=us-central1-a

# SSH through IAP tunnel
gcloud compute ssh my-vm --zone=us-central1-a --tunnel-through-iap

# RDP through IAP tunnel
gcloud compute start-iap-tunnel my-windows-vm 3389 \
  --local-host-port=localhost:3390 \
  --zone=us-central1-a
```

### Step 2: Configure IAM Bindings for Access Control

Grant access to specific users and groups with optional access level conditions.

```bash
# Grant basic access to a group
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=my-backend-service \
  --member="group:engineering@company.com" \
  --role="roles/iap.httpsResourceAccessor"

# Grant access with access level condition
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=finance-app \
  --member="group:finance@company.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition='expression=request.auth.access_levels.exists(x, x == "accessPolicies/POLICY_ID/accessLevels/corporate-device"),title=RequireCorporateDevice,description=Requires managed corporate device'

# Grant access only during business hours
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=admin-console \
  --member="group:admins@company.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition='expression=request.time.getHours("America/New_York") >= 8 && request.time.getHours("America/New_York") <= 18 && request.time.getDayOfWeek("America/New_York") >= 1 && request.time.getDayOfWeek("America/New_York") <= 5,title=BusinessHoursOnly'

# Grant access to a specific URL path
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=internal-api \
  --member="group:api-consumers@company.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition='expression=request.path.startsWith("/api/v2/"),title=APIv2Access'
```

### Step 3: Create Access Levels with Access Context Manager

Define context-based access requirements using device attributes and network conditions.

```bash
# Create access level requiring encrypted corporate device
cat > managed-device.yaml << 'EOF'
- devicePolicy:
    allowedEncryptionStatuses:
      - ENCRYPTED
    osConstraints:
      - osType: DESKTOP_WINDOWS
        minimumVersion: "10.0.19045"
      - osType: DESKTOP_MAC
        minimumVersion: "14.0"
      - osType: DESKTOP_CHROME_OS
    requireScreenlock: true
    requireAdminApproval: true
    allowedDeviceManagementLevels:
      - ADVANCED
EOF

gcloud access-context-manager levels create managed-device \
  --policy=POLICY_ID \
  --title="Managed Device" \
  --basic-level-spec=managed-device.yaml

# Create access level for corporate network
cat > corp-network.yaml << 'EOF'
- ipSubnetworks:
    - "203.0.113.0/24"
    - "198.51.100.0/24"
  regions:
    - US
    - GB
EOF

gcloud access-context-manager levels create corp-network \
  --policy=POLICY_ID \
  --title="Corporate Network" \
  --basic-level-spec=corp-network.yaml

# Create custom access level using CEL for complex logic
cat > high-trust.yaml << 'EOF'
expression: >
  device.encryption_status == DeviceEncryptionStatus.ENCRYPTED &&
  device.is_admin_approved_device == true &&
  (
    origin.ip in ["203.0.113.0/24"] ||
    device.os_type == OsType.DESKTOP_CHROME_OS
  ) &&
  request.auth.claims.hd == "company.com"
EOF

gcloud access-context-manager levels create high-trust \
  --policy=POLICY_ID \
  --title="High Trust" \
  --custom-level-spec=high-trust.yaml
```

### Step 4: Configure Session Settings and Re-authentication

Set session duration and re-authentication policies per application.

```bash
# Configure re-authentication for a backend service
# Requires login every 4 hours for sensitive apps
gcloud iap settings set \
  --project=PROJECT_ID \
  --resource-type=compute \
  --service=finance-app \
  reauthSettings.method=LOGIN \
  reauthSettings.maxAge=14400s \
  reauthSettings.policyType=MINIMUM

# Configure session settings for App Engine
gcloud iap settings set \
  --project=PROJECT_ID \
  --resource-type=app-engine \
  reauthSettings.method=SECURE_KEY \
  reauthSettings.maxAge=3600s \
  reauthSettings.policyType=MINIMUM

# View current IAP settings
gcloud iap settings get \
  --project=PROJECT_ID \
  --resource-type=compute \
  --service=finance-app
```

### Step 5: Configure Programmatic Access for Service Accounts

Enable service-to-service communication through IAP-protected endpoints.

```python
#!/usr/bin/env python3
"""Access IAP-protected resource using service account credentials."""

import google.auth
import google.auth.transport.requests
from google.auth import impersonated_credentials
import requests as req

IAP_CLIENT_ID = "YOUR_IAP_OAUTH_CLIENT_ID.apps.googleusercontent.com"
IAP_URL = "https://my-app.company.com/api/data"

def access_iap_resource():
    # Get default credentials (works with service account key or workload identity)
    credentials, project = google.auth.default()

    # Create IAP-authenticated request
    authed_session = google.auth.transport.requests.AuthorizedSession(
        credentials,
        target_audience=IAP_CLIENT_ID
    )

    # Make request to IAP-protected resource
    response = authed_session.get(IAP_URL)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:500]}")

    return response

if __name__ == "__main__":
    access_iap_resource()
```

### Step 6: Set Up Audit Logging and Monitoring

Configure logging for all IAP access decisions.

```bash
# Enable data access audit logs for IAP
gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json

# Add IAP audit config to policy.json:
# {
#   "service": "iap.googleapis.com",
#   "auditLogConfigs": [
#     {"logType": "ADMIN_READ"},
#     {"logType": "DATA_READ"},
#     {"logType": "DATA_WRITE"}
#   ]
# }

gcloud projects set-iam-policy PROJECT_ID policy.json

# Create log-based metric for denied access
gcloud logging metrics create iap-denied-access \
  --description="Count of IAP access denials" \
  --log-filter='resource.type="gce_backend_service" AND protoPayload.status.code=16'

# Create alerting policy for high denial rates
gcloud alpha monitoring policies create \
  --display-name="IAP High Denial Rate" \
  --condition-display-name="Denied access > 50 in 5 min" \
  --condition-filter='metric.type="logging.googleapis.com/user/iap-denied-access"' \
  --condition-threshold-value=50 \
  --condition-threshold-duration=300s \
  --notification-channels=projects/PROJECT_ID/notificationChannels/CHANNEL_ID

# Query IAP access logs
gcloud logging read '
  resource.type="gce_backend_service"
  protoPayload.serviceName="iap.googleapis.com"
  timestamp >= "2026-02-22T00:00:00Z"
' --project=PROJECT_ID --format='table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.status.code,resource.labels.backend_service_name)' --limit=50
```

## Key Concepts

| Term | Definition |
|------|------------|
| Identity-Aware Proxy | GCP service that intercepts web requests and TCP connections, authenticating users and evaluating access policies before proxying to backend services |
| Backend Service | GCP load balancer component that IAP protects; can serve Compute Engine instances, GKE pods, Cloud Run services, or App Engine |
| IAP Tunnel | Secure TCP tunnel through IAP allowing SSH, RDP, and other TCP access to VMs without public IPs or VPN |
| OAuth Consent Screen | GCP configuration specifying the application name and support email shown to users during IAP authentication |
| Access Level | Named condition in Access Context Manager evaluated during IAP authorization (device posture, IP, geography) |
| Re-authentication | IAP feature requiring users to prove their identity again after a configurable session duration |

## Tools & Systems

- **Google Cloud IAP**: Identity-aware reverse proxy for GCP applications and TCP services
- **Access Context Manager**: Defines access levels based on device, network, and geographic attributes
- **gcloud CLI**: Command-line tool for configuring IAP, access levels, and IAM bindings
- **IAP TCP Forwarding**: Tunnel-based access to VMs for SSH/RDP without public IPs
- **Cloud Audit Logs**: Immutable records of all IAP access decisions for compliance
- **Endpoint Verification**: Chrome extension collecting device attributes for access level evaluation

## Common Scenarios

### Scenario: Securing 15 Internal GCP Services with IAP

**Context**: An e-commerce company runs 15 internal services on GKE and Cloud Run (admin dashboards, internal APIs, monitoring tools). Currently, these services are protected only by VPN and firewall rules, creating excessive network-level access.

**Approach**:
1. Deploy all services behind an HTTPS Load Balancer with managed SSL certificates
2. Enable IAP on each backend service with per-service OAuth clients
3. Create IAM bindings mapping Google Groups to specific services (admin group -> admin dashboard, engineering -> monitoring)
4. Define access levels: managed-device (encryption + screen lock), corp-network (office IP ranges)
5. Apply managed-device access level to admin dashboard and financial tools
6. Configure IAP TCP tunneling for SSH access to GKE nodes (replacing SSH bastion host)
7. Set re-authentication to 4 hours for admin tools, 8 hours for monitoring
8. Configure Cloud Audit Logs and create alerting for repeated denials

**Pitfalls**: IAP adds 10-50ms latency per request; test application performance. WebSocket connections through IAP require specific backend service configuration. Service-to-service calls within GKE should bypass IAP using internal service mesh, not external IAP endpoints. Break-glass access should use a separate IAM binding without access level conditions.

## Output Format

```
Google Cloud IAP Configuration Report
==================================================
Project: ecommerce-internal
Report Date: 2026-02-23

IAP-PROTECTED SERVICES:
  Backend Services:     12
  App Engine:            1
  Cloud Run:             2
  IAP TCP Tunnels:       4 (SSH access)
  Total:                19

ACCESS CONTROL:
  IAM Bindings:         34
  With Access Levels:   18 (52.9%)
  Access Levels:         3 (managed-device, corp-network, high-trust)

SESSION POLICIES:
  Admin tools:          4h re-auth (SECURE_KEY)
  Sensitive apps:       4h re-auth (LOGIN)
  General tools:        8h re-auth (LOGIN)

ACCESS LOGS (last 24h):
  Total requests:       23,456
  Authenticated:        23,289 (99.3%)
  Denied by IAM:           112
  Denied by access level:   55
  Unique users:            134
```
