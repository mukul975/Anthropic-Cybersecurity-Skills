# DLP Rule Templates (Step 4 detail)

Full DLP configuration for Step 4: the `dlp_rules.json` template for the Google Workspace DLP API (PII/SSN detection, credit card blocking, and confidential-document detection across Gmail, Drive external sharing, and Chat). Apply via Admin Console > Security > Data Protection, or deploy programmatically with the DLP API.

```bash
# Create DLP rules for Gmail and Drive
# Using Google Workspace DLP API

cat > dlp_rules.json << 'EOF'
{
  "dlpRules": [
    {
      "name": "PII Detection - SSN",
      "description": "Detect Social Security Numbers in outbound email and Drive sharing",
      "trigger": {
        "contentMatchers": [
          {
            "infoType": "US_SOCIAL_SECURITY_NUMBER",
            "likelihood": "LIKELY",
            "minMatchCount": 1
          }
        ],
        "scope": ["GMAIL_OUTBOUND", "DRIVE_EXTERNAL_SHARE"]
      },
      "action": {
        "blockAction": "QUARANTINE",
        "notifyAdmin": true,
        "notifyUser": true,
        "userMessage": "This message contains a Social Security Number and has been quarantined for review.",
        "auditLog": true
      }
    },
    {
      "name": "Credit Card Number Detection",
      "description": "Block credit card numbers in outbound communications",
      "trigger": {
        "contentMatchers": [
          {
            "infoType": "CREDIT_CARD_NUMBER",
            "likelihood": "LIKELY",
            "minMatchCount": 1
          }
        ],
        "scope": ["GMAIL_OUTBOUND", "DRIVE_EXTERNAL_SHARE", "CHAT"]
      },
      "action": {
        "blockAction": "BLOCK",
        "notifyAdmin": true,
        "notifyUser": true,
        "auditLog": true
      }
    },
    {
      "name": "Confidential Document Detection",
      "description": "Detect documents marked as Confidential or Internal Only",
      "trigger": {
        "contentMatchers": [
          {
            "customRegex": "(?i)(CONFIDENTIAL|INTERNAL ONLY|DO NOT DISTRIBUTE|RESTRICTED)",
            "minMatchCount": 2
          }
        ],
        "metadataMatchers": [
          {
            "driveLabels": ["Confidential", "Restricted"]
          }
        ],
        "scope": ["DRIVE_EXTERNAL_SHARE"]
      },
      "action": {
        "blockAction": "WARN",
        "requireJustification": true,
        "auditLog": true
      }
    }
  ]
}
EOF

echo "Apply DLP rules via Admin Console > Security > Data Protection"
echo "Or use the Google Workspace DLP API for programmatic deployment"
```

