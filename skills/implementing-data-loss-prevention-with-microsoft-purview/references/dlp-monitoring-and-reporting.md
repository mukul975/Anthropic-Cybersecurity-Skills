# DLP Monitoring and Reporting (Step 5 detail)

Programmatic retrieval of DLP events for SIEM integration and compliance reporting.

- **Query DLP events via Microsoft Graph API**: Programmatically retrieve DLP alerts and policy match details for integration with SIEM or custom dashboards:
  ```python
  import requests

  # Authenticate with Microsoft Graph (client credentials flow)
  token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
  token_response = requests.post(token_url, data={
      "client_id": client_id,
      "client_secret": client_secret,
      "scope": "https://graph.microsoft.com/.default",
      "grant_type": "client_credentials"
  })
  access_token = token_response.json()["access_token"]

  headers = {"Authorization": f"Bearer {access_token}"}

  # Retrieve DLP alerts
  alerts_url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
  params = {
      "$filter": "serviceSource eq 'microsoftDataLossPrevention'",
      "$top": 50,
      "$orderby": "createdDateTime desc"
  }
  response = requests.get(alerts_url, headers=headers, params=params)
  alerts = response.json().get("value", [])

  for alert in alerts:
      print(f"Alert: {alert['title']}")
      print(f"  Severity: {alert['severity']}")
      print(f"  Status: {alert['status']}")
      print(f"  Created: {alert['createdDateTime']}")
      print(f"  User: {alert.get('userStates', [{}])[0].get('userPrincipalName', 'N/A')}")
  ```
- **Retrieve DLP policy match details for compliance reporting**: Use the unified audit log to extract granular DLP match data including the matched content, SIT type, and confidence level:
  ```powershell
  # Search unified audit log for DLP policy matches
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -RecordType "DLP" `
    -ResultSize 1000 |
    Select-Object CreationDate, UserIds, Operations,
      @{N='PolicyName';E={($_.AuditData | ConvertFrom-Json).PolicyDetails.PolicyName}},
      @{N='RuleName';E={($_.AuditData | ConvertFrom-Json).PolicyDetails.Rules.RuleName}},
      @{N='SITMatched';E={($_.AuditData | ConvertFrom-Json).SensitiveInfoDetections.SensitiveType}} |
    Export-Csv -Path "DLP_Audit_Report.csv" -NoTypeInformation
  ```

