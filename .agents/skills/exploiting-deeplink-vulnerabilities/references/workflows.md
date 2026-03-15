# Workflows: Deep Link Vulnerability Testing

## Workflow 1: Deep Link Assessment
```
[Extract Manifest/Plist] --> [Enumerate schemes] --> [Test each deep link]
                                                          |
                                           +--------------+--------------+
                                           |              |              |
                                    [Parameter injection] [Redirect test] [WebView loading]
                                    [SQL/XSS/Path trav]  [Open redirect]  [JS injection]
                                           |              |              |
                                           +--------------+--------------+
                                                          |
                                                   [Link hijacking test]
                                                   [App Links verification]
                                                   [Report findings]
```

## Decision Matrix
| Scheme Type | Hijacking Risk | Mitigation |
|-------------|---------------|------------|
| Custom (myapp://) | HIGH - any app can register | Validate calling app, use App Links |
| App Links (verified) | LOW - domain verified | Ensure assetlinks.json is correct |
| Universal Links | LOW - domain verified | Ensure AASA file is correct |
