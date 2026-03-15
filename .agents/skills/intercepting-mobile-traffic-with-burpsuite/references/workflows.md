# Workflows: Mobile Traffic Interception with Burp Suite

## Workflow 1: Standard Mobile API Testing

```
[Configure Burp Listener] --> [Set Device Proxy] --> [Install CA Cert] --> [Open Target App]
                                                                                |
                                                                                v
                                                                     [Capture HTTP History]
                                                                                |
                                                          +---------------------+---------------------+
                                                          |                     |                     |
                                                   [Map API surface]    [Identify auth flow]   [Check data exposure]
                                                          |                     |                     |
                                                          v                     v                     v
                                                   [Send to Scanner]    [Token analysis]       [PII in responses]
                                                   [Active scan]        [Session testing]      [Sensitive headers]
                                                          |                     |                     |
                                                          +---------------------+---------------------+
                                                                                |
                                                                         [Compile findings]
                                                                         [Generate report]
```

## Workflow 2: SSL Pinning Bypass Pipeline

```
[Set Proxy] --> [Open App] --> [Connection fails?]
                                    |
                              [Yes: Pinning active]
                                    |
                     +--------------+--------------+
                     |              |              |
              [Frida bypass]  [Objection]   [APK repackage]
              [Generic script] [sslpinning] [Remove pinning code]
                     |         [disable]          |
                     +--------------+--------------+
                                    |
                           [Verify traffic flows]
                           [Continue assessment]
```

## Workflow 3: Authentication Testing

```
[Intercept login request] --> [Capture auth token] --> [Analyze token format]
                                                              |
                                                   +----------+----------+
                                                   |                     |
                                            [JWT analysis]        [Opaque token]
                                            [Decode payload]      [Session management]
                                            [Check signature]     [Timeout testing]
                                            [Modify claims]       [Concurrent session]
                                                   |                     |
                                                   +----------+----------+
                                                              |
                                                    [Test IDOR with user IDs]
                                                    [Test privilege escalation]
                                                    [Test token replay after logout]
```

## Decision Matrix: Traffic Interception Approach

| Scenario | Android | iOS |
|----------|---------|-----|
| No pinning, API < 24 | Standard proxy + user CA | Standard proxy + profile install |
| No pinning, API 24+ | System CA or network_security_config mod | Standard proxy + profile install |
| Pinning implemented | Frida/Objection bypass + system CA | Frida/Objection bypass |
| Custom protocol | Wireshark + custom Frida hooks | Wireshark + custom Frida hooks |
| VPN tunnel | iptables redirect on rooted device | Not feasible without jailbreak |
