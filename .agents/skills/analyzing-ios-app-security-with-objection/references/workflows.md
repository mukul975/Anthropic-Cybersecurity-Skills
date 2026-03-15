# Workflows: iOS App Security with Objection

## Workflow 1: iOS Runtime Security Assessment

```
[Setup Environment] --> [Prepare Device] --> [Attach Objection] --> [Runtime Analysis]
       |                      |                     |                      |
       v                      v                     v                      v
[Install Frida]      [Jailbroken: Start    [Connect via USB]    [Data Storage Check]
[Install Objection]   frida-server]        [Spawn target app]   [Network Security]
                     [Non-JB: Patch IPA]                        [Auth Mechanism Review]
                                                                [Binary Protection Test]
                                                                         |
                                                                         v
                                                                [Document Findings]
                                                                [Generate Report]
```

## Workflow 2: SSL Pinning Bypass for Traffic Interception

```
[Configure Burp Proxy] --> [Set device proxy] --> [Attach Objection]
                                                        |
                                                        v
                                              [ios sslpinning disable]
                                                        |
                                                        v
                                              [Navigate app in browser/UI]
                                                        |
                                                        v
                                              [Capture HTTPS traffic in Burp]
                                              [Analyze API endpoints]
                                              [Test authentication flows]
                                              [Check for sensitive data in transit]
```

## Workflow 3: Keychain and Data Storage Assessment

```
[Attach Objection] --> [ios keychain dump] --> [Analyze keychain items]
                              |                        |
                              v                        v
                    [ios nsuserdefaults get]   [Check protection classes]
                              |               [Identify sensitive tokens]
                              v               [Verify encryption at rest]
                    [List app sandbox files]
                              |
                              v
                    [sqlite connect *.db]
                    [Query sensitive tables]
                              |
                              v
                    [memory search "password"]
                    [memory search "token"]
                    [memory search "secret"]
```

## Workflow 4: Jailbreak Detection Assessment

```
[Attach Objection] --> [ios jailbreak disable] --> [Navigate app]
                              |                          |
                              v                   [App functions normally?]
                    [Hook detection methods]        /           \
                    [Monitor file checks]       [Yes]          [No]
                    [Monitor Cydia URL scheme]    |              |
                              |               [Detection       [Additional detection
                              v                bypassed]        methods exist]
                    [Document detection                          |
                     methods found]                    [Hook deeper: search
                    [Assess bypass                      for custom checks]
                     difficulty]                       [Frida script for
                                                       targeted bypass]
```

## Decision Matrix: Testing Approach

| Device State | IPA Access | Approach |
|-------------|-----------|----------|
| Jailbroken | Not needed | Direct Frida server + Objection attach |
| Non-jailbroken | Available | Patch IPA with `objection patchipa` |
| Non-jailbroken | Not available | Request IPA from client or use device management |
| Emulator | N/A | Limited: Frida on Corellium or similar platform |
