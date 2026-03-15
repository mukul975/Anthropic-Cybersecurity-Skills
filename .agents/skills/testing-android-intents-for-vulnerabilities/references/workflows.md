# Workflows: Android Intent Vulnerability Testing

## Workflow 1: IPC Security Assessment
```
[Decompile APK] --> [Parse AndroidManifest] --> [Enumerate exported components]
                                                        |
                                     +------------------+------------------+
                                     |          |           |              |
                              [Activities] [Services]  [Receivers]  [Providers]
                              [Direct launch] [Bind/Start] [Trigger] [Query/Inject]
                              [Auth bypass?]  [Data exfil?] [Sniff?] [SQLi? Traversal?]
                                     |          |           |              |
                                     +------------------+------------------+
                                                        |
                                                 [PendingIntent audit]
                                                 [Report findings]
```
