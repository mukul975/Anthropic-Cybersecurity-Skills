# Workflows: Exploiting Insecure Data Storage in Mobile

## Workflow 1: Android Data Storage Assessment

```
[Install & exercise app] --> [Root/ADB access] --> [Extract internal storage]
                                                          |
                                       +------------------+------------------+
                                       |                  |                  |
                              [SharedPreferences]   [SQLite DBs]      [File system]
                              [Grep for secrets]    [Open & query]    [Check permissions]
                              [Check encryption]    [Check SQLCipher] [External storage]
                                       |                  |                  |
                                       +------------------+------------------+
                                                          |
                                                   [Backup extraction]
                                                   [ADB backup test]
                                                          |
                                                   [Memory analysis]
                                                   [Logcat review]
                                                          |
                                                   [Report findings]
```

## Workflow 2: iOS Data Storage Assessment

```
[Install & exercise app] --> [Jailbreak/Objection] --> [Extract sandbox data]
                                                              |
                                           +------------------+------------------+
                                           |                  |                  |
                                    [Keychain dump]    [Plist analysis]   [SQLite DBs]
                                    [Protection class] [NSUserDefaults]   [Core Data]
                                    [Access control]   [Sensitive values] [Encryption check]
                                           |                  |                  |
                                           +------------------+------------------+
                                                              |
                                                    [Backup inclusion check]
                                                    [Memory string search]
                                                    [Clipboard monitoring]
                                                              |
                                                    [Report findings]
```

## Decision Matrix: Data Storage Risk

| Storage Mechanism | Encrypted | Access Restricted | Backup Excluded | Risk Level |
|-------------------|-----------|-------------------|-----------------|------------|
| SharedPreferences (plaintext) | No | App-only | No | CRITICAL |
| EncryptedSharedPreferences | Yes | App-only | Depends | LOW |
| SQLite (no SQLCipher) | No | App-only | No | HIGH |
| SQLCipher (key in code) | Yes* | App-only | No | MEDIUM |
| Android Keystore | Yes | Hardware-backed | N/A | LOW |
| iOS Keychain (kSecAttrAccessibleAlways) | Yes | Always accessible | N/A | MEDIUM |
| iOS Keychain (complete protection) | Yes | When unlocked only | N/A | LOW |
| External storage | No | World-readable | N/A | CRITICAL |
