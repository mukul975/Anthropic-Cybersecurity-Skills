# API Reference: Insecure Mobile Data Storage Detection

## OWASP Mobile Top 10 — M9: Insecure Data Storage

### Risk Areas
| Storage Type | Platform | Risk |
|-------------|----------|------|
| SharedPreferences | Android | HIGH (plaintext XML) |
| SQLite databases | Both | CRITICAL if unencrypted |
| Keychain (improper) | iOS | MEDIUM |
| External storage | Android | HIGH (world-readable) |
| Plist files | iOS | HIGH (plaintext) |

## Android Data Locations

### App Private Storage
```
/data/data/<package>/shared_prefs/    # SharedPreferences XML
/data/data/<package>/databases/        # SQLite databases
/data/data/<package>/files/            # App files
/data/data/<package>/cache/            # Cache data
```

### External Storage (World-Readable)
```
/sdcard/Android/data/<package>/
```

## ADB Commands

### Pull App Data
```bash
adb pull /data/data/com.target.app/ ./extracted/
```

### List SharedPreferences
```bash
adb shell run-as com.target.app ls /data/data/com.target.app/shared_prefs/
```

### Read SharedPreferences
```bash
adb shell run-as com.target.app cat shared_prefs/credentials.xml
```

## SQLite Analysis

### Python sqlite3
```python
import sqlite3
conn = sqlite3.connect("app.db")
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
for table in cursor.fetchall():
    cursor.execute(f"PRAGMA table_info({table[0]})")
    print(cursor.fetchall())
```

## iOS Data Locations

### App Sandbox
```
/var/mobile/Containers/Data/Application/<UUID>/
    Documents/
    Library/Preferences/     # NSUserDefaults (plist)
    Library/Caches/
    tmp/
```

### Keychain
```bash
# Using keychain-dumper
./keychain-dumper -a
```

## Frida Scripts for Data Storage Audit

### Hook SharedPreferences (Android)
```javascript
Java.perform(function() {
    var sp = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    sp.putString.implementation = function(key, value) {
        console.log("SharedPrefs PUT: " + key + " = " + value);
        return this.putString(key, value);
    };
});
```

### Hook NSUserDefaults (iOS)
```javascript
var NSUserDefaults = ObjC.classes.NSUserDefaults;
var orig = NSUserDefaults["- setObject:forKey:"];
Interceptor.attach(orig.implementation, {
    onEnter: function(args) {
        console.log("NSUserDefaults: " + ObjC.Object(args[3]) + " = " + ObjC.Object(args[2]));
    }
});
```

## Secure Storage Alternatives

| Platform | Secure Method |
|----------|---------------|
| Android | EncryptedSharedPreferences, Android Keystore |
| iOS | Keychain Services with kSecAttrAccessible |
| Both | SQLCipher for encrypted databases |
