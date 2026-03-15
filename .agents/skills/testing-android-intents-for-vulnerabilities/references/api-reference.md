# API Reference: Testing Android Intents for Vulnerabilities

## Drozer Modules

| Module | Description |
|--------|-------------|
| `app.package.attacksurface` | Enumerate exported components |
| `app.activity.info` | List exported activities |
| `app.service.info` | List exported services |
| `app.broadcast.info` | List exported receivers |
| `app.provider.info` | List content providers |
| `app.provider.query` | Query content provider URI |
| `scanner.provider.injection` | Test for SQL injection |
| `scanner.provider.traversal` | Test for path traversal |
| `app.broadcast.send` | Send broadcast intent |
| `app.activity.start` | Start exported activity |

## ADB Intent Commands

| Command | Description |
|---------|-------------|
| `adb shell am start -n <pkg>/<activity>` | Start activity |
| `adb shell am broadcast -a <action>` | Send broadcast |
| `adb shell am startservice -n <pkg>/<svc>` | Start service |
| `adb shell content query --uri <uri>` | Query provider |
| `adb shell dumpsys package <pkg>` | Package info |

## Component Types

| Type | Risk | Test |
|------|------|------|
| Exported Activity | Auth bypass | Direct launch without intent filters |
| Content Provider | Data leakage, SQLi | Query with modified URIs |
| Broadcast Receiver | Action spoofing | Send crafted broadcasts |
| Service | Unauthorized actions | Bind/start with extras |
| PendingIntent | Hijacking | Check FLAG_MUTABLE |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute adb/drozer CLI |
| `re` | stdlib | Parse command output |
| `json` | stdlib | Report generation |

## References

- Drozer: https://github.com/WithSecureLabs/drozer
- OWASP MASTG: https://mas.owasp.org/MASTG/
- Android IPC: https://developer.android.com/guide/components/intents-filters
