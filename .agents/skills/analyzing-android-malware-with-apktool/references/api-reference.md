# API Reference — Analyzing Android Malware with Apktool

## Libraries Used
- **androguard**: Python APK/DEX analysis — `AnalyzeAPK()`, permission enumeration, API call scanning
- **re**: Regex extraction of URLs, IPs, base64 patterns from DEX strings
- **json**: JSON serialization for analysis reports

## CLI Interface
```
python agent.py sample.apk permissions
python agent.py sample.apk manifest
python agent.py sample.apk apis
python agent.py sample.apk strings
python agent.py sample.apk full
python agent.py sample.apk           # defaults to full analysis
```

## Core Functions

### `analyze_permissions(apk)` — Permission risk assessment
Calls `apk.get_permissions()`. Flags 20 dangerous permissions including
SEND_SMS, READ_CONTACTS, BIND_DEVICE_ADMIN, BIND_ACCESSIBILITY_SERVICE.
Risk: CRITICAL >= 8 dangerous, HIGH >= 5, MEDIUM >= 2, LOW < 2.

### `analyze_manifest(apk)` — Manifest component extraction
Calls `apk.get_activities()`, `get_services()`, `get_receivers()`, `get_providers()`.
Returns package name, version, SDK levels, and all component lists.

### `scan_suspicious_apis(dx)` — Suspicious API call detection
Searches DEX analysis for 14 patterns including:
- `Runtime.exec`, `ProcessBuilder.start` — command execution
- `DexClassLoader.loadClass` — dynamic code loading
- `Method.invoke`, `Class.forName` — reflection
- `Cipher.getInstance` — cryptographic operations
- `SmsManager.sendTextMessage` — SMS abuse

### `extract_strings(dx, apk)` — IOC extraction from DEX strings
Regex extraction of HTTP/HTTPS URLs, external IP addresses, and base64 strings.
Filters out private IP ranges (10.x, 192.168.x, 172.16.x, 127.x).

### `detect_obfuscation(apk, dx)` — Obfuscation indicator detection
Checks for single-letter class names (ProGuard), multi-DEX, native libraries.

### `full_analysis(apk_path)` — Comprehensive malware assessment

## Androguard API
| Method | Returns |
|--------|---------|
| `AnalyzeAPK(path)` | `(APK, list[DEX], Analysis)` tuple |
| `apk.get_permissions()` | List of Android permissions |
| `apk.get_activities()` | Activity component names |
| `apk.get_services()` | Service component names |
| `apk.get_receivers()` | BroadcastReceiver names |
| `apk.get_package()` | Package name string |
| `dx.find_methods(classname, methodname)` | Matching method analysis objects |
| `dx.get_strings()` | All strings from DEX files |
| `dx.get_classes()` | All class analysis objects |

## Risk Scoring
| Factor | Max Points |
|--------|-----------|
| Dangerous permissions (8 pts each) | 40 |
| Suspicious API calls (10 pts each) | 30 |
| External IPs (5 pts each) | 15 |
| Obfuscation detected | 15 |

## Dependencies
- `androguard` >= 3.4.0
- Isolated analysis environment recommended
