# API Reference: Mobile Device Forensics with Cellebrite

## Key SQLite Databases

### Android
| Database | Path | Content |
|----------|------|---------|
| mmssms.db | `data/data/com.android.providers.telephony/databases/` | SMS/MMS messages |
| calllog.db | `data/data/com.android.providers.contacts/databases/` | Call logs |
| contacts2.db | `data/data/com.android.providers.contacts/databases/` | Contacts |
| msgstore.db | `data/data/com.whatsapp/databases/` | WhatsApp messages |
| History | `data/data/com.android.chrome/app_chrome/Default/` | Chrome history |

### iOS
| Database | Path | Content |
|----------|------|---------|
| sms.db | `HomeDomain/Library/SMS/` | iMessage and SMS |
| AddressBook.sqlitedb | `HomeDomain/Library/AddressBook/` | Contacts |
| Safari/History.db | `HomeDomain/Library/Safari/` | Safari browsing history |
| knowledgeC.db | `RootDomain/private/var/db/CoreDuet/Knowledge/` | App usage patterns |

## ADB Commands (Android)

| Command | Description |
|---------|-------------|
| `adb devices` | List connected devices |
| `adb backup -apk -shared -all -f backup.ab` | Full device backup |
| `adb pull /data/data/<pkg>/` | Extract app data (root required) |
| `adb shell pm list packages` | List installed packages |

## libimobiledevice (iOS)

| Command | Description |
|---------|-------------|
| `idevice_id -l` | List connected iOS devices |
| `ideviceinfo -u <UDID>` | Get device information |
| `idevicebackup2 backup --full <dir>` | Create full iOS backup |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `sqlite3` | stdlib | Parse mobile app SQLite databases |
| `csv` | stdlib | Export extracted data |
| `pathlib` | stdlib | Navigate extraction directory structure |

## References

- ALEAPP: https://github.com/abrignoni/ALEAPP
- iLEAPP: https://github.com/abrignoni/iLEAPP
- libimobiledevice: https://libimobiledevice.org/
- Cellebrite UFED: https://cellebrite.com/en/ufed/
