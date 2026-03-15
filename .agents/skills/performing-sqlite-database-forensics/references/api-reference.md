# API Reference: SQLite Database Forensics

## SQLite File Header (First 100 Bytes)

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 16 | Magic: `SQLite format 3\000` |
| 16 | 2 | Page size (512-65536; 1 means 65536) |
| 24 | 4 | File change counter |
| 28 | 4 | Database size in pages |
| 32 | 4 | First freelist trunk page |
| 36 | 4 | Total freelist pages |
| 52 | 4 | Text encoding (1=UTF-8, 2=UTF-16le, 3=UTF-16be) |

## Page Types

| Type Byte | Description |
|-----------|-------------|
| `0x02` | Index interior (B-tree) |
| `0x05` | Table interior (B-tree) |
| `0x0A` | Index leaf (B-tree) |
| `0x0D` | Table leaf (B-tree) |

## Timestamp Decoders

| Format | Epoch | Conversion |
|--------|-------|------------|
| Unix | 1970-01-01 | `datetime.utcfromtimestamp(val)` |
| Chrome/WebKit | 1601-01-01 | `(val / 1e6) - 11644473600` seconds since Unix epoch |
| Mac Absolute | 2001-01-01 | `datetime(2001,1,1) + timedelta(seconds=val)` |
| Mozilla PRTime | 1970-01-01 | `val / 1e6` seconds since Unix epoch |

## Common Forensic Databases

| Application | File | Key Tables |
|------------|------|------------|
| Chrome | `History` | `urls`, `visits`, `downloads` |
| Firefox | `places.sqlite` | `moz_places`, `moz_historyvisits` |
| WhatsApp | `msgstore.db` | `messages`, `chat_list` |
| iMessage | `sms.db` | `message`, `handle`, `chat` |
| Android SMS | `mmssms.db` | `sms`, `threads` |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `sqlite3` | stdlib | Query database tables |
| `struct` | stdlib | Parse binary header and page structures |
| `os` / `pathlib` | stdlib | File size and path operations |

## References

- SQLite File Format: https://www.sqlite.org/fileformat2.html
- SQLite WAL Format: https://www.sqlite.org/wal.html
- Belkasoft SQLite Analysis: https://belkasoft.com/sqlite-analysis
- Sanderson Forensics SQLite: https://sqliteforensictoolkit.com/
