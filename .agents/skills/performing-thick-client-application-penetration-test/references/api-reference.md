# API Reference: Thick Client Penetration Testing

## Analysis Tools

| Tool | Purpose | Target |
|------|---------|--------|
| dnSpy | .NET decompilation and debugging | .NET Framework/Core apps |
| ILSpy | .NET decompilation (read-only) | .NET assemblies |
| JD-GUI / JADX | Java decompilation | JAR/APK files |
| Ghidra / IDA Pro | Native binary reverse engineering | C/C++ executables |
| Procmon | File/registry/network activity monitoring | Any Windows app |
| Process Hacker | Process inspection, memory, DLLs | Running processes |
| Burp Suite | HTTP/HTTPS traffic interception | Client-server communication |
| Echo Mirage | TCP/UDP traffic interception | Non-HTTP protocols |
| Frida | Dynamic instrumentation | Any platform |

## Static Analysis Targets

| Target | Search Pattern | Risk |
|--------|---------------|------|
| Hardcoded credentials | `password`, `secret`, `apikey` in strings | Critical |
| Connection strings | `jdbc:`, `Server=`, `mongodb://` | Critical |
| SQL queries | `SELECT`, `INSERT`, `UPDATE` | Medium |
| URLs and endpoints | `http://`, `https://` | Info |
| Disabled SSL validation | `ServerCertificateValidationCallback` | High |

## DLL Hijacking Detection

| Step | Tool | Action |
|------|------|--------|
| 1 | Procmon | Filter: `Result = NAME NOT FOUND`, `Path ends with .dll` |
| 2 | Check | Verify if DLL search path includes writable directories |
| 3 | Validate | Test with benign DLL in writable directory |

## Local Storage Locations

| Location | Type | Risk |
|----------|------|------|
| `%APPDATA%\<app>` | Config, SQLite | Credential storage |
| `%LOCALAPPDATA%\<app>` | Cache, logs | Data leakage |
| `HKCU\Software\<app>` | Registry settings | Stored credentials |
| App install directory | Config files | Hardcoded secrets |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `sqlite3` | stdlib | Audit local SQLite databases |
| `re` | stdlib | Pattern matching for credentials/URLs |
| `subprocess` | stdlib | Execute system analysis tools |
| `pathlib` | stdlib | File system traversal |

## References

- OWASP Thick Client Top 10: https://owasp.org/www-project-thick-client-top-10/
- dnSpy: https://github.com/dnSpy/dnSpy
- Procmon: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- Frida: https://frida.re/docs/home/
