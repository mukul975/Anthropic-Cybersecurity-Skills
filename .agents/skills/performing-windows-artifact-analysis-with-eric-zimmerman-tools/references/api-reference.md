# API Reference: Windows Artifact Analysis with Eric Zimmerman Tools

## EZ Tools Suite

| Tool | Artifact | Description |
|------|----------|-------------|
| `MFTECmd.exe` | $MFT | Parse Master File Table |
| `PECmd.exe` | Prefetch | Parse prefetch files for execution history |
| `LECmd.exe` | LNK | Parse shortcut files |
| `JLECmd.exe` | Jump Lists | Parse automatic/custom jump lists |
| `SBECmd.exe` | ShellBags | Parse folder access history from registry |
| `AmcacheParser.exe` | Amcache | Parse application execution evidence |
| `AppCompatCacheParser.exe` | Shimcache | Parse application compatibility cache |
| `EvtxECmd.exe` | EVTX | Parse Windows event logs |
| `RECmd.exe` | Registry | Parse registry hives |

## Common CLI Flags

| Flag | Description |
|------|-------------|
| `-f <file>` | Input file path |
| `-d <directory>` | Input directory |
| `--csv <dir>` | Output directory for CSV |
| `--csvf <file>` | CSV output filename |
| `--json <dir>` | Output directory for JSON |
| `--body <dir>` | Output bodyfile for timeline |

## Key Artifacts and Locations

| Artifact | Path | Evidence |
|----------|------|----------|
| $MFT | `C:\$MFT` | File creation/modification/access |
| Prefetch | `C:\Windows\Prefetch\` | Program execution with timestamps |
| LNK Files | `%APPDATA%\Microsoft\Windows\Recent\` | Recently accessed files |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Per-app recent files |
| ShellBags | NTUSER.DAT, UsrClass.dat | Folder browsing history |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Application execution |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute EZ tools |
| `csv` | stdlib | Parse CSV output |
| `json` | stdlib | Report generation |

## References

- Eric Zimmerman Tools: https://ericzimmerman.github.io/
- SANS Windows Forensic Analysis Poster: https://www.sans.org/posters/windows-forensic-analysis/
- EZ Tools GitHub: https://github.com/EricZimmerman
