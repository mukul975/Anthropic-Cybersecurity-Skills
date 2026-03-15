# Standards - LNK File and Jump List Forensics

## Standards
- MS-SHLLINK: Shell Link Binary File Format (Microsoft Open Specifications)
- NIST SP 800-86: Guide to Integrating Forensic Techniques
- SWGDE Best Practices for Computer Forensics

## Tools
- LECmd (Eric Zimmerman): LNK file parser
- JLECmd (Eric Zimmerman): Jump List parser
- LnkParse3 (Python): Cross-platform LNK parser
- Magnet AXIOM: Commercial forensic tool with LNK/Jump List support

## Key Artifact Locations
- Recent files: %APPDATA%\Microsoft\Windows\Recent\
- AutomaticDestinations: %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
- CustomDestinations: %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\
- Office Recent: %APPDATA%\Microsoft\Office\Recent\

## MITRE ATT&CK Mappings
- T1547.009 - Shortcut Modification
- T1204.002 - User Execution: Malicious File
