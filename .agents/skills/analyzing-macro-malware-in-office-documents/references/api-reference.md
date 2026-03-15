# API Reference: Office Macro Malware Analysis Tools

## olevba - VBA Macro Extraction (oletools)

### CLI Syntax
```bash
olevba document.docm                   # Full analysis
olevba --decode --deobf document.docm  # Decode + deobfuscate
olevba --code document.docm            # Extract VBA source only
olevba --json document.docm            # JSON output
olevba --reveal document.docm          # Reveal hidden content
```

### Output Sections
| Section | Content |
|---------|---------|
| `AutoExec` | Auto-execution triggers (AutoOpen, Document_Open) |
| `Suspicious` | Dangerous functions (Shell, WScript, CreateObject) |
| `IOC` | Extracted indicators (URLs, IPs, file paths) |
| `Hex String` | Decoded hex-encoded strings |

### Python API
```python
from oletools.olevba import VBA_Parser
vba = VBA_Parser("document.docm")
if vba.detect_vba_macros():
    for (fn, stream, vba_fn, code) in vba.extract_macros():
        print(code)
    for (kw_type, keyword, desc) in vba.analyze_macros():
        print(f"{kw_type}: {keyword}")
vba.close()
```

## oleid - Document Capability Identification

### CLI Syntax
```bash
oleid document.docm
```

### Indicators
| Indicator | Risk Values |
|-----------|-------------|
| `VBA Macros` | True/False |
| `XLM Macros` | True/False |
| `External Relationships` | True/False |
| `ObjectPool` | True/False |
| `Flash` | True/False |

## oledump.py - OLE Stream Analysis

### CLI Syntax
```bash
oledump.py document.docm                    # List streams
oledump.py -s 8 -v document.docm           # Extract stream 8
oledump.py -p plugin_vba_dco document.docm  # VBA decompile
oledump.py -p plugin_msg.py document.msg    # MSG file parsing
```

### Stream Markers
| Marker | Meaning |
|--------|---------|
| `M` | Contains VBA macros |
| `m` | Contains macro attributes |
| `O` | Contains OLE objects |

## XLMDeobfuscator - Excel 4.0 Macros

### CLI Syntax
```bash
xlmdeobfuscator -f document.xlsm
xlmdeobfuscator -f document.xlsm --output-format json
```

### Dangerous XLM Functions
| Function | Purpose |
|----------|---------|
| `EXEC()` | Execute shell command |
| `CALL()` | Call DLL function |
| `REGISTER()` | Register DLL function |
| `URLDownloadToFileA` | Download file from URL |

## VBA Auto-Execution Triggers

| Trigger | Application |
|---------|-------------|
| `Auto_Open` / `AutoOpen` | Word |
| `Document_Open` | Word |
| `Workbook_Open` | Excel |
| `Auto_Close` | Word |
| `AutoExec` | Word |

## VBA Suspicious Functions

| Function | Risk |
|----------|------|
| `Shell()` | Command execution |
| `WScript.Shell` | Windows scripting |
| `CreateObject()` | COM object instantiation |
| `URLDownloadToFile` | File download |
| `MSXML2.XMLHTTP` | HTTP requests |
| `ADODB.Stream` | Binary file writing |
| `CallByName` | Indirect method invocation |
| `Environ()` | Environment variable access |

## ViperMonkey - VBA Emulation

### Syntax
```bash
vmonkey document.docm
vmonkey --iocs document.docm   # Extract IOCs only
```
