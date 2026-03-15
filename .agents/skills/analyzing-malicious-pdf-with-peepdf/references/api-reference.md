# Malicious PDF Analysis Reference

## peepdf Installation

```bash
# Python 3 version
pip install peepdf-3

# From source
git clone https://github.com/jesparza/peepdf.git
cd peepdf && pip install -r requirements.txt
```

## peepdf CLI Usage

```bash
# Basic analysis (loose mode, force parsing)
peepdf -f -l malicious.pdf

# Interactive mode
peepdf -i malicious.pdf

# Batch script execution
peepdf -s commands.txt malicious.pdf

# JSON output
peepdf -j malicious.pdf
```

## peepdf Interactive Commands

| Command | Description |
|---------|-------------|
| `info` | Display document summary and suspicious elements |
| `tree` | Show object tree structure |
| `object <id>` | Display raw content of object |
| `stream <id>` | Decode and display stream content |
| `rawstream <id>` | Display raw (encoded) stream |
| `js_analyse <id>` | Analyze JavaScript in object |
| `js_eval <id>` | Evaluate JavaScript (requires PyV8) |
| `vtcheck` | Check file hash on VirusTotal |
| `extract uri` | Extract all URIs from document |
| `search <string>` | Search for string across objects |
| `offsets <id>` | Show byte offsets of object in file |
| `metadata` | Display document metadata |

## pdfid.py Usage

```bash
# Basic scan
pdfid.py malicious.pdf

# Additional disarm indicators
pdfid.py -e malicious.pdf

# Scan directory
pdfid.py -r /samples/
```

### pdfid Suspicious Keywords

| Keyword | Risk | Significance |
|---------|------|-------------|
| /JS | High | JavaScript object reference |
| /JavaScript | High | JavaScript action |
| /OpenAction | High | Automatic execution on open |
| /AA | High | Additional actions trigger |
| /Launch | Critical | Launch external application |
| /EmbeddedFile | High | Embedded file (dropper) |
| /XFA | High | XML Forms Architecture (exploit surface) |
| /JBIG2Decode | Medium | Image decoder (CVE-2009-0658) |
| /AcroForm | Medium | Interactive form (potential exploit) |
| /ObjStm | Low | Object stream (can hide objects) |
| /URI | Low | External URL reference |

## pdf-parser.py Usage

```bash
# Document statistics
pdf-parser.py --stats malicious.pdf

# Extract specific object
pdf-parser.py -o 10 malicious.pdf

# Extract and decode filters
pdf-parser.py -o 10 -f malicious.pdf

# Dump decoded stream to file
pdf-parser.py -o 10 -f -d extracted.bin malicious.pdf

# Search for keyword
pdf-parser.py --search "/JavaScript" malicious.pdf

# Search by type
pdf-parser.py --type "/Action" malicious.pdf
```

## Common CVEs in PDF Exploits

| CVE | Component | Description |
|-----|-----------|-------------|
| CVE-2009-0658 | JBIG2 | Buffer overflow in JBIG2 decoder |
| CVE-2009-4324 | Doc.media | Use-after-free via newplayer |
| CVE-2010-0188 | LibTIFF | TIFF image handling overflow |
| CVE-2013-0640 | XFA | Memory corruption in XFA |
| CVE-2017-11882 | Equation Editor | Stack buffer overflow |

## Shellcode Detection Patterns

| Pattern | Indicator |
|---------|-----------|
| `%u9090%u9090` | NOP sled (Unicode) |
| `\x90\x90\x90` | NOP sled (hex) |
| `unescape()` | Shellcode decoding |
| `String.fromCharCode` | Character code assembly |
| `eval()` | Dynamic code execution |
| `new ActiveXObject` | COM object instantiation |
| `spray` variable name | Heap spray technique |

## VirusTotal Check via peepdf

```
PPDF> vtcheck
MD5: abc123...
Detections: 45/72
```
