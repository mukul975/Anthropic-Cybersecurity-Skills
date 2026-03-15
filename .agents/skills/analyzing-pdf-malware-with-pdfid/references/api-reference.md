# API Reference: PDF Malware Analysis Tools

## PDFiD - PDF Keyword Scanner

### Syntax
```bash
pdfid.py document.pdf
pdfid.py -n document.pdf     # Show all keywords (including zero counts)
pdfid.py -e document.pdf     # Extra data (entropy)
pdfid.py -f document.pdf     # Force scan (ignore header)
```

### Suspicious Keywords
| Keyword | Risk | Description |
|---------|------|-------------|
| `/JS` | HIGH | JavaScript code |
| `/JavaScript` | HIGH | JavaScript action |
| `/AA` | HIGH | Additional Actions (auto-execute) |
| `/OpenAction` | HIGH | Action on document open |
| `/Launch` | HIGH | Launch external application |
| `/EmbeddedFile` | MEDIUM | Embedded file object |
| `/AcroForm` | MEDIUM | Interactive form |
| `/JBIG2Decode` | HIGH | JBIG2 exploit vector (CVE-2009-0658) |
| `/RichMedia` | MEDIUM | Flash/multimedia content |
| `/XFA` | MEDIUM | XML Forms (script capable) |
| `/ObjStm` | LOW | Object streams (can hide objects) |

### Output Format
```
PDF Header: %PDF-1.7
 obj                   45
 endobj                45
 stream                12
 /JS                    2
 /JavaScript            1
 /OpenAction            1
 /EmbeddedFile          0
```

## pdf-parser.py - PDF Object Parser

### Syntax
```bash
pdf-parser.py document.pdf                      # List all objects
pdf-parser.py -o 5 document.pdf                 # Show object 5
pdf-parser.py -s "/JS" document.pdf             # Search for keyword
pdf-parser.py -f document.pdf                   # Filter streams
pdf-parser.py -c document.pdf                   # Show raw content
pdf-parser.py -d 5 document.pdf                 # Dump stream of object 5
pdf-parser.py --object 5 --filter document.pdf  # Decompress stream
```

## peepdf - Interactive PDF Analysis

### Syntax
```bash
peepdf -i document.pdf              # Interactive mode
peepdf -f document.pdf              # Force analysis
peepdf -l document.pdf              # Loose mode
```

### Interactive Commands
```
info                    # Document summary
tree                    # Object tree
object 5                # Show object
stream 5                # Show stream content
js_analyse              # Analyze all JavaScript
extract js > output.js  # Extract JavaScript
```

## Known PDF Exploit CVEs

| CVE | Component | Description |
|-----|-----------|-------------|
| CVE-2009-0658 | JBIG2Decode | Buffer overflow in JBIG2 decoder |
| CVE-2009-0927 | Collab.getIcon | JavaScript method exploit |
| CVE-2008-2992 | util.printf | Format string vulnerability |
| CVE-2010-0188 | LibTIFF | TIFF image processing overflow |
| CVE-2013-0640 | XFA | XML Forms Architecture exploit |
| CVE-2018-4990 | EmbeddedFile | Double-free in embedded files |

## YARA Rules for PDF Malware

### Example Rule
```yara
rule PDF_Suspicious {
    meta:
        description = "PDF with JavaScript and auto-execution"
    strings:
        $pdf = "%PDF-"
        $js = "/JS" nocase
        $openaction = "/OpenAction"
        $launch = "/Launch"
    condition:
        $pdf at 0 and ($js and $openaction) or $launch
}
```

## Python PDF Libraries

### PyPDF2
```python
from PyPDF2 import PdfReader
reader = PdfReader("document.pdf")
print(len(reader.pages))
for page in reader.pages:
    print(page.extract_text())
```

### pikepdf
```python
import pikepdf
pdf = pikepdf.open("document.pdf")
for obj_num in pdf.objects:
    obj = pdf.get_object(obj_num)
    if "/JS" in str(obj):
        print(f"JavaScript in object {obj_num}")
```
