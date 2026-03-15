---
name: performing-file-carving-with-foremost
description: Recover files from disk images and unallocated space using Foremost's header-footer signature carving to extract evidence regardless of file system state.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, file-carving, foremost, data-recovery, evidence-recovery, unallocated-space]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing File Carving with Foremost

## When to Use
- When recovering files from unallocated disk space or corrupted file systems
- For extracting evidence from formatted or wiped storage media
- When file system metadata is unavailable but raw data sectors contain evidence
- During investigations requiring recovery of specific file types from raw images
- As a complement to file system-based recovery for maximum evidence extraction

## Prerequisites
- Foremost installed on forensic workstation
- Forensic disk image in raw (dd) format
- Sufficient output storage (potentially larger than source)
- Custom foremost.conf for specialized file types (optional)
- Understanding of file signatures (magic bytes) for target file types
- Scalpel as an alternative for performance-critical carving

## Workflow

### Step 1: Install and Configure Foremost

```bash
# Install Foremost
sudo apt-get install foremost

# Verify installation
foremost -V

# Review default configuration
cat /etc/foremost.conf

# The default foremost.conf supports:
# jpg, gif, png, bmp - Image formats
# avi, exe, mpg, wav - Media and executables
# riff, wmv, mov, pdf - Documents and video
# ole (doc/xls/ppt), zip, rar - Office and archives
# htm, cpp, java - Text/code files

# Create custom configuration for additional file types
cp /etc/foremost.conf /cases/case-2024-001/custom_foremost.conf

# Add custom file signatures
cat << 'EOF' >> /cases/case-2024-001/custom_foremost.conf
# Custom additions for investigation
# Format: extension  case_sensitive  max_size  header  footer
    docx    y    10000000    \x50\x4b\x03\x04    \x50\x4b\x05\x06
    xlsx    y    10000000    \x50\x4b\x03\x04    \x50\x4b\x05\x06
    pptx    y    10000000    \x50\x4b\x03\x04    \x50\x4b\x05\x06
    sqlite  y    50000000    \x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74
    pst     y    500000000   \x21\x42\x44\x4e
    eml     y    1000000     \x46\x72\x6f\x6d\x3a    \x0d\x0a\x0d\x0a
    evtx    y    50000000    \x45\x6c\x66\x46\x69\x6c\x65
EOF
```

### Step 2: Run Foremost Against the Disk Image

```bash
# Basic carving of all supported file types
foremost -t all \
   -i /cases/case-2024-001/images/evidence.dd \
   -o /cases/case-2024-001/carved/foremost_all/

# Carve only specific file types
foremost -t jpg,png,pdf,doc,xls,zip \
   -i /cases/case-2024-001/images/evidence.dd \
   -o /cases/case-2024-001/carved/foremost_targeted/

# Use custom configuration
foremost -c /cases/case-2024-001/custom_foremost.conf \
   -i /cases/case-2024-001/images/evidence.dd \
   -o /cases/case-2024-001/carved/foremost_custom/

# Carve from a specific partition offset
# First, find partitions
mmls /cases/case-2024-001/images/evidence.dd
# Then carve from unallocated space only
# Extract unallocated space with blkls
blkls -o 2048 /cases/case-2024-001/images/evidence.dd \
   > /cases/case-2024-001/unallocated.dd

foremost -t all \
   -i /cases/case-2024-001/unallocated.dd \
   -o /cases/case-2024-001/carved/foremost_unalloc/

# Verbose mode for detailed progress
foremost -v -t all \
   -i /cases/case-2024-001/images/evidence.dd \
   -o /cases/case-2024-001/carved/foremost_verbose/ 2>&1 | \
   tee /cases/case-2024-001/carved/foremost_log.txt

# Indirect mode (process standard input)
dd if=/cases/case-2024-001/images/evidence.dd bs=512 skip=2048 | \
   foremost -t jpg,pdf -o /cases/case-2024-001/carved/foremost_pipe/
```

### Step 3: Use Scalpel for High-Performance Carving

```bash
# Install Scalpel (faster alternative based on Foremost)
sudo apt-get install scalpel

# Edit Scalpel configuration (uncomment desired file types)
cp /etc/scalpel/scalpel.conf /cases/case-2024-001/scalpel.conf
# Uncomment lines for target file types in the config

# Run Scalpel
scalpel -c /cases/case-2024-001/scalpel.conf \
   -o /cases/case-2024-001/carved/scalpel/ \
   /cases/case-2024-001/images/evidence.dd

# Scalpel with file size limits
# Edit scalpel.conf to set appropriate max sizes:
# jpg  y  5000000  \xff\xd8\xff  \xff\xd9
# pdf  y  20000000 %PDF  %%EOF
```

### Step 4: Process and Validate Carved Files

```bash
# Review Foremost audit report
cat /cases/case-2024-001/carved/foremost_all/audit.txt

# The audit.txt contains:
# - Number of files found per type
# - Start and end offsets
# - File sizes

# Validate carved files
python3 << 'PYEOF'
import os
import subprocess
from collections import defaultdict

carved_dir = '/cases/case-2024-001/carved/foremost_all/'
stats = defaultdict(lambda: {'total': 0, 'valid': 0, 'invalid': 0, 'size': 0})

for subdir in os.listdir(carved_dir):
    subdir_path = os.path.join(carved_dir, subdir)
    if not os.path.isdir(subdir_path) or subdir == 'audit.txt':
        continue

    for filename in os.listdir(subdir_path):
        filepath = os.path.join(subdir_path, filename)
        if not os.path.isfile(filepath):
            continue

        ext = subdir
        filesize = os.path.getsize(filepath)
        stats[ext]['total'] += 1
        stats[ext]['size'] += filesize

        # Validate file using 'file' command
        result = subprocess.run(['file', '--brief', filepath], capture_output=True, text=True)
        file_type = result.stdout.strip()

        if 'data' in file_type.lower() or 'empty' in file_type.lower():
            stats[ext]['invalid'] += 1
        else:
            stats[ext]['valid'] += 1

print("=== CARVED FILE VALIDATION ===\n")
print(f"{'Type':<10} {'Total':<8} {'Valid':<8} {'Invalid':<10} {'Total Size':<15}")
print("-" * 55)
for ext in sorted(stats.keys()):
    s = stats[ext]
    size_mb = s['size'] / (1024*1024)
    print(f"{ext:<10} {s['total']:<8} {s['valid']:<8} {s['invalid']:<10} {size_mb:>10.1f} MB")

# Remove zero-byte files
for subdir in os.listdir(carved_dir):
    subdir_path = os.path.join(carved_dir, subdir)
    if os.path.isdir(subdir_path):
        for filename in os.listdir(subdir_path):
            filepath = os.path.join(subdir_path, filename)
            if os.path.isfile(filepath) and os.path.getsize(filepath) == 0:
                os.remove(filepath)
PYEOF

# Hash all valid carved files
find /cases/case-2024-001/carved/foremost_all/ -type f ! -name "audit.txt" \
   -exec sha256sum {} \; > /cases/case-2024-001/carved/carved_file_hashes.txt

# Check against known-bad hash database
# Check against NSRL known-good database to filter
```

### Step 5: Examine and Catalog Evidence Files

```bash
# Extract metadata from carved images (EXIF data including GPS)
exiftool -r -csv /cases/case-2024-001/carved/foremost_all/jpg/ \
   > /cases/case-2024-001/analysis/carved_image_metadata.csv

# Search carved documents for keywords
find /cases/case-2024-001/carved/foremost_all/pdf/ -name "*.pdf" -exec pdftotext {} - \; 2>/dev/null | \
   grep -iE '(confidential|secret|password|account|ssn|credit.card)' \
   > /cases/case-2024-001/analysis/keyword_hits_pdf.txt

# Generate thumbnails for image review
mkdir -p /cases/case-2024-001/carved/thumbnails/
find /cases/case-2024-001/carved/foremost_all/jpg/ -name "*.jpg" -exec \
   convert {} -thumbnail 200x200 /cases/case-2024-001/carved/thumbnails/{} \; 2>/dev/null

# Create evidence catalog
python3 << 'PYEOF'
import os, hashlib, csv, subprocess

catalog = []
carved_dir = '/cases/case-2024-001/carved/foremost_all/'

for subdir in sorted(os.listdir(carved_dir)):
    subdir_path = os.path.join(carved_dir, subdir)
    if not os.path.isdir(subdir_path):
        continue
    for filename in sorted(os.listdir(subdir_path)):
        filepath = os.path.join(subdir_path, filename)
        if not os.path.isfile(filepath):
            continue
        size = os.path.getsize(filepath)
        sha256 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
        file_type = subprocess.run(['file', '--brief', filepath], capture_output=True, text=True).stdout.strip()

        catalog.append({
            'filename': filename,
            'type': subdir,
            'size': size,
            'sha256': sha256,
            'file_description': file_type[:100]
        })

with open('/cases/case-2024-001/analysis/carved_file_catalog.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['filename', 'type', 'size', 'sha256', 'file_description'])
    writer.writeheader()
    writer.writerows(catalog)

print(f"Catalog created with {len(catalog)} files")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| File carving | Recovering files by searching for known header/footer byte sequences in raw data |
| File signature | Unique byte pattern at the start (header) or end (footer) identifying a file type |
| Unallocated space | Disk sectors not assigned to any file; primary target for carving |
| Fragmentation | When file data is stored in non-contiguous sectors, complicating carving |
| Header-footer carving | Extracting data between known file start and end signatures |
| False positives | Carved data matching file signatures but containing corrupt or unrelated content |
| Slack space | Unused bytes at the end of a file's last allocated cluster |
| Sector alignment | Files typically start at sector boundaries, improving carving accuracy |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Foremost | Original header-footer file carving tool developed for US Air Force OSI |
| Scalpel | High-performance file carver with configurable signatures |
| PhotoRec | Signature-based file recovery supporting 300+ formats |
| bulk_extractor | Extracts features (emails, URLs, credit cards) from raw data |
| blkls | Sleuth Kit tool extracting unallocated space from disk images |
| mmls | Partition table display for identifying carving targets |
| ExifTool | Metadata extraction from carved image and document files |
| hashdeep | Recursive hash computation for carved file cataloging |

## Common Scenarios

**Scenario 1: Recovering Deleted Evidence Documents**
Run Foremost targeting doc, pdf, xlsx formats against the unallocated space extracted with blkls, validate carved documents, search content for case-relevant keywords, catalog and hash all recoverable documents, present as evidence.

**Scenario 2: Image Recovery from Formatted Media**
Carve JPEG, PNG, GIF, BMP from a formatted USB drive image, extract EXIF metadata including GPS coordinates and camera information, generate thumbnails for rapid visual review, identify evidence-relevant images, document recovery chain.

**Scenario 3: Email Recovery from Damaged PST**
Use custom foremost.conf with PST and EML signatures, carve email artifacts from damaged Outlook data file, attempt to open carved PST fragments in a viewer, extract individual EML messages, search for relevant communications.

**Scenario 4: Database Recovery for Financial Investigation**
Configure Foremost to carve SQLite databases from unallocated space, recover application databases that were deleted, query recovered databases for financial records, cross-reference with known transaction data, document findings for prosecution.

## Output Format

```
File Carving Summary:
  Tool: Foremost 1.5.7
  Source: evidence.dd (500 GB)
  Target: Unallocated space (234 GB)
  Duration: 1h 45m

  Files Carved:
    jpg:    2,345 files (1.8 GB) - Valid: 2,100 / Invalid: 245
    png:      234 files (456 MB) - Valid: 210 / Invalid: 24
    pdf:      156 files (890 MB) - Valid: 134 / Invalid: 22
    doc:       89 files (234 MB) - Valid: 67 / Invalid: 22
    xls:       45 files (123 MB) - Valid: 38 / Invalid: 7
    zip:       67 files (567 MB) - Valid: 52 / Invalid: 15
    exe:       34 files (234 MB) - Valid: 30 / Invalid: 4
    sqlite:    12 files (89 MB)  - Valid: 10 / Invalid: 2

  Total Files: 2,982 (3.4 GB recovered)
  Evidence-Relevant: 45 files flagged for review
  Audit Log: /cases/case-2024-001/carved/foremost_all/audit.txt
  File Catalog: /cases/case-2024-001/analysis/carved_file_catalog.csv
```
