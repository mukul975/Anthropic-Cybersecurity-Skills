# API Reference: Recovering Deleted Files with PhotoRec Agent

## Overview

Wraps PhotoRec via subprocess for forensic file recovery from disk images, with automated file cataloging, SHA-256 hashing for evidence integrity, and categorized sorting.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| hashlib | stdlib | SHA-256 hashing for evidence integrity |
| subprocess | stdlib | PhotoRec command execution |
| pathlib | stdlib | File extension handling |

## External Tools Required

| Tool | Purpose |
|------|---------|
| photorec | File carving and recovery from disk images |
| file | File type identification |

## Core Functions

### `run_photorec(image_path, output_dir, file_types, partition)`
Executes PhotoRec with optional file type filtering and partition selection.
- **Timeout**: 14400 seconds (4 hours)
- **Returns**: `dict` with command, returncode, output_dir

### `catalog_recovered_files(output_dir)`
Catalogs all recovered files by extension with counts and sizes.
- **Returns**: `dict` with `total_files`, `total_mb`, `by_extension`

### `hash_recovered_files(output_dir, extensions)`
Generates SHA-256 hashes for recovered files, optionally filtered by extension.
- **Returns**: `list[dict]` with file path, sha256, size

### `sort_recovered_files(output_dir, sorted_dir)`
Sorts recovered files into categories: documents, images, databases, archives, executables, email, web, other.
- **Returns**: `dict[str, int]` - category to file count

### `full_recovery_pipeline(image_path, output_dir, file_types)`
End-to-end: image info -> PhotoRec recovery -> catalog -> sort.

## File Categories

| Category | Extensions |
|----------|-----------|
| documents | .doc, .docx, .pdf, .xls, .xlsx, .ppt, .txt, .csv |
| images | .jpg, .png, .gif, .bmp, .tiff, .svg |
| databases | .db, .sqlite, .mdb, .sql |
| archives | .zip, .rar, .7z, .tar, .gz |
| executables | .exe, .dll, .bat, .ps1, .sh |
| email | .eml, .msg, .pst, .ost |

## Usage

```bash
python agent.py /cases/evidence.dd /cases/recovered/ jpg,pdf,doc
```
