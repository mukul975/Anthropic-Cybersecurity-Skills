# API Reference: Steganography Detection Agent

## Overview

Detects hidden data in images and media using LSB analysis with Pillow/numpy, trailing data detection, and subprocess wrappers for binwalk, zsteg, and steghide.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Pillow | >= 9.0 | Image loading and pixel manipulation |
| numpy | >= 1.23 | Array-based LSB bit extraction and statistics |

## External Tools (Optional)

| Tool | Purpose |
|------|---------|
| binwalk | Embedded file and data detection |
| zsteg | PNG/BMP LSB steganography detection |
| steghide | JPEG/BMP/WAV/AU data extraction with passwords |

## Core Functions

### `check_trailing_data(filepath)`
Detects data appended after JPEG (FF D9) or PNG (IEND) end markers, and embedded ZIP/RAR archives.
- **Returns**: `dict` with `trailing_bytes`, `embedded_zip`, `embedded_rar`

### `lsb_analysis(filepath)`
Analyzes LSB bit distribution across RGB channels. Flags `NEAR_RANDOM` (possible stego) or `SIGNIFICANT_DEVIATION`.
- **Returns**: `dict[str, dict]` - per-channel zeros, ones, ratio, anomaly

### `extract_lsb_data(filepath, output_path)`
Extracts red channel LSB data and checks for known file signatures (ZIP, PNG, JPEG, PDF, GIF).
- **Returns**: `dict` with `output`, `header_hex`, `detected_format`

### `run_binwalk(filepath)`
Subprocess wrapper for binwalk embedded file detection.
- **Returns**: `dict` with `tool` and `output`

### `run_zsteg(filepath)`
Subprocess wrapper for zsteg PNG/BMP LSB analysis.
- **Returns**: `dict` with `tool` and `output`

### `run_steghide_extract(filepath, passwords=None)`
Attempts steghide extraction with a password list.
- **Default passwords**: empty, password, secret, hidden, stego, test, 123456
- **Returns**: `list[dict]` - successful extractions with password and output path

### `analyze_file(filepath, output_dir=None)`
Full analysis pipeline combining all detection methods.
- **Returns**: `dict` - complete report with findings list

## Finding Types

| Type | Description |
|------|-------------|
| `trailing_data` | Data after image end marker |
| `embedded_archive` | ZIP/RAR found within file |
| `lsb_hidden_file` | Known file format in LSB data |
| `steghide_extraction` | Successfully extracted hidden data |

## Usage

```bash
python agent.py suspect_image.png
```
