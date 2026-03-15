# API Reference: Timeline Reconstruction with Plaso Agent

## Overview

Wraps Plaso (log2timeline/psort) via subprocess for forensic super-timeline generation, filtering, export, and automated CSV analysis for activity spikes and source distribution.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| csv | stdlib | Timeline CSV parsing |
| subprocess | stdlib | Plaso tool execution |

## External Tools Required

| Tool | Purpose |
|------|---------|
| log2timeline.py | Forensic timeline generation from disk images |
| psort.py | Timeline filtering, sorting, and export |

## Core Functions

### `run_log2timeline(image_path, storage_file, parsers, filter_file)`
Executes log2timeline.py to parse a disk image into a Plaso storage file.
- **Parameters**: `image_path` (str), `storage_file` (str), `parsers` (str, optional), `filter_file` (str, optional)
- **Timeout**: 7200 seconds (2 hours)
- **Returns**: `dict` with command, returncode, stdout, stderr

### `run_psort_export(storage_file, output_file, output_format, date_filter)`
Exports timeline from Plaso storage to CSV, JSONL, or dynamic format.
- **Formats**: `l2tcsv`, `json_line`, `dynamic`
- **Returns**: `dict` with command, returncode, output_file

### `create_filter_file(filter_path, paths)`
Generates a Plaso filter file targeting key forensic artifacts.
- **Default paths**: winevt, Prefetch, NTUSER.DAT, Chrome, Firefox, MFT, USN Journal, registry

### `analyze_timeline_csv(csv_path, max_rows)`
Statistical analysis of exported timeline: source distribution and hourly activity spikes (>3x average).
- **Returns**: `dict` with `total_events`, `source_counts`, `spike_hours`, `avg_events_per_hour`

### `generate_incident_window(storage_file, output_dir, start_date, end_date)`
Exports events within a specific date range for focused analysis.

### `full_pipeline(image_path, output_dir, parsers, start_date, end_date)`
End-to-end pipeline: log2timeline -> psort export -> CSV analysis -> incident window -> JSONL export.

## Default Parsers

```
winevtx, prefetch, mft, usnjrnl, lnk, recycle_bin,
chrome_history, firefox_history, winreg
```

## Usage

```bash
python agent.py /cases/evidence.dd /cases/timeline/ "2024-01-15 00:00:00" "2024-01-20 23:59:59"
```

## Output Files

| File | Format | Purpose |
|------|--------|---------|
| evidence.plaso | SQLite | Plaso intermediate storage |
| full_timeline.csv | L2T CSV | Complete super-timeline |
| incident_window.csv | L2T CSV | Filtered incident period |
| timeline.jsonl | JSON Lines | SIEM/Timesketch import |
