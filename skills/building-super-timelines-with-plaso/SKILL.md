---
name: building-super-timelines-with-plaso
description: Generate forensic super-timelines with Plaso's log2timeline.py, pinfo.py, psort.py, and psteal.py CLI tools (fusing file-system MACB, registry, EVTX, browser history, prefetch, LNK, and more), then triage and filter the results in Timesketch. Use when reconstructing the full sequence of events on a compromised or forensically imaged host during a DFIR investigation. Do not use for general timeline reconstruction methodology with Plaso - use performing-timeline-reconstruction-with-plaso.
domain: cybersecurity
subdomain: digital-forensics
tags:
- digital-forensics
- plaso
- log2timeline
- super-timeline
- timesketch
- dfir
- timeline-analysis
- incident-response
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-03
mitre_attack:
- T1070
---
# Building Super Timelines with Plaso

> **Authorized Use Only:** Build timelines only from evidence you are authorized to analyze. Work from forensic images/copies and preserve chain of custody.

## Overview

Plaso (Plaso Langar Að Safna Öllu) is the open-source engine behind **log2timeline**, the standard for building forensic *super timelines* — a single chronological, normalized view fusing hundreds of artifact types (file-system MACB times, registry, EVTX, browser history, prefetch, LNK, $UsnJrnl, syslog, and more) into one timeline. Plaso has three core CLI tools:

- **log2timeline.py** — extracts events from a source (disk image, mount point, directory, or device) into a `.plaso` storage file using its large parser/plugin set.
- **pinfo.py** — reports on the contents and processing metadata of a `.plaso` file.
- **psort.py** — post-processes, filters, deduplicates, time-zones, and exports the storage file to an output format (CSV, JSON-line, Elasticsearch, Timesketch, etc.).
- **psteal.py** — convenience wrapper that runs extraction + export in one step.

The resulting timeline is enormous, so analysts triage it in **Timesketch** — a collaborative, web-based timeline analysis platform that ingests `.plaso` files (or CSV/JSONL) and supports filtering, tagging, starring, saved searches, and automated analyzers.

## When to Use

- Reconstructing the full sequence of events on a compromised host during incident response.
- Correlating activity across many artifact sources on a single normalized timeline.
- Investigating anti-forensic behavior such as timestomping or log clearing (which stands out against MACB and journal evidence).
- Feeding a curated timeline into Timesketch for team triage.

## Prerequisites

- Install Plaso (Docker is the supported, reproducible method):
  ```bash
  docker pull log2timeline/plaso
  # Run a tool, mounting your evidence/output directory
  docker run -v /cases:/data log2timeline/plaso log2timeline.py --version
  ```
  Alternatively on Ubuntu via the GIFT PPA:
  ```bash
  sudo add-apt-repository ppa:gift/stable
  sudo apt-get update && sudo apt-get install -y plaso-tools
  ```
- A Timesketch instance (docker-compose deployment from https://github.com/google/timesketch) for triage.
- A forensic image (E01/raw) or mounted file system.

## Objectives

- Extract events from an image into a `.plaso` storage file.
- Inspect the storage file with pinfo.
- Filter and export a focused super timeline with psort.
- Import the timeline into Timesketch and triage it.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1070 | Indicator Removal | Super timelines reveal indicator-removal behavior (log clearing, file deletion, timestomping) by exposing inconsistencies between MACB timestamps, the USN journal, and event logs. |

Plaso is a defensive forensics engine; the mapping reflects the anti-forensic adversary behavior super timelines are well suited to detect.

## Workflow

### 1. Extract events into a storage file
`log2timeline.py` writes a `.plaso` file from a source. `--storage-file` names the output; the source can be an `.E01`, raw image, mount point, or directory.
```bash
log2timeline.py --storage-file timeline.plaso /cases/greendale/image.E01
```
Scope parsers for speed/relevance with `--parsers` (presets like `win7`, `webhist`, or explicit parser names):
```bash
log2timeline.py --parsers "win7,!filestat" --storage-file timeline.plaso /cases/image.E01
```

### 2. Inspect the storage file
`pinfo.py` reports source, parsers used, event counts, and any warnings.
```bash
pinfo.py timeline.plaso
```

### 3. Export a filtered super timeline (CSV)
`psort.py` selects an output module with `-o`, writes with `-w`, normalizes the timezone with `--output-time-zone`, and accepts an event filter expression to scope a date range.
```bash
psort.py --output-time-zone 'UTC' \
  -o l2tcsv \
  -w supertimeline.csv \
  timeline.plaso \
  "date > datetime('2026-01-01T00:00:00') AND date < datetime('2026-01-27T00:00:00')"
```
For Timesketch-friendly JSON lines, use the `json_line` output module:
```bash
psort.py --output-time-zone 'UTC' -o json_line -w supertimeline.jsonl timeline.plaso
```

### 4. One-step extraction + export with psteal
`psteal.py` runs extraction and CSV export together for quick triage.
```bash
psteal.py --source /cases/greendale/image.E01 -o l2tcsv -w supertimeline.csv
```

### 5. Import into Timesketch
Use the official `timesketch_importer` CLI to upload the `.plaso` (or CSV/JSONL) into a sketch. Timesketch chunks/reassembles and indexes the file.
```bash
timesketch_importer \
  --host http://127.0.0.1:5000 \
  --username admin \
  --timeline_name "greendale-host01" \
  --sketch_id 1 \
  timeline.plaso
```

### 6. Triage in Timesketch
In the sketch UI:
- Filter to a suspicious window or `data_type` (e.g. `windows:evtx:record`, `fs:stat`).
- Star/tag events of interest and add comments for collaboration.
- Save searches and run analyzers (e.g. browser timeframe, similarity, sigma) over the timeline.
- Build a narrative from corroborating events across artifact sources.

### 7. Hunt for anti-forensics
Look for MACB timestamps that disagree with $UsnJrnl entries (timestomping), gaps or `EventLog cleared` (1102) records, and deleted-then-recreated files — all visible on the unified timeline.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Plaso (log2timeline) | Timeline engine + tools | https://github.com/log2timeline/plaso |
| Plaso documentation | Tool usage and parsers | https://plaso.readthedocs.io/ |
| Timesketch | Timeline analysis platform | https://github.com/google/timesketch |
| Timesketch docs | Deployment, importer, analyzers | https://timesketch.org/ |
| Plaso Docker image | Reproducible runtime | https://hub.docker.com/r/log2timeline/plaso |

## Key Commands

| Command | Purpose |
|---------|---------|
| `log2timeline.py --storage-file out.plaso <source>` | Extract events |
| `log2timeline.py --parsers <preset> ...` | Scope parsers |
| `pinfo.py out.plaso` | Inspect storage file |
| `psort.py -o l2tcsv -w out.csv out.plaso "<filter>"` | Filter + export CSV |
| `psort.py -o json_line -w out.jsonl out.plaso` | Export JSONL |
| `psteal.py --source <img> -o l2tcsv -w out.csv` | Extract + export in one step |
| `timesketch_importer --host ... <file>` | Import into Timesketch |

## Validation Criteria

- [ ] `.plaso` storage file produced from the source image
- [ ] pinfo confirms expected parsers ran and event counts are non-zero
- [ ] Super timeline exported with UTC normalization and a scoped filter
- [ ] Timeline imported into a Timesketch sketch and indexed
- [ ] Suspicious window triaged with tags/stars/saved searches
- [ ] Anti-forensic indicators (timestomping, log clearing) checked
- [ ] Findings documented with corroborating cross-source events
