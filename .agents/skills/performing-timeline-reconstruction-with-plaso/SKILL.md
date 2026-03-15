---
name: performing-timeline-reconstruction-with-plaso
description: Build comprehensive forensic super-timelines using Plaso (log2timeline) to correlate events across file systems, logs, and artifacts into a unified chronological view.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, timeline-analysis, plaso, log2timeline, super-timeline, event-correlation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Timeline Reconstruction with Plaso

## When to Use
- When building a comprehensive forensic timeline from multiple evidence sources
- For correlating events across file system metadata, event logs, browser history, and registry
- During complex investigations requiring chronological reconstruction of activities
- When standard log analysis is insufficient to establish the sequence of events
- For presenting investigation findings in a visual, chronological format

## Prerequisites
- Plaso (log2timeline/psort) installed on forensic workstation
- Forensic disk image(s) in raw (dd), E01, or VMDK format
- Sufficient storage for Plaso output (can be 10x+ the image size)
- Minimum 8GB RAM (16GB+ recommended for large images)
- Timeline Explorer (Eric Zimmerman) or Timesketch for visualization
- Understanding of timestamp types (MACB: Modified, Accessed, Changed, Born)

## Workflow

### Step 1: Install Plaso and Prepare the Environment

```bash
# Install Plaso on Ubuntu/Debian
sudo add-apt-repository ppa:gift/stable
sudo apt-get update
sudo apt-get install plaso-tools

# Or install via pip
pip install plaso

# Or use Docker (recommended for dependency isolation)
docker pull log2timeline/plaso

# Verify installation
log2timeline.py --version
psort.py --version

# Create output directory
mkdir -p /cases/case-2024-001/timeline/

# Verify the forensic image
img_stat /cases/case-2024-001/images/evidence.dd
```

### Step 2: Generate the Plaso Storage File with log2timeline

```bash
# Basic processing of a disk image (all parsers)
log2timeline.py \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

# Process with specific parsers for faster targeted analysis
log2timeline.py \
   --parsers "winevtx,prefetch,mft,usnjrnl,lnk,recycle_bin,chrome_history,firefox_history,winreg" \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

# Process with a filter file to focus on specific paths
cat << 'EOF' > /cases/case-2024-001/timeline/filter.txt
/Windows/System32/winevt/Logs
/Windows/Prefetch
/Users/*/NTUSER.DAT
/Users/*/AppData/Local/Google/Chrome
/Users/*/AppData/Roaming/Mozilla/Firefox
/$MFT
/$UsnJrnl:$J
/Windows/System32/config
EOF

log2timeline.py \
   --filter-file /cases/case-2024-001/timeline/filter.txt \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

# Using Docker
docker run --rm -v /cases:/cases log2timeline/plaso log2timeline \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

# Process multiple evidence sources into one timeline
log2timeline.py \
   --storage-file /cases/case-2024-001/timeline/combined.plaso \
   /cases/case-2024-001/images/workstation.dd

log2timeline.py \
   --storage-file /cases/case-2024-001/timeline/combined.plaso \
   /cases/case-2024-001/images/server.dd
```

### Step 3: Filter and Export Timeline with psort

```bash
# Export full timeline to CSV (super-timeline format)
psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/full_timeline.csv \
   /cases/case-2024-001/timeline/evidence.plaso

# Export with date range filter (focus on incident window)
psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/incident_window.csv \
   /cases/case-2024-001/timeline/evidence.plaso \
   "date > '2024-01-15 00:00:00' AND date < '2024-01-20 23:59:59'"

# Export in JSON Lines format (for ingestion into SIEM/Timesketch)
psort.py \
   -o json_line \
   -w /cases/case-2024-001/timeline/timeline.jsonl \
   /cases/case-2024-001/timeline/evidence.plaso

# Export with specific source type filters
psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/registry_events.csv \
   /cases/case-2024-001/timeline/evidence.plaso \
   "source_short == 'REG'"

psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/evtx_events.csv \
   /cases/case-2024-001/timeline/evidence.plaso \
   "source_short == 'EVT'"

# Export for Timeline Explorer (dynamic CSV)
psort.py \
   -o dynamic \
   -w /cases/case-2024-001/timeline/timeline_explorer.csv \
   /cases/case-2024-001/timeline/evidence.plaso
```

### Step 4: Analyze Timeline with Timesketch

```bash
# Install Timesketch (Docker deployment)
git clone https://github.com/google/timesketch.git
cd timesketch
docker compose up -d

# Import Plaso file into Timesketch via CLI
timesketch_importer \
   --host http://localhost:5000 \
   --username analyst \
   --password password \
   --sketch_id 1 \
   --timeline_name "Case 2024-001 Workstation" \
   /cases/case-2024-001/timeline/evidence.plaso

# Alternatively, import JSONL
timesketch_importer \
   --host http://localhost:5000 \
   --username analyst \
   --sketch_id 1 \
   --timeline_name "Case 2024-001" \
   /cases/case-2024-001/timeline/timeline.jsonl

# In Timesketch web UI:
# 1. Search for events: "data_type:windows:evtx:record AND event_identifier:4624"
# 2. Apply Sigma analyzers for automated detection
# 3. Star/tag important events
# 4. Create stories documenting the investigation narrative
# 5. Share with team members
```

### Step 5: Perform Targeted Timeline Analysis

```bash
# Analyze specific time periods around known events
python3 << 'PYEOF'
import csv
from collections import defaultdict
from datetime import datetime

# Load incident window timeline
events_by_hour = defaultdict(list)
source_counts = defaultdict(int)

with open('/cases/case-2024-001/timeline/incident_window.csv', 'r', errors='ignore') as f:
    reader = csv.DictReader(f)
    total = 0
    for row in reader:
        total += 1
        timestamp = row.get('datetime', row.get('date', ''))
        source = row.get('source_short', row.get('source', 'Unknown'))
        description = row.get('message', row.get('desc', ''))

        source_counts[source] += 1

        # Group by hour for activity patterns
        try:
            dt = datetime.strptime(timestamp[:19], '%Y-%m-%dT%H:%M:%S')
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            events_by_hour[hour_key].append({
                'time': timestamp,
                'source': source,
                'description': description[:200]
            })
        except (ValueError, TypeError):
            pass

print(f"Total events in incident window: {total}\n")

print("=== EVENTS BY SOURCE TYPE ===")
for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {source}: {count}")

print("\n=== ACTIVITY BY HOUR ===")
for hour in sorted(events_by_hour.keys()):
    count = len(events_by_hour[hour])
    bar = '#' * min(count // 10, 50)
    print(f"  {hour}: {count:>6} events {bar}")

# Find hours with unusual activity spikes
avg = total / max(len(events_by_hour), 1)
print(f"\n=== ANOMALOUS HOURS (>{avg*3:.0f} events) ===")
for hour in sorted(events_by_hour.keys()):
    if len(events_by_hour[hour]) > avg * 3:
        print(f"  {hour}: {len(events_by_hour[hour])} events (SPIKE)")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Super-timeline | Unified chronological view combining all artifact timestamps from multiple sources |
| MACB timestamps | Modified, Accessed, Changed (metadata), Born (created) - four key file timestamp types |
| Plaso storage file | SQLite-based intermediate format storing parsed events before export |
| L2T CSV | Log2timeline CSV format with standardized columns for timeline events |
| Parser | Plaso module extracting timestamps from a specific artifact type (e.g., winevtx, prefetch) |
| Psort | Plaso sorting and filtering tool for post-processing storage files |
| Timesketch | Google open-source collaborative timeline analysis platform |
| Pivot points | Known timestamps (e.g., malware execution) used to focus investigation scope |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| log2timeline (Plaso) | Primary timeline generation engine parsing 100+ artifact types |
| psort | Plaso output filtering, sorting, and export utility |
| Timesketch | Web-based collaborative forensic timeline analysis platform |
| Timeline Explorer | Eric Zimmerman's Windows GUI for CSV timeline analysis |
| KAPE | Automated triage collection feeding into Plaso processing |
| mactime (TSK) | Simpler timeline generation from Sleuth Kit bodyfiles |
| Excel/Sheets | Manual timeline review for small filtered datasets |
| Elastic/Kibana | Alternative visualization platform for JSONL timeline data |

## Common Scenarios

**Scenario 1: Ransomware Attack Reconstruction**
Process the full disk image with Plaso, filter to the week before encryption was discovered, identify the initial access vector from browser history and event logs, trace privilege escalation through registry and Prefetch, map lateral movement from network logon events, pinpoint encryption start from MFT timestamps showing mass file modifications.

**Scenario 2: Data Theft Investigation**
Create super-timeline from suspect's workstation, filter for USB device connection events, file access timestamps, and cloud storage browser activity, build a narrative showing data staging, compression, and exfiltration, present timeline to legal team with tagged evidence points.

**Scenario 3: Multi-System Breach Analysis**
Process disk images from all affected systems into a single Plaso storage file, import into Timesketch for collaborative analysis, search for lateral movement patterns across system timelines, identify the patient-zero system and initial compromise vector, map the full attack chain across the environment.

**Scenario 4: Insider Threat After-Hours Activity**
Filter timeline to non-business hours only, identify file access patterns outside normal working times, correlate with authentication events (badge access, VPN logon), search for data access to sensitive directories during these periods, build evidence package for HR/legal.

## Output Format

```
Timeline Reconstruction Summary:
  Evidence Sources:
    Disk Image: evidence.dd (500 GB, NTFS)
    Plaso Storage: evidence.plaso (2.3 GB)

  Processing Statistics:
    Total events extracted: 4,567,890
    Parsers used: 45 (winevtx, prefetch, mft, usnjrnl, lnk, chrome, firefox, winreg, ...)
    Processing time: 3h 45m

  Incident Window (2024-01-15 to 2024-01-20):
    Events in window: 234,567
    Event Sources:
      MFT:          89,234
      Event Logs:   45,678
      USN Journal:  56,789
      Registry:     23,456
      Prefetch:     1,234
      Browser:      5,678
      LNK Files:    2,345
      Other:        10,153

  Key Timeline Events:
    2024-01-15 14:32 - Phishing email opened (browser)
    2024-01-15 14:33 - Malicious document downloaded
    2024-01-15 14:35 - PowerShell executed (Prefetch + Event Log)
    2024-01-15 14:36 - C2 connection established (Registry + Event Log)
    2024-01-16 02:30 - Mimikatz execution (Prefetch)
    2024-01-16 02:45 - Lateral movement to DC (Event Log)
    2024-01-17 03:00 - Data exfiltration (MFT + USN Journal)
    2024-01-18 03:00 - Log clearing (Event Log)

  Exported Files:
    Full Timeline:     /timeline/full_timeline.csv (4.5M rows)
    Incident Window:   /timeline/incident_window.csv (234K rows)
    Timesketch Import: /timeline/timeline.jsonl
```
