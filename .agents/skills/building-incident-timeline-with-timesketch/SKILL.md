---
name: building-incident-timeline-with-timesketch
description: Build collaborative forensic incident timelines using Timesketch to ingest, normalize, and analyze multi-source event data for attack chain reconstruction and investigation documentation.
domain: cybersecurity
subdomain: incident-response
tags: [timesketch, timeline-analysis, forensic-timeline, plaso, dfir, incident-investigation, collaborative-forensics]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Building Incident Timeline with Timesketch

## Overview

Timesketch is an open-source collaborative forensic timeline analysis tool developed by Google that enables security teams to visualize and analyze chronological data from multiple sources during incident investigations. It ingests logs and artifacts from endpoints, servers, and cloud services, normalizes them into a unified searchable timeline, and provides powerful analysis capabilities including built-in analyzers, tagging, sketch annotations, and story building. Timesketch integrates with Plaso (log2timeline) for artifact parsing and supports direct CSV/JSONL ingestion for rapid timeline construction during active incidents.

## Architecture and Components

### Core Components
- **Timesketch Server**: Web application with REST API for timeline management
- **OpenSearch/Elasticsearch**: Backend storage and search engine for timeline events
- **PostgreSQL**: Metadata storage for sketches, stories, and user data
- **Redis**: Task queue management for background processing
- **Celery Workers**: Asynchronous processing of timeline uploads and analyzers

### Data Flow
```
Evidence Sources --> Plaso/log2timeline --> Plaso storage file (.plaso)
     |                                           |
     v                                           v
  CSV/JSONL --> Timesketch Importer --> OpenSearch Index
                                           |
                                           v
                                    Timesketch Web UI
                                    (Search, Analyze, Story)
```

## Deployment

### Docker Deployment (Recommended)
```bash
# Clone Timesketch repository
git clone https://github.com/google/timesketch.git
cd timesketch

# Run deployment helper script
cd docker
sudo docker compose up -d

# Default access: https://localhost:443
# Admin credentials generated during first run
```

### System Requirements
- Minimum 8 GB RAM (16+ GB recommended for large investigations)
- 4 CPU cores minimum
- SSD storage for OpenSearch indices
- Docker and Docker Compose installed

## Data Ingestion Methods

### Method 1: Plaso Integration (Comprehensive)
```bash
# Process disk image with log2timeline
log2timeline.py --storage-file evidence.plaso /path/to/disk/image

# Process Windows event logs
log2timeline.py --parsers winevtx --storage-file windows_events.plaso /path/to/evtx/

# Process multiple evidence sources
log2timeline.py --parsers "winevtx,prefetch,amcache,shimcache,userassist" \
  --storage-file full_analysis.plaso /path/to/mounted/image/

# Import Plaso file into Timesketch
timesketch_importer -s "Case-2025-001" -t "Endpoint-WKS01" evidence.plaso
```

### Method 2: CSV Import (Quick Ingestion)
```csv
message,datetime,timestamp_desc,source,hostname
"User login detected","2025-01-15T08:30:00Z","Event Recorded","Security Log","DC01"
"PowerShell execution","2025-01-15T08:31:15Z","Event Recorded","PowerShell","WKS042"
```

```bash
# Import CSV directly
timesketch_importer -s "Case-2025-001" -t "Quick-Triage" events.csv
```

### Method 3: JSONL Import (Structured Data)
```json
{"message": "Suspicious logon from 10.1.2.3", "datetime": "2025-01-15T08:30:00Z", "timestamp_desc": "Event Recorded", "source_short": "Security", "hostname": "DC01"}
```

### Method 4: Sigma Rule Integration
```bash
# Upload Sigma rules for automated detection
timesketch_importer --sigma-rules /path/to/sigma/rules/
```

## Analysis Workflow

### Step 1: Create Investigation Sketch
```
1. Log into Timesketch web interface
2. Create new sketch (investigation case)
3. Add relevant timelines to the sketch
4. Set sketch description and tags
```

### Step 2: Run Built-in Analyzers
Timesketch includes analyzers that automatically identify:
- **Browser Search Analyzer**: Extracts search queries from browser history
- **Chain of Events Analyzer**: Links related events (download -> execute)
- **Domain Analyzer**: Extracts and categorizes domain names
- **Feature Extraction Analyzer**: Identifies IPs, URLs, hashes
- **Geo Location Analyzer**: Maps events to geographic locations
- **Similarity Scorer**: Finds similar events across timelines
- **Sigma Analyzer**: Matches events against Sigma detection rules
- **Account Finder**: Identifies user account activity patterns
- **Tagger**: Applies labels based on predefined rules

### Step 3: Search and Filter
```
# Search examples in Timesketch query language

# Find all events related to specific user
source_short:Security AND message:"john.admin"

# Find PowerShell execution events
data_type:"windows:evtx:record" AND event_identifier:4104

# Find lateral movement indicators
source_short:Security AND event_identifier:4624 AND xml_string:"LogonType\">3"

# Find events within specific time range
datetime:[2025-01-15T00:00:00 TO 2025-01-15T23:59:59]

# Find file creation events
data_type:"fs:stat" AND timestamp_desc:"Creation Time"

# Search with tags
tag:"suspicious" OR tag:"lateral_movement"
```

### Step 4: Build Investigation Story
```
1. Create new story within the sketch
2. Add search views that support each finding
3. Annotate key events with investigator notes
4. Link events to MITRE ATT&CK techniques
5. Document the attack narrative chronologically
6. Export story for inclusion in incident report
```

## Advanced Features

### Collaborative Investigation
- Multiple analysts work on the same sketch simultaneously
- Comments and annotations persist on events
- Saved searches shared across the team
- Investigation stories document findings in context

### API Automation
```python
from timesketch_api_client import config
from timesketch_api_client import client as ts_client

# Connect to Timesketch
ts = ts_client.TimesketchApi(
    host_uri="https://timesketch.local",
    username="analyst",
    password="password"
)

# Get sketch
sketch = ts.get_sketch(1)

# Search events
search = sketch.explore(
    query_string='event_identifier:4624 AND LogonType:3',
    return_fields='datetime,message,hostname,source_short'
)

# Add tags to events
for event in search.get('objects', []):
    sketch.tag_event(event['_id'], ['lateral_movement'])
```

### Integration with Dissect
```bash
# Use Dissect for faster artifact parsing (alternative to Plaso)
target-query -f timesketch://timesketch.local/case-001 \
  targets/hostname/ -q "windows.evtx" --limit 0
```

## Key Data Sources for Timeline Building

| Source | Parser | Evidence Value |
|--------|--------|---------------|
| Windows Event Logs (.evtx) | winevtx | Authentication, process execution, services |
| Prefetch Files | prefetch | Program execution history |
| MFT ($MFT) | mft | File system activity |
| Registry Hives | winreg | System configuration, persistence |
| Browser History | chrome/firefox | Web activity, downloads |
| Syslog | syslog | Linux/network device events |
| CloudTrail Logs | jsonl | AWS API activity |
| Azure Activity Logs | jsonl | Azure resource operations |
| Firewall Logs | csv/jsonl | Network connections |
| Proxy Logs | csv/jsonl | HTTP/HTTPS traffic |

## MITRE ATT&CK Mapping

| Technique | Timeline Indicators |
|-----------|-------------------|
| Initial Access (TA0001) | First malicious event, phishing email receipt |
| Execution (T1059) | PowerShell/CMD events, process creation |
| Persistence (TA0003) | Registry modifications, scheduled tasks, services |
| Lateral Movement (TA0008) | Remote logons, SMB connections, RDP sessions |
| Exfiltration (TA0010) | Large data transfers, cloud storage uploads |

## References

- [Timesketch Official Documentation](https://timesketch.org/)
- [Timesketch GitHub Repository](https://github.com/google/timesketch)
- [CISA Timesketch Resource](https://www.cisa.gov/resources-tools/services/timesketch)
- [Hunt and Hackett: Scalable Forensics with Dissect and Timesketch](https://www.huntandhackett.com/blog/scalable-forensics-timeline-analysis-using-dissect-and-timesketch)
- [Plaso (log2timeline) Documentation](https://plaso.readthedocs.io/)
