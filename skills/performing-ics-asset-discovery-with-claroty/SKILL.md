---
name: performing-ics-asset-discovery-with-claroty
description: 'Performs ICS/OT asset discovery with Claroty xDome, combining passive
  monitoring and Claroty Edge active queries to inventory PLCs, RTUs, HMIs, and network
  infrastructure across Purdue Model levels. Use when gaining visibility into an
  undocumented OT environment, preparing an IEC 62443 asset inventory, or onboarding
  Claroty xDome; not for IT-only discovery.

  '
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot-security
- ics
- asset-discovery
- claroty
- xdome
- scada
- network-visibility
- iec62443
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
mitre_attack:
- T1078
- T1190
- T1059
- T0816
- T0836
---

# Performing ICS Asset Discovery with Claroty

## When to Use

- When gaining initial visibility into an OT environment with unknown or poorly documented assets
- When preparing for an IEC 62443 risk assessment requiring a complete asset inventory
- When onboarding Claroty xDome into a brownfield industrial environment
- When validating existing asset inventory against actual network communications
- When identifying shadow OT devices or unauthorized connections in the control network

**Do not use** for IT-only asset discovery (use tools like Nessus or Qualys), for active scanning of sensitive PLC networks without vendor approval, or for environments where Claroty is not the deployed platform (see implementing-ot-network-traffic-analysis-with-nozomi).

## Prerequisites

- Claroty xDome SaaS subscription or on-premises deployment
- Network TAP or SPAN port configured at OT network boundaries (Levels 1-3 of Purdue Model)
- Claroty Edge collector deployed for safe active querying of hard-to-reach network segments
- Integration credentials for CMDB tools (ServiceNow, BMC) if used
- Network architecture diagram showing VLANs, switches, and firewall zones

## Workflow

### Step 1: Configure Passive Network Monitoring

Deploy Claroty sensors on SPAN ports to passively observe all OT network traffic without impacting operations.

See [references/discovery-scripts.md](references/discovery-scripts.md#step-1-claroty-xdome-asset-discovery-and-reporting-tool) for the full `ClarotyAssetDiscovery` API tool (sites, assets, communication maps, CSV export, Purdue-level report).


### Step 2: Configure Active Discovery with Claroty Edge

Claroty Edge performs safe, targeted queries of OT devices using native industrial protocols (not IT scanning) to extract detailed asset information from devices that passive monitoring alone cannot fully identify.

```yaml
# Claroty Edge Active Discovery Configuration
# Safe active queries using native industrial protocols

edge_configuration:
  deployment_mode: "on-premises"
  collection_schedule:
    frequency: "weekly"
    maintenance_window: "Sunday 02:00-06:00"
    max_concurrent_queries: 5

  protocol_queries:
    siemens_s7:
      enabled: true
      target_subnets: ["10.10.1.0/24", "10.10.2.0/24"]
      ports: [102]
      query_type: "SZL_read"
      information_collected:
        - "Module identification"
        - "Firmware version"
        - "Hardware configuration"
        - "Protection level"

    rockwell_cip:
      enabled: true
      target_subnets: ["10.10.3.0/24"]
      ports: [44818]
      query_type: "CIP_identity"
      information_collected:
        - "Product name and revision"
        - "Serial number"
        - "Device type"
        - "Vendor ID"

    modbus:
      enabled: true
      target_subnets: ["10.10.4.0/24"]
      ports: [502]
      query_type: "read_device_identification"
      function_code: 43
      information_collected:
        - "Vendor name"
        - "Product code"
        - "Firmware revision"

    bacnet:
      enabled: true
      target_subnets: ["10.10.5.0/24"]
      ports: [47808]
      query_type: "who_is"
      information_collected:
        - "Device name"
        - "Vendor identifier"
        - "Model name"
        - "Application software version"

  safety_controls:
    excluded_subnets: ["10.10.100.0/24"]  # SIS network - never active scan
    rate_limiting: true
    max_packets_per_second: 10
    timeout_seconds: 5
    retry_count: 1
    abort_on_device_error: true
```

### Step 3: Validate and Enrich Asset Data

Cross-reference discovered assets against known inventories and enrich with vulnerability data.

See [references/discovery-scripts.md](references/discovery-scripts.md#step-3-asset-validation-and-enrichment-tool) for the full `AssetValidator` script (CMDB comparison, shadow/missing device detection, NVD enrichment, risk summary).


## Key Concepts

| Term | Definition |
|------|------------|
| Passive Monitoring | Observing mirrored network traffic via SPAN/TAP without injecting packets, safe for all OT devices |
| Active Querying | Sending native protocol requests to extract detailed device information; requires careful scheduling |
| Claroty Edge | Claroty's safe active discovery collector that uses native industrial protocols rather than IT scanning |
| Purdue Level | Hierarchical classification of industrial network assets from Level 0 (physical process) to Level 5 (enterprise) |
| Shadow OT Device | Asset connected to the OT network that is not documented in the asset management system |
| xDome | Claroty's SaaS-based cyber-physical systems protection platform providing visibility, risk management, and threat detection |

## Common Scenarios

### Scenario: Brownfield Factory Asset Discovery

**Context**: A manufacturing plant with 20 years of equipment additions needs a complete OT asset inventory for an IEC 62443 risk assessment. No accurate asset records exist.

**Approach**:
1. Deploy Claroty sensors on SPAN ports at each major network segment (control, supervisory, DMZ)
2. Allow passive monitoring for 2-4 weeks to capture all regular communication patterns
3. Schedule Claroty Edge active queries during a planned maintenance window
4. Export discovered inventory and categorize assets by Purdue level, vendor, and criticality
5. Cross-reference against any existing documentation (P&ID diagrams, network drawings)
6. Identify shadow devices and initiate a review process with plant operations
7. Feed validated inventory into IEC 62443 zone and conduit risk assessment

**Pitfalls**: Do not rush active discovery before passive monitoring has captured baseline traffic patterns. Never use IT vulnerability scanners (Nessus active scans) directly against PLCs or RTUs -- this can crash legacy controllers. Always exclude Safety Instrumented Systems (SIS) from active queries.

## Output Format

```
ICS ASSET DISCOVERY REPORT
============================
Date: YYYY-MM-DD
Platform: Claroty xDome
Site: [Site Name]

DISCOVERY SUMMARY:
  Total Assets Discovered: [count]
  New Assets (not in CMDB): [count]
  High-Risk Assets: [count]

PURDUE LEVEL DISTRIBUTION:
  Level 0 (Process): [count] assets
  Level 1 (Control): [count] assets
  Level 2 (Supervisory): [count] assets
  Level 3 (Operations): [count] assets
  Level 3.5 (DMZ): [count] assets
  Level 4-5 (Enterprise): [count] assets

TOP VENDORS:
  1. [Vendor] - [count] devices
  2. [Vendor] - [count] devices

CRITICAL FINDINGS:
  - [Shadow device description]
  - [End-of-life firmware finding]
  - [Unencrypted protocol concern]
```
