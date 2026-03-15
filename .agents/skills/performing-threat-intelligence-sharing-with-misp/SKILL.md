---
name: performing-threat-intelligence-sharing-with-misp
description: Use PyMISP to create, enrich, and share threat intelligence events on a MISP platform, including IOC management, feed integration, STIX export, and community sharing workflows.
domain: cybersecurity
subdomain: threat-intelligence
tags: [misp, pymisp, threat-intelligence, ioc-sharing, stix, taxii, threat-feeds, information-sharing]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Threat Intelligence Sharing with MISP

## Overview

MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform designed for collecting, storing, distributing, and sharing cybersecurity indicators and threat information. PyMISP is the official Python library for interacting with MISP instances via the REST API, enabling programmatic event creation, attribute management, tag assignment, galaxy cluster attachment, and feed synchronization. This skill covers using PyMISP to create events with structured IOCs (IP addresses, domains, file hashes, URLs), enrich events with MITRE ATT&CK tags, manage sharing groups and distribution levels, search for existing intelligence, and export in STIX 2.1 format for interoperability with other platforms.

## Prerequisites

- MISP instance (v2.4+) with API access enabled
- Python 3.9+ with `pymisp` (`pip install pymisp`)
- MISP API key (Settings > Auth Keys)
- Understanding of MISP data model (Events, Attributes, Objects, Tags, Galaxies)
- Knowledge of TLP marking and sharing protocols

## Steps

1. Install PyMISP: `pip install pymisp`
2. Initialize `ExpandedPyMISP(url, key, ssl=True)` connection
3. Create a `MISPEvent` with info, distribution level, threat level, and analysis status
4. Add attributes via `event.add_attribute(type, value)` for IPs, domains, hashes
5. Apply TLP tags and MITRE ATT&CK technique tags
6. Publish the event with `misp.publish(event)`
7. Search existing events with `misp.search(controller='events', value=..., type_attribute=...)`
8. Enable and configure threat feeds for automatic IOC ingestion
9. Export events in STIX 2.1 format for cross-platform sharing
10. Validate sharing group configuration and sync server settings

## Expected Output

A JSON report summarizing events created, attributes added, tags applied, feed sync status, and any correlation hits against existing intelligence, with event IDs and distribution metadata.
