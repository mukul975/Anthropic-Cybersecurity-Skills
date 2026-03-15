---
name: detecting-living-off-the-land-attacks
description: >
  Detect abuse of legitimate Windows binaries (LOLBins) used for living off
  the land attacks. Monitors process creation, command-line arguments, and
  parent-child relationships to identify suspicious LOLBin execution patterns.
domain: cybersecurity
subdomain: threat-detection
tags: [lolbins, lotl, fileless-attacks, process-monitoring]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Living Off the Land Attacks

Monitor for suspicious use of legitimate Windows binaries (LOLBins)
including certutil, mshta, rundll32, regsvr32, and others used in
fileless and living-off-the-land attack techniques.
