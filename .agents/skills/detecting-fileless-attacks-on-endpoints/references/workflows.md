# Workflows
## Fileless Attack Detection
```
[Enable telemetry (Sysmon, PS logging, AMSI)] → [Build detection rules per technique]
  → [Deploy rules in SIEM] → [Threat hunt for historical fileless indicators]
  → [Triage alerts] → [Investigate memory for confirmed incidents]
  → [Extract IOCs from memory analysis] → [Tune detections]
```
