# API Reference: OT Conduit Security Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| (stdlib only) | Python 3.8+ | Socket-based OT port scanning, JSON processing |

## CLI Usage

```bash
python scripts/agent.py \
  --targets 10.10.1.1 10.10.1.2 \
  --controls-data /assessments/conduit_controls.json \
  --output-dir /reports/
```

## Functions

### `scan_ot_ports(target, timeout) -> list`
TCP connect scan for 9 OT protocol ports (Modbus 502, S7comm 102, OPC UA 4840, etc.).

### `assess_conduit_controls(responses) -> list`
Evaluates 8 IEC 62443-aligned conduit controls: jump server, MFA, session recording, segmentation, encryption.

### `compute_conduit_risk_score(control_results, open_ports) -> dict`
Calculates risk score (0-100) penalizing for exposed OT ports and missing controls.

### `generate_report(targets, responses) -> dict`
Full assessment with port scanning, control evaluation, and risk scoring.

## OT Protocols Scanned

| Port | Protocol |
|------|----------|
| 502 | Modbus TCP |
| 102 | S7comm (Siemens) |
| 44818 | EtherNet/IP |
| 20000 | DNP3 |
| 4840 | OPC UA |
| 47808 | BACnet |

## IEC 62443 Controls Checked

| ID | Control | IEC Ref |
|----|---------|---------|
| C-01 | Jump server required | SR 5.1 |
| C-02 | MFA at conduit entry | SR 1.1 |
| C-05 | IT/OT segmentation | SR 5.1 |
| C-06 | Protocol-aware firewall | SR 5.2 |

## Output Schema

```json
{
  "summary": {"controls_implemented": 6, "controls_total": 8},
  "targets": [{"host": "10.10.1.1", "open_ot_ports": [{"port": 502, "protocol": "Modbus TCP"}]}]
}
```
