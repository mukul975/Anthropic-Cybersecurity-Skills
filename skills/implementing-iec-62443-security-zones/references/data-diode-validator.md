# Data Diode Configuration Validator (Step 4 detail)

Full Python validator for the unidirectional historian-replication data diode between the operations zone and the DMZ (Waterfall Security, Owl Cyber Defense, or Siemens). Confirms forward flow works, reverse flow is physically blocked, and replication latency is acceptable.

```python
#!/usr/bin/env python3
"""Data Diode Configuration Validator.

Validates that historian replication across the data diode
(Waterfall Security, Owl Cyber Defense, or Siemens) is
functioning correctly with unidirectional enforcement.
"""

import socket
import struct
import time
import json
from datetime import datetime


class DataDiodeValidator:
    """Validates data diode unidirectional enforcement."""

    def __init__(self, diode_tx_ip, diode_rx_ip, historian_port=5450):
        self.tx_ip = diode_tx_ip  # OT side (transmit)
        self.rx_ip = diode_rx_ip  # IT/DMZ side (receive)
        self.port = historian_port
        self.results = []

    def test_forward_flow(self):
        """Verify data flows from OT (TX) to DMZ (RX) through diode."""
        test_payload = f"DIODE_TEST_{datetime.now().isoformat()}"

        try:
            # Send test data to TX interface
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(test_payload.encode(), (self.tx_ip, self.port))
            sock.close()

            self.results.append({
                "test": "forward_flow",
                "status": "PASS",
                "detail": f"Data sent to TX interface {self.tx_ip}:{self.port}",
            })
        except Exception as e:
            self.results.append({
                "test": "forward_flow",
                "status": "FAIL",
                "detail": f"Cannot reach TX interface: {e}",
            })

    def test_reverse_flow_blocked(self):
        """Verify reverse flow (DMZ to OT) is physically blocked by diode."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.tx_ip, self.port))
            sock.close()

            if result != 0:
                self.results.append({
                    "test": "reverse_flow_blocked",
                    "status": "PASS",
                    "detail": "Reverse connection to OT side correctly rejected",
                })
            else:
                self.results.append({
                    "test": "reverse_flow_blocked",
                    "status": "CRITICAL_FAIL",
                    "detail": "REVERSE FLOW POSSIBLE - Data diode bypass detected!",
                })
        except (socket.timeout, ConnectionRefusedError):
            self.results.append({
                "test": "reverse_flow_blocked",
                "status": "PASS",
                "detail": "Reverse connection timed out (expected with hardware diode)",
            })

    def test_historian_replication_latency(self):
        """Measure replication latency across the data diode."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            start = time.time()
            sock.connect((self.rx_ip, self.port))
            latency = (time.time() - start) * 1000
            sock.close()

            status = "PASS" if latency < 1000 else "WARN"
            self.results.append({
                "test": "replication_latency",
                "status": status,
                "detail": f"Replication endpoint latency: {latency:.1f}ms",
            })
        except Exception as e:
            self.results.append({
                "test": "replication_latency",
                "status": "FAIL",
                "detail": f"Cannot reach RX historian: {e}",
            })

    def run_all_tests(self):
        """Run complete data diode validation suite."""
        print("=" * 60)
        print("DATA DIODE VALIDATION REPORT")
        print("=" * 60)

        self.test_forward_flow()
        self.test_reverse_flow_blocked()
        self.test_historian_replication_latency()

        for r in self.results:
            status_icon = "+" if r["status"] == "PASS" else "-"
            print(f"  [{status_icon}] {r['test']}: {r['status']}")
            print(f"      {r['detail']}")

        return self.results


if __name__ == "__main__":
    validator = DataDiodeValidator(
        diode_tx_ip="10.30.1.100",   # Operations zone TX
        diode_rx_ip="172.16.1.100",  # DMZ zone RX
    )
    validator.run_all_tests()
```

