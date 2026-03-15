# API Reference: Performing Bandwidth Throttling Attack Simulation

## Scapy Library

| Function/Class | Description |
|----------------|-------------|
| `IP(dst=target)` | Construct IP packet to target |
| `UDP(sport, dport)` | Construct UDP packet for bandwidth flooding |
| `Raw(load=bytes)` | Add raw payload for packet size control |
| `send(packet, verbose)` | Send packet at layer 3 |
| `RandShort()` | Generate random source port |

## tc (Traffic Control) Commands

| Command | Description |
|---------|-------------|
| `tc qdisc add dev <iface> root netem rate <rate>` | Apply bandwidth throttle |
| `tc qdisc add dev <iface> root netem delay <ms>` | Add latency |
| `tc qdisc add dev <iface> root netem loss <pct>` | Add packet loss |
| `tc qdisc del dev <iface> root` | Remove all tc rules |
| `tc qdisc show dev <iface>` | Display current tc configuration |

## iperf3 (Bandwidth Measurement)

| Flag | Description |
|------|-------------|
| `-c <server>` | Connect to iperf3 server |
| `-t <seconds>` | Duration of test |
| `-J` | Output in JSON format |
| `-u` | Use UDP instead of TCP |
| `-b <bandwidth>` | Target bandwidth for UDP test |

## Key Libraries

- **scapy** (`pip install scapy`): Packet crafting for bandwidth flood generation
- **iperf3**: Bandwidth measurement tool (system binary)
- **subprocess** (stdlib): Execute tc and iperf3 commands

## Configuration

| Variable | Description |
|----------|-------------|
| Interface | Network interface to apply throttling rules |
| Root/sudo | tc and Scapy require root privileges |
| iperf3 server | Remote iperf3 server for bandwidth measurement |

## Safety Controls

| Control | Purpose |
|---------|---------|
| Written authorization | Required before any bandwidth testing |
| `remove_tc_throttle()` | Always remove tc rules after testing |
| Packet count limit | Control flood volume to prevent unintended DoS |
| Isolated network | Run on isolated test segment only |

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Linux tc Manual](https://man7.org/linux/man-pages/man8/tc.8.html)
- [netem Network Emulator](https://man7.org/linux/man-pages/man8/tc-netem.8.html)
- [iperf3 Documentation](https://iperf.fr/iperf-doc.php)
