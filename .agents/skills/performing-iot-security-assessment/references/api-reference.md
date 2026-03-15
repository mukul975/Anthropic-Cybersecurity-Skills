# API Reference: IoT Security Assessment

## Tools CLI Reference

| Tool | Command | Description |
|------|---------|-------------|
| nmap | `nmap -sV -sC -p- <target>` | Full port scan with version detection |
| binwalk | `binwalk -eM <firmware>` | Recursive firmware extraction |
| tcpdump | `tcpdump -i <iface> host <ip> -w <pcap>` | Packet capture from device |
| openssl | `openssl s_client -connect <ip>:<port>` | TLS certificate inspection |
| flashrom | `flashrom -p ch341a_spi -r <output>` | SPI flash memory dump |

## Firmwalker (Firmware Scanner)

```bash
./firmwalker.sh <extracted_fs_root>/
# Scans for: passwords, keys, URLs, IPs, emails, config files
```

## FirmAE / Firmadyne (Firmware Emulation)

```bash
python3 fat.py <firmware.bin>
# Boots extracted Linux firmware in QEMU for dynamic testing
```

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute nmap, binwalk, tcpdump commands |
| `hashlib` | stdlib | Firmware integrity hashing |
| `paho-mqtt` | >=1.6 | MQTT protocol testing for unauthenticated access |

## Common IoT Protocols & Ports

| Protocol | Port | Security Concern |
|----------|------|-----------------|
| MQTT | 1883/8883 | Often unauthenticated, subscribe to # |
| CoAP | 5683 | UDP-based, usually no authentication |
| UPnP | 1900 | Service discovery, often exposes admin |
| RTSP | 554 | Video streams, frequently unauthenticated |
| Telnet | 23 | Plaintext credentials |

## References

- OWASP IoT Top 10: https://owasp.org/www-project-internet-of-things/
- FCC ID lookup: https://www.fcc.gov/oet/ea/fccid
- Firmadyne: https://github.com/firmadyne/firmadyne
- Binwalk: https://github.com/ReFirmLabs/binwalk
