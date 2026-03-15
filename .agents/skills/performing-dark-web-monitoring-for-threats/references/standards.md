# Standards and Frameworks Reference

## Dark Web Intelligence Classification
- **TLP:RED**: Dark web source details, forum credentials, HUMINT methods
- **TLP:AMBER**: Specific threat actor mentions, leaked data analysis
- **TLP:GREEN**: Aggregated trends, anonymized statistics
- **TLP:CLEAR**: Public dark web monitoring advisories

## MITRE ATT&CK Mapping
- T1589 - Gather Victim Identity Information (credential theft)
- T1590 - Gather Victim Network Information (reconnaissance)
- T1597 - Search Closed Sources (dark web forums)
- T1598 - Phishing for Information

## Dark Web Source Categories
| Category | Description | Examples |
|----------|-------------|---------|
| Forums | Discussion boards for cybercriminals | RaidForums successors, XSS.is, Exploit.in |
| Marketplaces | Buying/selling stolen data and tools | Various .onion markets |
| Paste Sites | Anonymous text sharing | Dark web paste services |
| Leak Sites | Ransomware data publication | LockBit, BlackCat, Royal blogs |
| Chat Channels | Real-time communication | Telegram groups, Discord |

## Legal and Ethical Framework
- Passive observation of publicly accessible dark web content is legal in most jurisdictions
- Active engagement (posting, purchasing) requires legal authorization
- Credential harvesting for defensive purposes requires clear policy
- Evidence collection must follow chain of custody procedures

## References
- [FIRST Traffic Light Protocol](https://www.first.org/tlp/)
- [MITRE ATT&CK Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [Tor Project Documentation](https://www.torproject.org/docs/)
