# Standards - Linux Log Forensics
## Standards
- NIST SP 800-92: Guide to Computer Security Log Management
- NIST SP 800-86: Guide to Integrating Forensic Techniques
- RFC 5424: The Syslog Protocol
## Key Log Locations
- /var/log/auth.log (Debian) or /var/log/secure (RHEL): Authentication events
- /var/log/syslog (Debian) or /var/log/messages (RHEL): System messages
- /var/log/kern.log: Kernel messages
- /var/log/audit/audit.log: Linux Audit Framework
- /var/log/wtmp, /var/log/btmp, /var/log/lastlog: Login records (binary)
## Tools
- journalctl: Systemd journal query tool
- ausearch/aureport: Audit log analysis
- logwatch, lnav: Log analysis utilities
