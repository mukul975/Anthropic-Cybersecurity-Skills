# Ransomware Incident Response - Detailed Workflow

## Phase 1: Detection and Initial Assessment (0-30 minutes)

### Detection Sources
1. EDR/AV alert for ransomware behavior (mass file encryption)
2. User reports of inaccessible files or ransom notes
3. SIEM correlation of suspicious patterns (VSS deletion + mass file writes)
4. Backup system alerts for failed or corrupted backups
5. Canary file monitoring triggers

### Initial Assessment Steps
1. Confirm ransomware activity (not a false positive or legitimate encryption)
2. Identify patient zero (first infected system)
3. Determine ransomware variant from ransom note or encrypted file extension
4. Check if encryption is still in progress or completed
5. Assess scope: single host, department, or enterprise-wide
6. Activate incident response team and establish war room

### Variant Identification
1. Upload ransom note to ID Ransomware (id-ransomware.malwarehunterteam.com)
2. Submit encrypted file sample to identify encryption algorithm
3. Check file extension against known ransomware database
4. Cross-reference IOCs with threat intelligence feeds
5. Search for Bitcoin wallet addresses in threat intel databases

## Phase 2: Containment (30-120 minutes)

### Immediate Actions
1. Network-isolate all confirmed infected hosts via EDR
2. Block known C2 IPs/domains at perimeter firewall
3. Disable file sharing (SMB, NFS) between network segments
4. Block lateral movement protocols (RDP, WinRM, PsExec)
5. Disable compromised user/service accounts
6. Take backup systems offline (protect from encryption)

### Network Segmentation
1. Implement emergency firewall rules between VLANs
2. Disable inter-VLAN routing for affected segments
3. Block east-west traffic for non-essential ports
4. Enable full packet capture on affected segments
5. Deploy network honey tokens

### Backup Protection Priority
1. Disconnect backup networks from production
2. Verify immutable backup copies exist and are intact
3. Test a sample restoration to confirm backup viability
4. Document last known good backup date for each system
5. If using cloud backups, verify object lock/WORM settings

## Phase 3: Investigation (2-48 hours)

### Determine Initial Access Vector
1. Review VPN/remote access logs for compromised credentials
2. Check email logs for phishing delivery
3. Analyze exploitation of public-facing applications
4. Review RDP brute force attempts in event logs
5. Check supply chain/third-party access logs

### Map Attack Timeline
1. Correlate SIEM/EDR data to build attack chronology
2. Identify dwell time (initial access to encryption)
3. Map lateral movement path through the network
4. Identify all systems accessed by the attacker
5. Determine if data was exfiltrated before encryption

### Evidence Collection
1. Capture memory images from key systems
2. Create forensic disk images before remediation
3. Export relevant SIEM logs (authentication, file access, network)
4. Preserve EDR detection data and timeline
5. Document all ransom communications

## Phase 4: Eradication (24-72 hours)

### Remove Attacker Persistence
1. Identify and remove all backdoors (web shells, RATs, implants)
2. Remove scheduled tasks created by the attacker
3. Clean malicious registry entries
4. Remove unauthorized user accounts
5. Revoke all compromised credentials (including KRBTGT if needed)
6. Patch the vulnerability used for initial access

### Validate Clean State
1. Run full AV/EDR scans on all systems
2. Scan with YARA rules specific to the ransomware family
3. Verify no unauthorized processes or services
4. Check for fileless persistence mechanisms
5. Validate Group Policy objects are clean

## Phase 5: Recovery (24 hours - 2 weeks)

### Recovery Prioritization
| Priority | System Category | Recovery Target |
|----------|----------------|-----------------|
| P1 | Domain controllers, DNS, DHCP | 4-8 hours |
| P2 | Email, communication systems | 8-24 hours |
| P3 | Core business applications | 24-72 hours |
| P4 | File shares, secondary systems | 3-7 days |
| P5 | Non-critical workstations | 1-2 weeks |

### Recovery Steps
1. Rebuild systems from known-good images (not infected backups)
2. Restore data from verified clean backups
3. Apply all security patches before reconnecting to network
4. Reset all passwords enterprise-wide
5. Implement MFA on all remote access
6. Reconnect systems in phases with enhanced monitoring
7. Verify data integrity after restoration

### Decryption Assessment
1. Check nomoreransom.org for available decryptors
2. Contact law enforcement for potential seized decryption keys
3. Assess if partial decryption is possible
4. Evaluate third-party decryption services (with caution)
5. Document any data that cannot be recovered

## Phase 6: Post-Incident (1-4 weeks)

### Lessons Learned
1. Conduct formal after-action review
2. Document complete attack timeline
3. Identify what worked and what failed in the response
4. Update incident response playbook based on findings
5. Brief executive leadership and board

### Preventive Improvements
1. Implement or enhance immutable backups
2. Deploy additional network segmentation
3. Improve endpoint detection rules
4. Conduct security awareness training
5. Test backup restoration procedures regularly
6. Implement privileged access management (PAM)
