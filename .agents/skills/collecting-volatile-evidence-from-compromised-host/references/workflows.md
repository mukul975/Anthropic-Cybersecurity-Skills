# Volatile Evidence Collection - Detailed Workflow

## Order of Volatility Collection Sequence

### Priority 1: Memory (Most Volatile) - Collect First
1. Connect forensic USB with memory acquisition tool
2. Run memory dump tool from USB (NOT from compromised disk)
3. Save memory image to external storage
4. Record start time, end time, and memory size
5. Generate SHA256 hash of memory image immediately
6. Document any errors during acquisition

### Priority 2: Network State
1. Capture all active TCP/UDP connections with process IDs
2. Capture ARP cache (maps IP to MAC addresses)
3. Capture DNS resolver cache
4. Capture routing table
5. Capture active firewall rules
6. Capture listening ports and associated processes
7. Hash all network evidence files

### Priority 3: Running Processes
1. List all processes with full command lines
2. List parent-child process relationships (process tree)
3. List all loaded modules/DLLs per process
4. List all open file handles per process
5. List process network connections per PID
6. Capture process creation timestamps
7. Hash all process evidence files

### Priority 4: User Sessions
1. List all currently logged-in users
2. List active remote sessions (RDP, SSH, SMB)
3. List mapped network drives
4. Capture recent authentication events
5. List active tokens and session keys (if accessible)

### Priority 5: System Configuration
1. Capture system time and UTC offset
2. Export autostart/persistence locations (Registry Run keys, crontab)
3. List all services and their states
4. Capture environment variables
5. List installed software
6. Export relevant event log entries

### Priority 6: Temporary/Cache Data
1. Capture browser history and cache (if relevant)
2. Capture clipboard contents (if accessible)
3. Capture temp directory contents
4. Capture recent file lists
5. Capture prefetch files (Windows)

## Platform-Specific Collection Procedures

### Windows Collection Checklist
```
[ ] Memory: WinPmem/Magnet RAM Capture
[ ] Processes: tasklist /V, wmic process, Get-Process
[ ] Network: netstat -anob, Get-NetTCPConnection
[ ] Users: query user, net session
[ ] Registry: Run keys, Services, Startup
[ ] Services: sc queryex, Get-Service
[ ] Scheduled Tasks: schtasks /query
[ ] DNS Cache: ipconfig /displaydns
[ ] ARP: arp -a
[ ] Firewall: netsh advfirewall
[ ] Event Logs: wevtutil (Security, System, Application)
[ ] Prefetch: %SystemRoot%\Prefetch\*
[ ] Time: w32tm /query /status
```

### Linux Collection Checklist
```
[ ] Memory: LiME kernel module or /proc/kcore
[ ] Processes: ps auxwwf, /proc/*/cmdline, /proc/*/maps
[ ] Network: ss -tulnp, /proc/net/tcp, /proc/net/udp
[ ] Users: who, w, last
[ ] Cron: crontab -l, /etc/cron.*
[ ] Services: systemctl list-units
[ ] DNS: systemd-resolve, /etc/resolv.conf
[ ] ARP: ip neigh
[ ] Firewall: iptables -L -n -v, nftables
[ ] Logs: /var/log/auth.log, /var/log/syslog
[ ] Open Files: lsof
[ ] Time: timedatectl
[ ] Loaded Modules: lsmod
```

## Evidence Integrity Procedures

### Hashing Protocol
1. Hash EVERY collected file immediately after creation
2. Use SHA256 (minimum) - SHA512 preferred for legal cases
3. Store hash manifest in separate file
4. Verify hashes before and after any transfer
5. Include hash in chain of custody documentation

### Chain of Custody Requirements
1. Record who collected each evidence item
2. Record exact time of collection (UTC)
3. Record collection method and tool version
4. Record any transfer of evidence
5. Record storage location and access controls
6. Record any analysis performed on copies (never originals)

## Common Pitfalls to Avoid
1. Running tools from the compromised system's disk
2. Forgetting to hash evidence immediately
3. Not recording system time offset from UTC
4. Installing collection tools on the compromised system
5. Rebooting the system before memory collection
6. Modifying file timestamps by browsing the filesystem
7. Not documenting collection steps in real-time
8. Collecting evidence without proper authorization
