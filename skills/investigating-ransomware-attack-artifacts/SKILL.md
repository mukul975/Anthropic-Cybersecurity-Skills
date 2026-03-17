---
name: investigating-ransomware-attack-artifacts
description: Identify, collect, and analyze ransomware attack artifacts to determine the variant, initial access vector, encryption scope, and recovery options.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, ransomware, malware-analysis, incident-response, encryption-recovery, evidence-collection]
mitre_attack: ["T1486", "T1490", "T1489", "T1570"]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Investigating Ransomware Attack Artifacts

## When to Use
- Immediately after discovering ransomware encryption on systems
- When performing forensic analysis to understand the full scope of a ransomware incident
- For identifying the ransomware variant and determining if decryption is possible
- When tracing the attack chain from initial access to encryption
- For documenting evidence to support law enforcement and insurance claims

## Prerequisites
- Forensic images of affected systems (preserve before remediation)
- Memory dumps captured before system shutdown (if available)
- Ransom notes and encrypted file samples
- Network traffic captures from the attack period
- Windows Event Logs, Prefetch files, and registry hives
- Access to ransomware identification tools (ID Ransomware, No More Ransom)
- Isolated sandbox environment for malware analysis

## Workflow

### Step 1: Preserve Evidence and Identify the Ransomware Variant

```bash
# CRITICAL: Do NOT restart systems. Preserve memory first if possible.
# Encryption keys may still be in memory.

# Capture memory from running systems
# Windows: DumpIt.exe (generates memory.raw)
# Linux: sudo insmod lime.ko "path=/evidence/memory.lime format=lime"

# Collect ransom note
cp /mnt/evidence/Users/*/Desktop/README*.txt /cases/case-2024-001/ransomware/ransom_notes/
cp /mnt/evidence/Users/*/Desktop/DECRYPT*.txt /cases/case-2024-001/ransomware/ransom_notes/
cp /mnt/evidence/Users/*/Desktop/HOW_TO*.txt /cases/case-2024-001/ransomware/ransom_notes/
find /mnt/evidence/ -name "*.hta" -o -name "*DECRYPT*" -o -name "*RANSOM*" -o -name "*README*" \
   2>/dev/null | head -20 > /cases/case-2024-001/ransomware/note_locations.txt

# Collect sample encrypted files (for identification)
find /mnt/evidence/Users/ -name "*.encrypted" -o -name "*.locked" -o -name "*.crypted" \
   -o -name "*.crypt" -o -name "*.enc" | head -10 > /cases/case-2024-001/ransomware/encrypted_samples.txt

# Copy sample encrypted files
mkdir -p /cases/case-2024-001/ransomware/samples/
head -5 /cases/case-2024-001/ransomware/encrypted_samples.txt | while read f; do
    cp "$f" /cases/case-2024-001/ransomware/samples/
done

# Identify ransomware variant using file extension and ransom note
python3 << 'PYEOF'
import os, hashlib, json

ransomware_indicators = {
    '.lockbit': 'LockBit',
    '.blackcat': 'BlackCat/ALPHV',
    '.royal': 'Royal',
    '.akira': 'Akira',
    '.clop': 'Cl0p',
    '.conti': 'Conti',
    '.ryuk': 'Ryuk',
    '.revil': 'REvil/Sodinokibi',
    '.maze': 'Maze',
    '.phobos': 'Phobos',
    '.dharma': 'Dharma/CrySIS',
    '.stop': 'STOP/Djvu',
    '.hive': 'Hive',
    '.blackbasta': 'Black Basta',
    '.play': 'Play',
}

# Check encrypted file extensions
samples_dir = '/cases/case-2024-001/ransomware/samples/'
for f in os.listdir(samples_dir):
    ext = os.path.splitext(f)[1].lower()
    variant = ransomware_indicators.get(ext, 'Unknown')
    sha256 = hashlib.sha256(open(os.path.join(samples_dir, f), 'rb').read()).hexdigest()
    print(f"File: {f}")
    print(f"  Extension: {ext}")
    print(f"  Suspected Variant: {variant}")
    print(f"  SHA-256: {sha256}")
    print()

# Parse ransom note for IoCs
note_dir = '/cases/case-2024-001/ransomware/ransom_notes/'
for note in os.listdir(note_dir):
    with open(os.path.join(note_dir, note), 'r', errors='ignore') as f:
        content = f.read()
        print(f"\n=== Ransom Note: {note} ===")
        # Extract bitcoin addresses
        import re
        btc = re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39}', content)
        tor = re.findall(r'[a-z2-7]{56}\.onion', content)
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)

        if btc: print(f"  Bitcoin addresses: {btc}")
        if tor: print(f"  Tor addresses: {tor}")
        if emails: print(f"  Contact emails: {emails}")
PYEOF
```

### Step 2: Determine the Attack Timeline

```bash
# Find the earliest encrypted file (encryption start time)
find /mnt/evidence/ -name "*.encrypted" -printf '%T+ %p\n' 2>/dev/null | sort | head -5 \
   > /cases/case-2024-001/ransomware/encryption_start.txt

# Find the latest encrypted file (encryption end time)
find /mnt/evidence/ -name "*.encrypted" -printf '%T+ %p\n' 2>/dev/null | sort -r | head -5 \
   > /cases/case-2024-001/ransomware/encryption_end.txt

# Analyze Prefetch for ransomware executable
ls /mnt/evidence/Windows/Prefetch/ | grep -iE "(encrypt|ransom|lock|crypt)" \
   > /cases/case-2024-001/ransomware/prefetch_hits.txt

# Check Windows Event Logs for key events
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser

# Security log - authentication and access events
parser = PyEvtxParser("/cases/case-2024-001/evtx/Security.evtx")

attack_events = []
for record in parser.records_json():
    data = json.loads(record['data'])
    event_id = str(data['Event']['System']['EventID'])
    timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']

    # Key events for ransomware investigation
    if event_id in ('4624', '4625', '4648', '4672', '4697', '4698', '4688', '1102'):
        event_data = data['Event'].get('EventData', {})
        attack_events.append({
            'time': timestamp,
            'event_id': event_id,
            'data': json.dumps(event_data, default=str)[:200]
        })

# Sort and display timeline
attack_events.sort(key=lambda x: x['time'])
print("=== RANSOMWARE ATTACK TIMELINE ===\n")
for event in attack_events[-50:]:
    print(f"  [{event['time']}] EventID {event['event_id']}: {event['data'][:150]}")
PYEOF

# Check for Volume Shadow Copy deletion (common ransomware behavior)
# Look for vssadmin.exe or wmic shadowcopy in event logs and Prefetch
grep -l "vssadmin" /cases/case-2024-001/evtx/*.evtx 2>/dev/null
ls /mnt/evidence/Windows/Prefetch/ | grep -i "vssadmin\|wmic\|bcdedit\|wbadmin"
```

### Step 3: Trace Initial Access and Lateral Movement

```bash
# Check for common ransomware initial access vectors

# RDP brute force
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser
from collections import defaultdict

parser = PyEvtxParser("/cases/case-2024-001/evtx/Security.evtx")

failed_rdp = defaultdict(int)
successful_rdp = []

for record in parser.records_json():
    data = json.loads(record['data'])
    event_id = str(data['Event']['System']['EventID'])
    event_data = data['Event'].get('EventData', {})
    timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']

    if event_id == '4625':  # Failed logon
        logon_type = str(event_data.get('LogonType', ''))
        if logon_type == '10':  # RDP
            source_ip = event_data.get('IpAddress', 'Unknown')
            failed_rdp[source_ip] += 1

    if event_id == '4624':  # Successful logon
        logon_type = str(event_data.get('LogonType', ''))
        if logon_type in ('10', '3'):  # RDP or Network
            source_ip = event_data.get('IpAddress', 'Unknown')
            username = event_data.get('TargetUserName', 'Unknown')
            successful_rdp.append({'time': timestamp, 'user': username, 'ip': source_ip, 'type': logon_type})

print("=== FAILED RDP ATTEMPTS ===")
for ip, count in sorted(failed_rdp.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {ip}: {count} failed attempts")

print(f"\n=== SUCCESSFUL NETWORK/RDP LOGONS ===")
for logon in successful_rdp[-20:]:
    type_name = 'RDP' if logon['type'] == '10' else 'Network'
    print(f"  [{logon['time']}] {logon['user']} from {logon['ip']} ({type_name})")
PYEOF

# Check for phishing-related artifacts
# Browser downloads, email attachments, Office macros
find /mnt/evidence/Users/*/Downloads/ -name "*.exe" -o -name "*.dll" -o -name "*.js" \
   -o -name "*.vbs" -o -name "*.hta" -o -name "*.ps1" 2>/dev/null \
   > /cases/case-2024-001/ransomware/suspicious_downloads.txt

# Check PowerShell execution
ls /mnt/evidence/Windows/Prefetch/ | grep -i powershell
```

### Step 4: Assess Encryption Scope and Recovery Options

```bash
# Count encrypted files by directory
find /mnt/evidence/ -name "*.encrypted" 2>/dev/null | \
   awk -F/ '{OFS="/"; NF--; print}' | sort | uniq -c | sort -rn | head -20 \
   > /cases/case-2024-001/ransomware/encryption_scope.txt

# Check if Volume Shadow Copies survived
vssadmin list shadows 2>/dev/null > /cases/case-2024-001/ransomware/vss_status.txt

# Check for backup integrity
find /mnt/evidence/ -name "*.bak" -o -name "*.backup" 2>/dev/null | head -20

# Check No More Ransom project for available decryptors
# https://www.nomoreransom.org/en/decryption-tools.html
echo "Check https://www.nomoreransom.org/ for decryption tools" \
   > /cases/case-2024-001/ransomware/decryption_options.txt

# Attempt to recover encryption keys from memory dump
if [ -f /cases/case-2024-001/memory/memory.raw ]; then
    # Search for AES key schedules in memory
    vol -f /cases/case-2024-001/memory/memory.raw yarascan \
       --yara-rules 'rule AES_Key { strings: $aes = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 } condition: $aes }' \
       > /cases/case-2024-001/ransomware/aes_key_search.txt

    # Search for RSA key material
    vol -f /cases/case-2024-001/memory/memory.raw yarascan \
       --yara-rules 'rule RSA_Key { strings: $rsa = "RSA PRIVATE KEY" condition: $rsa }' \
       > /cases/case-2024-001/ransomware/rsa_key_search.txt
fi
```

### Step 5: Document Findings and Generate Report

```bash
# Generate comprehensive ransomware investigation report
cat << 'REPORT' > /cases/case-2024-001/ransomware/investigation_report.txt
RANSOMWARE INCIDENT INVESTIGATION REPORT
==========================================
Case Number: 2024-001
Date: $(date -u)
Analyst: [Examiner Name]

1. INCIDENT OVERVIEW
   - Ransomware Variant: [Identified variant]
   - First Encryption: [Timestamp from earliest encrypted file]
   - Last Encryption: [Timestamp from latest encrypted file]
   - Systems Affected: [Count]
   - Data Encrypted: [Volume estimate]

2. INITIAL ACCESS VECTOR
   - Method: [RDP brute force / Phishing / Exploit / etc.]
   - Entry Point: [System and IP]
   - Timestamp: [First unauthorized access]
   - Credentials Used: [Account names]

3. ATTACK CHAIN
   a. Initial Access: [Details]
   b. Execution: [Ransomware binary details]
   c. Persistence: [Services, scheduled tasks]
   d. Privilege Escalation: [Method used]
   e. Lateral Movement: [Systems accessed, methods]
   f. Collection/Staging: [Data staging before encryption]
   g. Impact: [Encryption execution]

4. INDICATORS OF COMPROMISE
   - Ransomware Binary SHA-256: [Hash]
   - C2 Servers: [IPs/Domains]
   - Bitcoin Wallet: [Address]
   - Tor Site: [.onion address]
   - Attacker IPs: [Source IPs]

5. RECOVERY ASSESSMENT
   - Decryptor Available: [Yes/No]
   - Shadow Copies: [Survived/Deleted]
   - Backups: [Status and integrity]
   - Memory Key Recovery: [Attempted/Results]

6. RECOMMENDATIONS
   - [Remediation steps]
   - [Prevention measures]
   - [Monitoring improvements]
REPORT
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Ransomware variant identification | Determining the specific ransomware family from extensions, notes, and behavior |
| Double extortion | Attack combining encryption with data theft and threatened public release |
| Volume Shadow Copies | Windows backup mechanism often deleted by ransomware to prevent recovery |
| Encryption scope | Assessment of which files, directories, and systems were encrypted |
| Dwell time | Period between initial access and ransomware deployment (often days to weeks) |
| Ransom note IoCs | Bitcoin addresses, Tor sites, and email addresses in ransom demands |
| Key recovery | Attempting to extract encryption keys from memory before shutdown |
| No More Ransom | Law enforcement initiative providing free decryption tools for some variants |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| ID Ransomware | Online service identifying ransomware variant from samples |
| No More Ransom | Free decryption tools from law enforcement partnerships |
| Volatility | Memory forensics for encryption key and malware artifact recovery |
| Chainsaw/Hayabusa | Windows Event Log analysis for attack timeline reconstruction |
| PECmd | Prefetch analysis confirming ransomware executable execution |
| YARA | Pattern matching for ransomware variant identification |
| Any.Run/Joe Sandbox | Online malware sandboxes for ransomware behavior analysis |
| Capa | Mandiant tool identifying malware capabilities from static analysis |

## Common Scenarios

**Scenario 1: LockBit Attack via RDP**
Trace initial access through RDP brute force in event logs, identify attacker IP and compromised account, follow lateral movement through network logons, find LockBit deployment via PsExec or GPO, document encryption timeline from file timestamps, check for data exfiltration before encryption.

**Scenario 2: Phishing-Initiated Ransomware**
Trace phishing email through browser history and email artifacts, identify malicious attachment execution in Prefetch, follow Cobalt Strike beacon communication in network logs, trace privilege escalation and domain compromise, document ransomware deployment across the network.

**Scenario 3: Supply Chain Ransomware Attack**
Identify the compromised software update mechanism, trace the malicious update distribution in application logs, analyze the ransomware payload delivered via the trusted channel, assess which systems received the update, determine if the vendor was notified.

**Scenario 4: Recovery from Partial Encryption**
Determine which systems and files were encrypted before containment, check for surviving volume shadow copies, verify backup integrity and restoration capability, attempt memory-based key recovery, contact law enforcement for potential decryptor availability.

## Output Format

```
Ransomware Investigation Summary:
  Variant: LockBit 3.0
  First Seen: 2024-01-18 02:00:00 UTC
  Encryption Duration: 4 hours 23 minutes
  Systems Encrypted: 45 out of 200 (containment stopped spread)

  Attack Timeline:
    2024-01-10 14:32 - RDP brute force from 203.0.113.45 (1,234 attempts)
    2024-01-10 15:00 - Successful RDP login as admin_backup
    2024-01-12 02:00 - Mimikatz executed (credential dump)
    2024-01-12 02:30 - Domain Admin credentials obtained
    2024-01-15 03:00 - Data exfiltration (45 GB to 185.x.x.x)
    2024-01-18 02:00 - LockBit deployed via PsExec to 45 systems
    2024-01-18 06:23 - Encryption completed on affected systems

  Recovery Options:
    Decryptor: Not available (LockBit 3.0)
    Shadow Copies: Deleted on all systems
    Backups: Last clean backup 2024-01-09 (9 days of data loss)
    Memory Keys: Not recovered (systems rebooted)

  IOCs:
    Ransomware Hash: a1b2c3d4e5f6...
    C2 IP: 185.x.x.x
    Bitcoin: bc1q...
    Tor: http://lockbit...onion
```
