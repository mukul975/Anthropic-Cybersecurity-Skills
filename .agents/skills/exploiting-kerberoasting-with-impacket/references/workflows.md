# Workflows: Kerberoasting with Impacket

## Kerberoasting Attack Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                KERBEROASTING ATTACK WORKFLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. ENUMERATE SPN ACCOUNTS                                       │
│     ├── GetUserSPNs.py (list mode, no -request)                  │
│     ├── Identify high-value targets (DA members, AdminCount)     │
│     ├── Check password age (older = weaker)                      │
│     └── Prioritize targets                                       │
│                                                                  │
│  2. REQUEST TGS TICKETS                                          │
│     ├── GetUserSPNs.py -request -outputfile hashes.txt           │
│     ├── Target specific high-value accounts first                │
│     ├── Request RC4 tickets if possible (faster cracking)        │
│     └── OPSEC: Space out requests to avoid detection             │
│                                                                  │
│  3. OFFLINE CRACKING                                             │
│     ├── hashcat -m 13100 (RC4) or -m 19700 (AES256)             │
│     ├── Use quality wordlists (rockyou, SecLists)                │
│     ├── Apply rules (best64, dive, OneRuleToRuleThemAll)         │
│     └── Use GPU acceleration for faster results                  │
│                                                                  │
│  4. VALIDATE CREDENTIALS                                         │
│     ├── CrackMapExec SMB validation                              │
│     ├── Check access levels (local admin, domain admin)          │
│     ├── Enumerate additional access paths                        │
│     └── Document findings                                        │
│                                                                  │
│  5. LEVERAGE ACCESS                                              │
│     ├── If Domain Admin: DCSync / Golden Ticket                  │
│     ├── If Local Admin: Dump LSASS, pivot laterally              │
│     ├── If standard user: Use for further enumeration            │
│     └── Update BloodHound with newly owned accounts              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Target Prioritization Matrix

```
Priority Decision Tree
│
├── Is account in Domain Admins group?
│   └── YES → CRITICAL priority → Crack immediately
│
├── Is AdminCount = 1?
│   └── YES → HIGH priority → Currently or previously privileged
│
├── Password last set > 2 years ago?
│   └── YES → HIGH priority → Likely weak/legacy password
│
├── Is account AdminTo any computers?
│   └── YES → MEDIUM priority → Lateral movement opportunity
│
├── Account description contains password hint?
│   └── YES → HIGH priority → Common OPSEC failure
│
└── Standard service account
    └── LOW priority → Crack opportunistically
```

## Hashcat Command Reference

```bash
# Basic Kerberoasting crack (RC4)
hashcat -m 13100 hashes.txt wordlist.txt

# With rules
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule

# Multiple wordlists with rules
hashcat -m 13100 hashes.txt wordlist1.txt wordlist2.txt \
  -r rules/OneRuleToRuleThemAll.rule

# AES-256 cracking
hashcat -m 19700 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force (8 chars)
hashcat -m 13100 hashes.txt -a 3 ?a?a?a?a?a?a?a?a

# Show cracked passwords
hashcat -m 13100 hashes.txt --show
```

## Detection and Response Workflow

```
SOC DETECTION WORKFLOW
│
├── SIEM Alert: Multiple 4769 events with RC4 encryption
│   ├── Check source account - is it a service account?
│   │   └── NO → Potential Kerberoasting
│   ├── Check volume - more than 5 TGS requests in 5 minutes?
│   │   └── YES → High confidence Kerberoasting
│   └── Check encryption type - 0x17 (RC4)?
│       └── YES → Confirm Kerberoasting attempt
│
├── RESPONSE ACTIONS
│   ├── Identify source IP and user account
│   ├── Isolate source system if compromised
│   ├── Reset passwords on all targeted service accounts
│   ├── Check for lateral movement from source
│   └── Review service account permissions
│
└── POST-INCIDENT
    ├── Implement gMSA for targeted accounts
    ├── Disable RC4 encryption via GPO
    ├── Deploy Kerberoasting detection rule
    └── Conduct AD security assessment
```
