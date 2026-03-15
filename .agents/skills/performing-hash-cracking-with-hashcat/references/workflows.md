# Workflows - Hash Cracking with Hashcat

## Workflow 1: Hash Identification and Cracking

```
[Captured Hashes]
      |
[Identify Hash Type]
(hashcat --identify, hashid, haiti)
      |
[Select Attack Strategy]:
  1. Dictionary attack (rockyou.txt)
  2. Dictionary + rules (best64.rule)
  3. Mask attack (brute-force)
  4. Hybrid (wordlist + mask)
      |
[Execute Hashcat]
      |
[Analyze Results]
(cracked count, time, patterns)
      |
[Generate Password Strength Report]
```

## Workflow 2: Hashcat Command Examples

```bash
# Dictionary attack
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# Dictionary + rules
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r best64.rule

# Mask (brute-force 8-char lowercase)
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?l

# Hybrid (wordlist + 4 digits)
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d?d

# Show cracked passwords
hashcat -m 0 hashes.txt --show
```

## Workflow 3: Password Audit Report

```
[Cracking Results]
      |
[Categorize]:
  - Cracked in < 1 min: CRITICAL
  - Cracked in < 1 hour: HIGH
  - Cracked in < 1 day: MEDIUM
  - Not cracked: Acceptable
      |
[Pattern Analysis]:
  - Common base words
  - Character set distribution
  - Length distribution
  - Policy compliance
      |
[Generate Report with Recommendations]
```
