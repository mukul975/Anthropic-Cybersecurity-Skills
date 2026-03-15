# Hash Cracking Assessment Template

## Authorization Verification

- [ ] Written authorization obtained from asset owner
- [ ] Scope of engagement defines which hashes may be cracked
- [ ] Data handling requirements documented
- [ ] Results reporting chain defined
- [ ] Data destruction timeline agreed

## Hashcat Quick Reference

```bash
# Identify hash type
hashcat --identify hash.txt

# MD5 dictionary
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# NTLM with rules
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# bcrypt dictionary (slow)
hashcat -m 3200 -a 0 hashes.txt wordlist.txt

# Benchmark
hashcat -b
```

## Mask Charsets

| Charset | Characters | Symbol |
|---------|-----------|--------|
| ?l | a-z | lowercase |
| ?u | A-Z | uppercase |
| ?d | 0-9 | digits |
| ?s | special chars | symbols |
| ?a | ?l?u?d?s | all printable |

## Reporting Template

| Metric | Value |
|--------|-------|
| Total hashes | [count] |
| Cracked | [count] ([%]) |
| < 1 minute | [count] (CRITICAL) |
| < 1 hour | [count] (HIGH) |
| < 1 day | [count] (MEDIUM) |
| Not cracked | [count] (OK) |
