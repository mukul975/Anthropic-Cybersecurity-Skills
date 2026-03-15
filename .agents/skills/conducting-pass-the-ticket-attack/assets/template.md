# Pass-the-Ticket Attack Report Template

## Document Control
| Field | Value |
|-------|-------|
| Domain | [DOMAIN.LOCAL] |
| Engagement ID | [ID] |
| Date | [DATE] |

---

## 1. Ticket Extraction

| Source Host | Method | Tickets Found | High-Value |
|------------|--------|--------------|------------|
| | Mimikatz/Rubeus | | |

## 2. Ticket Details

| User | Type | Service | Expiry | Encryption |
|------|------|---------|--------|-----------|
| | TGT/TGS | krbtgt/cifs | | RC4/AES |

## 3. Lateral Movement Results

| Target | Access | Method | Evidence |
|--------|--------|--------|----------|
| | Admin/User | PsExec/SMB | Screenshot |

## 4. Recommendations
1. Enable Credential Guard
2. Implement Protected Users group
3. Enable LSASS RunAsPPL protection
4. Monitor Event ID 4769 anomalies
5. Reduce TGT lifetime for admin accounts

## MITRE ATT&CK
- T1550.003 - Pass the Ticket
- T1003.001 - LSASS Memory
