# Ransomware Backup Strategy Assessment Template

## Organization Information

| Field | Value |
|-------|-------|
| Organization Name | |
| Assessment Date | |
| Assessor Name | |
| Backup Solution | |
| Number of Servers | |
| Total Data Volume | |

## Current Backup Architecture

### Backup Copies Inventory

| Copy # | Location | Media Type | Offsite? | Immutable? | Air-Gapped? | Retention | Encrypted? | Last Successful |
|--------|----------|------------|----------|------------|-------------|-----------|------------|-----------------|
| 1 | | | | | | | | |
| 2 | | | | | | | | |
| 3 | | | | | | | | |

### 3-2-1-1-0 Compliance Checklist

- [ ] **3 Copies**: At least 3 copies of data exist
- [ ] **2 Media Types**: Backups stored on at least 2 different media types
- [ ] **1 Offsite**: At least 1 copy stored offsite or in a different geographic location
- [ ] **1 Immutable/Air-Gapped**: At least 1 copy is immutable or physically air-gapped
- [ ] **0 Errors**: Automated restore testing passes with zero errors

## Recovery Tier Classification

### Tier 1 - Critical Systems

| System | RPO Target | RTO Target | Backup Frequency | Dependencies |
|--------|-----------|-----------|-------------------|--------------|
| | | | | |

### Tier 2 - Important Systems

| System | RPO Target | RTO Target | Backup Frequency | Dependencies |
|--------|-----------|-----------|-------------------|--------------|
| | | | | |

### Tier 3 - Standard Systems

| System | RPO Target | RTO Target | Backup Frequency | Dependencies |
|--------|-----------|-----------|-------------------|--------------|
| | | | | |

## Credential Isolation Assessment

| Control | Status | Evidence |
|---------|--------|----------|
| Backup servers removed from production AD | Yes / No | |
| Dedicated backup admin accounts | Yes / No | |
| MFA enabled for backup console | Yes / No | |
| Backup network segmented | Yes / No | |
| RDP disabled on backup servers | Yes / No | |
| Backup encryption keys stored separately | Yes / No | |

## Restore Testing History

| Date | Tier | Systems Tested | Result | RTO Achieved | Issues |
|------|------|---------------|--------|-------------|--------|
| | | | | | |

## Gap Analysis

| Control | Current State | Target State | Gap | Priority | Effort |
|---------|--------------|-------------|-----|----------|--------|
| Immutable backup | | | | | |
| Credential isolation | | | | | |
| Restore testing | | | | | |
| Offsite copy | | | | | |
| Encryption | | | | | |

## Recommendations

### Critical Priority

1. **[Finding]**: [Recommendation] - Estimated effort: [X days/weeks]

### High Priority

1. **[Finding]**: [Recommendation] - Estimated effort: [X days/weeks]

### Medium Priority

1. **[Finding]**: [Recommendation] - Estimated effort: [X days/weeks]

## Recovery Runbook Checklist

### Pre-Recovery
- [ ] Incident declared and scope determined
- [ ] Affected systems isolated from network
- [ ] Backup integrity verified (immutable copies confirmed clean)
- [ ] Backup timestamps verified to predate infection
- [ ] Recovery environment prepared (clean network, fresh OS images)

### Recovery Execution
- [ ] Phase 1: Identity infrastructure (AD, DNS, DHCP)
- [ ] Phase 2: Tier 1 critical systems
- [ ] Phase 3: Tier 2 important systems
- [ ] Phase 4: Tier 3 standard systems
- [ ] Each restored system validated before connecting to network

### Post-Recovery
- [ ] All restored systems scanned for persistence mechanisms
- [ ] Security controls validated (EDR, firewall rules, MFA)
- [ ] Users notified and credentials reset
- [ ] Recovery time documented against RTO targets
- [ ] Lessons learned documented

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| IT Director | | | |
| CISO | | | |
| Backup Admin | | | |
