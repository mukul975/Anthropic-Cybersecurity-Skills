# XSOAR Playbook Design Template

## Playbook Metadata

| Field | Value |
|---|---|
| Playbook Name | |
| Version | |
| Incident Type | |
| Description | |
| Author | |
| Created Date | |
| SLA Target | |

## Playbook Logic Flow

### Phase 1: Enrichment
- [ ] Extract indicators from alert/incident
- [ ] Enrich IPs via threat intelligence
- [ ] Enrich domains via threat intelligence
- [ ] Enrich file hashes via sandbox/TI
- [ ] Query asset database for affected hosts
- [ ] Query identity store for affected users

### Phase 2: Analysis
- [ ] Determine verdict (malicious/benign/unknown)
- [ ] Calculate risk score
- [ ] Check against allowlists/blocklists
- [ ] Correlate with existing incidents

### Phase 3: Response
- [ ] Manual approval gate for destructive actions
- [ ] Containment actions
- [ ] Eradication actions
- [ ] Recovery actions

### Phase 4: Documentation
- [ ] Update incident fields
- [ ] Generate closing report
- [ ] Update ticketing system
- [ ] Notify stakeholders

## Integrations Required

| Integration | Commands Used | Purpose |
|---|---|---|
| | | |

## Error Handling

| Task | Error Type | Handling |
|---|---|---|
| | | |

## Testing Checklist

- [ ] Test with known malicious sample
- [ ] Test with known benign sample
- [ ] Test error handling paths
- [ ] Verify manual gates function correctly
- [ ] Confirm notifications are sent
- [ ] Validate closing report content
