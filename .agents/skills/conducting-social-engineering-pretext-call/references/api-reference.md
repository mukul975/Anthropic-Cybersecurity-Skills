# Social Engineering Pretext Call — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | API integration with tracking platforms |
| twilio | `pip install twilio` | Programmatic phone call management |
| jinja2 | `pip install Jinja2` | Pretext script template rendering |

## Pretext Call Phases

| Phase | Description |
|-------|-------------|
| Reconnaissance | Research target name, role, department, reporting chain |
| Pretext Development | Create believable scenario and script |
| Call Execution | Make the call, follow script, adapt to responses |
| Documentation | Record outcome, information obtained, duration |
| Analysis | Calculate success rates, identify vulnerable departments |

## Success Criteria Categories

| Category | Description |
|----------|-------------|
| Full Success | Target provided credentials, access, or completed action |
| Partial Success | Target revealed organizational info but not credentials |
| Failed | Target refused or became suspicious |
| Reported | Target reported the call to security team |

## Key Metrics

| Metric | Formula |
|--------|---------|
| Success Rate | successful_calls / total_calls x 100 |
| Report Rate | calls_reported_to_security / total_calls x 100 |
| Avg Call Duration | total_duration / total_calls |
| Dept Vulnerability | dept_successes / dept_total x 100 |

## Legal Considerations

| Requirement | Description |
|-------------|-------------|
| Written Authorization | Signed Rules of Engagement from client |
| Recording Consent | Follow state/jurisdiction recording laws |
| Scope Boundaries | Only call authorized targets |
| Data Handling | Securely store any obtained credentials, delete after report |

## External References

- [Social Engineering Framework](https://www.social-engineer.org/framework/)
- [PTES Pre-engagement Guidelines](http://www.pentest-standard.org/)
- [Twilio Voice API](https://www.twilio.com/docs/voice)
