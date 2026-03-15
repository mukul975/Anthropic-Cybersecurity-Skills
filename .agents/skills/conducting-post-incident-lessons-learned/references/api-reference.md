# Post-Incident Lessons Learned — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | API calls to ticketing/SIEM systems |
| jinja2 | `pip install Jinja2` | Report template rendering |
| matplotlib | `pip install matplotlib` | Timeline and metric visualization |

## Key Metrics

| Metric | Formula | Target |
|--------|---------|--------|
| MTTD | Detection time - Incident start | < 30 minutes |
| MTTC | Containment time - Detection time | < 60 minutes |
| MTTR | Resolution time - Detection time | < 4 hours |
| Dwell Time | Detection time - Initial compromise | < 24 hours |

## NIST SP 800-61 Phases

| Phase | Activities |
|-------|-----------|
| Preparation | Playbooks, tools, training |
| Detection & Analysis | Alert triage, scoping, evidence collection |
| Containment | Short-term and long-term isolation |
| Eradication & Recovery | Root cause removal, system restoration |
| Post-Incident | Lessons learned, action items, metrics |

## Report Template Sections

| Section | Content |
|---------|---------|
| Executive Summary | Impact, scope, duration |
| Timeline | Chronological event sequence |
| Root Cause | 5-Whys or fishbone analysis |
| Action Items | Prioritized P1/P2/P3 with owners |

## External References

- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [VERIS Framework](http://veriscommunity.net/)
