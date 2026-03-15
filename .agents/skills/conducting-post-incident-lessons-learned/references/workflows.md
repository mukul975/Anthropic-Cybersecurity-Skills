# Post-Incident Lessons Learned - Detailed Workflow

## Pre-Meeting Preparation (1-3 days before)
1. Compile complete incident timeline from all sources
2. Gather all communication logs (email, chat, phone)
3. Export incident metrics from ticketing system
4. Collect detection data from SIEM/EDR
5. Identify all participants and send calendar invites

## Meeting Facilitation Guide

### Ground Rules
1. Blameless discussion - focus on processes and systems
2. Everyone's perspective is valued equally
3. Objective review of facts, not opinions
4. All observations documented in real-time
5. Action items must have owners and deadlines

### Discussion Framework
1. What was the incident? (5 min) - Brief factual summary
2. Walk the timeline (20 min) - Chronological event review
3. What went well? (15 min) - Effective actions and decisions
4. What could improve? (15 min) - Gaps and failures
5. Root cause deep dive (15 min) - 5 Whys or fishbone diagram
6. Action items (10 min) - Assigned improvements
7. Playbook updates (10 min) - Procedural changes

## Key Metrics Framework

| Metric | Formula | Industry Benchmark |
|--------|---------|-------------------|
| Dwell Time | Detection - Initial Compromise | Median: 10 days (Mandiant) |
| MTTD | Triage Complete - First Alert | Target: < 15 min (P1) |
| MTTC | Containment Complete - Detection | Target: < 4 hours |
| MTTR | Recovery Complete - Eradication | Target: < 48 hours |
| Total Duration | Closure - Detection | Target: < 7 days |

## Action Item Categories

### Process
- Updated playbooks and runbooks
- Communication plan updates
- Escalation criteria changes

### Technology
- New detection rules
- Tool improvements
- Monitoring expansion
- Automation opportunities

### People
- Training needs
- Staffing gaps
- Cross-training requirements

## Follow-Up Schedule
- 1 week: Action items tracked in project system
- 1 month: First progress review
- 3 months: Validate improvements with tabletop
- 6 months: Re-evaluate metrics
