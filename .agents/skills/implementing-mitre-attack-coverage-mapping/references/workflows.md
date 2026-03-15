# Workflows - MITRE ATT&CK Coverage Mapping

## Quarterly Coverage Assessment Workflow

```
1. Export all active SIEM detection rules
   |
   v
2. Map each rule to MITRE ATT&CK technique(s)
   |
   v
3. Score each technique (0-100)
   |
   v
4. Generate ATT&CK Navigator heatmap
   |
   v
5. Identify top 10 gap techniques
   |
   v
6. Prioritize based on threat landscape
   |
   v
7. Create detection engineering backlog
   |
   v
8. Build and deploy new rules
   |
   v
9. Validate with adversary emulation
   |
   v
10. Update coverage map
```

## Continuous Improvement Cycle

```
Assess Coverage --> Identify Gaps --> Prioritize -->
Build Rules --> Test Rules --> Deploy --> Validate -->
Measure --> Report --> Repeat
```

## Gap Closure Tracking

| Week | New Rules | Techniques Covered | Coverage Delta |
|---|---|---|---|
| 1 | 3 | T1059, T1055, T1003 | +1.5% |
| 2 | 2 | T1053, T1547 | +1.0% |
| 3 | 3 | T1071, T1105, T1048 | +1.5% |
| 4 | 2 | T1218, T1036 | +1.0% |
