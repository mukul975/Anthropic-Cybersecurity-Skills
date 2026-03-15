# Workflows - Docker Bench Security Assessment

## Assessment Workflow
```
[Run Docker Bench] --> [Parse Results] --> [Prioritize FAIL findings]
        |                    |                      |
        v                    v                      v
  Initial baseline    Export JSON           Group by section
  assessment          for tracking          and severity
        |                    |                      |
        +--------------------+----------------------+
                             |
                             v
                [Create Remediation Plan]
                             |
                             v
                [Apply Fixes] --> [Re-run Assessment] --> [Compare Scores]
```
