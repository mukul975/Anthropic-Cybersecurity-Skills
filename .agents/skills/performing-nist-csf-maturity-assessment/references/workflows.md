# NIST CSF Maturity Assessment Workflows

## Workflow 1: Assessment Planning

```
Start
  |
  v
[Define Assessment Scope]
  - Enterprise-wide or business unit
  - Include/exclude OT systems
  - Include/exclude third parties
  |
  v
[Identify Stakeholders]
  - CISO and security team
  - IT leadership
  - Business unit leaders
  - Risk management
  - Legal/compliance
  - Executive sponsors
  |
  v
[Select Assessment Approach]
  +--> Self-Assessment (internal team)
  +--> Facilitated (consultant-guided)
  +--> Third-Party (independent assessment)
  |
  v
[Gather Documentation]
  - Security policies and procedures
  - Risk assessments and registers
  - Architecture diagrams
  - Previous audit results
  - Incident reports
  - Training records
  |
  v
[Schedule Assessment Activities]
  |
  v
End
```

## Workflow 2: Current State Scoring

```
Start
  |
  v
[For Each CSF Function (GV, ID, PR, DE, RS, RC)]
  |
  v
  [For Each Category in Function]
    |
    v
    [For Each Subcategory]
      |
      v
      [Evaluate Against Tier Criteria]
        |
        +--> Tier 1 (Partial)?
        |     - No formal process
        |     - Ad hoc practices
        |     - Limited documentation
        |
        +--> Tier 2 (Risk-Informed)?
        |     - Approved by management
        |     - Inconsistent application
        |     - Some documentation
        |
        +--> Tier 3 (Repeatable)?
        |     - Formal policies
        |     - Consistent implementation
        |     - Regular updates
        |     - Metrics captured
        |
        +--> Tier 4 (Adaptive)?
              - Continuous improvement
              - Real-time adaptation
              - Advanced automation
              - Lessons learned integrated
      |
      v
      [Document Score and Evidence]
      |
      v
      [Record Strengths and Gaps]
    |
    v
  [Calculate Category Average Score]
  |
  v
[Calculate Function Average Score]
  |
  v
[Generate Current Profile Heatmap]
  |
  v
End
```

## Workflow 3: Gap Analysis

```
Start
  |
  v
[Define Target Profile]
  - Executive input on risk appetite
  - Industry benchmark comparison
  - Regulatory requirements
  - Available resources
  |
  v
[Compare Current vs Target for Each Subcategory]
  Gap = Target Tier - Current Tier
  |
  v
[Classify Gaps]
  |
  +--> Critical (Gap >= 2 tiers, high-risk area)
  +--> Significant (Gap = 1 tier, high-risk area)
  +--> Moderate (Gap = 1 tier, medium-risk area)
  +--> Minor (Gap = 1 tier, low-risk area)
  +--> None (current meets or exceeds target)
  |
  v
[Prioritize Based On]
  - Risk reduction impact
  - Regulatory requirements
  - Implementation effort
  - Cost and resource availability
  - Dependencies on other improvements
  |
  v
[Generate Prioritized Gap Report]
  |
  v
End
```

## Workflow 4: Improvement Roadmap

```
Start
  |
  v
[Quick Wins (0-3 months)]
  - Low effort, high impact
  - Policy updates and documentation
  - Enable existing but unused capabilities
  - Awareness training refresh
  |
  v
[Medium-Term (3-12 months)]
  - Tool deployment and configuration
  - Process formalization
  - Staff training and certification
  - Vendor security programme establishment
  |
  v
[Long-Term (12-24 months)]
  - Architecture redesign
  - Advanced automation (SOAR, AI-driven)
  - Cultural transformation
  - Advanced threat detection capabilities
  |
  v
[Assign Ownership and Budget]
  - Initiative owner for each item
  - Resource allocation
  - Budget approval
  - Success metrics
  |
  v
[Track Progress Quarterly]
  - Milestone reviews
  - Reassess maturity scores
  - Adjust roadmap as needed
  |
  v
End
```
