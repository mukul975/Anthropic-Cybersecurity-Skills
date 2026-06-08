# Attack Scenario: {scenario_name}

**Generated**: {timestamp}
**Entry Technique**: {entry_technique_id} - {entry_technique_name}
**Tactic**: {entry_tactic_id} - {entry_tactic_name}
**Depth**: {depth} steps
**Objective**: {objective}

## Scenario Overview

This attack scenario simulates a realistic adversary progression starting from **{entry_technique_name}**.
The path follows MITRE ATT&CK tactics through {total_steps} stages with {unique_techniques} distinct techniques.

**Total mapped skills**: {total_skills}

---

## Attack Chain

{% for step in steps %}
### Step {{ step.number }}: {{ step.technique_id }} - {{ step.technique_name }}
**Tactic**: {{ step.tactic_id }} - {{ step.tactic_name }}
**Score**: {{ step.score }}/100

_{{ step.description }}_

{% if step.skills %}
#### Mapped Skills
{% for s in step.skills %}
- {{ s.name }} ({{ s.predicate }})
{% endfor %}
{% endif %}

{% endfor %}

## Skill Coverage Summary

| Skill | Techniques Covered |
|-------|--------------------|
{skill_coverage_table}
