# Plan: Attack Scenario Generator

## Overview

Build an `attackScenarioGenerator` that creates realistic attack simulations by traversing the LanceDB knowledge graph, leveraging MITRE ATT&CK technique relationships to produce step-by-step attack narratives with skill references.

## Current Assets Available

| Asset | Count | Usage |
|-------|-------|-------|
| Skills | 754 | Defensive/actionable skills (mitigations, detections, responses) |
| ATT&CK Techniques | 218 | Adversarial techniques for building attack paths |
| NIST CSF Categories | 46 | Compliance controls mapping |
| OWASP Categories | 10 | Web application security risks |
| Relationships | 7,098 | Skill↔Technique and Technique↔Skill mappings |

## Proposed Design

### Core Concept
Generate attack scenarios by:
1. **Starting point**: Initial access technique (phishing, exploit, valid accounts)
2. **Tactical flow**: Follow MITRE ATT&CK tactics TA0001→TA0008→TA0010
3. **Path optimization**: Select techniques based on coverage scores and skill availability
4. **Output**: Structured scenario with techniques, prerequisites, and mapped skills

### Files to Create

```
tools/
  attack-scenario-generator.py    # Main scenario generation script
  templates/
    scenario-template.md          # Markdown template for scenario output
    atomic-workflow.json        # Structured output format
```

### Implementation Phases

#### Phase 1: ATT&CK Tactic Sequence Engine
Build a directed graph of tactic flow:
- TA0001 (Initial Access) → TA0002 (Execution) → TA0003 (Persistence) → ... → TA0010 (Exfiltration)
- Parse technique→tactic relationships from ATT&CK Navigator layer or fetch STIX data
- Create `tactic_sequence.json` mapping valid tactic progressions

#### Phase 2: Technique Selection Logic
For each tactic, select techniques based on:
- `score` field from attack-navigator-layer.json (higher = more covered skills)
- Skill count (minimum 2+ skills for actionable guidance)
- Tactic coherence (parent technique vs sub-technique)

#### Phase 3: Scenario Assembly
Generate scenarios with:
- Entry technique (user-specified or auto-selected)
- Technique chain (3-7 steps based on depth parameter)
- Mapped skills for each technique (detections, mitigations)
- Prerequisites (what access/conditions needed)
- Commands/tool suggestions from skill workflows

#### Phase 4: Output Formats
Support multiple output formats:
- Markdown (human-readable report)
- JSON (structured data for automation)
- YAML (for integration with threat emulation tools)

## Implementation Status

### Completed

- Created `tools/attack-scenario-generator.py` (387-line CLI with JSON/Markdown/YAML output)
- Created `tools/templates/scenario-template.md` (Jinja2 markdown template)
- Created `mappings/jsonld/tactic-mapping.json` (manual ATT&CK tactic-to-technique mapping)
- Knowledge graph and JSON-LD generation already in place via `tools/build-lancedb.py` / `tools/build-jsonld.py`
- `.codegraph/` directory and LanceDB tables exist locally

### Remaining

- `tools/templates/atomic-workflow.json` is referenced in the plan but not yet created
- `tools/attack-scenario-generator.py.bak` was created during development and should be removed
- Verify scenario generation end-to-end against the existing `.codegraph/knowledge_graph.lance` database

## Updated CLI Interface

```bash
# Generate a phishing-based attack scenario
python tools/attack-scenario-generator.py --entry T1566.001 --depth 5 --format markdown

# Generate all-paths scenario from credential access
python tools/attack-scenario-generator.py --entry T1003 --tactic TA0006 --format json

# Generate scenario with specific objectives
python tools/attack-scenario-generator.py --objective "domain-dominance" --format yaml
```

## Key Design Decisions

| Decision | Options | Recommendation |
|----------|---------|---------------|
| Graph traversal | DFS vs BFS vs Weighted | Weighted by technique coverage score |
| Output format | Markdown vs JSON-first | Both - JSON as default, MD as readable format |
| Technique source | Local mappings vs live STIX | Local mappings (attack-navigator-layer.json) |
| Skills inclusion | All related vs top-N | Top 3 related skills by tag relevance |
| Scenario length | Fixed vs variable | Variable via `--depth` parameter |

## Implementation Notes

- Leverage existing `tools/query-graph.py` for relationship lookups
- Reuse `sentence-transformers` embeddings for skill-text similarity
- ATT&CK tactic IDs extracted from existing technique metadata or STIX
- Technique→tactic mapping stored in `mappings/jsonld/tactic-mapping.json`