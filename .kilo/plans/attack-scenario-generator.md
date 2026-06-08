# Plan: Attack Coverage Verification and Cleanup

## Status

- Code and tooling are functional end-to-end against the local graph.
- `TACTIC_SEQUENCE` in `tools/attack-scenario-generator.py` is expanded to the full enterprise tactic flow.
- Tactic metadata is preserved in `mappings/jsonld/techniques.jsonld`, so coverage can now be verified programmatically.
- Syntax checks pass for all modified tools.
- Knowledge graph: **361 techniques** (218 original + 143 added), **754 skills**, **7241 relationships**, **320 techniques with tactic metadata**.

## Coverage Target Clarification

The stated goal is **"150% of MITRE coverage."** Current interpretation and open question:

| Baseline | Current | Target (150%) |
|----------|---------|----------------|
| Techniques in graph | 361 | Unknown |
| Techniques in mapping | 340 | Unknown |

**Open question for user:**
- Does "150%" mean: (a) 150% of the **current graph size** (expand from 361 to ~540 techniques), (b) 150% of **enterprise ATT&CK** (~600 enterprise techniques → ~900), or (c) full coverage of **Enterprise + Mobile + ICS** matrices combined?
- Skills currently reference 271 Enterprise, 15 ICS, and 0 Mobile techniques. Do we scale by adding skills for gaps, or only by adding new techniques?

This clarification determines whether the next work item focuses on:
- **Option A**: Expand the existing `mappings/jsonld/tactic-mapping.json` to include every Enterprise technique (~600) with at least one skill mapped, or
- **Option B**: Add Mobile (`M*`) and ICS (`T08*`) techniques referenced by skills, or
- **Option C**: Include MITRE ATT&CK pre-attack/intelligence requirements (TA00) alongside enterprise.

## Remaining Work

### 1. Coverage Gate Tool

Add a verification script that:
- Parses `mappings/jsonld/tactic-mapping.json` (authoritative technique list)
- Opens `.codegraph/knowledge_graph.lance`
- Confirms every referenced technique exists as a node with a populated `tactic` field
- Reports **missing techniques** (in mapping but not graph), **orphaned nodes** (in graph but not mapping), and **tactic coverage %**
- Exits non-zero when coverage regresses

Suggested CLI:
```bash
python tools/coverage-audit.py [--strict] [--report json|text]
```

### 2. Generator Hardening

- `generate_scenario` should fail fast when the graph or mapping is mismatched
- Add `--validate` flag to run the coverage gate inline before generating scenarios
- Expand Markdown fallback to produce readable content even with missing template/Jinja2
- Confirm or deprecate `atomic-workflow.json` path (template file already exists)

### 3. Tactic Mapping Expansion (pending target clarification)

If the user confirms target option A/B/C:
- Scripted augmentation of `mappings/jsonld/tactic-mapping.json` to fill gaps from the official ATT&CK matrix
- Rebuild pipeline: `python tools/build-jsonld.py && python tools/build-lancedb.py`
- Verify 150% target is met via the coverage gate

### 4. Toolchain Hygiene

- Remove `tools/attack-scenario-generator.py.bak`
- Verify `.codegraph/.gitignore` excludes `knowledge_graph.lance/`
- Ensure `tools/build-jsonld.py` and `tools/build-lancedb.py` share a single source of truth for tactic mapping

## Objective

Bring the workspace to a verifiable green state where coverage is tracked, updatable, and protected from accidental regression.
