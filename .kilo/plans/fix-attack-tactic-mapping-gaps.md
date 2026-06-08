# Plan: Fix ATT&CK Tactic-Mapping Gaps

## Objective

The ATT&CK tactic-mapping gaps have been fixed. `coverage-audit.py` now reports 93.1% tactic coverage (336/361 techniques). All ATLAS techniques have tactic metadata assigned from official ATLAS YAML data.

## Root Cause

- `mappings/jsonld/tactic-mapping.json` initially had ~260 unique techniques across 14 tactics, with many duplicates inflating line counts.
- 194 technique IDs in `attack-navigator-layer.json` were absent from the mapping.
- Out of those 194, 165 were Enterprise ATT&CK techniques missing tactic assignments; 29 were ICS-techniques (T08xx/T14xx ranges) with no MITRE Enterprise tactic data.
- The mapping also contained duplicates and tautological IDs (technique IDs matching parent categories like "T1059" listed alongside "T1059.001").
- Final ATT&CK tactics count: 16 (added `TA0112: Defense Impairment` to the original 15 — TA0010/Exfiltration was already present)

## Approach

Source authoritative tactic assignments from MITRE CTI `enterprise-attack.json` kill chain phases, deduplicate the mapping, and rebuild the knowledge graph.

## Steps

1. **Inventory gaps**
   - Diff `attack-navigator-layer.json` (361 techniques) against `tactic-mapping.json` (260 unique IDs).
   - Identified 194 missing IDs: 165 Enterprise + 29 ICS.
   - Cross-referenced with LanceDB nodes: all 194 were present in the graph.

2. **Populate missing tactics from official data**
    - Downloaded MITRE CTI `enterprise-attack.json` (25,842 objects).
    - Extracted kill chain phases for all 858 attack-pattern objects.
    - Mapped each phase name to canonical TA using: `stealth → TA0005`, `defense-impairment → TA0112`, etc.
    - Expanded tactics from 15 to 16: added `TA0112: Defense Impairment` (v19.1 split Defense Evasion into Stealth and Defense Impairment).
    - Removed duplicate and tautological technique IDs during merge (e.g., T1059, T1105, T1106 were being listed multiple times per tactic without adding new coverage).
    - Final unique technique count: 425 (up from 260).

3. **Rebuild knowledge graph**
   - Re-ran `tools/build-jsonld.py` to regenerate `techniques.jsonld`.
   - Re-ran `tools/build-lancedb.py` to populate `tactic` fields in LanceDB.

4. **Validate**
    - `coverage-audit.py --framework mitre-attack`: 336/361 ATT&CK techniques in graph have tactic metadata (93.1% coverage).
    - 93 techniques in tactic-mapping.json are missing from graph (these are in CTI but not in navigator layer).
    - Empty tactic count: 25 (all ICS techniques: T0801–T0888, T1406–T1426, T1626.001, T1633, T1635, T1655.001).
    - `attack-scenario-generator.py --validate` works for all ATT&CK techniques with tactics.
    - ATLAS coverage: 100% (all 21 techniques have tactic assignments).

## ATLAS Tactic Backfill

The ATLAS framework has its own tactic structure separate from ATT&CK:

- ATLAS tactics use IDs like `AML.TA0000` through `AML.TA0015` (16 tactics total per official YAML)
- All 21 ATLAS techniques referenced in skills have tactic metadata assigned via `atlas-tactic-mapping.json`
- `atlas-tactic-mapping.json` contains 170 technique mappings across 101 unique base ATLAS techniques
- `build-jsonld.py` populates ATLAS tactic fields from the mapping file
- Tactics are now stored in `mappings/jsonld/atlas-tactic-mapping.json` (created)
- The attack-scenario-generator uses the mapping for consistent tactic sequences

**ATLAS tactics (from `mappings/jsonld/atlas-tactic-mapping.json`):**
- `AML.TA0000` - AI Model Access
- `AML.TA0001` - AI Attack Staging
- `AML.TA0002` - Reconnaissance
- `AML.TA0003` - Resource Development
- `AML.TA0004` - Initial Access
- `AML.TA0005` - Execution
- `AML.TA0006` - Persistence
- `AML.TA0007` - Defense Evasion
- `AML.TA0008` - Discovery
- `AML.TA0009` - Collection
- `AML.TA0010` - Exfiltration
- `AML.TA0011` - Impact
- `AML.TA0012` - Privilege Escalation
- `AML.TA0013` - Credential Access
- `AML.TA0014` - Command and Control
- `AML.TA0015` - Lateral Movement

**ATLAS implementation completed:**
- `mappings/jsonld/atlas-tactic-mapping.json` created with technique→tactic assignments from official ATLAS YAML
- `build-jsonld.py` updated to populate ATLAS tactic fields from this mapping
- ATLAS JSON-LD and LanceDB rebuilt
- All 21 ATLAS techniques now have tactic fields populated (100% coverage)

## Out of Scope

- ICS/EPS technique mappings (T08xx, T14xx) — outside MITRE Enterprise ATT&CK scope.
- Non-ATT&CK/Non-ATLAS frameworks (AI RMF, OWASP).

## Deliverable

- `mappings/jsonld/tactic-mapping.json`: expanded from 260 to 425 unique techniques, 14→16 tactics, all deduplicated.
- `mappings/jsonld/techniques.jsonld`: rebuilt with updated tactic assignments.
- `.codegraph/knowledge_graph.lance`: rebuilt with 93.1% Enterprise ATT&CK tactic coverage (336/361 techniques).
- `mappings/jsonld/atlas-tactic-mapping.json`: new file with ATLAS technique→tactic assignments from official ATLAS YAML.
- `mappings/jsonld/atlas.jsonld`: rebuilt with all 21 ATLAS techniques having tactic fields populated.
- Tactics sourced from official MITRE CTI and ATLAS data, not manually invented.
- Remaining 25 uncovered techniques are ICS (T08xx/T14xx ranges), out of scope.

## Todo List

- [x] Fix coverage-audit.py query to use Python-side filtering for LanceDB
- [x] Fix .github/workflows/knowledge-graph.yml build job artifact upload
- [x] Update attack-scenario-generator.py with --framework and --cross-framework flags
- [x] Fix coverage-audit.py type filters to match stored values
- [x] Update tactic-mapping.json with missing MITRE ATT&CK techniques
- [x] Rebuild JSON-LD and LanceDB graph for ATT&CK
- [x] Create `mappings/jsonld/atlas-tactic-mapping.json` with technique→tactic assignments
- [x] Update build-jsonld.py to populate ATLAS tactic fields
- [x] Rebuild ATLAS JSON-LD and LanceDB graph
- [x] Run final end-to-end verification for both frameworks

## Post-Release Documentation Updates

- [x] Update `mappings/README.md`: tactic/technique counts to 16 tactics, 361 techniques
- [x] Update `mappings/atlas/README.md`: reflect populated tactic metadata
- [x] Update `README.md`: ATT&CK tactic count from 15 to 16
