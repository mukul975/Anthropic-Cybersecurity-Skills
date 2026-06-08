# Plan: Fix ATT&CK Tactic-Mapping Gaps

## Objective

Reduce the 93 ATT&CK techniques that are unmapped or have empty tactic metadata in the knowledge graph, so `coverage-audit.py` reports higher coverage and `attack-scenario-generator.py` can build complete chains. Additionally, backfill ATLAS technique tactic metadata from `atlas.mitre.org` data so ATLAS nodes have proper tactic assignments.

## Root Cause

- `mappings/jsonld/tactic-mapping.json` initially had ~260 unique techniques across 14 tactics, with many duplicates inflating line counts.
- 194 technique IDs in `attack-navigator-layer.json` were absent from the mapping.
- Out of those 194, 165 were Enterprise ATT&CK techniques missing tactic assignments; 29 were ICS-techniques (T08xx/T14xx ranges) with no MITRE Enterprise tactic data.
- The mapping also contained duplicates and tautological IDs (technique IDs matching parent categories like "T1059" listed alongside "T1059.001").

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
   - Added both new tactic buckets: `TA0010: Exfiltration` and `TA0112: Defense Impairment`.
   - Removed duplicate and tautological technique IDs during merge (e.g., T1059, T1105, T1106 were being listed multiple times per tactic without adding new coverage).
   - Final unique technique count: 425 (up from 260).

3. **Rebuild knowledge graph**
   - Re-ran `tools/build-jsonld.py` to regenerate `techniques.jsonld`.
   - Re-ran `tools/build-lancedb.py` to populate `tactic` fields in LanceDB.

4. **Validate**
   - `coverage-audit.py --framework mitre-attack`: Enterprise ATT&CK coverage improved from ~320/361 with tactics to 336/361.
   - Empty tactic count reduced from 41 to 25.
   - Remaining 25 empty-tactic nodes are all ICS techniques (T0801–T0888, T1406–T1426, T1626.001, T1633, T1635, T1655.001) with no Enterprise ATT&CK mapping.
   - `attack-scenario-generator.py --validate` works for all valid Enterprise entries.

## ATLAS Tactic Backfill

The ATLAS framework has its own tactic structure separate from ATT&CK:

- ATLAS tactics use IDs like `AML.TA0000` through `AML.TA0008` (9 tactics total)
- Current ATLAS JSON-LD (`mappings/jsonld/atlas.jsonld`) has 21 techniques with empty `tactic` fields
- `build-jsonld.py` builds ATLAS entities from skill frontmatter only, with no tactic assignment
- Tactics are not stored in a mapping file (no `atlas-tactic-mapping.json` exists)
- The attack-scenario-generator has a hardcoded `_ATLAS_TACTIC_SEQUENCE` list

**ATLAS tactics (from `dist/v6/ATLAS-latest.yaml`):**
- `AML.TA0000` - AI Model Access
- `AML.TA0001` - AI Attack Staging
- `AML.TA0002` - Reconnaissance
- `AML.TA0003` - Resource Development
- `AML.TA0004` - Initial Access
- `AML.TA0005` - Execution
- `AML.TA0006` - Persistence
- `AML.TA0007` - Privilege Escalation
- `AML.TA0008` - Collection

**Approach for ATLAS:**
1. Create `mappings/jsonld/atlas-tactic-mapping.json` with technique→tactic assignments sourced from the official ATLAS YAML
2. Update `build-jsonld.py` to populate ATLAS tactic fields from this mapping
3. Rebuild JSON-LD and LanceDB
4. Verify ATLAS techniques have tactics in the graph

## Out of Scope

- ICS/EPS technique mappings (T08xx, T14xx) — outside MITRE Enterprise ATT&CK scope.
- Non-ATT&CK frameworks (ATLAS, AI RMF, OWASP).

## Deliverable

- `mappings/jsonld/tactic-mapping.json`: expanded from 260 to 425 unique techniques, 14→16 tactics, all deduplicated.
- `mappings/jsonld/techniques.jsonld`: rebuilt with updated tactic assignments.
- `.codegraph/knowledge_graph.lance`: rebuilt with 93.1% Enterprise ATT&CK tactic coverage (336/361).
- `mappings/jsonld/atlas-tactic-mapping.json`: new file with ATLAS technique→tactic assignments from official ATLAS data.
- `mappings/jsonld/atlas.jsonld`: rebuilt with ATLAS tactic fields populated.
- Tactics sourced from official MITRE CTI and ATLAS data, not manually invented.

## Todo List

- [x] Fix coverage-audit.py query to use Python-side filtering for LanceDB
- [x] Fix .github/workflows/knowledge-graph.yml build job artifact upload
- [x] Update attack-scenario-generator.py with --framework and --cross-framework flags
- [x] Fix coverage-audit.py type filters to match stored values
- [x] Update tactic-mapping.json with missing MITRE ATT&CK techniques
- [x] Rebuild JSON-LD and LanceDB graph for ATT&CK
- [ ] Download official ATLAS data (dist/v6/ATLAS-latest.yaml)
- [ ] Extract ATLAS technique→tactic mappings from YAML
- [ ] Create mappings/jsonld/atlas-tactic-mapping.json
- [ ] Update build-jsonld.py to populate ATLAS tactic fields
- [ ] Rebuild ATLAS JSON-LD and LanceDB graph
- [ ] Run final end-to-end verification for both frameworks
