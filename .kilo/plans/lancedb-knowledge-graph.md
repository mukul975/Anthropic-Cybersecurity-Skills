# Plan: Assess Schema/JSON-LD/Graph Production & Build Knowledge Graph in LanceDB

## 1. Current State Assessment

### Existing Artifacts
| Artifact | Format | Content | Schema/LD/Graph role |
|----------|--------|---------|----------------------|
| `index.json` | JSON | 754 skill records (name, description, domain, path) | Core schema registry |
| `skills/*/SKILL.md` | Markdown + YAML frontmatter | name, description, domain, subdomain, tags, version, author, license, plus framework arrays: `atlas_techniques`, `nist_csf`, `mitre_attack` | Extracted schema per skill |
| `mappings/attack-navigator-layer.json` | JSON (ATT&CK Navigator v4.5) | Technique coverage scores, skill list metadata per technique | Graph edges: Skill ↔ ATT&CK Technique |
| `mappings/nist-csf/csf-alignment.md` | Markdown tables | Subdomain → NIST CSF function/category alignment | Graph edges: Subdomain ↔ CSF Category |
| `mappings/owasp/` | Markdown | OWASP references | Graph edges: Skill ↔ OWASP |
| `mappings/mitre-attack/` | Various | MITRE ATT&CK references | Graph edges: Skill ↔ ATT&CK Technique |
| `.codegraph/codegraph.db` | SQLite (CodeGraph) | Project code graph: nodes (import, function, variable, method, file, class) + edges | **Code-level** graph only, backend locked to SQLite |

### Key Findings
- **Schema** is currently implicit: YAML frontmatter fields in every SKILL.md + the flat `index.json` structure.
- **JSON-LD** is not produced anywhere today. `attack-navigator-layer.json` is close to linked-data but uses MITRE's proprietary Navigator schema, not generic JSON-LD.
- **Graph** exists at two levels:
  1. **Code graph**: CodeGraph tool indexes Python/YAML code as nodes/edges in SQLite.
  2. **Concept graph**: Framework mappings (ATT&CK, NIST CSF, ATLAS, D3FEND, AI RMF) create implicit relationships between skills → techniques → tactics → sub-techniques. These are flat markdown files, not a traversable graph.
- **No LanceDB** currently exists in the repo.

---

## 2. Proposed Approach

### Goal
Build a **semantic knowledge graph** in LanceDB that turns the skill library into a traversable, queryable knowledge base of cybersecurity concepts — supplements (not replaces) the existing SQLite code graph.

### Phase 1: Schema Definition & Normalization
1. Define a **canonical JSON-LD `@context`** for security skill entities:
   - `Skill`, `Technique`, `Tactic`, `Category`, `Control`, `Framework`
   - Reuse existing vocabularies where possible (`schema.org`, `STIX 2.1`, `dcterms`)
2. Extract all skill frontmatter + framework references into a **normalized schema**:
   - `Skill { id, name, description, domain, subdomain, tags, references[] }`
   - `Technique { id, name, tactic, framework, skills[] }`
   - `Framework { id, name, version, type }`
3. Add a `schemas/` directory under `mappings/` for canonical schema files.

### Phase 2: JSON-LD Production Pipeline
1. Write a Python script (`tools/build-jsonld.py`) that:
   - Reads `index.json` + all SKILL.md frontmatter
   - Cross-references `mappings/mitre-attack/`, `mappings/nist-csf/`, `mappings/owasp/`
   - Emits **JSON-LD documents** for each entity:
     - One per skill (`{@id: ex:skill/analyzing-indicators-of-compromise, @type: Skill}`)
     - One per technique
     - Relationships as `https://schema.org/knows`, or domain-specific predicates like `implements`, `mitigates`, `references`
   - Output: `mappings/jsonld/` directory

### Phase 3: LanceDB Knowledge Graph Construction
1. Install LanceDB Python SDK in the repo.
2. Write `tools/build-lancedb.py` that:
   - Reads the JSON-LD documents (or directly parses SKILL.md + mappings)
   - Creates a LanceDB table with the following schema:
     - `id: str` (primary, e.g. `skill:analyzing-indicators-of-compromise`)
     - `type: str` (enum: `Skill`, `Technique`, `Tactic`, `Category`, `Subdomain`, `Control`)
     - `name: str`
     - `description: str`
     - `framework: str` (e.g. `mitre-attack`, `nist-csf`, `d3fend`, `atlas`, `ai-rmf`)
     - `framework_id: str` (e.g. `T1071`, `DE.CM`, `D3-NTA`)
     - `tags: list[str]`
     - `relationships: list[str]` (JSON array of related entity IDs)
     - `vector: [768] float32` — embedding for semantic search
   - Also create a **relationships (edge) table**:
     - `source: str` → `target: str` with `predicate: str` and `weight: float`
   - Embedding strategy: Use `skill` type text fields as input to a sentence-transformer or `ai-sdk` compatible embedding model.
   - Store LanceDB database at `.codegraph/knowledge_graph.lance/`

### Phase 4: Query Layer
1. Add semantic search: `tools/query-graph.py --query "detect credential dumping" --top-k 5`
2. Add graph traversal: `tools/query-graph.py --walk T1071 --depth 2`
3. Add framework filtering: `tools/query-graph.py --framework mitre-attack --tactic TA0006`
4. Add impact analysis: `tools/query-graph.py --impact "analyzing-indicators-of-compromise"`

### Phase 5: Integration with Existing CodeGraph
1. LanceDB graph complements the SQLite code graph:
   - SQLite codegraph: code structure (functions, imports, classes)
   - LanceDB knowledge graph: security concepts (frameworks, skills, techniques, controls)
2. Add optional `codegraph serve` integration to expose LanceDB endpoints as MCP tools.

---

## 6. Ingestion Pipeline Design

### Phase 6: Incremental Updates & Framework Expansion

#### 6.1 Incremental Update Strategy
Create `tools/update-graph.py` that:
- Detects changed/added/removed skills via git diff since last ingest
- Updates only affected entities in the LanceDB tables
- Maintains a `.codegraph/.ingest-state.json` with:
  - `last_run`: ISO timestamp
  - `processed_skills`: set of skill paths
  - `graph_version`: semantic version of the graph schema

Implementation approach:
```
# Fast path: Only process changed skills
CHANGED_SKILLS=$(git diff --name-only HEAD~1 HEAD -- skills/*/SKILL.md)
for skill in $CHANGED_SKILLS; do
    python3 tools/update-graph.py --skill "$skill"
done
```

#### 6.2 Framework Expansion
Current: MITRE ATT&CK + NIST CSF (with ATLAS references in skill frontmatter)

To add:
- **OWASP**: Parse `mappings/owasp/README.md` for OWASP Top 10 mappings
- **D3FEND**: Import from `mappings/d3fend/` if available, or generate from skill-tag correlation
- **AI RMF**: Import from `mappings/ai-rmf/` for AI security controls

Script extension in `build-jsonld.py`:
```python
def build_owasp_entities():
    """Parse OWASP references and create entities."""
    # Extract from mappings/owasp/README.md

def build_d3fend_entities():
    """Generate D3FEND entities from security technique patterns."""
    # Map defensive techniques to skills
```

#### 6.3 CI/CD Automation
Add `.github/workflows/knowledge-graph.yml`:
```yaml
name: Update Knowledge Graph
on:
  push:
    branches: [main]
    paths:
      - 'skills/**'
      - 'mappings/**'
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r tools/requirements-kg.txt
      - run: python3 tools/build-jsonld.py
      - run: python3 tools/build-lancedb.py
      - run: mkdir -p dist && cp -r .codegraph/knowledge_graph.lance dist/
      - uses: actions/upload-artifact@v4
        with:
          name: knowledge-graph
          path: dist/knowledge_graph.lance
```

#### 6.4 External Sources Integration
For live ATT&CK data:
- Fetch latest ATT&CK STIX from `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json`
- Cross-reference with skill mappings to enrich technique descriptions and tactics

For D3FEND:
- Use `https://d3fend.mitre.org/api/` or parse NVD/CVE references

---

## 3. Files to Create/Modify

```
mappings/
  schemas/
    skill-schema.json          # Canonical JSON Schema for Skill entity
    technique-schema.json      # Canonical JSON Schema for Technique entity
    owasp-schema.json         # JSON Schema for OWASP entities
  jsonld/
    context.jsonld             # JSON-LD @context
    skills.jsonld              # All skills as JSON-LD (bundled)
    techniques.jsonld          # All techniques as JSON-LD (bundled)
    owasp.jsonld               # OWASP Top 10 entities

tools/
  build-jsonld.py              # Extract + normalize → JSON-LD
  build-lancedb.py             # Build LanceDB tables from JSON-LD
  query-graph.py               # Query LanceDB knowledge graph
  update-graph.py              # Incremental update script (planned)
  validate-skill.py            # (exists, no change unless needed)

.codegraph/
  knowledge_graph.lance/       # LanceDB database (gitignored)
  .ingest-state.json           # Last update timestamp + processed skills
```

---

## 4. Key Decisions & Tradeoffs

| Decision | Options | Recommendation |
|----------|---------|---------------|
| Embedding model | Local (sentence-transformers) vs Managed (OpenAI) | Start with local (no external deps, aligns with stdlib-only tooling); allow configurable override |
| LanceDB storage path | `mappings/` vs `.codegraph/` | `.codegraph/knowledge_graph.lance/` — keeps derived data local, already gitignored |
| JSON-LD granularity | One large bundle vs one file per entity | Bundled top-level files for simplicity; individual URI dereferencable via in-memory index |
| Graph predicates | Generic (relatedTo) vs domain-specific | Domain-specific: `implements`, `mitigates`, `references`, `belongsToTactic`, `alignedWith` |
| Relationship source of truth | SKILL.md frontmatter arrays only vs enriched from mappings | Primary: frontmatter arrays; secondary: enrich from `mappings/` directories |

---

## 5. Implementation Status

### Completed (Phase 1-4)
- ✅ `mappings/schemas/skill-schema.json` - Canonical schema for skills
- ✅ `mappings/schemas/technique-schema.json` - Canonical schema for techniques
- ✅ `mappings/schemas/owasp-schema.json` - Canonical schema for OWASP entities
- ✅ `mappings/jsonld/context.jsonld` - JSON-LD context with vocabulary
- ✅ `mappings/jsonld/skills.jsonld` - 754 skill entities
- ✅ `mappings/jsonld/techniques.jsonld` - 218 ATT&CK techniques + 46 NIST CSF categories
- ✅ `mappings/jsonld/owasp.jsonld` - 10 OWASP Top 10 category entities
- ✅ `tools/build-jsonld.py` - JSON-LD production script (extended with OWASP parsing)
- ✅ `tools/build-lancedb.py` - LanceDB construction script (extended with OWASP support)
- ✅ `tools/query-graph.py` - Query interface (semantic search, walk, framework filter, impact analysis)
- ✅ `tools/update-graph.py` - Incremental update script
- ✅ `.github/workflows/knowledge-graph.yml` - CI/CD automation
- ✅ `.codegraph/.gitignore` - Updated to exclude `knowledge_graph.lance/`

### Remaining (Future Enhancements)
- 🔜 Support for D3FEND framework entities (requires mappings/d3fend/ directory)
- 🔜 Support for AI RMF framework entities (requires mappings/ai-rmf/ directory)
