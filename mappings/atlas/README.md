# MITRE ATLAS Mapping

## Source

This mapping seeds MITRE Adversarial Threat Landscape for Artificial-Intelligence Systems (ATLAS) entities from skill frontmatter references (`atlas_techniques`) discovered in the repository.

## Coverage

- Current IDs are captured from `skills/*/SKILL.md` frontmatter.
- Update `mappings/jsonld/atlas.jsonld` by re-running `python tools/build-jsonld.py`.
- All 21 ATLAS techniques have tactic metadata assigned from official ATLAS YAML (v6) via `mappings/jsonld/atlas-tactic-mapping.json`.
