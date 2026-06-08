# MITRE ATLAS Mapping

## Source

This mapping seeds MITRE Adversarial Threat Landscape for Artificial-Intelligence Systems (ATLAS) entities from skill frontmatter references (`atlas_techniques`) discovered in the repository. This is a v1 implementation; future releases may enrich the mapping by fetching the official ATLAS matrix.

## Coverage

- Current IDs are captured from `skills/*/SKILL.md` frontmatter.
- Update `mappings/jsonld/atlas.jsonld` by re-running `python tools/build-jsonld.py`.
- Tactic metadata is empty for v1 and will be populated after importing the official ATLAS matrix.
