# NIST AI RMF Mapping

## Source

This mapping seeds NIST AI Risk Management Framework entities from skill frontmatter references (`nist_ai_rmf`) in the repository. It tracks Govern / Map / Measure / Manage function references used by skills.

## Coverage

- Current IDs are captured from `skills/*/SKILL.md` frontmatter.
- Update `mappings/jsonld/ai-rmf.jsonld` by re-running `python tools/build-jsonld.py`.
- v1 stores only the referenced functions; future work may add categories and subcategories.
