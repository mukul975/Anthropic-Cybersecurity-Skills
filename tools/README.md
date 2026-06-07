# Attack Scenario Generator

Tools for generating realistic attack simulations by traversing the LanceDB knowledge graph.

## Files

- `attack-scenario-generator.py` — Main CLI entry point
- `templates/scenario-template.md` — Markdown output template
- `templates/atomic-workflow.json` — Structured output mode

## Prerequisites

```bash
pip install pyyaml
```

The knowledge graph must exist (`.codegraph/knowledge_graph.lance`).

## Usage

```bash
python tools/attack-scenario-generator.py --entry T1566.001 --depth 5 --format markdown
python tools/attack-scenario-generator.py --entry T1003 --tactic TA0006 --format json
python tools/attack-scenario-generator.py --objective "domain-dominance" --format yaml
```
