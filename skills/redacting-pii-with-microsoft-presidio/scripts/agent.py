#!/usr/bin/env python3
"""
PII redaction/audit CLI built on Microsoft Presidio.

Two subcommands:
    redact  -- detect PII and write a de-identified copy + a JSON findings report
    audit   -- detect only; print entity counts/offsets, write no rewrite

The findings report records entity types, counts, and offsets only -- never the
raw PII values -- so it is safe to retain as evidence of what was removed.

Dependencies:
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg

Docs: https://microsoft.github.io/presidio/
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from pathlib import Path

try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(
        "Presidio is not installed. Run:\n"
        "  pip install presidio-analyzer presidio-anonymizer\n"
        "  python -m spacy download en_core_web_lg\n"
    )
    raise

DEFAULT_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    "IBAN_CODE", "IP_ADDRESS", "LOCATION", "US_SSN", "UK_NINO",
]

# operator name -> params factory; keeps the CLI to a safe, documented subset.
OPERATORS = {
    "replace": lambda: OperatorConfig("replace", {"new_value": "<REDACTED>"}),
    "redact": lambda: OperatorConfig("redact", {}),
    "hash": lambda: OperatorConfig("hash", {"hash_type": "sha256"}),
    "mask": lambda: OperatorConfig(
        "mask", {"masking_char": "*", "chars_to_mask": 8, "from_end": True}
    ),
}


def build_analyzer(custom_patterns: list[tuple[str, str]] | None) -> AnalyzerEngine:
    """Return an AnalyzerEngine, optionally with extra regex recognisers.

    custom_patterns: list of (ENTITY_TYPE, regex) pairs.
    """
    analyzer = AnalyzerEngine()
    for entity, regex in custom_patterns or []:
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity=entity,
                patterns=[Pattern(name=f"{entity.lower()}_custom", regex=regex, score=0.85)],
            )
        )
    return analyzer


def analyze_text(analyzer, text, entities, threshold):
    return analyzer.analyze(
        text=text, language="en", entities=entities or None, score_threshold=threshold
    )


def summarize(results, with_offsets=False):
    counts = Counter(r.entity_type for r in results)
    out = {"total": len(results), "by_entity": dict(sorted(counts.items()))}
    if with_offsets:
        out["spans"] = [
            {"entity": r.entity_type, "start": r.start, "end": r.end, "score": round(r.score, 3)}
            for r in results
        ]
    return out


def parse_custom(values):
    pairs = []
    for v in values or []:
        if "=" not in v:
            raise SystemExit(f"--custom expects ENTITY=regex, got: {v!r}")
        entity, regex = v.split("=", 1)
        pairs.append((entity.strip(), regex))
    return pairs


def cmd_redact(args):
    text = Path(args.infile).read_text(encoding="utf-8")
    analyzer = build_analyzer(parse_custom(args.custom))
    anonymizer = AnonymizerEngine()

    results = analyze_text(analyzer, text, args.entities, args.threshold)
    op = OPERATORS[args.operator]()
    clean = anonymizer.anonymize(
        text=text, analyzer_results=results, operators={"DEFAULT": op}
    ).text

    Path(args.outfile).write_text(clean, encoding="utf-8")
    report = summarize(results, with_offsets=True)
    report["input"] = args.infile
    report["output"] = args.outfile
    report["operator"] = args.operator

    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("total", "by_entity")}, indent=2))

    # verify: re-scan output for the same entity types
    residual = analyze_text(analyzer, clean, args.entities, args.threshold)
    if residual and args.operator in ("replace", "redact"):
        print(f"WARNING: {len(residual)} span(s) still detected after {args.operator}; "
              f"sample-review the output.", file=sys.stderr)


def cmd_audit(args):
    analyzer = build_analyzer(parse_custom(args.custom))
    if args.column:
        rows = list(csv.DictReader(io.StringIO(Path(args.infile).read_text(encoding="utf-8"))))
        if not rows or args.column not in rows[0]:
            raise SystemExit(f"Column {args.column!r} not found in {args.infile}")
        texts = [r.get(args.column, "") for r in rows]
    else:
        texts = [Path(args.infile).read_text(encoding="utf-8")]

    agg = Counter()
    for t in texts:
        for r in analyze_text(analyzer, t, args.entities, args.threshold):
            agg[r.entity_type] += 1
    print(json.dumps({"records": len(texts), "total": sum(agg.values()),
                      "by_entity": dict(sorted(agg.items()))}, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--in", dest="infile", required=True, help="input file")
    common.add_argument("--entities", nargs="*", default=DEFAULT_ENTITIES,
                        help="entity types to detect (default: common PII set)")
    common.add_argument("--threshold", type=float, default=0.5,
                        help="minimum confidence score (default 0.5)")
    common.add_argument("--custom", nargs="*", default=[],
                        help="extra recognisers as ENTITY=regex (repeatable)")

    r = sub.add_parser("redact", parents=[common], help="write a de-identified copy")
    r.add_argument("--out", dest="outfile", required=True)
    r.add_argument("--operator", choices=sorted(OPERATORS), default="replace")
    r.add_argument("--report", help="write JSON findings report here")
    r.set_defaults(func=cmd_redact)

    a = sub.add_parser("audit", parents=[common], help="detect only, no rewrite")
    a.add_argument("--column", help="for CSV input, scan this column")
    a.set_defaults(func=cmd_audit)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
