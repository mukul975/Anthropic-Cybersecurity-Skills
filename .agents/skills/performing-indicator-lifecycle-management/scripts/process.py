#!/usr/bin/env python3
"""
Indicator Lifecycle Management Script

Manages IOC lifecycle: discovery, validation, deployment, monitoring, retirement.

Requirements: pip install requests

Usage:
    python process.py --import-iocs iocs.csv --output lifecycle_db.json
    python process.py --decay --db lifecycle_db.json
    python process.py --review --db lifecycle_db.json --output review_report.json
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta


class IOCLifecycleManager:
    def __init__(self):
        self.indicators = {}

    def add_indicator(self, ioc_type, value, source, confidence=50):
        key = f"{ioc_type}:{value}"
        self.indicators[key] = {
            "type": ioc_type, "value": value, "source": source,
            "confidence": confidence, "state": "discovered",
            "created": datetime.utcnow().isoformat(),
            "last_updated": datetime.utcnow().isoformat(),
            "hit_count": 0, "fp_count": 0, "last_seen": None,
        }

    def apply_decay(self):
        half_lives = {"ip": 30, "domain": 90, "hash": 365, "url": 60, "email": 180}
        for key, ioc in self.indicators.items():
            if ioc["state"] == "retired":
                continue
            hl = half_lives.get(ioc["type"], 90)
            age = (datetime.utcnow() - datetime.fromisoformat(ioc["created"])).days
            decay = 0.5 ** (age / hl)
            ioc["confidence"] = max(0, int(ioc["confidence"] * decay))
            if ioc["confidence"] < 10:
                ioc["state"] = "under_review"

    def review_indicators(self):
        review = {"retire": [], "keep": [], "boost": []}
        for key, ioc in self.indicators.items():
            age = (datetime.utcnow() - datetime.fromisoformat(ioc["created"])).days
            max_ages = {"ip": 90, "domain": 180, "hash": 730, "url": 120}
            max_age = max_ages.get(ioc["type"], 180)

            if age > max_age and ioc["hit_count"] == 0:
                review["retire"].append(key)
                ioc["state"] = "retired"
            elif ioc["fp_count"] > 3:
                review["retire"].append(key)
                ioc["state"] = "retired"
            elif ioc["hit_count"] > 5:
                review["boost"].append(key)
                ioc["confidence"] = min(100, ioc["confidence"] + 10)
            else:
                review["keep"].append(key)
        return review

    def get_stats(self):
        states = {}
        for ioc in self.indicators.values():
            states[ioc["state"]] = states.get(ioc["state"], 0) + 1
        return {
            "total": len(self.indicators),
            "by_state": states,
            "avg_confidence": (
                sum(i["confidence"] for i in self.indicators.values()) / len(self.indicators)
                if self.indicators else 0
            ),
        }

    def load(self, filepath):
        with open(filepath) as f:
            self.indicators = json.load(f)

    def save(self, filepath):
        with open(filepath, "w") as f:
            json.dump(self.indicators, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="IOC Lifecycle Manager")
    parser.add_argument("--import-iocs", help="CSV file with IOCs")
    parser.add_argument("--decay", action="store_true", help="Apply confidence decay")
    parser.add_argument("--review", action="store_true", help="Review indicators")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--db", default="lifecycle_db.json", help="Database file")
    parser.add_argument("--output", default="lifecycle_report.json")
    args = parser.parse_args()

    mgr = IOCLifecycleManager()
    try:
        mgr.load(args.db)
    except FileNotFoundError:
        pass

    if args.import_iocs:
        with open(args.import_iocs) as f:
            reader = csv.DictReader(f)
            for row in reader:
                mgr.add_indicator(
                    row.get("type", "ip"), row.get("value", ""),
                    row.get("source", "import"), int(row.get("confidence", 50)),
                )
        mgr.save(args.db)

    if args.decay:
        mgr.apply_decay()
        mgr.save(args.db)

    if args.review:
        result = mgr.review_indicators()
        mgr.save(args.db)
        print(json.dumps(result, indent=2))

    if args.stats:
        print(json.dumps(mgr.get_stats(), indent=2))


if __name__ == "__main__":
    main()
