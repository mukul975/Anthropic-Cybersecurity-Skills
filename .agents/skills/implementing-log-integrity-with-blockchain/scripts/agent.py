#!/usr/bin/env python3
"""Log Integrity Chain Agent - Implements SHA-256 hash-chained append-only log for tamper detection."""

import json
import hashlib
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def compute_hash(data):
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def create_chain_entry(index, timestamp, content, prev_hash):
    """Create a single chain entry with hash linking."""
    content_hash = compute_hash(content)
    chain_input = f"{prev_hash}{timestamp}{content_hash}"
    chain_hash = compute_hash(chain_input)
    return {
        "index": index,
        "timestamp": timestamp,
        "content_hash": content_hash,
        "prev_hash": prev_hash,
        "chain_hash": chain_hash,
        "content_preview": content[:200],
    }


def load_chain(chain_file):
    """Load an existing hash chain from a JSON file."""
    try:
        with open(chain_file, "r") as f:
            chain = json.load(f)
        logger.info("Loaded chain with %d entries from %s", len(chain), chain_file)
        return chain
    except FileNotFoundError:
        logger.info("No existing chain found, starting new chain")
        return []


def save_chain(chain, chain_file):
    """Save the hash chain to a JSON file."""
    with open(chain_file, "w") as f:
        json.dump(chain, f, indent=2)
    logger.info("Saved chain with %d entries to %s", len(chain), chain_file)


def ingest_log_file(log_file):
    """Read log entries from a file (one entry per line)."""
    entries = []
    with open(log_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(line)
    logger.info("Read %d log entries from %s", len(entries), log_file)
    return entries


def ingest_json_log(json_file):
    """Read structured log entries from a JSON array file."""
    with open(json_file, "r") as f:
        data = json.load(f)
    entries = []
    if isinstance(data, list):
        for item in data:
            entries.append(json.dumps(item, sort_keys=True))
    logger.info("Read %d JSON log entries from %s", len(entries), json_file)
    return entries


def append_entries(chain, log_entries):
    """Append new log entries to the hash chain."""
    prev_hash = chain[-1]["chain_hash"] if chain else GENESIS_HASH
    start_index = len(chain)
    new_entries = []
    for i, content in enumerate(log_entries):
        timestamp = datetime.utcnow().isoformat() + "Z"
        entry = create_chain_entry(start_index + i, timestamp, content, prev_hash)
        chain.append(entry)
        new_entries.append(entry)
        prev_hash = entry["chain_hash"]
    logger.info("Appended %d entries to chain (total: %d)", len(new_entries), len(chain))
    return new_entries


def verify_chain(chain):
    """Verify the integrity of the entire hash chain."""
    if not chain:
        return {"valid": True, "entries_checked": 0, "breaks": []}
    breaks = []
    prev_hash = GENESIS_HASH
    for entry in chain:
        expected_input = f"{prev_hash}{entry['timestamp']}{entry['content_hash']}"
        expected_hash = compute_hash(expected_input)
        if entry["chain_hash"] != expected_hash:
            breaks.append({
                "index": entry["index"],
                "expected_hash": expected_hash,
                "actual_hash": entry["chain_hash"],
                "prev_hash_match": entry["prev_hash"] == prev_hash,
            })
        if entry["prev_hash"] != prev_hash:
            breaks.append({
                "index": entry["index"],
                "issue": "prev_hash mismatch",
                "expected_prev": prev_hash,
                "actual_prev": entry["prev_hash"],
            })
        prev_hash = entry["chain_hash"]
    valid = len(breaks) == 0
    logger.info("Chain verification: %d entries checked, %d breaks found", len(chain), len(breaks))
    return {"valid": valid, "entries_checked": len(chain), "breaks": breaks}


def find_tampered_range(breaks):
    """Identify the range of entries affected by tampering."""
    if not breaks:
        return None
    first_break = min(b["index"] for b in breaks)
    return {
        "first_tampered_entry": first_break,
        "total_affected": len(breaks),
        "tamper_start_index": first_break,
        "note": f"All entries from index {first_break} onward may be compromised",
    }


def create_checkpoint(chain, checkpoint_file):
    """Create an integrity checkpoint with the current chain head hash."""
    if not chain:
        return None
    checkpoint = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "chain_length": len(chain),
        "head_hash": chain[-1]["chain_hash"],
        "head_index": chain[-1]["index"],
        "genesis_hash": GENESIS_HASH,
        "checkpoint_hash": compute_hash(f"{len(chain)}{chain[-1]['chain_hash']}"),
    }
    with open(checkpoint_file, "w") as f:
        json.dump(checkpoint, f, indent=2)
    logger.info("Created checkpoint at index %d: %s", checkpoint["head_index"], checkpoint["checkpoint_hash"][:16])
    return checkpoint


def verify_checkpoint(chain, checkpoint_file):
    """Verify chain against a previously saved checkpoint."""
    with open(checkpoint_file, "r") as f:
        checkpoint = json.load(f)
    cp_index = checkpoint["head_index"]
    if cp_index >= len(chain):
        return {"valid": False, "error": "Chain shorter than checkpoint"}
    actual_hash = chain[cp_index]["chain_hash"]
    valid = actual_hash == checkpoint["head_hash"]
    return {
        "valid": valid,
        "checkpoint_index": cp_index,
        "expected_hash": checkpoint["head_hash"],
        "actual_hash": actual_hash,
    }


def generate_report(verification, checkpoint, chain_length):
    """Generate log integrity verification report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "chain_length": chain_length,
        "integrity_valid": verification["valid"],
        "entries_checked": verification["entries_checked"],
        "breaks_found": len(verification["breaks"]),
        "break_details": verification["breaks"][:20],
        "checkpoint": checkpoint,
    }
    status = "INTACT" if verification["valid"] else "TAMPERED"
    print(f"LOG INTEGRITY: {status} - {chain_length} entries, {len(verification['breaks'])} breaks")
    return report


def main():
    parser = argparse.ArgumentParser(description="Log Integrity Chain Agent")
    parser.add_argument("--log-file", help="Log file to ingest")
    parser.add_argument("--chain-file", default="log_chain.json", help="Hash chain storage file")
    parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    parser.add_argument("--checkpoint", help="Create/verify checkpoint file")
    parser.add_argument("--output", default="integrity_report.json")
    args = parser.parse_args()

    chain = load_chain(args.chain_file)

    if args.log_file:
        entries = ingest_log_file(args.log_file)
        append_entries(chain, entries)
        save_chain(chain, args.chain_file)

    verification = {"valid": True, "entries_checked": 0, "breaks": []}
    if args.verify:
        verification = verify_chain(chain)

    checkpoint = None
    if args.checkpoint:
        if args.verify:
            checkpoint = verify_checkpoint(chain, args.checkpoint)
        else:
            checkpoint = create_checkpoint(chain, args.checkpoint)

    report = generate_report(verification, checkpoint, len(chain))
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
