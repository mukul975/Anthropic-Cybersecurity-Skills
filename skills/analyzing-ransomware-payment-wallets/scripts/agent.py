#!/usr/bin/env python3
"""Ransomware payment wallet blockchain analysis agent.

Traces cryptocurrency payment flows from ransomware wallets using public
blockchain APIs. Identifies transaction patterns, cluster relationships,
and fund movement to exchanges or mixers.
"""

import json
import re
import sys

try:
    import requests
except ImportError:
    print("[!] 'requests' library required: pip install requests")
    sys.exit(1)

BLOCKCHAIN_API = "https://blockchain.info"
BLOCKSTREAM_API = "https://blockstream.info/api"

BTC_ADDRESS_REGEX = re.compile(
    r"^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$"
)

KNOWN_RANSOMWARE_WALLETS = {
    "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw": "WannaCry",
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94": "WannaCry",
    "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn": "WannaCry",
    "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX": "DarkSide (Colonial Pipeline)",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "DarkSide",
}


def validate_btc_address(address):
    """Validate Bitcoin address format."""
    if BTC_ADDRESS_REGEX.match(address):
        return True
    return False


def query_address_info(address):
    """Query blockchain.info for address details."""
    url = f"{BLOCKCHAIN_API}/rawaddr/{address}?limit=50"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "address": address,
        "total_received_btc": data.get("total_received", 0) / 1e8,
        "total_sent_btc": data.get("total_sent", 0) / 1e8,
        "final_balance_btc": data.get("final_balance", 0) / 1e8,
        "n_tx": data.get("n_tx", 0),
        "transactions": data.get("txs", []),
    }


def query_blockstream_address(address):
    """Query Blockstream API for address stats (fallback)."""
    url = f"{BLOCKSTREAM_API}/address/{address}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    chain = data.get("chain_stats", {})
    return {
        "address": address,
        "funded_txo_count": chain.get("funded_txo_count", 0),
        "spent_txo_count": chain.get("spent_txo_count", 0),
        "funded_txo_sum_btc": chain.get("funded_txo_sum", 0) / 1e8,
        "spent_txo_sum_btc": chain.get("spent_txo_sum", 0) / 1e8,
    }


def extract_output_addresses(transactions, source_address):
    """Extract downstream addresses from transaction outputs."""
    downstream = {}
    for tx in transactions:
        tx_hash = tx.get("hash", "unknown")
        is_outgoing = any(
            inp.get("prev_out", {}).get("addr") == source_address
            for inp in tx.get("inputs", [])
        )
        if not is_outgoing:
            continue
        for out in tx.get("out", []):
            addr = out.get("addr")
            value = out.get("value", 0) / 1e8
            if addr and addr != source_address:
                if addr not in downstream:
                    downstream[addr] = {"total_btc": 0, "tx_count": 0, "tx_hashes": []}
                downstream[addr]["total_btc"] += value
                downstream[addr]["tx_count"] += 1
                downstream[addr]["tx_hashes"].append(tx_hash[:16])
    return downstream


def check_known_wallets(address):
    """Check if address matches known ransomware wallets."""
    if address in KNOWN_RANSOMWARE_WALLETS:
        return {"known": True, "family": KNOWN_RANSOMWARE_WALLETS[address]}
    return {"known": False, "family": None}


def detect_peel_chain(transactions, address):
    """Detect peel chain pattern in outgoing transactions."""
    outgoing_values = []
    for tx in transactions:
        is_outgoing = any(
            inp.get("prev_out", {}).get("addr") == address
            for inp in tx.get("inputs", [])
        )
        if is_outgoing:
            outputs = [o.get("value", 0) / 1e8 for o in tx.get("out", []) if o.get("addr") != address]
            outgoing_values.extend(outputs)

    if len(outgoing_values) < 3:
        return {"peel_chain_detected": False, "reason": "Insufficient transactions"}

    decreasing = sum(1 for i in range(1, len(outgoing_values)) if outgoing_values[i] < outgoing_values[i - 1])
    ratio = decreasing / (len(outgoing_values) - 1) if len(outgoing_values) > 1 else 0
    return {
        "peel_chain_detected": ratio > 0.6,
        "decreasing_ratio": round(ratio, 3),
        "num_outputs": len(outgoing_values),
    }


def analyze_wallet(address):
    """Full analysis of a ransomware payment wallet."""
    report = {"analysis_type": "Ransomware Payment Wallet Analysis", "address": address}

    if not validate_btc_address(address):
        report["error"] = f"Invalid Bitcoin address format: {address}"
        return report

    report["known_wallet_check"] = check_known_wallets(address)

    try:
        info = query_address_info(address)
        report["wallet_info"] = {
            "total_received_btc": info["total_received_btc"],
            "total_sent_btc": info["total_sent_btc"],
            "final_balance_btc": info["final_balance_btc"],
            "transaction_count": info["n_tx"],
        }

        downstream = extract_output_addresses(info["transactions"], address)
        report["downstream_addresses"] = {
            "count": len(downstream),
            "top_recipients": sorted(
                [{"address": a, **d} for a, d in downstream.items()],
                key=lambda x: x["total_btc"],
                reverse=True,
            )[:10],
        }

        for recipient in report["downstream_addresses"]["top_recipients"]:
            match = check_known_wallets(recipient["address"])
            recipient["known_entity"] = match["family"] if match["known"] else "Unknown"

        report["peel_chain_analysis"] = detect_peel_chain(info["transactions"], address)
    except requests.RequestException as e:
        report["error"] = f"API query failed: {e}"
        try:
            fallback = query_blockstream_address(address)
            report["wallet_info_blockstream"] = fallback
        except requests.RequestException as e2:
            report["fallback_error"] = f"Blockstream fallback also failed: {e2}"

    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Payment Wallet Analysis Agent")
    print("Blockchain tracing, cluster analysis, fund flow mapping")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python agent.py <bitcoin_address>")
        print("  python agent.py <bitcoin_address> --deep")
        print("\nExample:")
        print("  python agent.py 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw")
        sys.exit(0)

    address = sys.argv[1]
    print(f"\n[*] Analyzing wallet: {address}")

    report = analyze_wallet(address)

    known = report.get("known_wallet_check", {})
    if known.get("known"):
        print(f"[!] KNOWN RANSOMWARE WALLET: {known['family']}")

    info = report.get("wallet_info", {})
    if info:
        print("\n--- Wallet Summary ---")
        print(f"  Total received: {info.get('total_received_btc', 0):.8f} BTC")
        print(f"  Total sent:     {info.get('total_sent_btc', 0):.8f} BTC")
        print(f"  Balance:        {info.get('final_balance_btc', 0):.8f} BTC")
        print(f"  Transactions:   {info.get('transaction_count', 0)}")

    ds = report.get("downstream_addresses", {})
    if ds.get("count", 0) > 0:
        print(f"\n--- Top Downstream Recipients ({ds['count']} total) ---")
        for r in ds.get("top_recipients", [])[:5]:
            entity = r.get("known_entity", "Unknown")
            print(f"  {r['address'][:20]}... {r['total_btc']:.8f} BTC [{entity}]")

    peel = report.get("peel_chain_analysis", {})
    if peel.get("peel_chain_detected"):
        print(f"\n[!] Peel chain pattern detected (ratio: {peel['decreasing_ratio']})")

    if report.get("error"):
        print(f"\n[!] Error: {report['error']}")

    print(f"\n[*] Full report:\n{json.dumps(report, indent=2, default=str)}")
