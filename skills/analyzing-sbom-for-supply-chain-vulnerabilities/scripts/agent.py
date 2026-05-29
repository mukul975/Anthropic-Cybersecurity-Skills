#!/usr/bin/env python3
"""SBOM supply chain vulnerability analysis agent.

Parses CycloneDX and SPDX JSON SBOMs, correlates components against the NVD 2.0 API
for known CVEs, builds dependency graphs with networkx, calculates risk scores, and
generates compliance reports.
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    from packaging.version import Version, InvalidVersion
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False

# NVD API 2.0 configuration
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_RATE_LIMIT_NO_KEY = 6.0   # seconds between requests without API key
NVD_RATE_LIMIT_WITH_KEY = 0.6  # seconds between requests with API key
NVD_RESULTS_PER_PAGE = 50

# CVSS severity thresholds
SEVERITY_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
}


class SBOMComponent:
    """Represents a single software component extracted from an SBOM."""

    def __init__(self, name, version, purl=None, cpe=None, component_type="library",
                 licenses=None, supplier=None):
        self.name = name
        self.version = version
        self.purl = purl
        self.cpe = cpe
        self.component_type = component_type
        self.licenses = licenses or []
        self.supplier = supplier
        self.cves = []
        self.max_cvss = 0.0
        self.risk_level = "NONE"

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "cpe": self.cpe,
            "type": self.component_type,
            "licenses": self.licenses,
            "cves": self.cves,
            "max_cvss": self.max_cvss,
            "risk_level": self.risk_level,
        }


def detect_sbom_format(sbom_data):
    """Detect whether the SBOM is CycloneDX or SPDX format."""
    if isinstance(sbom_data, dict):
        if sbom_data.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if "spdxVersion" in sbom_data:
            return "spdx"
        if "components" in sbom_data and any(
            "purl" in c for c in sbom_data.get("components", [])
        ):
            return "cyclonedx"
        if "packages" in sbom_data:
            return "spdx"
    return "unknown"


def parse_cyclonedx(sbom_data):
    """Parse CycloneDX JSON SBOM and extract components and dependencies."""
    components = []
    dependencies = {}

    spec_version = sbom_data.get("specVersion", "unknown")
    print(f"  Format: CycloneDX v{spec_version}")

    for comp in sbom_data.get("components", []):
        name = comp.get("name", "unknown")
        version = comp.get("version", "unknown")
        purl = comp.get("purl")
        cpe = None

        # Extract CPE from multiple possible locations
        if "cpe" in comp:
            cpe = comp["cpe"]
        for prop in comp.get("properties", []):
            if prop.get("name") == "syft:cpe23" or "cpe" in prop.get("name", "").lower():
                cpe = prop.get("value")
                break

        # Extract licenses
        licenses = []
        for lic_entry in comp.get("licenses", []):
            lic = lic_entry.get("license", {})
            if "id" in lic:
                licenses.append(lic["id"])
            elif "name" in lic:
                licenses.append(lic["name"])

        component = SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            cpe=cpe,
            component_type=comp.get("type", "library"),
            licenses=licenses,
            supplier=comp.get("supplier", {}).get("name"),
        )
        components.append(component)

    # Parse dependency graph
    for dep_entry in sbom_data.get("dependencies", []):
        ref = dep_entry.get("ref", "")
        depends_on = dep_entry.get("dependsOn", [])
        dependencies[ref] = depends_on

    return components, dependencies


def parse_spdx(sbom_data):
    """Parse SPDX JSON SBOM and extract components and dependencies."""
    components = []
    dependencies = {}

    spdx_version = sbom_data.get("spdxVersion", "unknown")
    print(f"  Format: SPDX {spdx_version}")

    spdx_id_to_purl = {}

    for pkg in sbom_data.get("packages", []):
        name = pkg.get("name", "unknown")
        version = pkg.get("versionInfo", "unknown")
        spdx_id = pkg.get("SPDXID", "")
        purl = None
        cpe = None

        for ref in pkg.get("externalRefs", []):
            ref_type = ref.get("referenceType", "")
            locator = ref.get("referenceLocator", "")
            if ref_type == "purl" or "purl" in ref_type.lower():
                purl = locator
            elif ref_type == "cpe23Type" or "cpe" in ref_type.lower():
                cpe = locator

        licenses = []
        concluded = pkg.get("licenseConcluded", "NOASSERTION")
        if concluded and concluded != "NOASSERTION":
            licenses.append(concluded)
        declared = pkg.get("licenseDeclared", "NOASSERTION")
        if declared and declared != "NOASSERTION" and declared not in licenses:
            licenses.append(declared)

        component = SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            cpe=cpe,
            component_type="library",
            licenses=licenses,
            supplier=pkg.get("supplier"),
        )
        components.append(component)
        spdx_id_to_purl[spdx_id] = purl or f"{name}@{version}"

    # Parse relationships
    for rel in sbom_data.get("relationships", []):
        rel_type = rel.get("relationshipType", "")
        if rel_type == "DEPENDS_ON":
            parent_id = rel.get("spdxElementId", "")
            child_id = rel.get("relatedSpdxElement", "")
            parent_ref = spdx_id_to_purl.get(parent_id, parent_id)
            child_ref = spdx_id_to_purl.get(child_id, child_id)
            if parent_ref not in dependencies:
                dependencies[parent_ref] = []
            dependencies[parent_ref].append(child_ref)

    return components, dependencies


def parse_sbom(sbom_path):
    """Load and parse an SBOM file, auto-detecting the format."""
    if not os.path.isfile(sbom_path):
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    fmt = detect_sbom_format(sbom_data)
    print(f"\n[INFO] Parsing SBOM: {sbom_path}")

    if fmt == "cyclonedx":
        return parse_cyclonedx(sbom_data), fmt
    elif fmt == "spdx":
        return parse_spdx(sbom_data), fmt
    else:
        raise ValueError(
            f"Unrecognized SBOM format. Expected CycloneDX or SPDX JSON. "
            f"Keys found: {list(sbom_data.keys())[:10]}"
        )


def query_nvd_by_cpe(cpe_name, api_key=None):
    """Query NVD 2.0 API for CVEs matching a CPE name."""
    if not HAS_REQUESTS:
        return []

    params = {"cpeName": cpe_name, "resultsPerPage": NVD_RESULTS_PER_PAGE}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=30)
        if resp.status_code == 403:
            print("    [WARN] NVD API rate limited. Waiting...", file=sys.stderr)
            time.sleep(NVD_RATE_LIMIT_NO_KEY * 2)
            resp = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"    [WARN] NVD API error for {cpe_name}: {e}", file=sys.stderr)
        return []


def query_nvd_by_keyword(keyword, api_key=None):
    """Query NVD 2.0 API for CVEs matching a keyword search."""
    if not HAS_REQUESTS:
        return []

    params = {"keywordSearch": keyword, "resultsPerPage": NVD_RESULTS_PER_PAGE}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"    [WARN] NVD keyword search error for '{keyword}': {e}", file=sys.stderr)
        return []


def extract_cve_info(vuln_entry):
    """Extract structured CVE information from an NVD API response entry."""
    cve_data = vuln_entry.get("cve", {})
    cve_id = cve_data.get("id", "UNKNOWN")

    # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2.0)
    cvss_score = 0.0
    cvss_version = "none"
    metrics = cve_data.get("metrics", {})

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_version = cvss_data.get("version", version_key)
            break

    # Extract description
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # Determine severity
    severity = "LOW"
    for level, threshold in sorted(SEVERITY_THRESHOLDS.items(),
                                    key=lambda x: x[1], reverse=True):
        if cvss_score >= threshold:
            severity = level
            break

    # Check for known exploited (CISA KEV indicator)
    is_kev = False
    for ref in cve_data.get("references", []):
        if "cisa.gov" in ref.get("url", "").lower():
            is_kev = True
            break

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "severity": severity,
        "description": description[:300],
        "is_kev": is_kev,
        "published": cve_data.get("published", ""),
    }


def correlate_cves(components, api_key=None, skip_nvd=False):
    """Correlate all SBOM components against NVD for known vulnerabilities."""
    rate_limit = NVD_RATE_LIMIT_WITH_KEY if api_key else NVD_RATE_LIMIT_NO_KEY
    total = len(components)
    vuln_count = 0

    print(f"\n[INFO] Correlating {total} components against NVD CVE database...")
    if not api_key:
        print(f"  [NOTE] No NVD API key. Rate limited to 1 request per {rate_limit}s.")
        print("  Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")

    if skip_nvd:
        print("  [NOTE] NVD queries skipped (--skip-nvd flag). Using offline mode.")
        return components

    for idx, comp in enumerate(components):
        print(f"  [{idx+1}/{total}] {comp.name}@{comp.version}...", end="", flush=True)

        vulns = []
        # Try CPE-based search first (most precise)
        if comp.cpe:
            vulns = query_nvd_by_cpe(comp.cpe, api_key)

        # Fallback to keyword search if no CPE or no results
        if not vulns:
            keyword = f"{comp.name} {comp.version}"
            vulns = query_nvd_by_keyword(keyword, api_key)

        # Process results
        for v in vulns:
            cve_info = extract_cve_info(v)
            if cve_info["cvss_score"] > 0:
                comp.cves.append(cve_info)
                if cve_info["cvss_score"] > comp.max_cvss:
                    comp.max_cvss = cve_info["cvss_score"]

        # Assign risk level
        if comp.max_cvss >= SEVERITY_THRESHOLDS["CRITICAL"]:
            comp.risk_level = "CRITICAL"
        elif comp.max_cvss >= SEVERITY_THRESHOLDS["HIGH"]:
            comp.risk_level = "HIGH"
        elif comp.max_cvss >= SEVERITY_THRESHOLDS["MEDIUM"]:
            comp.risk_level = "MEDIUM"
        elif comp.max_cvss > 0:
            comp.risk_level = "LOW"

        cve_count = len(comp.cves)
        vuln_count += cve_count
        status = f" {cve_count} CVEs (max CVSS: {comp.max_cvss})" if cve_count else " clean"
        print(status)

        # Rate limiting
        if idx < total - 1:
            time.sleep(rate_limit)

    print(f"\n[INFO] Correlation complete. Found {vuln_count} total CVEs across all components.")
    return components


def build_dependency_graph(components, dependencies):
    """Build a directed dependency graph using networkx."""
    if not HAS_NETWORKX:
        print("[WARN] networkx not installed. Dependency graph analysis skipped.", file=sys.stderr)
        return None

    G = nx.DiGraph()

    # Build lookup for components by purl or name@version
    comp_lookup = {}
    for comp in components:
        ref = comp.purl or f"{comp.name}@{comp.version}"
        G.add_node(ref, name=comp.name, version=comp.version,
                   max_cvss=comp.max_cvss, risk_level=comp.risk_level,
                   cve_count=len(comp.cves))
        comp_lookup[ref] = comp

    # Add edges from dependency relationships
    for parent_ref, children in dependencies.items():
        if parent_ref not in G:
            G.add_node(parent_ref)
        for child_ref in children:
            if child_ref not in G:
                G.add_node(child_ref)
            G.add_edge(parent_ref, child_ref)

    return G


def analyze_dependency_graph(G):
    """Analyze the dependency graph for risk metrics."""
    if G is None or len(G.nodes) == 0:
        return {}

    analysis = {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "is_dag": nx.is_directed_acyclic_graph(G),
    }

    # Find most depended-on components (highest in-degree)
    in_degrees = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)
    analysis["most_depended_on"] = [
        {"ref": node, "dependents": deg, **G.nodes[node]}
        for node, deg in in_degrees[:10] if deg > 0
    ]

    # Find root nodes (no incoming edges - likely the application itself)
    roots = [n for n, d in G.in_degree() if d == 0]
    analysis["root_components"] = len(roots)

    # Find leaf nodes (no outgoing edges - no dependencies)
    leaves = [n for n, d in G.out_degree() if d == 0]
    analysis["leaf_components"] = len(leaves)

    # Calculate longest dependency chain
    if analysis["is_dag"] and len(G.nodes) > 0:
        try:
            longest_path = nx.dag_longest_path(G)
            analysis["deepest_chain_length"] = len(longest_path)
            analysis["deepest_chain"] = longest_path
        except nx.NetworkXError:
            analysis["deepest_chain_length"] = 0

    # Identify vulnerable components with high in-degree (blast radius)
    high_risk_hubs = []
    for node, deg in in_degrees:
        node_data = G.nodes.get(node, {})
        if node_data.get("max_cvss", 0) >= SEVERITY_THRESHOLDS["HIGH"] and deg > 0:
            high_risk_hubs.append({
                "ref": node,
                "dependents": deg,
                "max_cvss": node_data.get("max_cvss", 0),
                "risk_level": node_data.get("risk_level", "UNKNOWN"),
            })
    analysis["high_risk_hubs"] = high_risk_hubs

    # Betweenness centrality for bottleneck identification
    if len(G.nodes) > 1:
        centrality = nx.betweenness_centrality(G)
        top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
        analysis["bottleneck_components"] = [
            {"ref": node, "centrality": round(cent, 4)} for node, cent in top_central if cent > 0
        ]

    return analysis


def check_license_compliance(components):
    """Check for potentially problematic licenses in SBOM components."""
    copyleft_licenses = {
        "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
        "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
        "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
        "MPL-2.0", "EUPL-1.2", "CPAL-1.0", "OSL-3.0",
    }

    findings = {
        "copyleft_components": [],
        "unknown_license_components": [],
        "license_distribution": defaultdict(int),
    }

    for comp in components:
        if not comp.licenses or comp.licenses == ["NOASSERTION"]:
            findings["unknown_license_components"].append(
                {"name": comp.name, "version": comp.version}
            )
        for lic in comp.licenses:
            findings["license_distribution"][lic] += 1
            if lic in copyleft_licenses:
                findings["copyleft_components"].append({
                    "name": comp.name,
                    "version": comp.version,
                    "license": lic,
                })

    findings["license_distribution"] = dict(findings["license_distribution"])
    return findings


def generate_report(components, dependencies, graph_analysis, license_info,
                    sbom_path, sbom_format, output_path=None):
    """Generate a comprehensive vulnerability analysis report."""
    # Aggregate statistics
    vuln_components = [c for c in components if c.cves]
    total_cves = sum(len(c.cves) for c in components)
    severity_counts = defaultdict(lambda: {"components": 0, "cves": 0})

    for comp in components:
        if comp.risk_level != "NONE":
            severity_counts[comp.risk_level]["components"] += 1
            severity_counts[comp.risk_level]["cves"] += len(comp.cves)

    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("SBOM VULNERABILITY ANALYSIS REPORT")
    report_lines.append("=" * 60)
    report_lines.append(f"SBOM File:          {sbom_path}")
    report_lines.append(f"Format:             {sbom_format}")
    report_lines.append(f"Analysis Date:      {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report_lines.append(f"Total Components:   {len(components)}")

    direct_deps = len(dependencies)
    transitive = len(components) - direct_deps if direct_deps < len(components) else 0
    report_lines.append(f"Dependencies:       {len(dependencies)} direct, ~{transitive} transitive")
    report_lines.append("")

    report_lines.append("VULNERABILITY SUMMARY")
    report_lines.append("-" * 40)
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        counts = severity_counts.get(level, {"components": 0, "cves": 0})
        report_lines.append(
            f"  {level:10s}: {counts['components']:3d} components / {counts['cves']:3d} CVEs"
        )
    report_lines.append(f"  {'TOTAL':10s}: {len(vuln_components):3d} components / {total_cves:3d} CVEs")
    report_lines.append("")

    # Critical and high findings detail
    critical_high = sorted(
        [c for c in components if c.risk_level in ("CRITICAL", "HIGH")],
        key=lambda c: c.max_cvss, reverse=True
    )

    if critical_high:
        report_lines.append("CRITICAL & HIGH FINDINGS")
        report_lines.append("-" * 40)
        for i, comp in enumerate(critical_high[:20], 1):
            report_lines.append(f"\n  {i}. {comp.name}@{comp.version} [{comp.risk_level}]")
            for cve in sorted(comp.cves, key=lambda c: c["cvss_score"], reverse=True)[:5]:
                kev_flag = " [CISA KEV]" if cve.get("is_kev") else ""
                report_lines.append(
                    f"     {cve['cve_id']} (CVSS {cve['cvss_score']:.1f}){kev_flag}"
                )
                if cve["description"]:
                    desc_short = cve["description"][:120]
                    report_lines.append(f"       {desc_short}...")

    # Dependency graph analysis
    if graph_analysis:
        report_lines.append("")
        report_lines.append("DEPENDENCY GRAPH ANALYSIS")
        report_lines.append("-" * 40)
        report_lines.append(f"  Nodes: {graph_analysis.get('total_nodes', 0)}")
        report_lines.append(f"  Edges: {graph_analysis.get('total_edges', 0)}")
        report_lines.append(f"  DAG: {graph_analysis.get('is_dag', 'N/A')}")
        chain_len = graph_analysis.get("deepest_chain_length", 0)
        if chain_len:
            report_lines.append(f"  Deepest dependency chain: {chain_len} levels")

        hubs = graph_analysis.get("high_risk_hubs", [])
        if hubs:
            report_lines.append("\n  HIGH-RISK HUBS (vulnerable + many dependents):")
            for hub in hubs[:5]:
                report_lines.append(
                    f"    {hub['ref']}: {hub['dependents']} dependents, "
                    f"CVSS {hub['max_cvss']:.1f} [{hub['risk_level']}]"
                )

    # License compliance
    if license_info:
        report_lines.append("")
        report_lines.append("LICENSE COMPLIANCE")
        report_lines.append("-" * 40)
        copyleft = license_info.get("copyleft_components", [])
        unknown = license_info.get("unknown_license_components", [])
        report_lines.append(f"  Copyleft licenses found: {len(copyleft)}")
        for cl in copyleft[:10]:
            report_lines.append(f"    {cl['name']}@{cl['version']}: {cl['license']}")
        report_lines.append(f"  Unknown/missing licenses: {len(unknown)}")

    report_text = "\n".join(report_lines)
    print(f"\n{report_text}")

    # Build JSON result
    result = {
        "sbom_file": sbom_path,
        "sbom_format": sbom_format,
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_components": len(components),
            "vulnerable_components": len(vuln_components),
            "total_cves": total_cves,
            "severity_counts": dict(severity_counts),
        },
        "components": [c.to_dict() for c in components],
        "dependency_graph": graph_analysis or {},
        "license_compliance": license_info or {},
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n[OK] Full report saved to {output_path}")

    return result


def analyze_sbom(sbom_path, api_key=None, output_path=None, skip_nvd=False):
    """Full SBOM analysis pipeline: parse, correlate CVEs, graph analysis, report."""
    (components, dependencies), sbom_format = parse_sbom(sbom_path)
    print(f"  Components: {len(components)}")
    print(f"  Dependency entries: {len(dependencies)}")

    # Correlate with NVD
    components = correlate_cves(components, api_key=api_key, skip_nvd=skip_nvd)

    # Build and analyze dependency graph
    G = build_dependency_graph(components, dependencies)
    graph_analysis = analyze_dependency_graph(G)

    # License compliance check
    license_info = check_license_compliance(components)

    # Generate report
    result = generate_report(
        components, dependencies, graph_analysis, license_info,
        sbom_path, sbom_format, output_path
    )

    return result


def compare_sboms(sbom_path_old, sbom_path_new, api_key=None):
    """Compare two SBOMs to identify added, removed, and changed components."""
    (comps_old, _), _ = parse_sbom(sbom_path_old)
    (comps_new, _), _ = parse_sbom(sbom_path_new)

    old_set = {f"{c.name}@{c.version}" for c in comps_old}
    new_set = {f"{c.name}@{c.version}" for c in comps_new}
    old_names = {c.name for c in comps_old}
    new_names = {c.name for c in comps_new}

    added = new_set - old_set
    removed = old_set - new_set

    # Version changes: same name, different version
    old_versions = {c.name: c.version for c in comps_old}
    new_versions = {c.name: c.version for c in comps_new}
    version_changes = []
    for name in old_names & new_names:
        if old_versions[name] != new_versions[name]:
            version_changes.append({
                "name": name,
                "old_version": old_versions[name],
                "new_version": new_versions[name],
            })

    print(f"\n{'='*60}")
    print("SBOM DIFF REPORT")
    print(f"{'='*60}")
    print(f"Old: {sbom_path_old} ({len(comps_old)} components)")
    print(f"New: {sbom_path_new} ({len(comps_new)} components)")
    print(f"\nAdded:   {len(added)} components")
    for a in sorted(added):
        print(f"  + {a}")
    print(f"\nRemoved: {len(removed)} components")
    for r in sorted(removed):
        print(f"  - {r}")
    print(f"\nVersion Changes: {len(version_changes)}")
    for vc in version_changes:
        print(f"  ~ {vc['name']}: {vc['old_version']} -> {vc['new_version']}")

    return {"added": sorted(added), "removed": sorted(removed),
            "version_changes": version_changes}


def main():
    parser = argparse.ArgumentParser(
        description="SBOM Supply Chain Vulnerability Analysis Agent"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze SBOM
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an SBOM for vulnerabilities")
    analyze_parser.add_argument("sbom_path", help="Path to SBOM file (CycloneDX or SPDX JSON)")
    analyze_parser.add_argument("--api-key", help="NVD API key for higher rate limits")
    analyze_parser.add_argument("--output", "-o", help="Save full report to JSON file")
    analyze_parser.add_argument("--skip-nvd", action="store_true",
                                help="Skip NVD API queries (offline mode)")

    # Compare two SBOMs
    diff_parser = subparsers.add_parser("diff", help="Compare two SBOMs for changes")
    diff_parser.add_argument("old_sbom", help="Path to old/baseline SBOM")
    diff_parser.add_argument("new_sbom", help="Path to new/current SBOM")
    diff_parser.add_argument("--api-key", help="NVD API key")

    # Parse only (no NVD queries)
    parse_parser = subparsers.add_parser("parse", help="Parse SBOM and list components")
    parse_parser.add_argument("sbom_path", help="Path to SBOM file")
    parse_parser.add_argument("--output", "-o", help="Save component list to JSON")

    # License check
    license_parser = subparsers.add_parser("licenses", help="Check license compliance")
    license_parser.add_argument("sbom_path", help="Path to SBOM file")

    args = parser.parse_args()

    if args.command == "analyze":
        if not HAS_REQUESTS:
            print("[ERROR] requests library required. Install: pip install requests",
                  file=sys.stderr)
            sys.exit(1)
        api_key = args.api_key or os.environ.get("NVD_API_KEY")
        analyze_sbom(args.sbom_path, api_key=api_key, output_path=args.output,
                     skip_nvd=args.skip_nvd)

    elif args.command == "diff":
        compare_sboms(args.old_sbom, args.new_sbom, api_key=args.api_key)

    elif args.command == "parse":
        (components, dependencies), fmt = parse_sbom(args.sbom_path)
        print(f"\n  Total components: {len(components)}")
        for comp in components:
            print(f"    {comp.name}@{comp.version} [{comp.component_type}] "
                  f"licenses={comp.licenses}")
        if args.output:
            data = {"format": fmt, "component_count": len(components),
                    "components": [c.to_dict() for c in components]}
            with open(args.output, "w") as f:
                json.dump(data, f, indent=2)
            print(f"\n[OK] Component list saved to {args.output}")

    elif args.command == "licenses":
        (components, _), _ = parse_sbom(args.sbom_path)
        info = check_license_compliance(components)
        print("\nLicense Distribution:")
        for lic, count in sorted(info["license_distribution"].items(),
                                  key=lambda x: x[1], reverse=True):
            print(f"  {lic}: {count}")
        if info["copyleft_components"]:
            print(f"\nCopyleft Components ({len(info['copyleft_components'])}):")
            for cl in info["copyleft_components"]:
                print(f"  {cl['name']}@{cl['version']}: {cl['license']}")
        if info["unknown_license_components"]:
            print(f"\nUnknown License ({len(info['unknown_license_components'])}):")
            for ul in info["unknown_license_components"]:
                print(f"  {ul['name']}@{ul['version']}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
