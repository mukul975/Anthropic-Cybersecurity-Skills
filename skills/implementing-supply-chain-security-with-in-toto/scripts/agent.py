#!/usr/bin/env python3
"""in-toto supply chain security agent.

Implements software supply chain verification using the in-toto framework.
Creates and verifies supply chain layouts, generates link metadata for
build steps, and validates that all steps were performed by authorized
functionaries with correct materials and products.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def find_intoto_binary():
    """Locate in-toto CLI tools."""
    tools = {}
    for name in ["in-toto-run", "in-toto-verify", "in-toto-record", "in-toto-sign"]:
        for ext in ["", ".exe"]:
            for d in os.environ.get("PATH", "").split(os.pathsep):
                full = os.path.join(d, name + ext)
                if os.path.isfile(full):
                    tools[name] = full
                    break
    return tools


def create_layout_template(output_path, project_name, steps=None):
    """Generate a supply chain layout template."""
    if steps is None:
        steps = [
            {"name": "clone", "expected_command": ["git", "clone"],
             "threshold": 1, "materials": [], "products": ["src/*"]},
            {"name": "build", "expected_command": ["make"],
             "threshold": 1, "materials": ["src/*"], "products": ["dist/*"]},
            {"name": "test", "expected_command": ["make", "test"],
             "threshold": 1, "materials": ["src/*", "dist/*"], "products": []},
            {"name": "package", "expected_command": ["tar", "czf"],
             "threshold": 1, "materials": ["dist/*"], "products": ["*.tar.gz"]},
        ]

    layout = {
        "_type": "layout",
        "expires": (datetime.now(timezone.utc).replace(year=datetime.now().year + 1)).isoformat(),
        "readme": f"Supply chain layout for {project_name}",
        "steps": [],
        "inspect": [
            {
                "name": "verify-signature",
                "expected_materials": [["MATCH", "*.tar.gz", "WITH", "PRODUCTS", "FROM", "package"]],
                "expected_products": [],
                "run": ["sha256sum", "*.tar.gz"],
            }
        ],
        "keys": {},
    }

    for step in steps:
        layout["steps"].append({
            "name": step["name"],
            "expected_command": step.get("expected_command", []),
            "threshold": step.get("threshold", 1),
            "expected_materials": [
                ["MATCH", m, "WITH", "PRODUCTS", "FROM", steps[i-1]["name"]]
                if i > 0 else ["ALLOW", m]
                for i, m in enumerate(step.get("materials", []))
            ] or [["ALLOW", "*"]],
            "expected_products": [
                ["CREATE", p] for p in step.get("products", [])
            ] or [["ALLOW", "*"]],
            "pubkeys": [],
        })

    with open(output_path, "w") as f:
        json.dump(layout, f, indent=2)
    print(f"[+] Layout template written to {output_path}")
    return layout


def run_step(tools, step_name, key_path, command, materials=None, products=None):
    """Execute a supply chain step and record link metadata."""
    intoto_run = tools.get("in-toto-run")
    if not intoto_run:
        print("[!] in-toto-run not found", file=sys.stderr)
        return None

    cmd = [intoto_run, "--step-name", step_name, "--key", key_path]
    if materials:
        for m in materials:
            cmd.extend(["--materials", m])
    if products:
        for p in products:
            cmd.extend(["--products", p])
    cmd.append("--")
    cmd.extend(command)

    print(f"[*] Running step '{step_name}': {' '.join(command)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"[!] Step failed: {result.stderr[:200]}", file=sys.stderr)
        return {"step": step_name, "status": "FAIL", "error": result.stderr[:200]}

    link_file = f"{step_name}.link"
    if os.path.isfile(link_file):
        print(f"[+] Link metadata: {link_file}")
        with open(link_file, "r") as f:
            link_data = json.load(f)
        return {"step": step_name, "status": "OK", "link_file": link_file,
                "materials_count": len(link_data.get("signed", {}).get("materials", {})),
                "products_count": len(link_data.get("signed", {}).get("products", {}))}
    return {"step": step_name, "status": "OK", "link_file": "generated"}


def verify_layout(tools, layout_path, layout_key_path, link_dir="."):
    """Verify the supply chain against the layout."""
    intoto_verify = tools.get("in-toto-verify")
    if not intoto_verify:
        print("[!] in-toto-verify not found", file=sys.stderr)
        return {"status": "FAIL", "error": "in-toto-verify not found"}

    cmd = [intoto_verify,
           "--layout", layout_path,
           "--layout-keys", layout_key_path,
           "--link-dir", link_dir]

    print(f"[*] Verifying supply chain layout: {layout_path}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        print("[+] Verification PASSED")
        return {"status": "PASS", "detail": "All steps verified successfully"}
    else:
        print(f"[!] Verification FAILED: {result.stderr[:300]}")
        return {"status": "FAIL", "detail": result.stderr[:300]}


def audit_existing_links(link_dir="."):
    """Audit existing link metadata files."""
    findings = []
    for fname in os.listdir(link_dir):
        if not fname.endswith(".link"):
            continue
        fpath = os.path.join(link_dir, fname)
        try:
            with open(fpath, "r") as f:
                link = json.load(f)
            signed = link.get("signed", {})
            step_name = signed.get("name", fname)
            materials = signed.get("materials", {})
            products = signed.get("products", {})
            command = signed.get("command", [])
            byproducts = signed.get("byproducts", {})

            findings.append({
                "link_file": fname,
                "step_name": step_name,
                "materials_count": len(materials),
                "products_count": len(products),
                "command": " ".join(command)[:80] if command else "N/A",
                "return_code": byproducts.get("return-value", "N/A"),
                "has_signature": bool(link.get("signatures")),
            })
        except (json.JSONDecodeError, IOError) as e:
            findings.append({"link_file": fname, "error": str(e)})

    return findings


def format_summary(results):
    """Print supply chain audit summary."""
    print(f"\n{'='*60}")
    print("  in-toto Supply Chain Security Report")
    print(f"{'='*60}")
    if isinstance(results, list):
        print(f"  Link Files Found: {len(results)}")
        for r in results:
            if "error" in r:
                print(f"    [ERR] {r['link_file']}: {r['error']}")
            else:
                sig = "signed" if r.get("has_signature") else "UNSIGNED"
                print(f"    [{sig:8s}] {r['step_name']:20s} | "
                      f"{r['materials_count']} materials, {r['products_count']} products | "
                      f"cmd: {r.get('command', 'N/A')[:40]}")


def main():
    parser = argparse.ArgumentParser(
        description="in-toto supply chain security agent"
    )
    sub = parser.add_subparsers(dest="command")

    p_layout = sub.add_parser("create-layout", help="Generate a layout template")
    p_layout.add_argument("--project", required=True, help="Project name")
    p_layout.add_argument("--output-path", default="root.layout", help="Layout output file")

    p_run = sub.add_parser("run-step", help="Execute a supply chain step")
    p_run.add_argument("--step-name", required=True)
    p_run.add_argument("--key", required=True, help="Functionary key path")
    p_run.add_argument("--materials", nargs="*")
    p_run.add_argument("--products", nargs="*")
    p_run.add_argument("cmd", nargs="+", help="Command to execute")

    p_verify = sub.add_parser("verify", help="Verify supply chain")
    p_verify.add_argument("--layout", required=True)
    p_verify.add_argument("--layout-key", required=True)
    p_verify.add_argument("--link-dir", default=".")

    p_audit = sub.add_parser("audit", help="Audit existing link metadata")
    p_audit.add_argument("--link-dir", default=".")

    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    tools = find_intoto_binary()
    result = {}

    if args.command == "create-layout":
        layout = create_layout_template(args.output_path, args.project)
        result = {"action": "create-layout", "layout": layout}
    elif args.command == "run-step":
        step_result = run_step(tools, args.step_name, args.key,
                               args.cmd, args.materials, args.products)
        result = {"action": "run-step", "result": step_result}
    elif args.command == "verify":
        verify_result = verify_layout(tools, args.layout, args.layout_key, args.link_dir)
        result = {"action": "verify", "result": verify_result}
    elif args.command == "audit":
        link_findings = audit_existing_links(args.link_dir)
        format_summary(link_findings)
        result = {"action": "audit", "links": link_findings}

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "in-toto",
        "result": result,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
