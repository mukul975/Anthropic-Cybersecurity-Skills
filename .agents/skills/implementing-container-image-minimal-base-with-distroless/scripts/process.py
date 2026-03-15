#!/usr/bin/env python3
"""
Container Image Base Analysis Tool

Analyzes container images to identify non-minimal base images and
recommends distroless alternatives based on the application runtime.
"""

import json
import subprocess
import sys
import argparse
from datetime import datetime


DISTROLESS_RECOMMENDATIONS = {
    "golang": "gcr.io/distroless/static-debian12:nonroot",
    "go": "gcr.io/distroless/static-debian12:nonroot",
    "rust": "gcr.io/distroless/static-debian12:nonroot",
    "java": "gcr.io/distroless/java21-debian12:nonroot",
    "openjdk": "gcr.io/distroless/java21-debian12:nonroot",
    "python": "gcr.io/distroless/python3-debian12:nonroot",
    "node": "gcr.io/distroless/nodejs22-debian12:nonroot",
    "nodejs": "gcr.io/distroless/nodejs22-debian12:nonroot",
    "dotnet": "mcr.microsoft.com/dotnet/runtime-deps:8.0-noble-chiseled",
    "ruby": "gcr.io/distroless/base-debian12:nonroot",
    "c": "gcr.io/distroless/cc-debian12:nonroot",
    "cpp": "gcr.io/distroless/cc-debian12:nonroot",
}

BLOATED_BASES = {"ubuntu", "debian", "centos", "fedora", "amazonlinux", "oraclelinux"}


def run_command(cmd: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def get_image_info(image: str) -> dict:
    """Get image metadata using docker inspect or crane."""
    output = run_command(["docker", "inspect", image])
    if output:
        try:
            data = json.loads(output)
            if data:
                return data[0]
        except json.JSONDecodeError:
            pass
    return {}


def analyze_image_layers(image: str) -> dict:
    """Analyze image layers and size."""
    info = get_image_info(image)
    if not info:
        return {"error": f"Cannot inspect image: {image}"}

    return {
        "image": image,
        "size_bytes": info.get("Size", 0),
        "size_mb": round(info.get("Size", 0) / 1024 / 1024, 1),
        "layers": len(info.get("RootFS", {}).get("Layers", [])),
        "os": info.get("Os", ""),
        "architecture": info.get("Architecture", ""),
        "user": info.get("Config", {}).get("User", "root"),
        "entrypoint": info.get("Config", {}).get("Entrypoint", []),
        "cmd": info.get("Config", {}).get("Cmd", []),
        "env": info.get("Config", {}).get("Env", []),
        "has_shell": check_shell_exists(image),
    }


def check_shell_exists(image: str) -> bool:
    """Check if the image contains a shell."""
    for shell in ["/bin/sh", "/bin/bash", "/bin/dash"]:
        output = run_command(["docker", "run", "--rm", "--entrypoint", "",
                             image, "test", "-f", shell])
        # If command succeeds, shell exists
    output = run_command(["docker", "run", "--rm", "--entrypoint", "",
                         image, "ls", "/bin/sh"], timeout=10)
    return bool(output)


def scan_vulnerabilities(image: str) -> dict:
    """Scan image for vulnerabilities using trivy."""
    output = run_command(["trivy", "image", "--format", "json", "--quiet", image], timeout=120)
    if not output:
        return {"total": -1, "critical": -1, "high": -1, "medium": -1, "low": -1}

    try:
        data = json.loads(output)
        counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                counts["total"] += 1
                sev = vuln.get("Severity", "").lower()
                if sev in counts:
                    counts[sev] += 1
        return counts
    except json.JSONDecodeError:
        return {"total": -1, "critical": -1, "high": -1, "medium": -1, "low": -1}


def recommend_distroless(image: str) -> str:
    """Recommend a distroless base image based on current image."""
    image_lower = image.lower()
    for runtime, distroless in DISTROLESS_RECOMMENDATIONS.items():
        if runtime in image_lower:
            return distroless
    return "gcr.io/distroless/base-debian12:nonroot"


def analyze_kubernetes_images(namespace: str = "") -> list[dict]:
    """Analyze all container images in a Kubernetes cluster."""
    cmd = ["kubectl", "get", "pods", "-o", "json"]
    if namespace:
        cmd.extend(["-n", namespace])
    else:
        cmd.append("--all-namespaces")

    output = run_command(cmd)
    if not output:
        return []

    images = set()
    try:
        data = json.loads(output)
        for pod in data.get("items", []):
            for cs in pod.get("status", {}).get("containerStatuses", []):
                images.add(cs.get("image", ""))
    except json.JSONDecodeError:
        return []

    results = []
    for image in sorted(images):
        if not image:
            continue
        is_distroless = "distroless" in image or "chiseled" in image
        is_bloated = any(base in image.lower() for base in BLOATED_BASES)

        results.append({
            "image": image,
            "is_distroless": is_distroless,
            "is_bloated_base": is_bloated,
            "recommendation": "Already minimal" if is_distroless else recommend_distroless(image)
        })

    return results


def generate_report(results: list[dict], output_format: str = "text") -> str:
    if output_format == "json":
        return json.dumps({"timestamp": datetime.utcnow().isoformat(),
                          "results": results}, indent=2)

    lines = ["=" * 70, "CONTAINER IMAGE BASE ANALYSIS REPORT",
             f"Generated: {datetime.utcnow().isoformat()}", "=" * 70]

    minimal = [r for r in results if r.get("is_distroless")]
    bloated = [r for r in results if r.get("is_bloated_base")]
    lines.append(f"\nImages Analyzed: {len(results)}")
    lines.append(f"Minimal/Distroless: {len(minimal)}")
    lines.append(f"Bloated Base: {len(bloated)}")

    if bloated:
        lines.append("\n## Images Needing Migration")
        for r in bloated:
            lines.append(f"  {r['image']}")
            lines.append(f"    Recommended: {r['recommendation']}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Container Image Base Analyzer")
    parser.add_argument("--image", help="Analyze a specific image")
    parser.add_argument("--namespace", default="", help="K8s namespace to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.image:
        info = analyze_image_layers(args.image)
        info["recommendation"] = recommend_distroless(args.image)
        print(generate_report([info], args.format))
    else:
        results = analyze_kubernetes_images(args.namespace)
        print(generate_report(results, args.format))


if __name__ == "__main__":
    main()
