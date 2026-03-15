#!/usr/bin/env python3
"""Agent for performing dynamic analysis of Android applications using Frida."""

import json
import argparse
import subprocess
from datetime import datetime

try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False


def list_packages(device_id=None):
    """List installed packages on Android device/emulator."""
    cmd = ["adb"] + (["-s", device_id] if device_id else []) + ["shell", "pm", "list", "packages", "-3"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    packages = [l.replace("package:", "").strip() for l in result.stdout.strip().split("\n") if l.strip()]
    return {"total": len(packages), "packages": packages}


def capture_network_traffic(device_id=None, duration=30, output="capture.pcap"):
    """Capture network traffic from Android device using tcpdump."""
    adb = ["adb"] + (["-s", device_id] if device_id else [])
    subprocess.run(adb + ["shell", "tcpdump", "-i", "any", "-w", f"/sdcard/{output}", "-G", str(duration), "-W", "1"],
                   timeout=duration + 10, capture_output=True)
    subprocess.run(adb + ["pull", f"/sdcard/{output}", output], capture_output=True, timeout=15)
    return {"output": output, "duration": duration}


def check_ssl_pinning(package_name, device_id=None):
    """Check if app implements SSL/TLS certificate pinning using Frida."""
    if not HAS_FRIDA:
        return {"error": "frida not installed"}
    device = frida.get_usb_device() if not device_id else frida.get_device(device_id)
    pid = device.spawn([package_name])
    session = device.attach(pid)
    script = session.create_script("""
    Java.perform(function() {
        var results = {pinning_detected: false, methods: []};
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function() {
                results.pinning_detected = true;
                results.methods.push('TrustManagerImpl.verifyChain');
                return arguments[0];
            };
        } catch(e) {}
        try {
            var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
            OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() {
                results.pinning_detected = true;
                results.methods.push('OkHostnameVerifier.verify');
                return true;
            };
        } catch(e) {}
        setTimeout(function() { send(results); }, 5000);
    });
    """)
    results = {}
    def on_message(msg, data):
        nonlocal results
        if msg["type"] == "send":
            results = msg["payload"]
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    import time
    time.sleep(8)
    session.detach()
    return {"package": package_name, "ssl_pinning": results}


def analyze_exported_components(package_name, device_id=None):
    """List exported activities, services, receivers, and providers."""
    adb = ["adb"] + (["-s", device_id] if device_id else [])
    result = subprocess.run(
        adb + ["shell", "dumpsys", "package", package_name],
        capture_output=True, text=True, timeout=15
    )
    output = result.stdout
    components = {"activities": [], "services": [], "receivers": [], "providers": []}
    section = None
    for line in output.split("\n"):
        line = line.strip()
        if "Activity Resolver Table:" in line:
            section = "activities"
        elif "Service Resolver Table:" in line:
            section = "services"
        elif "Receiver Resolver Table:" in line:
            section = "receivers"
        elif "Provider Resolver Table:" in line:
            section = "providers"
        elif section and package_name in line:
            components[section].append(line[:200])
    return {"package": package_name, "components": components}


def check_data_storage(package_name, device_id=None):
    """Check for insecure data storage patterns."""
    adb = ["adb"] + (["-s", device_id] if device_id else [])
    findings = []
    # Check shared preferences for sensitive data
    sp_result = subprocess.run(
        adb + ["shell", "run-as", package_name, "ls", "shared_prefs/"],
        capture_output=True, text=True, timeout=10
    )
    if sp_result.returncode == 0:
        prefs = [f.strip() for f in sp_result.stdout.split("\n") if f.strip()]
        findings.append({"type": "shared_prefs", "files": prefs})
    # Check for world-readable files
    wr_result = subprocess.run(
        adb + ["shell", "run-as", package_name, "find", ".", "-perm", "-o+r", "-type", "f"],
        capture_output=True, text=True, timeout=10
    )
    if wr_result.stdout.strip():
        findings.append({"type": "world_readable", "files": wr_result.stdout.strip().split("\n")[:20]})
    return {"package": package_name, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description="Android Dynamic Analysis Agent")
    parser.add_argument("--device", help="ADB device ID")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("packages", help="List third-party packages")
    s = sub.add_parser("ssl", help="Check SSL pinning")
    s.add_argument("--package", required=True)
    c = sub.add_parser("components", help="Analyze exported components")
    c.add_argument("--package", required=True)
    d = sub.add_parser("storage", help="Check data storage security")
    d.add_argument("--package", required=True)
    n = sub.add_parser("network", help="Capture network traffic")
    n.add_argument("--duration", type=int, default=30)
    args = parser.parse_args()
    if args.command == "packages":
        result = list_packages(args.device)
    elif args.command == "ssl":
        result = check_ssl_pinning(args.package, args.device)
    elif args.command == "components":
        result = analyze_exported_components(args.package, args.device)
    elif args.command == "storage":
        result = check_data_storage(args.package, args.device)
    elif args.command == "network":
        result = capture_network_traffic(args.device, args.duration)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
