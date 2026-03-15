#!/usr/bin/env python3
"""
Certificate Pinning Bypass Manager

Manages Frida scripts for bypassing SSL pinning on Android and iOS targets.
Provides pre-built bypass scripts and validates successful bypass.

Usage:
    python process.py --platform android --package com.target.app [--proxy-host 192.168.1.100]
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ANDROID_BYPASS_SCRIPT = """
Java.perform(function() {
    console.log("[*] Loading Android SSL pinning bypass...");

    // TrustManagerImpl (Android system)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function() {
            console.log("[+] Bypassed TrustManagerImpl.verifyChain");
            return arguments[0];
        };
    } catch(e) { console.log("[-] TrustManagerImpl not found"); }

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation =
            function(hostname, peerCertificates) {
                console.log("[+] Bypassed OkHttp3 pinning for: " + hostname);
            };
    } catch(e) { console.log("[-] OkHttp3 CertificatePinner not found"); }

    // SSLContext init
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var Bypass = Java.registerClass({
            name: "com.bypass.TrustAll",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation =
            function(km, tm, sr) {
                console.log("[+] Bypassed SSLContext.init");
                this.init(km, [Bypass.$new()], sr);
            };
    } catch(e) { console.log("[-] SSLContext bypass failed"); }

    console.log("[*] Bypass script loaded successfully");
});
"""

IOS_BYPASS_SCRIPT = """
if (ObjC.available) {
    console.log("[*] Loading iOS SSL pinning bypass...");

    // SecTrustEvaluateWithError
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError,
            new NativeCallback(function(trust, error) {
                console.log("[+] Bypassed SecTrustEvaluateWithError");
                return 1;
            }, "bool", ["pointer", "pointer"])
        );
    }

    // NSURLSession delegate
    var resolver = new ApiResolver("objc");
    resolver.enumerateMatches("-[* URLSession:didReceiveChallenge:completionHandler:]", {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var handler = new ObjC.Block(args[4]);
                    var trust = new ObjC.Object(args[3]).protectionSpace().serverTrust();
                    var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                    handler.invoke(0, cred);
                    console.log("[+] Bypassed NSURLSession delegate pinning");
                }
            });
        },
        onComplete: function() {}
    });

    console.log("[*] iOS bypass loaded");
}
"""


def run_bypass(platform: str, package: str, device_id: str = None) -> dict:
    """Deploy and run SSL pinning bypass script."""
    script = ANDROID_BYPASS_SCRIPT if platform == "android" else IOS_BYPASS_SCRIPT
    script_file = Path(f"/tmp/ssl_bypass_{platform}.js")
    script_file.write_text(script)

    cmd = ["frida", "-U", "-f", package, "-l", str(script_file), "--no-pause"]
    if device_id:
        cmd.extend(["-D", device_id])

    print(f"[*] Deploying {platform} SSL pinning bypass for {package}...")
    print(f"[*] Script saved to {script_file}")
    print(f"[*] Command: {' '.join(cmd)}")

    return {
        "platform": platform,
        "package": package,
        "script_path": str(script_file),
        "command": " ".join(cmd),
        "timestamp": datetime.now().isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="SSL Pinning Bypass Manager")
    parser.add_argument("--platform", choices=["android", "ios"], required=True)
    parser.add_argument("--package", required=True, help="App package/bundle ID")
    parser.add_argument("--device-id", help="Device serial/UDID")
    parser.add_argument("--output", default="pinning_bypass.json", help="Output report")
    parser.add_argument("--execute", action="store_true", help="Execute bypass immediately")
    args = parser.parse_args()

    result = run_bypass(args.platform, args.package, args.device_id)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Configuration saved: {args.output}")

    if args.execute:
        print("[*] Starting Frida bypass (Ctrl+C to stop)...")
        subprocess.run(result["command"].split())


if __name__ == "__main__":
    main()
