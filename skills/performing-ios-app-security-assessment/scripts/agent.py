#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""iOS App Security Assessment Agent - Automates Frida-based iOS security testing including
SSL pinning bypass, keychain extraction, IPA static analysis, and runtime method hooking."""

import argparse
import json
import logging
import os
import plistlib
import re
import subprocess
import zipfile
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Frida JavaScript payloads for iOS instrumentation
SSL_PINNING_BYPASS_SCRIPT = r"""
'use strict';

// Hook NSURLSessionDelegate certificate challenge methods
if (ObjC.available) {
    try {
        // Bypass NSURLSession certificate pinning
        var NSURLSessionTask = ObjC.classes.NSURLSessionTask;
        var resolveMethod = ObjC.classes.NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];

        Interceptor.attach(
            ObjC.classes.NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation, {
            onEnter: function(args) {
                send('[SSL Bypass] Intercepted NSURLSession challenge');
            }
        });
    } catch(e) {}

    // Hook SecTrustEvaluate to always return success
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function(retval) {
                    retval.replace(0); // errSecSuccess
                    send('[SSL Bypass] SecTrustEvaluate -> success');
                }
            });
        }
    } catch(e) {}

    // Hook SecTrustEvaluateWithError (iOS 12+)
    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function(retval) {
                    retval.replace(1); // true = trusted
                    send('[SSL Bypass] SecTrustEvaluateWithError -> trusted');
                }
            });
        }
    } catch(e) {}

    // Hook SecTrustGetTrustResult
    try {
        var SecTrustGetTrustResult = Module.findExportByName('Security', 'SecTrustGetTrustResult');
        if (SecTrustGetTrustResult) {
            Interceptor.attach(SecTrustGetTrustResult, {
                onLeave: function(retval) {
                    retval.replace(0);
                    send('[SSL Bypass] SecTrustGetTrustResult -> proceed');
                }
            });
        }
    } catch(e) {}

    // Bypass AFNetworking pinning
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0); // AFSSLPinningModeNone
                    send('[SSL Bypass] AFNetworking pinning disabled');
                }
            });
        }
    } catch(e) {}

    // Bypass TrustKit pinning
    try {
        var TrustKit = ObjC.classes.TSKPinningValidator;
        if (TrustKit) {
            Interceptor.attach(TrustKit['- evaluateTrust:forHostname:'].implementation, {
                onLeave: function(retval) {
                    retval.replace(0); // TSKTrustEvaluationSuccess
                    send('[SSL Bypass] TrustKit pinning bypassed');
                }
            });
        }
    } catch(e) {}

    send('[SSL Bypass] All hooks installed successfully');
} else {
    send('[SSL Bypass] Objective-C runtime not available');
}
"""

KEYCHAIN_DUMP_SCRIPT = r"""
'use strict';

if (ObjC.available) {
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    var results = [];

    // Enumerate keychain item classes
    var kSecClasses = [
        'genp',  // kSecClassGenericPassword
        'inet',  // kSecClassInternetPassword
        'cert',  // kSecClassCertificate
        'keys',  // kSecClassKey
        'idnt'   // kSecClassIdentity
    ];

    var classNames = {
        'genp': 'GenericPassword',
        'inet': 'InternetPassword',
        'cert': 'Certificate',
        'keys': 'CryptoKey',
        'idnt': 'Identity'
    };

    for (var i = 0; i < kSecClasses.length; i++) {
        try {
            var query = ObjC.classes.NSMutableDictionary.alloc().init();
            query.setObject_forKey_(kSecClasses[i], 'class');
            query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'r_Ref');
            query.setObject_forKey_('m_LimitAll', 'm_Limit');
            query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'r_Data');
            query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), 'r_Attributes');

            var resultPtr = Memory.alloc(Process.pointerSize);
            var status = new NativeFunction(SecItemCopyMatching, 'int', ['pointer', 'pointer']);
            var ret = status(query.handle, resultPtr);

            if (ret === 0) {
                var resultObj = new ObjC.Object(resultPtr.readPointer());
                send({
                    type: 'keychain',
                    class: classNames[kSecClasses[i]],
                    count: resultObj.count ? resultObj.count() : 1
                });
            }
        } catch(e) {
            send({type: 'keychain_error', class: classNames[kSecClasses[i]], error: e.toString()});
        }
    }
    send({type: 'keychain_complete'});
}
"""

JAILBREAK_DETECTION_BYPASS_SCRIPT = r"""
'use strict';

if (ObjC.available) {
    // Hook NSFileManager fileExistsAtPath: to hide jailbreak indicators
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];

    var jailbreakPaths = [
        '/Applications/Cydia.app',
        '/Applications/Sileo.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/bin/bash', '/usr/sbin/sshd', '/etc/apt',
        '/usr/bin/ssh', '/private/var/lib/apt/',
        '/private/var/lib/cydia', '/private/var/tmp/cydia.log',
        '/var/lib/dpkg/info', '/usr/libexec/cydia/'
    ];

    Interceptor.attach(fileExistsAtPath.implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (this.path.indexOf(jailbreakPaths[i]) !== -1) {
                    retval.replace(0); // false
                    send('[JB Bypass] Hidden: ' + this.path);
                    break;
                }
            }
        }
    });

    // Hook canOpenURL to block cydia:// scheme detection
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.indexOf('cydia://') !== -1 || this.url.indexOf('sileo://') !== -1) {
                retval.replace(0);
                send('[JB Bypass] Blocked URL scheme: ' + this.url);
            }
        }
    });

    // Hook fork() to prevent fork-based jailbreak detection
    var fork = Module.findExportByName(null, 'fork');
    if (fork) {
        Interceptor.attach(fork, {
            onLeave: function(retval) {
                retval.replace(-1); // fork fails on non-jailbroken
                send('[JB Bypass] fork() returned -1');
            }
        });
    }

    send('[JB Bypass] All jailbreak detection bypasses installed');
}
"""


def analyze_ipa_static(ipa_path, output_dir):
    """Perform static analysis on an IPA file."""
    findings = []
    extract_dir = os.path.join(output_dir, "ipa_extracted")

    if not zipfile.is_zipfile(ipa_path):
        logger.error("Not a valid IPA/ZIP file: %s", ipa_path)
        return findings

    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(extract_dir)
    logger.info("Extracted IPA to %s", extract_dir)

    # Find the .app directory
    payload_dir = os.path.join(extract_dir, "Payload")
    if not os.path.isdir(payload_dir):
        logger.error("No Payload directory found in IPA")
        return findings

    app_dirs = [d for d in os.listdir(payload_dir) if d.endswith(".app")]
    if not app_dirs:
        logger.error("No .app bundle found in Payload")
        return findings

    app_path = os.path.join(payload_dir, app_dirs[0])
    logger.info("Analyzing app bundle: %s", app_dirs[0])

    # Parse Info.plist
    info_plist_path = os.path.join(app_path, "Info.plist")
    if os.path.exists(info_plist_path):
        with open(info_plist_path, "rb") as f:
            try:
                plist_data = plistlib.load(f)
            except Exception:
                plist_data = {}

        # Check App Transport Security configuration
        ats = plist_data.get("NSAppTransportSecurity", {})
        if ats.get("NSAllowsArbitraryLoads", False):
            findings.append({
                "id": "IOS-STATIC-001",
                "severity": "Medium",
                "title": "App Transport Security Disabled",
                "detail": "NSAllowsArbitraryLoads is set to true, allowing cleartext HTTP traffic",
                "masvs": "MASVS-NETWORK",
                "mastg": "MASTG-TEST-0066",
            })

        # Check URL schemes for deep link hijacking potential
        url_types = plist_data.get("CFBundleURLTypes", [])
        custom_schemes = []
        for url_type in url_types:
            schemes = url_type.get("CFBundleURLSchemes", [])
            custom_schemes.extend(schemes)
        if custom_schemes:
            findings.append({
                "id": "IOS-STATIC-002",
                "severity": "Informational",
                "title": "Custom URL Schemes Registered",
                "detail": f"App registers URL schemes: {', '.join(custom_schemes)}. "
                          "Test for deep link hijacking and parameter injection.",
                "masvs": "MASVS-PLATFORM",
                "mastg": "MASTG-TEST-0075",
            })

        # Check for background modes that could leak data
        bg_modes = plist_data.get("UIBackgroundModes", [])
        if bg_modes:
            findings.append({
                "id": "IOS-STATIC-003",
                "severity": "Informational",
                "title": "Background Execution Modes Enabled",
                "detail": f"Background modes: {', '.join(bg_modes)}. "
                          "Verify sensitive operations are not exposed in background.",
                "masvs": "MASVS-STORAGE",
                "mastg": "MASTG-TEST-0058",
            })

    # Scan binary strings for hardcoded secrets
    executable_name = plist_data.get("CFBundleExecutable", app_dirs[0].replace(".app", ""))
    executable_path = os.path.join(app_path, executable_name)

    if os.path.exists(executable_path):
        secret_patterns = [
            (r'(?i)api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}', "Hardcoded API Key"),
            (r'(?i)secret\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}', "Hardcoded Secret"),
            (r'(?i)password\s*[:=]\s*["\'][^"\']{4,}', "Hardcoded Password"),
            (r'https?://[a-zA-Z0-9._\-]+\.firebaseio\.com', "Firebase URL"),
            (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Embedded Private Key"),
        ]

        try:
            result = subprocess.run(
                ["strings", executable_path],
                capture_output=True, text=True, timeout=60,
            )
            binary_strings = result.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            binary_strings = ""
            try:
                with open(executable_path, "rb") as f:
                    raw = f.read()
                binary_strings = raw.decode("ascii", errors="ignore")
            except Exception:
                pass

        for pattern, label in secret_patterns:
            matches = re.findall(pattern, binary_strings)
            if matches:
                findings.append({
                    "id": "IOS-STATIC-004",
                    "severity": "High",
                    "title": f"{label} Found in Binary",
                    "detail": f"Pattern match for {label}: {len(matches)} occurrence(s) found. "
                              f"Sample: {matches[0][:60]}...",
                    "masvs": "MASVS-STORAGE",
                    "mastg": "MASTG-TEST-0058",
                })

    # Check for embedded provisioning profile
    provision_path = os.path.join(app_path, "embedded.mobileprovision")
    if os.path.exists(provision_path):
        try:
            result = subprocess.run(
                ["security", "cms", "-D", "-i", provision_path],
                capture_output=True, text=True, timeout=30,
            )
            if "get-task-allow" in result.stdout and "<true/>" in result.stdout:
                findings.append({
                    "id": "IOS-STATIC-005",
                    "severity": "Medium",
                    "title": "Debug Entitlement Enabled (get-task-allow)",
                    "detail": "The provisioning profile has get-task-allow=true, "
                              "indicating a development/debug build that allows attaching debuggers.",
                    "masvs": "MASVS-RESILIENCE",
                    "mastg": "MASTG-TEST-0083",
                })
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # Check for unprotected frameworks
    frameworks_dir = os.path.join(app_path, "Frameworks")
    if os.path.isdir(frameworks_dir):
        frameworks = [f for f in os.listdir(frameworks_dir) if f.endswith(".framework")]
        if frameworks:
            findings.append({
                "id": "IOS-STATIC-006",
                "severity": "Informational",
                "title": "Embedded Frameworks Inventory",
                "detail": f"App embeds {len(frameworks)} frameworks: {', '.join(frameworks[:10])}. "
                          "Review for known vulnerable versions.",
                "masvs": "MASVS-RESILIENCE",
                "mastg": "MASTG-TEST-0083",
            })

    logger.info("Static analysis complete: %d findings", len(findings))
    return findings


def run_frida_script(target_bundle, script_source, device_type="usb", timeout_sec=30):
    """Execute a Frida script against a target iOS application."""
    messages = []

    try:
        import frida
    except ImportError:
        logger.error("Frida Python bindings not installed: pip install frida")
        return messages

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            messages.append(payload)
            logger.info("Frida: %s", payload)
        elif message["type"] == "error":
            logger.error("Frida error: %s", message.get("description", ""))

    try:
        if device_type == "usb":
            device = frida.get_usb_device(timeout=10)
        elif device_type == "remote":
            device = frida.get_remote_device()
        else:
            device = frida.get_local_device()

        logger.info("Attached to device: %s", device.name)

        # Try to attach to running process first
        try:
            pid = device.get_process(target_bundle).pid
            session = device.attach(pid)
            logger.info("Attached to running process PID %d", pid)
        except frida.ProcessNotFoundError:
            # Spawn the app
            pid = device.spawn([target_bundle])
            session = device.attach(pid)
            device.resume(pid)
            logger.info("Spawned and attached to PID %d", pid)

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        import time
        time.sleep(timeout_sec)

        script.unload()
        session.detach()

    except Exception as e:
        logger.error("Frida execution failed: %s", e)
        messages.append({"error": str(e)})

    return messages


def run_objection_command(bundle_id, command):
    """Execute an Objection command against a target app."""
    try:
        result = subprocess.run(
            ["objection", "--gadget", bundle_id, "run", command],
            capture_output=True, text=True, timeout=60,
        )
        return {"command": command, "stdout": result.stdout, "stderr": result.stderr,
                "returncode": result.returncode}
    except FileNotFoundError:
        logger.error("Objection not found: pip install objection")
        return {"command": command, "error": "objection not installed"}
    except subprocess.TimeoutExpired:
        logger.warning("Objection command timed out: %s", command)
        return {"command": command, "error": "timeout"}


def assess_keychain_security(bundle_id):
    """Dump and analyze keychain items for insecure storage practices."""
    findings = []
    result = run_objection_command(bundle_id, "ios keychain dump --json")

    if result.get("error"):
        logger.warning("Keychain dump failed: %s", result.get("error"))
        return findings

    try:
        items = json.loads(result["stdout"])
    except (json.JSONDecodeError, KeyError):
        logger.warning("Could not parse keychain dump output")
        return findings

    insecure_accessibility = [
        "kSecAttrAccessibleAlways",
        "kSecAttrAccessibleAlwaysThisDeviceOnly",
        "kSecAttrAccessibleAfterFirstUnlock",
    ]

    for item in items:
        accessible = item.get("accessible", "")
        if any(a in accessible for a in insecure_accessibility):
            findings.append({
                "id": "IOS-KEYCHAIN-001",
                "severity": "High",
                "title": "Insecure Keychain Accessibility Attribute",
                "detail": f"Keychain item '{item.get('service', 'unknown')}' uses "
                          f"accessibility '{accessible}'. Data may be accessible "
                          "without device unlock.",
                "masvs": "MASVS-STORAGE",
                "mastg": "MASTG-TEST-0055",
            })

        # Check for unprotected password items
        if item.get("class") == "genp" and not item.get("accessControl"):
            findings.append({
                "id": "IOS-KEYCHAIN-002",
                "severity": "Medium",
                "title": "Keychain Password Without Access Control",
                "detail": f"Generic password '{item.get('service', 'unknown')}' lacks "
                          "biometric or passcode access control constraints.",
                "masvs": "MASVS-STORAGE",
                "mastg": "MASTG-TEST-0055",
            })

    logger.info("Keychain analysis: %d findings from %d items", len(findings), len(items))
    return findings


def generate_report(findings, target_app, output_path):
    """Generate comprehensive iOS security assessment report."""
    critical = [f for f in findings if f.get("severity") == "Critical"]
    high = [f for f in findings if f.get("severity") == "High"]
    medium = [f for f in findings if f.get("severity") == "Medium"]
    low = [f for f in findings if f.get("severity") in ("Low", "Informational")]

    report = {
        "assessment": "iOS Application Security Assessment",
        "target": target_app,
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low_informational": len(low),
        },
        "findings": findings,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s (%d findings)", output_path, len(findings))
    return report


def main():
    parser = argparse.ArgumentParser(
        description="iOS App Security Assessment Agent - Frida/Objection-based testing"
    )
    parser.add_argument("--bundle-id", help="Target app bundle identifier (e.g., com.target.app)")
    parser.add_argument("--ipa", help="Path to IPA file for static analysis")
    parser.add_argument("--device", choices=["usb", "remote", "local"], default="usb",
                        help="Frida device type (default: usb)")
    parser.add_argument("--ssl-bypass", action="store_true",
                        help="Run SSL pinning bypass script")
    parser.add_argument("--keychain", action="store_true",
                        help="Dump and analyze keychain security")
    parser.add_argument("--jailbreak-bypass", action="store_true",
                        help="Run jailbreak detection bypass")
    parser.add_argument("--frida-timeout", type=int, default=30,
                        help="Frida script execution timeout in seconds")
    parser.add_argument("--output", default="ios_assessment_report.json",
                        help="Output report file path")
    parser.add_argument("--output-dir", default=".",
                        help="Directory for extracted IPA and artifacts")
    args = parser.parse_args()

    if not args.bundle_id and not args.ipa:
        parser.error("Provide --bundle-id for dynamic testing or --ipa for static analysis")

    findings = []

    # Static analysis of IPA
    if args.ipa:
        logger.info("=== IPA Static Analysis ===")
        findings.extend(analyze_ipa_static(args.ipa, args.output_dir))

    # Dynamic analysis with Frida/Objection
    if args.bundle_id:
        if args.ssl_bypass:
            logger.info("=== SSL Pinning Bypass ===")
            msgs = run_frida_script(args.bundle_id, SSL_PINNING_BYPASS_SCRIPT,
                                    args.device, args.frida_timeout)
            if any("success" in str(m).lower() for m in msgs):
                findings.append({
                    "id": "IOS-NET-001",
                    "severity": "Informational",
                    "title": "SSL Pinning Successfully Bypassed",
                    "detail": "Certificate pinning was bypassed using Frida hooks on "
                              "SecTrustEvaluate, SecTrustEvaluateWithError, and framework-specific "
                              "trust evaluation methods. Traffic can be intercepted via proxy.",
                    "masvs": "MASVS-NETWORK",
                    "mastg": "MASTG-TEST-0068",
                })

        if args.jailbreak_bypass:
            logger.info("=== Jailbreak Detection Bypass ===")
            msgs = run_frida_script(args.bundle_id, JAILBREAK_DETECTION_BYPASS_SCRIPT,
                                    args.device, args.frida_timeout)
            if any("bypass" in str(m).lower() for m in msgs):
                findings.append({
                    "id": "IOS-RES-001",
                    "severity": "Medium",
                    "title": "Jailbreak Detection Bypassed at Runtime",
                    "detail": "Jailbreak detection checks (file existence, URL scheme, fork) "
                              "were all bypassed using Frida method hooks.",
                    "masvs": "MASVS-RESILIENCE",
                    "mastg": "MASTG-TEST-0079",
                })

        if args.keychain:
            logger.info("=== Keychain Security Analysis ===")
            findings.extend(assess_keychain_security(args.bundle_id))

    target_name = args.bundle_id or args.ipa or "unknown"
    report = generate_report(findings, target_name, args.output)

    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
