#!/usr/bin/env python3
"""Agent for static analysis of Android APK malware using androguard."""

import json
import re
import argparse
from datetime import datetime

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.misc import AnalyzeAPK
except ImportError:
    APK = None
    AnalyzeAPK = None

DANGEROUS_PERMISSIONS = [
    "android.permission.SEND_SMS", "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.INSTALL_PACKAGES", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN", "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WRITE_SETTINGS", "android.permission.CHANGE_WIFI_STATE",
]

SUSPICIOUS_API_PATTERNS = [
    r"Ljava/lang/Runtime;->exec",
    r"Ljava/lang/ProcessBuilder;->start",
    r"Ldalvik/system/DexClassLoader;->loadClass",
    r"Ljava/lang/reflect/Method;->invoke",
    r"Ljava/lang/Class;->forName",
    r"Ljavax/crypto/Cipher;->getInstance",
    r"Landroid/telephony/SmsManager;->sendTextMessage",
    r"Landroid/app/admin/DevicePolicyManager;->lockNow",
    r"Landroid/content/pm/PackageManager;->setComponentEnabledSetting",
    r"Ljava/net/HttpURLConnection;->connect",
    r"Lokhttp3/OkHttpClient;->newCall",
    r"Landroid/webkit/WebView;->loadUrl",
    r"Landroid/os/Build;->SERIAL",
    r"Landroid/provider/Settings\$Secure;->getString",
]


def analyze_permissions(apk):
    """Analyze requested permissions and flag dangerous ones."""
    permissions = apk.get_permissions()
    dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    return {
        "total_permissions": len(permissions),
        "permissions": permissions,
        "dangerous_permissions": dangerous,
        "dangerous_count": len(dangerous),
        "permission_risk": "CRITICAL" if len(dangerous) >= 8 else "HIGH" if len(dangerous) >= 5 else "MEDIUM" if len(dangerous) >= 2 else "LOW",
    }


def analyze_manifest(apk):
    """Extract manifest components: activities, services, receivers, providers."""
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()
    return {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "activities": list(activities),
        "services": list(services),
        "receivers": list(receivers),
        "providers": list(providers),
        "activity_count": len(activities),
        "service_count": len(services),
        "receiver_count": len(receivers),
        "provider_count": len(providers),
    }


def scan_suspicious_apis(dx):
    """Scan DEX analysis for suspicious API calls."""
    findings = []
    if not dx:
        return findings
    for pattern in SUSPICIOUS_API_PATTERNS:
        class_name = pattern.split(";->")[0] + ";"
        method_name = pattern.split(";->")[1] if ";->" in pattern else None
        for method in dx.find_methods(classname=class_name, methodname=method_name):
            xrefs = list(method.get_xref_from())
            if xrefs:
                findings.append({
                    "api": pattern,
                    "callers": len(xrefs),
                    "first_caller_class": str(xrefs[0][0].name) if xrefs else None,
                })
    return findings


def extract_strings(dx, apk):
    """Extract suspicious strings: URLs, IPs, base64 patterns."""
    url_pattern = re.compile(r'https?://[\w\-._~:/?#\[\]@!$&\'()*+,;=]+', re.IGNORECASE)
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{30,}={0,2}')

    urls = set()
    ips = set()
    b64_strings = []

    if dx:
        for s in dx.get_strings():
            val = str(s)
            urls.update(url_pattern.findall(val))
            ips.update(ip_pattern.findall(val))
            b64_matches = b64_pattern.findall(val)
            b64_strings.extend(b64_matches[:5])

    private_ips = {"10.", "192.168.", "172.16.", "127.0."}
    external_ips = [ip for ip in ips if not any(ip.startswith(p) for p in private_ips)]

    return {
        "urls": sorted(urls)[:30],
        "external_ips": sorted(external_ips)[:20],
        "suspicious_base64": b64_strings[:10],
        "url_count": len(urls),
        "external_ip_count": len(external_ips),
    }


def detect_obfuscation(apk, dx):
    """Detect code obfuscation indicators."""
    indicators = []
    if dx:
        short_class_names = 0
        for cls in dx.get_classes():
            name = str(cls.name)
            parts = name.replace("/", ".").split(".")
            if any(len(p) == 1 and p.isalpha() for p in parts):
                short_class_names += 1
        if short_class_names > 10:
            indicators.append({"type": "single_letter_classes", "count": short_class_names})

    dex_files = [f for f in apk.get_files() if f.endswith(".dex")]
    if len(dex_files) > 1:
        indicators.append({"type": "multi_dex", "dex_count": len(dex_files)})

    native_libs = [f for f in apk.get_files() if f.endswith(".so")]
    if native_libs:
        indicators.append({"type": "native_libraries", "libs": native_libs[:10]})

    return {
        "obfuscation_indicators": indicators,
        "likely_obfuscated": len(indicators) > 0,
    }


def full_analysis(apk_path):
    """Run comprehensive APK malware analysis."""
    if not APK or not AnalyzeAPK:
        return {"error": "androguard not installed: pip install androguard"}

    a, d, dx = AnalyzeAPK(apk_path)

    perm_analysis = analyze_permissions(a)
    manifest = analyze_manifest(a)
    suspicious_apis = scan_suspicious_apis(dx)
    strings = extract_strings(dx, a)
    obfuscation = detect_obfuscation(a, dx)

    risk_score = 0
    risk_score += min(perm_analysis["dangerous_count"] * 8, 40)
    risk_score += min(len(suspicious_apis) * 10, 30)
    risk_score += min(strings["external_ip_count"] * 5, 15)
    risk_score += 15 if obfuscation["likely_obfuscated"] else 0
    risk_score = min(risk_score, 100)

    return {
        "analysis_type": "Android APK Static Analysis",
        "timestamp": datetime.utcnow().isoformat(),
        "file": apk_path,
        "manifest": manifest,
        "permissions": perm_analysis,
        "suspicious_apis": suspicious_apis[:20],
        "strings": strings,
        "obfuscation": obfuscation,
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW",
        "mitre_techniques": [
            {"id": "T1418", "name": "Software Discovery"} if manifest["service_count"] > 5 else None,
            {"id": "T1417", "name": "Input Capture"} if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_analysis["permissions"] else None,
            {"id": "T1582", "name": "SMS Control"} if "android.permission.SEND_SMS" in perm_analysis["permissions"] else None,
            {"id": "T1404", "name": "Exploitation for Privilege Escalation"} if any("DevicePolicyManager" in a.get("api", "") for a in suspicious_apis) else None,
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Android APK Malware Analysis Agent")
    parser.add_argument("apk", help="Path to APK file")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("permissions", help="Analyze permissions")
    sub.add_parser("manifest", help="Extract manifest components")
    sub.add_parser("apis", help="Scan for suspicious API calls")
    sub.add_parser("strings", help="Extract URLs, IPs, and encoded strings")
    sub.add_parser("full", help="Full malware analysis")
    args = parser.parse_args()

    if args.command == "full" or args.command is None:
        result = full_analysis(args.apk)
    else:
        a, d, dx = AnalyzeAPK(args.apk)
        if args.command == "permissions":
            result = analyze_permissions(a)
        elif args.command == "manifest":
            result = analyze_manifest(a)
        elif args.command == "apis":
            result = scan_suspicious_apis(dx)
        elif args.command == "strings":
            result = extract_strings(dx, a)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
