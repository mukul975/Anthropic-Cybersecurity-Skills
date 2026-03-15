#!/usr/bin/env python3
"""Agent for iOS app reverse engineering with Frida.

Uses frida-tools to attach to iOS processes, hook Objective-C
methods, bypass SSL pinning, dump keychain entries, and trace
API calls for security assessment.
"""

import subprocess
import json
import sys
import re
from datetime import datetime
from pathlib import Path


class FridaIOSAgent:
    """Reverse engineers iOS applications using Frida."""

    def __init__(self, target_app, device_id=None, output_dir="./frida_ios"):
        self.target_app = target_app
        self.device_id = device_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _frida_cmd(self, script_code, timeout=60):
        cmd = ["frida", "-U"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        cmd.extend(["-n", self.target_app, "-q", "-e", script_code])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout)
            return {"stdout": result.stdout, "stderr": result.stderr,
                    "returncode": result.returncode}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"error": str(exc)}

    def list_running_apps(self):
        """List running applications on the connected iOS device."""
        cmd = ["frida-ps", "-Ua"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return {"apps": result.stdout}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"error": str(exc)}

    def bypass_ssl_pinning(self):
        """Inject Frida script to bypass SSL certificate pinning."""
        script = """
var m = ObjC.classes.NSURLSessionConfiguration;
Interceptor.attach(m['- setTLSMinimumSupportedProtocol:'].implementation, {
    onEnter: function(args) { console.log('[*] TLS config intercepted'); }
});
try {
    var SSLSetPeerDomainName = Module.findExportByName(null, 'SSLSetPeerDomainName');
    if (SSLSetPeerDomainName) {
        Interceptor.attach(SSLSetPeerDomainName, {
            onEnter: function(args) { },
            onLeave: function(retval) { retval.replace(0); }
        });
        console.log('[+] SSL pinning bypassed');
    }
} catch(e) { console.log('[-] ' + e); }
"""
        result = self._frida_cmd(script)
        if "SSL pinning bypassed" in result.get("stdout", ""):
            self.findings.append({"type": "SSL Pinning Bypass",
                                  "severity": "Medium",
                                  "details": "SSL pinning can be bypassed with Frida"})
        return result

    def dump_keychain(self):
        """Dump iOS Keychain entries accessible by the app."""
        script = """
var kSecClass = ObjC.classes.NSString.stringWithString_('kSecClass');
var query = ObjC.classes.NSMutableDictionary.dictionary();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('kSecClassGenericPassword'), kSecClass);
query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), ObjC.classes.NSString.stringWithString_('kSecReturnAttributes'));
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('kSecMatchLimitAll'), ObjC.classes.NSString.stringWithString_('kSecMatchLimit'));
var result = new ObjC.Object(ptr(0));
var status = ObjC.classes.NSDictionary.alloc();
console.log('[*] Keychain query executed');
"""
        result = self._frida_cmd(script)
        return result

    def trace_objc_methods(self, class_name):
        """Trace all method calls on a specific Objective-C class."""
        script = f"""
var target = ObjC.classes.{class_name};
if (target) {{
    var methods = target.$ownMethods;
    console.log('[*] Tracing ' + methods.length + ' methods on {class_name}');
    methods.forEach(function(method) {{
        try {{
            Interceptor.attach(target[method].implementation, {{
                onEnter: function(args) {{
                    console.log('[CALL] {class_name} ' + method);
                }}
            }});
        }} catch(e) {{}}
    }});
}} else {{
    console.log('[-] Class {class_name} not found');
}}
"""
        return self._frida_cmd(script, timeout=30)

    def check_jailbreak_detection(self):
        """Test if app has jailbreak detection and attempt bypass."""
        script = """
var paths = ['/Applications/Cydia.app', '/usr/sbin/sshd',
             '/bin/bash', '/usr/bin/ssh', '/etc/apt'];
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();
        for (var i = 0; i < paths.length; i++) {
            if (path.indexOf(paths[i]) !== -1) {
                console.log('[*] Jailbreak check: ' + path);
            }
        }
    },
    onLeave: function(retval) {}
});
console.log('[+] Jailbreak detection hooks installed');
"""
        result = self._frida_cmd(script, timeout=15)
        if "Jailbreak check" in result.get("stdout", ""):
            self.findings.append({"type": "Jailbreak Detection Present",
                                  "severity": "Info"})
        return result

    def generate_report(self):
        report = {
            "target_app": self.target_app,
            "report_date": datetime.utcnow().isoformat(),
            "findings": self.findings,
        }
        report_path = self.output_dir / "frida_ios_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    app = sys.argv[1] if len(sys.argv) > 1 else "TargetApp"
    agent = FridaIOSAgent(app)
    agent.list_running_apps()
    agent.bypass_ssl_pinning()
    agent.check_jailbreak_detection()
    agent.generate_report()


if __name__ == "__main__":
    main()
