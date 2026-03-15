#!/usr/bin/env python3
"""
Palo Alto NGFW Security Policy Audit Script.
Connects to Palo Alto firewall via XML API and audits security policies
for common misconfigurations and best practice violations.
"""

import xml.etree.ElementTree as ET
import json
import sys
import urllib.request
import urllib.parse
import ssl
from datetime import datetime
from typing import Optional


class PaloAltoAuditor:
    """Audit Palo Alto NGFW security configuration against best practices."""

    def __init__(self, host: str, api_key: str, verify_ssl: bool = False):
        self.host = host
        self.api_key = api_key
        self.base_url = f"https://{host}/api/"
        self.findings = []

        if not verify_ssl:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self.ssl_context = ssl.create_default_context()

    def _api_request(self, params: dict) -> Optional[ET.Element]:
        """Make API request to Palo Alto firewall."""
        params['key'] = self.api_key
        query = urllib.parse.urlencode(params)
        url = f"{self.base_url}?{query}"

        try:
            req = urllib.request.Request(url)
            response = urllib.request.urlopen(req, context=self.ssl_context)
            xml_response = response.read()
            return ET.fromstring(xml_response)
        except Exception as e:
            print(f"API request failed: {e}")
            return None

    def get_security_rules(self) -> Optional[ET.Element]:
        """Retrieve security policy rules."""
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                     "/vsys/entry[@name='vsys1']/rulebase/security/rules"
        }
        return self._api_request(params)

    def get_decryption_rules(self) -> Optional[ET.Element]:
        """Retrieve decryption policy rules."""
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                     "/vsys/entry[@name='vsys1']/rulebase/decryption/rules"
        }
        return self._api_request(params)

    def get_zone_protection_profiles(self) -> Optional[ET.Element]:
        """Retrieve zone protection profiles."""
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': "/config/devices/entry[@name='localhost.localdomain']"
                     "/network/profiles/zone-protection-profile"
        }
        return self._api_request(params)

    def add_finding(self, severity: str, category: str, rule_name: str,
                    description: str, recommendation: str):
        """Add an audit finding."""
        self.findings.append({
            'severity': severity,
            'category': category,
            'rule_name': rule_name,
            'description': description,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat(),
        })

    def audit_security_rules(self, rules_xml: ET.Element):
        """Audit security rules for best practice violations."""
        if rules_xml is None:
            return

        rules = rules_xml.findall('.//entry')
        for rule in rules:
            name = rule.get('name', 'Unknown')

            # Check for any/any rules
            from_zones = [z.text for z in rule.findall('.//from/member')]
            to_zones = [z.text for z in rule.findall('.//to/member')]
            if 'any' in from_zones and 'any' in to_zones:
                self.add_finding(
                    'HIGH', 'Overly Permissive', name,
                    'Rule uses "any" for both source and destination zones',
                    'Specify explicit source and destination zones'
                )

            # Check for application "any"
            apps = [a.text for a in rule.findall('.//application/member')]
            if 'any' in apps:
                action = rule.findtext('.//action')
                if action == 'allow':
                    self.add_finding(
                        'HIGH', 'Application Control', name,
                        'Rule allows "any" application (port-based rule)',
                        'Use App-ID to specify allowed applications. '
                        'Use Policy Optimizer to identify actual applications.'
                    )

            # Check for missing security profiles
            profile_setting = rule.find('.//profile-setting')
            action = rule.findtext('.//action')
            if action == 'allow' and profile_setting is None:
                self.add_finding(
                    'HIGH', 'Threat Prevention', name,
                    'Allow rule has no Security Profile Group attached',
                    'Attach Anti-Virus, Anti-Spyware, Vulnerability, '
                    'URL Filtering, File Blocking, and WildFire profiles'
                )

            # Check for disabled rules
            disabled = rule.findtext('.//disabled')
            if disabled == 'yes':
                self.add_finding(
                    'LOW', 'Hygiene', name,
                    'Rule is disabled',
                    'Remove disabled rules to reduce policy complexity'
                )

            # Check for logging disabled
            log_end = rule.findtext('.//log-end')
            if log_end == 'no' and action == 'allow':
                self.add_finding(
                    'MEDIUM', 'Logging', name,
                    'Rule does not log at session end',
                    'Enable log-at-session-end for all allow rules'
                )

            # Check for service "any" instead of application-default
            services = [s.text for s in rule.findall('.//service/member')]
            if 'any' in services and 'any' not in apps:
                self.add_finding(
                    'MEDIUM', 'Service Enforcement', name,
                    'Rule uses "any" service instead of "application-default"',
                    'Use "application-default" to enforce standard ports for identified applications'
                )

    def audit_decryption(self, decryption_xml: ET.Element):
        """Audit SSL decryption coverage."""
        if decryption_xml is None:
            self.add_finding(
                'HIGH', 'SSL Decryption', 'N/A',
                'No SSL decryption policy is configured',
                'Configure SSL Forward Proxy for outbound traffic inspection '
                'and SSL Inbound Inspection for critical servers'
            )
            return

        rules = decryption_xml.findall('.//entry')
        has_decrypt = any(
            rule.findtext('.//action') == 'decrypt'
            for rule in rules
        )
        if not has_decrypt:
            self.add_finding(
                'HIGH', 'SSL Decryption', 'N/A',
                'No active decryption rules found',
                'Enable SSL Forward Proxy to inspect encrypted traffic'
            )

    def generate_report(self) -> dict:
        """Generate audit report."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            severity_counts[finding['severity']] = \
                severity_counts.get(finding['severity'], 0) + 1

        report = {
            'audit_date': datetime.now().isoformat(),
            'firewall_host': self.host,
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': severity_counts,
            },
            'findings': self.findings,
        }
        return report

    def run_audit(self):
        """Execute full audit."""
        print(f"[*] Starting audit of {self.host}...")

        print("[*] Auditing security rules...")
        security_rules = self.get_security_rules()
        self.audit_security_rules(security_rules)

        print("[*] Auditing decryption policy...")
        decryption_rules = self.get_decryption_rules()
        self.audit_decryption(decryption_rules)

        report = self.generate_report()

        print(f"\n{'='*70}")
        print(f"PALO ALTO NGFW SECURITY AUDIT REPORT")
        print(f"{'='*70}")
        print(f"Host: {report['firewall_host']}")
        print(f"Date: {report['audit_date']}")
        print(f"\nTotal Findings: {report['summary']['total_findings']}")
        for sev, count in report['summary']['by_severity'].items():
            print(f"  {sev}: {count}")

        print(f"\n{'='*70}")
        for finding in self.findings:
            print(f"\n[{finding['severity']}] {finding['category']} - {finding['rule_name']}")
            print(f"  Issue: {finding['description']}")
            print(f"  Fix: {finding['recommendation']}")

        # Save JSON report
        report_path = f"paloalto_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {report_path}")

        return report


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python process.py <firewall_host> <api_key>")
        print("Example: python process.py 10.0.1.1 LUFRPT1234567890==")
        sys.exit(1)

    host = sys.argv[1]
    api_key = sys.argv[2]

    auditor = PaloAltoAuditor(host, api_key)
    auditor.run_audit()
