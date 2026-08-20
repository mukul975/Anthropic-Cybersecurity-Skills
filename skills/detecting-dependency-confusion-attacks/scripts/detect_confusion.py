#!/usr/bin/env python3
"""
Dependency Confusion Detection Script

Monitors public registries (npm, PyPI, RubyGems, Maven Central) for packages
matching internal package names. Alerts when collisions are detected.

Usage:
  python detect_confusion.py --packages internal_packages.txt --registries npm,pypi
  python detect_confusion.py --continuous --interval 86400  # Daily monitoring
"""

import argparse
import json
import sys
import time
import requests
from datetime import datetime, timezone
from typing import List, Dict, Optional

# ANSI color codes for terminal output
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'

class RegistryChecker:
    """Base class for registry checking."""
    
    def check_package(self, package_name: str) -> Optional[Dict]:
        """Check if package exists on registry. Returns metadata if found."""
        raise NotImplementedError

class NPMChecker(RegistryChecker):
    """npm registry checker."""
    
    def check_package(self, package_name: str) -> Optional[Dict]:
        try:
            response = requests.get(
                f"https://registry.npmjs.org/{package_name}",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                latest_version = data['dist-tags'].get('latest', 'unknown')
                
                # Check for install scripts
                latest_data = data.get('versions', {}).get(latest_version, {})
                scripts = latest_data.get('scripts', {})
                has_install_scripts = any(k in scripts for k in 
                    ['preinstall', 'install', 'postinstall'])
                
                return {
                    'registry': 'npm',
                    'package': package_name,
                    'version': latest_version,
                    'author': data.get('author', {}).get('name', 'unknown'),
                    'published': data.get('time', {}).get('created', 'unknown'),
                    'has_install_scripts': has_install_scripts,
                    'downloads': data.get('downloads', {}).get('last-month', 0),
                    'url': f"https://www.npmjs.com/package/{package_name}"
                }
        except Exception as e:
            pass
        return None

class PyPIChecker(RegistryChecker):
    """PyPI registry checker."""
    
    def check_package(self, package_name: str) -> Optional[Dict]:
        try:
            response = requests.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                info = data.get('info', {})
                
                return {
                    'registry': 'PyPI',
                    'package': package_name,
                    'version': info.get('version', 'unknown'),
                    'author': info.get('author', 'unknown'),
                    'published': 'unknown',  # PyPI API doesn't expose easily
                    'has_install_scripts': True,  # setup.py can execute code
                    'downloads': 0,  # Not in basic API
                    'url': f"https://pypi.org/project/{package_name}/"
                }
        except Exception as e:
            pass
        return None

class RubyGemsChecker(RegistryChecker):
    """RubyGems registry checker."""
    
    def check_package(self, package_name: str) -> Optional[Dict]:
        try:
            response = requests.get(
                f"https://rubygems.org/api/v1/gems/{package_name}.json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'registry': 'RubyGems',
                    'package': package_name,
                    'version': data.get('version', 'unknown'),
                    'author': data.get('authors', 'unknown'),
                    'published': data.get('version_created_at', 'unknown'),
                    'has_install_scripts': False,  # Less common in gems
                    'downloads': data.get('downloads', 0),
                    'url': f"https://rubygems.org/gems/{package_name}"
                }
        except Exception as e:
            pass
        return None

class MavenChecker(RegistryChecker):
    """Maven Central registry checker."""
    
    def check_package(self, package_name: str) -> Optional[Dict]:
        # Maven uses groupId:artifactId format, simplified check
        try:
            # Search Maven Central
            response = requests.get(
                f"https://search.maven.org/solrsearch/select",
                params={'q': f'a:{package_name}', 'rows': 1},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                docs = data.get('response', {}).get('docs', [])
                if docs:
                    doc = docs[0]
                    return {
                        'registry': 'Maven Central',
                        'package': f"{doc.get('g')}:{doc.get('a')}",
                        'version': doc.get('latestVersion', 'unknown'),
                        'author': doc.get('g', 'unknown'),
                        'published': 'unknown',
                        'has_install_scripts': False,
                        'downloads': 0,
                        'url': f"https://search.maven.org/artifact/{doc.get('g')}/{doc.get('a')}"
                    }
        except Exception as e:
            pass
        return None

def load_internal_packages(filepath: str) -> List[str]:
    """Load list of internal package names."""
    try:
        with open(filepath, 'r') as f:
            packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return packages
    except FileNotFoundError:
        print(f"{RED}Error: Package list file not found: {filepath}{RESET}", file=sys.stderr)
        sys.exit(1)

def check_collisions(packages: List[str], registries: List[str]) -> List[Dict]:
    """Check for package name collisions across registries."""
    checkers = {
        'npm': NPMChecker(),
        'pypi': PyPIChecker(),
        'rubygems': RubyGemsChecker(),
        'maven': MavenChecker()
    }
    
    collisions = []
    
    for package in packages:
        for registry in registries:
            if registry not in checkers:
                continue
            
            print(f"Checking {registry} for {package}...", end=' ')
            result = checkers[registry].check_package(package)
            
            if result:
                print(f"{RED}COLLISION DETECTED{RESET}")
                collisions.append(result)
            else:
                print(f"{GREEN}OK{RESET}")
            
            # Rate limiting
            time.sleep(0.5)
    
    return collisions

def generate_report(collisions: List[Dict], output_format: str = 'text'):
    """Generate report of detected collisions."""
    if not collisions:
        print(f"\n{GREEN}✓ No collisions detected{RESET}")
        return
    
    print(f"\n{RED}🚨 DEPENDENCY CONFUSION RISKS DETECTED{RESET}\n")
    print(f"Found {len(collisions)} package collision(s):\n")
    
    for i, collision in enumerate(collisions, 1):
        print(f"{i}. {YELLOW}{collision['package']}{RESET}")
        print(f"   Registry:       {collision['registry']}")
        print(f"   Version:        {collision['version']}")
        print(f"   Author:         {collision['author']}")
        print(f"   Published:      {collision['published']}")
        print(f"   Install Scripts: {'⚠️  YES' if collision['has_install_scripts'] else 'No'}")
        print(f"   URL:            {collision['url']}")
        print()
    
    if output_format == 'json':
        report_file = f"collision_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(collisions, f, indent=2)
        print(f"JSON report saved to: {report_file}")

def send_alert(collisions: List[Dict], webhook_url: Optional[str]):
    """Send alert to webhook (Slack, Teams, etc.)."""
    if not webhook_url or not collisions:
        return
    
    message = {
        "text": f"🚨 Dependency Confusion Alert: {len(collisions)} collision(s) detected",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {"title": "Package", "value": c['package'], "short": True},
                    {"title": "Registry", "value": c['registry'], "short": True}
                ]
            }
            for c in collisions[:10]  # Limit to first 10
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=message, timeout=10)
        if response.status_code == 200:
            print(f"{GREEN}Alert sent successfully{RESET}")
        else:
            print(f"{RED}Failed to send alert: {response.status_code}{RESET}", file=sys.stderr)
    except Exception as e:
        print(f"{RED}Error sending alert: {e}{RESET}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description='Detect dependency confusion attacks by monitoring public registries'
    )
    parser.add_argument('--packages', '-p', required=True,
                       help='File containing internal package names (one per line)')
    parser.add_argument('--registries', '-r', default='npm,pypi',
                       help='Comma-separated list of registries to check (npm,pypi,rubygems,maven)')
    parser.add_argument('--output', '-o', choices=['text', 'json'], default='text',
                       help='Output format')
    parser.add_argument('--webhook', '-w',
                       help='Webhook URL for alerts (Slack, Teams, etc.)')
    parser.add_argument('--continuous', '-c', action='store_true',
                       help='Run continuously at specified interval')
    parser.add_argument('--interval', '-i', type=int, default=86400,
                       help='Interval in seconds for continuous mode (default: 86400 = 24 hours)')
    
    args = parser.parse_args()
    
    registries = [r.strip() for r in args.registries.split(',')]
    
    print(f"Dependency Confusion Detection")
    print(f"{'=' * 50}")
    print(f"Package list: {args.packages}")
    print(f"Registries:   {', '.join(registries)}")
    print(f"Mode:         {'Continuous' if args.continuous else 'One-time'}")
    print(f"{'=' * 50}\n")
    
    try:
        while True:
            packages = load_internal_packages(args.packages)
            print(f"Loaded {len(packages)} internal package(s)\n")
            
            collisions = check_collisions(packages, registries)
            generate_report(collisions, args.output)
            
            if collisions:
                send_alert(collisions, args.webhook)
                sys.exit(1)  # Exit with error if collisions found
            
            if not args.continuous:
                break
            
            print(f"\nNext check in {args.interval} seconds...")
            time.sleep(args.interval)
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Monitoring stopped by user{RESET}")
        sys.exit(0)

if __name__ == '__main__':
    main()
