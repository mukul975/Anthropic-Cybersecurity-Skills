#!/usr/bin/env python3
"""
Install Script Analyzer for npm/PyPI packages

Downloads and analyzes install scripts for malicious patterns including:
- Network calls (curl, wget, http.request)
- Environment variable access (process.env, os.environ)
- Shell execution (child_process, subprocess, eval)
- Obfuscated code (base64, fromCharCode)
- Filesystem access outside package directory

Usage:
  python analyze_install_scripts.py npm suspicious-package
  python analyze_install_scripts.py pypi malicious-package --version 1.2.3
"""

import argparse
import json
import subprocess
import sys
import os
import re
import base64
import tempfile
import shutil
from pathlib import Path

# Suspicious patterns to detect
PATTERNS = {
    'network': {
        'regex': r'(curl|wget|http\.request|https\.request|fetch\(|XMLHttpRequest|axios)',
        'severity': 'HIGH',
        'description': 'Network call detected (potential exfiltration)'
    },
    'env_access': {
        'regex': r'(process\.env|os\.environ|getenv\(|ENV\[)',
        'severity': 'MEDIUM',
        'description': 'Environment variable access (potential secret theft)'
    },
    'shell_exec': {
        'regex': r'(child_process|subprocess\.call|subprocess\.run|os\.system|eval\(|exec\()',
        'severity': 'HIGH',
        'description': 'Shell command execution'
    },
    'obfuscation': {
        'regex': r'(Buffer\.from.*base64|atob\(|fromCharCode|String\.fromCharCode)',
        'severity': 'HIGH',
        'description': 'Code obfuscation detected'
    },
    'file_write': {
        'regex': r'(fs\.writeFile|fs\.appendFile|open\(.*[\'"]w|file\.write)',
        'severity': 'MEDIUM',
        'description': 'File write operation'
    },
    'crypto_mining': {
        'regex': r'(stratum\+tcp|xmrig|cryptonight|monero)',
        'severity': 'CRITICAL',
        'description': 'Cryptocurrency mining indicators'
    },
    'persistence': {
        'regex': r'(crontab|\.bashrc|\.bash_profile|rc\.local|systemd)',
        'severity': 'HIGH',
        'description': 'Persistence mechanism'
    }
}

def download_npm_package(package_name, version=None):
    """Download npm package tarball."""
    tmpdir = tempfile.mkdtemp()
    
    try:
        pkg_spec = f"{package_name}@{version}" if version else package_name
        result = subprocess.run(
            ['npm', 'pack', pkg_spec],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"Error downloading {pkg_spec}: {result.stderr}", file=sys.stderr)
            return None
        
        tarball = Path(tmpdir) / result.stdout.strip()
        
        # Extract tarball
        subprocess.run(
            ['tar', '-xzf', tarball],
            cwd=tmpdir,
            check=True
        )
        
        return Path(tmpdir) / 'package'
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None

def download_pypi_package(package_name, version=None):
    """Download PyPI package."""
    tmpdir = tempfile.mkdtemp()
    
    try:
        pkg_spec = f"{package_name}=={version}" if version else package_name
        result = subprocess.run(
            ['pip', 'download', '--no-deps', pkg_spec, '-d', tmpdir],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"Error downloading {pkg_spec}: {result.stderr}", file=sys.stderr)
            return None
        
        # Extract package (could be .tar.gz or .whl)
        for file in Path(tmpdir).glob('*'):
            if file.suffix == '.gz':
                subprocess.run(['tar', '-xzf', file], cwd=tmpdir, check=True)
            elif file.suffix == '.whl':
                subprocess.run(['unzip', '-q', file], cwd=tmpdir, check=True)
        
        # Find extracted directory
        extracted_dirs = [d for d in Path(tmpdir).iterdir() if d.is_dir()]
        if extracted_dirs:
            return extracted_dirs[0]
        
        return Path(tmpdir)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None

def analyze_npm_scripts(package_dir):
    """Analyze npm package.json scripts."""
    package_json = package_dir / 'package.json'
    
    if not package_json.exists():
        return None
    
    with open(package_json) as f:
        data = json.load(f)
    
    scripts = data.get('scripts', {})
    dangerous_hooks = ['preinstall', 'install', 'postinstall', 'preuninstall', 'uninstall', 'postuninstall']
    
    findings = []
    for hook in dangerous_hooks:
        if hook in scripts:
            findings.append({
                'hook': hook,
                'command': scripts[hook],
                'file': 'package.json'
            })
    
    return findings

def analyze_pypi_setup(package_dir):
    """Analyze PyPI setup.py."""
    setup_py = package_dir / 'setup.py'
    
    if not setup_py.exists():
        return None
    
    with open(setup_py) as f:
        content = f.read()
    
    # PyPI setup.py executes arbitrary code
    return [{
        'hook': 'setup.py',
        'command': content,
        'file': 'setup.py'
    }]

def scan_for_patterns(code):
    """Scan code for suspicious patterns."""
    matches = {}
    
    for pattern_name, pattern_info in PATTERNS.items():
        regex = pattern_info['regex']
        found = re.findall(regex, code, re.IGNORECASE | re.MULTILINE)
        
        if found:
            matches[pattern_name] = {
                'severity': pattern_info['severity'],
                'description': pattern_info['description'],
                'matches': found[:5]  # Limit to first 5 matches
            }
    
    return matches

def deobfuscate_base64(code):
    """Attempt to deobfuscate base64 encoded strings."""
    # Pattern: Buffer.from('...', 'base64')
    pattern = r'Buffer\.from\([\'"]([A-Za-z0-9+/=]{20,})[\'"]\s*,\s*[\'"]base64[\'"]\)'
    matches = re.findall(pattern, code)
    
    decoded = []
    for match in matches:
        try:
            decoded_bytes = base64.b64decode(match)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str.isprintable():
                decoded.append(decoded_str)
        except:
            pass
    
    # Pattern: atob('...')
    atob_pattern = r'atob\([\'"]([A-Za-z0-9+/=]{20,})[\'"]\)'
    atob_matches = re.findall(atob_pattern, code)
    
    for match in atob_matches:
        try:
            decoded_bytes = base64.b64decode(match)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str.isprintable():
                decoded.append(decoded_str)
        except:
            pass
    
    return decoded

def calculate_risk_score(findings):
    """Calculate overall risk score."""
    severity_scores = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 1
    }
    
    total_score = 0
    for finding in findings:
        for pattern_matches in finding.get('patterns', {}).values():
            total_score += severity_scores.get(pattern_matches['severity'], 0)
    
    return min(total_score, 100)  # Cap at 100

def generate_report(package_name, registry, findings):
    """Generate analysis report."""
    print("\n" + "=" * 70)
    print(f"INSTALL SCRIPT ANALYSIS REPORT")
    print("=" * 70)
    print(f"Package:   {package_name}")
    print(f"Registry:  {registry}")
    print(f"Timestamp: {subprocess.run(['date'], capture_output=True, text=True).stdout.strip()}")
    print("=" * 70)
    
    if not findings:
        print("\n✅ No install scripts found")
        return 0
    
    risk_score = calculate_risk_score(findings)
    risk_level = 'CRITICAL' if risk_score >= 20 else 'HIGH' if risk_score >= 10 else 'MEDIUM' if risk_score >= 5 else 'LOW'
    
    print(f"\nRisk Score: {risk_score}/100 ({risk_level})")
    print(f"Install Scripts Found: {len(findings)}")
    
    for i, finding in enumerate(findings, 1):
        print(f"\n{'─' * 70}")
        print(f"Script {i}: {finding['hook']}")
        print(f"File: {finding['file']}")
        print(f"{'─' * 70}")
        
        # Show first 200 chars of command
        command = finding['command']
        if len(command) > 200:
            print(f"Command: {command[:200]}...")
        else:
            print(f"Command: {command}")
        
        # Show suspicious patterns
        if finding.get('patterns'):
            print(f"\n⚠️  SUSPICIOUS PATTERNS DETECTED:")
            for pattern_name, pattern_data in finding['patterns'].items():
                severity = pattern_data['severity']
                desc = pattern_data['description']
                matches = pattern_data['matches']
                
                severity_icon = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'
                print(f"  {severity_icon} [{severity}] {desc}")
                print(f"     Matches: {', '.join(matches[:3])}")
        
        # Show deobfuscated content
        if finding.get('deobfuscated'):
            print(f"\n🔓 DEOBFUSCATED CONTENT:")
            for dec in finding['deobfuscated'][:3]:
                print(f"   {dec}")
    
    print("\n" + "=" * 70)
    print("RECOMMENDATION:")
    if risk_score >= 20:
        print("🔴 CRITICAL: DO NOT INSTALL - High confidence malicious package")
    elif risk_score >= 10:
        print("🟠 HIGH RISK: Review carefully before installing")
    elif risk_score >= 5:
        print("🟡 MEDIUM RISK: Install scripts present, verify legitimacy")
    else:
        print("🟢 LOW RISK: Standard install scripts detected")
    print("=" * 70)
    
    return 1 if risk_score >= 10 else 0

def main():
    parser = argparse.ArgumentParser(
        description='Analyze install scripts from npm/PyPI packages for malicious patterns'
    )
    parser.add_argument('registry', choices=['npm', 'pypi'],
                       help='Package registry')
    parser.add_argument('package', help='Package name')
    parser.add_argument('--version', '-v', help='Specific version to analyze')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output as JSON')
    
    args = parser.parse_args()
    
    print(f"Analyzing {args.registry} package: {args.package}")
    if args.version:
        print(f"Version: {args.version}")
    print()
    
    # Download package
    if args.registry == 'npm':
        package_dir = download_npm_package(args.package, args.version)
        if not package_dir:
            sys.exit(1)
        script_findings = analyze_npm_scripts(package_dir)
    else:
        package_dir = download_pypi_package(args.package, args.version)
        if not package_dir:
            sys.exit(1)
        script_findings = analyze_pypi_setup(package_dir)
    
    if not script_findings:
        print("✅ No install scripts found")
        shutil.rmtree(package_dir.parent, ignore_errors=True)
        sys.exit(0)
    
    # Analyze each script
    analyzed_findings = []
    for finding in script_findings:
        code = finding['command']
        
        # Scan for patterns
        patterns = scan_for_patterns(code)
        
        # Attempt deobfuscation
        deobfuscated = deobfuscate_base64(code)
        
        analyzed_findings.append({
            'hook': finding['hook'],
            'file': finding['file'],
            'command': code,
            'patterns': patterns,
            'deobfuscated': deobfuscated
        })
    
    # Generate report
    exit_code = generate_report(args.package, args.registry, analyzed_findings)
    
    # Cleanup
    shutil.rmtree(package_dir.parent, ignore_errors=True)
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
