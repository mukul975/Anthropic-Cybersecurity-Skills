#!/usr/bin/env python3
"""Typosquatting domain detection agent using dnstwist concepts."""

import os, sys, json, socket
from datetime import datetime

try:
    import dnstwist as dnstwist_lib
    HAS_DNSTWIST = True
except ImportError:
    HAS_DNSTWIST = False

KEYBOARD_NEIGHBORS = {
    'q': 'wa', 'w': 'qeas', 'e': 'wrds', 'r': 'etfd', 't': 'rygf',
    'y': 'tuhg', 'u': 'yijh', 'i': 'uokj', 'o': 'iplk', 'p': 'ol',
    'a': 'qwsz', 's': 'wedxza', 'd': 'erfcxs', 'f': 'rtgvcd',
    'g': 'tyhbvf', 'h': 'yujnbg', 'j': 'uikmnh', 'k': 'iolmj',
    'l': 'opk', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
    'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
}

def generate_permutations(domain):
    name = domain.split('.')[0]
    tld = '.'.join(domain.split('.')[1:]) or 'com'
    results = set()
    for i in range(len(name)):
        results.add(name[:i] + name[i+1:] + '.' + tld)
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i+1] = s[i+1], s[i]
        results.add(''.join(s) + '.' + tld)
    for i in range(len(name)):
        if name[i] in KEYBOARD_NEIGHBORS:
            for c in KEYBOARD_NEIGHBORS[name[i]]:
                results.add(name[:i] + c + name[i+1:] + '.' + tld)
    homoglyphs = {'o': '0', 'l': '1', 'i': '1', 's': '5', 'a': '4', 'e': '3'}
    for i in range(len(name)):
        if name[i] in homoglyphs:
            results.add(name[:i] + homoglyphs[name[i]] + name[i+1:] + '.' + tld)
    for i in range(1, len(name)):
        results.add(name[:i] + '-' + name[i:] + '.' + tld)
    results.discard(domain)
    return sorted(results)

def resolve_domain(domain):
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list(set(ip[4][0] for ip in ips))
    except socket.gaierror:
        return []

def check_domains(permutations, max_check=200):
    results = []
    for domain in permutations[:max_check]:
        ips = resolve_domain(domain)
        if ips:
            results.append({'domain': domain, 'ips': ips, 'registered': True})
    return results

def run_dnstwist_cli(domain):
    import subprocess
    try:
        result = subprocess.run(['dnstwist', '-r', '-f', 'json', domain],
                                capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None

if __name__ == '__main__':
    print('=' * 60)
    print('Typosquatting Domain Detection Agent (dnstwist)')
    print('Permutation generation, DNS resolution, risk scoring')
    print('=' * 60)
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    if not domain:
        print('
[DEMO] Usage: python agent.py <domain.com>')
        sys.exit(0)
    print(f'
[*] Target: {domain}')
    dnstwist_results = run_dnstwist_cli(domain)
    if dnstwist_results:
        print(f'[*] dnstwist found {len(dnstwist_results)} permutations')
        for r in dnstwist_results[:10]:
            a = r.get('dns_a', [''])[0] if r.get('dns_a') else ''
            print(f'  {r.get("domain", "?"):40s} {a}')
    else:
        perms = generate_permutations(domain)
        print(f'[*] Generated {len(perms)} permutations')
        print('[*] Resolving domains...')
        resolved = check_domains(perms)
        print(f'[*] Active typosquats: {len(resolved)}')
        for r in resolved[:15]:
            print(f'  {r["domain"]:40s} {", ".join(r["ips"])}')
        risk = 'HIGH' if len(resolved) > 20 else 'MEDIUM' if len(resolved) > 5 else 'LOW'
        print(f'
[*] Risk: {risk}')
