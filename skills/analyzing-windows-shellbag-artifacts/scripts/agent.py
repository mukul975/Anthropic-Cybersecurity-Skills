#!/usr/bin/env python3
"""Windows ShellBag artifact analysis agent.

Parses ShellBag registry artifacts to reconstruct folder access history,
directory browsing patterns, and evidence of accessed network shares.
"""

import os
import sys
import struct
import datetime

try:
    import Registry
    HAS_REGISTRY = True
except ImportError:
    try:
        from regipy.registry import RegistryHive
        HAS_REGIPY = True
        HAS_REGISTRY = False
    except ImportError:
        HAS_REGISTRY = False
        HAS_REGIPY = False


SHELLBAG_PATHS = {
    'ntuser': [
        r'Software\Microsoft\Windows\Shell\BagMRU',
        r'Software\Microsoft\Windows\Shell\Bags',
        r'Software\Microsoft\Windows\ShellNoRoam\BagMRU',
        r'Software\Microsoft\Windows\ShellNoRoam\Bags',
    ],
    'usrclass': [
        r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
        r'Local Settings\Software\Microsoft\Windows\Shell\Bags',
    ],
}


def filetime_to_datetime(filetime):
    if not filetime or filetime == 0:
        return None
    try:
        epoch = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=filetime // 10)
        return (epoch + delta).isoformat() + 'Z'
    except (OverflowError, OSError):
        return None


def parse_shell_item(data):
    if len(data) < 2:
        return None
    item_size = struct.unpack_from('<H', data, 0)[0]
    if item_size < 2 or item_size > len(data):
        return None
    item_type = data[2] if len(data) > 2 else 0
    result = {'size': item_size, 'type': hex(item_type)}

    if item_type == 0x1F:
        result['class'] = 'Root Folder (GUID)'
        if len(data) >= 18:
            guid = data[4:20].hex()
            result['guid'] = guid
    elif item_type in (0x31, 0x32, 0x35):
        result['class'] = 'File Entry'
        if len(data) > 14:
            file_size = struct.unpack_from('<I', data, 4)[0]
            result['file_size'] = file_size
            name_offset = 14
            if name_offset < len(data):
                name_end = data.find(b'\x00', name_offset)
                if name_end > name_offset:
                    result['short_name'] = data[name_offset:name_end].decode('ascii', errors='replace')
    elif item_type in (0x41, 0x42, 0x46, 0x47):
        result['class'] = 'Network Location'
        if len(data) > 5:
            name_start = 5
            name_end = data.find(b'\x00', name_start)
            if name_end > name_start:
                result['network_path'] = data[name_start:name_end].decode('ascii', errors='replace')
    elif item_type == 0x71:
        result['class'] = 'Control Panel'
    else:
        result['class'] = 'Unknown'

    return result


def parse_bagmru_value(data):
    items = []
    offset = 0
    while offset < len(data) - 2:
        item_size = struct.unpack_from('<H', data, offset)[0]
        if item_size == 0:
            break
        item_data = data[offset:offset + item_size]
        parsed = parse_shell_item(item_data)
        if parsed:
            items.append(parsed)
        offset += item_size
    return items


def analyze_shellbags_regipy(hive_path):
    if not HAS_REGIPY:
        return []
    hive = RegistryHive(hive_path)
    results = []
    for path_group in SHELLBAG_PATHS.values():
        for reg_path in path_group:
            try:
                key = hive.get_key(reg_path)
                if key:
                    for value in key.iter_values():
                        if isinstance(value.value, bytes):
                            items = parse_bagmru_value(value.value)
                            for item in items:
                                item['registry_path'] = reg_path
                                item['value_name'] = value.name
                                results.append(item)
            except Exception:
                continue
    return results


def detect_suspicious_paths(shellbag_entries):
    findings = []
    suspicious_indicators = [
        ('\\', 'UNC path access (network share)'),
        ('temp', 'Temp directory access'),
        ('appdata', 'AppData directory (persistence location)'),
        ('recycle', 'Recycle Bin access'),
        ('usb', 'USB device path'),
        ('removable', 'Removable media'),
        ('.tor', 'Tor browser directory'),
        ('sysinternals', 'Sysinternals tools directory'),
        ('mimikatz', 'Mimikatz tool directory'),
        ('powershell', 'PowerShell directory'),
    ]
    for entry in shellbag_entries:
        path = (entry.get('short_name', '') + ' ' + entry.get('network_path', '')).lower()
        for pattern, description in suspicious_indicators:
            if pattern in path:
                findings.append({
                    'type': 'suspicious_path',
                    'path': entry.get('short_name', entry.get('network_path', '')),
                    'indicator': description,
                    'severity': 'HIGH' if 'mimikatz' in pattern else 'MEDIUM',
                })
                break
    return findings


if __name__ == '__main__':
    print('=' * 60)
    print('Windows ShellBag Artifact Analysis Agent')
    print('Registry parsing, folder history, network share detection')
    print('=' * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target or not os.path.exists(target):
        print('\n[DEMO] Usage: python agent.py <NTUSER.DAT|UsrClass.dat>')
        print(f'  regipy available: {HAS_REGIPY if not HAS_REGISTRY else False}')
        print(f'  python-registry available: {HAS_REGISTRY}')
        sys.exit(0)

    print(f'\n[*] Analyzing: {target}')
    entries = analyze_shellbags_regipy(target)
    print(f'[*] ShellBag entries: {len(entries)}')

    print('\n--- Folder Access History ---')
    for e in entries[:20]:
        name = e.get('short_name', e.get('network_path', e.get('guid', '?')))
        print(f'  [{e["class"]:20s}] {name}')

    findings = detect_suspicious_paths(entries)
    print(f'\n--- Suspicious Paths ({len(findings)}) ---')
    for f in findings[:10]:
        print(f'  [{f["severity"]}] {f["indicator"]}: {f["path"]}')
