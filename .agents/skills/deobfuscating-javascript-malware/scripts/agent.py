#!/usr/bin/env python3
"""JavaScript malware deobfuscation agent using jsbeautifier and pattern matching."""

import re
import sys
import json
import base64
import urllib.parse
from pathlib import Path

try:
    import jsbeautifier
except ImportError:
    jsbeautifier = None


def beautify_js(code):
    """Beautify JavaScript code using jsbeautifier."""
    if jsbeautifier is None:
        return code
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.wrap_line_length = 120
    return jsbeautifier.beautify(code, opts)


def decode_hex_strings(code):
    """Replace \\xNN hex escape sequences with ASCII characters."""
    def hex_replace(match):
        hex_str = match.group(0)
        try:
            return bytes.fromhex(hex_str.replace("\\x", "")).decode("ascii", errors="replace")
        except Exception:
            return hex_str
    return re.sub(r'(?:\\x[0-9a-fA-F]{2})+', hex_replace, code)


def decode_unicode_escapes(code):
    """Replace \\uNNNN sequences with actual characters."""
    def unicode_replace(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)
    return re.sub(r'\\u([0-9a-fA-F]{4})', unicode_replace, code)


def decode_charcode_calls(code):
    """Resolve String.fromCharCode() calls with static arguments."""
    def charcode_replace(match):
        try:
            codes = [int(c.strip()) for c in match.group(1).split(",") if c.strip()]
            return '"' + "".join(chr(c) for c in codes) + '"'
        except Exception:
            return match.group(0)
    return re.sub(r'String\.fromCharCode\(([0-9,\s]+)\)', charcode_replace, code)


def decode_atob_calls(code):
    """Resolve atob() calls containing static base64 strings."""
    def atob_replace(match):
        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
            return json.dumps(decoded)
        except Exception:
            return match.group(0)
    return re.sub(r'atob\(["\']([A-Za-z0-9+/=]+)["\']\)', atob_replace, code)


def decode_unescape_calls(code):
    """Resolve unescape() calls with percent-encoded strings."""
    def unescape_replace(match):
        try:
            decoded = urllib.parse.unquote(match.group(1))
            return json.dumps(decoded)
        except Exception:
            return match.group(0)
    return re.sub(r'unescape\(["\']([^"\']+)["\']\)', unescape_replace, code)


def detect_obfuscation_techniques(code):
    """Identify obfuscation techniques used in the script."""
    techniques = []
    if re.search(r'\\x[0-9a-fA-F]{2}', code):
        techniques.append("hex_encoding")
    if re.search(r'\\u[0-9a-fA-F]{4}', code):
        techniques.append("unicode_escapes")
    if "String.fromCharCode" in code:
        techniques.append("fromCharCode")
    if "atob(" in code:
        techniques.append("base64_atob")
    if re.search(r'eval\s*\(', code):
        techniques.append("eval_chain")
    if "new Function(" in code or "new Function (" in code:
        techniques.append("function_constructor")
    if re.search(r'document\.write\s*\(', code):
        techniques.append("document_write")
    if re.search(r'setTimeout\s*\(', code):
        techniques.append("setTimeout_exec")
    if re.search(r'setInterval\s*\(\s*function\s*\(\)\s*\{\s*debugger', code):
        techniques.append("anti_debugging_debugger")
    if re.search(r'window\.outerWidth\s*-\s*window\.innerWidth', code):
        techniques.append("anti_debugging_devtools")
    if re.search(r'performance\.now\s*\(\)', code):
        techniques.append("anti_debugging_timing")
    if re.search(r'_0x[0-9a-fA-F]+', code):
        techniques.append("variable_mangling")
    if re.search(r'var\s+_0x[0-9a-fA-F]+\s*=\s*\[', code):
        techniques.append("string_array")
    if "unescape(" in code:
        techniques.append("unescape_encoding")
    return techniques


def extract_iocs(code):
    """Extract potential IOCs from deobfuscated JavaScript."""
    iocs = {"urls": [], "domains": [], "ips": [], "emails": []}
    url_pattern = re.compile(r'https?://[^\s"\'<>\)]+', re.IGNORECASE)
    domain_pattern = re.compile(r'(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|top|info|cc|ru|cn|tk)\b')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    iocs["urls"] = list(set(url_pattern.findall(code)))
    iocs["domains"] = list(set(domain_pattern.findall(code)))
    iocs["ips"] = list(set(ip_pattern.findall(code)))
    iocs["emails"] = list(set(email_pattern.findall(code)))
    return iocs


def remove_anti_debug(code):
    """Remove common anti-debugging traps from JavaScript."""
    code = re.sub(
        r'setInterval\s*\(\s*function\s*\(\)\s*\{\s*debugger\s*;?\s*\}\s*,\s*\d+\s*\)',
        '/* anti-debug removed */',
        code
    )
    code = re.sub(
        r'if\s*\(\s*window\.outerWidth\s*-\s*window\.innerWidth\s*>\s*\d+\s*\)[^}]*\}',
        '/* devtools detection removed */',
        code
    )
    return code


def deobfuscate(code, remove_debug=True):
    """Apply all deobfuscation passes to JavaScript code."""
    if remove_debug:
        code = remove_anti_debug(code)
    code = decode_hex_strings(code)
    code = decode_unicode_escapes(code)
    code = decode_charcode_calls(code)
    code = decode_atob_calls(code)
    code = decode_unescape_calls(code)
    code = beautify_js(code)
    return code


def extract_scripts_from_html(html_content):
    """Extract inline JavaScript from HTML file."""
    pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
    scripts = pattern.findall(html_content)
    return [s.strip() for s in scripts if s.strip()]


def analyze_file(file_path):
    """Full analysis pipeline for a JavaScript or HTML file."""
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    content = path.read_text(encoding="utf-8", errors="replace")

    if path.suffix.lower() in (".html", ".htm"):
        scripts = extract_scripts_from_html(content)
    else:
        scripts = [content]

    results = []
    for i, script in enumerate(scripts):
        techniques = detect_obfuscation_techniques(script)
        deobfuscated = deobfuscate(script)
        iocs = extract_iocs(deobfuscated)
        results.append({
            "script_index": i,
            "original_size": len(script),
            "deobfuscated_size": len(deobfuscated),
            "obfuscation_techniques": techniques,
            "iocs": iocs,
            "deobfuscated_preview": deobfuscated[:2000],
        })

    return {
        "file": file_path,
        "script_count": len(scripts),
        "analyses": results,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: agent.py <file.js|file.html> [--full]")
        sys.exit(1)

    result = analyze_file(sys.argv[1])
    if "--full" in sys.argv:
        print(json.dumps(result, indent=2, default=str))
    else:
        for analysis in result.get("analyses", []):
            analysis.pop("deobfuscated_preview", None)
        print(json.dumps(result, indent=2, default=str))
