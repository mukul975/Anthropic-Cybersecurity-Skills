# JavaScript Malware Deobfuscation API Reference

## jsbeautifier (Python)

```python
import jsbeautifier

opts = jsbeautifier.default_options()
opts.indent_size = 2
opts.wrap_line_length = 120

result = jsbeautifier.beautify(obfuscated_code, opts)
```

## jsbeautifier CLI

```bash
# Beautify a file
js-beautify malicious.js -o output.js

# npx alternative
npx js-beautify script.js -o script_pretty.js
```

## Common Decoding Patterns (Python)

```python
import re, base64, urllib.parse

# Hex strings: \x68\x65\x6c\x6c\x6f -> hello
decoded = bytes.fromhex("68656c6c6f").decode("ascii")

# Unicode escapes: \u0068\u0065 -> he
decoded = chr(0x0068) + chr(0x0065)

# Base64 (atob equivalent)
decoded = base64.b64decode("aGVsbG8=").decode("utf-8")

# URL encoding (unescape equivalent)
decoded = urllib.parse.unquote("%68%65%6c%6c%6f")

# String.fromCharCode
decoded = "".join(chr(c) for c in [104, 101, 108, 108, 111])
```

## Node.js VM Sandbox

```javascript
const vm = require('vm');
const sandbox = {
    eval: function(code) {
        console.log("EVAL INTERCEPTED:", code.substring(0, 500));
        return code;
    },
    document: { write: function(h) { console.log("DOC.WRITE:", h); } },
    atob: function(s) { return Buffer.from(s, 'base64').toString(); },
    window: { location: { href: "" } },
};
const context = vm.createContext(sandbox);
vm.runInContext(code, context, { timeout: 5000 });
```

## CyberChef Operations

| Operation | Use Case |
|-----------|----------|
| From Hex | Decode `\xNN` sequences |
| From Base64 | Decode `atob()` payloads |
| URL Decode | Decode `unescape()` strings |
| JavaScript Beautify | Format minified code |
| From CharCode | Decode `fromCharCode` arrays |
| XOR | Decode XOR-encrypted strings |
| Generic Code Beautify | Format mixed content |

## IOC Extraction Regex

```python
# URLs
re.findall(r'https?://[^\s"\'<>)]+', code)

# IP addresses
re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', code)

# Domains
re.findall(r'(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz)\b', code)
```
