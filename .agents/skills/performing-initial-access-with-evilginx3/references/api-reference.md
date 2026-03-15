# API Reference — Performing Initial Access with Evilginx3

## Libraries Used
- **pyyaml**: Parse Evilginx3 phishlet YAML configuration files
- **subprocess**: Check Evilginx installation and version
- **pathlib**: Directory listing and file reading
- **re**: IP address extraction from session logs

## CLI Interface
```
python agent.py parse --phishlet office365.yaml
python agent.py logs --file sessions.log
python agent.py check
python agent.py list --dir /path/to/phishlets/
python agent.py detect --phishlet office365.yaml
```

## Core Functions

### `parse_phishlet(phishlet_path)` — Analyze phishlet configuration
Extracts proxy hosts, auth tokens, credential fields. Determines MFA bypass capability.

### `analyze_session_log(log_file)` — Parse Evilginx session captures
Identifies sessions with captured tokens and credentials. Extracts source IPs.

### `check_evilginx_installation()` — Verify Evilginx3 binary
Returns installed status and version string.

### `list_phishlets(phishlet_dir)` — Enumerate available phishlets
Lists .yaml/.yml files in phishlet directory with sizes.

### `generate_detection_rules(phishlet_path)` — Create defensive signatures
Generates DNS monitoring, cookie relay detection, and network anomaly rules.
Includes FIDO2/WebAuthn MFA recommendations.

## Phishlet Structure
- `proxy_hosts`: Domain-to-phishing-subdomain mappings
- `auth_tokens`: Session cookies to intercept (enables MFA bypass)
- `credentials`: Form fields to capture (username/password)
- `sub_filters`: Content replacement rules for convincing proxied pages

## Dependencies
```
pip install pyyaml
```
System: evilginx (optional, for live testing)
