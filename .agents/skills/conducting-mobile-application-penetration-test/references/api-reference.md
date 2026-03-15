# Mobile Application Penetration Test — API Reference

## Libraries & Tools

| Tool | Install | Purpose |
|------|---------|---------|
| apktool | `apt install apktool` | Android APK decompilation and recompilation |
| objection | `pip install objection` | Runtime mobile exploration via Frida |
| frida-tools | `pip install frida-tools` | Dynamic instrumentation framework |
| jadx | Binary download | Java decompiler for APK source code |
| MobSF | `docker pull opensecurity/mobile-security-framework-mobsf` | Automated mobile security scanner |

## Key objection Commands

| Command | Description |
|---------|-------------|
| `objection -g <pkg> explore` | Attach to running app |
| `android sslpinning disable` | Bypass SSL certificate pinning |
| `android root disable` | Bypass root detection |
| `android hooking list activities` | List app activities |
| `android keystore list` | Dump Android Keystore entries |
| `android clipboard monitor` | Monitor clipboard content |

## Frida Script Patterns

| Pattern | Purpose |
|---------|---------|
| `Java.use("class").method.implementation` | Hook Java method |
| `Interceptor.attach(addr, {onEnter, onLeave})` | Hook native function |
| `Java.choose("class", {onMatch, onComplete})` | Find live instances |

## OWASP Mobile Top 10 Checks

| ID | Vulnerability |
|----|--------------|
| M1 | Improper Platform Usage |
| M2 | Insecure Data Storage |
| M3 | Insecure Communication |
| M4 | Insecure Authentication |
| M5 | Insufficient Cryptography |

## External References

- [OWASP Mobile Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Frida Documentation](https://frida.re/docs/home/)
- [objection Wiki](https://github.com/sensepost/objection/wiki)
- [apktool Documentation](https://apktool.org/docs/install)
