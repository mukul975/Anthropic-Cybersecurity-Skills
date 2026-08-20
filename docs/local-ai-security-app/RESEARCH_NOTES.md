# Research Notes

## Purpose

These notes capture the source-backed feasibility conclusions for building SentinelBlue as a Rust/Tauri local desktop app with llama.cpp and a local Gemma-class model, while also supporting continuous server deployment.

## Feasibility Summary

The product is feasible with a split runtime:

- Desktop mode: Tauri shell plus Rust backend, with `llama-server` bundled or installed as a sidecar.
- Server mode: same Rust backend compiled as a headless service, with `llama-server` managed as a process, system service, or container.
- Model mode: GGUF model downloaded at bootstrap or provided by the administrator; model weights should not be committed to git.
- Skills mode: this repository is parsed into a local skill index and retrieval layer.

The biggest implementation risks are packaging large model files, hardware fit for a 31B model, safe automation, cross-platform service installation, and model output reliability. These are manageable if deterministic detectors remain authoritative and the model is used for reasoning, summarization, planning, and analyst assistance.

## Key Sources And Implications

### Tauri Desktop Packaging

Tauri v2 supports bundling external binaries as sidecars through `bundle.externalBin`; each target architecture needs the correct target-triple suffixed binary name. This makes packaging `llama-server` beside the desktop app viable, but requires per-platform build artifacts and explicit shell permissions.

Source: [Tauri sidecar documentation](https://v2.tauri.app/develop/sidecar/)

Product implications:

- Package `llama-server` as a sidecar in desktop builds.
- Use target-specific binaries for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`, and Linux targets.
- Do not expose arbitrary sidecar arguments to frontend code.
- Launch sidecars from Rust, not directly from the webview.

### Tauri Security Model

Tauri permissions and capabilities are explicit privilege boundaries between frontend windows/webviews and backend commands. Capabilities can reduce frontend compromise impact, but they do not protect against insecure Rust code or overly broad command scopes.

Sources:

- [Tauri permissions](https://v2.tauri.app/security/permissions/)
- [Tauri capabilities](https://v2.tauri.app/security/capabilities/)

Product implications:

- Keep security-critical actions in Rust.
- Give the UI only narrow commands: list cases, request approval, read sanitized evidence, and run approved jobs.
- Separate capabilities for main analyst window, setup window, and admin/settings window.
- Treat the policy engine as mandatory backend enforcement, not a UI convention.

### Desktop Continuous Operation

Tauri supports autostart on desktop platforms and system tray integration. This supports a local app that keeps collectors and background workers running while minimized.

Sources:

- [Tauri autostart plugin](https://v2.tauri.app/plugin/autostart/)
- [Tauri system tray](https://v2.tauri.app/learn/system-tray/)

Product implications:

- Desktop mode should provide a tray status indicator: healthy, degraded, model loading, offline, action pending.
- Autostart must be opt-in and visible in settings.
- Background monitoring should run even when the main window is closed if the user enables monitoring mode.

### Updates And Distribution

Tauri's updater plugin creates update artifacts and expects signed update metadata. Production updater endpoints require TLS unless insecure transport is deliberately enabled.

Source: [Tauri updater documentation](https://v2.tauri.app/plugin/updater/)

Product implications:

- Sign desktop releases and update artifacts.
- Do not auto-update model weights with app updates.
- Support separate app update and model update channels.
- Enterprise/server deployments should support offline update bundles.

### llama.cpp Runtime

llama.cpp is designed for local and cloud inference across CPU and GPU backends, supports quantization, and can run an OpenAI-compatible API server via `llama-server`.

Sources:

- [llama.cpp README](https://github.com/ggml-org/llama.cpp)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)

Product implications:

- Use `llama-server` first, not direct FFI.
- Bind to `127.0.0.1` in desktop mode.
- Use API keys if server mode binds beyond localhost.
- Prefer OpenAI-compatible `/v1/chat/completions` for app integration.
- Use `/health`, slot monitoring, and metrics where enabled for runtime health.
- Use grammar/JSON schema constraints for structured model outputs when possible.

### Local Model: Gemma 4 31B

Google's Gemma 4 31B instruction-tuned model exists, is Apache-2.0 licensed on Hugging Face, and is described as a 30.7B dense model with long-context, reasoning, coding, and agentic capabilities. The Unsloth GGUF distribution provides llama.cpp usage examples with `llama-server -hf unsloth/gemma-4-31B-it-GGUF:UD-Q4_K_XL`.

Sources:

- [google/gemma-4-31B-it](https://huggingface.co/google/gemma-4-31B-it)
- [unsloth/gemma-4-31B-it-GGUF](https://huggingface.co/unsloth/gemma-4-31B-it-GGUF)

Product implications:

- Gemma 4 31B can be a high-quality local workstation target.
- The app should also ship fallback presets for smaller models because not every endpoint or server can run 31B comfortably.
- Model bootstrap must validate license, file integrity, disk space, and hardware fit.
- The app should benchmark prompt processing and token generation before enabling autonomous summaries.

### Wazuh As Initial SIEM/XDR Source

Wazuh provides XDR and SIEM capabilities for cloud, container, and server workloads. Its architecture includes agents, server, indexer, and dashboard. The Wazuh API is RESTful and authenticates by obtaining a JWT token from `/security/user/authenticate`.

Sources:

- [Wazuh components](https://documentation.wazuh.com/current/getting-started/components/index.html)
- [Wazuh architecture](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Wazuh API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)

Product implications:

- Make Wazuh the first supported external integration.
- Support read-only API access first: agents, alerts, vulnerability status, rules summary.
- Keep Wazuh active response actions behind explicit approval.
- Let users run without Wazuh by importing local JSON logs.

### Network Telemetry

Zeek is a passive network traffic analyzer widely used as a network security monitor. It emits structured logs suitable for post-processing by external tools. Suricata EVE JSON outputs alerts, anomalies, metadata, file info, and protocol records through JSON.

Sources:

- [Zeek overview](https://docs.zeek.org/en/lts/about.html)
- [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)

Product implications:

- Treat Zeek and Suricata logs as first-class local file/stream inputs.
- Normalize by `timestamp`, `src_ip`, `dest_ip`, `dest_port`, `proto`, `dns.query`, `http.uri`, `tls.sni`, `community_id`, and alert metadata.
- Use `community_id` when available to correlate Suricata alerts with Zeek connection metadata.

### Endpoint Telemetry

osquery presents operating-system data through SQL-style tables and is widely used for host instrumentation, monitoring, and analytics.

Sources:

- [osquery GitHub](https://github.com/osquery/osquery)
- [osquery SQL introduction](https://osquery.readthedocs.io/en/stable/introduction/sql/)

Product implications:

- Add osquery as a second endpoint source after Wazuh/Sysmon.
- Treat osquery scheduled query packs as detector inputs and evidence collectors.
- Do not allow arbitrary model-generated SQL to run without validation.

### Detection Rules

Sigma is a generic, open, structured detection format for SIEM systems. Sigma rules can become portable detector content and can be converted or interpreted for supported telemetry backends.

Sources:

- [Sigma specification](https://sigmahq.io/sigma-specification/)
- [Sigma main rule repository](https://github.com/SigmaHQ/sigma)

Product implications:

- Support Sigma import in a later phase.
- Store Sigma rules as source artifacts and compile them to backend-specific queries.
- Keep rule provenance and version in case evidence.

### Security Frameworks

NIST CSF 2.0 is organized around six functions: Govern, Identify, Protect, Detect, Respond, and Recover. NIST SP 800-61 Rev. 2 remains an important incident handling guide. MITRE ATT&CK Enterprise organizes adversary tactics and techniques across enterprise platforms.

Sources:

- [NIST CSF 2.0 release note](https://www.nist.gov/node/1840561)
- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE Enterprise Tactics](https://attack.mitre.org/tactics/)

Product implications:

- Every detection and case should map to ATT&CK where possible.
- Coverage views should roll up to NIST CSF functions and repo skill coverage.
- Case workflow should follow incident handling stages: preparation, detection/analysis, containment/eradication/recovery, and post-incident activity.

### Meta-Blue Inspired UI Direction

Public brand color references commonly list Meta blues around `#0082FB` and `#0064E0`. We should treat this as a Meta-inspired palette, not a strict brand clone.

Source: [Meta colors reference](https://brandcolor.dev/brands/meta)

Product implications:

- Use Meta-inspired blue only as the core accent, not a one-note blue UI.
- Build neutral, dense, operational security screens.
- Provide light, dark, and system themes.
- Enforce contrast requirements for text, charts, buttons, badges, and severity colors.
