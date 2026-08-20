#!/usr/bin/env python3
"""Agent for implementing browser isolation within a Zero Trust architecture.

Deploys remote browser isolation (RBI) policies with URL categorization,
content disarming and reconstruction (CDR), DLP controls, and integration
with Secure Web Gateway and ZTNA platforms. Based on Cloudflare Browser
Isolation, Menlo Security, and Zscaler RBI approaches.
"""

import os
import json
import uuid
import hashlib
import argparse
import re
from datetime import datetime


# ---------------------------------------------------------------------------
# URL categorization database
# ---------------------------------------------------------------------------
URL_CATEGORIES = {
    # Trusted business categories
    "cloud_productivity": {
        "risk_weight": 1,
        "domains": [
            "docs.google.com", "drive.google.com", "sheets.google.com",
            "office365.com", "office.com", "sharepoint.com",
            "onedrive.live.com", "dropbox.com", "box.com",
        ],
        "patterns": [r".*\.google\.com/.*doc", r".*\.office\.com/.*"],
    },
    "business_saas": {
        "risk_weight": 1,
        "domains": [
            "salesforce.com", "slack.com", "github.com", "gitlab.com",
            "atlassian.net", "jira.atlassian.com", "notion.so",
            "figma.com", "linear.app", "asana.com",
        ],
        "patterns": [],
    },
    "developer_tools": {
        "risk_weight": 2,
        "domains": [
            "stackoverflow.com", "npmjs.com", "pypi.org", "crates.io",
            "hub.docker.com", "registry.npmjs.org", "maven.org",
        ],
        "patterns": [],
    },
    "search_engines": {
        "risk_weight": 1,
        "domains": [
            "google.com", "bing.com", "duckduckgo.com", "yahoo.com",
        ],
        "patterns": [r".*\.google\.[a-z]{2,3}/search.*"],
    },
    # Medium risk categories
    "social_media": {
        "risk_weight": 3,
        "domains": [
            "facebook.com", "twitter.com", "x.com", "linkedin.com",
            "instagram.com", "reddit.com", "tiktok.com", "youtube.com",
        ],
        "patterns": [],
    },
    "webmail": {
        "risk_weight": 3,
        "domains": [
            "mail.google.com", "outlook.live.com", "mail.yahoo.com",
            "protonmail.com", "zoho.com",
        ],
        "patterns": [],
    },
    "news_media": {
        "risk_weight": 2,
        "domains": [
            "cnn.com", "bbc.com", "reuters.com", "nytimes.com",
            "washingtonpost.com", "theguardian.com",
        ],
        "patterns": [],
    },
    "file_sharing": {
        "risk_weight": 4,
        "domains": [
            "wetransfer.com", "sendspace.com", "mediafire.com",
            "mega.nz", "zippyshare.com",
        ],
        "patterns": [],
    },
    # High risk categories
    "admin_console": {
        "risk_weight": 4,
        "domains": [
            "console.aws.amazon.com", "portal.azure.com",
            "console.cloud.google.com", "admin.google.com",
        ],
        "patterns": [r".*admin\..*/.*", r".*console\..*/.*"],
    },
    "ai_tools": {
        "risk_weight": 3,
        "domains": [
            "chat.openai.com", "claude.ai", "bard.google.com",
            "copilot.microsoft.com", "perplexity.ai",
        ],
        "patterns": [],
    },
    "email_client": {
        "risk_weight": 3,
        "domains": [],
        "patterns": [r".*mail\..*", r".*webmail\..*"],
    },
    # Dangerous categories
    "newly_registered": {
        "risk_weight": 5,
        "domains": [],
        "patterns": [],
        "heuristic": "domain_age_days < 30",
    },
    "uncategorized": {
        "risk_weight": 5,
        "domains": [],
        "patterns": [],
    },
    "malware_hosting": {
        "risk_weight": 5,
        "domains": [],
        "patterns": [],
    },
    "phishing": {
        "risk_weight": 5,
        "domains": [],
        "patterns": [
            r".*micr[o0]s[o0]ft.*login.*",
            r".*g[o0]{2}gle.*auth.*",
            r".*paypa[l1].*verify.*",
            r".*amaz[o0]n.*security.*",
            r".*app[l1]e.*id.*confirm.*",
        ],
    },
}

# Risk level thresholds
RISK_LEVELS = {
    1: "low",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

# CDR threat types
CDR_THREAT_TYPES = {
    "macro": {
        "description": "VBA/Office macro with potentially malicious code",
        "file_types": ["docx", "xlsx", "pptx", "doc", "xls", "ppt", "docm", "xlsm"],
        "severity": "high",
        "indicators": ["AutoOpen", "AutoExec", "Document_Open", "Workbook_Open",
                       "Shell", "WScript", "CreateObject", "PowerShell"],
    },
    "embedded_ole": {
        "description": "Embedded OLE object (may contain executable payload)",
        "file_types": ["docx", "xlsx", "pptx", "pdf", "rtf"],
        "severity": "high",
        "indicators": ["OLE2", "Package", "ObjectPool", "CompObj"],
    },
    "javascript_pdf": {
        "description": "JavaScript embedded in PDF document",
        "file_types": ["pdf"],
        "severity": "high",
        "indicators": ["/JavaScript", "/JS", "/Launch", "/SubmitForm",
                       "/OpenAction", "/AA", "/URI"],
    },
    "external_link": {
        "description": "External template or resource reference",
        "file_types": ["docx", "xlsx", "pptx"],
        "severity": "medium",
        "indicators": ["attachedTemplate", "externalLink", "oleLink"],
    },
    "embedded_executable": {
        "description": "Embedded executable or script file",
        "file_types": ["pdf", "docx", "xlsx", "zip", "rar", "7z"],
        "severity": "critical",
        "indicators": ["MZ", "PE", ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"],
    },
    "dde_exploit": {
        "description": "Dynamic Data Exchange field that can execute commands",
        "file_types": ["docx", "xlsx", "csv"],
        "severity": "high",
        "indicators": ["DDE", "DDEAUTO", "cmd.exe", "powershell"],
    },
    "hidden_content": {
        "description": "Hidden text, sheets, or layers that may contain sensitive data",
        "file_types": ["docx", "xlsx", "pptx", "pdf"],
        "severity": "low",
        "indicators": ["hidden", "visibility:hidden", "display:none"],
    },
    "metadata_leak": {
        "description": "Document metadata containing sensitive information",
        "file_types": ["docx", "xlsx", "pptx", "pdf", "jpg", "png"],
        "severity": "low",
        "indicators": ["author", "company", "gps", "location", "revision"],
    },
}

# File extension to MIME type mapping
FILE_EXTENSIONS = {
    "pdf": {"mime": "application/pdf", "cdr_supported": True},
    "docx": {"mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "cdr_supported": True},
    "xlsx": {"mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "cdr_supported": True},
    "pptx": {"mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation", "cdr_supported": True},
    "doc": {"mime": "application/msword", "cdr_supported": True},
    "xls": {"mime": "application/vnd.ms-excel", "cdr_supported": True},
    "ppt": {"mime": "application/vnd.ms-powerpoint", "cdr_supported": True},
    "rtf": {"mime": "application/rtf", "cdr_supported": True},
    "csv": {"mime": "text/csv", "cdr_supported": True},
    "zip": {"mime": "application/zip", "cdr_supported": True},
    "rar": {"mime": "application/x-rar-compressed", "cdr_supported": True},
    "7z": {"mime": "application/x-7z-compressed", "cdr_supported": True},
    "png": {"mime": "image/png", "cdr_supported": True},
    "jpg": {"mime": "image/jpeg", "cdr_supported": True},
    "gif": {"mime": "image/gif", "cdr_supported": True},
    "svg": {"mime": "image/svg+xml", "cdr_supported": True},
    "html": {"mime": "text/html", "cdr_supported": True},
    "exe": {"mime": "application/x-msdownload", "cdr_supported": False},
    "msi": {"mime": "application/x-msi", "cdr_supported": False},
    "dll": {"mime": "application/x-msdownload", "cdr_supported": False},
    "bat": {"mime": "application/x-msdos-program", "cdr_supported": False},
    "ps1": {"mime": "application/x-powershell", "cdr_supported": False},
    "sh": {"mime": "application/x-sh", "cdr_supported": False},
    "iso": {"mime": "application/x-iso9660-image", "cdr_supported": False},
}

# Isolation modes
ISOLATION_MODES = {
    "full_isolation": {
        "description": "Full pixel-streaming RBI - no code reaches endpoint",
        "rendering": "pixel_stream",
        "endpoint_code_execution": False,
        "network_isolation": True,
    },
    "dom_reconstruction": {
        "description": "DOM reconstruction - sanitized DOM streamed to endpoint",
        "rendering": "dom_mirror",
        "endpoint_code_execution": False,
        "network_isolation": True,
    },
    "read_only_isolation": {
        "description": "Isolated rendering with all input disabled except scrolling",
        "rendering": "pixel_stream",
        "endpoint_code_execution": False,
        "network_isolation": True,
        "input_restricted": True,
    },
    "cdr_passthrough": {
        "description": "Direct browsing but files processed through CDR pipeline",
        "rendering": "direct",
        "endpoint_code_execution": True,
        "network_isolation": False,
        "cdr_enabled": True,
    },
    "allow_direct": {
        "description": "Direct access without isolation (trusted sites)",
        "rendering": "direct",
        "endpoint_code_execution": True,
        "network_isolation": False,
    },
    "block": {
        "description": "Block access entirely",
        "rendering": "none",
        "endpoint_code_execution": False,
        "network_isolation": True,
    },
}

DEFAULT_DLP_CONTROLS = {
    "disable_copy_paste": False,
    "disable_download": False,
    "disable_upload": False,
    "disable_printing": False,
    "disable_keyboard_input": False,
    "watermark_session": False,
    "record_session": False,
    "log_all_downloads": True,
    "log_clipboard_events": True,
    "log_file_uploads": True,
    "max_download_size_mb": 100,
    "blocked_upload_types": ["exe", "bat", "ps1", "sh", "dll", "msi"],
}


def _extract_domain(url):
    """Extract the domain from a URL."""
    url = url.lower().strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    domain = url.split("/", 1)[0]
    domain = domain.split(":", 1)[0]  # Remove port
    return domain


def _domain_matches(domain, pattern):
    """Check if a domain matches a pattern (supports wildcard prefix)."""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return domain == pattern


class BrowserIsolationPolicyEngine:
    """Engine for managing browser isolation policies and CDR processing."""

    def __init__(self, organization="", default_isolation_mode="isolate_risky"):
        self.organization = organization
        self.default_isolation_mode = default_isolation_mode
        self.policies = []
        self.sessions = {}
        self.session_events = {}
        self.cdr_results = {}
        self.zt_integration = None
        self._threat_intel_domains = set()

    # ------------------------------------------------------------------
    # URL Classification
    # ------------------------------------------------------------------
    def classify_url(self, url, referrer=None):
        """Classify a URL by category and risk level."""
        domain = _extract_domain(url)
        url_lower = url.lower()

        matched_category = "uncategorized"
        max_risk_weight = 5  # Default for uncategorized

        # Check against known phishing patterns first
        for pattern in URL_CATEGORIES.get("phishing", {}).get("patterns", []):
            if re.match(pattern, url_lower):
                return {
                    "url": url,
                    "domain": domain,
                    "category": "phishing",
                    "risk_level": "critical",
                    "risk_weight": 5,
                    "action": "block",
                    "reason": f"URL matches phishing pattern: {pattern}",
                }

        # Check against threat intelligence
        if domain in self._threat_intel_domains:
            return {
                "url": url,
                "domain": domain,
                "category": "malware_hosting",
                "risk_level": "critical",
                "risk_weight": 5,
                "action": "block",
                "reason": "Domain flagged in threat intelligence feed",
            }

        # Check against category databases
        for cat_name, cat_def in URL_CATEGORIES.items():
            if cat_name in ("phishing", "uncategorized", "malware_hosting", "newly_registered"):
                continue

            # Domain match
            for known_domain in cat_def.get("domains", []):
                if domain == known_domain or domain.endswith("." + known_domain):
                    matched_category = cat_name
                    max_risk_weight = cat_def["risk_weight"]
                    break

            # Pattern match
            if matched_category == "uncategorized":
                for pattern in cat_def.get("patterns", []):
                    if re.match(pattern, url_lower):
                        matched_category = cat_name
                        max_risk_weight = cat_def["risk_weight"]
                        break

            if matched_category != "uncategorized":
                break

        risk_level = RISK_LEVELS.get(max_risk_weight, "critical")

        # Determine action based on risk
        if risk_level == "critical":
            action = "block"
        elif risk_level == "high":
            action = "full_isolation"
        elif risk_level == "medium":
            if self.default_isolation_mode == "isolate_risky":
                action = "full_isolation"
            else:
                action = "dom_reconstruction"
        else:
            action = "allow_direct"

        return {
            "url": url,
            "domain": domain,
            "category": matched_category,
            "risk_level": risk_level,
            "risk_weight": max_risk_weight,
            "action": action,
            "reason": f"Categorized as {matched_category} (risk: {risk_level})",
        }

    def add_threat_intel_domains(self, domains):
        """Add domains from threat intelligence feeds."""
        self._threat_intel_domains.update(d.lower().strip() for d in domains)
        return {"added": len(domains), "total": len(self._threat_intel_domains)}

    # ------------------------------------------------------------------
    # Policy Management
    # ------------------------------------------------------------------
    def add_isolation_policy(self, name, description="", match_criteria=None,
                              isolation_mode="full_isolation", dlp_controls=None,
                              cdr_config=None, priority=None):
        """Add an isolation policy."""
        if isolation_mode not in ISOLATION_MODES:
            raise ValueError(f"Invalid isolation mode: {isolation_mode}. "
                             f"Valid modes: {list(ISOLATION_MODES.keys())}")

        if priority is None:
            priority = len(self.policies) + 1

        effective_dlp = dict(DEFAULT_DLP_CONTROLS)
        if dlp_controls:
            effective_dlp.update(dlp_controls)

        policy = {
            "policy_id": f"POL-{uuid.uuid4().hex[:8].upper()}",
            "name": name,
            "description": description,
            "match_criteria": match_criteria or {},
            "isolation_mode": isolation_mode,
            "isolation_details": ISOLATION_MODES[isolation_mode],
            "dlp_controls": effective_dlp,
            "cdr_config": cdr_config,
            "priority": priority,
            "enabled": True,
            "created_at": datetime.utcnow().isoformat(),
        }

        self.policies.append(policy)
        self.policies.sort(key=lambda p: p["priority"])
        return policy

    def list_policies(self):
        """List all isolation policies ordered by priority."""
        return [
            {
                "policy_id": p["policy_id"],
                "name": p["name"],
                "priority": p["priority"],
                "isolation_mode": p["isolation_mode"],
                "enabled": p["enabled"],
            }
            for p in self.policies
        ]

    def _match_policy(self, url, category, risk_level, user_groups=None,
                       referrer=None, file_type=None):
        """Find the first matching policy for a request."""
        domain = _extract_domain(url)

        for policy in self.policies:
            if not policy["enabled"]:
                continue

            criteria = policy["match_criteria"]
            matched = True

            # Check URL categories
            if "url_categories" in criteria:
                cats = criteria["url_categories"]
                if "*" not in cats and category not in cats:
                    matched = False

            # Check risk levels
            if matched and "risk_levels" in criteria:
                if risk_level not in criteria["risk_levels"]:
                    matched = False

            # Check domains
            if matched and "domains" in criteria:
                domain_matched = False
                for pattern_domain in criteria["domains"]:
                    if _domain_matches(domain, pattern_domain):
                        domain_matched = True
                        break
                if not domain_matched:
                    matched = False

            # Check referrer categories
            if matched and "referrer_categories" in criteria:
                if referrer:
                    ref_result = self.classify_url(referrer)
                    if ref_result["category"] not in criteria["referrer_categories"]:
                        matched = False
                else:
                    matched = False

            # Check file types
            if matched and "file_types" in criteria:
                if file_type and file_type not in criteria["file_types"]:
                    matched = False
                elif not file_type and "file_types" in criteria:
                    # Policy is file-type specific, skip for non-file requests
                    if not any(k in criteria for k in ["url_categories", "domains", "risk_levels"]):
                        matched = False

            # Check user groups
            if matched and "user_groups" in criteria:
                if not user_groups or not set(user_groups) & set(criteria["user_groups"]):
                    matched = False

            if matched:
                return policy

        return None

    # ------------------------------------------------------------------
    # CDR Processing
    # ------------------------------------------------------------------
    def process_file_cdr(self, file_path, source_url="", cdr_profile="standard"):
        """Process a file through Content Disarm and Reconstruction."""
        filename = os.path.basename(file_path)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        file_info = FILE_EXTENSIONS.get(ext, {"mime": "application/octet-stream", "cdr_supported": False})

        if not file_info["cdr_supported"]:
            return {
                "status": "blocked",
                "reason": f"File type '{ext}' is not CDR-supported and has been quarantined",
                "original": {"filename": filename, "extension": ext},
                "quarantined": True,
            }

        # Determine file size (use actual if exists, else simulate)
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            file_size = 0

        # Simulate CDR analysis based on file type and profile
        threats_found = []
        for threat_type, threat_def in CDR_THREAT_TYPES.items():
            if ext in threat_def["file_types"]:
                # Simulate threat detection based on profile strictness
                if cdr_profile == "strict":
                    # Strict mode flags all potential threat types for this file format
                    threats_found.append({
                        "type": threat_type,
                        "description": threat_def["description"],
                        "severity": threat_def["severity"],
                        "action": "STRIPPED",
                        "indicators_checked": threat_def["indicators"],
                    })
                elif cdr_profile == "standard":
                    # Standard mode only flags high/critical severity
                    if threat_def["severity"] in ("high", "critical"):
                        threats_found.append({
                            "type": threat_type,
                            "description": threat_def["description"],
                            "severity": threat_def["severity"],
                            "action": "STRIPPED",
                            "indicators_checked": threat_def["indicators"][:3],
                        })
                elif cdr_profile == "permissive":
                    # Permissive mode only flags critical severity
                    if threat_def["severity"] == "critical":
                        threats_found.append({
                            "type": threat_type,
                            "description": threat_def["description"],
                            "severity": threat_def["severity"],
                            "action": "STRIPPED",
                            "indicators_checked": threat_def["indicators"][:2],
                        })

        # Calculate reconstructed file size (stripped content reduces size)
        size_reduction = len(threats_found) * 0.05  # ~5% per threat stripped
        reconstructed_size = max(int(file_size * (1 - size_reduction)), int(file_size * 0.7))

        clean_filename = filename.rsplit(".", 1)
        clean_filename = f"{clean_filename[0]}_clean.{clean_filename[1]}" if len(clean_filename) > 1 else f"{filename}_clean"

        result = {
            "status": "processed",
            "cdr_profile": cdr_profile,
            "original": {
                "filename": filename,
                "extension": ext,
                "mime_type": file_info["mime"],
                "size_bytes": file_size,
                "source_url": source_url,
                "hash_sha256": hashlib.sha256(filename.encode()).hexdigest(),
            },
            "threats_found": len(threats_found),
            "threats_detail": threats_found,
            "reconstructed": {
                "filename": clean_filename,
                "size_bytes": reconstructed_size,
                "usable": True,
                "format_preserved": True,
                "hash_sha256": hashlib.sha256(clean_filename.encode()).hexdigest(),
            },
            "processing_time_ms": len(threats_found) * 150 + 200,
            "processed_at": datetime.utcnow().isoformat(),
        }

        self.cdr_results[filename] = result
        return result

    def batch_cdr_process(self, files, cdr_profile="standard", quarantine_on_threat=True):
        """Process multiple files through CDR pipeline."""
        results = []
        threats_neutralized = 0
        quarantined = 0
        clean = 0

        for file_path in files:
            result = self.process_file_cdr(
                file_path=file_path,
                cdr_profile=cdr_profile,
            )
            results.append({
                "filename": os.path.basename(file_path),
                "status": result["status"],
                "threats_found": result.get("threats_found", 0),
                "clean": result.get("threats_found", 0) == 0,
                "quarantined": result.get("quarantined", False),
            })

            if result.get("quarantined"):
                quarantined += 1
            elif result.get("threats_found", 0) > 0:
                threats_neutralized += result["threats_found"]
            else:
                clean += 1

        return {
            "total_processed": len(files),
            "clean_count": clean,
            "threats_neutralized": threats_neutralized,
            "quarantined_count": quarantined,
            "cdr_profile": cdr_profile,
            "results": results,
            "processed_at": datetime.utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # Session Management
    # ------------------------------------------------------------------
    def create_isolation_session(self, user_id, target_url,
                                  user_groups=None, device_posture=None,
                                  user_risk_level="low"):
        """Create an isolated browsing session."""
        session_id = f"SES-{uuid.uuid4().hex[:12].upper()}"

        # Classify the target URL
        classification = self.classify_url(target_url)

        # Find matching policy
        policy = self._match_policy(
            url=target_url,
            category=classification["category"],
            risk_level=classification["risk_level"],
            user_groups=user_groups,
        )

        # Check ZT integration rules
        zt_overrides = {}
        if self.zt_integration:
            for rule in self.zt_integration.get("conditional_access_rules", []):
                condition = rule.get("condition", {})
                rule_matched = True

                if "device_managed" in condition:
                    if device_posture and device_posture.get("managed") != condition["device_managed"]:
                        rule_matched = False
                    elif not device_posture:
                        rule_matched = False

                if "user_risk_level" in condition:
                    if user_risk_level != condition["user_risk_level"]:
                        rule_matched = False

                if "user_group" in condition:
                    if not user_groups or condition["user_group"] not in user_groups:
                        rule_matched = False

                if "target_category" in condition:
                    if classification["category"] != condition["target_category"]:
                        rule_matched = False

                if rule_matched:
                    zt_overrides = {
                        "action": rule.get("action", "full_isolation"),
                        "dlp_override": rule.get("dlp_override", {}),
                        "matched_rule": rule["name"],
                    }
                    break

        # Determine effective isolation mode and DLP controls
        if zt_overrides:
            isolation_mode = zt_overrides["action"]
            effective_dlp = dict(DEFAULT_DLP_CONTROLS)
            if policy:
                effective_dlp.update(policy.get("dlp_controls", {}))
            effective_dlp.update(zt_overrides.get("dlp_override", {}))
            applied_policy = zt_overrides.get("matched_rule", "Zero Trust Override")
        elif policy:
            isolation_mode = policy["isolation_mode"]
            effective_dlp = policy["dlp_controls"]
            applied_policy = policy["name"]
        else:
            isolation_mode = classification["action"]
            effective_dlp = dict(DEFAULT_DLP_CONTROLS)
            applied_policy = "Default Classification"

        session = {
            "session_id": session_id,
            "user_id": user_id,
            "user_groups": user_groups or [],
            "target_url": target_url,
            "url_classification": classification,
            "device_posture": device_posture or {},
            "user_risk_level": user_risk_level,
            "isolation_mode": isolation_mode,
            "isolation_details": ISOLATION_MODES.get(isolation_mode, {}),
            "applied_policy": applied_policy,
            "dlp_controls": effective_dlp,
            "zt_overrides": zt_overrides,
            "status": "active",
            "started_at": datetime.utcnow().isoformat(),
        }

        self.sessions[session_id] = session

        # Record session start event
        self.session_events.setdefault(session_id, []).append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "session_start",
            "details": f"Isolation session started for {target_url} "
                       f"(mode: {isolation_mode}, policy: {applied_policy})",
        })

        return session

    def get_session_events(self, session_id):
        """Get all events for a session."""
        return self.session_events.get(session_id, [])

    def end_session(self, session_id):
        """End an isolation session."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.sessions[session_id]
        session["status"] = "ended"
        session["ended_at"] = datetime.utcnow().isoformat()

        self.session_events.setdefault(session_id, []).append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "session_end",
            "details": "Isolation session terminated",
        })

        return session

    def generate_session_audit(self, user_id=None, date_range=None):
        """Generate audit report for isolation sessions."""
        sessions = list(self.sessions.values())
        if user_id:
            sessions = [s for s in sessions if s["user_id"] == user_id]

        total = len(sessions)
        isolated = sum(1 for s in sessions if s["isolation_mode"] != "allow_direct")
        cdr_files = len(self.cdr_results)
        dlp_violations = sum(
            1 for events in self.session_events.values()
            for e in events if e["event_type"] == "dlp_violation"
        )

        return {
            "user_id": user_id,
            "date_range": date_range,
            "total_sessions": total,
            "isolated_sessions": isolated,
            "direct_sessions": total - isolated,
            "isolation_rate": round((isolated / total * 100), 1) if total else 0,
            "cdr_processed_files": cdr_files,
            "dlp_violations": dlp_violations,
            "generated_at": datetime.utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # Zero Trust Integration
    # ------------------------------------------------------------------
    def create_zero_trust_integration(self, identity_provider="",
                                       conditional_access_rules=None,
                                       swg_integration=None):
        """Configure Zero Trust platform integration."""
        self.zt_integration = {
            "identity_provider": identity_provider,
            "conditional_access_rules": conditional_access_rules or [],
            "swg_integration": swg_integration or {},
            "configured_at": datetime.utcnow().isoformat(),
        }
        return self.zt_integration

    def evaluate_access_request(self, user_id, target_url, user_groups=None,
                                 device_posture=None, user_risk_level="low",
                                 referrer=None):
        """Evaluate an access request against all policies and ZT rules."""
        # Create a session (which evaluates all policies)
        session = self.create_isolation_session(
            user_id=user_id,
            target_url=target_url,
            user_groups=user_groups,
            device_posture=device_posture,
            user_risk_level=user_risk_level,
        )

        matched_rules = []
        if session.get("zt_overrides", {}).get("matched_rule"):
            matched_rules.append({"name": session["zt_overrides"]["matched_rule"],
                                   "source": "zero_trust"})
        if session.get("applied_policy") and session["applied_policy"] != "Default Classification":
            matched_rules.append({"name": session["applied_policy"],
                                   "source": "isolation_policy"})

        return {
            "session_id": session["session_id"],
            "action": session["isolation_mode"],
            "url_classification": session["url_classification"],
            "matched_rules": matched_rules,
            "effective_dlp_controls": session["dlp_controls"],
            "device_posture_evaluated": bool(device_posture),
            "isolation_details": session["isolation_details"],
        }

    # ------------------------------------------------------------------
    # Compliance Reporting
    # ------------------------------------------------------------------
    def generate_compliance_report(self, date_range=None, include_metrics=True):
        """Generate a compliance report for browser isolation deployment."""
        total_sessions = len(self.sessions)
        isolated = sum(1 for s in self.sessions.values()
                       if s["isolation_mode"] not in ("allow_direct",))
        blocked = sum(1 for s in self.sessions.values()
                      if s["isolation_mode"] == "block")

        cdr_total = len(self.cdr_results)
        cdr_threats = sum(r.get("threats_found", 0) for r in self.cdr_results.values())
        cdr_quarantined = sum(1 for r in self.cdr_results.values() if r.get("quarantined"))

        dlp_violations = sum(
            1 for events in self.session_events.values()
            for e in events if e["event_type"] == "dlp_violation"
        )

        report = {
            "organization": self.organization,
            "report_period": date_range,
            "generated_at": datetime.utcnow().isoformat(),
            "total_requests": total_sessions,
            "isolated_requests": isolated,
            "blocked_requests": blocked,
            "direct_requests": total_sessions - isolated - blocked,
            "isolation_rate": round((isolated / total_sessions * 100), 1) if total_sessions else 0,
            "policies_configured": len(self.policies),
            "policies_enabled": sum(1 for p in self.policies if p["enabled"]),
            "cdr_stats": {
                "total_files": cdr_total,
                "threats_neutralized": cdr_threats,
                "files_quarantined": cdr_quarantined,
                "clean_files": cdr_total - cdr_quarantined,
            },
            "dlp_violations_blocked": dlp_violations,
            "zero_day_blocked": blocked,
            "zero_trust_integration": bool(self.zt_integration),
        }

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Browser Isolation for Zero Trust - Policy Engine"
    )
    parser.add_argument("--org", default="", help="Organization name")
    parser.add_argument("--output", default="rbi_report.json", help="Output report path")
    parser.add_argument("--action", choices=[
        "classify", "demo", "cdr_test", "policy_report",
    ], default="demo", help="Action to perform")
    parser.add_argument("--url", default="", help="URL to classify (for classify action)")
    parser.add_argument("--file", default="", help="File to process (for cdr_test action)")
    args = parser.parse_args()

    engine = BrowserIsolationPolicyEngine(
        organization=args.org or "Demo Corp",
        default_isolation_mode="isolate_risky",
    )

    if args.action == "classify" and args.url:
        result = engine.classify_url(args.url)
        print(f"URL: {result['url']}")
        print(f"Domain: {result['domain']}")
        print(f"Category: {result['category']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Action: {result['action']}")
        print(f"Reason: {result['reason']}")

    elif args.action == "cdr_test" and args.file:
        result = engine.process_file_cdr(args.file, cdr_profile="strict")
        print(f"Status: {result['status']}")
        if result["status"] == "processed":
            print(f"Threats found: {result['threats_found']}")
            for t in result["threats_detail"]:
                print(f"  [{t['severity'].upper()}] {t['type']}: {t['description']} -> {t['action']}")
            print(f"Clean file: {result['reconstructed']['filename']}")

    elif args.action == "demo":
        print("[*] Running Browser Isolation Demo...\n")

        # Add policies
        engine.add_isolation_policy(
            name="Block Phishing and Malware",
            match_criteria={"url_categories": ["phishing", "malware_hosting"],
                            "risk_levels": ["critical"]},
            isolation_mode="block",
            priority=1,
        )
        engine.add_isolation_policy(
            name="Isolate Uncategorized Sites",
            match_criteria={"url_categories": ["uncategorized", "newly_registered"],
                            "risk_levels": ["high", "critical"]},
            isolation_mode="full_isolation",
            dlp_controls={"disable_download": True, "disable_upload": True,
                          "watermark_session": True},
            priority=2,
        )
        engine.add_isolation_policy(
            name="Isolate Webmail",
            match_criteria={"url_categories": ["webmail"]},
            isolation_mode="read_only_isolation",
            dlp_controls={"disable_copy_paste": True, "disable_download": True},
            priority=3,
        )
        engine.add_isolation_policy(
            name="CDR for File Sharing",
            match_criteria={"url_categories": ["file_sharing"]},
            isolation_mode="cdr_passthrough",
            cdr_config={"strip_macros": True, "strip_embedded_objects": True},
            priority=4,
        )
        engine.add_isolation_policy(
            name="Allow Trusted SaaS",
            match_criteria={"url_categories": ["cloud_productivity", "business_saas"],
                            "risk_levels": ["low"]},
            isolation_mode="allow_direct",
            priority=10,
        )
        print(f"[+] Configured {len(engine.policies)} isolation policies\n")

        # Configure ZT integration
        engine.create_zero_trust_integration(
            identity_provider="Azure AD",
            conditional_access_rules=[
                {"name": "Unmanaged Device Isolation",
                 "condition": {"device_managed": False},
                 "action": "full_isolation",
                 "dlp_override": {"disable_download": True}},
                {"name": "Contractor Restricted",
                 "condition": {"user_group": "contractors"},
                 "action": "read_only_isolation",
                 "dlp_override": {"disable_download": True, "disable_printing": True}},
            ],
        )
        print("[+] Zero Trust integration configured\n")

        # Classify URLs
        test_urls = [
            "https://docs.google.com/spreadsheets/d/abc123",
            "https://mail.google.com/inbox",
            "https://unknown-domain-xyz.top/page.html",
            "https://micr0s0ft-login.phishing.com/auth",
            "https://github.com/org/repo",
            "https://mega.nz/file/abc123",
            "https://console.aws.amazon.com/ec2",
        ]

        print("--- URL Classification ---")
        for url in test_urls:
            result = engine.classify_url(url)
            print(f"  {url}")
            print(f"    Category: {result['category']} | Risk: {result['risk_level']} | Action: {result['action']}")
        print()

        # Create isolation sessions
        print("--- Isolation Sessions ---")
        session1 = engine.create_isolation_session(
            user_id="employee@acme.com",
            user_groups=["engineering"],
            device_posture={"managed": True, "edr_running": True},
            target_url="https://unknown-domain-xyz.top/page.html",
        )
        print(f"  Session: {session1['session_id']}")
        print(f"    URL: {session1['target_url']}")
        print(f"    Mode: {session1['isolation_mode']}")
        print(f"    Policy: {session1['applied_policy']}")

        session2 = engine.create_isolation_session(
            user_id="contractor@vendor.com",
            user_groups=["contractors"],
            device_posture={"managed": False, "edr_running": False},
            target_url="https://docs.google.com/document/d/abc",
        )
        print(f"\n  Session: {session2['session_id']}")
        print(f"    URL: {session2['target_url']}")
        print(f"    Mode: {session2['isolation_mode']}")
        print(f"    Policy: {session2['applied_policy']}")
        print()

        # CDR processing
        print("--- CDR Processing ---")
        test_files = [
            "/tmp/downloads/report.docx",
            "/tmp/downloads/data.xlsx",
            "/tmp/downloads/presentation.pptx",
            "/tmp/downloads/invoice.pdf",
            "/tmp/downloads/malware.exe",
        ]
        batch = engine.batch_cdr_process(test_files, cdr_profile="strict", quarantine_on_threat=True)
        print(f"  Processed: {batch['total_processed']}")
        print(f"  Clean: {batch['clean_count']}")
        print(f"  Threats neutralized: {batch['threats_neutralized']}")
        print(f"  Quarantined: {batch['quarantined_count']}")
        for r in batch["results"]:
            status = "QUARANTINED" if r["quarantined"] else ("CLEAN" if r["clean"] else "SANITIZED")
            print(f"    [{status}] {r['filename']}: {r['threats_found']} threats")
        print()

        # Compliance report
        report = engine.generate_compliance_report(
            date_range=("2026-03-01", "2026-03-19"),
        )
        print("--- Compliance Report ---")
        print(f"  Total requests: {report['total_requests']}")
        print(f"  Isolated: {report['isolated_requests']} ({report['isolation_rate']}%)")
        print(f"  Blocked: {report['blocked_requests']}")
        print(f"  CDR files: {report['cdr_stats']['total_files']}")
        print(f"  Threats neutralized: {report['cdr_stats']['threats_neutralized']}")

        # Save report
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")

    else:
        print("[!] Specify --action and required parameters.")
        print("    --action classify --url <URL>")
        print("    --action cdr_test --file <FILE>")
        print("    --action demo")


if __name__ == "__main__":
    main()
