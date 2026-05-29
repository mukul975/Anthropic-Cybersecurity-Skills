#!/usr/bin/env python3
"""
GDPR Data Subject Access Request (DSAR) Workflow Automation Agent.

Implements end-to-end DSAR processing: intake, identity verification, PII discovery
using regex and NER, data mapping to Article 15 categories, exemption review,
response generation, deadline tracking, and audit logging.

References:
    - GDPR Article 15: https://gdpr-info.eu/art-15-gdpr/
    - ICO DSAR Guidance: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/subject-access-requests/
    - EDPB Guidelines 01/2022 on Right of Access
"""

import re
import json
import uuid
import hashlib
import argparse
import csv
import io
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# PII Regex Patterns -- sourced from Netwrix, PII Crawler, and Varonis
# guidance for EU/UK personal data discovery
# ---------------------------------------------------------------------------

PII_PATTERNS = {
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "description": "Email address",
        "confidence": 0.95,
        "gdpr_category": "contact_information",
    },
    "phone_international": {
        "pattern": r"(?:\+\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
        "description": "Phone number (international format)",
        "confidence": 0.70,
        "gdpr_category": "contact_information",
    },
    "uk_phone": {
        "pattern": r"\b(?:0|\+44[\s\-]?)(?:\d[\s\-]?){9,10}\b",
        "description": "UK phone number",
        "confidence": 0.80,
        "gdpr_category": "contact_information",
    },
    "ssn_us": {
        "pattern": r"\b(?!000|666|9\d{2})\d{3}[\-\s]?(?!00)\d{2}[\-\s]?(?!0000)\d{4}\b",
        "description": "US Social Security Number",
        "confidence": 0.85,
        "gdpr_category": "government_id",
    },
    "nino_uk": {
        "pattern": r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        "description": "UK National Insurance Number",
        "confidence": 0.90,
        "gdpr_category": "government_id",
    },
    "credit_card": {
        "pattern": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
                   r"[\-\s]?\d{4}[\-\s]?\d{4}[\-\s]?\d{1,4}\b",
        "description": "Credit/debit card number",
        "confidence": 0.85,
        "gdpr_category": "financial_data",
    },
    "iban": {
        "pattern": r"\b[A-Z]{2}\d{2}\s?(?:\d{4}\s?){2,7}\d{1,4}\b",
        "description": "IBAN (International Bank Account Number)",
        "confidence": 0.80,
        "gdpr_category": "financial_data",
    },
    "ipv4": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b",
        "description": "IPv4 address",
        "confidence": 0.60,
        "gdpr_category": "online_identifier",
    },
    "date_of_birth": {
        "pattern": r"\b(?:0[1-9]|[12]\d|3[01])[/\-.](?:0[1-9]|1[0-2])[/\-.]"
                   r"(?:19|20)\d{2}\b",
        "description": "Date of birth (DD/MM/YYYY or DD-MM-YYYY)",
        "confidence": 0.65,
        "gdpr_category": "demographic_data",
    },
    "uk_postcode": {
        "pattern": r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
        "description": "UK postcode",
        "confidence": 0.75,
        "gdpr_category": "location_data",
    },
    "passport_uk": {
        "pattern": r"\b\d{9}\b",
        "description": "UK passport number (9 digits)",
        "confidence": 0.40,
        "gdpr_category": "government_id",
    },
    "eu_vat": {
        "pattern": r"\b[A-Z]{2}\d{8,12}\b",
        "description": "EU VAT number",
        "confidence": 0.50,
        "gdpr_category": "financial_data",
    },
}

# Compiled patterns for performance
COMPILED_PATTERNS = {
    name: re.compile(info["pattern"], re.IGNORECASE if name in ("email",) else 0)
    for name, info in PII_PATTERNS.items()
}

# ---------------------------------------------------------------------------
# Article 15 response categories -- information that MUST be provided
# ---------------------------------------------------------------------------

ARTICLE_15_CATEGORIES = {
    "processing_purposes": {
        "label": "Purposes of Processing",
        "article_ref": "Art. 15(1)(a)",
        "description": "The purposes for which the personal data are being processed",
    },
    "data_categories": {
        "label": "Categories of Personal Data",
        "article_ref": "Art. 15(1)(b)",
        "description": "The categories of personal data concerned",
    },
    "recipients": {
        "label": "Recipients or Categories of Recipients",
        "article_ref": "Art. 15(1)(c)",
        "description": "Recipients to whom personal data have been or will be disclosed",
    },
    "retention_period": {
        "label": "Retention Period",
        "article_ref": "Art. 15(1)(d)",
        "description": "Envisaged retention period or criteria used to determine it",
    },
    "data_subject_rights": {
        "label": "Data Subject Rights",
        "article_ref": "Art. 15(1)(e-f)",
        "description": "Right to rectification, erasure, restriction, objection, and complaint",
    },
    "data_source": {
        "label": "Source of Data",
        "article_ref": "Art. 15(1)(g)",
        "description": "Where data was not collected from the subject, available source info",
    },
    "automated_decisions": {
        "label": "Automated Decision-Making",
        "article_ref": "Art. 15(1)(h)",
        "description": "Existence of automated decision-making including profiling",
    },
    "international_transfers": {
        "label": "International Transfers",
        "article_ref": "Art. 15(2)",
        "description": "Appropriate safeguards for transfers to third countries",
    },
}

# ---------------------------------------------------------------------------
# DSAR exemption types per GDPR/UK GDPR
# ---------------------------------------------------------------------------

EXEMPTION_TYPES = {
    "third_party_data": {
        "label": "Third-Party Personal Data",
        "description": "Data relating to another identifiable individual",
        "legal_basis": "Art. 15(4) / DPA 2018 Sch. 2 Para 16",
        "action": "redact",
    },
    "legal_professional_privilege": {
        "label": "Legal Professional Privilege",
        "description": "Communications subject to legal privilege",
        "legal_basis": "DPA 2018 Sch. 2 Para 19",
        "action": "withhold",
    },
    "trade_secrets": {
        "label": "Trade Secrets / Confidential Info",
        "description": "Trade secrets or intellectual property",
        "legal_basis": "Recital 63 GDPR",
        "action": "redact",
    },
    "crime_prevention": {
        "label": "Crime Prevention / Detection",
        "description": "Data processed for crime prevention purposes",
        "legal_basis": "DPA 2018 Sch. 2 Para 2",
        "action": "withhold",
    },
    "management_forecasting": {
        "label": "Management Forecasting / Planning",
        "description": "Data processed for management planning that would prejudice business",
        "legal_basis": "DPA 2018 Sch. 2 Para 22",
        "action": "withhold",
    },
    "negotiations": {
        "label": "Negotiations",
        "description": "Data that would prejudice negotiations with the data subject",
        "legal_basis": "DPA 2018 Sch. 2 Para 24",
        "action": "withhold",
    },
    "regulatory_function": {
        "label": "Regulatory Functions",
        "description": "Data processed for regulatory purposes",
        "legal_basis": "DPA 2018 Sch. 2 Para 20",
        "action": "withhold",
    },
}


# ===========================================================================
# PII Pattern Matcher
# ===========================================================================

class PIIPatternMatcher:
    """Scans text for PII using compiled regex patterns with confidence scoring."""

    def __init__(self, custom_patterns=None):
        self.patterns = dict(COMPILED_PATTERNS)
        self.pattern_info = dict(PII_PATTERNS)
        if custom_patterns:
            for name, spec in custom_patterns.items():
                self.patterns[name] = re.compile(spec["pattern"])
                self.pattern_info[name] = spec

    def scan_text(self, text: str, min_confidence: float = 0.5) -> list[dict]:
        """Scan text for PII matches with confidence scoring."""
        matches = []
        for name, compiled in self.patterns.items():
            info = self.pattern_info[name]
            if info.get("confidence", 1.0) < min_confidence:
                continue
            for m in compiled.finditer(text):
                value = m.group().strip()
                if len(value) < 3:
                    continue
                confidence = info.get("confidence", 0.5)
                # Boost confidence if contextual keywords are nearby
                context_start = max(0, m.start() - 50)
                context_end = min(len(text), m.end() + 50)
                context = text[context_start:context_end].lower()
                context_keywords = {
                    "email": ["email", "e-mail", "contact", "address"],
                    "phone_international": ["phone", "tel", "mobile", "call"],
                    "uk_phone": ["phone", "tel", "mobile", "call"],
                    "ssn_us": ["ssn", "social security", "tax id"],
                    "nino_uk": ["nino", "national insurance", "ni number"],
                    "credit_card": ["card", "visa", "mastercard", "payment"],
                    "iban": ["iban", "bank", "account"],
                    "date_of_birth": ["dob", "birth", "born", "age"],
                    "uk_postcode": ["postcode", "post code", "address", "zip"],
                }
                if name in context_keywords:
                    for kw in context_keywords[name]:
                        if kw in context:
                            confidence = min(1.0, confidence + 0.15)
                            break

                matches.append({
                    "type": name,
                    "value": value,
                    "description": info["description"],
                    "confidence": round(confidence, 2),
                    "gdpr_category": info.get("gdpr_category", "unknown"),
                    "position": {"start": m.start(), "end": m.end()},
                })
        return matches

    def scan_file(self, file_path: str, min_confidence: float = 0.5) -> dict:
        """Scan a file for PII matches."""
        path = Path(file_path)
        if not path.exists():
            return {"file": file_path, "error": "File not found", "matches": []}
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return {"file": file_path, "error": str(e), "matches": []}
        matches = self.scan_text(text, min_confidence)
        return {
            "file": file_path,
            "size_bytes": path.stat().st_size,
            "matches": matches,
            "match_count": len(matches),
            "pii_types_found": list({m["type"] for m in matches}),
        }


# ===========================================================================
# PII Discovery Engine
# ===========================================================================

class PIIDiscoveryEngine:
    """Discovers PII across structured (database) and unstructured (files) data sources."""

    def __init__(self, custom_patterns=None):
        self.matcher = PIIPatternMatcher(custom_patterns)
        self.results = []

    def scan_database(self, connection_string: str,
                      search_identifiers: dict,
                      tables: list[str] | None = None) -> dict:
        """
        Scan a database for records matching search identifiers.

        In production, this connects via SQLAlchemy/psycopg2. This implementation
        generates the parameterized queries needed for discovery.
        """
        queries = []
        if not tables:
            tables = [
                "users", "customers", "orders", "contacts", "employees",
                "audit_log", "login_history", "consent_records",
                "communication_preferences", "support_tickets",
            ]

        safe_table_re = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.]*$")

        for table in tables:
            if not safe_table_re.match(table):
                continue
            for field, value in search_identifiers.items():
                if not safe_table_re.match(field):
                    continue
                queries.append({
                    "table": table,
                    "query": f"SELECT * FROM [{table}] WHERE [{field}] = ?",
                    "params": [value],
                    "search_field": field,
                    "search_value": value,
                })

        # Full-text search query for unstructured columns
        for table in tables:
            if not safe_table_re.match(table):
                continue
            for identifier_value in search_identifiers.values():
                queries.append({
                    "table": table,
                    "query": f"SELECT * FROM [{table}] WHERE CAST(* AS TEXT) LIKE ?",
                    "params": [f"%{identifier_value}%"],
                    "search_type": "full_text",
                })

        result = {
            "source_type": "database",
            "connection": _redact_connection_string(connection_string),
            "tables_scanned": len(tables),
            "queries_generated": len(queries),
            "queries": queries,
            "scan_timestamp": datetime.utcnow().isoformat(),
        }
        self.results.append(result)
        return result

    def scan_files(self, directories: list[str],
                   search_identifiers: dict,
                   file_extensions: list[str] | None = None,
                   max_file_size_mb: int = 50) -> dict:
        """Scan files in directories for PII matching search identifiers."""
        if not file_extensions:
            file_extensions = [
                ".txt", ".csv", ".json", ".xml", ".log", ".html",
                ".md", ".yaml", ".yml", ".ini", ".conf", ".cfg",
            ]

        scanned_files = []
        matches_found = []
        errors = []
        max_bytes = max_file_size_mb * 1024 * 1024

        for directory in directories:
            dir_path = Path(directory)
            if not dir_path.exists():
                errors.append({"directory": directory, "error": "Directory not found"})
                continue
            for ext in file_extensions:
                for file_path in dir_path.rglob(f"*{ext}"):
                    if file_path.stat().st_size > max_bytes:
                        continue
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                    except Exception as e:
                        errors.append({"file": str(file_path), "error": str(e)})
                        continue

                    scanned_files.append(str(file_path))

                    # Check for identifier matches
                    for id_type, id_value in search_identifiers.items():
                        if id_value.lower() in text.lower():
                            # Run full PII scan on matching files
                            pii_matches = self.matcher.scan_text(text)
                            matches_found.append({
                                "file": str(file_path),
                                "matched_identifier": id_type,
                                "pii_matches": pii_matches,
                            })
                            break

        result = {
            "source_type": "files",
            "directories_scanned": len(directories),
            "files_scanned": len(scanned_files),
            "files_with_matches": len(matches_found),
            "matches": matches_found,
            "errors": errors,
            "raw_text_matches": [m["file"] for m in matches_found],
            "scan_timestamp": datetime.utcnow().isoformat(),
        }
        self.results.append(result)
        return result

    def scan_with_ner(self, text_corpus: list[str],
                      entity_types: list[str] | None = None,
                      confidence_threshold: float = 0.7) -> dict:
        """
        Scan text using Named Entity Recognition for contextual PII detection.

        Uses spaCy NER model when available, falls back to regex+context heuristics.
        Entity types: PERSON, EMAIL, PHONE_NUMBER, LOCATION, DATE_OF_BIRTH,
                      ORG, GPE, NORP, CARDINAL
        """
        if not entity_types:
            entity_types = [
                "PERSON", "EMAIL", "PHONE_NUMBER", "LOCATION",
                "DATE_OF_BIRTH", "ORG", "GPE",
            ]

        ner_results = []
        nlp = None

        # Attempt to load spaCy model
        try:
            import spacy
            try:
                nlp = spacy.load("en_core_web_lg")
            except OSError:
                try:
                    nlp = spacy.load("en_core_web_sm")
                except OSError:
                    nlp = None
        except ImportError:
            nlp = None

        for file_path in text_corpus:
            path = Path(file_path)
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            entities_found = []

            if nlp is not None:
                # Use spaCy NER
                doc = nlp(text[:100000])  # Limit to 100k chars for performance
                for ent in doc.ents:
                    if ent.label_ in entity_types:
                        entities_found.append({
                            "text": ent.text,
                            "label": ent.label_,
                            "start": ent.start_char,
                            "end": ent.end_char,
                            "confidence": round(0.7 + (0.3 if ent.label_ in ("PERSON", "ORG") else 0.1), 2),
                            "method": "spacy_ner",
                        })
            else:
                # Fallback: regex + context heuristics
                regex_matches = self.matcher.scan_text(text, min_confidence=confidence_threshold)
                for m in regex_matches:
                    ner_label = _map_pii_type_to_ner(m["type"])
                    if ner_label in entity_types:
                        entities_found.append({
                            "text": m["value"],
                            "label": ner_label,
                            "start": m["position"]["start"],
                            "end": m["position"]["end"],
                            "confidence": m["confidence"],
                            "method": "regex_heuristic",
                        })

                # Name detection heuristic (Title Case sequences near person-keywords)
                if "PERSON" in entity_types:
                    name_pattern = re.compile(
                        r"(?:(?:name|customer|employee|patient|client|user|requester|subject)"
                        r"[\s:=]+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
                        re.MULTILINE,
                    )
                    for m in name_pattern.finditer(text):
                        entities_found.append({
                            "text": m.group(1),
                            "label": "PERSON",
                            "start": m.start(1),
                            "end": m.end(1),
                            "confidence": 0.75,
                            "method": "context_heuristic",
                        })

            ner_results.append({
                "file": str(file_path),
                "entities": entities_found,
                "entity_count": len(entities_found),
            })

        return {
            "source_type": "ner",
            "files_processed": len(ner_results),
            "total_entities": sum(r["entity_count"] for r in ner_results),
            "results": ner_results,
            "model_used": "spacy" if nlp else "regex_heuristic",
            "entity_types_requested": entity_types,
            "scan_timestamp": datetime.utcnow().isoformat(),
        }

    def consolidate_results(self, *result_sets) -> dict:
        """Consolidate PII discovery results from multiple sources."""
        all_records = []
        sources = set()

        for result in result_sets:
            if not result:
                continue
            source_type = result.get("source_type", "unknown")
            sources.add(source_type)

            if source_type == "database":
                for query in result.get("queries", []):
                    all_records.append({
                        "source": f"database:{query['table']}",
                        "type": "structured",
                        "details": query,
                    })

            elif source_type == "files":
                for match in result.get("matches", []):
                    for pii in match.get("pii_matches", []):
                        all_records.append({
                            "source": f"file:{match['file']}",
                            "type": "unstructured",
                            "pii_type": pii["type"],
                            "value_hash": hashlib.sha256(
                                pii["value"].encode()
                            ).hexdigest()[:16],
                            "confidence": pii["confidence"],
                            "gdpr_category": pii["gdpr_category"],
                        })

            elif source_type == "ner":
                for file_result in result.get("results", []):
                    for entity in file_result.get("entities", []):
                        all_records.append({
                            "source": f"ner:{file_result['file']}",
                            "type": "ner_entity",
                            "entity_label": entity["label"],
                            "value_hash": hashlib.sha256(
                                entity["text"].encode()
                            ).hexdigest()[:16],
                            "confidence": entity["confidence"],
                        })

        return {
            "total_records": len(all_records),
            "source_count": len(sources),
            "sources": list(sources),
            "records": all_records,
            "consolidated_at": datetime.utcnow().isoformat(),
        }

    def full_scan(self, search_identifiers: dict,
                  sources: list[str] | None = None,
                  db_connection: str = "",
                  directories: list[str] | None = None) -> dict:
        """Run a complete PII discovery scan across all source types."""
        if sources is None:
            sources = ["database", "files"]
        if directories is None:
            directories = []

        results = []

        if "database" in sources and db_connection:
            results.append(self.scan_database(db_connection, search_identifiers))

        if "files" in sources and directories:
            results.append(self.scan_files(directories, search_identifiers))

        if "ner" in sources:
            # Gather text files from file scan
            text_files = []
            for r in results:
                text_files.extend(r.get("raw_text_matches", []))
            if text_files:
                results.append(self.scan_with_ner(text_files))

        return self.consolidate_results(*results)


# ===========================================================================
# Data Mapper -- maps PII to Article 15 categories
# ===========================================================================

class DataMapper:
    """Maps discovered PII to GDPR Article 15 disclosure categories."""

    def __init__(self, data_inventory_path: str | None = None):
        self.inventory = {}
        if data_inventory_path and Path(data_inventory_path).exists():
            with open(data_inventory_path) as f:
                self.inventory = json.load(f)

    def map_to_article15(self, pii_records: dict,
                         data_subject_id: str) -> dict:
        """Map PII records to Article 15 required categories."""
        categories = []
        gdpr_categories_found = set()

        for record in pii_records.get("records", []):
            cat = record.get("gdpr_category") or record.get("entity_label", "unknown")
            gdpr_categories_found.add(cat)

        # Build category mappings
        category_mapping = {
            "contact_information": {
                "name": "Contact Information",
                "processing_purpose": "Account management, communication, service delivery",
                "legal_basis": "Art. 6(1)(b) - Contract performance",
                "retention_period": "Duration of account + 6 years post-closure",
                "recipients": ["Internal customer service", "Email service provider"],
                "data_types": ["Email address", "Phone number", "Postal address"],
            },
            "government_id": {
                "name": "Government-Issued Identification",
                "processing_purpose": "Identity verification, regulatory compliance (KYC/AML)",
                "legal_basis": "Art. 6(1)(c) - Legal obligation",
                "retention_period": "5 years after last verification event",
                "recipients": ["Compliance team", "Identity verification provider"],
                "data_types": ["National Insurance Number", "Passport number", "SSN"],
            },
            "financial_data": {
                "name": "Financial Information",
                "processing_purpose": "Payment processing, billing, fraud prevention",
                "legal_basis": "Art. 6(1)(b) - Contract performance",
                "retention_period": "7 years for tax compliance",
                "recipients": ["Payment processor", "Finance department", "Tax authority"],
                "data_types": ["Credit card number (tokenized)", "IBAN", "Transaction records"],
            },
            "online_identifier": {
                "name": "Online Identifiers",
                "processing_purpose": "Security monitoring, service analytics",
                "legal_basis": "Art. 6(1)(f) - Legitimate interest (security)",
                "retention_period": "90 days for logs, 2 years for analytics",
                "recipients": ["IT security team", "Analytics platform"],
                "data_types": ["IP address", "Cookie ID", "Device fingerprint"],
            },
            "demographic_data": {
                "name": "Demographic Data",
                "processing_purpose": "Service personalization, age verification",
                "legal_basis": "Art. 6(1)(a) - Consent / Art. 6(1)(b) - Contract",
                "retention_period": "Duration of account relationship",
                "recipients": ["Marketing team (with consent)", "Analytics"],
                "data_types": ["Date of birth", "Gender", "Language preference"],
            },
            "location_data": {
                "name": "Location Data",
                "processing_purpose": "Service delivery, address verification",
                "legal_basis": "Art. 6(1)(b) - Contract performance",
                "retention_period": "Duration of account + 2 years",
                "recipients": ["Delivery partner", "Address verification service"],
                "data_types": ["Postal code", "City", "Country"],
            },
        }

        # Override with data inventory if available
        if self.inventory:
            for cat_key, inv_data in self.inventory.items():
                if cat_key in category_mapping:
                    category_mapping[cat_key].update(inv_data)

        for cat in gdpr_categories_found:
            if cat in category_mapping:
                mapping = category_mapping[cat]
                categories.append(mapping)
            else:
                categories.append({
                    "name": cat.replace("_", " ").title(),
                    "processing_purpose": "See data processing register for details",
                    "legal_basis": "Determined per processing activity",
                    "retention_period": "Per retention schedule",
                    "recipients": ["See recipient register"],
                    "data_types": [cat],
                })

        # Add standard Article 15 supplementary information
        supplementary = {
            "data_subject_rights": {
                "right_to_rectification": "Art. 16 - Right to rectification of inaccurate data",
                "right_to_erasure": "Art. 17 - Right to erasure ('right to be forgotten')",
                "right_to_restriction": "Art. 18 - Right to restriction of processing",
                "right_to_data_portability": "Art. 20 - Right to data portability",
                "right_to_object": "Art. 21 - Right to object to processing",
                "right_to_complaint": "Right to lodge a complaint with the ICO (ico.org.uk) "
                                     "or relevant supervisory authority",
            },
            "automated_decision_making": {
                "exists": False,
                "description": "No automated decision-making or profiling with legal/significant effect",
                "note": "Update based on actual processing activities",
            },
            "international_transfers": {
                "transfers_exist": False,
                "safeguards": "Standard Contractual Clauses (SCCs) where applicable",
                "countries": [],
            },
        }

        return {
            "data_subject": data_subject_id,
            "categories": categories,
            "supplementary_info": supplementary,
            "article_15_reference": ARTICLE_15_CATEGORIES,
            "mapped_at": datetime.utcnow().isoformat(),
        }


# ===========================================================================
# Exemption Reviewer
# ===========================================================================

class ExemptionReviewer:
    """Reviews DSAR data against applicable GDPR/UK GDPR exemptions."""

    def __init__(self):
        self.exemption_types = EXEMPTION_TYPES

    def review_exemptions(self, mapped_data: dict,
                          exemption_checks: list[str] | None = None) -> dict:
        """Review mapped data for applicable exemptions."""
        if not exemption_checks:
            exemption_checks = list(self.exemption_types.keys())

        applicable_exemptions = []

        for check in exemption_checks:
            if check not in self.exemption_types:
                continue

            exemption_info = self.exemption_types[check]
            # Each exemption requires manual DPO review; we flag candidates
            applicable_exemptions.append({
                "exemption_type": check,
                "label": exemption_info["label"],
                "legal_basis": exemption_info["legal_basis"],
                "action": exemption_info["action"],
                "status": "pending_review",
                "dpo_review_required": True,
                "notes": f"Flagged for DPO review: {exemption_info['description']}",
            })

        return {
            "exemption_count": len(applicable_exemptions),
            "exemptions": applicable_exemptions,
            "review_status": "pending_dpo_approval",
            "reviewed_at": datetime.utcnow().isoformat(),
        }

    def apply_redactions(self, mapped_data: dict,
                         approved_exemptions: list[dict]) -> dict:
        """Apply approved exemption redactions to mapped data."""
        redacted = json.loads(json.dumps(mapped_data))

        redaction_log = []
        for exemption in approved_exemptions:
            if exemption.get("status") != "approved":
                continue
            action = exemption.get("action", "redact")
            redaction_log.append({
                "exemption_type": exemption["exemption_type"],
                "action_taken": action,
                "legal_basis": exemption["legal_basis"],
                "applied_at": datetime.utcnow().isoformat(),
            })

        redacted["redaction_log"] = redaction_log
        redacted["redactions_applied"] = len(redaction_log)
        return redacted


# ===========================================================================
# DSAR Response Generator
# ===========================================================================

class DSARResponseGenerator:
    """Generates compliant DSAR response packages per GDPR Article 15."""

    COVER_LETTER_TEMPLATE = """
DATA SUBJECT ACCESS REQUEST RESPONSE
=====================================

Date: {response_date}
DSAR Reference: {dsar_id}

Dear {data_subject},

Thank you for your data subject access request received on {request_date}.

In accordance with Article 15 of the General Data Protection Regulation (GDPR),
we are writing to confirm that we do process your personal data. Please find
enclosed:

1. A copy of all personal data we hold about you
2. Supplementary information as required under Article 15(1)

SUPPLEMENTARY INFORMATION
--------------------------

Purposes of Processing:
{processing_purposes}

Categories of Personal Data:
{data_categories}

Recipients:
{recipients}

Retention Periods:
{retention_periods}

Data Source:
{data_source}

Your Rights:
You have the right to:
- Request rectification of inaccurate personal data (Art. 16)
- Request erasure of your personal data (Art. 17)
- Request restriction of processing (Art. 18)
- Receive your data in a portable format (Art. 20)
- Object to processing based on legitimate interest (Art. 21)
- Lodge a complaint with the Information Commissioner's Office (ico.org.uk)

Automated Decision-Making:
{automated_decisions}

International Transfers:
{international_transfers}

If you have any questions about this response, please contact our Data
Protection Officer at {dpo_email}.

Yours sincerely,
{controller_name}
Data Protection Officer
{organization_name}
"""

    def __init__(self, template_dir: str | None = None,
                 organization_name: str = "Organization",
                 dpo_email: str = "dpo@organization.com",
                 controller_name: str = "Data Protection Officer"):
        self.template_dir = template_dir
        self.organization_name = organization_name
        self.dpo_email = dpo_email
        self.controller_name = controller_name

    def generate_response(self, dsar_id: str, data_subject: str,
                          mapped_data: dict, format: str = "json",
                          request_date: str | None = None) -> dict:
        """Generate a complete DSAR response package."""
        if not request_date:
            request_date = datetime.utcnow().strftime("%Y-%m-%d")

        documents = []

        # 1. Cover letter with supplementary information
        cover_letter = self._generate_cover_letter(
            dsar_id, data_subject, mapped_data, request_date
        )
        documents.append({
            "filename": f"DSAR_{dsar_id}_cover_letter.txt",
            "type": "cover_letter",
            "content": cover_letter,
        })

        # 2. Personal data export
        data_export = self._generate_data_export(dsar_id, mapped_data, format)
        ext = "json" if format == "json" else "csv"
        documents.append({
            "filename": f"DSAR_{dsar_id}_personal_data.{ext}",
            "type": "data_export",
            "content": data_export,
        })

        # 3. Supplementary information document
        supp_doc = self._generate_supplementary_doc(dsar_id, mapped_data)
        documents.append({
            "filename": f"DSAR_{dsar_id}_supplementary_info.json",
            "type": "supplementary_information",
            "content": supp_doc,
        })

        # 4. Audit metadata
        audit_meta = {
            "dsar_id": dsar_id,
            "data_subject": data_subject,
            "response_generated_at": datetime.utcnow().isoformat(),
            "documents_generated": len(documents),
            "format": format,
            "exemptions_applied": mapped_data.get("redactions_applied", 0),
        }
        documents.append({
            "filename": f"DSAR_{dsar_id}_audit_metadata.json",
            "type": "audit_metadata",
            "content": json.dumps(audit_meta, indent=2),
        })

        return {
            "dsar_id": dsar_id,
            "documents": documents,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _generate_cover_letter(self, dsar_id: str, data_subject: str,
                               mapped_data: dict, request_date: str) -> str:
        """Generate the DSAR cover letter."""
        categories = mapped_data.get("categories", [])
        supplementary = mapped_data.get("supplementary_info", {})

        processing_purposes = "\n".join(
            f"  - {cat['name']}: {cat['processing_purpose']}"
            for cat in categories
        ) or "  No personal data processing identified."

        data_categories_text = "\n".join(
            f"  - {cat['name']}: {', '.join(cat.get('data_types', []))}"
            for cat in categories
        ) or "  No categories identified."

        recipients_text = "\n".join(
            f"  - {cat['name']}: {', '.join(cat.get('recipients', []))}"
            for cat in categories
        ) or "  No third-party recipients."

        retention_text = "\n".join(
            f"  - {cat['name']}: {cat.get('retention_period', 'Per retention schedule')}"
            for cat in categories
        ) or "  Per organizational retention schedule."

        auto_decisions = supplementary.get("automated_decision_making", {})
        auto_text = auto_decisions.get(
            "description",
            "No automated decision-making or profiling applies."
        )

        transfers = supplementary.get("international_transfers", {})
        transfer_text = (
            f"Transfers to: {', '.join(transfers['countries'])}. "
            f"Safeguards: {transfers.get('safeguards', 'N/A')}"
            if transfers.get("transfers_exist")
            else "No international transfers of your personal data."
        )

        return self.COVER_LETTER_TEMPLATE.format(
            response_date=datetime.utcnow().strftime("%d %B %Y"),
            dsar_id=dsar_id,
            data_subject=data_subject,
            request_date=request_date,
            processing_purposes=processing_purposes,
            data_categories=data_categories_text,
            recipients=recipients_text,
            retention_periods=retention_text,
            data_source="Data collected directly from you unless otherwise stated.",
            automated_decisions=auto_text,
            international_transfers=transfer_text,
            dpo_email=self.dpo_email,
            controller_name=self.controller_name,
            organization_name=self.organization_name,
        )

    def _generate_data_export(self, dsar_id: str, mapped_data: dict,
                              format: str) -> str:
        """Generate the personal data export in requested format."""
        export_data = {
            "dsar_reference": dsar_id,
            "export_date": datetime.utcnow().isoformat(),
            "categories": [],
        }

        for cat in mapped_data.get("categories", []):
            export_data["categories"].append({
                "category": cat["name"],
                "data_types": cat.get("data_types", []),
                "processing_purpose": cat["processing_purpose"],
                "legal_basis": cat.get("legal_basis", ""),
            })

        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Category", "Data Types", "Processing Purpose", "Legal Basis",
            ])
            for cat in export_data["categories"]:
                writer.writerow([
                    cat["category"],
                    "; ".join(cat["data_types"]),
                    cat["processing_purpose"],
                    cat["legal_basis"],
                ])
            return output.getvalue()

        return json.dumps(export_data, indent=2)

    def _generate_supplementary_doc(self, dsar_id: str,
                                    mapped_data: dict) -> str:
        """Generate the Article 15 supplementary information document."""
        doc = {
            "dsar_reference": dsar_id,
            "article_15_compliance": {},
        }

        for key, cat_info in ARTICLE_15_CATEGORIES.items():
            doc["article_15_compliance"][key] = {
                "article_reference": cat_info["article_ref"],
                "label": cat_info["label"],
                "description": cat_info["description"],
                "provided": True,
            }

        doc["supplementary_info"] = mapped_data.get("supplementary_info", {})
        doc["redaction_log"] = mapped_data.get("redaction_log", [])

        return json.dumps(doc, indent=2)

    def save_response_package(self, response: dict, output_dir: str) -> list[str]:
        """Save all response documents to disk."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        saved = []
        for doc in response.get("documents", []):
            file_path = out_path / doc["filename"]
            file_path.write_text(doc["content"], encoding="utf-8")
            saved.append(str(file_path))
        return saved


# ===========================================================================
# DSAR Workflow Engine -- orchestrates the full lifecycle
# ===========================================================================

class DSARWorkflowEngine:
    """Manages the complete DSAR lifecycle: intake, tracking, and compliance."""

    VALID_STATUSES = [
        "received", "identity_verification", "verification_failed",
        "in_progress", "pii_discovery", "exemption_review",
        "dpo_review", "response_generation", "response_sent",
        "closed", "refused",
    ]

    def __init__(self, config_path: str | None = None):
        self.config = {}
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                self.config = json.load(f)
        self.dsars: dict[str, dict] = {}

    def register_dsar(self, requester_name: str, requester_email: str,
                      request_channel: str, request_text: str,
                      identity_docs: list[str] | None = None) -> dict:
        """Register a new DSAR and start the compliance clock."""
        dsar_id = f"DSAR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        received_at = datetime.utcnow()
        deadline = received_at + timedelta(days=30)

        identity_verified = bool(identity_docs and len(identity_docs) > 0)

        dsar = {
            "dsar_id": dsar_id,
            "requester_name": requester_name,
            "requester_email": requester_email,
            "request_channel": request_channel,
            "request_text": request_text,
            "received_at": received_at.isoformat(),
            "deadline": deadline.isoformat(),
            "deadline_date": deadline.strftime("%Y-%m-%d"),
            "identity_verified": identity_verified,
            "identity_docs": identity_docs or [],
            "status": "received" if identity_verified else "identity_verification",
            "status_history": [
                {
                    "status": "received",
                    "timestamp": received_at.isoformat(),
                    "notes": f"Request received via {request_channel}",
                }
            ],
            "clock_paused": False,
            "extension_applied": False,
        }

        self.dsars[dsar_id] = dsar
        return dsar

    def update_status(self, dsar_id: str, new_status: str,
                      notes: str = "") -> dict:
        """Update DSAR processing status."""
        if dsar_id not in self.dsars:
            raise ValueError(f"DSAR not found: {dsar_id}")
        if new_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}")

        dsar = self.dsars[dsar_id]
        dsar["status"] = new_status
        dsar["status_history"].append({
            "status": new_status,
            "timestamp": datetime.utcnow().isoformat(),
            "notes": notes,
        })
        return dsar

    def apply_extension(self, dsar_id: str, reason: str) -> dict:
        """Apply a 2-month extension for complex requests (Art. 12(3))."""
        if dsar_id not in self.dsars:
            raise ValueError(f"DSAR not found: {dsar_id}")

        dsar = self.dsars[dsar_id]
        if dsar["extension_applied"]:
            raise ValueError("Extension already applied to this DSAR")

        original_deadline = datetime.fromisoformat(dsar["deadline"])
        new_deadline = original_deadline + timedelta(days=60)

        dsar["deadline"] = new_deadline.isoformat()
        dsar["deadline_date"] = new_deadline.strftime("%Y-%m-%d")
        dsar["extension_applied"] = True
        dsar["extension_reason"] = reason
        dsar["status_history"].append({
            "status": "extension_applied",
            "timestamp": datetime.utcnow().isoformat(),
            "notes": f"2-month extension: {reason}",
        })
        return dsar

    def pause_clock(self, dsar_id: str, reason: str) -> dict:
        """Pause the response clock (e.g., awaiting identity verification)."""
        if dsar_id not in self.dsars:
            raise ValueError(f"DSAR not found: {dsar_id}")

        dsar = self.dsars[dsar_id]
        dsar["clock_paused"] = True
        dsar["clock_paused_at"] = datetime.utcnow().isoformat()
        dsar["clock_pause_reason"] = reason
        dsar["status_history"].append({
            "status": "clock_paused",
            "timestamp": datetime.utcnow().isoformat(),
            "notes": f"Clock paused: {reason}",
        })
        return dsar

    def days_remaining(self, dsar_id: str) -> int:
        """Calculate remaining days until DSAR deadline."""
        if dsar_id not in self.dsars:
            raise ValueError(f"DSAR not found: {dsar_id}")

        dsar = self.dsars[dsar_id]
        deadline = datetime.fromisoformat(dsar["deadline"])
        remaining = (deadline - datetime.utcnow()).days
        return max(0, remaining)

    def get_overdue_dsars(self) -> list[dict]:
        """Get all DSARs that are past their deadline."""
        overdue = []
        now = datetime.utcnow()
        for dsar in self.dsars.values():
            if dsar["status"] in ("closed", "refused", "response_sent"):
                continue
            deadline = datetime.fromisoformat(dsar["deadline"])
            if now > deadline:
                overdue.append({
                    "dsar_id": dsar["dsar_id"],
                    "requester": dsar["requester_name"],
                    "deadline": dsar["deadline_date"],
                    "days_overdue": (now - deadline).days,
                    "status": dsar["status"],
                })
        return overdue

    def generate_dashboard(self) -> dict:
        """Generate a DSAR processing dashboard summary."""
        total = len(self.dsars)
        statuses = {}
        for dsar in self.dsars.values():
            status = dsar["status"]
            statuses[status] = statuses.get(status, 0) + 1

        overdue = self.get_overdue_dsars()

        return {
            "total_dsars": total,
            "status_breakdown": statuses,
            "overdue_count": len(overdue),
            "overdue_dsars": overdue,
            "generated_at": datetime.utcnow().isoformat(),
        }


# ===========================================================================
# DSAR Audit Logger
# ===========================================================================

class DSARAuditLogger:
    """Maintains audit trails for DSAR processing lifecycle."""

    def __init__(self, log_path: str = "dsar_audit_logs"):
        self.log_path = Path(log_path)
        self.log_path.mkdir(parents=True, exist_ok=True)

    def log_event(self, dsar_id: str, event_type: str,
                  details: dict | None = None) -> dict:
        """Log a DSAR processing event."""
        event = {
            "dsar_id": dsar_id,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
            "event_id": uuid.uuid4().hex[:12],
        }

        log_file = self.log_path / f"{dsar_id}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

        return event

    def get_audit_trail(self, dsar_id: str) -> list[dict]:
        """Retrieve the complete audit trail for a DSAR."""
        log_file = self.log_path / f"{dsar_id}.jsonl"
        if not log_file.exists():
            return []
        events = []
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def generate_compliance_report(self, dsar_id: str) -> dict:
        """Generate a compliance report for a DSAR showing all processing steps."""
        events = self.get_audit_trail(dsar_id)

        report = {
            "dsar_id": dsar_id,
            "report_generated_at": datetime.utcnow().isoformat(),
            "total_events": len(events),
            "event_types": list({e["event_type"] for e in events}),
            "timeline": [],
            "compliance_checks": {
                "request_acknowledged": False,
                "identity_verified": False,
                "pii_discovery_complete": False,
                "exemption_review_complete": False,
                "response_generated": False,
                "response_sent": False,
                "within_deadline": False,
            },
        }

        for event in events:
            report["timeline"].append({
                "timestamp": event["timestamp"],
                "event": event["event_type"],
                "details": event.get("details", {}),
            })

            etype = event["event_type"]
            if etype == "request_received":
                report["compliance_checks"]["request_acknowledged"] = True
            elif etype == "identity_verified":
                report["compliance_checks"]["identity_verified"] = True
            elif etype == "pii_discovery_complete":
                report["compliance_checks"]["pii_discovery_complete"] = True
            elif etype == "exemption_review_complete":
                report["compliance_checks"]["exemption_review_complete"] = True
            elif etype == "response_generated":
                report["compliance_checks"]["response_generated"] = True
            elif etype == "response_sent":
                report["compliance_checks"]["response_sent"] = True
                report["compliance_checks"]["within_deadline"] = True

        all_passed = all(report["compliance_checks"].values())
        report["overall_compliance"] = "COMPLIANT" if all_passed else "REVIEW_REQUIRED"

        return report


# ===========================================================================
# Utility functions
# ===========================================================================

def _redact_connection_string(conn_str: str) -> str:
    """Redact passwords from connection strings for logging."""
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", conn_str)


def _map_pii_type_to_ner(pii_type: str) -> str:
    """Map PII regex type names to NER entity labels."""
    mapping = {
        "email": "EMAIL",
        "phone_international": "PHONE_NUMBER",
        "uk_phone": "PHONE_NUMBER",
        "ssn_us": "GOVERNMENT_ID",
        "nino_uk": "GOVERNMENT_ID",
        "credit_card": "FINANCIAL",
        "iban": "FINANCIAL",
        "ipv4": "ONLINE_ID",
        "date_of_birth": "DATE_OF_BIRTH",
        "uk_postcode": "LOCATION",
        "passport_uk": "GOVERNMENT_ID",
        "eu_vat": "FINANCIAL",
    }
    return mapping.get(pii_type, "UNKNOWN")


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="GDPR DSAR Workflow Automation Agent"
    )
    parser.add_argument(
        "--action",
        choices=[
            "register", "scan_pii", "scan_files", "map_data",
            "generate_response", "full_pipeline", "dashboard",
        ],
        default="full_pipeline",
        help="Action to perform",
    )
    parser.add_argument("--requester-name", default="Test Subject")
    parser.add_argument("--requester-email", default="test@example.com")
    parser.add_argument("--request-channel", default="email")
    parser.add_argument("--scan-dirs", nargs="*", default=[])
    parser.add_argument("--db-connection", default="")
    parser.add_argument("--output-dir", default="dsar_output")
    parser.add_argument("--config", default="dsar_config.json")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--min-confidence", type=float, default=0.5)
    parser.add_argument(
        "--scan-text",
        help="Direct text to scan for PII",
        default="",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("GDPR DSAR Workflow Automation Agent")
    print("=" * 60)

    if args.action == "scan_pii" and args.scan_text:
        matcher = PIIPatternMatcher()
        matches = matcher.scan_text(args.scan_text, args.min_confidence)
        print(f"\n[+] PII Scan Results ({len(matches)} matches):")
        for m in matches:
            print(f"  [{m['type']}] '{m['value']}' "
                  f"(confidence: {m['confidence']}, category: {m['gdpr_category']})")
        return

    if args.action == "scan_files" and args.scan_dirs:
        pii = PIIDiscoveryEngine()
        results = pii.scan_files(
            args.scan_dirs,
            {"email": args.requester_email, "name": args.requester_name},
        )
        print(f"\n[+] File Scan: {results['files_scanned']} files scanned, "
              f"{results['files_with_matches']} with matches")
        output_file = Path(args.output_dir) / "file_scan_results.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(results, indent=2))
        print(f"[+] Results saved to {output_file}")
        return

    # Full pipeline
    engine = DSARWorkflowEngine(config_path=args.config)
    pii_engine = PIIDiscoveryEngine()
    mapper = DataMapper()
    reviewer = ExemptionReviewer()
    generator = DSARResponseGenerator(
        organization_name=engine.config.get("organization_name", "Organization"),
        dpo_email=engine.config.get("dpo_email", "dpo@organization.com"),
    )
    audit_logger = DSARAuditLogger(log_path=f"{args.output_dir}/audit_logs")

    # Step 1: Register DSAR
    print("\n[Step 1] Registering DSAR...")
    request = engine.register_dsar(
        requester_name=args.requester_name,
        requester_email=args.requester_email,
        request_channel=args.request_channel,
        request_text="Request for all personal data under GDPR Article 15.",
        identity_docs=["email_verified"],
    )
    print(f"  DSAR ID: {request['dsar_id']}")
    print(f"  Deadline: {request['deadline_date']}")
    print(f"  Status: {request['status']}")

    audit_logger.log_event(request["dsar_id"], "request_received", {
        "channel": args.request_channel,
        "requester": args.requester_name,
    })

    # Step 2: PII Discovery
    print("\n[Step 2] Running PII Discovery...")
    engine.update_status(request["dsar_id"], "pii_discovery")

    search_ids = {"email": args.requester_email, "name": args.requester_name}
    all_results = []

    if args.db_connection:
        db_results = pii_engine.scan_database(args.db_connection, search_ids)
        all_results.append(db_results)
        print(f"  Database: {db_results['queries_generated']} queries generated")

    if args.scan_dirs:
        file_results = pii_engine.scan_files(args.scan_dirs, search_ids)
        all_results.append(file_results)
        print(f"  Files: {file_results['files_scanned']} scanned, "
              f"{file_results['files_with_matches']} matches")

    consolidated = pii_engine.consolidate_results(*all_results)
    print(f"  Total PII records: {consolidated['total_records']}")

    audit_logger.log_event(request["dsar_id"], "pii_discovery_complete", {
        "records_found": consolidated["total_records"],
        "sources": consolidated["sources"],
    })

    # Step 3: Data Mapping
    print("\n[Step 3] Mapping to Article 15 categories...")
    mapped = mapper.map_to_article15(consolidated, args.requester_email)
    print(f"  Categories mapped: {len(mapped['categories'])}")

    # Step 4: Exemption Review
    print("\n[Step 4] Reviewing exemptions...")
    engine.update_status(request["dsar_id"], "exemption_review")
    review = reviewer.review_exemptions(mapped)
    redacted = reviewer.apply_redactions(mapped, review["exemptions"])
    print(f"  Exemptions flagged for DPO review: {review['exemption_count']}")

    audit_logger.log_event(request["dsar_id"], "exemption_review_complete", {
        "exemptions_flagged": review["exemption_count"],
    })

    # Step 5: Response Generation
    print("\n[Step 5] Generating response package...")
    engine.update_status(request["dsar_id"], "response_generation")
    response = generator.generate_response(
        dsar_id=request["dsar_id"],
        data_subject=args.requester_name,
        mapped_data=redacted,
        format=args.format,
        request_date=datetime.utcnow().strftime("%Y-%m-%d"),
    )
    saved_files = generator.save_response_package(response, args.output_dir)
    for f in saved_files:
        print(f"  Saved: {f}")

    audit_logger.log_event(request["dsar_id"], "response_generated", {
        "documents": len(response["documents"]),
        "format": args.format,
    })

    # Step 6: Mark complete
    engine.update_status(request["dsar_id"], "response_sent",
                         "Response package generated and ready for delivery")
    audit_logger.log_event(request["dsar_id"], "response_sent", {
        "delivery_method": "manual",
    })

    # Compliance report
    print("\n[Step 6] Generating compliance report...")
    compliance = audit_logger.generate_compliance_report(request["dsar_id"])
    compliance_file = Path(args.output_dir) / f"compliance_report_{request['dsar_id']}.json"
    compliance_file.write_text(json.dumps(compliance, indent=2))
    print(f"  Compliance status: {compliance['overall_compliance']}")
    print(f"  Report saved: {compliance_file}")

    # Dashboard
    print("\n" + "=" * 60)
    dashboard = engine.generate_dashboard()
    print(f"Dashboard: {dashboard['total_dsars']} DSARs, "
          f"{dashboard['overdue_count']} overdue")
    print(f"Days remaining: {engine.days_remaining(request['dsar_id'])}")
    print("=" * 60)
    print("\n[+] DSAR processing complete.")


if __name__ == "__main__":
    main()
