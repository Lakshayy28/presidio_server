"""
SafeChat Presidio Server
========================
A standalone FastAPI service that exposes Microsoft Presidio's analysis and
anonymization capabilities over HTTP.

Endpoints
---------
GET  /health          — liveness check
POST /analyze         — detect PII entities, return findings (no masking)
POST /anonymize       — mask PII entities, return anonymized text
POST /sanitize        — analyze + anonymize in one call (recommended)

Usage
-----
    pip install -r requirements.txt
    python -m spacy download en_core_web_lg
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

The VS Code extension connects to http://localhost:8000 by default.
To change the port, either:
  • Pass --port <n> to uvicorn
  • Set the SAFECHAT_PORT environment variable
  • Update the `safechat.presidioApiUrl` setting in VS Code
"""

import os
import re
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── Engine initialisation (done once at startup) ──────────────────────────────
# IMPORTANT: custom recognizer imports are intentionally deferred to AFTER
# AnalyzerEngine() is created.  Presidio's registry loader scans
# PatternRecognizer.__subclasses__() during __init__; if our custom classes
# are already imported they can collide with Presidio's own built-in class
# names (e.g. MacAddressRecognizer) and cause a TypeError.

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Deferred import — must come after AnalyzerEngine() to avoid class-name
# collisions with Presidio's built-in recognizer YAML config loader.
try:
    from presidio_server.recognizers import ALL_CUSTOM_RECOGNIZERS
    from presidio_server.profiles import get_entities_for_profile, PROFILES, PROFILE_DESCRIPTIONS
except ImportError:
    from recognizers import ALL_CUSTOM_RECOGNIZERS  # type: ignore[no-redef]
    from profiles import get_entities_for_profile, PROFILES, PROFILE_DESCRIPTIONS  # type: ignore[no-redef]

# Register all custom recognizers with the already-initialised engine.
for _recognizer in ALL_CUSTOM_RECOGNIZERS:
    analyzer.registry.add_recognizer(_recognizer)

# Full list of entity types to scan for
ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "CRYPTO",
    "IP_ADDRESS",
    "IBAN_CODE",
    "NRP",
    "LOCATION",
    "DATE_TIME",
    "US_SSN",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "US_PASSPORT",
    "US_ITIN",
    "MEDICAL_LICENSE",
    "URL",
]

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SafeChat Presidio Server",
    description="PII analysis and anonymization API powered by Microsoft Presidio",
    version="1.0.0",
)

# Allow the VS Code Extension Host (and any local client) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response models ─────────────────────────────────────────────────


class CustomRecognizerDef(BaseModel):
    """User-defined regex recognizer sent from the extension (via YAML config)."""
    name: str                          # entity type label, e.g. "EMPLOYEE_ID"
    pattern: str                       # Python regex
    score: float = 0.85                # confidence score
    context: Optional[list[str]] = None  # context words for score boosting


class TextRequest(BaseModel):
    text: str
    language: str = "en"
    entities: Optional[list[str]] = None  # explicit override
    profile: Optional[str] = None  # "financial" | "developer" | "infrastructure" | "cicd" | "full"
    custom_recognizers: Optional[list[CustomRecognizerDef]] = None


class AnalyzeResponse(BaseModel):
    entities_found: list[dict]  # [{entity_type, start, end, score, text_snippet}]


class AnonymizeRequest(BaseModel):
    text: str
    language: str = "en"
    entities: Optional[list[str]] = None
    profile: Optional[str] = None  # "financial" | "developer" | "infrastructure" | "cicd" | "full"
    replacement_format: str = "<{entity_type}>"  # e.g. "<EMAIL_ADDRESS>"
    rules: Optional[dict[str, str]] = None
    """
    Per-entity anonymization overrides supplied by the extension's rules file.
    Keys are canonical Presidio entity types (e.g. "PHONE_NUMBER").
    Values are one of: replace, mask, redact, hash, encrypt
    (Legacy: "Mask" → mask, "Replace" → replace)
    """
    custom_recognizers: Optional[list[CustomRecognizerDef]] = None
    """
    User-defined regex recognizers. Each one creates a temporary
    PatternRecognizer for this request only.
    """


class AnonymizeResponse(BaseModel):
    anonymized_text: str
    entities_found: list[dict]


class SanitizeResponse(BaseModel):
    sanitized_text: str
    was_modified: bool
    entities_found: list[dict]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _format_results(
    raw_text: str, results: list[RecognizerResult]
) -> list[dict]:
    return [
        {
            "entity_type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 4),
            "text_snippet": raw_text[r.start : r.end],
        }
        for r in results
    ]


def _filter_false_positives(
    text: str, results: list[RecognizerResult]
) -> list[RecognizerResult]:
    """Remove common false positive matches produced by Presidio built-in recognizers.

    1. PERSON — skip all-uppercase variable/env names (DATABASE_PASSWORD, etc.)
    2. URL    — skip dotted config property names that have no URL indicators
    """
    filtered = []
    for r in results:
        snippet = text[r.start : r.end]

        if r.entity_type == "PERSON" and re.fullmatch(r"[A-Z][A-Z0-9_]+", snippet):
            continue

        if r.entity_type == "URL" and "://" not in snippet and "/" not in snippet:
            continue

        filtered.append(r)
    return filtered


def _normalize_operation(raw: str) -> str:
    """Map legacy and mixed-case operation names to canonical lowercase."""
    canon = raw.strip().lower()
    # Legacy backwards-compat
    if canon == "mask" and raw.strip() == "Mask":
        return "mask"
    if canon == "replace" and raw.strip() == "Replace":
        return "replace"
    if canon in ("replace", "mask", "redact", "hash", "encrypt"):
        return canon
    return "replace"  # safe default


def _build_operators(
    replacement_format: str,
    results: list[RecognizerResult],
    rules: dict[str, str] | None = None,
) -> dict:
    """
    Build Presidio operator config for each detected entity type.

    Supported operations (case-insensitive, set per-entity in rules YAML):
      replace  → substitute with <ENTITY_TYPE> placeholder (default)
      mask     → substitute with asterisks  (****)
      redact   → remove entirely
      hash     → one-way SHA-256 hash
      encrypt  → AES-CBC encryption (requires SAFECHAT_ENCRYPT_KEY env var)
    """
    effective_rules: dict[str, str] = {
        k.upper(): _normalize_operation(v) for k, v in (rules or {}).items()
    }
    operators: dict[str, OperatorConfig] = {}
    for r in results:
        if r.entity_type in operators:
            continue
        operation = effective_rules.get(r.entity_type, "replace")

        if operation == "mask":
            operators[r.entity_type] = OperatorConfig(
                "mask",
                {"type": "mask", "masking_char": "*", "chars_to_mask": 128, "from_end": False},
            )
        elif operation == "redact":
            operators[r.entity_type] = OperatorConfig("redact", {})
        elif operation == "hash":
            operators[r.entity_type] = OperatorConfig(
                "hash", {"hash_type": "sha256"}
            )
        elif operation == "encrypt":
            key = os.environ.get("SAFECHAT_ENCRYPT_KEY", "")
            if not key or len(key) not in (16, 24, 32):
                # Fall back to replace if no valid key is configured
                label = replacement_format.replace("{entity_type}", r.entity_type)
                operators[r.entity_type] = OperatorConfig(
                    "replace", {"new_value": label}
                )
            else:
                operators[r.entity_type] = OperatorConfig(
                    "encrypt", {"key": key}
                )
        else:  # "replace" (default)
            label = replacement_format.replace("{entity_type}", r.entity_type)
            operators[r.entity_type] = OperatorConfig(
                "replace", {"new_value": label}
            )
    return operators


def _register_custom_recognizers(
    custom_defs: list[CustomRecognizerDef],
) -> tuple[list[PatternRecognizer], list[str]]:
    """
    Create temporary PatternRecognizer instances from user-supplied definitions.
    Returns (recognizer_list, extra_entity_types).
    """
    recognizers: list[PatternRecognizer] = []
    extra_entities: list[str] = []
    for defn in custom_defs:
        entity_name = defn.name.upper().replace(" ", "_").replace("-", "_")
        # Validate regex
        try:
            re.compile(defn.pattern)
        except re.error:
            continue  # skip invalid regex
        pattern = Pattern(
            name=f"{entity_name}_pattern",
            regex=defn.pattern,
            score=defn.score,
        )
        recognizer = PatternRecognizer(
            supported_entity=entity_name,
            patterns=[pattern],
            context=defn.context or [],
            name=f"CustomRecognizer_{entity_name}",
        )
        recognizers.append(recognizer)
        extra_entities.append(entity_name)
    return recognizers, extra_entities


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health", summary="Liveness check")
def health():
    return {"status": "ok", "service": "safechat-presidio-server"}


@app.post("/analyze", response_model=AnalyzeResponse, summary="Detect PII entities")
def analyze(req: TextRequest):
    """
    Analyze text for PII entities and return the findings without modifying
    the original text. Useful for previewing what would be masked.
    """
    if not req.text.strip():
        return AnalyzeResponse(entities_found=[])

    try:
        entity_list = get_entities_for_profile(req.profile, req.entities)

        # Register any user-supplied custom recognizers for this request
        temp_recognizers: list[PatternRecognizer] = []
        if req.custom_recognizers:
            temp_recognizers, extra = _register_custom_recognizers(req.custom_recognizers)
            entity_list = list(set(entity_list + extra))
            for rec in temp_recognizers:
                analyzer.registry.add_recognizer(rec)

        results = analyzer.analyze(
            text=req.text, language=req.language, entities=entity_list
        )
        results = _filter_false_positives(req.text, results)

        # Clean up temporary recognizers
        for rec in temp_recognizers:
            try:
                analyzer.registry.remove_recognizer(rec.name)
            except Exception:
                pass

        return AnalyzeResponse(entities_found=_format_results(req.text, results))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/anonymize", response_model=AnonymizeResponse, summary="Mask PII entities")
def anonymize(req: AnonymizeRequest):
    """
    Analyze text for PII entities and return the anonymized text with
    placeholders (e.g. <EMAIL_ADDRESS>). Also returns the entity findings.
    """
    if not req.text.strip():
        return AnonymizeResponse(anonymized_text=req.text, entities_found=[])

    try:
        entity_list = get_entities_for_profile(req.profile, req.entities)

        # Register any user-supplied custom recognizers for this request
        temp_recognizers: list[PatternRecognizer] = []
        if req.custom_recognizers:
            temp_recognizers, extra = _register_custom_recognizers(req.custom_recognizers)
            entity_list = list(set(entity_list + extra))
            for rec in temp_recognizers:
                analyzer.registry.add_recognizer(rec)

        results = analyzer.analyze(
            text=req.text, language=req.language, entities=entity_list
        )
        results = _filter_false_positives(req.text, results)
        operators = _build_operators(req.replacement_format, results, req.rules)
        anonymized = anonymizer.anonymize(
            text=req.text,
            analyzer_results=results,
            operators=operators,
        )

        # Clean up temporary recognizers
        for rec in temp_recognizers:
            try:
                analyzer.registry.remove_recognizer(rec.name)
            except Exception:
                pass

        return AnonymizeResponse(
            anonymized_text=anonymized.text,
            entities_found=_format_results(req.text, results),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/sanitize", response_model=SanitizeResponse, summary="Analyze + anonymize in one call")
def sanitize(req: AnonymizeRequest):
    """
    Single-call endpoint: analyzes and anonymizes the text, and additionally
    returns a `was_modified` flag so the client can skip caching when there is
    nothing to mask.
    """
    if not req.text.strip():
        return SanitizeResponse(
            sanitized_text=req.text, was_modified=False, entities_found=[]
        )

    try:
        entity_list = get_entities_for_profile(req.profile, req.entities)

        # Register any user-supplied custom recognizers for this request
        temp_recognizers: list[PatternRecognizer] = []
        if req.custom_recognizers:
            temp_recognizers, extra = _register_custom_recognizers(req.custom_recognizers)
            entity_list = list(set(entity_list + extra))
            for rec in temp_recognizers:
                analyzer.registry.add_recognizer(rec)

        results = analyzer.analyze(
            text=req.text, language=req.language, entities=entity_list
        )
        results = _filter_false_positives(req.text, results)

        # Clean up temporary recognizers
        for rec in temp_recognizers:
            try:
                analyzer.registry.remove_recognizer(rec.name)
            except Exception:
                pass

        if not results:
            return SanitizeResponse(
                sanitized_text=req.text, was_modified=False, entities_found=[]
            )

        operators = _build_operators(req.replacement_format, results, req.rules)
        anonymized = anonymizer.anonymize(
            text=req.text,
            analyzer_results=results,
            operators=operators,
        )
        return SanitizeResponse(
            sanitized_text=anonymized.text,
            was_modified=anonymized.text != req.text,
            entities_found=_format_results(req.text, results),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/profiles", summary="List available sanitization profiles")
def list_profiles():
    """
    Return all built-in sanitization profile names with descriptions.
    Clients can pass any of these names as the ``profile`` field in
    /analyze, /anonymize, or /sanitize requests.
    """
    return {
        "profiles": [
            {"name": name, "description": PROFILE_DESCRIPTIONS.get(name, ""), "entity_count": len(entities)}
            for name, entities in PROFILES.items()
        ]
    }


# ── Documentation endpoints ──────────────────────────────────────────────────

try:
    from presidio_server.docs_ui import get_docs_html, BUILTIN_ENTITIES, CUSTOM_ENTITY_GROUPS, ANONYMIZER_OPERATIONS
except ImportError:
    from docs_ui import get_docs_html, BUILTIN_ENTITIES, CUSTOM_ENTITY_GROUPS, ANONYMIZER_OPERATIONS  # type: ignore[no-redef]


@app.get("/docs/ui", response_class=HTMLResponse, summary="Documentation web page")
def docs_ui():
    """Serve the interactive documentation page listing all recognizers, profiles, and anonymizer operations."""
    return get_docs_html()


@app.get("/docs/entities", summary="JSON entity catalogue")
def docs_entities():
    """Return a structured JSON catalogue of all entity types grouped by category."""
    return {
        "builtin": BUILTIN_ENTITIES,
        "custom": {name: entities for name, entities in CUSTOM_ENTITY_GROUPS.items()},
        "profiles": {
            name: {"description": PROFILE_DESCRIPTIONS.get(name, ""), "entities": entities}
            for name, entities in PROFILES.items()
        },
        "anonymizer_operations": [op["name"] for op in ANONYMIZER_OPERATIONS],
    }


# ── Entry point (for `python main.py`) ────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("SAFECHAT_PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
