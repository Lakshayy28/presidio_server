"""
SafeChat Presidio PII Engine
=============================
A lean FastAPI service that exposes Presidio's NLP-powered analysis and
anonymization for **Human PII & Financial Data only**.

All developer secrets, CI/CD tokens, and infrastructure configs are now
handled by the TypeScript extension (regex + AST + Shannon entropy).

Endpoints
---------
GET  /health    — liveness check
POST /sanitize  — analyze + anonymize in one call (the only endpoint the extension uses)
"""

import os
import re
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── Engine initialisation ─────────────────────────────────────────────────────
# Create engine FIRST, then import custom recognizers to avoid class-name
# collisions with Presidio's built-in recognizer YAML config loader.

registry = RecognizerRegistry()
registry.load_predefined_recognizers()

analyzer = AnalyzerEngine(registry=registry)
anonymizer = AnonymizerEngine()

# Deferred import — must come after AnalyzerEngine() init.
try:
    from presidio_server.recognizers import CardCvvRecognizer, CardExpiryRecognizer
    from presidio_server.profiles import ACTIVE_ENTITIES
except ImportError:
    from recognizers import CardCvvRecognizer, CardExpiryRecognizer  # type: ignore[no-redef]
    from profiles import ACTIVE_ENTITIES  # type: ignore[no-redef]

registry.add_recognizer(CardCvvRecognizer())
registry.add_recognizer(CardExpiryRecognizer())

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="SafeChat Presidio PII Engine",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response models ─────────────────────────────────────────────────


class SanitizeRequest(BaseModel):
    text: str
    rules: Optional[dict[str, str]] = None


class SanitizeResponse(BaseModel):
    sanitized_text: str
    was_modified: bool
    entities_found: list[dict]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _format_results(raw_text: str, results: list[RecognizerResult]) -> list[dict]:
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
    """Remove common false positives from Presidio built-in recognizers."""
    filtered = []
    for r in results:
        snippet = text[r.start : r.end]

        # PERSON — skip all-uppercase variable/env names (DATABASE_PASSWORD, etc.)
        if r.entity_type == "PERSON" and re.fullmatch(r"[A-Z][A-Z0-9_]+", snippet):
            continue

        # URL — skip dotted config property names that have no URL indicators
        if r.entity_type == "URL" and "://" not in snippet and "/" not in snippet:
            continue

        filtered.append(r)
    return filtered


def _normalize_operation(raw: str) -> str:
    """Map legacy and mixed-case operation names to canonical lowercase."""
    canon = raw.strip().lower()
    if canon in ("replace", "mask", "redact", "hash"):
        return canon
    return "replace"


def _build_operators(
    results: list[RecognizerResult],
    rules: dict[str, str] | None = None,
) -> dict:
    """Build Presidio operator config from per-entity rules."""
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
        else:  # "replace" (default)
            label = f"<{r.entity_type}>"
            operators[r.entity_type] = OperatorConfig(
                "replace", {"new_value": label}
            )
    return operators


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health", summary="Liveness check")
def health():
    return {"status": "ok", "service": "safechat-presidio-pii-engine", "entities": len(ACTIVE_ENTITIES)}


@app.post("/sanitize", response_model=SanitizeResponse, summary="Analyze + anonymize in one call")
def sanitize(req: SanitizeRequest):
    """
    Single-call endpoint: analyzes text against ACTIVE_ENTITIES, anonymizes,
    and returns a was_modified flag so the client can skip caching when clean.
    """
    if not req.text.strip():
        return SanitizeResponse(
            sanitized_text=req.text, was_modified=False, entities_found=[]
        )

    try:
        results = analyzer.analyze(
            text=req.text,
            entities=ACTIVE_ENTITIES,
            language="en",
        )
        results = _filter_false_positives(req.text, results)

        if not results:
            return SanitizeResponse(
                sanitized_text=req.text, was_modified=False, entities_found=[]
            )

        operators = _build_operators(results, req.rules)
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


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("SAFECHAT_PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
