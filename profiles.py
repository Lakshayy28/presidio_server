"""
Sanitization profiles — Anti-Hallucination Edition
───────────────────────────────────────────────────
Presidio handles NLP-only duties (PERSON, CREDIT_CARD, SSN, etc.).
Secret/token detection has moved to the TypeScript regex engine.

CRITICAL: US_DRIVER_LICENSE and US_ITIN are intentionally EXCLUDED —
they hallucinate on source code (e.g. apiVersion: v1, Kubernetes labels).
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# The lean, anti-hallucination PII entity list
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_PII_ENTITIES: list[str] = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "US_BANK_NUMBER",
    "CRYPTO",
    "IP_ADDRESS",
    "URL",
]

FINANCIAL_ENTITIES: list[str] = [
    "CARD_CVV",
    "CARD_EXPIRY",
]

ACTIVE_ENTITIES: list[str] = DEFAULT_PII_ENTITIES + FINANCIAL_ENTITIES
