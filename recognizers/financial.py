"""
Financial PII recognizers
─────────────────────────
Focused set of financial recognizers that complement Presidio's built-in
CREDIT_CARD, IBAN_CODE, US_BANK_NUMBER, and US_SSN detection.

Only recognizers with low false-positive risk are included here.
For niche identifiers (ISIN, CUSIP, SEDOL, SWIFT BIC, tax IDs, etc.)
users can add custom_recognizers via safechat-rules.yaml.

  CardCvvRecognizer             CARD_CVV              – Card security codes (labelled only)
  CardExpiryRecognizer          CARD_EXPIRY           – Card expiry dates (MM/YY, MM/YYYY)
"""

from presidio_analyzer import Pattern, PatternRecognizer


class CardCvvRecognizer(PatternRecognizer):
    """Card CVV / CVC / CID security codes (labelled only to avoid false positives)."""

    PATTERNS = [
        Pattern("Card CVV (labelled)", r"(?i)(?:cvv|cvc2?|cvv2|cid)\s*[:=]\s*(\d{3,4})\b", 0.9),
    ]
    CONTEXT = [
        "cvv", "cvc", "cvc2", "cvv2", "cid", "security code", "security number",
        "card verification", "verification value",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="CARD_CVV",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class CardExpiryRecognizer(PatternRecognizer):
    """Credit/debit card expiry dates."""

    PATTERNS = [
        Pattern("Card Expiry MM/YY",   r"\b(0[1-9]|1[0-2])\/(2[0-9])\b",       0.55),
        Pattern("Card Expiry MM/YYYY", r"\b(0[1-9]|1[0-2])\/(20[2-9]\d)\b",     0.55),
        Pattern("Card Expiry MM-YY",   r"\b(0[1-9]|1[0-2])-(2[0-9])\b",         0.45),
    ]
    CONTEXT = ["expiry", "expiration", "expires", "exp", "valid thru", "valid until", "valid through", "exp date"]

    def __init__(self):
        super().__init__(
            supported_entity="CARD_EXPIRY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )
