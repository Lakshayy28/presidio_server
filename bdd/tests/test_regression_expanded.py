"""
Expanded regression test suite — covers edge cases, multi-entity detection,
negative/false-positive tests, boundary conditions, structure preservation,
error handling, profile filtering, anonymization rules, and format variations.

Complements the existing BDD feature tests which provide one positive case
per entity type.
"""

import json
import pytest
import requests
import allure

from conftest import BASE_URL, HTTP_TIMEOUT

_SANITIZE = f"{BASE_URL}/sanitize"
_ANALYZE = f"{BASE_URL}/analyze"
_ANONYMIZE = f"{BASE_URL}/anonymize"
_HEALTH = f"{BASE_URL}/health"


def _post(url, payload, timeout=HTTP_TIMEOUT):
    return requests.post(url, json=payload, timeout=timeout)


def _sanitize(text, **kwargs):
    payload = {"text": text, "language": "en", **kwargs}
    resp = _post(_SANITIZE, payload)
    assert resp.status_code == 200
    return resp.json()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Edge Cases")
class TestEdgeCases:
    """Validate behaviour for unusual or degenerate input."""

    @allure.story("Empty and blank inputs")
    def test_empty_text(self):
        body = _sanitize("")
        assert body["was_modified"] is False
        assert body["entities_found"] == []

    @allure.story("Empty and blank inputs")
    def test_whitespace_only_text(self):
        body = _sanitize("   \n\t  ")
        assert body["was_modified"] is False
        assert body["entities_found"] == []

    @allure.story("Empty and blank inputs")
    def test_single_character(self):
        body = _sanitize("a")
        assert body["was_modified"] is False

    @allure.story("No PII text")
    def test_clean_business_text(self):
        text = (
            "Revenue growth is strong across all product lines. "
            "Our engineering team shipped the new feature ahead of plan. "
            "Cost optimization efforts reduced infrastructure spend significantly."
        )
        body = _sanitize(text, profile="full")
        assert body["was_modified"] is False
        assert body["entities_found"] == []

    @allure.story("Long input")
    def test_long_text_with_scattered_pii(self):
        filler = "This is a routine log entry with no sensitive data. " * 200
        text = (
            filler
            + "User email: alice@example.com\n"
            + filler
            + "SSN: 323-45-6789\n"
            + filler
        )
        body = _sanitize(text, profile="full")
        assert body["was_modified"] is True
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "EMAIL_ADDRESS" in found
        assert "US_SSN" in found


# ═══════════════════════════════════════════════════════════════════════════════
# 2. MULTI-ENTITY MIXED TEXT
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Multi-Entity Detection")
class TestMultiEntity:
    """Text with several PII types must have all detected."""

    @allure.story("Built-in entities mixed")
    def test_email_phone_ssn_in_one_text(self):
        text = (
            "Customer alice@example.com called from (415) 555-0192 "
            "about account SSN 323-45-6789."
        )
        body = _sanitize(text)
        found = {e["entity_type"] for e in body["entities_found"]}
        assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN"} <= found

    @allure.story("Built-in + custom entities")
    def test_credit_card_and_aws_key(self):
        text = (
            "Payment card 4532015112830366 was charged. "
            "Debug: aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        )
        body = _sanitize(text, profile="full")
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "CREDIT_CARD" in found
        assert "AWS_ACCESS_KEY" in found

    @allure.story("Cross-domain entities")
    def test_financial_developer_infrastructure_combined(self):
        text = (
            "IBAN: GB29NWBK60161331926819\n"
            'Bearer token: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123\n'
            "DB: postgresql://admin:secret@db.internal:5432/prod"
        )
        body = _sanitize(text, profile="full")
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "IBAN_CODE" in found
        assert "DB_CONNECTION_STRING" in found

    @allure.story("Multiple instances of same entity")
    def test_multiple_emails(self):
        text = (
            "Notify alice@example.com, bob@example.com, and charlie@example.com."
        )
        body = _sanitize(text)
        emails = [e for e in body["entities_found"] if e["entity_type"] == "EMAIL_ADDRESS"]
        assert len(emails) >= 3


# ═══════════════════════════════════════════════════════════════════════════════
# 3. NEGATIVE / FALSE POSITIVE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("False Positive Prevention")
class TestNegativeCases:
    """Text that looks like PII but isn't must NOT be flagged."""

    @allure.story("Non-PII numeric strings")
    def test_random_16_digits_not_credit_card(self):
        # 1234567890123456 fails Luhn check → should not be CREDIT_CARD
        text = "Order reference: 1234567890123456."
        body = _sanitize(text, entities=["CREDIT_CARD"])
        cc = [e for e in body["entities_found"] if e["entity_type"] == "CREDIT_CARD"]
        assert len(cc) == 0

    @allure.story("Non-PII variable names")
    def test_uppercase_variable_not_person(self):
        # Env-var like names should be filtered by _filter_false_positives
        text = "Setting DATABASE_PASSWORD and REDIS_HOST in the config."
        body = _sanitize(text, entities=["PERSON"])
        persons = [e for e in body["entities_found"] if e["entity_type"] == "PERSON"]
        assert len(persons) == 0

    @allure.story("Non-PII code patterns")
    def test_hex_color_not_detected(self):
        text = "The primary color is #FF5733 and secondary is #C70039."
        body = _sanitize(text, profile="full")
        # Should not detect these as crypto or any PII
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "CRYPTO" not in found

    @allure.story("Non-PII dot notation")
    def test_dotted_property_not_url(self):
        text = "spring.datasource.url is a configuration property name."
        body = _sanitize(text, entities=["URL"])
        urls = [e for e in body["entities_found"] if e["entity_type"] == "URL"]
        assert len(urls) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. BOUNDARY CONDITIONS
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Boundary Conditions")
class TestBoundaryConditions:
    """PII at unusual positions in text."""

    @allure.story("PII at text boundaries")
    def test_pii_at_start_of_text(self):
        text = "alice@example.com reported the issue yesterday."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        assert body["was_modified"] is True
        assert any(e["entity_type"] == "EMAIL_ADDRESS" for e in body["entities_found"])

    @allure.story("PII at text boundaries")
    def test_pii_at_end_of_text(self):
        text = "Please contact alice@example.com"
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        assert body["was_modified"] is True

    @allure.story("PII in brackets/delimiters")
    def test_pii_in_square_brackets(self):
        text = "Logged user: [alice@example.com] at 14:00."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        emails = [e for e in body["entities_found"] if e["entity_type"] == "EMAIL_ADDRESS"]
        assert len(emails) >= 1

    @allure.story("PII in brackets/delimiters")
    def test_pii_in_angle_brackets(self):
        text = "From: <alice@example.com>"
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        assert body["was_modified"] is True

    @allure.story("Adjacent PII")
    def test_back_to_back_pii(self):
        text = "alice@example.com bob@example.com"
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        emails = [e for e in body["entities_found"] if e["entity_type"] == "EMAIL_ADDRESS"]
        assert len(emails) >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# 5. STRUCTURE PRESERVATION
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Structure Preservation")
class TestStructurePreservation:
    """Sanitized output must remain structurally valid."""

    @allure.story("JSON structure preserved")
    def test_json_validity_after_sanitization(self):
        obj = {
            "user": "alice@example.com",
            "phone": "(415) 555-0192",
            "notes": "Customer SSN: 323-45-6789"
        }
        text = json.dumps(obj)
        body = _sanitize(text, profile="full")
        assert body["was_modified"] is True
        # The sanitized text should still be valid JSON
        parsed = json.loads(body["sanitized_text"])
        assert isinstance(parsed, dict)
        assert "user" in parsed

    @allure.story("Line count preserved")
    def test_line_count_preserved(self):
        text = "Line one: normal\nLine two: alice@example.com\nLine three: normal"
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        assert body["was_modified"] is True
        assert body["sanitized_text"].count("\n") == text.count("\n")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Error Handling")
class TestErrorHandling:
    """Invalid requests must return appropriate HTTP errors."""

    @allure.story("Missing required fields")
    def test_missing_text_field(self):
        resp = _post(_SANITIZE, {"language": "en"})
        assert resp.status_code == 422

    @allure.story("Wrong HTTP method")
    def test_get_on_sanitize_not_allowed(self):
        resp = requests.get(_SANITIZE, timeout=HTTP_TIMEOUT)
        assert resp.status_code == 405

    @allure.story("Empty JSON body")
    def test_empty_json_body(self):
        resp = _post(_SANITIZE, {})
        assert resp.status_code == 422

    @allure.story("Health endpoint")
    def test_health_endpoint(self):
        resp = requests.get(_HEALTH, timeout=HTTP_TIMEOUT)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. PROFILE-BASED FILTERING
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Profile Filtering")
class TestProfileFiltering:
    """Profile selection controls which entity types are returned."""

    @allure.story("Financial profile scope")
    def test_financial_profile_does_not_detect_developer_secrets(self):
        text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        body = _sanitize(text, profile="financial")
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "AWS_ACCESS_KEY" not in found

    @allure.story("Developer profile scope")
    def test_developer_profile_does_not_detect_cicd(self):
        text = "sonar.login=squ_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        body = _sanitize(text, profile="developer")
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "SONARQUBE_TOKEN" not in found

    @allure.story("Full profile includes all")
    def test_full_profile_detects_all_domains(self):
        text = (
            "Card: 4532015112830366. "
            "Key: aws_access_key_id=AKIAIOSFODNN7EXAMPLE. "
            "DB: postgresql://admin:secret@db.internal:5432/prod. "
            "sonar.login=squ_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        body = _sanitize(text, profile="full")
        found = {e["entity_type"] for e in body["entities_found"]}
        assert "CREDIT_CARD" in found
        assert "AWS_ACCESS_KEY" in found
        assert "DB_CONNECTION_STRING" in found


# ═══════════════════════════════════════════════════════════════════════════════
# 8. ANONYMIZATION RULES
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Anonymization Rules")
class TestAnonymizationRules:
    """Different rules (replace/mask/redact) yield different output formats."""

    @allure.story("Replace rule")
    def test_replace_uses_placeholder(self):
        text = "Contact alice@example.com for help."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"], rules={"EMAIL_ADDRESS": "replace"})
        assert body["was_modified"] is True
        assert "<EMAIL_ADDRESS>" in body["sanitized_text"]
        assert "alice@example.com" not in body["sanitized_text"]

    @allure.story("Mask rule")
    def test_mask_uses_asterisks(self):
        text = "Contact alice@example.com for help."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"], rules={"EMAIL_ADDRESS": "mask"})
        assert body["was_modified"] is True
        assert "alice@example.com" not in body["sanitized_text"]
        assert "*" in body["sanitized_text"]

    @allure.story("Redact rule")
    def test_redact_removes_value(self):
        text = "Contact alice@example.com for help."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"], rules={"EMAIL_ADDRESS": "redact"})
        assert body["was_modified"] is True
        assert "alice@example.com" not in body["sanitized_text"]
        assert "<EMAIL_ADDRESS>" not in body["sanitized_text"]

    @allure.story("Hash rule")
    def test_hash_produces_hex_digest(self):
        text = "Contact alice@example.com for help."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"], rules={"EMAIL_ADDRESS": "hash"})
        assert body["was_modified"] is True
        assert "alice@example.com" not in body["sanitized_text"]
        # SHA-256 hash is 64 hex characters
        sanitized = body["sanitized_text"]
        # Hash should appear as a hex string in the output
        import re
        assert re.search(r"[0-9a-f]{20,}", sanitized)

    @allure.story("Default rule (no rule specified)")
    def test_default_rule_replaces(self):
        text = "Contact alice@example.com for help."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        assert body["was_modified"] is True
        assert "<EMAIL_ADDRESS>" in body["sanitized_text"]

    @allure.story("Mixed rules per entity")
    def test_different_rules_per_entity(self):
        text = "Email: alice@example.com, SSN: 323-45-6789."
        body = _sanitize(
            text,
            entities=["EMAIL_ADDRESS", "US_SSN"],
            rules={"EMAIL_ADDRESS": "mask", "US_SSN": "redact"},
        )
        assert body["was_modified"] is True
        assert "alice@example.com" not in body["sanitized_text"]
        assert "323-45-6789" not in body["sanitized_text"]


# ═══════════════════════════════════════════════════════════════════════════════
# 9. FORMAT VARIATIONS
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("Format Variations")
class TestFormatVariations:
    """Different formats of the same entity type should all be detected."""

    @allure.story("Credit card formats")
    @pytest.mark.parametrize("cc,desc", [
        ("4716108999716531", "Visa 16 digits no separators"),
        ("5425233430109903", "Mastercard 16 digits"),
        ("378282246310005", "Amex 15 digits"),
    ])
    def test_credit_card_formats(self, cc, desc):
        text = f"Card on file: {cc}."
        body = _sanitize(text, entities=["CREDIT_CARD"])
        found = [e for e in body["entities_found"] if e["entity_type"] == "CREDIT_CARD"]
        assert len(found) >= 1, f"Failed for {desc}: {cc}"

    @allure.story("Phone number formats")
    @pytest.mark.parametrize("phone,desc", [
        ("(415) 555-0192", "US parenthesized"),
        ("+1-800-555-0199", "US international"),
        ("+44 20 7946 0958", "UK international"),
    ])
    def test_phone_number_formats(self, phone, desc):
        text = f"Call support: {phone} for assistance."
        body = _sanitize(text, entities=["PHONE_NUMBER"])
        phones = [e for e in body["entities_found"] if e["entity_type"] == "PHONE_NUMBER"]
        assert len(phones) >= 1, f"Failed for {desc}: {phone}"

    @allure.story("SSN formats")
    @pytest.mark.parametrize("ssn", [
        "323-45-6789",
        "323 45 6789",
    ])
    def test_ssn_formats(self, ssn):
        text = f"Applicant SSN: {ssn}."
        body = _sanitize(text, entities=["US_SSN"])
        ssns = [e for e in body["entities_found"] if e["entity_type"] == "US_SSN"]
        assert len(ssns) >= 1, f"SSN not detected: {ssn}"

    @allure.story("Email formats")
    @pytest.mark.parametrize("email", [
        "alice@example.com",
        "alice.johnson@securecorp.com",
        "user+tag@example.org",
    ])
    def test_email_formats(self, email):
        text = f"Send to {email} immediately."
        body = _sanitize(text, entities=["EMAIL_ADDRESS"])
        emails = [e for e in body["entities_found"] if e["entity_type"] == "EMAIL_ADDRESS"]
        assert len(emails) >= 1, f"Email not detected: {email}"

    @allure.story("IP address formats")
    def test_ipv6_detection(self):
        text = "Server at 2001:0db8:85a3:0000:0000:8a2e:0370:7334 is unreachable."
        body = _sanitize(text, entities=["IP_ADDRESS"])
        ips = [e for e in body["entities_found"] if e["entity_type"] == "IP_ADDRESS"]
        assert len(ips) >= 1, "IPv6 not detected"

    @allure.story("URL formats")
    @pytest.mark.parametrize("url,desc", [
        ("https://admin.internal.corp/dashboard", "HTTPS"),
        ("http://internal.corp.com:8080/admin", "HTTP with hostname and port"),
    ])
    def test_url_formats(self, url, desc):
        text = f"Access console at {url} for config."
        body = _sanitize(text, entities=["URL"])
        urls = [e for e in body["entities_found"] if e["entity_type"] == "URL"]
        assert len(urls) >= 1, f"URL not detected ({desc}): {url}"

    @allure.story("IBAN formats")
    @pytest.mark.parametrize("iban,country", [
        ("GB29NWBK60161331926819", "UK"),
        ("DE89370400440532013000", "Germany"),
        ("FR7630006000011234567890189", "France"),
    ])
    def test_iban_formats(self, iban, country):
        text = f"Wire to IBAN {iban}."
        body = _sanitize(text, entities=["IBAN_CODE"])
        ibans = [e for e in body["entities_found"] if e["entity_type"] == "IBAN_CODE"]
        assert len(ibans) >= 1, f"IBAN not detected ({country}): {iban}"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. ANALYZE AND ANONYMIZE ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

@allure.feature("API Endpoints")
class TestEndpoints:
    """Verify /analyze and /anonymize endpoints work correctly."""

    @allure.story("/analyze returns findings only")
    def test_analyze_no_masking(self):
        text = "Contact alice@example.com for help."
        resp = _post(_ANALYZE, {"text": text, "language": "en", "entities": ["EMAIL_ADDRESS"]})
        assert resp.status_code == 200
        body = resp.json()
        assert any(e["entity_type"] == "EMAIL_ADDRESS" for e in body["entities_found"])
        # /analyze should not have sanitized_text field
        assert "sanitized_text" not in body

    @allure.story("/anonymize returns masked text")
    def test_anonymize_masks_text(self):
        text = "Contact alice@example.com for help."
        resp = _post(_ANONYMIZE, {"text": text, "language": "en", "entities": ["EMAIL_ADDRESS"]})
        assert resp.status_code == 200
        body = resp.json()
        assert "alice@example.com" not in body["anonymized_text"]
        assert any(e["entity_type"] == "EMAIL_ADDRESS" for e in body["entities_found"])

    @allure.story("/analyze empty text")
    def test_analyze_empty_text(self):
        resp = _post(_ANALYZE, {"text": "  ", "language": "en"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["entities_found"] == []

    @allure.story("/anonymize empty text")
    def test_anonymize_empty_text(self):
        resp = _post(_ANONYMIZE, {"text": "  ", "language": "en"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["anonymized_text"] == "  "
