@financial
Feature: Financial PII Detection and Sanitization

  The SafeChat Presidio server must detect financial entity types including
  Presidio built-in payment entities and the custom CARD_CVV and CARD_EXPIRY
  recognizers.  Niche identifiers (ISIN, CUSIP, SWIFT BIC, etc.) can be
  added via custom_recognizers in safechat-rules.yaml.

  Background:
    Given the Presidio server is running

  # ── Presidio built-in payment entities ─────────────────────────────────────

  @smoke
  Scenario Outline: Detect and mask <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type  |
      | CREDIT_CARD  |
      | IBAN_CODE    |
      | US_SSN       |

  # ── Custom financial recognisers ────────────────────────────────────────────

  Scenario Outline: Detect and mask custom financial entity <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type       |
      | CARD_CVV          |
      | CARD_EXPIRY       |

  # ── Analyze-only (no masking) ───────────────────────────────────────────────

  Scenario: Analyze text returns valid JSON with entities_found
    Given I have a document with "CREDIT_CARD" data
    When  I POST the text to /analyze
    Then  the response status should be 200
    And   the entity "CREDIT_CARD" should be detected
