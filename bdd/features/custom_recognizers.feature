@custom
Feature: User-Defined Custom Recognizer Tests

  The /sanitize and /analyze endpoints accept a `custom_recognizers` list.
  Each entry defines a temporary regex recognizer for that request only.
  These tests verify the dynamic recognizer mechanism end-to-end.

  Background:
    Given the Presidio server is running

  @smoke
  Scenario: Custom employee-ID recognizer detects badge numbers
    Given I have a document with "CUSTOM_EMPLOYEE_ID" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "EMPLOYEE_ID" should be detected

  Scenario: Custom SSN-style pattern applied to a regional format
    Given I have a document with "CUSTOM_REGION_CODE" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true

  Scenario: Custom recognizer with context words boosts detection score
    Given I have a document with "CUSTOM_PROJECT_CODE" data
    When  I POST the text to /analyze
    Then  the response status should be 200
    And   the entity "PROJECT_CODE" should be detected

  Scenario: Multiple custom recognizers applied in one request
    Given I have a document with "CUSTOM_MULTI" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain at least 2 detected entities
