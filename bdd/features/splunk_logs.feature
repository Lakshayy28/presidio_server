@splunk
Feature: Splunk Log PII Detection and Sanitization

  Splunk-format log lines (JSON event, CEF syslog, KV pairs) frequently contain
  PII: user names, IP addresses, SSNs embedded in query params, email addresses
  in audit trails, and credentials echoed in plaintext pipelines.

  The sanitizer must identify and mask all PII within these log lines without
  corrupting the surrounding log structure tokens (timestamps, field names, etc.).

  Background:
    Given the Presidio server is running

  @smoke
  Scenario: Sanitize a Splunk JSON event log with PII
    Given I have the file "splunk_access.log"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain at least 3 detected entities

  @smoke
  Scenario: Sanitize Splunk log line containing an email address
    Given I have a Splunk log line with "EMAIL_ADDRESS"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "EMAIL_ADDRESS" should be detected

  Scenario: Sanitize Splunk log line containing an IP address
    Given I have a Splunk log line with "IP_ADDRESS"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "IP_ADDRESS" should be detected

  Scenario: Sanitize Splunk log line containing a US SSN
    Given I have a Splunk log line with "US_SSN"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "US_SSN" should be detected

  Scenario: Sanitize Splunk log line containing a phone number
    Given I have a Splunk log line with "PHONE_NUMBER"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "PHONE_NUMBER" should be detected

  Scenario: Sanitize Splunk log line containing a credit card number
    Given I have a Splunk log line with "CREDIT_CARD"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "CREDIT_CARD" should be detected

  Scenario: Sanitize Splunk log line containing an AWS access key
    Given I have a Splunk log line with "AWS_ACCESS_KEY"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "AWS_ACCESS_KEY" should be detected

  Scenario: Splunk log with PERSON entity is anonymized
    Given I have a Splunk log line with "PERSON"
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
