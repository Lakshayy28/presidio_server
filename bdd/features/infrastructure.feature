@infrastructure
Feature: Infrastructure Credential Detection and Sanitization

  The SafeChat Presidio server must detect all 8 infrastructure entity types
  that appear in environment files, container manifests, and IaC configs.

  Background:
    Given the Presidio server is running

  @smoke
  Scenario Outline: Detect and mask critical infrastructure entity <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type            |
      | DB_CONNECTION_STRING   |
      | AZURE_CONN_STRING      |
      | REDIS_URL              |
      | MONGO_URL              |
      | ENV_VARIABLE_VALUE     |

  Scenario Outline: Detect and mask infrastructure entity <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type              |
      | JDBC_URL                 |
      | INTERNAL_HOSTNAME        |
      | PRIVATE_IP_ADDRESS       |

  Scenario: Database connection string value is removed from sanitized output
    Given I have a document with "DB_CONNECTION_STRING" data
    When  I POST the text to /sanitize
    Then  was_modified should be true
    And   the sanitized text should not contain the original value
