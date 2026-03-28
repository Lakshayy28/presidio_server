@developer
Feature: Developer Secret Detection and Sanitization

  The SafeChat Presidio server must detect all 14 developer-secret entity types
  that appear in source code, config files, and environment variable exports.

  Background:
    Given the Presidio server is running

  @smoke
  Scenario Outline: Detect and mask critical developer secret <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type           |
      | AWS_ACCESS_KEY        |
      | AWS_SECRET_KEY        |
      | GITHUB_TOKEN          |
      | JWT_TOKEN             |
      | PRIVATE_KEY_BLOCK     |

  Scenario Outline: Detect and mask additional developer secret <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type           |
      | GITLAB_TOKEN          |
      | SLACK_TOKEN           |
      | STRIPE_KEY            |
      | SENDGRID_KEY          |
      | NPM_TOKEN             |
      | HASHICORP_VAULT_TOKEN |
      | GENERIC_API_KEY       |
      | BEARER_TOKEN          |
      | CERTIFICATE_BLOCK     |

  Scenario: Sanitized output removes the AWS access key value
    Given I have a document with "AWS_ACCESS_KEY" data
    When  I POST the text to /sanitize
    Then  was_modified should be true
    And   the sanitized text should not contain the original value
