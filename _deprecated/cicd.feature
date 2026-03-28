@cicd
Feature: CI/CD Pipeline Token Detection and Sanitization

  The SafeChat Presidio server must detect all 8 CI/CD entity types including
  platform tokens, encrypted secrets, cloud service-account keys, and
  container registry credentials.

  Background:
    Given the Presidio server is running

  @smoke
  Scenario Outline: Detect and mask critical CI/CD secret <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type                  |
      | SONARQUBE_TOKEN              |
      | OPENSHIFT_TOKEN              |
      | GCP_SA_KEY                   |
      | ANSIBLE_VAULT                |

  Scenario Outline: Detect and mask additional CI/CD entity <entity_type>
    Given I have a document with "<entity_type>" data
    When  I POST the text to /sanitize
    Then  the response status should be 200
    And   was_modified should be true
    And   the entity "<entity_type>" should be detected

    Examples:
      | entity_type                  |
      | DOCKER_REGISTRY_CREDENTIAL   |
      | HELM_SECRET                  |
      | TERRAFORM_TOKEN              |
      | BITBUCKET_APP_PASSWORD       |

  Scenario: GCP service account email is removed from sanitized output
    Given I have a document with "GCP_SA_KEY" data
    When  I POST the text to /sanitize
    Then  was_modified should be true
    And   the sanitized text should not contain the original value
