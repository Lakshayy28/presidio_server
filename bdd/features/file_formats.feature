@file_formats
Feature: Multi-Format File Content Sanitization

  Realistic sample files in common DevOps and application formats are sent to
  the /sanitize endpoint.  Each file contains deliberately embedded PII or
  credentials; the sanitizer must detect and mask all of them.

  Background:
    Given the Presidio server is running

  @smoke
  Scenario: Sanitize a JSON config file with embedded credentials
    Given I have the file "sample_config.json"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  @smoke
  Scenario: Sanitize a .env file with secrets
    Given I have the file "sample.env"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  Scenario: Sanitize an nginx-style .conf file
    Given I have the file "sample.conf"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  Scenario: Sanitize a Kubernetes YAML file with secrets
    Given I have the file "sample.yaml"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  Scenario: Sanitize a Java .properties file
    Given I have the file "sample.properties"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  Scenario: Sanitize an XML configuration file
    Given I have the file "sample.xml"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  Scenario: Sanitize a CSV file with PII columns
    Given I have the file "sample.csv"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain at least 3 detected entities

  Scenario: Sanitize a Terraform .tfvars file
    Given I have the file "sample.tfvars"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities

  Scenario: Sanitize a Kubernetes Secret manifest
    Given I have the file "kubernetes_secret.yaml"
    When  I POST the file content to /sanitize using profile "full"
    Then  the response status should be 200
    And   was_modified should be true
    And   the response should contain entities
