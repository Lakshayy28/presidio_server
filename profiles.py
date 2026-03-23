"""
Sanitization profiles
─────────────────────
Each profile maps a named use-case to the list of entity types that should be
detected.  Pass the profile name in the ``profile`` field of an API request;
the server will resolve it to the corresponding entity list automatically.

Available profiles:
  financial       – Banking, capital-markets, and payments PII/data
  developer       – Source-code secrets (API keys, tokens, certs)
  infrastructure  – Database URLs, private IPs, env vars, K8s secrets
  cicd            – CI/CD pipeline secrets, OpenShift/K8s platform tokens
  full            – Union of all profiles + Presidio core entities
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# Base sets
# ─────────────────────────────────────────────────────────────────────────────

PRESIDIO_CORE_ENTITIES: list[str] = [
    "CREDIT_CARD",
    "CRYPTO",
    "DATE_TIME",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    "MEDICAL_LICENSE",
    "NRP",
    "PERSON",
    "PHONE_NUMBER",
    "URL",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "US_SSN",
]

FINANCIAL_ENTITIES: list[str] = [
    # Presidio built-ins relevant to finance
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_BANK_NUMBER",
    "US_SSN",
    "US_ITIN",
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    # Custom financial recognizers
    "CARD_CVV",
    "CARD_EXPIRY",
]

DEVELOPER_ENTITIES: list[str] = [
    # Presidio built-ins
    "EMAIL_ADDRESS",
    "URL",
    # Custom developer recognizers
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "BEARER_TOKEN",
    "CERTIFICATE_BLOCK",
    "GENERIC_API_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "HASHICORP_VAULT_TOKEN",
    "JWT_TOKEN",
    "NPM_TOKEN",
    "PRIVATE_KEY_BLOCK",
    "SENDGRID_KEY",
    "SLACK_TOKEN",
    "STRIPE_KEY",
]

INFRASTRUCTURE_ENTITIES: list[str] = [
    # Presidio built-ins
    "IP_ADDRESS",
    "URL",
    # Custom infrastructure recognizers
    "AZURE_CONN_STRING",
    "DB_CONNECTION_STRING",
    "ENV_VARIABLE_VALUE",
    "INTERNAL_HOSTNAME",
    "JDBC_URL",
    "MONGO_URL",
    "PRIVATE_IP_ADDRESS",
    "REDIS_URL",
]

CICD_ENTITIES: list[str] = [
    # CI/CD-specific
    "ANSIBLE_VAULT",
    "BITBUCKET_APP_PASSWORD",
    "DOCKER_REGISTRY_CREDENTIAL",
    "GCP_SA_KEY",
    "HELM_SECRET",
    "OPENSHIFT_TOKEN",
    "SONARQUBE_TOKEN",
    "TERRAFORM_TOKEN",
    # Developer secrets also relevant in pipelines
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "BEARER_TOKEN",
    "GENERIC_API_KEY",
    "JWT_TOKEN",
    "PRIVATE_KEY_BLOCK",
]

FULL_ENTITIES: list[str] = sorted(
    set(
        PRESIDIO_CORE_ENTITIES
        + FINANCIAL_ENTITIES
        + DEVELOPER_ENTITIES
        + INFRASTRUCTURE_ENTITIES
        + CICD_ENTITIES
    )
)

# ─────────────────────────────────────────────────────────────────────────────
# Profile registry
# ─────────────────────────────────────────────────────────────────────────────

PROFILES: dict[str, list[str]] = {
    "financial":      FINANCIAL_ENTITIES,
    "developer":      DEVELOPER_ENTITIES,
    "infrastructure": INFRASTRUCTURE_ENTITIES,
    "cicd":           CICD_ENTITIES,
    "full":           FULL_ENTITIES,
}

PROFILE_DESCRIPTIONS: dict[str, str] = {
    "financial":      "Banking and payments identifiers (CVV, card expiry) plus Presidio built-ins (credit card, IBAN, SSN)",
    "developer":      "Source-code secrets — API keys, OAuth tokens, private keys, and service credentials",
    "infrastructure": "Infrastructure secrets — DB/cache URLs, private IPs, env var values",
    "cicd":           "CI/CD & platform tokens — OpenShift, SonarQube, Terraform, Ansible, GCP SA, Bitbucket, Helm, Docker",
    "full":           "All profiles combined plus Presidio core entities",
}


# ─────────────────────────────────────────────────────────────────────────────
# Resolution helper
# ─────────────────────────────────────────────────────────────────────────────

def get_entities_for_profile(
    profile: str | None,
    custom_entities: list[str] | None = None,
) -> list[str]:
    """Return the entity list for a request.

    Priority:
      1. ``custom_entities`` — explicit override always wins.
      2. ``profile`` — look up the named profile.
      3. Fall back to ``PRESIDIO_CORE_ENTITIES`` (backwards-compatible default).
    """
    if custom_entities:
        return custom_entities
    if profile:
        resolved = PROFILES.get(profile.lower())
        if resolved:
            return resolved
    return PRESIDIO_CORE_ENTITIES
