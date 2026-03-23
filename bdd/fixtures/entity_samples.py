"""
Mock text samples for every entity type recognised by the SafeChat Presidio
server.  Each entry is a dict with:

  text            – realistic sentence/snippet that reliably triggers the recognizer
  entities        – list of expected entity types (may be >1 for mixed text)
  rules           – per-entity anonymisation override  (passed as payload `rules`)
  expected_masked – True if the sanitize endpoint should return was_modified=True
  profile         – optional Presidio profile name that enables this entity
                    (None  → use default entity set;
                     "financial"|"developer"|"infrastructure"|"cicd"|"full")

Samples are grouped by:
  PRESIDIO_BUILTIN_SAMPLES  – standard Presidio entities
  FINANCIAL_SAMPLES         – custom financial recognisers (2: CARD_CVV, CARD_EXPIRY)
  DEVELOPER_SAMPLES         – custom developer-secret recognisers (14)
  INFRASTRUCTURE_SAMPLES    – custom infrastructure recognisers (8)
  CICD_SAMPLES              – custom CI/CD recognisers (8)

ENTITY_SAMPLES is the merged dict imported by conftest and step definitions.
"""

# ---------------------------------------------------------------------------
# Presidio built-in entities
# ---------------------------------------------------------------------------
PRESIDIO_BUILTIN_SAMPLES: dict = {
    "PERSON": {
        "text": "The account holder John Smith called to dispute charge ref #TX-20240315.",
        "entities": ["PERSON"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "EMAIL_ADDRESS": {
        "text": "Please forward the SOX audit report to alice.johnson@securecorp.com by Friday.",
        "entities": ["EMAIL_ADDRESS"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "PHONE_NUMBER": {
        "text": "Customer support line: (415) 555-0192. After-hours: +1-800-555-0199.",
        "entities": ["PHONE_NUMBER"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "CREDIT_CARD": {
        "text": "Card on file: 4532015112830366 (Visa) expiring 12/28.",
        "entities": ["CREDIT_CARD"],
        "rules": {"CREDIT_CARD": "mask"},
        "expected_masked": True,
        "profile": None,
    },
    "CRYPTO": {
        "text": "Refund sent to BTC wallet 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.",
        "entities": ["CRYPTO"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "IP_ADDRESS": {
        "text": "Request originated from 203.0.113.42 at 14:23 UTC.",
        "entities": ["IP_ADDRESS"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "IBAN_CODE": {
        "text": "Please wire payment to IBAN GB29NWBK60161331926819.",
        "entities": ["IBAN_CODE"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "US_SSN": {
        "text": "Applicant SSN: 323-45-6789. Please verify identity before proceeding.",
        "entities": ["US_SSN"],
        "rules": {"US_SSN": "redact"},
        "expected_masked": True,
        "profile": None,
    },
    "US_BANK_NUMBER": {
        "text": "Direct deposit to checking account number 3530111333300000.",
        "entities": ["US_BANK_NUMBER"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "US_PASSPORT": {
        "text": "Primary ID verified: US Passport A12345678 issued New York.",
        "entities": ["US_PASSPORT"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "US_ITIN": {
        "text": "ITIN for non-resident filing: 900-70-0001.",
        "entities": ["US_ITIN"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "MEDICAL_LICENSE": {
        "text": "DEA certificate for Dr. Adams: BJ1234563, authorized prescriber.",
        "entities": ["MEDICAL_LICENSE"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
    "URL": {
        "text": "Admin console available at https://admin.internal.corp/dashboard.",
        "entities": ["URL"],
        "rules": {},
        "expected_masked": True,
        "profile": None,
    },
}

# ---------------------------------------------------------------------------
# Financial custom recognisers (2 types — niche identifiers removed; use custom_recognizers)
# ---------------------------------------------------------------------------
FINANCIAL_SAMPLES: dict = {
    "CARD_CVV": {
        "text": "Card verification CVV2: 857 — do not store or log.",
        "entities": ["CARD_CVV"],
        "rules": {"CARD_CVV": "redact"},
        "expected_masked": True,
        "profile": "financial",
    },
    "CARD_EXPIRY": {
        "text": "Card expiry date 09/28. Reissue required before valid_thru.",
        "entities": ["CARD_EXPIRY"],
        "rules": {"CARD_EXPIRY": "mask"},
        "expected_masked": True,
        "profile": "financial",
    },
}
# ---------------------------------------------------------------------------
# Developer secret recognisers (14 types)
# ---------------------------------------------------------------------------
DEVELOPER_SAMPLES: dict = {
    "AWS_ACCESS_KEY": {
        "text": "aws_access_key_id: AKIAIOSFODNN7EXAMPLE",
        "entities": ["AWS_ACCESS_KEY"],
        "rules": {"AWS_ACCESS_KEY": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "AWS_SECRET_KEY": {
        "text": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "entities": ["AWS_SECRET_KEY"],
        "rules": {"AWS_SECRET_KEY": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "GITHUB_TOKEN": {
        "text": "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234",
        "entities": ["GITHUB_TOKEN"],
        "rules": {"GITHUB_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "GITLAB_TOKEN": {
        "text": "CI_JOB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRSt",
        "entities": ["GITLAB_TOKEN"],
        "rules": {"GITLAB_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "SLACK_TOKEN": {
        "text": "Slack bot token: xoxb-1234567890-1234567890-ABCDEFGHIJabcdefghij",
        "entities": ["SLACK_TOKEN"],
        "rules": {"SLACK_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "JWT_TOKEN": {
        "text": (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
        "entities": ["JWT_TOKEN"],
        "rules": {"JWT_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "STRIPE_KEY": {
        "text": "STRIPE_SECRET_KEY=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXabcdefgh",
        "entities": ["STRIPE_KEY"],
        "rules": {"STRIPE_KEY": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "SENDGRID_KEY": {
        "text": "SENDGRID_API_KEY=SG.ABCDEFGHIJklmnopqrstUV.ABCDEFGHIJ0123456789abcdefghij0123456789ABC",
        "entities": ["SENDGRID_KEY"],
        "rules": {"SENDGRID_KEY": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "NPM_TOKEN": {
        "text": "NODE_AUTH_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        "entities": ["NPM_TOKEN"],
        "rules": {"NPM_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "HASHICORP_VAULT_TOKEN": {
        "text": "VAULT_TOKEN=hvs.CAESIABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
        "entities": ["HASHICORP_VAULT_TOKEN"],
        "rules": {"HASHICORP_VAULT_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "GENERIC_API_KEY": {
        "text": "api_key = sk-prod-1234567890abcdefghijklmnopqrstuvwxyz",
        "entities": ["GENERIC_API_KEY"],
        "rules": {"GENERIC_API_KEY": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "BEARER_TOKEN": {
        "text": "Authorization: Bearer abc123def456ghi789jkl012mno345pqr678stuvwxyz0000",
        "entities": ["BEARER_TOKEN"],
        "rules": {"BEARER_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "developer",
    },
    "PRIVATE_KEY_BLOCK": {
        "text": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJNe0p7t\n"
            "-----END RSA PRIVATE KEY-----"
        ),
        "entities": ["PRIVATE_KEY_BLOCK"],
        "rules": {"PRIVATE_KEY_BLOCK": "redact"},
        "expected_masked": True,
        "profile": "developer",
    },
    "CERTIFICATE_BLOCK": {
        "text": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n"
            "-----END CERTIFICATE-----"
        ),
        "entities": ["CERTIFICATE_BLOCK"],
        "rules": {"CERTIFICATE_BLOCK": "replace"},
        "expected_masked": True,
        "profile": "developer",
    },
}

# ---------------------------------------------------------------------------
# Infrastructure recognisers (8 types)
# ---------------------------------------------------------------------------
INFRASTRUCTURE_SAMPLES: dict = {
    "DB_CONNECTION_STRING": {
        "text": "spring.datasource.url=postgres://admin:Passw0rd!@prod-db.corp.internal:5432/payments",
        "entities": ["DB_CONNECTION_STRING"],
        "rules": {"DB_CONNECTION_STRING": "mask"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "AZURE_CONN_STRING": {
        "text": (
            "DefaultEndpointsProtocol=https;AccountName=mystorageacct;"
            "AccountKey=abc123base64encodedkeyABCDEFGHIJKLMNabcde==;"
            "EndpointSuffix=core.windows.net"
        ),
        "entities": ["AZURE_CONN_STRING"],
        "rules": {"AZURE_CONN_STRING": "mask"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "JDBC_URL": {
        "text": "datasource.url=jdbc:postgresql://prod-rds.internal:5432/payments?user=dbadmin&password=secret123",
        "entities": ["JDBC_URL"],
        "rules": {"JDBC_URL": "mask"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "REDIS_URL": {
        "text": "REDIS_URL=redis://:r3d1sPassw0rd@cache.prod.internal:6379/0",
        "entities": ["REDIS_URL"],
        "rules": {"REDIS_URL": "mask"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "MONGO_URL": {
        "text": "MONGODB_URI=mongodb+srv://admin:mongoSecret@cluster0.abc123.mongodb.net/prod",
        "entities": ["MONGO_URL"],
        "rules": {"MONGO_URL": "mask"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "INTERNAL_HOSTNAME": {
        "text": "DB_HOST=payments-db-primary.prod.internal",
        "entities": ["INTERNAL_HOSTNAME"],
        "rules": {"INTERNAL_HOSTNAME": "replace"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "PRIVATE_IP_ADDRESS": {
        "text": "Service mesh endpoint: 10.240.0.15:8443 (internal TLS).",
        "entities": ["PRIVATE_IP_ADDRESS"],
        "rules": {"PRIVATE_IP_ADDRESS": "replace"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
    "ENV_VARIABLE_VALUE": {
        "text": "DATABASE_PASSWORD=Sup3rS3cr3t_P@ssw0rd_2024\nDB_USER=prod_admin",
        "entities": ["ENV_VARIABLE_VALUE"],
        "rules": {"ENV_VARIABLE_VALUE": "mask"},
        "expected_masked": True,
        "profile": "infrastructure",
    },
}

# ---------------------------------------------------------------------------
# CI/CD recognisers (8 types)
# ---------------------------------------------------------------------------
CICD_SAMPLES: dict = {
    "SONARQUBE_TOKEN": {
        "text": "SONAR_TOKEN=sqp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
        "entities": ["SONARQUBE_TOKEN"],
        "rules": {"SONARQUBE_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "OPENSHIFT_TOKEN": {
        "text": "OCP_TOKEN=sha256~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
        "entities": ["OPENSHIFT_TOKEN"],
        "rules": {"OPENSHIFT_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "DOCKER_REGISTRY_CREDENTIAL": {
        "text": '{"auths":{"registry.corp.internal:5000":{"auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}}',
        "entities": ["DOCKER_REGISTRY_CREDENTIAL"],
        "rules": {"DOCKER_REGISTRY_CREDENTIAL": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "HELM_SECRET": {
        "text": (
            "db_password: ENC[AES256_GCM,data:abc123XYZ,iv:AB12CD34EF56GH78IJ90KL==,tag:MNOPQRST==]"
        ),
        "entities": ["HELM_SECRET"],
        "rules": {"HELM_SECRET": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "TERRAFORM_TOKEN": {
        "text": (
            'credentials "app.terraform.io" { '
            "token = ABCDEFGHIJklmn.atlasv1."
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDE"
            " }"
        ),
        "entities": ["TERRAFORM_TOKEN"],
        "rules": {"TERRAFORM_TOKEN": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "ANSIBLE_VAULT": {
        "text": (
            "$ANSIBLE_VAULT;1.1;AES256\n"
            "35363466623663363531653564316438333766393863343661326337663633\n"
            "37626665373736386531303935653332393234356263306434316566373866"
        ),
        "entities": ["ANSIBLE_VAULT"],
        "rules": {"ANSIBLE_VAULT": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "GCP_SA_KEY": {
        "text": (
            '{"type":"service_account","project_id":"my-gcp-project",'
            '"private_key_id":"abc123","client_email":"sa@my-gcp-project.iam.gserviceaccount.com",'
            '"client_id":"123456789012345678901"}'
        ),
        "entities": ["GCP_SA_KEY"],
        "rules": {"GCP_SA_KEY": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
    "BITBUCKET_APP_PASSWORD": {
        "text": "BITBUCKET_APP_PASSWORD=ATBBabcdefghijklmnopqrstuvwx1234",
        "entities": ["BITBUCKET_APP_PASSWORD"],
        "rules": {"BITBUCKET_APP_PASSWORD": "mask"},
        "expected_masked": True,
        "profile": "cicd",
    },
}

# ---------------------------------------------------------------------------
# Merged lookup used by conftest / step definitions
# ---------------------------------------------------------------------------
ENTITY_SAMPLES: dict = {
    **PRESIDIO_BUILTIN_SAMPLES,
    **FINANCIAL_SAMPLES,
    **DEVELOPER_SAMPLES,
    **INFRASTRUCTURE_SAMPLES,
    **CICD_SAMPLES,
}

# Convenience groupings used by feature files / reports
FINANCIAL_ENTITIES   = list(FINANCIAL_SAMPLES.keys())
DEVELOPER_ENTITIES   = list(DEVELOPER_SAMPLES.keys())
INFRASTRUCTURE_ENTITIES = list(INFRASTRUCTURE_SAMPLES.keys())
CICD_ENTITIES        = list(CICD_SAMPLES.keys())
BUILTIN_ENTITIES     = list(PRESIDIO_BUILTIN_SAMPLES.keys())
ALL_ENTITIES         = list(ENTITY_SAMPLES.keys())
