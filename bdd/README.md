# SafeChat Presidio – BDD Regression Test Suite

A comprehensive pytest-bdd + Allure regression suite covering every entity
type detected by the SafeChat Presidio server.

---

## Directory Layout

```
bdd/
├── features/               Gherkin (.feature) files – one per category
├── steps/                  Step definitions (shared across all features)
├── tests/                  pytest entry-points (import scenarios from features)
├── fixtures/
│   ├── entity_samples.py   Mock text → entity-type mapping
│   └── file_samples/       Realistic sample files (.json, .env, .conf, …)
├── conftest.py             Shared pytest fixtures
├── pytest.ini              pytest configuration
├── requirements.txt        Test-only dependencies
├── generate_postman.py     Appends BDD payloads to Postman collection
└── reports/                Allure results + HTML report (git-ignored)
```

---

## Quick Start

```bash
# 1. Activate the server's venv
source presidio_server/.venv/bin/activate

# 2. Install test dependencies
pip install -r presidio_server/bdd/requirements.txt

# 3. Start the Presidio server (different terminal)
PYTHONPATH=. .venv/bin/uvicorn presidio_server.main:app \
    --host 0.0.0.0 --port 8000

# 4. Run all tests from the bdd/ directory
cd presidio_server/bdd
pytest

# -- OR run a specific category --
pytest -m financial
pytest -m developer
pytest -m cicd
pytest -m splunk

# -- Smoke run (fast subset) --
pytest -m smoke
```

---

## Allure Report

```bash
# After running tests
allure serve reports/allure-results
# or to generate a static site
allure generate reports/allure-results -o reports/allure-report --clean
```

The `--html` flag also generates `reports/test_report.html` automatically.

---

## Update Postman Collection

```bash
python generate_postman.py
# Writes a BDD Regression Suite folder into:
#   presidio_server/SafeChat-Presidio.postman_collection.json
```

---

## Environment Variables

| Variable        | Default                   | Purpose                              |
|-----------------|---------------------------|--------------------------------------|
| `PRESIDIO_URL`  | `http://localhost:8000`   | Base URL of the running server       |
| `BDD_TIMEOUT`   | `10`                      | HTTP request timeout in seconds      |

---

## Coverage

| Category         | Entities |
|------------------|----------|
| Presidio (built-in) | PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, CRYPTO, IP_ADDRESS, IBAN_CODE, US_SSN, US_BANK_NUMBER, US_PASSPORT, US_ITIN, MEDICAL_LICENSE, URL |
| Financial        | SWIFT_BIC_CODE, US_ROUTING_NUMBER, UK_SORT_CODE, BSB_CODE, CARD_CVV, CARD_EXPIRY, ISIN_CODE, CUSIP, SEDOL, TAX_EIN, VAT_NUMBER, PAYMENT_REFERENCE, LOAN_ACCOUNT, CREDIT_SCORE, CREDIT_BUREAU_FILE, NMLS_ID, ACH_TRACE_NUMBER, LEI_CODE, MERS_MIN, FEDWIRE_IMAD, BANKRUPTCY_CASE, UCC_FILING_NUMBER, FICO_REASON_CODE |
| Developer        | AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, GITLAB_TOKEN, SLACK_TOKEN, JWT_TOKEN, STRIPE_KEY, SENDGRID_KEY, TWILIO_SID, NPM_TOKEN, HASHICORP_VAULT_TOKEN, GENERIC_API_KEY, BEARER_TOKEN, PRIVATE_KEY_BLOCK, CERTIFICATE_BLOCK |
| Infrastructure   | DB_CONNECTION_STRING, AZURE_CONN_STRING, JDBC_URL, REDIS_URL, MONGO_URL, INTERNAL_HOSTNAME, PRIVATE_IP_ADDRESS, MAC_ADDRESS, ENV_VARIABLE_VALUE, K8S_SECRET_VALUE, CERTIFICATE_THUMBPRINT |
| CI/CD            | JENKINS_TOKEN, CIRCLECI_TOKEN, GITLAB_CI_TOKEN, SONARQUBE_TOKEN, OPENSHIFT_TOKEN, K8S_SA_TOKEN, DOCKER_REGISTRY_CREDENTIAL, HELM_SECRET, TERRAFORM_TOKEN, ANSIBLE_VAULT, GCP_SA_KEY, AZURE_SP_SECRET, BITBUCKET_APP_PASSWORD, ARGOCD_TOKEN |
| Custom           | User-supplied regex via `custom_recognizers` field |
| File Formats     | .json, .env, .conf, .yaml, .properties, .xml, .csv, .tfvars, k8s secret |
| Splunk Logs      | Splunk JSON / CEF log lines containing PII |
