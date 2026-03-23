#!/usr/bin/env python3
"""
generate_postman.py
───────────────────
Reads the existing SafeChat-Presidio.postman_collection.json and appends a
new "BDD Regression Suite" folder containing one Postman request item for
every BDD test case in this suite.

The folder tree added:
  BDD Regression Suite/
  ├── Financial PII/         (23 entity types)
  ├── Developer Secrets/     (15 entity types)
  ├── Infrastructure/        (11 entity types)
  ├── CI/CD Tokens/          (14 entity types)
  ├── Custom Recognizers/    (employee ID, region code, project code, multi)
  ├── File Format Tests/     (10 file format payloads)
  └── Splunk Log Tests/      (9 Splunk log line cases)

Usage:
    cd presidio_server/bdd
    python generate_postman.py

The script is idempotent — it removes any existing "BDD Regression Suite"
folder before adding the freshly generated one.
"""

import json
import pathlib
import sys
import textwrap
import uuid

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BDD_ROOT    = pathlib.Path(__file__).parent
_SERVER_ROOT = _BDD_ROOT.parent
_COLLECTION  = _SERVER_ROOT / "SafeChat-Presidio.postman_collection.json"
_FILE_SAMPLES = _BDD_ROOT / "fixtures" / "file_samples"

sys.path.insert(0, str(_BDD_ROOT))
from fixtures.entity_samples import (  # noqa: E402
    PRESIDIO_BUILTIN_SAMPLES,
    FINANCIAL_SAMPLES,
    DEVELOPER_SAMPLES,
    INFRASTRUCTURE_SAMPLES,
    CICD_SAMPLES,
)

BASE_URL_VAR = "{{baseUrl}}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _new_id() -> str:
    return str(uuid.uuid4())


def _postman_test_script(*pm_tests: str) -> list[dict]:
    """Wrap pm.test() lines into a Postman test event."""
    lines = [
        "pm.test('Status 200', () => pm.response.to.have.status(200));",
        "pm.test('has entities_found', () => {",
        "    const body = pm.response.json();",
        "    pm.expect(body).to.have.property('entities_found');",
        "});",
    ]
    lines.extend(pm_tests)
    return [
        {
            "listen": "test",
            "script": {"exec": lines, "type": "text/javascript"},
        }
    ]


def _sanitize_item(name: str, payload: dict, extra_tests: list[str] | None = None) -> dict:
    """Build a POST /sanitize Postman item."""
    tests = _postman_test_script(*(extra_tests or []))
    return {
        "id":   _new_id(),
        "name": name,
        "event": tests,
        "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
                "mode": "raw",
                "raw": json.dumps(payload, indent=2),
                "options": {"raw": {"language": "json"}},
            },
            "url": {
                "raw":      f"{BASE_URL_VAR}/sanitize",
                "host":     [BASE_URL_VAR],
                "path":     ["sanitize"],
            },
        },
    }


def _analyze_item(name: str, payload: dict) -> dict:
    """Build a POST /analyze Postman item."""
    tests = _postman_test_script()
    return {
        "id":   _new_id(),
        "name": name,
        "event": tests,
        "request": {
            "method": "POST",
            "header": [{"key": "Content-Type", "value": "application/json"}],
            "body": {
                "mode": "raw",
                "raw": json.dumps(payload, indent=2),
                "options": {"raw": {"language": "json"}},
            },
            "url": {
                "raw":  f"{BASE_URL_VAR}/analyze",
                "host": [BASE_URL_VAR],
                "path": ["analyze"],
            },
        },
    }


def _folder(name: str, items: list[dict]) -> dict:
    return {"id": _new_id(), "name": name, "item": items}


# ---------------------------------------------------------------------------
# Build sub-folders
# ---------------------------------------------------------------------------
def _entity_folder(folder_name: str, samples: dict, profile: str | None = None) -> dict:
    """One sanitize item per entity type."""
    items = []
    for entity_type, sample in samples.items():
        payload: dict = {
            "text":     sample["text"],
            "language": "en",
        }
        if sample.get("rules"):
            payload["rules"] = sample["rules"]
        if sample.get("profile") or profile:
            payload["profile"] = sample.get("profile") or profile
        extra = [
            f"pm.test('{entity_type} detected', () => {{",
            "    const body = pm.response.json();",
            "    const types = body.entities_found.map(e => e.entity_type);",
            f"    pm.expect(types).to.include('{entity_type}');",
            "});",
            "pm.test('was_modified is true', () => {",
            "    pm.expect(pm.response.json().was_modified).to.be.true;",
            "});",
        ]
        items.append(_sanitize_item(f"Sanitize {entity_type}", payload, extra))
    return _folder(folder_name, items)


def _custom_recognizers_folder() -> dict:
    cases = [
        {
            "name": "Custom EMPLOYEE_ID recognizer",
            "payload": {
                "text": "Employee badge: EMP-00042781 has been flagged for review.",
                "language": "en",
                "rules": {"EMPLOYEE_ID": "mask"},
                "custom_recognizers": [
                    {"name": "EMPLOYEE_ID", "pattern": r"EMP-\d{8}", "score": 0.90,
                     "context": ["badge", "employee", "emp"]},
                ],
            },
            "entity": "EMPLOYEE_ID",
        },
        {
            "name": "Custom REGION_CODE recognizer",
            "payload": {
                "text": "Region code: APAC-SGP-007 assigned to cluster.",
                "language": "en",
                "rules": {"REGION_CODE": "replace"},
                "custom_recognizers": [
                    {"name": "REGION_CODE", "pattern": r"[A-Z]{3,4}-[A-Z]{3}-\d{3}", "score": 0.85},
                ],
            },
            "entity": "REGION_CODE",
        },
        {
            "name": "Custom PROJECT_CODE with context",
            "payload": {
                "text": "Project code PRJ-2024-ALPHA assigned to sprint 5.",
                "language": "en",
                "custom_recognizers": [
                    {"name": "PROJECT_CODE", "pattern": r"PRJ-\d{4}-[A-Z]+", "score": 0.85,
                     "context": ["project", "PRJ", "code"]},
                ],
            },
            "entity": "PROJECT_CODE",
        },
        {
            "name": "Multiple custom recognizers in one request",
            "payload": {
                "text": "Employee badge: EMP-00042781. Project code PRJ-2024-BETA flagged.",
                "language": "en",
                "custom_recognizers": [
                    {"name": "EMPLOYEE_ID",  "pattern": r"EMP-\d{8}",      "score": 0.90},
                    {"name": "PROJECT_CODE", "pattern": r"PRJ-\d{4}-[A-Z]+", "score": 0.85},
                ],
            },
            "entity": "EMPLOYEE_ID",
        },
    ]
    items = []
    for case in cases:
        extra = [
            f"pm.test('{case['entity']} detected', () => {{",
            "    const body = pm.response.json();",
            "    const types = body.entities_found.map(e => e.entity_type);",
            f"    pm.expect(types).to.include('{case['entity']}');",
            "});",
        ]
        items.append(_sanitize_item(case["name"], case["payload"], extra))
    return _folder("Custom Recognizers", items)


def _file_formats_folder() -> dict:
    sample_files = [
        ("sample_config.json", "Full JSON config with credentials"),
        ("sample.env",         ".env file with secrets"),
        ("sample.conf",        "nginx .conf file"),
        ("sample.yaml",        "Kubernetes Helm YAML"),
        ("sample.properties",  "Spring Boot .properties"),
        ("sample.xml",         "web.config XML"),
        ("sample.csv",         "Customer CSV with PII columns"),
        ("sample.tfvars",      "Terraform .tfvars"),
        ("kubernetes_secret.yaml", "Kubernetes Secret manifest"),
        ("splunk_access.log",  "Splunk access log"),
    ]
    items = []
    for filename, description in sample_files:
        file_path = _FILE_SAMPLES / filename
        if not file_path.exists():
            print(f"  Warning: {file_path} not found, skipping.")
            continue
        content = file_path.read_text(encoding="utf-8")
        # Truncate very long files for Postman readability (keep first 4 KB)
        if len(content) > 4096:
            content = content[:4096] + "\n... [truncated for Postman display]"
        payload = {"text": content, "language": "en", "profile": "full"}
        extra = [
            "pm.test('was_modified is true', () => {",
            "    pm.expect(pm.response.json().was_modified).to.be.true;",
            "});",
            "pm.test('entities detected', () => {",
            "    pm.expect(pm.response.json().entities_found.length).to.be.above(0);",
            "});",
        ]
        items.append(_sanitize_item(f"{description} ({filename})", payload, extra))
    return _folder("File Format Tests", items)


def _splunk_folder() -> dict:
    cases = [
        {
            "name": "Splunk JSON — email in user field",
            "text": (
                '{"time":"2024-03-15T09:42:01Z","host":"app01.prod.internal",'
                '"event":{"action":"login","user":"john.smith@corp.com","src_ip":"203.0.113.42"}}'
            ),
            "entity": "EMAIL_ADDRESS",
        },
        {
            "name": "Splunk CEF — SSN in DLP alert",
            "text": (
                "Mar 15 09:42:00 siem CEF:0|Symantec|DLP|14.0|100|Data Leak|5|"
                "src=10.240.0.15 dst=203.0.113.42 suser=alice@example.com msg=SSN 078-05-1120 found"
            ),
            "entity": "EMAIL_ADDRESS",
        },
        {
            "name": "Splunk KV — credit card in query param",
            "text": (
                'index=web_access method=POST uri="/api/checkout?card=4532015112830366&cvv=857" '
                "status=200 bytes=1024"
            ),
            "entity": "CREDIT_CARD",
        },
        {
            "name": "Splunk JSON — AWS access key in env dump",
            "text": (
                '{"time":"2024-03-15T10:00:00Z","source":"lambda","level":"DEBUG",'
                '"message":"env: aws_access_key_id=AKIAIOSFODNN7EXAMPLE region=us-east-1"}'
            ),
            "entity": "AWS_ACCESS_KEY",
        },
        {
            "name": "Splunk audit — SSN in SQL query",
            "text": (
                '{"time":"2024-03-15T11:15:00Z","audit_action":"search",'
                '"query":"SELECT * FROM customers WHERE ssn = \'078-05-1120\'","user":"dba_user"}'
            ),
            "entity": "US_SSN",
        },
        {
            "name": "Splunk pipeline — JWT token echoed",
            "text": (
                "2024-03-15 12:00:00 INFO pipeline[runner] env dump: "
                "CI_JOB_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fw"
            ),
            "entity": "JWT_TOKEN",
        },
        {
            "name": "Splunk CRM — phone number in ticket",
            "text": (
                '{"time":"2024-03-15T13:30:00Z","source":"crm","event":'
                '{"ticket_id":"TKT-9901","customer_phone":"(415) 555-0192","priority":"P1"}}'
            ),
            "entity": "PHONE_NUMBER",
        },
        {
            "name": "Splunk HR — person name in audit trail",
            "text": (
                '{"time":"2024-03-15T08:00:00Z","source":"hr_system","action":"record_update",'
                '"subject":"John Smith","updatedBy":"admin@corp.com"}'
            ),
            "entity": "PERSON",
        },
        {
            "name": "Full splunk_access.log file",
            "text": (_FILE_SAMPLES / "splunk_access.log").read_text(encoding="utf-8")
            if (_FILE_SAMPLES / "splunk_access.log").exists() else "",
            "entity": "EMAIL_ADDRESS",
        },
    ]
    items = []
    for case in cases:
        if not case["text"]:
            continue
        payload = {"text": case["text"], "language": "en", "profile": "full"}
        extra = [
            f"pm.test('{case['entity']} detected', () => {{",
            "    const body = pm.response.json();",
            "    const types = body.entities_found.map(e => e.entity_type);",
            f"    pm.expect(types).to.include('{case['entity']}');",
            "});",
        ]
        items.append(_sanitize_item(case["name"], payload, extra))
    return _folder("Splunk Log Tests", items)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not _COLLECTION.exists():
        print(f"Error: collection not found at {_COLLECTION}")
        sys.exit(1)

    with open(_COLLECTION, encoding="utf-8") as fh:
        collection = json.load(fh)

    # Remove any existing BDD Regression Suite folder (idempotent)
    collection["item"] = [
        f for f in collection["item"]
        if f.get("name") != "BDD Regression Suite"
    ]

    # Build sub-folders
    all_financial = {**PRESIDIO_BUILTIN_SAMPLES, **FINANCIAL_SAMPLES}

    bdd_folder = _folder(
        "BDD Regression Suite",
        [
            _entity_folder("Financial PII",       all_financial),
            _entity_folder("Developer Secrets",   DEVELOPER_SAMPLES),
            _entity_folder("Infrastructure",      INFRASTRUCTURE_SAMPLES),
            _entity_folder("CI/CD Tokens",        CICD_SAMPLES),
            _custom_recognizers_folder(),
            _file_formats_folder(),
            _splunk_folder(),
        ],
    )

    collection["item"].append(bdd_folder)

    with open(_COLLECTION, "w", encoding="utf-8") as fh:
        json.dump(collection, fh, indent=2, ensure_ascii=False)

    # Count items added
    total = sum(len(f.get("item", [])) for f in bdd_folder["item"])
    print(f"✓  Updated {_COLLECTION.name}")
    print(f"   Added 'BDD Regression Suite' folder with {len(bdd_folder['item'])} sub-folders")
    print(f"   Total new request items: {total}")


if __name__ == "__main__":
    main()
