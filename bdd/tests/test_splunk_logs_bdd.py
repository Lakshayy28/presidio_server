"""
pytest-bdd entry point: Splunk log PII detection scenarios.
"""

import sys
import pathlib

import allure
import pytest
import requests
from pytest_bdd import scenarios

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import steps.sanitize_steps  # noqa: F401

scenarios("../features/splunk_logs.feature")

from conftest import BASE_URL, HTTP_TIMEOUT  # noqa: E402

_SANITIZE_URL = f"{BASE_URL}/sanitize"
_FILE_SAMPLES = pathlib.Path(__file__).parent.parent / "fixtures" / "file_samples"

# ---------------------------------------------------------------------------
# Splunk-format log lines with embedded PII — parametrised regression
# ---------------------------------------------------------------------------
_SPLUNK_LOG_CASES = [
    # (description, log_line, expected_entity)
    (
        "Splunk JSON event – email in user field",
        '{"time":"2024-03-15T09:42:01Z","host":"app01.prod.internal",'
        '"event":{"action":"login","user":"john.smith@corp.com","src_ip":"203.0.113.42"}}',
        "EMAIL_ADDRESS",
    ),
    (
        "Splunk syslog – IP in CEF extension",
        "Mar 15 09:42:00 siem CEF:0|Symantec|DLP|14.0|100|Data Leak|5|"
        "src=10.240.0.15 dst=203.0.113.42 suser=alice@example.com msg=SSN 323-45-6789 found",
        "EMAIL_ADDRESS",
    ),
    (
        "Splunk KV – credit card in query param",
        'index=web_access method=POST uri="/api/checkout?card=4532015112830366&cvv=857" '
        "status=200 bytes=1024",
        "CREDIT_CARD",
    ),
    (
        "Splunk JSON – AWS access key in env dump",
        '{"time":"2024-03-15T10:00:00Z","source":"lambda","level":"DEBUG",'
        '"message":"env: aws_access_key_id=AKIAIOSFODNN7EXAMPLE region=us-east-1"}',
        "AWS_ACCESS_KEY",
    ),
    (
        "Splunk audit – SSN in user query",
        '{"time":"2024-03-15T11:15:00Z","audit_action":"search",'
        '"query":"SELECT * FROM customers WHERE ssn = \'323-45-6789\'","user":"dba_user"}',
        "US_SSN",
    ),
    (
        "Splunk pipeline – JWT token echoed",
        "2024-03-15 12:00:00 INFO pipeline[runner] env dump: "
        "CI_JOB_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fw",
        "JWT_TOKEN",
    ),
    (
        "Splunk event – phone number in ticket",
        '{"time":"2024-03-15T13:30:00Z","source":"crm","event":'
        '{"ticket_id":"TKT-9901","customer_phone":"(415) 555-0192","priority":"P1"}}',
        "PHONE_NUMBER",
    ),
    (
        "Splunk index – person name in audit trail",
        '2024-03-15T08:00:00Z source=hr_system action=record_update subject="John Smith" updatedBy=admin@corp.com',
        "PERSON",
    ),
]


@allure.feature("Splunk Logs")
@allure.story("PII in Splunk-format log lines")
@pytest.mark.splunk
@pytest.mark.regression
@pytest.mark.parametrize("description,log_line,expected_entity", _SPLUNK_LOG_CASES)
def test_splunk_log_pii_detected(description, log_line, expected_entity):
    """PII in a Splunk log line is detected by /sanitize."""
    payload = {"text": log_line, "language": "en", "profile": "full"}

    allure.dynamic.title(description)
    allure.dynamic.parameter("expected_entity", expected_entity)

    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:200]}"

    body = resp.json()
    found = [e["entity_type"] for e in body.get("entities_found", [])]
    assert expected_entity in found, (
        f"[{description}] Expected {expected_entity} but got: {found}\n"
        f"Log line: {log_line[:120]}"
    )
    assert body.get("was_modified"), (
        f"[{description}] was_modified=False"
    )


@allure.feature("Splunk Logs")
@allure.story("Full splunk_access.log file sanitization")
@pytest.mark.splunk
@pytest.mark.smoke
def test_splunk_log_file():
    """The complete splunk_access.log fixture file must trigger multiple PII detections."""
    log_path = _FILE_SAMPLES / "splunk_access.log"
    assert log_path.exists(), f"Missing fixture: {log_path}"

    text = log_path.read_text(encoding="utf-8")
    payload = {"text": text, "language": "en", "profile": "full"}

    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200
    body = resp.json()
    count = len(body.get("entities_found", []))
    assert body.get("was_modified"), "splunk_access.log: was_modified=False"
    assert count >= 4, (
        f"splunk_access.log: expected ≥4 entities, found {count}: "
        f"{[e['entity_type'] for e in body.get('entities_found', [])]}"
    )
