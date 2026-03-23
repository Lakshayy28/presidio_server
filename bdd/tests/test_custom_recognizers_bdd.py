"""
pytest-bdd entry point: user-defined custom recognizer scenarios.

The feature file uses four special entity keys that don't exist in
entity_samples.py; they are injected here into the step-definition
context via pytest.fixture overrides.
"""

import sys
import pathlib

import allure
import pytest
import requests
from pytest_bdd import scenarios, given, parsers

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import steps.sanitize_steps  # noqa: F401

scenarios("../features/custom_recognizers.feature")

from conftest import BASE_URL, HTTP_TIMEOUT  # noqa: E402

_SANITIZE_URL = f"{BASE_URL}/sanitize"
_ANALYZE_URL  = f"{BASE_URL}/analyze"

# ---------------------------------------------------------------------------
# Override the "I have a document with X data" step for custom entity keys
# ---------------------------------------------------------------------------
_CUSTOM_FIXTURES: dict = {
    "CUSTOM_EMPLOYEE_ID": {
        "text": "Employee badge: EMP-00042781 has been flagged for review.",
        "entities": ["EMPLOYEE_ID"],
        "rules": {"EMPLOYEE_ID": "mask"},
        "profile": None,
        "custom_recognizers": [
            {
                "name": "EMPLOYEE_ID",
                "pattern": r"EMP-\d{8}",
                "score": 0.90,
                "context": ["badge", "employee", "emp"],
            }
        ],
    },
    "CUSTOM_REGION_CODE": {
        "text": "Region code: APAC-SGP-007 assigned to cluster.",
        "entities": ["REGION_CODE"],
        "rules": {"REGION_CODE": "replace"},
        "profile": None,
        "custom_recognizers": [
            {
                "name": "REGION_CODE",
                "pattern": r"[A-Z]{3,4}-[A-Z]{3}-\d{3}",
                "score": 0.85,
            }
        ],
    },
    "CUSTOM_PROJECT_CODE": {
        "text": "Project code PRJ-2024-ALPHA assigned to sprint 5.",
        "entities": ["PROJECT_CODE"],
        "rules": {"PROJECT_CODE": "replace"},
        "profile": None,
        "custom_recognizers": [
            {
                "name": "PROJECT_CODE",
                "pattern": r"PRJ-\d{4}-[A-Z]+",
                "score": 0.85,
                "context": ["project", "PRJ", "code"],
            }
        ],
    },
    "CUSTOM_MULTI": {
        "text": (
            "Employee badge: EMP-00042781. "
            "Project code PRJ-2024-BETA flagged for decommission."
        ),
        "entities": ["EMPLOYEE_ID", "PROJECT_CODE"],
        "rules": {},
        "profile": None,
        "custom_recognizers": [
            {
                "name": "EMPLOYEE_ID",
                "pattern": r"EMP-\d{8}",
                "score": 0.90,
            },
            {
                "name": "PROJECT_CODE",
                "pattern": r"PRJ-\d{4}-[A-Z]+",
                "score": 0.85,
            },
        ],
    },
}


@given(
    parsers.parse('I have a document with "{entity_type}" data'),
    target_fixture="ctx",
)
def _custom_document(entity_type):
    if entity_type in _CUSTOM_FIXTURES:
        return dict(_CUSTOM_FIXTURES[entity_type])
    # Fall back to shared fixture for non-custom keys
    from fixtures.entity_samples import ENTITY_SAMPLES
    sample = ENTITY_SAMPLES[entity_type]
    return {
        "text":     sample["text"],
        "entities": sample.get("entities"),
        "rules":    sample.get("rules", {}),
        "profile":  sample.get("profile"),
        "entity_type": entity_type,
    }


# ---------------------------------------------------------------------------
# Standalone regression tests for custom recognizers
# ---------------------------------------------------------------------------
@allure.feature("Custom Recognizers")
@allure.story("Dynamic regex recognizer — employee ID")
@pytest.mark.custom
@pytest.mark.regression
def test_custom_employee_id():
    sample = _CUSTOM_FIXTURES["CUSTOM_EMPLOYEE_ID"]
    payload = {
        "text": sample["text"],
        "language": "en",
        "rules": sample["rules"],
        "custom_recognizers": sample["custom_recognizers"],
    }
    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200
    body = resp.json()
    found = [e["entity_type"] for e in body.get("entities_found", [])]
    assert "EMPLOYEE_ID" in found, f"EMPLOYEE_ID not detected; found: {found}"
    assert body["was_modified"], "was_modified should be True"


@allure.feature("Custom Recognizers")
@allure.story("Dynamic regex recognizer — multi-entity in one request")
@pytest.mark.custom
@pytest.mark.regression
def test_custom_multi_recognizers():
    sample = _CUSTOM_FIXTURES["CUSTOM_MULTI"]
    payload = {
        "text": sample["text"],
        "language": "en",
        "custom_recognizers": sample["custom_recognizers"],
    }
    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200
    body = resp.json()
    found = set(e["entity_type"] for e in body.get("entities_found", []))
    assert "EMPLOYEE_ID" in found, f"EMPLOYEE_ID missing; found: {found}"
    assert "PROJECT_CODE" in found, f"PROJECT_CODE missing; found: {found}"


@allure.feature("Custom Recognizers")
@allure.story("Custom recognizer with context words")
@pytest.mark.custom
def test_custom_with_context():
    sample = _CUSTOM_FIXTURES["CUSTOM_PROJECT_CODE"]
    payload = {
        "text": sample["text"],
        "language": "en",
        "custom_recognizers": sample["custom_recognizers"],
    }
    resp = requests.post(_ANALYZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200
    body = resp.json()
    found = [e["entity_type"] for e in body.get("entities_found", [])]
    assert "PROJECT_CODE" in found, f"PROJECT_CODE not detected; found: {found}"
