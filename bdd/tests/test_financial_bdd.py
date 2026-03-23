"""
pytest-bdd entry point: financial PII detection scenarios.
All step definitions are provided by steps/sanitize_steps.py.
"""

import sys
import pathlib

import allure
import pytest
from pytest_bdd import scenarios

# Ensure steps/ and fixtures/ are on sys.path
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Import step definitions (side-effect: registers @given/@when/@then)
import steps.sanitize_steps  # noqa: F401

# Load all scenarios from the financial feature file
scenarios("../features/financial.feature")


# ---------------------------------------------------------------------------
# Additional parametrised regression — covers every single financial entity
# ---------------------------------------------------------------------------
import pytest
import requests
from fixtures.entity_samples import FINANCIAL_SAMPLES, PRESIDIO_BUILTIN_SAMPLES
from conftest import BASE_URL, HTTP_TIMEOUT

_SANITIZE_URL = f"{BASE_URL}/sanitize"

_ALL_FINANCIAL = {**PRESIDIO_BUILTIN_SAMPLES, **FINANCIAL_SAMPLES}


@allure.feature("Financial PII")
@allure.story("Regression — all financial entities")
@pytest.mark.financial
@pytest.mark.regression
@pytest.mark.parametrize("entity_type,sample", _ALL_FINANCIAL.items())
def test_financial_entity_sanitized(entity_type, sample):
    """Each financial entity type is detected and the response is modified."""
    payload = {
        "text":     sample["text"],
        "language": "en",
        "rules":    sample.get("rules", {}),
    }
    if sample.get("profile"):
        payload["profile"] = sample["profile"]

    allure.dynamic.title(f"Financial: {entity_type}")
    allure.dynamic.parameter("entity_type", entity_type)

    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:200]}"

    body = resp.json()
    found = [e["entity_type"] for e in body.get("entities_found", [])]

    assert entity_type in found, (
        f"[{entity_type}] not in entities_found: {found}\n"
        f"Input text: {sample['text']}"
    )
    if sample.get("expected_masked"):
        assert body.get("was_modified"), (
            f"[{entity_type}] was_modified=False — entity detected ({found}) "
            f"but text unchanged."
        )
