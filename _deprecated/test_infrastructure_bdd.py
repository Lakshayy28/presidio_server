"""
pytest-bdd entry point: infrastructure credential detection scenarios.
"""

import sys
import pathlib

import allure
import pytest
import requests
from pytest_bdd import scenarios

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import steps.sanitize_steps  # noqa: F401

scenarios("../features/infrastructure.feature")


# ---------------------------------------------------------------------------
# Parametrised regression — all 8 infrastructure entity types
# ---------------------------------------------------------------------------
from fixtures.entity_samples import INFRASTRUCTURE_SAMPLES
from conftest import BASE_URL, HTTP_TIMEOUT

_SANITIZE_URL = f"{BASE_URL}/sanitize"


@allure.feature("Infrastructure Credentials")
@allure.story("Regression — all infrastructure entities")
@pytest.mark.infrastructure
@pytest.mark.regression
@pytest.mark.parametrize("entity_type,sample", INFRASTRUCTURE_SAMPLES.items())
def test_infrastructure_entity_sanitized(entity_type, sample):
    """Each infrastructure entity type is detected and masked."""
    payload = {
        "text":     sample["text"],
        "language": "en",
        "rules":    sample.get("rules", {}),
    }
    if sample.get("profile"):
        payload["profile"] = sample["profile"]

    allure.dynamic.title(f"Infrastructure: {entity_type}")
    allure.dynamic.parameter("entity_type", entity_type)

    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:200]}"

    body = resp.json()
    found = [e["entity_type"] for e in body.get("entities_found", [])]

    assert entity_type in found, (
        f"[{entity_type}] not in entities_found: {found}\n"
        f"Input text: {sample['text'][:120]}"
    )
    if sample.get("expected_masked"):
        assert body.get("was_modified"), (
            f"[{entity_type}] was_modified=False — entity detected but text unchanged."
        )
