"""
Shared pytest fixtures for the SafeChat BDD regression suite.

Fixtures available to all tests in this bdd/ tree:
  base_url          – root URL of the running Presidio server
  http_timeout      – per-request timeout (seconds)
  entity_samples    – full ENTITY_SAMPLES dict from fixtures/entity_samples.py
  sanitize          – helper function: POST /sanitize, assert 200, return body
  analyze           – helper function: POST /analyze,  assert 200, return body
  file_samples_dir  – pathlib.Path to fixtures/file_samples/
"""

import os
import sys
import time
import pathlib
import pytest
import requests
import allure

# Register step definitions as pytest fixtures so that pytest-bdd 7 discovers
# them for every test file under this conftest's directory tree.
pytest_plugins = ["steps.sanitize_steps"]

# Make bdd/fixtures importable regardless of run location
_BDD_ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(_BDD_ROOT))

from fixtures.entity_samples import ENTITY_SAMPLES  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL    = os.getenv("PRESIDIO_URL", "http://localhost:8000")
HTTP_TIMEOUT = int(os.getenv("BDD_TIMEOUT", "10"))


# ---------------------------------------------------------------------------
# Known product-defect entity types — mark these tests as xfail so that
# Allure/pytest reports distinguish them from genuine test failures.
# Re-enable individual entries as each recognizer is fixed.
# ---------------------------------------------------------------------------
_PRODUCT_DEFECT_ENTITIES = frozenset({
    # All entity detection issues resolved — keep set for future use
})


def pytest_runtest_setup(item):
    """Auto-xfail tests whose node-id references a known product-defect entity."""
    nodeid = item.nodeid
    for entity in _PRODUCT_DEFECT_ENTITIES:
        if (
            f"[{entity}" in nodeid            # [ENTITY_TYPE] or [ENTITY_TYPE-sampleN]
            or f"-{entity}]" in nodeid        # trailing param: -ENTITY_TYPE]
            or f"_{entity.lower()}" in nodeid  # test function name: _us_ssn
        ):
            pytest.xfail(
                f"Known product defect: {entity} recognizer has detection gaps — skip until fixed"
            )


# ---------------------------------------------------------------------------
# Session-scoped: verify server is up once
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def _ensure_server_running():
    """Fail the entire suite early if the Presidio server cannot be reached."""
    health_url = f"{BASE_URL}/health"
    for attempt in range(3):
        try:
            resp = requests.get(health_url, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                return
        except requests.ConnectionError:
            pass
        time.sleep(1)
    pytest.fail(
        f"[conftest] Presidio server not reachable at {health_url}. "
        "Start it with: PYTHONPATH=. .venv/bin/uvicorn presidio_server.main:app --port 8000"
    )


# ---------------------------------------------------------------------------
# Basic URL fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
def http_timeout() -> int:
    return HTTP_TIMEOUT


@pytest.fixture(scope="session")
def sanitize_url(base_url) -> str:
    return f"{base_url}/sanitize"


@pytest.fixture(scope="session")
def analyze_url(base_url) -> str:
    return f"{base_url}/analyze"


@pytest.fixture(scope="session")
def anonymize_url(base_url) -> str:
    return f"{base_url}/anonymize"


# ---------------------------------------------------------------------------
# Entity samples fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def entity_samples() -> dict:
    return ENTITY_SAMPLES


# ---------------------------------------------------------------------------
# File samples path
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def file_samples_dir() -> pathlib.Path:
    return _BDD_ROOT / "fixtures" / "file_samples"


# ---------------------------------------------------------------------------
# Helper callables
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def sanitize(sanitize_url, http_timeout):
    """
    Call POST /sanitize and assert HTTP 200.

    Usage:
        body = sanitize(text, entities=["CREDIT_CARD"], rules={"CREDIT_CARD": "mask"})
    """
    def _call(
        text: str,
        entities: list | None = None,
        profile: str | None = None,
        rules: dict | None = None,
        custom_recognizers: list | None = None,
    ) -> dict:
        payload: dict = {"text": text, "language": "en"}
        if entities:
            payload["entities"] = entities
        if profile:
            payload["profile"] = profile
        if rules:
            payload["rules"] = rules
        if custom_recognizers:
            payload["custom_recognizers"] = custom_recognizers

        with allure.step(f"POST /sanitize — {len(text)} chars"):
            resp = requests.post(sanitize_url, json=payload, timeout=http_timeout)
        assert resp.status_code == 200, (
            f"/sanitize returned HTTP {resp.status_code}: {resp.text[:300]}"
        )
        return resp.json()

    return _call


@pytest.fixture(scope="session")
def analyze(analyze_url, http_timeout):
    """
    Call POST /analyze and assert HTTP 200.

    Usage:
        body = analyze(text, entities=["US_SSN"])
    """
    def _call(
        text: str,
        entities: list | None = None,
        profile: str | None = None,
        custom_recognizers: list | None = None,
    ) -> dict:
        payload: dict = {"text": text, "language": "en"}
        if entities:
            payload["entities"] = entities
        if profile:
            payload["profile"] = profile
        if custom_recognizers:
            payload["custom_recognizers"] = custom_recognizers

        with allure.step(f"POST /analyze — {len(text)} chars"):
            resp = requests.post(analyze_url, json=payload, timeout=http_timeout)
        assert resp.status_code == 200, (
            f"/analyze returned HTTP {resp.status_code}: {resp.text[:300]}"
        )
        return resp.json()

    return _call


# ---------------------------------------------------------------------------
# Assertion helpers (importable from conftest in step definitions)
# ---------------------------------------------------------------------------
def assert_entity_in_response(body: dict, entity_type: str) -> None:
    """Assert that entity_type appears in entities_found list."""
    found = [e["entity_type"] for e in body.get("entities_found", [])]
    assert entity_type in found, (
        f"Expected '{entity_type}' in entities_found but got: {found}"
    )


def assert_was_modified(body: dict) -> None:
    """Assert sanitize endpoint reports was_modified=True."""
    assert body.get("was_modified") is True, (
        f"Expected was_modified=True but response body: {body}"
    )


def assert_original_not_in_sanitized(original_value: str, sanitized_text: str) -> None:
    """Assert a known secret no longer appears verbatim in the sanitized output."""
    assert original_value not in sanitized_text, (
        f"Sensitive value '{original_value[:40]}…' still present in sanitized output."
    )
