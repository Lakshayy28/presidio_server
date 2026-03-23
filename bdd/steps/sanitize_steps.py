"""
Shared pytest-bdd step definitions for the SafeChat BDD regression suite.

These steps are imported by every test_*_bdd.py file via conftest.py
and apply to all .feature files.

Step vocabulary
───────────────
Given:
  "the Presidio server is running"
  "I have a document with {entity_type} data"
  "I have the file {filename}"
  "I have a Splunk log line with {entity_type}"

When:
  "I POST the text to /sanitize"
  "I POST the text to /analyze"
  "I POST the file content to /sanitize"
  "I POST the file content to /sanitize using profile {profile}"

Then:
  "the response status should be 200"
  "was_modified should be true"
  "the entity {entity_type} should be detected"
  "the sanitized text should not contain the original value"
  "the response should contain at least {n} detected entities"
"""

import pathlib
import sys
import pytest
import allure
import requests
from pytest_bdd import given, when, then, parsers

# Ensure bdd/ root is importable (pytest-bdd can run from tests/ sub-dir)
_BDD_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(_BDD_ROOT))

from fixtures.entity_samples import ENTITY_SAMPLES  # noqa: E402
from conftest import (  # noqa: E402
    assert_entity_in_response,
    assert_was_modified,
    assert_original_not_in_sanitized,
    BASE_URL,
    HTTP_TIMEOUT,
)

_SANITIZE_URL  = f"{BASE_URL}/sanitize"
_ANALYZE_URL   = f"{BASE_URL}/analyze"
_FILE_SAMPLES  = _BDD_ROOT / "fixtures" / "file_samples"


# ---------------------------------------------------------------------------
# Shared state — stored in pytest's `context` dict via a request-scoped fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def ctx():
    """Per-scenario mutable state bag."""
    return {}


# ---------------------------------------------------------------------------
# GIVEN steps
# ---------------------------------------------------------------------------
@given("the Presidio server is running")
def step_server_running():
    """Validated by the session-scoped _ensure_server_running fixture in conftest."""


@given(parsers.parse('I have a document with "{entity_type}" data'), target_fixture="ctx")
def step_have_document(entity_type):
    sample = ENTITY_SAMPLES[entity_type]
    return {
        "text":     sample["text"],
        "entities": sample.get("entities"),
        "rules":    sample.get("rules", {}),
        "profile":  sample.get("profile"),
        "entity_type": entity_type,
    }


@given(parsers.parse('I have the file "{filename}"'), target_fixture="ctx")
def step_have_file(filename):
    file_path = _FILE_SAMPLES / filename
    assert file_path.exists(), f"Sample file not found: {file_path}"
    return {
        "text":     file_path.read_text(encoding="utf-8"),
        "entities": None,
        "rules":    {},
        "profile":  "full",
        "entity_type": None,
    }


@given(
    parsers.parse('I have a Splunk log line with "{entity_type}"'),
    target_fixture="ctx",
)
def step_have_splunk_log(entity_type):
    sample = ENTITY_SAMPLES.get(entity_type, {})
    return {
        "text":     sample.get("text", f"sample log line for {entity_type}"),
        "entities": sample.get("entities"),
        "rules":    sample.get("rules", {}),
        "profile":  "full",
        "entity_type": entity_type,
    }


# ---------------------------------------------------------------------------
# WHEN steps
# ---------------------------------------------------------------------------
@when("I POST the text to /sanitize", target_fixture="response_body")
def step_post_sanitize(ctx):
    payload = {
        "text":     ctx["text"],
        "language": "en",
    }
    if ctx.get("entities"):
        payload["entities"] = ctx["entities"]
    if ctx.get("profile"):
        payload["profile"] = ctx["profile"]
    if ctx.get("rules"):
        payload["rules"] = ctx["rules"]
    if ctx.get("custom_recognizers"):
        payload["custom_recognizers"] = ctx["custom_recognizers"]

    with allure.step(f"POST /sanitize — {len(ctx['text'])} chars"):
        resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)

    ctx["_response"] = resp
    ctx["_payload"]  = payload
    return resp.json() if resp.status_code == 200 else {}


@when("I POST the text to /analyze", target_fixture="response_body")
def step_post_analyze(ctx):
    payload = {
        "text":     ctx["text"],
        "language": "en",
    }
    if ctx.get("entities"):
        payload["entities"] = ctx["entities"]
    if ctx.get("profile"):
        payload["profile"] = ctx["profile"]
    if ctx.get("custom_recognizers"):
        payload["custom_recognizers"] = ctx["custom_recognizers"]

    with allure.step(f"POST /analyze — {len(ctx['text'])} chars"):
        resp = requests.post(_ANALYZE_URL, json=payload, timeout=HTTP_TIMEOUT)

    ctx["_response"] = resp
    ctx["_payload"]  = payload
    return resp.json() if resp.status_code == 200 else {}


@when("I POST the file content to /sanitize", target_fixture="response_body")
def step_post_file_sanitize(ctx):
    return step_post_sanitize(ctx)


@when(
    parsers.parse('I POST the file content to /sanitize using profile "{profile}"'),
    target_fixture="response_body",
)
def step_post_file_with_profile(ctx, profile):
    ctx["profile"] = profile
    return step_post_sanitize(ctx)


# ---------------------------------------------------------------------------
# THEN steps
# ---------------------------------------------------------------------------
@then("the response status should be 200")
def step_status_200(ctx):
    resp = ctx.get("_response")
    assert resp is not None, "No HTTP response stored; did the When step run?"
    assert resp.status_code == 200, (
        f"Expected 200 but got {resp.status_code}: {resp.text[:300]}"
    )


@then("was_modified should be true")
def step_was_modified(response_body):
    assert response_body.get("was_modified") is True, (
        f"Expected was_modified=True; body={response_body}"
    )


@then(parsers.parse('the entity "{entity_type}" should be detected'))
def step_entity_detected(response_body, entity_type):
    assert_entity_in_response(response_body, entity_type)


@then("the sanitized text should not contain the original value")
def step_value_removed(ctx, response_body):
    original = ctx.get("text", "")
    sanitized = response_body.get("sanitized_text", "")
    # If was_modified is False there is nothing to check
    if response_body.get("was_modified"):
        assert sanitized != original, "Sanitized text is identical to input text."


@then(parsers.parse("the response should contain at least {n:d} detected entities"))
def step_min_entities(response_body, n):
    count = len(response_body.get("entities_found", []))
    assert count >= n, f"Expected ≥{n} entities but found {count}."


@then("the response should contain entities")
def step_has_entities(response_body):
    count = len(response_body.get("entities_found", []))
    assert count > 0, "Expected at least 1 detected entity but found none."
