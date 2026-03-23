"""
pytest-bdd entry point: multi-format file content scenarios.
"""

import sys
import pathlib

import allure
import pytest
import requests
from pytest_bdd import scenarios

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import steps.sanitize_steps  # noqa: F401

scenarios("../features/file_formats.feature")

from conftest import BASE_URL, HTTP_TIMEOUT  # noqa: E402

_SANITIZE_URL = f"{BASE_URL}/sanitize"
_FILE_SAMPLES = pathlib.Path(__file__).parent.parent / "fixtures" / "file_samples"

# ---------------------------------------------------------------------------
# Standalone regression test — verify every sample file yields detections
# ---------------------------------------------------------------------------
_SAMPLE_FILES = [
    # ── Already existing ──────────────────────────────────────────────────
    ("sample_config.json",     "full", 3),
    ("sample.env",             "full", 3),
    ("sample.conf",            "full", 2),
    ("sample.yaml",            "full", 2),
    ("sample.properties",      "full", 2),
    ("sample.xml",             "full", 2),
    ("sample.csv",             "full", 3),
    ("sample.tfvars",          "full", 2),
    ("kubernetes_secret.yaml", "full", 1),
    # ── Universal config formats ──────────────────────────────────────────
    ("sample.yml",             "full", 2),
    ("sample.toml",            "full", 2),
    ("sample.ini",             "full", 2),
    ("sample.cfg",             "full", 2),
    ("sample.config",          "full", 2),
    # ── Secret / credential dotfiles ──────────────────────────────────────
    ("sample.secret",          "full", 2),
    ("sample.npmrc",           "full", 2),
    ("sample.yarnrc",          "full", 1),
    ("sample.gemrc",           "full", 1),
    ("sample.netrc",           "full", 2),
    ("sample.pgpass",          "full", 1),
    ("sample.terraformrc",     "full", 1),
    # ── Certificates / keys ───────────────────────────────────────────────
    ("sample.pem",             "full", 1),
    ("sample.crt",             "full", 1),
    ("sample.cer",             "full", 1),
    ("sample.key",             "full", 1),
    ("sample.pub",             "full", 1),
    ("sample.ppk",             "full", 1),
    ("sample.asc",             "full", 1),
    # ── Infrastructure as Code ────────────────────────────────────────────
    ("sample.tf",              "full", 2),
    ("sample.tfstate",         "full", 2),
    ("sample.hcl",             "full", 2),
    # ── JVM ───────────────────────────────────────────────────────────────
    ("sample.gradle",          "full", 2),
    ("sample.kts",             "full", 2),
    # ── .NET ──────────────────────────────────────────────────────────────
    ("sample.csproj",          "full", 2),
    ("sample.nuspec",          "full", 1),
    ("sample.props",           "full", 2),
    ("sample.targets",         "full", 2),
    # ── Shell scripts ─────────────────────────────────────────────────────
    ("sample.sh",              "full", 2),
    ("sample.bash",            "full", 2),
    ("sample.zsh",             "full", 2),
    ("sample.ps1",             "full", 2),
    ("sample.psm1",            "full", 2),
    ("sample.bat",             "full", 2),
    ("sample.cmd",             "full", 2),
    # ── Data / reports ────────────────────────────────────────────────────
    ("sample.tsv",             "full", 3),
    ("sample.sql",             "full", 2),
    ("sample.txt",             "full", 2),
    ("sample.jsonl",           "full", 2),
    ("splunk_access.log",      "full", 2),
    # ── API / schema definitions ──────────────────────────────────────────
    ("sample.graphql",         "full", 2),
    ("sample.gql",             "full", 2),
    ("sample.proto",           "full", 2),
    ("sample.wsdl",            "full", 2),
    ("sample.xsd",             "full", 2),
]


@allure.feature("File Format Tests")
@allure.story("Multi-format PII sanitization regression")
@pytest.mark.file_formats
@pytest.mark.regression
@pytest.mark.parametrize("filename,profile,min_entities", _SAMPLE_FILES)
def test_file_sample_sanitized(filename, profile, min_entities):
    """Each sample file must yield at least min_entities detections."""
    file_path = _FILE_SAMPLES / filename
    assert file_path.exists(), f"Sample file missing: {file_path}"

    text = file_path.read_text(encoding="utf-8")
    payload = {"text": text, "language": "en", "profile": profile}

    allure.dynamic.title(f"File: {filename}")
    allure.dynamic.parameter("file", filename)

    resp = requests.post(_SANITIZE_URL, json=payload, timeout=HTTP_TIMEOUT)
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:200]}"

    body = resp.json()
    count = len(body.get("entities_found", []))
    assert body.get("was_modified"), f"{filename}: was_modified=False"
    assert count >= min_entities, (
        f"{filename}: expected ≥{min_entities} entities but found {count}.\n"
        f"Found: {[e['entity_type'] for e in body.get('entities_found', [])]}"
    )
