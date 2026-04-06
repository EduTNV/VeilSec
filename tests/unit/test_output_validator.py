from __future__ import annotations

import json

import pytest

from packages.domain.ai.layer4_validator import OutputValidator
from packages.domain.exceptions import LLMOutputValidationError

VALID_OUTPUT = json.dumps(
    {
        "findings": [
            {
                "rule_id": "LGPD-001",
                "severity": "high",
                "lgpd_article": "Art. 46",
                "category": "PII_LEAK",
                "description": "PII exposto em log.",
                "remediation": "Remova PII dos logs.",
                "line_start": 5,
                "line_end": 5,
            }
        ],
        "lgpd_articles": ["Art. 46"],
        "severity": "high",
    }
)


@pytest.fixture
def validator():
    return OutputValidator()


def test_valid_output_parses_correctly(validator):
    result = validator.parse(VALID_OUTPUT)
    assert len(result.findings) == 1
    assert result.severity == "high"


def test_invalid_json_raises(validator):
    with pytest.raises(LLMOutputValidationError):
        validator.parse("not json {{{")


def test_missing_required_field_raises(validator):
    with pytest.raises(LLMOutputValidationError):
        validator.parse(json.dumps({"findings": []}))


def test_invalid_severity_raises(validator):
    with pytest.raises(LLMOutputValidationError):
        validator.parse(json.dumps({"findings": [], "lgpd_articles": [], "severity": "extreme"}))


def test_empty_findings_is_valid(validator):
    result = validator.parse(json.dumps({"findings": [], "lgpd_articles": [], "severity": "low"}))
    assert result.findings == []
