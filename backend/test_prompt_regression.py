# -*- coding: utf-8 -*-
"""Focused tests for Gemini prompt construction in main.py.

The prompt must carry the deterministic URL assessment (classification +
explanation) so Gemini can distinguish an "unverified" URL (no deceptive
indicators, not malicious) from a "suspicious" one. Expectations are derived
from analyze_rules() output, not hardcoded.
"""

import pytest

from rules import analyze_rules


@pytest.fixture()
def main_module():
    try:
        import main
    except Exception as exc:
        pytest.skip(f"API module unavailable in this environment: {exc}")
    return main


def _link_row(rule_results):
    for item in rule_results["rule_breakdown"]:
        if item.get("classification"):
            return item
    raise AssertionError("no URL rule row with a classification found")


def test_prompt_carries_unverified_url_assessment(main_module):
    text = (
        "URGENT: This is the Income Tax Department. Your PAN will be "
        "suspended today unless you verify your details immediately at "
        "https://example.com/verify."
    )
    rule_results = analyze_rules(text)
    link = _link_row(rule_results)
    assert link["classification"] == "unverified"
    assert link["triggered"] is False

    prompt = main_module._build_prompt(text, rule_results, "knowledge", "en")

    assert f"- URL Assessment: {link['classification']}" in prompt
    assert link["explanation"] in prompt
    # Existing deterministic context must be preserved verbatim.
    assert f"- Rule Score: {rule_results['rule_score']}" in prompt
    assert f"- Risk Level: {rule_results['risk_level']}" in prompt
    assert text in prompt


def test_prompt_carries_suspicious_url_assessment(main_module):
    text = "Track here: https://bit.ly/example"
    rule_results = analyze_rules(text)
    link = _link_row(rule_results)
    assert link["classification"] == "suspicious"
    assert link["triggered"] is True

    prompt = main_module._build_prompt(text, rule_results, "knowledge", "en")

    assert f"- URL Assessment: {link['classification']}" in prompt
    assert link["explanation"] in prompt


def test_prompt_carries_none_url_assessment(main_module):
    text = "Lunch at 2 tomorrow? Let me know."
    rule_results = analyze_rules(text)
    link = _link_row(rule_results)
    assert link["classification"] == "none"

    prompt = main_module._build_prompt(text, rule_results, "knowledge", "en")

    assert "- URL Assessment: none" in prompt


def test_prompt_distinguishes_unverified_from_malicious(main_module):
    text = "See https://example.com/verify for details."
    rule_results = analyze_rules(text)
    prompt = main_module._build_prompt(text, rule_results, "knowledge", "en")

    assert '"unverified" verdict is not a finding of maliciousness' in prompt
    assert (
        "do not claim the deterministic checks established\n"
        "that it is malicious or a confirmed phishing link" in prompt
    )
    assert (
        "never present the absence of\n"
        "deceptive indicators" in prompt
    )


def test_prompt_keeps_message_suspicious_on_other_evidence(main_module):
    text = (
        "URGENT: This is the Income Tax Department. Your PAN will be "
        "suspended today unless you verify your details immediately at "
        "https://example.com/verify."
    )
    rule_results = analyze_rules(text)
    prompt = main_module._build_prompt(text, rule_results, "knowledge", "en")

    assert "can still be suspicious because of impersonation" in prompt
    assert "recommend independent\nverification when appropriate" in prompt
    # Pre-existing guardrails must survive the refactor.
    assert "Only flag a domain as\nsuspicious if there is a concrete reason" in prompt
