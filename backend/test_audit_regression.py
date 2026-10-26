

import pytest

from rules import (
    analyze_rules,
    calculate_calibrated_score,
)


def _row(result, prefix):
    for item in result["rule_breakdown"]:
        if item["rule"].startswith(prefix):
            return item
    raise AssertionError(f"no rule starting with {prefix!r}")


def test_urgent_pan_with_unverified_example_url():
    text = (
        "URGENT: This is the Income Tax Department. Your PAN will be "
        "suspended today unless you verify your details immediately at "
        "https://example.com/verify."
    )
    result = analyze_rules(text)
    urgency = _row(result, "Urgent")
    link = _row(result, "Suspicious")
    assert urgency["triggered"] is True
    assert urgency["points"] == 35
    # example.com is unverified, NOT malicious: link stays untriggered.
    assert link["triggered"] is False
    assert link["points"] == 0
    assert link["evidence"] == ""
    assert link["classification"] == "unverified"
    assert "nverified" in link["explanation"]
    assert any("example.com/verify" in u for u in result["extracted_urls"])
    assert any("example.com/verify" in u for u in result["unverified_urls"])
    assert result["rule_score"] == 60
    assert result["risk_level"] == "MEDIUM"


def test_official_sbi_domain_is_clean():
    result = analyze_rules(
        "Your statement is ready. Visit https://sbi.co.in/ when convenient."
    )
    link = _row(result, "Suspicious")
    assert result["rule_score"] == 0
    assert result["risk_level"] == "LOW"
    assert link["triggered"] is False
    assert link["points"] == 0
    assert link["classification"] == "none"
    assert result["unverified_urls"] == []


def test_official_subdomain_is_clean():
    result = analyze_rules("Login at https://www.sbi.co.in/login safely.")
    link = _row(result, "Suspicious")
    assert result["rule_score"] == 0
    assert link["triggered"] is False
    assert link["classification"] == "none"


def test_known_good_subdomain_is_clean():
    result = analyze_rules(
        "Sign in at https://accounts.google.com/ to continue."
    )
    link = _row(result, "Suspicious")
    assert result["rule_score"] == 0
    assert result["risk_level"] == "LOW"
    assert link["triggered"] is False
    assert link["classification"] == "none"


def test_deceptive_sbi_hostname_is_flagged():
    result = analyze_rules("Verify now: https://sbi.co.in.fake-site.example/")
    link = _row(result, "Suspicious")
    assert link["triggered"] is True
    assert link["points"] == 40
    assert link["classification"] == "suspicious"
    assert "sbi.co.in.fake-site.example" in link["evidence"]
    assert result["rule_score"] == 65
    assert result["risk_level"] == "HIGH"


def test_deceptive_google_hostname_is_flagged():
    result = analyze_rules(
        "Sign in at https://google.com.fake-site.example/ to continue."
    )
    link = _row(result, "Suspicious")
    assert link["triggered"] is True
    assert link["points"] == 40
    assert link["classification"] == "suspicious"
    assert "google.com.fake-site.example" in link["evidence"]
    assert result["rule_score"] == 65
    assert result["risk_level"] == "HIGH"


def test_known_shortener_is_flagged():
    result = analyze_rules("Track here: https://bit.ly/example")
    link = _row(result, "Suspicious")
    assert link["triggered"] is True
    assert link["points"] == 25
    assert link["classification"] == "suspicious"
    assert "bit.ly/example" in link["evidence"]
    assert result["rule_score"] == 48
    assert result["risk_level"] == "MEDIUM"


def test_uidaia_typosquat_still_flagged():
    result = analyze_rules("See https://www.uidaia.gov.in/verify")
    link = _row(result, "Suspicious")
    assert link["triggered"] is True
    assert link["classification"] == "suspicious"
    assert result["rule_score"] == 65
    assert result["risk_level"] == "HIGH"


def test_otp_safety_warning_is_not_a_request():
    result = analyze_rules("Do not share your OTP with anyone.")
    cred = _row(result, "OTP")
    assert cred["triggered"] is False
    assert cred["points"] == 0
    assert result["rule_score"] == 0
    assert result["risk_level"] == "LOW"


def test_otp_request_still_triggers():
    result = analyze_rules("Share your OTP now to verify your account.")
    cred = _row(result, "OTP")
    assert cred["triggered"] is True
    assert cred["points"] == 35


def test_courier_no_fee_is_not_flagged():
    result = analyze_rules(
        "Your parcel is on hold. No clearance fee is required."
    )
    courier = _row(result, "Courier")
    assert courier["triggered"] is False
    assert courier["points"] == 0
    assert result["rule_score"] == 0
    assert result["risk_level"] == "LOW"


def test_courier_clearance_fee_is_flagged():
    result = analyze_rules(
        "Your parcel is held at customs. Pay Rs 1250 clearance fee now."
    )
    courier = _row(result, "Courier")
    assert courier["triggered"] is True
    assert courier["points"] == 30
    assert courier["evidence"] != ""
    assert "ourier" in courier["explanation"].lower() or "ustom" in courier["explanation"]
    assert result["rule_score"] == 82
    assert result["risk_level"] == "HIGH"


def test_hindi_job_security_fee_is_flagged():
    text = (
        "बधाई हो! आपकी प्रोफाइल Data Entry Operator पद के लिए चुन ली गई है। "
        "सैलरी ₹25,000 होगी। जॉइनिंग के लिए ₹1500 सिक्योरिटी फीस जमा करनी होगी, "
        "जो पहली सैलरी के साथ वापस आ जाएगी।"
    )
    result = analyze_rules(text)
    assert result["language"] == "hi"
    job = _row(result, "Job")
    assert job["triggered"] is True
    assert job["points"] == 30
    assert result["rule_score"] == 82
    assert result["risk_level"] == "HIGH"


def test_hindi_coercive_condition_still_triggers_urgency():
    result = analyze_rules("भुगतान नहीं करने पर ऑफर रद्द कर दिया जाएगा")
    assert result["language"] == "hi"
    urgency = _row(result, "Urgent")
    assert urgency["triggered"] is True
    assert urgency["points"] == 35
    assert urgency["evidence"] != ""
    assert result["rule_score"] == 60
    assert result["risk_level"] == "MEDIUM"


def test_hindi_negated_fee_warning_stays_clean():
    result = analyze_rules(
        "हमारी कंपनी कभी भी कोई फीस नहीं लेती। सिक्योरिटी फीस जमा न करें।"
    )
    assert result["rule_score"] == 0
    assert result["risk_level"] == "LOW"


def test_normal_message_stays_low():
    result = analyze_rules("Lunch at 2 tomorrow? Let me know.")
    assert result["rule_score"] == 0
    assert result["risk_level"] == "LOW"
    assert all(item["triggered"] is False for item in result["rule_breakdown"])
    assert all(item["points"] == 0 for item in result["rule_breakdown"])


def test_score_and_level_agree_with_calibration():
    for text in [
        "Lunch at 2 tomorrow? Let me know.",
        "Track here: https://bit.ly/example",
        "Verify now: https://sbi.co.in.fake-site.example/",
        "Your parcel is held at customs. Pay Rs 1250 clearance fee now.",
    ]:
        result = analyze_rules(text)
        expected_score, expected_level = calculate_calibrated_score(
            result["raw_points"]
        )
        assert result["rule_score"] == expected_score
        assert result["risk_level"] == expected_level


def test_api_response_carries_url_classification():
    try:
        from main import _fallback_response, _rule_rows
    except Exception as exc:
        pytest.skip(f"API module unavailable in this environment: {exc}")
    text = "Track here: https://bit.ly/example"
    rule_results = analyze_rules(text)
    rows = _rule_rows(rule_results, "en")
    link = next(r for r in rows if r.rule.startswith("Suspicious"))
    assert link.classification == "suspicious"
    assert link.triggered is True
    response = _fallback_response(text, rule_results, "en")
    assert response.calculated_score == rule_results["rule_score"]
    assert response.risk_level == rule_results["risk_level"]
    assert len(response.rule_breakdown) == len(rule_results["rule_breakdown"])


def _build_minimal_pdf(payload: bytes) -> bytes:
    """Assemble a tiny one-page PDF holding a single text line."""
    stream = b"BT /F1 18 Tf 50 100 Td (" + payload + b") Tj ET"
    bodies = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
        + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = [b"%PDF-1.4\n"]
    offsets = []
    for number, body in enumerate(bodies, start=1):
        offsets.append(sum(len(chunk) for chunk in out))
        out.append(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref_pos = sum(len(chunk) for chunk in out)
    out.append(b"xref\n0 %d\n" % (len(bodies) + 1))
    out.append(b"0000000000 65535 f \n")
    for offset in offsets:
        out.append(b"%010d 00000 n \n" % offset)
    out.append(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(bodies) + 1, xref_pos)
    )
    return b"".join(out)


def test_extract_text_endpoints_without_gemini():
    """PDF / pasted-text / empty extraction must work without AI calls."""
    try:
        from fastapi.testclient import TestClient
        import main
    except Exception as exc:
        pytest.skip(f"API test client unavailable: {exc}")
    client = TestClient(main.app)

    pdf_bytes = _build_minimal_pdf(b"Your account is blocked")
    response = client.post(
        "/api/extract-text",
        files={"file": ("notice.pdf", pdf_bytes, "application/pdf")},
    )
    assert response.status_code == 200
    assert "Your account is blocked" in response.json()["text"]

    response = client.post("/api/extract-text", data={"raw_text": "hello"})
    assert response.status_code == 200
    assert response.json() == {"text": "hello"}

    response = client.post("/api/extract-text")
    assert response.status_code == 200
    assert response.json() == {"text": ""}


def test_analyze_rejects_missing_text_without_gemini():
    """Missing form text fails FastAPI validation before any AI call."""
    try:
        from fastapi.testclient import TestClient
        import main
    except Exception as exc:
        pytest.skip(f"API test client unavailable: {exc}")
    client = TestClient(main.app)
    response = client.post("/api/analyze", data={})
    assert response.status_code == 422
