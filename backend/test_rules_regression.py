import pytest

from rules import analyze_rules


@pytest.mark.parametrize(
    "text, expected_score, expected_level, expected_flags",
    [
        ("There is no urgent deadline for this message.", 0, "LOW", []),
        ("Your account is blocked. Pay Rs 1000 immediately.", 84, "HIGH", [
            "High-pressure urgency or legal intimidation detected.",
            "Financial demand or digital payment indicator detected.",
        ]),
        ("आपका बैंक खाता सही है; हम कभी भी OTP नहीं मांगते, कृपया कोई शुल्क जमा न करें.", 0, "LOW", []),
        ("आपका UIDAI खाता निलंबित है। तुरंत ₹999 जमा करें और OTP साझा करें.", 94, "HIGH", [
            "तुरंत कार्रवाई का दबाव या कानूनी धमकी के संकेत मिले।",
            "पैसे की मांग या डिजिटल भुगतान का संकेत मिला।",
            "OTP, आधार या संवेदनशील जानकारी मांगने का संकेत मिला।",
        ]),
        ("इंटर्नशिप के लिए आवेदन करें; ₹999 जमा करें और 2 घंटे में काम शुरू करें.", 93, "HIGH", [
            "तुरंत कार्रवाई का दबाव या कानूनी धमकी के संकेत मिले।",
            "पैसे की मांग या डिजिटल भुगतान का संकेत मिला।",
            "नौकरी, भर्ती या इनाम के लालच जैसी भाषा मिली।",
        ]),
        ("आपके पार्सल पर कस्टम शुल्क ₹2500 है, कृपया भुगतान करें.", 82, "HIGH", [
            "पैसे की मांग या डिजिटल भुगतान का संकेत मिला।",
            "कूरियर या कस्टम क्लीयरेंस शुल्क जैसा पैटर्न मिला।",
        ]),
        ("आपका बैंक सही है; कोई शुल्क जमा न करें, OTP कभी साझा न करें.", 0, "LOW", []),
    ],
)
def test_rule_score_regressions(text, expected_score, expected_level, expected_flags):
    result = analyze_rules(text)
    assert result["rule_score"] == expected_score
    assert result["risk_level"] == expected_level
    assert result["flags"] == expected_flags


def test_url_regressions():
    assert analyze_rules("https://sbi.co.in")["rule_score"] == 0
    assert analyze_rules("https://google.com")["rule_score"] == 0
    assert analyze_rules("https://www.uidaia.gov.in/verify")["rule_score"] == 65
    assert analyze_rules("https://bit.ly/abc")["rule_score"] == 48


def test_negated_hindi_does_not_trigger():
    benign = [
        "कोई शुल्क जमा न करें",
        "OTP कभी साझा न करें",
        "हम कभी भी OTP नहीं मांगते",
        "शुल्क जमा न करें",
    ]
    for text in benign:
        result = analyze_rules(text)
        assert result["rule_score"] == 0
        assert result["risk_level"] == "LOW"
