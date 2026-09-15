import re

def analyze_rules(text: str) -> dict:
    flags = []
    score = 0

    # 1. Urgent deadline / coercion
    urgency_pattern = re.compile(r'\b(immediate|within \d+ hours?|today|urgent|warrant|arrest)\b', re.I)
    negation_pattern = re.compile(r"\b(no|not|none|without|isn't|doesn't)\b", re.I)
    urgency_matches = []
    for match in urgency_pattern.finditer(text):
        preceding_words = re.findall(r"\b[\w']+\b", text[:match.start()])[-3:]
        if not negation_pattern.search(" ".join(preceding_words)):
            urgency_matches.append(match.group(1))
    urgency_triggered = bool(urgency_matches)
    if urgency_triggered:
        flags.append("High-pressure urgency or threat indicators detected.")
        score += 35

    # 2. Financial demands / UPI / suspicious payments
    payment_matches = re.findall(r'(@[a-zA-Z]{3,}|upi|paytm|gpay|transfer ₹?\s*[\d,]+)', text, re.I)
    payment_triggered = bool(payment_matches)
    payment_handles = [
        match
        for match in payment_matches
        if match.startswith("@") or match.lower() in {"upi", "paytm", "gpay"}
    ]
    amounts = []
    for match in payment_matches:
        amount_match = re.search(r'(?:₹\s*|Rs\.?\s*|INR\s*)?[\d,]+(?:\.\d+)?', match, re.I)
        if amount_match:
            amount = amount_match.group(0).strip()
            if amount not in amounts:
                amounts.append(amount)
    if payment_triggered:
        flags.append("Direct digital payment / UPI request present.")
        score += 35

    # 3. Suspicious / Non-official link
    urls = re.findall(r'https?://\S+', text)
    link_candidates = re.findall(
        r'(?:https?://\S+|\b(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|cutt\.ly)/\S+)',
        text,
        re.I,
    )
    suspicious_urls = [
        u for u in link_candidates
        if not (".gov.in" in u or ".nic.in" in u or ".ac.in" in u)
    ]
    if suspicious_urls:
        flags.append(f"Non-governmental/unverified external link found: {suspicious_urls[0]}")
        score += 25

    return {
        "rule_score": min(score, 100),
        "flags": flags,
        "extracted_urls": urls,
        "amounts": amounts,
        "payment_handles": payment_handles,
        "urgency_phrases": urgency_matches,
        "rule_breakdown": [
            {
                "rule": "Urgent deadline or coercion",
                "points": 35,
                "triggered": urgency_triggered,
                "evidence": ", ".join(urgency_matches),
                "explanation": (
                    "High-pressure urgency or threat indicators detected."
                    if urgency_triggered
                    else "No urgency or coercive threat indicator detected."
                ),
            },
            {
                "rule": "Financial demand or digital payment",
                "points": 35,
                "triggered": payment_triggered,
                "evidence": ", ".join(payment_matches),
                "explanation": (
                    "Direct digital payment / UPI request present."
                    if payment_triggered
                    else "No direct digital payment or UPI request detected."
                ),
            },
            {
                "rule": "Suspicious external link",
                "points": 25,
                "triggered": bool(suspicious_urls),
                "evidence": suspicious_urls[0] if suspicious_urls else "",
                "explanation": (
                    f"Non-governmental/unverified external link found: {suspicious_urls[0]}"
                    if suspicious_urls
                    else "No suspicious external link detected."
                ),
            },
        ],
    }