
import math
import re
from urllib.parse import urlparse

# Curated institutional domains frequently spoofed in fraud campaigns
OFFICIAL_DOMAINS = {
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "incometax": "incometax.gov.in",
    "indiapost": "indiapost.gov.in",
    "cybercrime": "cybercrime.gov.in",
    "ecourts": "ecourts.gov.in",
    "epfo": "epfindia.gov.in",
    "uidai": "uidai.gov.in",
    "chase": "chase.com",
    "paypal": "paypal.com",
}

ABUSE_TLDS = {
    ".top", ".buzz", ".xyz", ".icu", ".rest", ".tk",
    ".ml", ".ga", ".cf", ".cc", ".site", ".work",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co",
    "cutt.ly", "rb.gy", "shorturl.at",
}

NEGATION_PATTERN = re.compile(
    r"\b(?:no|not|none|without|isn't|doesn't|never|cannot)\b",
    re.I,
)

AMOUNT_PATTERN = re.compile(
    r"(?:₹\s*|rs\.?\s*|inr\s*)\d[\d,]*(?:\.\d+)?"
    r"|\b\d[\d,]*(?:\.\d+)?\s*(?:rupees|rs\.?)\b",
    re.I,
)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance without external dependencies."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if not s2:
        return len(s1)

    previous_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        current_row = [i + 1]

        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)

            current_row.append(
                min(insertions, deletions, substitutions)
            )

        previous_row = current_row

    return previous_row[-1]


def _deconstruct_url(raw_url: str) -> list[dict]:
    """Detect suspicious URL structure and possible institutional impersonation."""
    flags = []

    clean_url = (
        raw_url
        if raw_url.startswith(("http://", "https://"))
        else "http://" + raw_url
    )

    try:
        parsed = urlparse(clean_url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return flags

    if not host:
        return flags

    # 1. Direct IP address instead of a domain
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}", host
    ):
        flags.append({
            "type": "RAW_IP",
            "evidence": raw_url,
            "detail": (
                f"Directs to a numerical IP address ({host}) "
                "rather than an institutional domain."
            ),
            "weight": 35,
        })

    # 2. Known link shorteners
    if host in SHORTENERS:
        flags.append({
            "type": "SHORTENER",
            "evidence": raw_url,
            "detail": (
                f"Uses link shortener '{host}', which conceals "
                "the destination until the link is opened."
            ),
            "weight": 25,
        })

    # 3. High-abuse top-level domains
    matched_tlds = [
        tld for tld in ABUSE_TLDS if host.endswith(tld)
    ]

    if matched_tlds:
        tld_matched = max(matched_tlds, key=len)

        flags.append({
            "type": "ABUSE_TLD",
            "evidence": raw_url,
            "detail": (
                f"Uses a domain ending in '{tld_matched}', "
                "which warrants additional scrutiny."
            ),
            "weight": 25,
        })

    # 4. Brand impersonation and typosquatting
    host_parts = host.split(".")
    core_host = (
        host_parts[-2] if len(host_parts) >= 2 else host_parts[0]
    )

    for brand, legit_domain in OFFICIAL_DOMAINS.items():
        legit_core = legit_domain.split(".")[0]

        is_official_domain = (
            host == legit_domain
            or host.endswith("." + legit_domain)
        )

        # A brand name embedded in an unrelated hostname
        if brand in host and not is_official_domain:
            flags.append({
                "type": "SUBDOMAIN_TRAP",
                "evidence": raw_url,
                "detail": (
                    f"Brand name '{brand}' appears in unrelated "
                    f"hostname '{host}'."
                ),
                "weight": 40,
            })

        distance = _levenshtein_distance(
            core_host, legit_core
        )

        if (
            1 <= distance <= 2
            and core_host != legit_core
            and len(core_host) >= 4
            and host not in SHORTENERS
        ):
            flags.append({
                "type": "TYPOSQUATTING",
                "evidence": raw_url,
                "detail": (
                    f"Hostname '{host}' resembles legitimate "
                    f"domain '{legit_domain}' "
                    f"(edit distance: {distance})."
                ),
                "weight": 35,
            })

    return flags


def calculate_calibrated_score(raw_points: int) -> tuple[int, str]:
    """Convert raw risk points to a saturated 0-100 score."""
    if raw_points <= 0:
        return 0, "LOW"

    score = round(
        100 * (1.0 - math.exp(-raw_points / 38.0))
    )
    score = max(0, min(score, 100))

    if score < 25:
        level = "LOW"
    elif score < 65:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return score, level


def _keyword_matches(
    text: str,
    pattern: re.Pattern,
    negation_pattern: re.Pattern,
) -> list[str]:
    """Return matches unless nearby preceding words indicate negation."""
    matches = []

    for match in pattern.finditer(text):
        preceding_words = re.findall(
            r"\b[\w']+\b", text[:match.start()]
        )[-3:]

        if not negation_pattern.search(
            " ".join(preceding_words)
        ):
            matches.append(match.group(0))

    return list(dict.fromkeys(matches))


def analyze_rules(text: str) -> dict:
    """Run deterministic checks and return the existing API-compatible result."""
    text = text or ""

    raw_points = 0
    active_flags = []

    extracted_urls = re.findall(
        r"https?://[^\s<>'\"]+",
        text,
        re.I,
    )

    # 1. Urgency, coercion and threats
    urgency_pattern = re.compile(
        r"\b("
        r"immediate(?:ly)?|within\s+\d+\s*hours?|"
        r"today|urgent(?:ly)?|"
        r"only\s+\d+\s+(?:slots?|seats?|positions?)\s+left|"
        r"limited\s+(?:slots?|seats?|time)|"
        r"deadline|expires?\s+(?:today|soon|in)|"
        r"warrant|arrest|custody|seized|freeze|blocked|"
        r"disconnection|penalty|non-bailable|fir registered"
        r")\b",
        re.I,
    )

    urgency_matches = _keyword_matches(
        text, urgency_pattern, NEGATION_PATTERN
    )

    urgency_triggered = bool(urgency_matches)
    urgency_weight = 35 if urgency_triggered else 0
    raw_points += urgency_weight

    if urgency_triggered:
        active_flags.append(
            "High-pressure urgency or legal intimidation detected."
        )

    # 2. Financial demands and payment methods
    payment_pattern = re.compile(
        r"@[a-zA-Z0-9._-]{3,}"
        r"|upi|paytm|gpay|phonepe"
        r"|(?:pay|deposit|transfer|send|remit|submit|"
        r"charge|fee|payment)\b"
        r".{0,60}?"
        r"(?:₹\s*\d[\d,]*(?:\.\d+)?"
        r"|rs\.?\s*\d[\d,]*(?:\.\d+)?"
        r"|inr\s*\d[\d,]*(?:\.\d+)?"
        r"|\b\d[\d,]*(?:\.\d+)?\s*(?:rupees|rs\.?)\b)",
        re.I,
    )

    payment_matches = _keyword_matches(
        text, payment_pattern, NEGATION_PATTERN
    )

    payment_handles = [
        match for match in payment_matches
        if match.startswith("@")
        or match.lower() in {
            "upi", "paytm", "gpay", "phonepe"
        }
    ]

    amounts = list(dict.fromkeys(
        match.group(0).strip()
        for match in AMOUNT_PATTERN.finditer(text)
    ))

    payment_triggered = bool(payment_matches)
    payment_weight = 35 if payment_triggered else 0
    raw_points += payment_weight

    if payment_triggered:
        active_flags.append(
            "Financial demand or digital payment indicator detected."
        )

    # 3. URL analysis
    link_candidates = re.findall(
        r"https?://[^\s<>'\"]+"
        r"|\b(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|"
        r"cutt\.ly|rb\.gy|shorturl\.at)/[^\s<>'\"]+",
        text,
        re.I,
    )

    url_findings = []
    suspicious_urls = []

    for candidate in link_candidates:
        candidate = candidate.rstrip(".,;:!?)\"]}")
        findings = _deconstruct_url(candidate)

        if findings:
            url_findings.extend(findings)
            suspicious_urls.append(candidate)
            continue

        clean_candidate = (
            candidate
            if candidate.startswith(("http://", "https://"))
            else "http://" + candidate
        )

        try:
            parsed_host = (
                urlparse(clean_candidate).hostname or ""
            ).lower().rstrip(".")
        except Exception:
            parsed_host = ""

        is_institutional = any(
            parsed_host == suffix.lstrip(".")
            or parsed_host.endswith(suffix)
            for suffix in (
                ".gov.in", ".nic.in", ".ac.in", ".edu"
            )
        )

        if not is_institutional:
            suspicious_urls.append(candidate)

    suspicious_urls = list(dict.fromkeys(suspicious_urls))

    link_triggered = bool(url_findings or suspicious_urls)

    link_weight = (
        max(
            (finding["weight"] for finding in url_findings),
            default=25,
        )
        if link_triggered else 0
    )

    raw_points += link_weight

    if url_findings:
        active_flags.append(
            f"Deceptive URL indicator: {url_findings[0]['detail']}"
        )
    elif suspicious_urls:
        active_flags.append(
            f"Unverified external link found: {suspicious_urls[0]}"
        )

    # 4. OTP, Aadhaar and credential harvesting
    credential_pattern = re.compile(
        r"\b("
        r"otp|one[- ]time password|verification code|mpin|"
        r"m[- ]?pin|aadhaar|aadhar|uidai|"
        r"share (?:your )?(?:otp|pin|password|mpin)|"
        r"send (?:the )?(?:otp|verification code)|"
        r"confirm (?:your )?otp|"
        r"verify (?:your )?(?:aadhaar|aadhar|kyc)|"
        r"e[- ]?kyc|complete (?:your )?kyc|"
        r"(?:photo|copy|scan) of (?:your )?(?:aadhaar|aadhar|pan)"
        r")\b",
        re.I,
    )

    credential_matches = _keyword_matches(
        text, credential_pattern, NEGATION_PATTERN
    )

    credential_triggered = bool(credential_matches)
    credential_weight = 35 if credential_triggered else 0
    raw_points += credential_weight

    if credential_triggered:
        active_flags.append(
            "Request involving OTP, Aadhaar, or sensitive credentials detected."
        )

    # 5. Courier and customs impersonation
    courier_pattern = re.compile(
        r"\b("
        r"customs (?:fee|duty|clearance|charge)|"
        r"clearance (?:fee|charge|payment)|"
        r"consignment (?:held|blocked|detained|seized)|"
        r"parcel (?:held|detained|on hold|blocked)|"
        r"international (?:parcel|shipment|package).{0,40}"
        r"(?:fee|customs|clearance|pay)|"
        r"(?:pay|deposit).{0,30}"
        r"(?:customs|clearance) (?:fee|charge)|"
        r"courier (?:clearance|customs) (?:fee|charge)"
        r")\b",
        re.I,
    )

    courier_matches = courier_pattern.findall(text)
    courier_triggered = bool(courier_matches)
    courier_weight = 30 if courier_triggered else 0
    raw_points += courier_weight

    if courier_triggered:
        active_flags.append(
            "Courier or customs clearance-fee pattern detected."
        )

    # 6. Job, recruitment and prize lures
    job_pattern = re.compile(
        r"\b("
        r"work from home|wfh|"
        r"remote.{0,40}(?:internship|job|work|position|role)|"
        r"(?:software developer|data analyst|developer|"
        r"engineering|paid|unpaid).{0,35}internship|"
        r"(?:internship|job|recruitment|employment).{0,50}"
        r"(?:security fee|registration fee|processing fee|"
        r"deposit|training kit|payment|shortlisted)|"
        r"(?:security fee|registration fee|processing fee|"
        r"refundable fee|training kit).{0,50}"
        r"(?:internship|job|recruitment|position|role|"
        r"deposit|pay|₹|rs\.?)|"
        r"(?:job|interview|registration|processing|security) fee|"
        r"pay (?:to )?(?:join|register|apply|start)|"
        r"refundable.{0,30}(?:fee|deposit|security)|"
        r"shortlisted.{0,40}(?:job|internship|position|role)|"
        r"selected for (?:a )?(?:job|internship|position|role)|"
        r"whatsapp (?:job|interview|task|recruitment)|"
        r"task[- ]based (?:job|earning|work)|"
        r"earn ₹?\s*[\d,]+.{0,15}(?:daily|per day|per week|monthly)|"
        r"(?:won|winner).{0,25}(?:prize|lottery|reward)"
        r")\b",
        re.I,
    )

    job_matches = job_pattern.findall(text)
    job_triggered = bool(job_matches)
    job_weight = 30 if job_triggered else 0
    raw_points += job_weight

    if job_triggered:
        active_flags.append(
            "Job, recruitment, or prize-lure language detected."
        )

    # 7. Calibrated score and API-compatible rule breakdown
    calibrated_score, risk_level = calculate_calibrated_score(
        raw_points
    )

    rule_breakdown = [
        {
            "rule": "Urgent deadline or coercion",
            "points": urgency_weight,
            "triggered": urgency_triggered,
            "evidence": ", ".join(urgency_matches),
            "explanation": (
                "Coercive urgency or deadline indicators detected."
                if urgency_triggered
                else "No coercive deadline or threat keywords found."
            ),
        },
        {
            "rule": "Financial demand or digital payment",
            "points": payment_weight,
            "triggered": payment_triggered,
            "evidence": ", ".join(payment_matches),
            "explanation": (
                "Financial demand or payment indicator found."
                if payment_triggered
                else "No matching financial demand or payment indicator found."
            ),
        },
        {
            "rule": "Suspicious external link",
            "points": link_weight,
            "triggered": link_triggered,
            "evidence": suspicious_urls[0] if suspicious_urls else "",
            "explanation": (
                url_findings[0]["detail"]
                if url_findings
                else (
                    f"Unverified external URL detected: {suspicious_urls[0]}"
                    if suspicious_urls
                    else "No deceptive or unverified links found."
                )
            ),
        },
        {
            "rule": "OTP, Aadhaar, or credential request",
            "points": credential_weight,
            "triggered": credential_triggered,
            "evidence": ", ".join(credential_matches),
            "explanation": (
                "Sensitive credential-related language detected."
                if credential_triggered
                else "No matching credential-harvesting language found."
            ),
        },
        {
            "rule": "Courier or customs hold scam",
            "points": courier_weight,
            "triggered": courier_triggered,
            "evidence": ", ".join(dict.fromkeys(courier_matches)),
            "explanation": (
                "Courier or customs clearance-fee indicators detected."
                if courier_triggered
                else "No courier or customs clearance patterns found."
            ),
        },
        {
            "rule": "Job or recruitment scam lure",
            "points": job_weight,
            "triggered": job_triggered,
            "evidence": ", ".join(job_matches),
            "explanation": (
                "Job, recruitment, or prize-lure indicators detected."
                if job_triggered
                else "No matching job recruitment or prize-lure patterns found."
            ),
        },
    ]

    return {
        "rule_score": calibrated_score,
        "raw_points": raw_points,
        "risk_level": risk_level,
        "flags": active_flags,
        "extracted_urls": extracted_urls,
        "amounts": amounts,
        "payment_handles": payment_handles,
        "urgency_phrases": urgency_matches,
        "rule_breakdown": rule_breakdown,
    }
