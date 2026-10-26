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

KNOWN_GOOD_DOMAINS = {
    "google.com", "gmail.com", "github.com", "microsoft.com",
    "amazon.com", "amazon.in", "apple.com", "facebook.com",
    "instagram.com", "linkedin.com", "netflix.com", "dropbox.com",
    "whatsapp.com", "meta.com", "paypal.com", "x.com",
    "outlook.com", "office.com", "icloud.com",
}

ABUSE_TLDS = {
    ".top", ".buzz", ".xyz", ".icu", ".rest", ".tk",
    ".ml", ".ga", ".cf", ".cc", ".site", ".work",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co",
    "cutt.ly", "rb.gy", "shorturl.at",
}

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def detect_language(text: str) -> str:
    """Return "hi" when more than ~20% of the letters are Devanagari, else "en"."""
    if not text:
        return "en"
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return "en"
    devanagari = sum(0x0900 <= ord(ch) <= 0x097F for ch in letters)
    return "hi" if devanagari / len(letters) > 0.20 else "en"


# ---------------------------------------------------------------------------
# Word-boundary helpers.
# Python's \b treats Devanagari vowel signs (ी ा े ें ं ्) as NON-word
# characters, so \b(...)\b silently fails on many Hindi words. These
# lookarounds treat Devanagari letters AND signs as word characters.
# The danda (।, U+0964) and double danda (U+0965) are deliberately excluded
# so they still act as sentence boundaries.
# ---------------------------------------------------------------------------
DEV = r"ऀ-ॣ०-ॿ"
WB_START = r"(?<![\w" + DEV + r"])"
WB_END = r"(?![\w" + DEV + r"])"

# One negation pattern. Every alternative is boundary-safe, so "know",
# "casino", "मतलब", "भुगतान करें" etc. do not count as negation.
NEGATION_PATTERN = re.compile(
    r"(?:"
    r"\b(?:no|not|none|without|never|cannot|isn['’]t|doesn['’]t|don['’]t|"
    r"nahi|nahin|nhi|mat|bina|kabhi)\b"
    r"|"
    r"(?<![" + DEV + r"])(?:नहीं|कभी|बिना|मत)(?![" + DEV + r"])"
    r"|"
    r"(?<![" + DEV + r"])न\s+"
    r"(?:करें|करे|दे|दें|जमा|मांगें|मांगे|मांगते|साझा|भेजें|भेजे|रखें|रखे)"
    r"(?![" + DEV + r"])"
    r")",
    re.I | re.UNICODE,
)

# Amount: "₹500", "Rs. 500", "INR 500", "500 rupees", "500 रुपये"
# "rs" / "inr" must not be the tail of another word (e.g. "hours 2").
_AMT = (
    r"(?:"
    r"(?:₹|(?<![A-Za-z])rs\.?|(?<![A-Za-z])inr|रुपये|रु)\s*\d[\d,]*(?:\.\d+)?"
    r"|"
    r"\d[\d,]*(?:\.\d+)?\s*(?:rupees|rupaye|rs\.?|रुपये|रु)(?![A-Za-z])"
    r")"
)

AMOUNT_PATTERN = re.compile(_AMT, re.I | re.UNICODE)

# UPI-style handle such as name@okaxis (but not an email like a@gmail.com)
HANDLE_PATTERN = re.compile(
    r"(?<![\w.\-@])[\w.\-]{2,}@[A-Za-z]{2,}\b(?!\.[A-Za-z])"
)

# ---------------------------------------------------------------------------
# Display text (English / Hindi). Keys of the returned dict never change;
# only the human-readable strings switch language.
# ---------------------------------------------------------------------------
RULE_NAMES = {
    "urgency": ("Urgent deadline or coercion", "तुरंत कार्रवाई का दबाव या धमकी"),
    "payment": ("Financial demand or digital payment", "पैसे की मांग या डिजिटल भुगतान"),
    "link": ("Suspicious external link", "संदिग्ध बाहरी लिंक"),
    "credential": ("OTP, Aadhaar, or credential request", "OTP, आधार या पासवर्ड की मांग"),
    "courier": ("Courier or customs hold scam", "कूरियर या कस्टम होल्ड स्कैम"),
    "job": ("Job or recruitment scam lure", "नौकरी या भर्ती स्कैम का लालच"),
}

FLAG_TEXT = {
    "urgency": (
        "High-pressure urgency or legal intimidation detected.",
        "तुरंत कार्रवाई का दबाव या कानूनी धमकी के संकेत मिले।",
    ),
    "payment": (
        "Financial demand or digital payment indicator detected.",
        "पैसे की मांग या डिजिटल भुगतान का संकेत मिला।",
    ),
    "credential": (
        "Request involving OTP, Aadhaar, or sensitive credentials detected.",
        "OTP, आधार या संवेदनशील जानकारी मांगने का संकेत मिला।",
    ),
    "courier": (
        "Courier or customs clearance-fee pattern detected.",
        "कूरियर या कस्टम क्लीयरेंस शुल्क जैसा पैटर्न मिला।",
    ),
    "job": (
        "Job, recruitment, or prize-lure language detected.",
        "नौकरी, भर्ती या इनाम के लालच जैसी भाषा मिली।",
    ),
}

EXPLAIN_TEXT = {
    "urgency": (
        ("Coercive urgency or deadline indicators detected.",
         "No coercive deadline or threat keywords found."),
        ("तुरंत कार्रवाई या धमकी के संकेत मिले।",
         "कोई धमकी या जल्दबाजी वाले शब्द नहीं मिले।"),
    ),
    "payment": (
        ("Financial demand or payment indicator found.",
         "No matching financial demand or payment indicator found."),
        ("पैसे की मांग या भुगतान का संकेत मिला।",
         "पैसे की मांग या भुगतान का कोई संकेत नहीं मिला।"),
    ),
    "credential": (
        ("Sensitive credential-related language detected.",
         "No matching credential-harvesting language found."),
        ("OTP, आधार या पासवर्ड जैसी संवेदनशील जानकारी मांगने की भाषा मिली।",
         "संवेदनशील जानकारी मांगने वाली भाषा नहीं मिली।"),
    ),
    "courier": (
        ("Courier or customs clearance-fee indicators detected.",
         "No courier or customs clearance patterns found."),
        ("कूरियर या कस्टम क्लीयरेंस शुल्क के संकेत मिले।",
         "कूरियर या कस्टम से जुड़ा कोई पैटर्न नहीं मिला।"),
    ),
    "job": (
        ("Job, recruitment, or prize-lure indicators detected.",
         "No matching job recruitment or prize-lure patterns found."),
        ("नौकरी, भर्ती या इनाम के लालच के संकेत मिले।",
         "नौकरी या इनाम के लालच का कोई पैटर्न नहीं मिला।"),
    ),
}


def _pick(pair: tuple, lang: str) -> str:
    return pair[1] if lang == "hi" else pair[0]


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


def _get_reputable_core(host: str) -> str:
    """Return the registrable core for a hostname, ignoring common public suffixes."""
    normalized = host.lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    suffixes = (
        "co.in", "gov.in", "nic.in", "ac.in", "edu.in",
        "co.uk", "com.au", "co.jp",
        "com", "org", "net", "gov", "edu", "info", "io",
    )

    for suffix in sorted(suffixes, key=len, reverse=True):
        if normalized == suffix:
            return ""
        if normalized.endswith("." + suffix):
            return normalized[: -(len(suffix) + 1)].split(".")[-1]

    return normalized.split(".")[-1] if normalized else ""


def _is_known_good_domain(host: str) -> bool:
    """Return True for official or reputable domains that should not be flagged by default."""
    if not host:
        return False

    normalized = host.lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    if normalized in KNOWN_GOOD_DOMAINS:
        return True

    if any(
        normalized == domain or normalized.endswith("." + domain)
        for domain in OFFICIAL_DOMAINS.values()
    ):
        return True

    return False


def _deconstruct_url(raw_url: str) -> list[dict]:
    """Detect suspicious URL structure and possible institutional impersonation.

    Each finding keeps the original "detail" (English) and adds "detail_hi".
    """
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

    if _is_known_good_domain(host):
        return flags

    # 1. Direct IP address instead of a domain
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        flags.append({
            "type": "RAW_IP",
            "evidence": raw_url,
            "detail": (
                f"Directs to a numerical IP address ({host}) "
                "rather than an institutional domain."
            ),
            "detail_hi": (
                f"लिंक किसी संस्था के डोमेन की जगह सीधे IP पता ({host}) पर ले जाता है।"
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
            "detail_hi": (
                f"'{host}' जैसा छोटा लिंक इस्तेमाल हुआ है, जो खोलने से पहले असली "
                "वेबसाइट छिपा देता है।"
            ),
            "weight": 25,
        })

    # 3. High-abuse top-level domains
    matched_tlds = [tld for tld in ABUSE_TLDS if host.endswith(tld)]

    if matched_tlds:
        tld_matched = max(matched_tlds, key=len)

        flags.append({
            "type": "ABUSE_TLD",
            "evidence": raw_url,
            "detail": (
                f"Uses a domain ending in '{tld_matched}', "
                "which warrants additional scrutiny."
            ),
            "detail_hi": (
                f"डोमेन '{tld_matched}' पर खत्म होता है, जो अक्सर धोखाधड़ी में "
                "इस्तेमाल होता है, इसलिए सावधानी रखें।"
            ),
            "weight": 25,
        })

    # 4. Brand impersonation and typosquatting
    core_host = _get_reputable_core(host)
    host_tokens = [t for t in re.split(r"[.\-_]", host) if t]

    for brand, legit_domain in OFFICIAL_DOMAINS.items():
        legit_core = legit_domain.split(".")[0]

        is_official_domain = (
            host == legit_domain
            or host.endswith("." + legit_domain)
        )

        # Brand used as a whole label, or at the start of a label
        # (sbi-kyc.top, sbikyc.top, hdfcbank-login.xyz). A plain substring
        # test would wrongly flag words like "purchase" for "chase".
        brand_in_host = any(
            token == brand or token.startswith(brand)
            for token in host_tokens
        )

        if brand_in_host and not is_official_domain:
            flags.append({
                "type": "SUBDOMAIN_TRAP",
                "evidence": raw_url,
                "detail": (
                    f"Brand name '{brand}' appears in unrelated "
                    f"hostname '{host}'."
                ),
                "detail_hi": (
                    f"'{brand}' नाम एक असंबंधित वेबसाइट '{host}' में इस्तेमाल हुआ है।"
                ),
                "weight": 40,
            })

        distance = _levenshtein_distance(core_host, legit_core)

        # Short brands only tolerate 1 edit, and a shorter look-alike
        # (case.com vs chase.com) is ignored to avoid ordinary words.
        max_distance = 1 if len(legit_core) <= 6 else 2
        short_brand_too_short = (
            len(legit_core) <= 5 and len(core_host) < len(legit_core)
        )

        if (
            1 <= distance <= max_distance
            and core_host and core_host != legit_core
            and len(core_host) >= 4
            and not short_brand_too_short
            and not is_official_domain
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
                "detail_hi": (
                    f"वेबसाइट '{host}' असली डोमेन '{legit_domain}' से मिलती-जुलती "
                    f"नकली लगती है (अंतर: {distance} अक्षर)।"
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


def _clause_around(text: str, start: int, end: int, pad: int = 50) -> str:
    """Return the text near a match, limited to the same sentence/clause.

    A negation in a different sentence ("Do not worry. Pay Rs 500 now.")
    must not cancel a detection in this one.
    """
    seps = ".!?।;\n"
    left = max(text.rfind(c, 0, start) for c in seps) + 1
    rights = [i for i in (text.find(c, end) for c in seps) if i != -1]
    right = min(rights) if rights else len(text)
    return text[max(left, start - pad):min(right, end + pad)]


def _keyword_matches(
    text: str,
    pattern: re.Pattern,
    negation_pattern: re.Pattern,
) -> list[str]:
    """Return matches unless the same clause clearly negates them."""
    matches = []

    for match in pattern.finditer(text):
        local_context = _clause_around(text, match.start(), match.end())

        if negation_pattern.search(local_context):
            continue

        matches.append(match.group(0))

    return list(dict.fromkeys(matches))


def analyze_rules(text: str, lang: str | None = None) -> dict:
    """Run deterministic checks and return the existing API-compatible result.

    `lang` ("en" / "hi") controls only the display strings. When omitted it is
    detected from the text. All existing keys are unchanged; new keys are
    "language" and, per breakdown row, "rule_hi".
    """
    text = text or ""
    lang = lang if lang in ("en", "hi") else detect_language(text)

    raw_points = 0
    active_flags = []

    extracted_urls = re.findall(
        r"https?://[^\s<>'\"]+",
        text,
        re.I,
    )

    # 1. Urgency, coercion and threats
    urgency_pattern = re.compile(
        WB_START + r"("
        r"immediate(?:ly)?|within\s+\d+\s*hours?|"
        r"urgent(?:ly)?|"
        r"only\s+\d+\s+(?:slots?|seats?|positions?)\s+left|"
        r"limited\s+(?:slots?|seats?|time)|"
        r"deadline|expires?\s+(?:today|soon|in)|"
        r"warrant|arrest|custody|seized|freeze|blocked|block\s+ho\w*|"
        r"suspend(?:ed)?|"
        r"disconnection|penalty|non-bailable|fir registered|"
        r"(?:2\s*hours?|\d+\s*hours?|2\s*घंटे|\d+\s*घंटे|दो\s*घंटे|एक\s*घंटे)|"
        # Hinglish (Roman-script Hindi)
        r"turant|foran|"
        r"(?:abhi|jaldi)\s+(?:pay|bhej\w*|share|verify|karein|kare|karo|click|jama)|"
        # Hindi
        r"(?:तुरंत|फौरन|जरूरी|कानूनी|गिरफ्तारी|अरेस्ट|कैद|फ्रीज|ब्लॉक|पेनल्टी|"
        r"निलंबित|निलंबन|सस्पेंड|सस्पेंडेड|अवरोधित|खाता\s*(?:निलंबित|बंद|ब्लॉक)|"
        r"तुरंत\s*ही|"
        r"(?:आज|अभी|जल्दी)\s*(?:ही\s*)?(?:भुगतान|जमा|भेजें|भेजो|साझा|क्लिक|वेरीफाई|अपडेट))"
        r")" + WB_END,
        re.I | re.UNICODE,
    )

    urgency_matches = _keyword_matches(
        text, urgency_pattern, NEGATION_PATTERN
    )
    
    hindi_coercion_pattern = re.compile(
        r"(?:"
        r"भुगतान\s+नहीं\s+करने\s+पर"
        r"|ऑफर\s+रद्द\s+कर\s+दिया\s+जाएगा"
        r"|जल्दी\s+करें"
        r")",
        re.I | re.UNICODE,
    )

    hindi_coercion_matches = [
        match.group(0)
        for match in hindi_coercion_pattern.finditer(text)
    ]

    urgency_matches = list(
        dict.fromkeys(urgency_matches + hindi_coercion_matches)
    )


    urgency_triggered = bool(urgency_matches)
    urgency_weight = 35 if urgency_triggered else 0
    raw_points += urgency_weight

    if urgency_triggered:
        active_flags.append(_pick(FLAG_TEXT["urgency"], lang))

    # 2. Financial demand / digital payment
    payment_keyword = (
        r"(?:@[a-zA-Z0-9._-]{3,}|"
        + WB_START
        + r"(?:upi|paytm|gpay|phonepe|pay\w*|deposit\w*|transfer\w*|send|"
        r"remit\w*|submit|charge\w*|fees?|wallet|bhugtan|"
        r"जमा|भुगतान|पेमेंट|फीस|शुल्क|ट्रांसफर|भेजें|भेजो|राशि|अमाउंट|कस्टम|क्लीयरेंस))"
    )
    payment_verb = (
        WB_START
        + r"(?:जमा|भुगतान|पेमेंट|फीस|शुल्क|ट्रांसफर|भेजें|भेजो|भेजिए|चुकाएं|चुकाओ|सेंड|"
        r"pay\w*|deposit\w*|transfer\w*|send|submit|charge\w*|remit\w*|refund|"
        r"bhugtan|bhej\w*|jama|chukao)"
        + WB_END
    )

    payment_pattern = re.compile(
        r"(?:"
        + payment_keyword + r".{0,80}?" + _AMT
        + r"|"
        + _AMT + r".{0,60}?" + payment_verb
        + r"|"
        + payment_verb + r".{0,80}?" + _AMT
        + r")",
        re.I | re.UNICODE,
    )

    payment_matches = _keyword_matches(
        text, payment_pattern, NEGATION_PATTERN
    )

    payment_handles = list(dict.fromkeys(
        [h for h in HANDLE_PATTERN.findall(text)]
        + [
            match for match in payment_matches
            if match.lower() in {"upi", "paytm", "gpay", "phonepe"}
        ]
    ))

    amounts = list(dict.fromkeys(
        match.group(0).strip()
        for match in AMOUNT_PATTERN.finditer(text)
    ))

    payment_triggered = bool(payment_matches)
    payment_weight = 35 if payment_triggered else 0
    raw_points += payment_weight

    if payment_triggered:
        active_flags.append(_pick(FLAG_TEXT["payment"], lang))

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

    detail_key = "detail_hi" if lang == "hi" else "detail"

    if url_findings:
        prefix = "भ्रामक URL का संकेत: " if lang == "hi" else "Deceptive URL indicator: "
        active_flags.append(prefix + url_findings[0][detail_key])
    elif suspicious_urls:
        prefix = "अनजान बाहरी लिंक मिला: " if lang == "hi" else "Unverified external link found: "
        active_flags.append(prefix + suspicious_urls[0])

    # 4. OTP, Aadhaar and credential harvesting
    credential_pattern = re.compile(
        WB_START + r"("
        r"otp|one[- ]time password|verification code|mpin|"
        r"m[- ]?pin|aadhaar|aadhar|uidai|"
        r"share (?:your )?(?:otp|pin|password|mpin)|"
        r"send (?:the )?(?:otp|verification code)|"
        r"confirm (?:your )?otp|"
        r"verify (?:your )?(?:aadhaar|aadhar|kyc)|"
        r"e[- ]?kyc|complete (?:your )?kyc|"
        r"(?:photo|copy|scan) of (?:your )?(?:aadhaar|aadhar|pan)|"
        r"(?:password|passcode|pin|kyc|"
        r"पासवर्ड|ओटीपी|पिन|एमपिन|आधार|यूआईडीएआई|केवाईसी)"
        r"(?:\s+(?:कृपया|कृप्या|दें|मांगें|दे|जमा|भेजें|लिखें|चेक|बनाएं|बनाओ|करें|साझा\s*करें))?"
        r")" + WB_END,
        re.I | re.UNICODE,
    )

    credential_matches = _keyword_matches(
        text, credential_pattern, NEGATION_PATTERN
    )

    credential_triggered = bool(credential_matches)
    credential_weight = 35 if credential_triggered else 0
    raw_points += credential_weight

    if credential_triggered:
        active_flags.append(_pick(FLAG_TEXT["credential"], lang))

    # 5. Courier and customs impersonation
    courier_pattern = re.compile(
        WB_START + r"("
        r"customs (?:fee|duty|clearance|charge)|"
        r"clearance (?:fee|charge|payment)|"
        r"consignment (?:held|blocked|detained|seized)|"
        r"parcel (?:held|detained|on hold|blocked)|"
        r"international (?:parcel|shipment|package).{0,40}"
        r"(?:fee|customs|clearance|pay)|"
        r"(?:pay|deposit).{0,30}"
        r"(?:customs|clearance) (?:fee|charge)|"
        r"courier (?:clearance|customs) (?:fee|charge)|"
        r"(?:कस्टम|कस्टम्स|कूरियर|पार्सल|शिपमेंट|कैरियर|डिलीवरी).{0,45}"
        r"(?:फीस|शुल्क|चार्ज|पेमेंट|भुगतान|जमा|क्लीयरेंस)|"
        r"(?:फीस|शुल्क|चार्ज|पेमेंट|भुगतान|जमा).{0,35}"
        r"(?:कस्टम|क्लीयरेंस|पार्सल|कूरियर|शिपमेंट)"
        r")" + WB_END,
        re.I | re.UNICODE,
    )

    courier_matches = courier_pattern.findall(text)
    courier_triggered = bool(courier_matches)
    courier_weight = 30 if courier_triggered else 0
    raw_points += courier_weight

    if courier_triggered:
        active_flags.append(_pick(FLAG_TEXT["courier"], lang))

    # 6. Job, recruitment and prize lures
    job_pattern = re.compile(
        WB_START + r"("
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
        r"(?:won|winner).{0,25}(?:prize|lottery|reward)|"
        r"(?:internship|job|recruitment|employment|vacancy|role|position|work from home|home based).{0,60}"
        r"(?:फीस|शुल्क|जमा|भुगतान|पेमेंट|रजिस्ट्रेशन|प्रक्रिया|ट्रेनिंग)|"
        r"(?:रजिस्ट्रेशन|जॉब|इंटर्नशिप|कोर्स|पोज़ीशन).{0,35}"
        r"(?:फीस|शुल्क|जमा|भुगतान|पेमेंट|रजिस्ट्रेशन)|"
        r"(?:₹\s*\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s*(?:रुपये|rs))"
        r".{0,25}(?:दो\s*घंटे|2\s*घंटे|2\s*hours?|घंटे|दिन|daily)|"
        r"(?:इंटर्नशिप|जॉब|रोज़गार|नौकरी|कार्य|कार्यशाला|प्रोजेक्ट|काम).{0,40}"
        r"(?:₹\s*\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s*(?:रुपये|rs)|जमा|भुगतान|पेमेंट|शुल्क|फीस)"
        r".{0,40}(?:दो\s*घंटे|2\s*घंटे|अभी|तुरंत|आज|आज ही)|"
        r"(?:इंटर्नशिप|रजिस्ट्रेशन|जॉब|काम|कार्य).{0,60}"
        r"(?:₹\s*\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s*(?:रुपये|rs)|जमा|भुगतान|पेमेंट|शुल्क|फीस)"
        r".{0,60}(?:अभी|तुरंत|आज|आज ही|दो\s*घंटे|2\s*घंटे)|"
        # Upfront-fee job offers in Hindi ("सिक्योरिटी फीस", "यूनिफॉर्म/आईडी कार्ड" ...)
        r"(?:सिक्योरिटी|सिक्यूरिटी|रजिस्ट्रेशन|प्रोसेसिंग|ज्वाइनिंग|जॉइनिंग|ट्रेनिंग|"
        r"यूनिफॉर्म|आईडी\s*कार्ड|किट)\s*(?:फीस|शुल्क|चार्ज|डिपॉजिट|राशि)|"
        r"(?:चुन\s*ली\s*गई|चुना\s*गया|चयनित|सिलेक्ट|शॉर्टलिस्ट).{0,100}"
        r"(?:फीस|शुल्क|जमा|डिपॉजिट)|"
        r"(?:पद|नौकरी|जॉब|वैकेंसी|ज्वाइनिंग|जॉइनिंग).{0,150}"
        r"(?:फीस|शुल्क|डिपॉजिट).{0,60}(?:जमा|भुगतान|भेज)|"
        r"(?:फीस|शुल्क|डिपॉजिट).{0,80}(?:वापस|रिफंड)"
        r")" + WB_END,
        re.I | re.UNICODE,
    )

    
    hindi_job_fee_pattern = re.compile(
    r"(?:"
    r"नौकरी.{0,40}(?:चुना गया|चुनी गई|चयनित)"
    r"|"
    r"(?:चुना गया|चुनी गई|चयनित).{0,40}नौकरी"
    r"|"
    r"(?:नौकरी|जॉब).{0,50}सिक्योरिटी फीस"
    r"|"
    r"सिक्योरिटी फीस.{0,50}(?:जमा|भुगतान)"
    r")",
    re.I | re.UNICODE,
)

    hindi_job_matches = _keyword_matches(
    text, hindi_job_fee_pattern, NEGATION_PATTERN
)

    job_matches = list(dict.fromkeys(
    _keyword_matches(text, job_pattern, NEGATION_PATTERN)
    + hindi_job_matches
))

    job_triggered = bool(job_matches)
    job_weight = 30 if job_triggered else 0
    raw_points += job_weight

    if job_triggered:
        active_flags.append(_pick(FLAG_TEXT["job"], lang))

    # 7. Calibrated score and API-compatible rule breakdown
    calibrated_score, risk_level = calculate_calibrated_score(
        raw_points
    )

    if url_findings:
        link_explanation = url_findings[0][detail_key]
    elif suspicious_urls:
        link_explanation = (
            f"अनजान बाहरी URL मिला: {suspicious_urls[0]}"
            if lang == "hi"
            else f"Unverified external URL detected: {suspicious_urls[0]}"
        )
    else:
        link_explanation = (
            "कोई भ्रामक या अनजान लिंक नहीं मिला।"
            if lang == "hi"
            else "No deceptive or unverified links found."
        )

    def _explain(key: str, triggered: bool) -> str:
        yes_no = EXPLAIN_TEXT[key][1 if lang == "hi" else 0]
        return yes_no[0] if triggered else yes_no[1]

    rule_breakdown = [
        {
            "rule": RULE_NAMES["urgency"][0],
            "rule_hi": RULE_NAMES["urgency"][1],
            "points": urgency_weight,
            "triggered": urgency_triggered,
            "evidence": ", ".join(urgency_matches),
            "explanation": _explain("urgency", urgency_triggered),
        },
        {
            "rule": RULE_NAMES["payment"][0],
            "rule_hi": RULE_NAMES["payment"][1],
            "points": payment_weight,
            "triggered": payment_triggered,
            "evidence": ", ".join(payment_matches),
            "explanation": _explain("payment", payment_triggered),
        },
        {
            "rule": RULE_NAMES["link"][0],
            "rule_hi": RULE_NAMES["link"][1],
            "points": link_weight,
            "triggered": link_triggered,
            "evidence": suspicious_urls[0] if suspicious_urls else "",
            "explanation": link_explanation,
        },
        {
            "rule": RULE_NAMES["credential"][0],
            "rule_hi": RULE_NAMES["credential"][1],
            "points": credential_weight,
            "triggered": credential_triggered,
            "evidence": ", ".join(credential_matches),
            "explanation": _explain("credential", credential_triggered),
        },
        {
            "rule": RULE_NAMES["courier"][0],
            "rule_hi": RULE_NAMES["courier"][1],
            "points": courier_weight,
            "triggered": courier_triggered,
            "evidence": ", ".join(dict.fromkeys(courier_matches)),
            "explanation": _explain("courier", courier_triggered),
        },
        {
            "rule": RULE_NAMES["job"][0],
            "rule_hi": RULE_NAMES["job"][1],
            "points": job_weight,
            "triggered": job_triggered,
            "evidence": ", ".join(job_matches),
            "explanation": _explain("job", job_triggered),
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
        "language": lang,
    }