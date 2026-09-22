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
    ".top",
    ".buzz",
    ".xyz",
    ".icu",
    ".rest",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".cc",
    ".site",
    ".work",
}
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}


def _levenshtein_distance(s1: str, s2: str) -> int:
  """Pure-Python Levenshtein distance: zero extra C-dependencies, works everywhere."""
  if len(s1) < len(s2):
    return _levenshtein_distance(s2, s1)
  if len(s2) == 0:
    return len(s1)

  previous_row = range(len(s2) + 1)
  for i, c1 in enumerate(s1):
    current_row = [i + 1]
    for j, c2 in enumerate(s2):
      insertions = previous_row[j + 1] + 1
      deletions = current_row[j] + 1
      substitutions = previous_row[j] + (c1 != c2)
      current_row.append(min(insertions, deletions, substitutions))
    previous_row = current_row
  return previous_row[-1]


def _deconstruct_url(raw_url: str) -> list[dict]:
  """Analyzes an extracted URL for deceptive structure, raw IPs, and impersonation."""
  flags = []
  clean_url = (
      raw_url
      if raw_url.startswith(("http://", "https://"))
      else "http://" + raw_url
  )

  try:
    parsed = urlparse(clean_url)
    host = (parsed.hostname or "").lower()
  except Exception:
    return flags

  if not host:
    return flags

  # 1. Raw IP Host Check
  if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
    flags.append({
        "type": "RAW_IP",
        "evidence": raw_url,
        "detail": (
            f"Directs to a numerical IP address ({host}) rather than an"
            " official institutional domain."
        ),
        "weight": 35,
    })

  # 2. Anonymized Link Shortener
  if host in SHORTENERS:
    flags.append({
        "type": "SHORTENER",
        "evidence": raw_url,
        "detail": (
            f"Uses anonymizing shortener '{host}' to conceal destination."
        ),
        "weight": 25,
    })

  # 3. High-Abuse TLD Check
  if any(host.endswith(tld) for tld in ABUSE_TLDS):
    tld_matched = [tld for tld in ABUSE_TLDS if host.endswith(tld)][0]
    flags.append({
        "type": "ABUSE_TLD",
        "evidence": raw_url,
        "detail": f"Domain registered under high-abuse TLD '{tld_matched}'.",
        "weight": 25,
    })

  # 4. Brand Spoofing & Subdomain Traps
  for brand, legit_domain in OFFICIAL_DOMAINS.items():
    legit_core = legit_domain.split(".")[0]

    # Subdomain Trap (e.g., sbi.bank-login.xyz)
    if brand in host and not (
        host == legit_domain or host.endswith("." + legit_domain)
    ):
      flags.append({
          "type": "SUBDOMAIN_TRAP",
          "evidence": raw_url,
          "detail": (
              f"Deceptively places brand name '{brand}' inside unrelated host"
              f" '{host}'."
          ),
          "weight": 40,
      })

    # Typosquatting / Lookalike Domain
    host_parts = host.split(".")
    core_host = host_parts[-2] if len(host_parts) > 1 else host_parts[0]
    dist = _levenshtein_distance(core_host, legit_core)
    if (
        1 <= dist <= 2
        and core_host != legit_core
        and len(core_host) >= 4
        and host not in SHORTENERS
    ):
      flags.append({
          "type": "TYPOSQUATTING",
          "evidence": raw_url,
          "detail": (
              f"Domain '{host}' typosquats legitimate entity '{legit_domain}'"
              f" (edit distance: {dist})."
          ),
          "weight": 35,
      })

  return flags


def calculate_calibrated_score(raw_points: int) -> tuple[int, str]:
  """Saturates total points onto a 0-100 scale using an exponential curve: 100 * (1 - e^(-raw/38))."""
  if raw_points <= 0:
    return 0, "LOW"
  score = int(round(100 * (1.0 - math.exp(-raw_points / 38.0))))
  score = max(0, min(score, 100))

  if score < 25:
    level = "LOW"
  elif score < 65:
    level = "MEDIUM"
  else:
    level = "HIGH"

  return score, level


def analyze_rules(text: str) -> dict:
  raw_points = 0
  active_flags = []
  extracted_urls = re.findall(r"https?://\S+", text)

  # =========================================================================
  # 1. Urgent deadline / Coercion / Threat Indicators
  # =========================================================================
  urgency_pattern = re.compile(
      r"\b(immediate|immediately|within \d+"
      r" hours?|today|urgent|urgently|warrant|arrest|custody|seized|freeze|"
      r"blocked|disconnection|penalty|non-bailable|fir registered)\b",
      re.I,
  )
  negation_pattern = re.compile(
      r"\b(no|not|none|without|isn't|doesn't|never|cannot)\b", re.I
  )

  urgency_matches = []
  for match in urgency_pattern.finditer(text):
    preceding_words = re.findall(r"\b[\w']+\b", text[: match.start()])[-3:]
    if not negation_pattern.search(" ".join(preceding_words)):
      urgency_matches.append(match.group(1))

  urgency_triggered = bool(urgency_matches)
  urgency_weight = 35 if urgency_triggered else 0
  raw_points += urgency_weight
  if urgency_triggered:
    active_flags.append("High-pressure urgency or legal intimidation detected.")

  # =========================================================================
  # 2. Financial Demands / UPI / Unofficial Payment Rails
  # =========================================================================
  payment_pattern = re.compile(
      r"(@[a-zA-Z]{3,}|upi|paytm|gpay|phonepe|transfer ₹?\s*[\d,]+|pay"
      r" ₹?\s*[\d,]+|deposit ₹?\s*[\d,]+)",
      re.I,
  )
  payment_matches = payment_pattern.findall(text)
  payment_handles = [
      m
      for m in payment_matches
      if m.startswith("@")
      or m.lower() in {"upi", "paytm", "gpay", "phonepe"}
  ]

  amounts = []
  for m in payment_matches:
    amt = re.search(r"(?:₹\s*|Rs\.?\s*|INR\s*)?[\d,]+(?:\.\d+)?", m, re.I)
    if amt and amt.group(0).strip() not in amounts:
      amounts.append(amt.group(0).strip())

  payment_triggered = bool(payment_matches)
  payment_weight = 35 if payment_triggered else 0
  raw_points += payment_weight
  if payment_triggered:
    active_flags.append(
        "Direct digital payment / UPI / transfer demand present."
    )

  # =========================================================================
  # 3. Algorithmic Link Deconstruction & Abuse Detection
  # =========================================================================
  link_candidates = re.findall(
      r"(?:https?://\S+|\b(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|cutt\.ly|shorturl\.at)/\S+)",
      text,
      re.I,
  )

  url_findings = []
  suspicious_urls = []
  for candidate in link_candidates:
    findings = _deconstruct_url(candidate)
    if findings:
      url_findings.extend(findings)
      suspicious_urls.append(candidate)
    else:
      # If not explicitly gov/edu, mark as unverified
      clean_cand = (
          candidate
          if candidate.startswith(("http://", "https://"))
          else "http://" + candidate
      )
      parsed_cand = urlparse(clean_cand).hostname or ""
      if not any(
          parsed_cand.endswith(v)
          for v in [".gov.in", ".nic.in", ".ac.in", ".edu"]
      ):
        suspicious_urls.append(candidate)

  link_triggered = bool(url_findings) or bool(suspicious_urls)
  link_weight = (
      max([f["weight"] for f in url_findings], default=25)
      if link_triggered
      else 0
  )
  raw_points += link_weight

  if url_findings:
    top_finding = url_findings[0]
    active_flags.append(f"Deceptive URL flag: {top_finding['detail']}")
  elif suspicious_urls:
    active_flags.append(
        f"Non-governmental/unverified link found: {suspicious_urls[0]}"
    )

  # =========================================================================
  # 4. Synthesize Saturating Score and Breakdown
  # =========================================================================
  calibrated_score, risk_level = calculate_calibrated_score(raw_points)

  rule_breakdown = [
      {
          "rule": "Urgent deadline or coercion",
          "points": urgency_weight,
          "triggered": urgency_triggered,
          "evidence": ", ".join(set(urgency_matches)),
          "explanation": (
              "Coercive urgency / legal intimidation detected."
              if urgency_triggered
              else "No coercive deadline or threat keywords found."
          ),
      },
      {
          "rule": "Financial demand or digital payment",
          "points": payment_weight,
          "triggered": payment_triggered,
          "evidence": ", ".join(set(payment_matches)),
          "explanation": (
              "Direct digital payment or UPI transfer demand found."
              if payment_triggered
              else "No digital payment or peer-to-peer rails detected."
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
  ]

  return {
      "rule_score": calibrated_score,
      "raw_points": raw_points,
      "risk_level": risk_level,
      "flags": active_flags,
      "extracted_urls": extracted_urls,
      "amounts": amounts,
      "payment_handles": payment_handles,
      "urgency_phrases": list(set(urgency_matches)),
      "rule_breakdown": rule_breakdown,
  }