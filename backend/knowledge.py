KNOWLEDGE_BASE = {
    "government_tax": (
        "Official Indian government agencies (Income Tax Dept, GST, ED) issue formal notices "
        "via official portals (.gov.in or .nic.in). They never demand immediate UPI transfers, "
        "cryptocurrency, or iTunes gift cards, nor do they threaten instant arrest via WhatsApp."
    ),
    "law_enforcement": (
        "Police departments, cybercrime units, and courts do not conduct 'digital arrests' "
        "over Skype, WhatsApp video, or Telegram. Bail or penalty payments are never handled "
        "via personal UPI handles."
    ),
    "banking": (
        "RBI guidelines mandate that banks never solicit OTPs, passwords, or MPINs over SMS, "
        "unsolicited calls, or non-official links (e.g., bit.ly, tinyurl, .xyz domains)."
    )
}

def retrieve_context(text: str) -> str:
    text_lower = text.lower()
    matches = []
    if any(k in text_lower for k in ["tax", "itr", "refund", "gst"]):
        matches.append(KNOWLEDGE_BASE["government_tax"])
    if any(k in text_lower for k in ["police", "arrest", "court", "cbi", "warrant"]):
        matches.append(KNOWLEDGE_BASE["law_enforcement"])
    if any(k in text_lower for k in ["bank", "kyc", "otp", "debit", "account blocked"]):
        matches.append(KNOWLEDGE_BASE["banking"])
    return "\n\n".join(matches) if matches else "Standard caution applies: Verify sender identities via independent official public contact channels."