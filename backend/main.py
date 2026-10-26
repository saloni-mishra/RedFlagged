import os
import io
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from google import genai
from google.genai import types

from pypdf import PdfReader
from PIL import Image


from rules import analyze_rules
from knowledge import retrieve_context


# -----------------------------
# Environment
# -----------------------------

env_path = Path(__file__).resolve().parent / ".env"

load_dotenv(dotenv_path=env_path)

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise RuntimeError(
        f"GEMINI_API_KEY not found. Expected .env at: {env_path}"
    )

print("DEBUG: .env path:", env_path)
print("DEBUG: API key loaded:", api_key[:6] + "******")

client = genai.Client(api_key=api_key)


# -----------------------------
# Schema
# -----------------------------

class RedFlag(BaseModel):
    indicator: str
    evidence: str
    explanation: str


class RuleBreakdown(BaseModel):
    rule: str
    points: int
    triggered: bool
    explanation: str
    # URL classification from the rule engine ("suspicious", "unverified",
    # "none", or "" for non-URL rules). Optional so older clients are
    # unaffected.
    classification: str = ""


class GeminiAnalysisResponse(BaseModel):
    situation_type: str
    risk_level: str = Field(description="'LOW', 'MEDIUM', or 'HIGH'")
    summary: str
    red_flags: list[RedFlag]
    safe_next_steps: list[str]
    verification_guidance: list[str]
    disclaimer: str


class NoticeAnalysisResponse(BaseModel):
    situation_type: str
    risk_level: str = Field(description="'LOW', 'MEDIUM', or 'HIGH'")
    calculated_score: int
    rule_breakdown: list[RuleBreakdown]
    summary: str
    red_flags: list[RedFlag]
    safe_next_steps: list[str]
    verification_guidance: list[str]
    disclaimer: str
    amounts: list[str] = Field(default_factory=list)
    payment_handles: list[str] = Field(default_factory=list)
    urgency_phrases: list[str] = Field(default_factory=list)
    extracted_urls: list[str] = Field(default_factory=list)


# -----------------------------
# FastAPI
# -----------------------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://red-flagged-nu.vercel.app",
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Gemini model
# -----------------------------

# Override without editing code, e.g. GEMINI_MODEL=gemini-2.5-flash-lite
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


# -----------------------------
# Fallback (used when Gemini is unavailable: quota, timeout, bad JSON)
# -----------------------------

FALLBACK_TEXT = {
    "en": {
        "situation": {
            "HIGH": "Likely scam (rule-based check)",
            "MEDIUM": "Suspicious message (rule-based check)",
            "LOW": "No clear scam indicators (rule-based check)",
        },
        "summary": {
            "HIGH": "The automated rule checks found several strong warning signs of fraud in this message. The detailed AI explanation is temporarily unavailable, so this result is based on the rule checks only.",
            "MEDIUM": "The automated rule checks found some suspicious signs in this message. The detailed AI explanation is temporarily unavailable, so this result is based on the rule checks only.",
            "LOW": "The automated rule checks did not find clear scam indicators. The detailed AI explanation is temporarily unavailable, so please still stay cautious and verify independently.",
        },
        "safe_next_steps": [
            "Do not send money or click any link in this message until you have verified it.",
            "Never share an OTP, PIN, password or Aadhaar details with anyone.",
            "Contact the organisation yourself using its official website or phone number, not the details in the message.",
            "If you suspect fraud, report it on the National Cyber Crime helpline 1930 or at cybercrime.gov.in.",
        ],
        "verification_guidance": [
            "Check the information on the organisation's official website or app.",
            "Do not use phone numbers or links given inside the message to verify it.",
        ],
        "disclaimer": "This is an automated rule-based check and not legal or financial advice. Verify independently before paying money or sharing information.",
    },
    "hi": {
        "situation": {
            "HIGH": "संभावित धोखाधड़ी (नियम-आधारित जाँच)",
            "MEDIUM": "संदिग्ध संदेश (नियम-आधारित जाँच)",
            "LOW": "धोखाधड़ी के स्पष्ट संकेत नहीं (नियम-आधारित जाँच)",
        },
        "summary": {
            "HIGH": "स्वचालित नियम-जाँच में इस संदेश में धोखाधड़ी के कई गंभीर संकेत मिले हैं। विस्तृत AI विश्लेषण अभी उपलब्ध नहीं है, इसलिए यह परिणाम केवल नियम-जाँच पर आधारित है।",
            "MEDIUM": "स्वचालित नियम-जाँच में इस संदेश में कुछ संदिग्ध संकेत मिले हैं। विस्तृत AI विश्लेषण अभी उपलब्ध नहीं है, इसलिए यह परिणाम केवल नियम-जाँच पर आधारित है।",
            "LOW": "स्वचालित नियम-जाँच में धोखाधड़ी के स्पष्ट संकेत नहीं मिले। विस्तृत AI विश्लेषण अभी उपलब्ध नहीं है, इसलिए फिर भी सावधानी रखें और स्वयं पुष्टि करें।",
        },
        "safe_next_steps": [
            "पुष्टि किए बिना इस संदेश में दिए किसी खाते में पैसे न भेजें और किसी लिंक पर क्लिक न करें।",
            "OTP, पिन, पासवर्ड या आधार की जानकारी किसी से साझा न करें।",
            "संस्था से खुद उसकी आधिकारिक वेबसाइट या फोन नंबर के ज़रिए संपर्क करें, संदेश में दिए विवरण से नहीं।",
            "धोखाधड़ी का शक हो तो राष्ट्रीय साइबर अपराध हेल्पलाइन 1930 या cybercrime.gov.in पर रिपोर्ट करें।",
        ],
        "verification_guidance": [
            "संस्था की आधिकारिक वेबसाइट या ऐप पर जानकारी की पुष्टि करें।",
            "पुष्टि के लिए संदेश में दिए फोन नंबर या लिंक का उपयोग न करें।",
        ],
        "disclaimer": "यह स्वचालित नियम-आधारित जाँच है, कानूनी या वित्तीय सलाह नहीं। पैसे भेजने या जानकारी साझा करने से पहले स्वयं पुष्टि करें।",
    },
}


def _rule_rows(rule_results: dict, language: str) -> list[RuleBreakdown]:
    """Rule rows for the response. For Hindi, show the Hindi rule name."""
    rows = []
    for item in rule_results["rule_breakdown"]:
        name = item["rule"]
        if language == "hi" and item.get("rule_hi"):
            name = item["rule_hi"]
        rows.append(
            RuleBreakdown(
                rule=name,
                points=item["points"],
                triggered=item["triggered"],
                explanation=item["explanation"],
                classification=item.get("classification", ""),
            )
        )
    return rows


def _fallback_response(text: str, rule_results: dict, language: str) -> NoticeAnalysisResponse:
    """Build a normal response from the rule engine alone."""
    lang = "hi" if language == "hi" else "en"
    texts = FALLBACK_TEXT[lang]
    level = rule_results["risk_level"]

    red_flags = []
    for item in rule_results["rule_breakdown"]:
        if not item["triggered"]:
            continue
        name = item["rule_hi"] if lang == "hi" and item.get("rule_hi") else item["rule"]
        red_flags.append(
            RedFlag(
                indicator=name,
                evidence=item.get("evidence") or text[:200],
                explanation=item["explanation"],
            )
        )

    return NoticeAnalysisResponse(
        situation_type=texts["situation"][level],
        risk_level=level,
        calculated_score=rule_results["rule_score"],
        rule_breakdown=_rule_rows(rule_results, language),
        summary=texts["summary"][level],
        red_flags=red_flags,
        safe_next_steps=texts["safe_next_steps"],
        verification_guidance=texts["verification_guidance"],
        disclaimer=texts["disclaimer"],
        amounts=rule_results["amounts"],
        payment_handles=rule_results["payment_handles"],
        urgency_phrases=rule_results["urgency_phrases"],
        extracted_urls=rule_results["extracted_urls"],
    )


# -----------------------------
# Extract text
# -----------------------------

@app.post("/api/extract-text")
async def extract_text(
    file: UploadFile = File(None),
    raw_text: str = Form(None),
):
    if raw_text:
        return {"text": raw_text}

    if file:
        content = await file.read()

        if file.filename and file.filename.lower().endswith(".pdf"):
            reader = PdfReader(io.BytesIO(content))
            extracted = "".join(page.extract_text() or "" for page in reader.pages)
            return {"text": extracted.strip()}

        else:
            try:
                image = Image.open(io.BytesIO(content))
                response = client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=[
                        image,
                        "Extract and transcribe all readable text from this image verbatim. Return only the extracted text and nothing else.",
                    ],
                )
                extracted_text = response.text.strip() if response.text else ""
                return {"text": extracted_text}
            except Exception as e:
                print(f"Extraction failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))

    return {"text": ""}


# -----------------------------
# Analyze notice
# -----------------------------

@app.post("/api/analyze", response_model=NoticeAnalysisResponse)
def run_analysis(text: str = Form(...)):

    rule_results = analyze_rules(text)
    language = rule_results.get("language", "en")

    try:
        knowledge = retrieve_context(text)
    except Exception as e:
        print(f"Knowledge retrieval failed: {e}")
        knowledge = ""

    language_instruction = (
        "Write every user-facing field in Hindi using Devanagari script (for example: "
        "summary, red_flags[].indicator, red_flags[].explanation, safe_next_steps, "
        "verification_guidance, disclaimer, and any verdict text). Keep JSON keys, "
        "risk-level enum values (LOW/MEDIUM/HIGH), and URLs in English."
        if language == "hi"
        else "Write every user-facing field in English. Keep JSON keys, risk-level "
        "enum values (LOW/MEDIUM/HIGH), and URLs in English."
    )

    prompt = f"""
Analyze the following notice for indicators of scam,
impersonation, or coercive patterns.

IMPORTANT INTERPRETATION GUIDANCE:
Do not treat widely-known, reputable domains (e.g. google.com, github.com,
microsoft.com, amazon.com, apple.com) as inherently suspicious or as signs
of impersonation just because they are mentioned. Only flag a domain as
suspicious if there is a concrete reason in the message itself — such as a
misspelled/lookalike domain, a URL shortener, or the domain being paired
with a request for payment, OTP, or login credentials. If a message
explicitly states there is no urgency or no payment required, do not
describe this as a "contradiction" unless the deterministic rule checks
also independently confirm urgency or payment indicators are present.

LANGUAGE INSTRUCTION:
{language_instruction}

MESSAGE CONTENT:
{text}

DETERMINISTIC CHECKS:

- Rule Score: {rule_results['rule_score']}
- Risk Level: {rule_results['risk_level']}
- Identified Flags: {rule_results['flags']}
- Detected Language: {language}

VERIFIED KNOWLEDGE & INSTITUTIONAL STANDARDS:
{knowledge}

Provide an objective, non-accusatory assessment emphasizing
verification procedures.

Return the result using the required JSON schema.
"""

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=GeminiAnalysisResponse,
            ),
        )

        gemini_result = GeminiAnalysisResponse.model_validate_json(response.text)
    except Exception as e:
        # Quota (429), timeout, network or invalid JSON: still return the
        # rule-engine result instead of a 500 (which also breaks CORS in browsers).
        print(f"Gemini analysis failed, using rule-based fallback: {e}")
        return _fallback_response(text, rule_results, language)

    return NoticeAnalysisResponse(
        situation_type=gemini_result.situation_type,
        risk_level=rule_results["risk_level"],
        calculated_score=rule_results["rule_score"],
        rule_breakdown=_rule_rows(rule_results, language),
        summary=gemini_result.summary,
        red_flags=gemini_result.red_flags,
        safe_next_steps=gemini_result.safe_next_steps,
        verification_guidance=gemini_result.verification_guidance,
        disclaimer=gemini_result.disclaimer,
        amounts=rule_results["amounts"],
        payment_handles=rule_results["payment_handles"],
        urgency_phrases=rule_results["urgency_phrases"],
        extracted_urls=rule_results["extracted_urls"],
    )