import os
import io
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from google import genai
from google.genai import types

from pypdf import PdfReader
from PIL import Image
import pytesseract

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


# -----------------------------
# FastAPI
# -----------------------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://red-flagged-nu.vercel.app",
        "http://localhost:5173",
    ],
    allow_origin_regex=r"https://red-flagged.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Gemini model
# -----------------------------

GEMINI_MODEL = "gemini-2.5-flash"


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

            extracted = "".join(
                page.extract_text() or ""
                for page in reader.pages
            )

            return {"text": extracted.strip()}

        else:
            image = Image.open(io.BytesIO(content))
            extracted = pytesseract.image_to_string(image)

            return {"text": extracted.strip()}

    return {"text": ""}


# -----------------------------
# Analyze notice
# -----------------------------

@app.post("/api/analyze", response_model=NoticeAnalysisResponse)
def run_analysis(text: str = Form(...)):

    rule_results = analyze_rules(text)
    knowledge = retrieve_context(text)

    prompt = f"""
Analyze the following notice for indicators of scam,
impersonation, or coercive patterns.

MESSAGE CONTENT:
{text}

DETERMINISTIC CHECKS:

- Rule Score: {rule_results['rule_score']}
- Identified Flags: {rule_results['flags']}

VERIFIED KNOWLEDGE & INSTITUTIONAL STANDARDS:
{knowledge}

Provide an objective, non-accusatory assessment emphasizing
verification procedures.

Return the result using the required JSON schema.
"""

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=GeminiAnalysisResponse,
        ),
    )

    gemini_result = GeminiAnalysisResponse.model_validate_json(response.text)
    return NoticeAnalysisResponse(
        situation_type=gemini_result.situation_type,
        risk_level=gemini_result.risk_level,
        calculated_score=rule_results["rule_score"],
        rule_breakdown=[RuleBreakdown(**item) for item in rule_results["rule_breakdown"]],
        summary=gemini_result.summary,
        red_flags=gemini_result.red_flags,
        safe_next_steps=gemini_result.safe_next_steps,
        verification_guidance=gemini_result.verification_guidance,
        disclaimer=gemini_result.disclaimer,
    )