# RedFlagged

**Understand. Check. Verify.**

Scam messages that mimic legal or government notices — fake arrest warrants, fake Aadhaar-linkage threats, fake refund and payment scams — are built to make people panic and act immediately. RedFlagged lets anyone paste text or upload a screenshot/PDF of one of these messages and get back a risk assessment: a risk score and level, the specific warning signs detected (with quoted evidence and an explanation for each), and recommended safe steps and verification guidance. Results can also be read aloud or shared to WhatsApp/SMS with one click, so a warning can reach a less tech-savvy family member quickly.

🔗 **Live app:** https://red-flagged-nu.vercel.app/
🔗 **Backend API:** https://redflagged-hd8a.onrender.com

> ⚠️ **RedFlagged is not a law firm and does not provide legal advice or determine the legal validity/authenticity of a document.** Its assessment is intended to help users identify warning signs and find appropriate verification channels — not to declare a notice "real" or "fake."

---

## The problem

Scammers increasingly impersonate police, courts, and government departments through WhatsApp, SMS, and email — threatening arrest, account freezes, or legal action unless the recipient pays immediately or shares sensitive information. These messages exploit fear and urgency, and an ordinary person often has no fast way to check: *Is this real? What does it actually say? What should I do?*

Asking a general-purpose chatbot "is this a scam?" is unreliable — it can hallucinate legal information with no grounding in how institutions actually operate. RedFlagged is a dedicated verification workflow instead of a single freeform AI answer.

## How it works

**Extract → Detect → Verify → Explain → Act**

1. **Extract** — paste text or upload a file; text is pulled from PDFs via `pypdf`, and from images via Gemini's vision model
2. **Detect** — a deterministic rule engine (`rules.py`) checks the message for urgency/coercion language, direct payment or UPI demands, and deceptive links. Link checking goes beyond simple pattern matching: it flags raw IP addresses, known URL shorteners, high-abuse top-level domains, brand names stuffed into unrelated subdomains, and typosquatted lookalike domains (using Levenshtein edit-distance against a curated list of real institutional domains). Triggered rules' points are combined and passed through a saturating formula (`100·(1−e^(−points/38))`) so a numeric score never spikes or clips oddly as more indicators stack up
3. **Verify** — relevant, curated institutional context (e.g. how real government departments and banks actually communicate) is retrieved from the knowledge base to ground the next step
4. **Explain** — Gemini is given the message, the rule engine's output, and the retrieved institutional context, and returns a structured JSON response: a situation type, an assessment summary, a red-flags breakdown with quoted evidence and explanation for each, safe next steps, and verification guidance
5. **Act** — the results page shows a results summary (risk level, numeric score, warning count), the full evidence and explanation, and a "Before you act" section with recommended safe steps and official verification guidance. Results can be read aloud (Web Speech API) or copied as a formatted summary for sharing on WhatsApp/SMS, with the disclaimer shown throughout

The UI also offers a few quick-select sample categories (Government impersonation, Payment scam, Legitimate-looking notice, Ambiguous notice) to make it easy to try different scenarios.

## Architecture

```
                 User
                   ↓
         Text / file input
                   ↓
        Image (Gemini vision) / PDF (pypdf) text extraction
                   ↓
          ┌────────┴────────┐
          ↓                 ↓
   Rule engine         Knowledge base
  (URL deconstruction,  (curated,
   urgency/payment       source-backed
   checks → saturating   institutional info)
   0–100 score)
          ↓                 ↓
          └────────┬────────┘
                   ↓
      Gemini (structured JSON output)
                   ↓
   situation type, risk level, summary,
   red flags + evidence, safe next steps,
        verification guidance
                   ↓
                 User
```

**Note on risk level vs. risk score:** the numeric score shown in the results is computed entirely by the deterministic rule engine — triggered rules' point values are summed and passed through a saturating exponential curve (`100·(1−e^(−raw/38))`), so the score never spikes oddly as more indicators stack up. The **risk level** label (LOW/MEDIUM/HIGH) shown alongside it, however, is a separate field returned by Gemini based on its own reading of the message and context — it is not calculated from the numeric score using a fixed mapping. This means the two can still diverge (e.g. a moderate score shown alongside a HIGH label) when the AI's contextual judgment differs from where the score alone would land. Tightening this alignment remains an open item — see Known limitations.

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite, Tailwind CSS |
| Backend | Python, FastAPI |
| Image text extraction | Google Gemini vision (replacing Tesseract, which required a system binary Render doesn't provide by default) |
| PDF extraction | `pypdf` |
| LLM analysis | Google Gemini API (`google-genai`, structured JSON output) |
| Accessibility | Web Speech API (read-aloud), clipboard-based WhatsApp/SMS sharing |
| Hosting | Vercel (frontend), Render (backend) |

## Project structure

```
red-flagged/
├── frontend/          # React + Vite + Tailwind app
├── backend/
│   ├── main.py        # FastAPI app, routes, Gemini integration
│   ├── rules.py        # Deterministic risk-scoring engine
│   └── knowledge.py   # Curated knowledge base + retrieval
├── knowledge/          # Source knowledge files (scenarios, verified info)
└── README.md
```

## Running it locally

### Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
Create a `.env` file in `backend/` with:
```
GEMINI_API_KEY=your_key_here
```
Then run:
```bash
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Set the backend API URL the frontend points to (via an env variable or config file) to `http://localhost:8000` for local development.

## API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/extract-text` | POST | Accepts a file (image/PDF) or raw text, returns extracted text |
| `/api/analyze` | POST | Accepts message text, returns full structured risk analysis |

## Known limitations

- The numeric risk score (rule engine) and the risk level label (Gemini) are generated independently and don't currently follow a fixed mapping, so a given score can appear alongside a risk level that doesn't obviously match it. Aligning these more tightly is a priority fix.
- The knowledge base currently covers a curated set of common scam scenarios, not an exhaustive list
- URL and typosquatting checks are matched against a curated list of known institutional domains — a lookalike domain for an institution not in that list won't be caught by name-similarity checks (though other signals like shorteners or abuse TLDs still apply)
- Situation classification (via Gemini) has generalized correctly in testing to scenario types outside the four built-in UI categories, but the rule engine itself only checks the specific patterns it was built for
- Currently English-only

## Testing & validation

We tested RedFlagged against multiple scenario types, including ones outside the four built-in quick-select categories, and against a deliberately benign message to check for false positives. Two issues surfaced and were fixed during this process:

- **False positive on a benign message.** An early version of the rule engine matched urgency keywords (e.g. "urgent") without checking for negation, so a message stating *"there is no urgent deadline"* was incorrectly flagged. Fixed by adding negation-aware matching (a rule no longer triggers if a negation word appears in the few words preceding the keyword), and by instructing Gemini not to treat well-known domains as inherently suspicious or invent a "contradiction" narrative unless the rule engine independently confirms a real indicator. Verified: the same message now correctly returns LOW risk, 0/100, with no fabricated narrative.
- **Missed shortened-URL links.** The rule engine's link check only matched full `http(s)://` URLs, missing shortened links like `bit.ly/...` used in a customs/courier phishing test message. Fixed by extending the pattern to also match common shortener domains without a scheme. Verified: the same message now correctly triggers the "Suspicious external link" rule alongside the pre-existing urgency detection.
- **Image upload failing in production.** Tesseract OCR requires a system-level binary that isn't available in Render's default Python environment, causing image uploads to fail with a connection error (which surfaced misleadingly as a CORS error in the browser). Fixed by replacing Tesseract with Gemini's vision model for image text extraction — no OS-level dependency needed. Verified: both image and PDF uploads now correctly extract text end-to-end on the live site.

Both the negation and shortened-URL fixes were confirmed not to affect true positives — a refund/UPI scam and a government-impersonation scam continued to be correctly flagged as HIGH risk after the changes.

## Roadmap

- Reconcile the numeric rule score with the AI-assigned risk level so they consistently agree
- Hindi and Gujarati output
- Expanded knowledge base (financial fraud, phishing, fake job offers)
- A transparency panel showing exact rule weights and knowledge sources behind each result

## Disclaimer

RedFlagged identifies warning signs and provides verification guidance. It does not determine whether a document is legally genuine, and it is not a substitute for legal advice. If you're unsure about a legal or government communication, verify it through official, independently-sourced contact channels — not the number or link provided in the message itself.

## License

MIT