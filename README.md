# RedFlagged

**Understand. Check. Verify.**

RedFlagged helps people identify warning signs in suspicious messages that imitate legal notices, police communications, government departments, banks, or payment services.

Users can paste a message or upload an image or PDF for analysis. Messages in English and Hindi are supported, and the results come back in the same language as the message. The app returns a risk assessment, a numeric score, detected warning signs with supporting evidence, explanations, and recommended safety steps and verification guidance. Results can also be read aloud or copied for sharing through WhatsApp or SMS.

**Live app:** https://red-flagged-nu.vercel.app/  
**Backend API:** https://redflagged-hd8a.onrender.com

> **Important:** RedFlagged does not determine the legal validity or authenticity of a document and does not provide legal advice. Its assessment helps users identify warning signs and find appropriate verification channels; it does not establish that a message is definitively real or fake.

## The problem

Scammers impersonate police, courts, government departments, banks, and other organizations through WhatsApp, SMS, email, and document attachments. Their messages may threaten arrest, account freezes, penalties, or legal action unless the recipient pays immediately or shares sensitive information.

These tactics exploit fear and urgency. People may struggle to determine what a message is asking them to do, which parts are suspicious, and how to verify it safely.

Asking a general-purpose chatbot whether a message is a scam can produce unsupported conclusions. RedFlagged uses a dedicated workflow that combines deterministic rule-based checks, curated institutional information, and structured AI analysis to make its assessment more transparent.

## How it works

**Extract → Detect → Verify → Explain → Act**

1. **Extract** — Users paste message text or upload a file. PDF text is extracted using `pypdf`, while image text extraction uses Google's Gemini vision model.
2. **Detect** — A deterministic rule engine in `backend/rules.py` checks for indicators such as urgency, coercive language, direct payment or UPI demands, requests for OTP/Aadhaar/credentials, courier and customs-fee scams, job and internship fee scams, suspicious links, raw IP addresses, URL shorteners, high-abuse top-level domains, deceptive subdomains, and typosquatted lookalike domains. The rules work on English and Hindi (Devanagari) text, with partial support for Roman-script Hindi (Hinglish), and ignore matches that are clearly negated (for example, "the bank never asks for your OTP").
3. **Verify** — The application retrieves relevant information from a curated knowledge base containing institutional context and verification guidance.
4. **Explain** — Gemini receives the message, rule-engine findings, and retrieved context. It produces structured JSON containing the situation type, summary, warning signs, supporting evidence, explanations, recommended safe steps, and verification guidance.
5. **Act** — The results page presents the assessment and supporting details. Users can read the summary aloud (in Hindi for Hindi results, when the browser has a Hindi voice installed), copy a formatted result for sharing, and follow the recommended safety and verification steps.

**Backup mode:** if the Gemini call fails (for example, the free-tier quota is used up, a timeout, or an invalid response), the app does not fail. It returns the rule engine's score, risk level, triggered rules and evidence, together with fixed safety steps and verification guidance in the message's language, and states that the detailed AI explanation is temporarily unavailable.

The interface also includes sample messages for Government Impersonation, Payment Scam, Legitimate-Looking Notice, and Ambiguous Notice scenarios.

## Risk-scoring approach

The numeric score is calculated by the deterministic rule engine. Triggered rules contribute points, which are combined using a saturating exponential formula:

\[
\text{Score}=100\left(1-e^{-\text{raw points}/38}\right)
\]

This maps accumulated rule points onto a 0–100 scale while reducing the impact of additional points as the score increases.

The **risk-level label** is derived from the same numeric score using fixed thresholds: below 25 is LOW, 25 to 64 is MEDIUM, and 65 or above is HIGH. Gemini explains the result but does not change the score or the label, so the two always agree.

## Architecture

```text
                       User
                         |
                  Text or file input
                         |
                  Text extraction
                  /             \
             PDF: pypdf       Image: Gemini
                  \             /
                   Extracted text
                         |
             +-----------+-----------+
             |                       |
        Rule engine             Knowledge base
        - Urgency                - Curated context
        - Payment demands        - Institutional guidance
        - Suspicious URLs        - Verification information
        - Domain lookalikes      |
             |                       |
             +-----------+-----------+
                         |
                  Gemini analysis
                  Structured JSON
                         |
             +-----------+-----------+
             |           |           |
          Summary     Red flags    Safe steps
             |           |           |
             +-----------+-----------+
                         |
                   Results page
                         |
             Read aloud / Copy / Share
```

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, Tailwind CSS |
| Backend | Python, FastAPI |
| Image text extraction | Google Gemini vision |
| PDF text extraction | `pypdf` |
| AI analysis | Google Gemini API, `google-genai`, structured JSON output |
| Rule-based detection | Python, regular expressions (English and Devanagari-aware), negation handling, URL and domain checks, Levenshtein edit distance |
| Knowledge retrieval | Curated institutional knowledge base |
| Accessibility | Web Speech API (read aloud, including Hindi where a voice is available) |
| Sharing | Clipboard-based copying for WhatsApp and SMS |
| Frontend hosting | Vercel |
| Backend hosting | Render |

## Project structure

```text
red-flagged/
├── frontend/          # React + Vite + Tailwind frontend
├── backend/
│   ├── main.py        # FastAPI routes and Gemini integration
│   ├── rules.py       # Deterministic risk-scoring engine
│   └── knowledge.py   # Knowledge base and retrieval logic
├── knowledge/         # Curated knowledge and scenario files
└── README.md
```

## Running locally

### Prerequisites

- Python 3.12 recommended
- Node.js and npm
- A Google Gemini API key

### 1. Clone the repository

```bash
git clone https://github.com/saloni-mishra/RedFlagged.git
cd RedFlagged
```

### 2. Set up the backend

```bash
cd backend
python -m venv venv
```

Activate the virtual environment.

**Windows (Command Prompt):**

```bat
venv\Scripts\activate
```

**Windows (PowerShell):**

```powershell
.\venv\Scripts\Activate.ps1
```

**macOS/Linux:**

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file inside `backend/`:

```env
GEMINI_API_KEY=your_key_here
```

Replace `your_key_here` with your own API key. Do not commit `.env` or expose the key in frontend code.

Optionally, add `GEMINI_MODEL=<model name>` to choose a different Gemini model (the default is `gemini-2.5-flash`). Free-tier keys have daily request limits; when they are used up, the app switches to backup mode described above.

Start the backend:

```bash
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.

### 3. Set up the frontend

Open a second terminal:

```bash
cd frontend
npm install
```

Configure the frontend's backend URL using the environment variable expected by the application:

```env
VITE_API_URL=http://localhost:8000
```

Place this variable in the appropriate frontend environment file, such as `frontend/.env.local`, if supported by the current configuration.

Start the frontend:

```bash
npm run dev
```

Vite will print the local development URL in the terminal.

## API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/extract-text` | POST | Accepts supported file or text input and returns extracted text. |
| `/api/analyze` | POST | Accepts message text and returns the structured risk assessment. |

The exact request and response formats depend on the current implementation in `backend/main.py`.

## Testing and validation

Testing covered multiple message categories, including scenarios outside the built-in sample categories, and a deliberately benign message intended to test false-positive behavior.

### 1. Negation-aware urgency detection

**Issue:** An earlier rule matched urgency terms without considering negation. For example, a message stating that there was *no urgent deadline* could be incorrectly flagged.

**Change:** Negation-aware matching was added so that a nearby negation can prevent an urgency rule from triggering. Gemini's instructions were also refined to discourage unsupported suspiciousness claims and fabricated contradictions.

**Observed result:** The tested benign message returned LOW risk, a score of 0/100, and no fabricated warning narrative.

### 2. Shortened-URL detection

**Issue:** The URL detector initially matched full `http://` and `https://` links but missed some shortened URLs written without a scheme.

**Change:** The pattern was extended to recognize common URL-shortener domains without requiring a URL scheme.

**Observed result:** The tested customs/courier phishing message triggered the suspicious-external-link rule alongside the existing urgency detection.

### 3. Production image extraction

**Issue:** The initial image-extraction approach depended on Tesseract OCR, a system-level binary that was not available in the deployed Render environment.

**Change:** Image text extraction was moved to Gemini vision, removing that system-level dependency.

**Observed result:** Image and PDF extraction were tested successfully through the deployed application.

The negation and shortened-URL changes were also checked against tested refund/UPI and government-impersonation scam examples, which continued to trigger HIGH-risk assessments.

### 4. Hindi and job-scam coverage

**Issue:** Python's `\b` word boundary does not work with Hindi vowel signs, so several Hindi rules silently never matched, and Hindi negation phrases such as "भुगतान करें" could wrongly cancel real detections. Fee-based job offers written in Hindi were also missed.

**Change:** Hindi-safe word boundaries were introduced, the three overlapping negation checks were replaced by one clause-limited check, and Hindi and Hinglish patterns for payment, OTP, courier and job-fee scams were added. Generic words that flagged ordinary messages were tightened.

**Observed result:** A regression script of 30 messages (Hindi, Hinglish and English scams, genuine notices, and everyday messages that must stay LOW) passes. A Hindi fake-job message asking for a security fee now returns HIGH (82/100) with a Hindi explanation.

These are observed test results, not a claim of exhaustive validation across all possible messages.

## Known limitations

- **Limited knowledge coverage:** The curated knowledge base covers selected scenarios rather than every type of scam or institutional communication.
- **Curated domain coverage:** Lookalike-domain detection depends partly on the institutional domains included in the curated list. Unlisted institutions may not receive the same name-similarity checks.
- **Rule coverage:** The rule engine only detects patterns for which checks have been implemented. A message can contain warning signs that the current rules do not recognize.
- **AI limitations:** Gemini may misinterpret ambiguous messages or produce incorrect explanations. Results should not be treated as definitive proof of fraud or authenticity.
- **Language support:** English and Hindi (Devanagari) are supported. Roman-script Hindi (Hinglish) is detected by the rules, but the explanation is produced in English.
- **Read-aloud voices:** Reading aloud uses the browser's built-in voices. A Hindi voice must be installed on the user's device; otherwise the browser may fall back to another voice or stay silent.
- **Backup mode is less detailed:** When Gemini is unavailable, the explanation is fixed text based on the rule results rather than a message-specific AI explanation.
- **Verification is not automatic authentication:** Retrieved institutional context can guide users toward safer verification, but it does not independently authenticate the submitted document.

## Roadmap

- Expand the knowledge base to cover financial fraud, phishing, and fraudulent job or internship offers.
- Add a transparency panel explaining triggered rule weights and the knowledge sources used.
- Expand testing with more benign, ambiguous, and malicious examples to assess false positives and false negatives.

## Disclaimer

RedFlagged identifies potential warning signs and provides verification guidance. It does not establish whether a message or document is legally genuine, does not replace professional legal advice, and cannot guarantee that every scam will be detected.

If you receive a suspicious legal or government communication, do not rely solely on its contact details, links, or payment instructions. Find the relevant institution's official contact channel independently and verify the communication before acting.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.