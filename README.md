Markdown
# RedFlagged

> **Understand. Check. Verify.**  
> A grounded dual-engine verification pipeline that identifies, explains, and provides safe protocols for suspicious legal and administrative notices.

[![Live Web Application](https://img.shields.io/badge/Frontend-Vercel-black?logo=vercel)](https://red-flagged-nu.vercel.app/)
[![Backend API](https://img.shields.io/badge/Backend-Render-46E3B7?logo=render)](https://redflagged-hd8a.onrender.com)
[![Track](https://img.shields.io/badge/GIBC%20V2-Track%2003%20Open-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚠️ Regulatory Disclaimer
RedFlagged is an informational risk-assessment prototype. It is not a law firm, does not provide legal advice, and does not certify the legal authenticity of any document. Always verify sensitive communications directly through official, independently sourced departmental channels.

---

## The Problem
Scam notices impersonating police departments, courts, and tax agencies rely on urgent threats—such as simulated arrest warrants or immediate account freezes—to provoke impulsive compliance.

Standard conversational AI models often hallucinate legal assessments or issue ungrounded assurances when asked if a notice is legitimate. RedFlagged replaces unconstrained generation with a **grounded multi-stage verification pipeline**: pairing a deterministic heuristic engine with curated institutional protocols and structured multimodal AI reasoning.

---

## Architecture


```

```
                 User Notice Input (Text, Image, PDF)
                                  │
                 Multimodal Vision & PDF Parser
                     (Gemini Flash + pypdf)
                                  │
            ┌─────────────────────┴─────────────────────┐
            ▼                                           ▼
  Deterministic Engine                     Curated Institutional KB

```

• Proximity negation checks                • Formal service protocols
• Algorithmic URL deconstruction           • Real institutional workflows
• Mathematical saturation scoring          • Verified dispute portals
│                                           │
└─────────────────────┬─────────────────────┘
▼
Structured Reasoning Layer
(Google Gemini Flash via JSON Schema)
│
▼
Actionable Output Dashboard
• Calibrated Risk Score (0-100) & Risk Level
• Specific Evidence Quotes & Heuristic Audit
• Recommended Safe Steps & Verification Guidance
• One-Click Family Alert Sharing & Web Speech Audio

```

---

## Core Technical Features

- **Algorithmic Link Deconstruction:** Evaluates URLs for brand hijacking, raw IP destinations, high-abuse TLDs, and typosquatting via pure-Python string distance checks without external C-library dependencies.
- **Saturating Mathematical Scoring:** Uses an exponential curve ($$100 \cdot (1 - e^{-\text{raw}/38})$$) to compress compound signals cleanly into a 0–100 scale, eliminating score spikes and alignment issues.
- **Multimodal Document Processing:** Handles screenshots, mobile camera captures, and native PDF notices via Gemini Flash Vision and `pypdf`, bypassing fragile local OCR binaries.
- **Editable Extraction Buffer:** Allows users to inspect and correct extracted text before running analysis.
- **Accessibility & Safe Sharing:** Built-in Web Speech API voice synthesis and one-click formatted alert copying for family distribution on messaging apps.

---

## Tech Stack & Disclosures

- **Frontend:** React, Vite, Tailwind CSS, Lucide Icons (Deployed on Vercel)
- **Backend:** Python 3.11, FastAPI, Uvicorn (Deployed on Render)
- **Multimodal Vision & Inference:** Google Gemini API (`google-genai` with strict structured schemas)
- **Document Processing:** Pillow, pypdf
- **AI Tooling Disclosure:** AI coding assistants (Claude Code / ChatGPT / Cursor) were used for boilerplate scaffolding, regex optimization, and deployment debugging.

---

## Project Structure

```text
red-flagged/
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Dashboard, state, audio, and share handlers
│   │   ├── main.jsx         # Application entry
│   │   └── index.css        # Tailwind styling & themes
│   ├── package.json
│   └── vite.config.js
├── backend/
│   ├── main.py              # FastAPI endpoints & Gemini schema bindings
│   ├── rules.py             # Deterministic heuristics & URL deconstruction
│   ├── knowledge.py         # Institutional protocols & retrieval mappings
│   └── requirements.txt
└── README.md

```

---

## Getting Started Locally

### Prerequisites

* Node.js (v18+)
* Python (v3.10+)
* Gemini API Key

### Backend Setup

```bash
cd backend
python -m venv venv
# On Windows: venv\Scripts\activate | On macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

```

Create a `.env` file inside `backend/`:

```env
GEMINI_API_KEY=your_actual_gemini_api_key

```

Start the API server:

```bash
uvicorn main:app --reload --port 8000

```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev

```

Open `http://localhost:5173` to test the application locally.

---

## Verification & Validation

RedFlagged was evaluated across standard fraud categories and control samples:

* **Negation Validation:** Verified that benign phrases like *"there is no urgent deadline"* correctly evaluate to **0/100 (LOW risk)** without false-positive alarms.
* **Deceptive URL Handling:** Confirmed detection of subdomain traps (`brand.com.unrelated-domain.xyz`) and shorteners without schema prefixes.
* **Generalization:** Successfully categorizes real-world administrative and courier fraud scenarios outside built-in UI presets without hallucinating unrelated flags.

---
## Future Scope & Roadmap

- **Regional Localization:** Native support for Hindi, Gujarati, and Tamil for OCR extraction, explanations, and localized audio readouts.
- **Client Extensions:** Manifest V3 browser extension and WhatsApp/Telegram bot for on-the-spot message scanning without leaving the app.
- **Interactive Counterfactuals:** Real-time score recalculation showing users how removing specific flags changes the overall risk rating.
- **Edge Inference:** Lightweight on-device models (WebGPU / ONNX) for zero-latency local checks before calling cloud APIs.
- **Digital Signature Checks:** Cryptographic verification of embedded PDF signatures (PKCS#7) to catch fake stamp overlays.
- **Institutional Threat Registry:** Community-reported scam tracking and verified sender-ID lookup for courts, police, and banks.

## License

Distributed under the MIT License.

```

```