import React, { useState } from 'react';
import { AlertTriangle, CheckCircle, ShieldAlert, FileText, ArrowRight, Loader2 } from 'lucide-react';

const API_BASE = "http://localhost:8000";

const DEMO_EXAMPLES = {
  "Government impersonation": "URGENT: This is the Income Tax Department. Your PAN will be suspended today unless you verify your details immediately at https://example.com/verify.",
  "Payment scam": "Your bank account has been selected for a refund. Pay ₹2,500 processing charges via UPI to claim it now.",
  "Legitimate-looking notice": "Dear customer, your monthly account statement is ready. Please sign in through the official bank app to review it at your convenience.",
  "Ambiguous notice": "Your service request needs attention. Contact our support team soon to confirm the information associated with your account.",
};

const RISK_STYLES = {
  HIGH: {
    badge: "bg-[#f2deda] text-[#8f332d] border-[#c98b84]",
    bar: "bg-[#a3473e]",
    border: "border-[#c98b84]",
  },
  MEDIUM: {
    badge: "bg-[#f3e8d2] text-[#8a5a20] border-[#d5b477]",
    bar: "bg-[#b47a32]",
    border: "border-[#d5b477]",
  },
  LOW: {
    badge: "bg-[#e4eee7] text-[#356247] border-[#9dbca7]",
    bar: "bg-[#52765d]",
    border: "border-[#9dbca7]",
  },
};

function getEvidencePhrases(ruleBreakdown, notice) {
  const noticeLower = notice.toLocaleLowerCase();

  return [...new Set(
    ruleBreakdown.flatMap((item) => {
      if (!item.evidence) return [];
      if (noticeLower.includes(item.evidence.toLocaleLowerCase())) return [item.evidence];
      return item.evidence.split(/,\s+/).map((phrase) => phrase.trim());
    }),
  )]
    .filter((phrase) => phrase && noticeLower.includes(phrase.toLocaleLowerCase()))
    .sort((first, second) => second.length - first.length);
}

function highlightEvidence(notice, phrases) {
  const matches = [];

  phrases.forEach((phrase) => {
    const phraseLower = phrase.toLocaleLowerCase();
    let start = notice.toLocaleLowerCase().indexOf(phraseLower);
    while (start !== -1) {
      matches.push({ start, end: start + phrase.length, phrase });
      start = notice.toLocaleLowerCase().indexOf(phraseLower, start + phrase.length);
    }
  });

  matches.sort((first, second) => first.start - second.start || second.end - first.end);

  const rendered = [];
  let cursor = 0;
  matches.forEach((match) => {
    if (match.start < cursor) return;
    if (match.start > cursor) rendered.push(notice.slice(cursor, match.start));
    rendered.push(
      <mark key={`${match.start}-${match.end}`} className="bg-[#f3e8d2] text-[#6f4a1e] border-b border-[#d5b477] px-0.5">
        {notice.slice(match.start, match.end)}
      </mark>,
    );
    cursor = match.end;
  });

  if (cursor < notice.length) rendered.push(notice.slice(cursor));
  return rendered;
}

export default function App() {
  const [inputText, setInputText] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [results, setResults] = useState(null);
  const [analyzedText, setAnalyzedText] = useState("");
  const riskStyles = RISK_STYLES[results?.risk_level] || RISK_STYLES.LOW;
  const warningCount = results?.red_flags?.length ?? 0;

  const handleFileUpload = async (e) => {
    const uploadedFile = e.target.files[0];
    if (!uploadedFile) return;
    setFile(uploadedFile);
    setLoading(true);
    setStatusMessage("Extracting text from file...");

    const formData = new FormData();
    formData.append("file", uploadedFile);

    try {
      const res = await fetch(`${API_BASE}/api/extract-text`, { method: "POST", body: formData });
      const data = await res.json();
      setInputText(data.text || "");
    } catch (err) {
      alert("Error extracting text.");
    } finally {
      setLoading(false);
      setStatusMessage("");
    }
  };

  const handleAnalyze = async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    setStatusMessage("Running deterministic rules & consulting knowledge base...");

    try {
      const formData = new FormData();
      formData.append("text", inputText);

      const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: formData });
      const data = await res.json();
      setResults(data);
      setAnalyzedText(inputText);
    } catch (err) {
      alert("Analysis failed. Verify your backend server status.");
    } finally {
      setLoading(false);
      setStatusMessage("");
    }
  };

  return (
    <div
      className="min-h-screen text-[#1b1a18] font-sans p-5 md:p-10"
      style={{
        backgroundColor: "#f4f0e8",
        backgroundImage: "repeating-linear-gradient(0deg, rgba(80, 65, 45, 0.025) 0px, rgba(80, 65, 45, 0.025) 1px, transparent 1px, transparent 4px)",
      }}
    >
      <div className="max-w-4xl mx-auto space-y-10">
        
        {/* Header */}
        <header className="border-b border-[#cfc5b6] pb-5">
          <h1 className="text-3xl font-serif font-bold tracking-tight text-[#1b1a18] flex items-center gap-2">
            <ShieldAlert className="text-[#27558a] w-8 h-8" /> RedFlagged
          </h1>
          <p className="text-[#625d55] mt-2 text-sm">
            Deterministic rule engine + Grounded institutional verification for suspicious notices.
          </p>
        </header>

        <section className="bg-[#faf8f3] p-5 rounded-sm border border-[#cfc5b6] space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-[0.12em] text-[#625d55]">How RedFlagged works</h2>
          <p className="text-sm font-semibold text-[#27558a]">
            Extract <span className="text-[#a49a8b]">&rarr;</span> Detect <span className="text-[#a49a8b]">&rarr;</span> Verify <span className="text-[#a49a8b]">&rarr;</span> Explain <span className="text-[#a49a8b]">&rarr;</span> Act
          </p>
          <p className="text-xs text-[#625d55] leading-relaxed">
            Deterministic rules detect warning signs, institutional context supports verification, and Gemini helps explain the findings.
          </p>
        </section>

        {/* Input Phase */}
        <section className="bg-[#faf8f3] p-6 rounded-sm border border-[#cfc5b6] space-y-4">
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
            <label className="text-sm font-semibold text-[#2b2926]">Analyze a notice</label>
            <input 
              type="file" 
              accept=".pdf,image/*" 
              onChange={handleFileUpload}
              className="text-sm text-[#625d55] file:mr-4 file:py-2 file:px-4 file:rounded-sm file:border file:border-[#b9c8d8] file:text-sm file:font-semibold file:bg-[#edf2f7] file:text-[#27558a] hover:file:bg-[#e2eaf2] cursor-pointer"
            />
          </div>

          <textarea 
            rows="6"
            className="w-full p-3 border border-[#cfc5b6] rounded-sm bg-[#fffdf8] text-sm text-[#1b1a18] placeholder:text-[#8b8378] focus:ring-2 focus:ring-[#27558a] outline-none"
            placeholder="Paste raw SMS, email body, notice text, or verify extracted OCR text here..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
          />

          <div className="flex flex-wrap gap-2">
            {Object.entries(DEMO_EXAMPLES).map(([label, example]) => (
              <button
                key={label}
                type="button"
                onClick={() => setInputText(example)}
                className="px-3 py-2 text-xs font-medium text-[#27558a] bg-[#edf2f7] border border-[#b9c8d8] rounded-sm hover:bg-[#e2eaf2] transition"
              >
                {label}
              </button>
            ))}
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading || !inputText.trim()}
            className="flex items-center justify-center gap-2 w-full py-3 bg-[#27558a] hover:bg-[#1d426b] text-white font-medium rounded-sm disabled:opacity-50 transition"
          >
            {loading ? <Loader2 className="animate-spin w-5 h-5" /> : "Run Institutional Verification"}
          </button>

          {statusMessage && <p className="text-xs text-center text-[#625d55]">{statusMessage}</p>}
        </section>

        {/* Results Screen */}
        {results && (
          <section className="bg-[#faf8f3] p-6 rounded-sm border border-[#cfc5b6] space-y-7">
            <div className={`sticky top-3 z-10 flex flex-wrap items-center justify-between gap-3 bg-[#faf8f3] p-3 rounded-sm border ${riskStyles.border}`}>
              <span className="text-xs font-semibold uppercase tracking-[0.12em] text-[#625d55]">Results summary</span>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
                <span className={`px-2 py-1 rounded-sm border font-semibold ${riskStyles.badge}`}>
                  {results.risk_level} risk
                </span>
                <span className="text-[#2b2926]">
                  <strong>{results.calculated_score}/100</strong> score
                </span>
                <span className="text-[#625d55]">
                  <strong className="text-[#2b2926]">{warningCount}</strong> {warningCount === 1 ? "warning" : "warnings"}
                </span>
              </div>
            </div>

            <div className={`border-b pb-5 space-y-4 ${riskStyles.border}`}>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <span className="text-xs font-semibold text-[#857b6e] uppercase tracking-[0.12em]">Risk assessment</span>
                  <h2 className="text-xl font-serif font-bold text-[#1b1a18]">{results.situation_type}</h2>
                </div>
                <div className={`self-start px-4 py-2 rounded-full font-bold text-sm border ${riskStyles.badge}`}>
                  {results.risk_level} risk
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-[#625d55] uppercase tracking-wide">Risk score</span>
                  <span className="text-sm font-bold text-[#1b1a18]">{results.calculated_score}/100</span>
                </div>
                <div
                  className="h-3 w-full rounded-sm bg-[#e8e1d6] border border-[#cfc5b6] overflow-hidden"
                  role="progressbar"
                  aria-label="Risk score"
                  aria-valuemin="0"
                  aria-valuemax="100"
                  aria-valuenow={results.calculated_score}
                >
                  <div
                    className={`h-full rounded-full ${riskStyles.bar}`}
                    style={{ width: `${Math.max(0, Math.min(100, results.calculated_score))}%` }}
                  />
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-[#2b2926] mb-1">Assessment summary</h3>
              <p className="text-[#625d55] text-sm leading-relaxed">{results.summary}</p>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-[#2b2926] mb-3">Evidence in the notice</h3>
              <div className="border border-[#cfc5b6] rounded-sm bg-[#fffdf8] p-4 text-sm text-[#4f4941] leading-7 whitespace-pre-wrap">
                {highlightEvidence(analyzedText, getEvidencePhrases(results.rule_breakdown, analyzedText))}
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-[#2b2926] mb-3">Why this was flagged</h3>
              <div className="border border-[#cfc5b6] rounded-sm divide-y divide-[#cfc5b6]">
                {results.rule_breakdown.map((item, idx) => (
                  <div key={idx} className={`p-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:gap-4 ${
                    item.triggered ? "bg-[#f8e9e5] border-l-4 border-[#a3473e]" : "bg-[#f6f2eb]"
                  }`}>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`font-medium text-sm ${
                          item.triggered ? "text-[#1b1a18]" : "text-[#857b6e]"
                        }`}>{item.rule}</span>
                        <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wide ${
                          item.triggered ? "bg-[#f2deda] text-[#8f332d]" : "bg-[#e8e1d6] text-[#857b6e]"
                        }`}>
                          {item.triggered ? "Triggered" : "Not triggered"}
                        </span>
                      </div>
                      <p className={`text-xs mt-1 ${item.triggered ? "text-[#4f4941]" : "text-[#857b6e]"}`}>
                        {item.explanation}
                      </p>
                      {item.evidence && (
                        <p className={`text-xs font-mono mt-1 ${item.triggered ? "text-[#8f332d]" : "text-[#857b6e]"}`}>
                          <span className="font-semibold">Evidence:</span> {item.evidence}
                        </p>
                      )}
                    </div>
                    <span className={`text-xs font-semibold whitespace-nowrap ${
                      item.triggered ? "text-[#8f332d]" : "text-[#857b6e]"
                    }`}>
                      {item.points} points
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {(results.amounts?.length > 0 || results.payment_handles?.length > 0 || results.urgency_phrases?.length > 0 || results.extracted_urls?.length > 0) && (
              <div>
                <h3 className="text-sm font-semibold text-[#2b2926] mb-3">Extracted information</h3>
                <div className="border border-[#cfc5b6] rounded-sm divide-y divide-[#cfc5b6]">
                  {results.amounts?.length > 0 && (
                    <div className="p-3 flex flex-col gap-1 sm:flex-row sm:items-start sm:gap-4 bg-[#f6f2eb]">
                      <span className="font-medium text-sm text-[#2b2926] sm:w-40">Amounts</span>
                      <span className="text-xs font-mono text-[#625d55]">{results.amounts.join(", ")}</span>
                    </div>
                  )}
                  {results.payment_handles?.length > 0 && (
                    <div className="p-3 flex flex-col gap-1 sm:flex-row sm:items-start sm:gap-4 bg-[#f6f2eb]">
                      <span className="font-medium text-sm text-[#2b2926] sm:w-40">Payment handles</span>
                      <span className="text-xs font-mono text-[#625d55]">{results.payment_handles.join(", ")}</span>
                    </div>
                  )}
                  {results.urgency_phrases?.length > 0 && (
                    <div className="p-3 flex flex-col gap-1 sm:flex-row sm:items-start sm:gap-4 bg-[#f6f2eb]">
                      <span className="font-medium text-sm text-[#2b2926] sm:w-40">Urgency phrases</span>
                      <span className="text-xs font-mono text-[#625d55]">{results.urgency_phrases.join(", ")}</span>
                    </div>
                  )}
                  {results.extracted_urls?.length > 0 && (
                    <div className="p-3 flex flex-col gap-1 sm:flex-row sm:items-start sm:gap-4 bg-[#f6f2eb]">
                      <span className="font-medium text-sm text-[#2b2926] sm:w-40">URLs</span>
                      <span className="text-xs font-mono text-[#625d55] break-all">{results.extracted_urls.join(", ")}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Red Flags Table */}
            <div>
              <h3 className="text-sm font-semibold text-[#2b2926] mb-3">Identified Indicators & Evidence</h3>
              <div className="border border-[#cfc5b6] rounded-sm overflow-hidden">
                <table className="w-full text-left text-xs text-[#625d55]">
                  <thead className="bg-[#f1ece3] border-b border-[#cfc5b6] font-semibold text-[#2b2926]">
                    <tr>
                      <th className="p-3">Indicator</th>
                      <th className="p-3">Message Evidence</th>
                      <th className="p-3">Analysis</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#cfc5b6]">
                    {results.red_flags.map((flag, idx) => (
                      <tr key={idx} className="hover:bg-[#f6f2eb]">
                        <td className="p-3 font-medium text-[#2b2926]">{flag.indicator}</td>
                        <td className="p-3 font-mono text-[#857b6e] bg-[#f6f2eb]">{flag.evidence}</td>
                        <td className="p-3">{flag.explanation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="border border-[#d5b477] bg-[#f7efdf] rounded-sm p-4 space-y-4">
              <h3 className="text-sm font-bold text-[#2b2926] flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-[#a96d27]" /> Before you act
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-[#faf8f3] rounded-sm border border-[#cfc5b6]">
                <h4 className="text-xs font-bold text-[#2b2926] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4 text-[#52765d]" /> Recommended Safe Steps
                </h4>
                <ul className="text-xs text-[#625d55] space-y-1.5 list-disc pl-4">
                  {results.safe_next_steps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>

              <div className="p-4 bg-[#faf8f3] rounded-sm border border-[#cfc5b6]">
                <h4 className="text-xs font-bold text-[#2b2926] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-[#a96d27]" /> Official Verification Guidance
                </h4>
                <ul className="text-xs text-[#625d55] space-y-1.5 list-disc pl-4">
                  {results.verification_guidance.map((guide, idx) => (
                    <li key={idx}>{guide}</li>
                  ))}
                </ul>
              </div>
              </div>
            </div>

            {/* Regulatory Disclaimer */}
            <div className="p-3 bg-[#f7efdf] border border-[#d5b477] rounded-sm text-[#76501f] text-[11px] leading-relaxed">
              <strong>Disclaimer:</strong> {results.disclaimer || "NoticeGuard analyzes structural patterns, payment coercion indicators, and public domain institutional communication protocols. It provides risk mitigation steps rather than legally binding authenticity determinations."}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}