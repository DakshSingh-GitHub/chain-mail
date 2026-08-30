'use client';

import React, { useState } from 'react';
import {
  Copy,
  Play
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';
import { useForensicSession } from '@/components/forensic-context';
import { ActiveTargetBanner } from '@/components/active-target-banner';

export default function ApiDocsPage() {
  const { activeInput } = useForensicSession();
  const [selectedLanguage, setSelectedLanguage] = useState<'curl' | 'python' | 'node'>('curl');
  const [apiResponse, setApiResponse] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  const samplePayload = {
    raw_headers: activeInput?.raw_headers || PRESET_SCENARIOS[0].input.raw_headers,
    email_body: activeInput?.email_body || PRESET_SCENARIOS[0].input.email_body,
    metadata: activeInput?.metadata || PRESET_SCENARIOS[0].input.metadata
  };

  const handleTestApi = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(samplePayload)
      });
      const data = await res.json();
      setApiResponse(JSON.stringify(data, null, 2));
    } catch (err) {
      setApiResponse(JSON.stringify({ error: 'Failed to execute API call', details: String(err) }, null, 2));
    } finally {
      setIsLoading(false);
    }
  };

  const curlCode = `# Configured automatically on server via GEMINI_API_KEY in .env.local
curl -X POST https://chainmail-intelligence.internal/api/analyze \\
  -H "Content-Type: application/json" \\
  -d '{
    "raw_headers": "Delivered-To: ...\\nReceived: ...",
    "email_body": "Full body text...",
    "model": "gemini-2.5-flash",
    "engine_mode": "ai"
  }'`;

  const pythonCode = `import requests
import json

# Server uses GEMINI_API_KEY configured in environment variables
url = "https://chainmail-intelligence.internal/api/analyze"
headers = { "Content-Type": "application/json" }
payload = {
    "raw_headers": """${samplePayload.raw_headers.slice(0, 120)}...""",
    "email_body": """${samplePayload.email_body.slice(0, 80)}...""",
    "model": "gemini-2.5-flash",
    "engine_mode": "ai"
}

response = requests.post(url, json=payload, headers=headers)
forensic_report = response.json()

print(f"Engine: {forensic_report['_meta']['engine_mode']}")
print(f"Verdict: {forensic_report['threat_classification']}")
print(f"Risk Score: {forensic_report['fraud_risk_score']}/100")
print(f"Origin IP: {forensic_report['traceability_map']['earliest_reliable_ip']}")`;

  const nodeCode = `import fetch from 'node-fetch';

const response = await fetch('https://chainmail-intelligence.internal/api/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    raw_headers: \`\${rawHeaders}\`,
    email_body: \`\${emailBody}\`,
    model: 'gemini-2.5-flash',
    engine_mode: 'ai'
  })
});

const report = await response.json();
console.log('Engine Mode:', report._meta?.engine_mode);
console.log('Threat Classification:', report.threat_classification);
console.log('Actionable SOC Recommendations:', report.actionable_recommendations);`;

  const activeSnippet = selectedLanguage === 'curl' ? curlCode : selectedLanguage === 'python' ? pythonCode : nodeCode;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Active Target Banner */}
      <ActiveTargetBanner />

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              DEVELOPER & SIEM INTEGRATION API
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            AI Threat Engine REST API & Schema Reference
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Integrate autonomous email threat detection, SPF/DKIM/DMARC protocol analysis, and origin hop resolution into your SOAR pipeline.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20 font-semibold">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          POST /api/analyze (Live)
        </div>
      </div>

      {/* Schema Specification Card */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-6">
        <div className="flex items-center justify-between pb-4 border-b border-neutral-200 dark:border-black">
          <div>
            <h2 className="text-lg font-bold text-neutral-900 dark:text-white">
              API Endpoint Specification & Guardrails
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">Deterministic input validation and forensic response structure</p>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-mono bg-neutral-100 dark:bg-[#242424] text-neutral-800 dark:text-white border border-neutral-300 dark:border-black font-bold">
            HTTP POST
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs font-mono">
          {/* Request Payload */}
          <div className="space-y-2">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center justify-between font-sans">
              <span>Request Body (JSON)</span>
              <span className="text-neutral-600 dark:text-neutral-400 text-xs">application/json</span>
            </div>
            <pre className="p-4 rounded-2xl bg-neutral-900 dark:bg-[#121212] text-neutral-200 dark:text-neutral-300 text-[11px] leading-relaxed border border-neutral-800 dark:border-black overflow-x-auto">
              <code>{`{
  "raw_headers": "Delivered-To: ...\\nReceived: ...",
  "email_body": "Full body text or HTML...",
  "metadata": {
    "enriched_ip": "185.220.101.5",
    "threat_feed_hits": ["TOR_EXIT_NODE"]
  }
}`}</code>
            </pre>
          </div>

          {/* Response Payload */}
          <div className="space-y-2">
            <div className="font-bold text-neutral-900 dark:text-white flex items-center justify-between font-sans">
              <span>Response Body (7 Core Sections)</span>
              <span className="text-emerald-600 dark:text-emerald-500 text-xs font-semibold">HTTP 200 OK</span>
            </div>
            <pre className="p-4 rounded-2xl bg-neutral-900 dark:bg-[#121212] text-neutral-200 dark:text-neutral-300 text-[11px] leading-relaxed border border-neutral-800 dark:border-black overflow-x-auto">
              <code>{`{
  "threat_classification": "BEC" | "Phishing" | "Legitimate",
  "fraud_risk_score": 96,
  "nlp_analysis": { ... },
  "header_forensics": { ... },
  "traceability_map": { ... },
  "attribution_confidence": { ... },
  "actionable_recommendations": [ ... ]
}`}</code>
            </pre>
          </div>
        </div>
      </div>

      {/* Code Snippets & Interactive API Runner */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-200 dark:border-black">
          <div>
            <h2 className="text-lg font-bold text-neutral-900 dark:text-white">
              Integration Code Snippets & Interactive Test Runner
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">Trigger live API requests directly to test the backend response</p>
          </div>

          {/* Language Switcher Tabs */}
          <div className="flex items-center gap-1.5">
            {[
              { id: 'curl', label: 'cURL' },
              { id: 'python', label: 'Python' },
              { id: 'node', label: 'Node.js / TS' }
            ].map((lang) => (
              <button
                key={lang.id}
                onClick={() => setSelectedLanguage(lang.id as typeof selectedLanguage)}
                className={`px-3 py-1.5 rounded-full text-xs font-mono font-medium transition-all cursor-pointer border ${
                  selectedLanguage === lang.id
                    ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-black dark:border-black font-semibold shadow-xs'
                    : 'bg-neutral-100 dark:bg-[#222222] border-neutral-300 dark:border-black text-neutral-700 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-[#2a2a2a]'
                }`}
              >
                {lang.label}
              </button>
            ))}
          </div>
        </div>

        {/* Code Snippet Box */}
        <div className="relative">
          <button
            onClick={() => {
              navigator.clipboard.writeText(activeSnippet);
              setCopiedCode(true);
              setTimeout(() => setCopiedCode(false), 2000);
            }}
            className="absolute top-3 right-3 px-3 py-1 rounded-full text-[11px] font-mono bg-neutral-800 hover:bg-neutral-700 dark:bg-[#242424] dark:hover:bg-[#303030] text-neutral-200 dark:text-neutral-300 border border-neutral-700 dark:border-black transition-colors cursor-pointer flex items-center gap-1 z-10"
          >
            <Copy className="w-3 h-3" />
            {copiedCode ? 'Copied!' : 'Copy Code'}
          </button>
          <pre className="p-4 rounded-2xl bg-neutral-900 dark:bg-[#121212] text-neutral-200 dark:text-neutral-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-72 border border-neutral-800 dark:border-black">
            <code>{activeSnippet}</code>
          </pre>
        </div>

        {/* Live Test Trigger Button */}
        <div className="pt-2 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <button
            onClick={handleTestApi}
            disabled={isLoading}
            className="inline-flex items-center gap-2 px-6 py-3 rounded-full text-xs font-semibold text-white bg-neutral-950 hover:bg-neutral-800 dark:text-black dark:bg-white dark:hover:bg-neutral-200 border border-neutral-950 dark:border-black shadow-lg transition-all cursor-pointer disabled:opacity-50"
          >
            {isLoading ? (
              <div className="w-3.5 h-3.5 border-2 border-white dark:border-black border-t-transparent rounded-full animate-spin"></div>
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            <span>Execute Live API Request (POST /api/analyze)</span>
          </button>

          <span className="text-xs text-neutral-600 dark:text-neutral-400 font-mono">Status: 200 OK Guaranteed</span>
        </div>

        {/* Live Response Output */}
        {apiResponse && (
          <div className="space-y-2 pt-4 border-t border-neutral-200 dark:border-black">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-emerald-600 dark:text-emerald-500 font-bold">Live In-Browser API Response:</span>
              <span className="text-neutral-600 dark:text-neutral-400">JSON Payload</span>
            </div>
            <pre className="p-4 rounded-2xl bg-neutral-900 dark:bg-[#121212] text-emerald-400 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-80 border border-neutral-800 dark:border-black">
              <code>{apiResponse}</code>
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
