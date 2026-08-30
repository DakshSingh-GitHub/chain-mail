/* eslint-disable prefer-const */
import {
  EmailAnalysisInput,
  ForensicReport,
  ThreatClassification,
} from './types';
import { analyzeEmailThreat } from './forensic-engine';

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

export const SUPPORTED_GEMINI_MODELS = [
  { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash (Recommended)', description: 'Ultra-fast, accurate deep reasoning for real-time triage' },
  { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', description: 'Maximum depth for complex multi-stage APT analysis' },
  { id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', description: 'High-throughput lightweight model' }
];

const FORENSIC_SYSTEM_PROMPT = `You are ChainMail's AI Email Threat Forensic Engine — an autonomous, Tier-3 Senior Incident Response Investigator and Cyber Threat Intelligence Specialist.
Your purpose is to deeply dissect ingested RFC 5322 email headers and message bodies to uncover sophisticated Business Email Compromise (BEC), credential phishing, executive impersonation, homoglyph typosquatting, malware vectors, and authentication anomalies.

You must evaluate:
1. RFC 5322 & Cryptographic Headers:
   - Chronological 'Received:' hop chain latency and MTA traversal.
   - Isolation of the earliest reliable untrusted origin node IP (excluding RFC 1918 private subnets and trusted cloud gateway ingress like Cloudflare, Mimecast, Google Workspace).
   - SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489) validation and alignment.
   - Return-Path vs From divergence and Reply-To redirection.
   - Homoglyphs, typosquatting, and deceptive subdomain structures.
2. Natural Language Processing & Behavioral Heuristics:
   - Coercive psychological urgency, executive authority leverage, and secrecy mandates.
   - Financial fraud diversion (wire transfer instructions, routing changes, gift cards, invoice tampering).
   - Embedded link inspection (typosquatted domains, obfuscated redirects, tokenized phishing URLs).
   - Disguised attachment indicators (.iso, .vbs, .lnk, password-protected archives).
3. Attribution & Threat Intelligence:
   - Account state classification (Compromised Account, Purely Spoofed Domain, Direct Malicious Infrastructure, or Verified Legitimate).
   - Known cybercrime / APT campaign correlation (e.g. Cosmic Lynx, Scattered Spider, FIN7, TA505, Lazarus, or Benign).
   - Structured Indicators of Compromise (IoCs).
4. Actionable SOC Recommendations:
   - Prioritized containment steps (Immediate, High, Medium) with copy-pasteable technical commands (PowerShell, iptables, Azure AD Graph, Snort rules).
5. Scoring:
   - fraud_risk_score from 0 to 100:
     * 0-15: Completely Clean / Benign / Legitimate
     * 16-40: Low Risk / Minor Anomaly
     * 41-74: Suspicious / Impersonation Risk
     * 75-100: Critical Active Threat (Confirmed BEC, Phishing, or Weaponized Malware)

CRITICAL JSON RULES:
- You MUST return ONLY valid, parseable RFC 8259 JSON.
- Every string value must be valid JSON: escape all internal quotes as \\" and escape all newlines as \\n.
- NEVER include literal unescaped line breaks or unescaped quotes inside string values.
- Do NOT include markdown fences, backticks, or text outside the JSON object.`;

/**
 * Resilient JSON parser and repair utility for LLM outputs
 */
function cleanAndParseGeminiJson(rawText: string): Record<string, unknown> {
  if (!rawText || !rawText.trim()) {
    throw new Error('Gemini API returned an empty text payload.');
  }

  // 1. Strip markdown fences if present
  let cleaned = rawText.trim();
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, '');
    cleaned = cleaned.replace(/\s*```$/i, '');
    cleaned = cleaned.trim();
  }

  // 2. Direct parse attempt
  try {
    return JSON.parse(cleaned);
  } catch {
    // Continue to advanced repair
  }

  // 3. Scan and escape unescaped raw newlines and control characters inside quotes
  try {
    let inString = false;
    let escaped = false;
    let repaired = '';

    for (let i = 0; i < cleaned.length; i++) {
      const char = cleaned[i];

      if (char === '"' && !escaped) {
        inString = !inString;
        repaired += char;
      } else if (inString) {
        if (char === '\n') {
          repaired += '\\n';
        } else if (char === '\r') {
          repaired += '\\r';
        } else if (char === '\t') {
          repaired += '\\t';
        } else if (char === '\\' && !escaped) {
          escaped = true;
          repaired += char;
          continue;
        } else {
          repaired += char;
        }
      } else {
        repaired += char;
      }

      if (escaped && char !== '\\') {
        escaped = false;
      }
    }

    // Clean trailing commas before object/array closing
    repaired = repaired.replace(/,\s*([}\]])/g, '$1');

    return JSON.parse(repaired);
  } catch {
    // Continue to truncation & balance repair
  }

  // 4. Handle possible truncated response: balance unclosed brackets and braces
  try {
    let balanced = cleaned;

    // Fix open quotes
    const quoteMatches = balanced.match(/"/g);
    if (quoteMatches && quoteMatches.length % 2 !== 0) {
      balanced += '"';
    }

    let openBrackets = (balanced.match(/\[/g) || []).length;
    let closeBrackets = (balanced.match(/]/g) || []).length;
    while (openBrackets > closeBrackets) {
      balanced += ']';
      closeBrackets++;
    }

    let openBraces = (balanced.match(/{/g) || []).length;
    let closeBraces = (balanced.match(/}/g) || []).length;
    while (openBraces > closeBraces) {
      balanced += '}';
      closeBraces++;
    }

    // Escape strings within balanced text
    let inStr = false;
    let isEsc = false;
    let fixed = '';
    for (let i = 0; i < balanced.length; i++) {
      const c = balanced[i];
      if (c === '"' && !isEsc) {
        inStr = !inStr;
        fixed += c;
      } else if (inStr) {
        if (c === '\n') fixed += '\\n';
        else if (c === '\r') fixed += '\\r';
        else if (c === '\t') fixed += '\\t';
        else if (c === '\\' && !isEsc) {
          isEsc = true;
          fixed += c;
          continue;
        } else fixed += c;
      } else {
        fixed += c;
      }
      if (isEsc && c !== '\\') isEsc = false;
    }

    fixed = fixed.replace(/,\s*([}\]])/g, '$1');
    return JSON.parse(fixed);
  } catch (finalError) {
    console.error('Final JSON repair failed on payload:', rawText.slice(0, 500));
    throw new Error(`Failed to parse structured Gemini output: ${finalError instanceof Error ? finalError.message : 'Invalid JSON format'}`);
  }
}

/**
 * Validates connectivity with Gemini API using provided key
 */
export async function testGeminiApiKey(apiKey: string, model: string = 'gemini-2.5-flash'): Promise<{ success: boolean; model: string; message: string; latencyMs: number }> {
  const startTime = Date.now();
  try {
    const cleanKey = apiKey.trim();
    if (!cleanKey) {
      return { success: false, model, message: 'API key cannot be empty.', latencyMs: 0 };
    }

    const response = await fetch(`${GEMINI_API_BASE}/${model}:generateContent?key=${encodeURIComponent(cleanKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          {
            parts: [{ text: 'Respond with valid JSON: {"status": "ok", "message": "Gemini API connected successfully"}' }]
          }
        ],
        generationConfig: {
          responseMimeType: 'application/json',
          temperature: 0.1
        }
      })
    });

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      const errorText = await response.text();
      let errorMsg = `HTTP ${response.status} - ${response.statusText}`;
      try {
        const errorJson = JSON.parse(errorText);
        errorMsg = errorJson.error?.message || errorMsg;
      } catch {
        // use status text
      }
      return { success: false, model, message: errorMsg, latencyMs };
    }

    return {
      success: true,
      model,
      message: 'Connection verified. Gemini AI is ready to analyze email payloads.',
      latencyMs
    };
  } catch (err: unknown) {
    const latencyMs = Date.now() - startTime;
    return {
      success: false,
      model,
      message: err instanceof Error ? err.message : 'Network error communicating with Google Gemini API.',
      latencyMs
    };
  }
}

/**
 * Executes AI-powered Email Threat Analysis using Google Gemini API
 */
export async function analyzeEmailWithGemini(
  input: EmailAnalysisInput,
  apiKey: string,
  model: string = 'gemini-2.5-flash'
): Promise<ForensicReport> {
  const startTime = Date.now();
  const cleanKey = apiKey.trim();

  if (!cleanKey) {
    throw new Error('GEMINI_API_KEY environment variable is not configured.');
  }

  const promptUserContent = `Dissect the following email data and produce a strict JSON forensic analysis:

EMAIL SMTP HEADERS:
${input.raw_headers || 'None provided'}

EMAIL BODY CONTENT:
${input.email_body || 'None provided'}

INGESTION METADATA:
${JSON.stringify(input.metadata || {}, null, 2)}

Produce a valid single JSON object with:
- incident_id (string)
- threat_classification ("Legitimate" | "Suspicious" | "Impersonation" | "Phishing" | "BEC")
- fraud_risk_score (integer 0 to 100)
- nlp_analysis ({ intent, urgency_score, urgency_cues, social_engineering_tactics, financial_fraud_patterns, impersonation_target, detected_links, attachment_indicators, summary })
- header_forensics ({ spf, dkim, dmarc, return_path, from_header, reply_to_header, message_id, date_header, detected_spoofing, spoofing_vectors, relay_anomalies, domain_lookalike, hops })
- traceability_map ({ earliest_reliable_ip, reverse_dns, geolocation_estimate, infrastructure_type, infrastructure_risk_score, infrastructure_flags, domain_intelligence })
- attribution_confidence ({ account_state, confidence_level, confidence_score, associated_campaign, threat_actor, indicators_of_compromise, forensic_narrative })
- actionable_recommendations (array of { priority, category, action, technical_command, rationale })
- header_security_checks (array of { header_name, value, security_status, explanation })
- analysis_steps (array of { step_number, name, status, details })

CRITICAL: Return ONLY valid JSON with properly escaped strings (escape newlines as \\n and internal quotes as \\"). Do not output unescaped raw newlines in strings.`;

  const response = await fetch(`${GEMINI_API_BASE}/${model}:generateContent?key=${encodeURIComponent(cleanKey)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [
        {
          parts: [{ text: promptUserContent }]
        }
      ],
      systemInstruction: {
        parts: [{ text: FORENSIC_SYSTEM_PROMPT }]
      },
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.1,
        maxOutputTokens: 8192
      }
    })
  });

  const latencyMs = Date.now() - startTime;

  if (!response.ok) {
    const errText = await response.text();
    let message = `Gemini API returned HTTP ${response.status} (${response.statusText})`;
    try {
      const parsedErr = JSON.parse(errText);
      if (parsedErr.error?.message) {
        message = `Gemini Error: ${parsedErr.error.message}`;
      }
    } catch {
      // keep fallback message
    }
    throw new Error(message);
  }

  const responseData = await response.json();
  const rawText = responseData.candidates?.[0]?.content?.parts?.[0]?.text;

  if (!rawText) {
    throw new Error('Gemini API returned an empty response. Please verify payload formatting.');
  }

  // Parse with resilient JSON parser
  const parsed = cleanAndParseGeminiJson(rawText);
  const parsedReport = parsed as Partial<ForensicReport>;

  // Merge with baseline deterministic analysis to ensure complete integrity and no missing fields
  const baseline = analyzeEmailThreat(input);

  const finalReport: ForensicReport = {
    incident_id: typeof parsedReport.incident_id === 'string' ? parsedReport.incident_id : `INC-${Date.now().toString().slice(-8)}`,
    timestamp: typeof parsedReport.timestamp === 'string' ? parsedReport.timestamp : new Date().toISOString(),
    threat_classification: (parsedReport.threat_classification as ThreatClassification) || baseline.threat_classification,
    fraud_risk_score: typeof parsedReport.fraud_risk_score === 'number' ? Math.min(100, Math.max(0, parsedReport.fraud_risk_score)) : baseline.fraud_risk_score,
    nlp_analysis: {
      intent: (parsedReport.nlp_analysis?.intent as ThreatClassification) || baseline.nlp_analysis.intent,
      urgency_score: typeof parsedReport.nlp_analysis?.urgency_score === 'number' ? parsedReport.nlp_analysis.urgency_score : baseline.nlp_analysis.urgency_score,
      urgency_cues: Array.isArray(parsedReport.nlp_analysis?.urgency_cues) ? parsedReport.nlp_analysis.urgency_cues : baseline.nlp_analysis.urgency_cues,
      social_engineering_tactics: Array.isArray(parsedReport.nlp_analysis?.social_engineering_tactics) ? parsedReport.nlp_analysis.social_engineering_tactics : baseline.nlp_analysis.social_engineering_tactics,
      financial_fraud_patterns: Array.isArray(parsedReport.nlp_analysis?.financial_fraud_patterns) ? parsedReport.nlp_analysis.financial_fraud_patterns : baseline.nlp_analysis.financial_fraud_patterns,
      impersonation_target: parsedReport.nlp_analysis?.impersonation_target || baseline.nlp_analysis.impersonation_target,
      detected_links: Array.isArray(parsedReport.nlp_analysis?.detected_links) ? parsedReport.nlp_analysis.detected_links : baseline.nlp_analysis.detected_links,
      attachment_indicators: Array.isArray(parsedReport.nlp_analysis?.attachment_indicators) ? parsedReport.nlp_analysis.attachment_indicators : baseline.nlp_analysis.attachment_indicators,
      summary: parsedReport.nlp_analysis?.summary || baseline.nlp_analysis.summary
    },
    header_forensics: {
      spf: parsedReport.header_forensics?.spf || baseline.header_forensics.spf,
      dkim: parsedReport.header_forensics?.dkim || baseline.header_forensics.dkim,
      dmarc: parsedReport.header_forensics?.dmarc || baseline.header_forensics.dmarc,
      return_path: parsedReport.header_forensics?.return_path || baseline.header_forensics.return_path,
      from_header: parsedReport.header_forensics?.from_header || baseline.header_forensics.from_header,
      reply_to_header: parsedReport.header_forensics?.reply_to_header || baseline.header_forensics.reply_to_header,
      message_id: parsedReport.header_forensics?.message_id || baseline.header_forensics.message_id,
      date_header: parsedReport.header_forensics?.date_header || baseline.header_forensics.date_header,
      detected_spoofing: typeof parsedReport.header_forensics?.detected_spoofing === 'boolean' ? parsedReport.header_forensics.detected_spoofing : baseline.header_forensics.detected_spoofing,
      spoofing_vectors: Array.isArray(parsedReport.header_forensics?.spoofing_vectors) ? parsedReport.header_forensics.spoofing_vectors : baseline.header_forensics.spoofing_vectors,
      relay_anomalies: Array.isArray(parsedReport.header_forensics?.relay_anomalies) ? parsedReport.header_forensics.relay_anomalies : baseline.header_forensics.relay_anomalies,
      domain_lookalike: parsedReport.header_forensics?.domain_lookalike || baseline.header_forensics.domain_lookalike,
      hops: Array.isArray(parsedReport.header_forensics?.hops) && parsedReport.header_forensics.hops.length > 0 ? parsedReport.header_forensics.hops : baseline.header_forensics.hops
    },
    traceability_map: {
      earliest_reliable_ip: parsedReport.traceability_map?.earliest_reliable_ip || baseline.traceability_map.earliest_reliable_ip,
      reverse_dns: parsedReport.traceability_map?.reverse_dns || baseline.traceability_map.reverse_dns,
      geolocation_estimate: parsedReport.traceability_map?.geolocation_estimate || baseline.traceability_map.geolocation_estimate,
      infrastructure_type: parsedReport.traceability_map?.infrastructure_type || baseline.traceability_map.infrastructure_type,
      infrastructure_risk_score: typeof parsedReport.traceability_map?.infrastructure_risk_score === 'number' ? parsedReport.traceability_map.infrastructure_risk_score : baseline.traceability_map.infrastructure_risk_score,
      infrastructure_flags: Array.isArray(parsedReport.traceability_map?.infrastructure_flags) ? parsedReport.traceability_map.infrastructure_flags : baseline.traceability_map.infrastructure_flags,
      domain_intelligence: parsedReport.traceability_map?.domain_intelligence || baseline.traceability_map.domain_intelligence
    },
    attribution_confidence: {
      account_state: parsedReport.attribution_confidence?.account_state || baseline.attribution_confidence.account_state,
      confidence_level: parsedReport.attribution_confidence?.confidence_level || baseline.attribution_confidence.confidence_level,
      confidence_score: typeof parsedReport.attribution_confidence?.confidence_score === 'number' ? parsedReport.attribution_confidence.confidence_score : baseline.attribution_confidence.confidence_score,
      associated_campaign: parsedReport.attribution_confidence?.associated_campaign || baseline.attribution_confidence.associated_campaign,
      threat_actor: parsedReport.attribution_confidence?.threat_actor || baseline.attribution_confidence.threat_actor,
      indicators_of_compromise: Array.isArray(parsedReport.attribution_confidence?.indicators_of_compromise) ? parsedReport.attribution_confidence.indicators_of_compromise : baseline.attribution_confidence.indicators_of_compromise,
      forensic_narrative: parsedReport.attribution_confidence?.forensic_narrative || baseline.attribution_confidence.forensic_narrative
    },
    actionable_recommendations: Array.isArray(parsedReport.actionable_recommendations) && parsedReport.actionable_recommendations.length > 0 ? parsedReport.actionable_recommendations : baseline.actionable_recommendations,
    header_security_checks: Array.isArray(parsedReport.header_security_checks) && parsedReport.header_security_checks.length > 0 ? parsedReport.header_security_checks : baseline.header_security_checks,
    analysis_steps: Array.isArray(parsedReport.analysis_steps) && parsedReport.analysis_steps.length > 0 ? parsedReport.analysis_steps : baseline.analysis_steps,
    compliance_audit: baseline.compliance_audit,
    engine_mode: 'ai-gemini',
    model_name: model,
    analysis_latency_ms: latencyMs,
    ai_reasoning_summary: parsedReport.nlp_analysis?.summary || 'AI forensic dissection completed via Google Gemini.'
  };

  return finalReport;
}


