/* eslint-disable react-hooks/purity */
'use client';

import React, { useState, useMemo, useRef, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Upload,
  Search,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Brain,
  FileCode,
  MapPin,
  Crosshair,
  Sparkles,
  Code,
  ShieldCheck,
  ArrowLeft,
  Play,
  Copy,
  Globe,
  SlidersHorizontal,
  ChevronRight,
  ShieldAlert,
  ListOrdered,
  Cpu,
  Zap,
  RefreshCw,
  Loader2
} from 'lucide-react';
import { MOCK_100_EMAILS, EmailRecord } from '@/lib/mock-emails';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { parseEmlFileContent } from '@/lib/eml-parser';
import { ForensicReport, EmailAnalysisInput } from '@/lib/types';
import { useForensicSession } from '@/components/forensic-context';

interface ForensicStage {
  step: number;
  label: string;
  detail: string;
  percent: number;
}

const FORENSIC_STAGES: ForensicStage[] = [
  { step: 1, label: 'RFC 5322 Ingestion', detail: 'Parsing SMTP headers, Return-Path & MIME boundaries...', percent: 18 },
  { step: 2, label: 'MTA Traceability', detail: 'Deconstructing Received hop relays & isolating earliest reliable origin node...', percent: 38 },
  { step: 3, label: 'Auth Alignment', detail: 'Evaluating cryptographic SPF (RFC 7208), DKIM (RFC 6376) and DMARC (RFC 7489)...', percent: 58 },
  { step: 4, label: 'Gemini AI Dissection', detail: 'Dissecting NLP behavioral urgency, financial diversion & homoglyph lookalikes...', percent: 80 },
  { step: 5, label: 'Attribution & Playbook', detail: 'Synthesizing threat attribution, IoCs and SOC containment commands...', percent: 94 },
  { step: 6, label: 'Dossier Ready', detail: 'Forensic threat dossier synthesized and cryptographic alignment verified.', percent: 100 }
];

function AnalyzerContent() {
  const searchParams = useSearchParams();
  const mailIdQuery = searchParams.get('mailId') || searchParams.get('preset');
  const { activeInput, activeReport, activeMeta, setActiveEmail } = useForensicSession();

  // Engine Configuration State (Key is sourced from server environment variable GEMINI_API_KEY)
  const [geminiModel] = useState<string>('gemini-2.5-flash');
  const [engineMode, setEngineMode] = useState<'ai' | 'heuristic'>('ai');
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Dynamic Progress Bar States
  const [analysisProgress, setAnalysisProgress] = useState<number>(0);
  const [currentStageIndex, setCurrentStageIndex] = useState<number>(0);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const progressTimerRef = useRef<NodeJS.Timeout | null>(null);
  const elapsedTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      if (progressTimerRef.current) clearInterval(progressTimerRef.current);
      if (elapsedTimerRef.current) clearInterval(elapsedTimerRef.current);
    };
  }, []);

  // Selected email state (null = show 100-email selector / upload gate)
  const [selectedMail, setSelectedMail] = useState<EmailRecord | null>(() => {
    if (mailIdQuery) {
      return MOCK_100_EMAILS.find(m => m.id === mailIdQuery) || null;
    }
    return null;
  });

  // Filter & Search states for the 100-email catalog
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | 'SPOOFED' | 'SAFE' | 'BEC' | 'PHISHING' | 'MALWARE'>('ALL');
  const [minRiskFilter, setMinRiskFilter] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  // Mobile drawer / sidebar toggle states
  const [mobileFilterOpen, setMobileFilterOpen] = useState(false);
  const [mobileEditorOpen, setMobileEditorOpen] = useState(false);

  // Analysis report and edit states
  const [report, setReport] = useState<ForensicReport | null>(() => {
    if (mailIdQuery) {
      const match = MOCK_100_EMAILS.find(m => m.id === mailIdQuery);
      if (match) return analyzeEmailThreat(match.input);
    }
    return null;
  });

  const [rawHeaders, setRawHeaders] = useState<string>(() => selectedMail?.input.raw_headers || '');
  const [emailBody, setEmailBody] = useState<string>(() => selectedMail?.input.email_body || '');
  const [metadataJson, setMetadataJson] = useState<string>(() => JSON.stringify(selectedMail?.input.metadata || {}, null, 2));
  const [activeTab, setActiveTab] = useState<'overview' | 'analysisSteps' | 'headerSecurity' | 'headers' | 'traceability' | 'nlp' | 'attribution' | 'recs' | 'rawJson' | 'markdown'>('overview');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  // Filter 100 emails
  const filteredEmails = useMemo(() => {
    return MOCK_100_EMAILS.filter((mail) => {
      const matchesSearch =
        searchTerm === '' ||
        mail.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
        mail.senderEmail.toLowerCase().includes(searchTerm.toLowerCase()) ||
        mail.senderName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        mail.originIp.includes(searchTerm) ||
        mail.id.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesCategory =
        categoryFilter === 'ALL' ||
        (categoryFilter === 'SPOOFED' && mail.isSpoofed) ||
        (categoryFilter === 'SAFE' && !mail.isSpoofed) ||
        (categoryFilter === 'BEC' && mail.category === 'BEC') ||
        (categoryFilter === 'PHISHING' && mail.category === 'Phishing') ||
        (categoryFilter === 'MALWARE' && mail.category === 'Suspicious');

      const matchesRisk = mail.simulatedRisk >= minRiskFilter;

      return matchesSearch && matchesCategory && matchesRisk;
    });
  }, [searchTerm, categoryFilter, minRiskFilter]);

  const totalPages = Math.ceil(filteredEmails.length / itemsPerPage) || 1;
  const paginatedEmails = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredEmails.slice(start, start + itemsPerPage);
  }, [filteredEmails, currentPage]);

  // Execute analysis with Gemini AI or Heuristics Engine
  const executeAnalysisPayload = async (input: EmailAnalysisInput, modeOverride?: 'ai' | 'heuristic') => {
    setIsAnalyzing(true);
    setAnalysisError(null);
    setAnalysisProgress(12);
    setCurrentStageIndex(0);
    setElapsedSeconds(0);

    if (progressTimerRef.current) clearInterval(progressTimerRef.current);
    if (elapsedTimerRef.current) clearInterval(elapsedTimerRef.current);

    const startTime = Date.now();
    elapsedTimerRef.current = setInterval(() => {
      setElapsedSeconds(parseFloat(((Date.now() - startTime) / 1000).toFixed(1)));
    }, 100);

    // Progressively advance through stages
    let stepCount = 0;
    progressTimerRef.current = setInterval(() => {
      stepCount++;
      if (stepCount === 1) {
        setAnalysisProgress(24);
        setCurrentStageIndex(0);
      } else if (stepCount === 2) {
        setAnalysisProgress(42);
        setCurrentStageIndex(1);
      } else if (stepCount === 3) {
        setAnalysisProgress(62);
        setCurrentStageIndex(2);
      } else if (stepCount === 4) {
        setAnalysisProgress(80);
        setCurrentStageIndex(3);
      } else if (stepCount >= 5) {
        setAnalysisProgress((prev) => Math.min(94, prev + 2));
        setCurrentStageIndex(4);
      }
    }, 320);

    const activeMode = modeOverride || engineMode;

    // Fast initial fallback report while executing
    const initialReport = analyzeEmailThreat(input);
    initialReport.engine_mode = 'heuristic-offline';
    setReport(initialReport);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-engine-mode': activeMode
        },
        body: JSON.stringify({
          raw_headers: input.raw_headers,
          email_body: input.email_body,
          metadata: input.metadata,
          model: geminiModel,
          engine_mode: activeMode
        })
      });

      if (res.ok) {
        const data = await res.json();
        setReport(data);
        setActiveEmail(input, data, {
          id: selectedMail?.id,
          subject: selectedMail?.subject,
          senderName: selectedMail?.senderName,
          senderEmail: selectedMail?.senderEmail,
          isUploaded: Boolean(selectedMail?.id?.startsWith('EML-'))
        });
        if (data._meta?.ai_error) {
          setAnalysisError(data._meta.ai_error);
        }
      }
    } catch (err: unknown) {
      console.warn('Network error running analysis, fallback active:', err);
    } finally {
      if (progressTimerRef.current) clearInterval(progressTimerRef.current);
      if (elapsedTimerRef.current) clearInterval(elapsedTimerRef.current);

      setAnalysisProgress(100);
      setCurrentStageIndex(5);

      // Brief delay to let user see 100% completion before concluding animation
      setTimeout(() => {
        setIsAnalyzing(false);
      }, 450);
    }
  };

  // Load a chosen email into the active workbench
  const handleSelectEmail = (mail: EmailRecord) => {
    setSelectedMail(mail);
    setRawHeaders(mail.input.raw_headers);
    setEmailBody(mail.input.email_body);
    setMetadataJson(JSON.stringify(mail.input.metadata || {}, null, 2));

    setActiveEmail(mail.input, undefined, {
      id: mail.id,
      subject: mail.subject,
      senderName: mail.senderName,
      senderEmail: mail.senderEmail,
      isUploaded: false
    });

    executeAnalysisPayload(mail.input);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Handle .EML file upload
  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content) return;

      const parsed = parseEmlFileContent(content);
      const rep = analyzeEmailThreat(parsed);

      const customRecord: EmailRecord = {
        id: `EML-UPLOAD-${Date.now().toString().slice(-4)}`,
        subject: parsed.raw_headers.match(/Subject:\s*([^\r\n]+)/i)?.[1] || file.name,
        senderName: parsed.raw_headers.match(/From:\s*"?([^"<]+)"?\s*</i)?.[1] || 'External Sender',
        senderEmail: parsed.raw_headers.match(/From:\s*[^<]*<([^>]+)>/i)?.[1] || 'sender@external.com',
        displayDomain: 'custom-file.eml',
        actualDomain: 'custom-file.eml',
        recipient: 'analyst@acme-corp.com',
        date: new Date().toLocaleDateString(),
        category: rep.threat_classification,
        isSpoofed: rep.header_forensics.detected_spoofing,
        threatLevel: rep.fraud_risk_score > 70 ? 'Critical' : rep.fraud_risk_score > 40 ? 'High' : 'Clean',
        simulatedRisk: rep.fraud_risk_score,
        originIp: rep.traceability_map.earliest_reliable_ip,
        originCountry: rep.traceability_map.geolocation_estimate.country,
        snippet: parsed.email_body.slice(0, 120) + '...',
        input: parsed
      };

      setSelectedMail(customRecord);
      setRawHeaders(parsed.raw_headers);
      setEmailBody(parsed.email_body);
      setMetadataJson(JSON.stringify(parsed.metadata || {}, null, 2));

      setActiveEmail(parsed, rep, {
        id: customRecord.id,
        subject: customRecord.subject,
        senderName: customRecord.senderName,
        senderEmail: customRecord.senderEmail,
        isUploaded: true,
        fileName: file.name
      });

      executeAnalysisPayload(parsed);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    reader.readAsText(file);
  };

  const handleReRunAnalysis = (overrideMode?: 'ai' | 'heuristic') => {
    let parsedMeta = {};
    try {
      parsedMeta = JSON.parse(metadataJson);
    } catch {
      parsedMeta = {};
    }

    const input: EmailAnalysisInput = {
      raw_headers: rawHeaders,
      email_body: emailBody,
      metadata: parsedMeta
    };

    executeAnalysisPayload(input, overrideMode);
  };

  const handleCopy = (text: string, sectionKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionKey);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const generateMarkdownReport = (rep: ForensicReport) => {
    return `# FORENSIC INCIDENT INVESTIGATION REPORT: ${rep.incident_id}
Generated: ${rep.timestamp}
Evidence SHA256: ${rep.compliance_audit.evidence_hash_sha256}

## 1. EXECUTIVE VERDICT & THREAT CLASSIFICATION
- Threat Classification: **${rep.threat_classification}**
- Fraud Risk Score: **${rep.fraud_risk_score} / 100** (Lower = Safer)
- Account State: **${rep.attribution_confidence.account_state}**
- Attribution Confidence: **${rep.attribution_confidence.confidence_level} (${rep.attribution_confidence.confidence_score}%)**

## 2. HOW THIS EMAIL WAS ANALYZED
${rep.analysis_steps.map(s => `### Step ${s.step_number}: ${s.name} [${s.status}]
${s.details}`).join('\n\n')}

## 3. HEADER SECURITY AUDIT
${rep.header_security_checks.map(h => `* **${h.header_name}** [${h.security_status}]: \`${h.value}\`
  ${h.explanation}`).join('\n')}

## 4. ACTIONABLE SOC RECOMMENDATIONS
${rep.actionable_recommendations.map(r => `* [${r.priority}] ${r.action} (${r.category})
  ${r.rationale}`).join('\n\n')}
`;
  };

  // ==========================================
  // VIEW 1: EMAIL SELECTION & UPLOAD GATEWAY
  // ==========================================
  if (!selectedMail || !report) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8">
        {/* Top Hero Banner */}
        <div className="p-6 sm:p-8 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-3 sm:space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
                  RFC 5322 THREAT ANALYSIS SUITE
                </span>
              </div>
              <h1 className="text-2xl sm:text-4xl font-extrabold text-neutral-900 dark:text-white">
                Email Threat Forensic Analyzer
              </h1>
              <p className="text-xs sm:text-sm text-neutral-600 dark:text-neutral-400 max-w-2xl leading-relaxed">
                Autonomous multi-stage email threat dissection powered by Google Gemini AI and RFC 5322 cryptographic verification. Upload your raw <code className="font-mono text-neutral-900 dark:text-white bg-neutral-200/80 dark:bg-[#242424] px-1.5 py-0.5 rounded border border-neutral-300 dark:border-black">*.eml</code> message file or select from the 100 live threat queue emails below.
              </p>
            </div>

            
          </div>
        </div>

        {/* Drag and Drop .EML Uploader */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragActive(false);
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
              handleFileUpload(e.dataTransfer.files[0]);
            }
          }}
          className={`p-6 sm:p-8 rounded-3xl border-2 border-dashed transition-all text-center space-y-3 cursor-pointer ${
            dragActive
              ? 'border-neutral-900 dark:border-white bg-neutral-100 dark:bg-[#222222]'
              : 'border-neutral-300 dark:border-black bg-neutral-50 dark:bg-[#141414] hover:bg-neutral-100 dark:hover:bg-[#1a1a1a]'
          }`}
          onClick={() => {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = '.eml,.txt,.msg';
            input.onchange = (ev) => {
              const target = ev.target as HTMLInputElement;
              if (target.files && target.files[0]) {
                handleFileUpload(target.files[0]);
              }
            };
            input.click();
          }}
        >
          <div className="w-10 h-10 sm:w-12 sm:h-12 rounded-2xl bg-neutral-100 dark:bg-[#242424] border border-neutral-300 dark:border-black flex items-center justify-center text-neutral-900 dark:text-white mx-auto shadow-md">
            <Upload className="w-5 h-5 sm:w-6 sm:h-6" />
          </div>
          <div className="space-y-1">
            <div className="text-sm sm:text-base font-bold text-neutral-900 dark:text-white">
              Drop your <span className="font-mono text-neutral-900 dark:text-white">*.eml</span> file here or click to browse
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              Supports RFC 5322 SMTP headers, MIME body extraction, and message archives (.eml, .txt, .msg)
            </p>
          </div>
        </div>

        {/* 100 Email Queue Dataset Section */}
        <div className="rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl p-4 sm:p-8 space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-neutral-200 dark:border-black">
            <div>
              <div className="flex items-center justify-between">
                <h2 className="text-lg sm:text-xl font-extrabold text-neutral-900 dark:text-white flex items-center gap-2">
                  <span>Threat Ingestion Queue</span>
                  <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-neutral-100 dark:bg-[#242424] text-neutral-700 dark:text-neutral-300 border border-neutral-300 dark:border-black">
                    {filteredEmails.length} Emails
                  </span>
                </h2>

                {/* Mobile Filter Toggle Button */}
                <button
                  onClick={() => setMobileFilterOpen(!mobileFilterOpen)}
                  className="md:hidden flex items-center gap-1 px-3 py-1 rounded-full border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#242424] text-xs text-neutral-800 dark:text-white"
                >
                  <SlidersHorizontal className="w-3.5 h-3.5" />
                  <span>Filters</span>
                </button>
              </div>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 mt-0.5">
                Risk Score scale: <strong className="text-neutral-900 dark:text-white">0-15 = Safe</strong>, <strong className="text-rose-600 dark:text-rose-400">75-100 = Critical Threat</strong>. Lower score = safer email.
              </p>
            </div>

            {/* Search Input */}
            <div className="relative w-full md:w-72">
              <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
              <input
                type="text"
                placeholder="Search subject, sender, IP, or case ID..."
                value={searchTerm}
                onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                className="w-full pl-9 pr-4 py-2 rounded-full text-xs font-mono border border-neutral-300 dark:border-black bg-neutral-50 dark:bg-[#121212] text-neutral-800 dark:text-neutral-200 focus:outline-none focus:border-neutral-400"
              />
            </div>
          </div>

          {/* Filter Controls (Collapsible on Mobile) */}
          <div className={`${mobileFilterOpen ? 'block' : 'hidden md:flex'} flex-col md:flex-row md:items-center justify-between gap-3 text-xs space-y-3 md:space-y-0`}>
            <div className="flex flex-wrap items-center gap-1.5 p-1 rounded-2xl md:rounded-full border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#121212]">
              {[
                { id: 'ALL', label: 'All (100)' },
                { id: 'SPOOFED', label: 'Spoofed Threats (67)' },
                { id: 'SAFE', label: 'Safe / Clean (33)' },
                { id: 'BEC', label: 'BEC Wires (27)' },
                { id: 'PHISHING', label: 'Phishing (27)' },
                { id: 'MALWARE', label: 'Malware (13)' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => { setCategoryFilter(tab.id as typeof categoryFilter); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-full font-mono transition-all cursor-pointer border text-xs ${
                    categoryFilter === tab.id
                      ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-black dark:border-black font-bold shadow-xs'
                      : 'border-transparent text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Risk filter */}
            <div className="flex items-center gap-2 font-mono text-neutral-600 dark:text-neutral-400 pt-2 md:pt-0">
              <SlidersHorizontal className="w-3.5 h-3.5 shrink-0" />
              <span>Min Risk: {minRiskFilter}%</span>
              <input
                type="range"
                min="0"
                max="90"
                step="10"
                value={minRiskFilter}
                onChange={(e) => { setMinRiskFilter(parseInt(e.target.value, 10)); setCurrentPage(1); }}
                className="w-24 accent-neutral-900 dark:accent-white cursor-pointer"
              />
            </div>
          </div>

          {/* 100 Email List Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {paginatedEmails.map((mail) => (
              <div
                key={mail.id}
                onClick={() => handleSelectEmail(mail)}
                className="p-4 sm:p-5 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#141414] hover:bg-neutral-100 dark:hover:bg-[#1e1e1e] transition-all cursor-pointer flex flex-col justify-between space-y-3 sm:space-y-4 shadow-md group"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-neutral-900 dark:text-white group-hover:underline flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400" />
                      {mail.id}
                    </span>

                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                        mail.isSpoofed
                          ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
                          : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                      }`}
                    >
                      {mail.isSpoofed ? 'SPOOFED / THREAT' : 'AUTHENTIC / SAFE'}
                    </span>
                  </div>

                  <div>
                    <h3 className="font-bold text-xs text-neutral-900 dark:text-white line-clamp-1 group-hover:text-neutral-600 dark:group-hover:text-neutral-200">
                      {mail.subject}
                    </h3>
                    <div className="text-[11px] text-neutral-500 dark:text-neutral-400 line-clamp-1 mt-0.5 font-sans">
                      {mail.senderName} &lt;{mail.senderEmail}&gt;
                    </div>
                  </div>

                  <p className="text-[11px] text-neutral-600 dark:text-neutral-400 line-clamp-2 leading-relaxed font-sans">
                    {mail.snippet}
                  </p>
                </div>

                <div className="pt-2 sm:pt-3 border-t border-neutral-200 dark:border-black flex items-center justify-between text-[11px] font-mono">
                  <div className="text-neutral-500 dark:text-neutral-400 flex items-center gap-1 truncate max-w-[140px]">
                    <Globe className="w-3 h-3 text-neutral-500 dark:text-neutral-400 shrink-0" />
                    <span className="truncate">{mail.originCountry}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`font-bold ${mail.simulatedRisk > 75 ? 'text-rose-600 dark:text-rose-500' : mail.simulatedRisk > 40 ? 'text-amber-600 dark:text-amber-500' : 'text-emerald-600 dark:text-emerald-500'}`}>
                      Risk: {mail.simulatedRisk}/100
                    </span>
                    <ChevronRight className="w-3.5 h-3.5 text-neutral-400 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-neutral-200 dark:border-black text-xs font-mono">
              <span className="text-neutral-600 dark:text-neutral-400">
                Page {currentPage} of {totalPages} ({filteredEmails.length} emails)
              </span>
              <div className="flex items-center gap-1">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  className="px-3 py-1 rounded-full border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#1e1e1e] text-neutral-800 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-[#282828] disabled:opacity-30 cursor-pointer"
                >
                  Previous
                </button>
                <button
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  className="px-3 py-1 rounded-full border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#1e1e1e] text-neutral-800 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-[#282828] disabled:opacity-30 cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ==========================================
  // VIEW 2: ACTIVE FORENSIC REPORT WORKBENCH
  // ==========================================
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8">
      {/* Top Action Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 sm:p-5 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSelectedMail(null)}
            className="px-3.5 py-1.5 rounded-full text-xs font-mono font-semibold border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#222222] text-neutral-800 dark:text-white hover:bg-neutral-200 dark:hover:bg-[#2c2c2c] transition-colors cursor-pointer flex items-center gap-1.5 shrink-0"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Back to</span> 100 Email Queue
          </button>
          <div className="min-w-0">
            <div className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Selected Target</div>
            <div className="text-xs sm:text-sm font-bold font-mono text-neutral-900 dark:text-white truncate max-w-xs sm:max-w-md">{selectedMail.subject}</div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Mobile Payload Editor Toggle */}
          <button
            onClick={() => setMobileEditorOpen(!mobileEditorOpen)}
            className="lg:hidden px-3.5 py-1.5 rounded-full text-xs font-mono font-semibold border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#242424] text-neutral-800 dark:text-neutral-300 flex items-center gap-1.5"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{mobileEditorOpen ? 'Hide Payload' : 'Edit Payload'}</span>
          </button>

          <label className="px-3.5 py-1.5 rounded-full text-xs font-mono font-semibold border border-neutral-950 dark:border-black bg-neutral-950 text-white dark:bg-white dark:text-black hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-colors cursor-pointer flex items-center gap-1.5 shadow-sm">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload Another .EML</span>
            <input
              type="file"
              accept=".eml,.txt,.msg"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileUpload(e.target.files[0]);
                }
              }}
            />
          </label>
        </div>
      </div>

      {/* Main Forensic Workbench Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 sm:gap-8">
        {/* Left Column (4 Cols): Raw Ingest Details & Live Editor (Collapsible on Mobile) */}
        <div className={`lg:col-span-4 space-y-6 ${mobileEditorOpen ? 'block' : 'hidden lg:block'}`}>
          <div className="p-5 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-black">
              <span className="text-xs font-bold uppercase tracking-wider text-neutral-800 dark:text-neutral-300 font-mono">
                Target Payload Editor
              </span>
              <span className="text-[10px] font-mono text-neutral-500">{selectedMail.id}</span>
            </div>

            {/* Engine Selector Toggle */}
            <div className="space-y-1.5">
              <label className="font-semibold text-xs text-neutral-700 dark:text-neutral-300 flex items-center justify-between">
                <span>Execution Engine</span>
                <span className="text-[10px] font-mono text-neutral-500">via GEMINI_API_KEY</span>
              </label>
              <div className="grid grid-cols-2 gap-1.5 p-1 rounded-2xl border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#141414]">
                <button
                  type="button"
                  onClick={() => setEngineMode('ai')}
                  className={`py-1.5 px-2 rounded-xl text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                    engineMode === 'ai'
                      ? 'bg-neutral-950 text-white dark:bg-white dark:text-black shadow-xs'
                      : 'text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white'
                  }`}
                >
                  <Sparkles className="w-3 h-3 text-amber-500 fill-amber-500" />
                  <span>Gemini AI</span>
                </button>
                <button
                  type="button"
                  onClick={() => setEngineMode('heuristic')}
                  className={`py-1.5 px-2 rounded-xl text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                    engineMode === 'heuristic'
                      ? 'bg-neutral-950 text-white dark:bg-white dark:text-black shadow-xs'
                      : 'text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white'
                  }`}
                >
                  <Zap className="w-3 h-3 text-neutral-400" />
                  <span>Heuristics</span>
                </button>
              </div>
            </div>

            {/* Raw Headers Input */}
            <div className="space-y-1.5">
              <label className="font-semibold text-xs text-neutral-700 dark:text-neutral-300">Raw SMTP Headers</label>
              <textarea
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
                rows={7}
                className="w-full p-3 rounded-xl font-mono text-[11px] leading-relaxed border border-neutral-300 dark:border-black bg-neutral-50 dark:bg-[#121212] text-neutral-800 dark:text-neutral-200 focus:outline-none focus:border-neutral-400"
              />
            </div>

            {/* Email Body Input */}
            <div className="space-y-1.5">
              <label className="font-semibold text-xs text-neutral-700 dark:text-neutral-300">Email Body</label>
              <textarea
                value={emailBody}
                onChange={(e) => setEmailBody(e.target.value)}
                rows={5}
                className="w-full p-3 rounded-xl font-sans text-xs leading-relaxed border border-neutral-300 dark:border-black bg-neutral-50 dark:bg-[#121212] text-neutral-800 dark:text-neutral-200 focus:outline-none focus:border-neutral-400"
              />
            </div>

            {/* Action Trigger Button */}
            <button
              onClick={() => handleReRunAnalysis(engineMode)}
              disabled={isAnalyzing}
              className="w-full py-3 px-4 rounded-xl font-semibold text-xs text-white bg-neutral-950 hover:bg-neutral-800 dark:text-black dark:bg-white dark:hover:bg-neutral-200 border border-neutral-950 dark:border-black shadow-lg transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isAnalyzing ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white dark:border-black border-t-transparent rounded-full animate-spin"></div>
                  <span>{engineMode === 'ai' ? `Gemini AI Dissecting... ${analysisProgress}%` : `Calculating Heuristics... ${analysisProgress}%`}</span>
                </>
              ) : (
                <>
                  {engineMode === 'ai' ? (
                    <Sparkles className="w-3.5 h-3.5 text-amber-400 fill-amber-400" />
                  ) : (
                    <Play className="w-3.5 h-3.5 fill-current" />
                  )}
                  <span>{engineMode === 'ai' ? `Analyze with ${geminiModel}` : 'Re-Run Forensic Engine'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column (8 Cols): Forensic Report Viewer */}
        <div className="lg:col-span-8 space-y-6">
          {/* Dynamic Analysis Progress HUD Card */}
          {isAnalyzing && (
            <div className="p-5 sm:p-6 rounded-3xl border border-amber-500/40 bg-white dark:bg-[#181818] shadow-2xl space-y-4 animate-in fade-in slide-in-from-top-4 duration-300">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center shrink-0">
                    <Sparkles className="w-5 h-5 text-amber-500 fill-amber-500 animate-pulse" />
                  </div>
                  <div>
                    <div className="text-xs font-mono font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300 flex items-center gap-2">
                      <span>{engineMode === 'ai' ? 'Gemini 2.5 Flash Dissecting Threat' : 'Heuristic Engine Running'}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-700 dark:text-amber-300 font-mono">
                        PHASE {Math.min(currentStageIndex + 1, 5)} OF 5
                      </span>
                    </div>
                    <div className="text-sm sm:text-base font-bold text-neutral-900 dark:text-white">
                      {FORENSIC_STAGES[currentStageIndex]?.label || 'Deep Analysis'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right font-mono">
                    <div className="text-2xl font-black text-amber-600 dark:text-amber-400">
                      {analysisProgress}%
                    </div>
                    <div className="text-[11px] text-neutral-500 dark:text-neutral-400">
                      {elapsedSeconds.toFixed(1)}s elapsed
                    </div>
                  </div>
                </div>
              </div>

              {/* Animated Progress Bar Track */}
              <div className="w-full h-3.5 rounded-full bg-neutral-200 dark:bg-neutral-800 p-0.5 overflow-hidden relative shadow-inner">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-amber-500 via-amber-400 to-emerald-400 transition-all duration-300 ease-out relative shadow-sm"
                  style={{ width: `${analysisProgress}%` }}
                >
                  <div className="absolute inset-0 bg-white/25 animate-pulse" />
                </div>
              </div>

              {/* Current Step Description */}
              <div className="text-xs font-mono text-neutral-600 dark:text-neutral-300 flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-amber-500 animate-ping shrink-0" />
                <span className="truncate">{FORENSIC_STAGES[currentStageIndex]?.detail}</span>
              </div>

              {/* Multi-step Stage Indicator Nodes */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-3 border-t border-neutral-200 dark:border-neutral-800">
                {FORENSIC_STAGES.slice(0, 5).map((stage, idx) => {
                  const isDone = currentStageIndex > idx || analysisProgress === 100;
                  const isActive = currentStageIndex === idx && analysisProgress < 100;

                  return (
                    <div
                      key={stage.step}
                      className={`p-2 sm:p-2.5 rounded-xl border text-[11px] font-mono transition-all ${
                        isDone
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
                          : isActive
                          ? 'border-amber-500/40 bg-amber-500/10 text-amber-900 dark:text-amber-300 font-bold shadow-xs'
                          : 'border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#202020] text-neutral-400 dark:text-neutral-600'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 truncate">
                        {isDone ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                        ) : isActive ? (
                          <div className="w-3.5 h-3.5 border-2 border-amber-500 border-t-transparent rounded-full animate-spin shrink-0" />
                        ) : (
                          <div className="w-1.5 h-1.5 rounded-full bg-neutral-300 dark:bg-neutral-700 shrink-0" />
                        )}
                        <span className="truncate">{stage.label}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Verdict Summary Header Card */}
          <div className="p-4 sm:p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-4">
            {/* AI / Engine Telemetry Banner */}
            <div className={`flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-2xl border text-xs font-mono ${
              report.engine_mode === 'ai-gemini'
                ? 'border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-300'
                : 'border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] text-neutral-700 dark:text-neutral-300'
            }`}>
              <div className="flex items-center gap-2">
                {report.engine_mode === 'ai-gemini' ? (
                  <>
                    <Sparkles className="w-4 h-4 text-amber-500 fill-amber-500 shrink-0" />
                    <span className="font-bold">Analyzed with Google Gemini AI ({report.model_name || '2.5 Flash'})</span>
                    {typeof report.analysis_latency_ms === 'number' && (
                      <span className="text-[11px] opacity-75">• {report.analysis_latency_ms}ms</span>
                    )}
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-neutral-500 shrink-0" />
                    <span>Analyzed with Heuristic Rules Engine (Offline)</span>
                  </>
                )}
              </div>

              {report.engine_mode !== 'ai-gemini' ? (
                <button
                  onClick={() => {
                    setEngineMode('ai');
                    handleReRunAnalysis('ai');
                  }}
                  className="px-3 py-1 rounded-xl bg-neutral-950 text-white dark:bg-white dark:text-black font-semibold text-[11px] hover:opacity-90 flex items-center gap-1.5 cursor-pointer shadow-xs transition-opacity"
                >
                  <Sparkles className="w-3 h-3 text-amber-500" />
                  <span>Run Gemini AI Analysis</span>
                </button>
              ) : (
                <span className="text-[10px] font-mono text-neutral-500 dark:text-neutral-400">
                  Model: {report.model_name || 'Gemini 2.5 Flash'}
                </span>
              )}
            </div>

            {/* Error Notification if AI Fallback Occurred */}
            {analysisError && (
              <div className="p-3 rounded-2xl border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-400 text-xs font-mono flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold">AI Engine Notice:</div>
                  <div className="text-[11px]">{analysisError} (Fell back to deterministic heuristic inspection)</div>
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-neutral-200 dark:border-black">
              <div>
                <div className="text-[10px] font-mono uppercase text-neutral-600 dark:text-neutral-400 font-semibold">Forensic Incident ID</div>
                <div className="text-sm sm:text-base font-bold font-mono text-neutral-900 dark:text-white">{report.incident_id}</div>
              </div>

              <div className="flex items-center gap-3">
                {/* Classification badge */}
                <div className="flex flex-col items-end">
                  <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Threat Verdict</span>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${
                      report.threat_classification === 'BEC' || report.threat_classification === 'Phishing'
                        ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
                        : report.threat_classification === 'Suspicious' || report.threat_classification === 'Impersonation'
                        ? 'bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20'
                        : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                    }`}
                  >
                    {report.threat_classification}
                  </span>
                </div>

                {/* Fraud Risk Score Meter (Lower = Safer) */}
                <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] text-center min-w-[90px]">
                  <div className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Fraud Risk</div>
                  <div
                    className={`text-lg font-mono font-extrabold ${
                      report.fraud_risk_score > 70
                        ? 'text-rose-600 dark:text-rose-500'
                        : report.fraud_risk_score > 35
                        ? 'text-amber-600 dark:text-amber-500'
                        : 'text-emerald-600 dark:text-emerald-500'
                    }`}
                  >
                    {report.fraud_risk_score}
                    <span className="text-[10px] text-neutral-500 dark:text-neutral-400">/100</span>
                  </div>
                  <span className="text-[9px] font-mono text-neutral-500 dark:text-neutral-400 block">Lower=Safer</span>
                </div>
              </div>
            </div>

            {/* Narrative synopsis */}
            <p className="text-xs text-neutral-700 dark:text-neutral-300 leading-relaxed font-sans">
              {report.attribution_confidence.forensic_narrative}
            </p>

            {/* Sub-navigation tabs (Horizontally scrollable on mobile) */}
            <div className="flex items-center gap-1.5 pt-2 border-t border-neutral-200 dark:border-black text-xs overflow-x-auto pb-1">
              {[
                { id: 'overview', label: 'Executive Summary', icon: Sparkles },
                { id: 'analysisSteps', label: 'How Analyzed (Steps)', icon: ListOrdered },
                { id: 'headerSecurity', label: 'Header Security Audit', icon: ShieldAlert },
                { id: 'headers', label: 'Headers & Auth', icon: FileCode },
                { id: 'traceability', label: 'Origin Geo', icon: MapPin },
                { id: 'nlp', label: 'NLP & Behavior', icon: Brain },
                { id: 'attribution', label: 'Attribution & IoCs', icon: Crosshair },
                { id: 'recs', label: 'SOC Playbooks', icon: ShieldCheck },
                { id: 'rawJson', label: 'JSON Export', icon: Code },
                { id: 'markdown', label: 'Markdown Report', icon: FileText }
              ].map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full font-medium transition-all cursor-pointer text-[11px] border shrink-0 ${
                      isActive
                        ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-black dark:border-black font-semibold shadow-xs'
                        : 'bg-neutral-100 dark:bg-[#222222] border-neutral-300 dark:border-black text-neutral-700 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-[#2c2c2c]'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Tab Contents */}
          <div className="p-4 sm:p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl">
            {/* TAB 1: OVERVIEW */}
            {activeTab === 'overview' && (
              <div className="space-y-6 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1">
                    <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Account State</span>
                    <div className="font-semibold text-neutral-900 dark:text-white">
                      {report.attribution_confidence.account_state}
                    </div>
                  </div>

                  <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1">
                    <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Attribution Confidence</span>
                    <div className="font-semibold text-neutral-900 dark:text-white font-mono">
                      {report.attribution_confidence.confidence_level} ({report.attribution_confidence.confidence_score}%)
                    </div>
                  </div>

                  <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1">
                    <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Urgency Score</span>
                    <div className="font-semibold text-rose-600 dark:text-rose-500 font-mono">
                      {report.nlp_analysis.urgency_score} / 100
                    </div>
                  </div>
                </div>

                {/* Origin node highlight */}
                <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="font-bold text-neutral-800 dark:text-neutral-200 flex items-center gap-2">
                      <MapPin className="w-4 h-4 text-neutral-500 dark:text-neutral-400" />
                      Earliest Reliable Origin Node
                    </div>
                    <span className="font-mono text-[11px] bg-neutral-100 dark:bg-[#282828] text-neutral-800 dark:text-neutral-300 px-2 py-0.5 rounded border border-neutral-300 dark:border-black">
                      {report.traceability_map.infrastructure_type}
                    </span>
                  </div>
                  <div className="font-mono text-xs text-neutral-900 dark:text-neutral-200">
                    IP: {report.traceability_map.earliest_reliable_ip} ({report.traceability_map.geolocation_estimate.city}, {report.traceability_map.geolocation_estimate.country})
                  </div>
                  <div className="text-[11px] text-neutral-600 dark:text-neutral-400">
                    ISP: {report.traceability_map.geolocation_estimate.isp} • ASN: {report.traceability_map.geolocation_estimate.asn}
                  </div>
                </div>

                {/* Threat Flags */}
                <div className="space-y-2">
                  <div className="font-bold text-neutral-900 dark:text-white">Detected Threat Vectors:</div>
                  <div className="flex flex-wrap gap-2">
                    {report.header_forensics.spoofing_vectors.map((vec, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded-lg bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20 text-[11px] font-medium">
                        {vec}
                      </span>
                    ))}
                    {report.traceability_map.infrastructure_flags.map((flag, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20 text-[11px] font-mono">
                        {flag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: HOW THIS EMAIL WAS ANALYZED (STEP-BY-STEP) */}
            {activeTab === 'analysisSteps' && (
              <div className="space-y-4 text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-black">
                  <div>
                    <h3 className="text-sm font-bold text-neutral-900 dark:text-white">Forensic Ingestion & Analysis Execution Trace</h3>
                    <p className="text-neutral-600 dark:text-neutral-400 text-[11px]">How the ChainMail engine parsed, evaluated, and classified this message step-by-step</p>
                  </div>
                </div>

                <div className="space-y-3">
                  {report.analysis_steps.map((step) => (
                    <div
                      key={step.step_number}
                      className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-neutral-900 dark:text-white flex items-center gap-2">
                          <span className="w-5 h-5 rounded-full bg-neutral-200 dark:bg-[#282828] border border-neutral-300 dark:border-black text-neutral-800 dark:text-neutral-300 flex items-center justify-center font-mono text-[11px]">
                            {step.step_number}
                          </span>
                          {step.name}
                        </span>

                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                            step.status === 'Passed'
                              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                              : step.status === 'Flagged'
                              ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
                              : 'bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20'
                          }`}
                        >
                          {step.status}
                        </span>
                      </div>

                      <p className="text-neutral-600 dark:text-neutral-400 text-xs font-sans pl-7 leading-relaxed">
                        {step.details}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 3: HEADER SECURITY AUDIT */}
            {activeTab === 'headerSecurity' && (
              <div className="space-y-4 text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-black">
                  <div>
                    <h3 className="text-sm font-bold text-neutral-900 dark:text-white">RFC 5322 Header Security Audit</h3>
                    <p className="text-neutral-600 dark:text-neutral-400 text-[11px]">Individual security evaluation for every extracted header</p>
                  </div>
                </div>

                <div className="space-y-3">
                  {report.header_security_checks.map((hCheck, idx) => (
                    <div
                      key={idx}
                      className={`p-4 rounded-2xl border ${
                        hCheck.security_status === 'Critical Failure'
                          ? 'border-rose-500/30 bg-rose-500/5'
                          : hCheck.security_status === 'Warning'
                          ? 'border-amber-500/30 bg-amber-500/5'
                          : 'border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]'
                      } space-y-2`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <div className="font-mono font-bold text-xs text-neutral-900 dark:text-white">
                          Header: {hCheck.header_name}
                        </div>
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold self-start sm:self-auto ${
                            hCheck.security_status === 'Critical Failure'
                              ? 'bg-rose-500 text-white'
                              : hCheck.security_status === 'Warning'
                              ? 'bg-amber-500 text-white'
                              : 'bg-emerald-500 text-white'
                          }`}
                        >
                          {hCheck.security_status}
                        </span>
                      </div>

                      <div className="p-2 rounded-xl bg-neutral-900 dark:bg-[#121212] font-mono text-[11px] text-neutral-200 dark:text-neutral-300 border border-neutral-800 dark:border-black break-all">
                        {hCheck.value}
                      </div>

                      <p className="text-[11px] text-neutral-600 dark:text-neutral-400 font-sans leading-relaxed">
                        {hCheck.explanation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 4: HEADERS & AUTH */}
            {activeTab === 'headers' && (
              <div className="space-y-6 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-neutral-800 dark:text-neutral-200">SPF Validation</span>
                      <span className={`font-mono text-xs font-bold ${report.header_forensics.spf.status === 'PASS' ? 'text-emerald-600 dark:text-emerald-500' : 'text-rose-600 dark:text-rose-500'}`}>
                        {report.header_forensics.spf.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-neutral-600 dark:text-neutral-400">
                      {report.header_forensics.spf.details}
                    </p>
                  </div>

                  <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-neutral-800 dark:text-neutral-200">DKIM Signature</span>
                      <span className={`font-mono text-xs font-bold ${report.header_forensics.dkim.status === 'PASS' ? 'text-emerald-600 dark:text-emerald-500' : 'text-rose-600 dark:text-rose-500'}`}>
                        {report.header_forensics.dkim.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-neutral-600 dark:text-neutral-400">
                      {report.header_forensics.dkim.details}
                    </p>
                  </div>

                  <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-neutral-800 dark:text-neutral-200">DMARC Policy</span>
                      <span className={`font-mono text-xs font-bold ${report.header_forensics.dmarc.status === 'PASS' ? 'text-emerald-600 dark:text-emerald-500' : 'text-rose-600 dark:text-rose-500'}`}>
                        {report.header_forensics.dmarc.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-neutral-600 dark:text-neutral-400">
                      {report.header_forensics.dmarc.details}
                    </p>
                  </div>
                </div>

                <div className="space-y-2 font-mono">
                  {report.header_forensics.hops.map((hop) => (
                    <div
                      key={hop.hop_number}
                      className={`p-3 rounded-xl border ${
                        hop.is_anomalous
                          ? 'border-rose-500/30 bg-rose-500/5'
                          : 'border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]'
                      } flex flex-col sm:flex-row sm:items-center justify-between gap-2`}
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 rounded-full bg-neutral-200 dark:bg-[#282828] text-neutral-800 dark:text-neutral-300 border border-neutral-300 dark:border-black flex items-center justify-center font-bold text-xs">
                          {hop.hop_number}
                        </span>
                        <div>
                          <div className="font-semibold text-neutral-900 dark:text-white">
                            {hop.from_ip || 'IP Unresolved'}
                          </div>
                          <div className="text-[10px] text-neutral-500 dark:text-neutral-400 font-sans">
                            From: {hop.from_host} &rarr; By: {hop.by_host}
                          </div>
                        </div>
                      </div>
                      <div className="text-right text-[11px] font-sans">
                        {hop.is_earliest_reliable && (
                          <span className="px-2 py-0.5 rounded bg-neutral-950 text-white dark:bg-white dark:text-black font-bold text-[10px] mr-2">
                            EARLIEST RELIABLE
                          </span>
                        )}
                        <span className="text-neutral-500 dark:text-neutral-400">{hop.geo?.country}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 5: TRACEABILITY */}
            {activeTab === 'traceability' && (
              <div className="space-y-6 text-xs">
                <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                    <div>
                      <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">IP ADDRESS</span>
                      <span className="font-bold text-neutral-900 dark:text-white">{report.traceability_map.earliest_reliable_ip}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">LOCATION</span>
                      <span className="font-semibold text-neutral-800 dark:text-neutral-200">
                        {report.traceability_map.geolocation_estimate.city}, {report.traceability_map.geolocation_estimate.country_code}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">INFRASTRUCTURE</span>
                      <span className="font-semibold text-rose-600 dark:text-rose-500">{report.traceability_map.infrastructure_type}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">DOMAIN AGE</span>
                      <span className="font-semibold text-neutral-800 dark:text-neutral-200">
                        {report.traceability_map.domain_intelligence.domain_age_days} Days
                      </span>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="font-bold text-neutral-900 dark:text-white">Threat Indicators & Bulletproof Hosting Flags:</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {report.traceability_map.infrastructure_flags.map((flag, idx) => (
                      <div key={idx} className="p-3 rounded-xl border border-rose-500/20 bg-rose-500/5 font-mono text-[11px] text-rose-600 dark:text-rose-500 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <span>{flag}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 6: NLP & BEHAVIOR */}
            {activeTab === 'nlp' && (
              <div className="space-y-6 text-xs">
                <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-3">
                  <div className="font-bold text-neutral-900 dark:text-white">Psychological & Social Engineering Tactics</div>
                  <ul className="space-y-2">
                    {report.nlp_analysis.social_engineering_tactics.map((tac, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-neutral-700 dark:text-neutral-300">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-500 shrink-0 mt-0.5" />
                        <span>{tac}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-3">
                  <div className="font-bold text-neutral-900 dark:text-white">Financial Fraud & Payment Diversion Vectors</div>
                  <ul className="space-y-2">
                    {report.nlp_analysis.financial_fraud_patterns.map((pat, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-rose-600 dark:text-rose-500 font-medium">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-500 shrink-0 mt-0.5" />
                        <span>{pat}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* TAB 7: ATTRIBUTION & IOCS */}
            {activeTab === 'attribution' && (
              <div className="space-y-6 text-xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-[11px]">
                    <thead className="border-b border-neutral-200 dark:border-black text-neutral-600 dark:text-neutral-400">
                      <tr>
                        <th className="py-2 px-3">Type</th>
                        <th className="py-2 px-3">Value</th>
                        <th className="py-2 px-3">Description</th>
                        <th className="py-2 px-3">Verdict</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-neutral-200 dark:divide-neutral-900">
                      {report.attribution_confidence.indicators_of_compromise.map((ioc, idx) => (
                        <tr key={idx} className="hover:bg-neutral-50 dark:hover:bg-[#202020]">
                          <td className="py-2.5 px-3 text-neutral-900 dark:text-white font-bold">{ioc.type}</td>
                          <td className="py-2.5 px-3 font-semibold text-neutral-900 dark:text-white max-w-xs truncate">{ioc.value}</td>
                          <td className="py-2.5 px-3 text-neutral-600 dark:text-neutral-400 font-sans">{ioc.description}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              ioc.verdict === 'Malicious' ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500'
                            }`}>
                              {ioc.verdict}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB 8: SOC PLAYBOOKS */}
            {activeTab === 'recs' && (
              <div className="space-y-4 text-xs">
                {report.actionable_recommendations.map((rec, idx) => (
                  <div key={idx} className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-neutral-900 dark:text-white flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          rec.priority === 'Immediate' ? 'bg-rose-500/20 text-rose-600 dark:text-rose-500' : 'bg-amber-500/20 text-amber-600 dark:text-amber-500'
                        }`}>
                          {rec.priority}
                        </span>
                        {rec.action}
                      </span>
                      <span className="text-neutral-600 dark:text-neutral-400 text-[11px]">{rec.category}</span>
                    </div>
                    <p className="text-neutral-600 dark:text-neutral-400 text-[11px] leading-relaxed">
                      {rec.rationale}
                    </p>
                    {rec.technical_command && (
                      <div className="p-2.5 rounded-xl bg-neutral-900 dark:bg-[#121212] font-mono text-[11px] text-neutral-200 dark:text-neutral-300 flex items-center justify-between gap-2 overflow-x-auto border border-neutral-800 dark:border-black">
                        <code>{rec.technical_command}</code>
                        <button
                          onClick={() => handleCopy(rec.technical_command || '', `cmd-${idx}`)}
                          className="text-neutral-400 hover:text-white cursor-pointer shrink-0"
                        >
                          {copiedSection === `cmd-${idx}` ? 'Copied' : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* TAB 9: JSON EXPORT */}
            {activeTab === 'rawJson' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-neutral-600 dark:text-neutral-400 font-semibold">Structured JSON Engine Output</span>
                  <button
                    onClick={() => handleCopy(JSON.stringify(report, null, 2), 'json')}
                    className="px-3 py-1 rounded-full border border-neutral-300 dark:border-black bg-white dark:bg-transparent text-neutral-800 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-white dark:hover:text-black transition-colors cursor-pointer flex items-center gap-1 shadow-xs"
                  >
                    <Copy className="w-3 h-3" />
                    {copiedSection === 'json' ? 'Copied to Clipboard!' : 'Copy Full JSON'}
                  </button>
                </div>
                <pre className="p-4 rounded-2xl bg-neutral-900 dark:bg-[#121212] text-neutral-200 dark:text-neutral-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-96 border border-neutral-800 dark:border-black">
                  <code>{JSON.stringify(report, null, 2)}</code>
                </pre>
              </div>
            )}

            {/* TAB 10: MARKDOWN REPORT */}
            {activeTab === 'markdown' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-neutral-600 dark:text-neutral-400 font-semibold">RFC 5322 Incident Markdown Format</span>
                  <button
                    onClick={() => handleCopy(generateMarkdownReport(report), 'md')}
                    className="px-3 py-1 rounded-full border border-neutral-300 dark:border-black bg-white dark:bg-transparent text-neutral-800 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-white dark:hover:text-black transition-colors cursor-pointer flex items-center gap-1 shadow-xs"
                  >
                    <Copy className="w-3 h-3" />
                    {copiedSection === 'md' ? 'Copied Markdown!' : 'Copy Report'}
                  </button>
                </div>
                <pre className="p-4 rounded-2xl bg-neutral-900 dark:bg-[#121212] text-neutral-200 dark:text-neutral-300 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-96 whitespace-pre-wrap border border-neutral-800 dark:border-black">
                  <code>{generateMarkdownReport(report)}</code>
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AnalyzerPage() {
  return (
    <Suspense fallback={
      <div className="max-w-7xl mx-auto px-4 py-12 text-center text-neutral-400 font-mono text-xs">
        Loading Ingestion Workbench...
      </div>
    }>
      <AnalyzerContent />
    </Suspense>
  );
}
