'use client';

import React, { useState } from 'react';
import {
  Brain,
  Zap,
  AlertTriangle,
  Link as LinkIcon,
  FileWarning,
  CheckCircle2,
  DollarSign,
  Flame
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { useForensicSession } from '@/components/forensic-context';
import { ActiveTargetBanner } from '@/components/active-target-banner';

export default function NLPThreatsPage() {
  const { activeReport, activeMeta, isUploaded, resetToPreset } = useForensicSession();
  const [selectedPresetId, setSelectedPresetId] = useState<string | 'ACTIVE_EML'>('ACTIVE_EML');

  const scenario = selectedPresetId === 'ACTIVE_EML'
    ? null
    : PRESET_SCENARIOS.find(p => p.id === selectedPresetId);

  const report = scenario ? analyzeEmailThreat(scenario.input) : activeReport;
  const { nlp_analysis } = report;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Active Target Banner */}
      <ActiveTargetBanner />

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              NATURAL LANGUAGE & BEHAVIORAL HEURISTICS
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            NLP & Social Engineering Threat Analyzer
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Detecting psychological coercion, executive authority manipulation, wire fraud diversion patterns, and credential lures.
          </p>
        </div>

        {/* Case Switcher */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setSelectedPresetId('ACTIVE_EML')}
            className={`px-3 py-1.5 rounded-full text-xs font-mono transition-all cursor-pointer border flex items-center gap-1.5 ${
              selectedPresetId === 'ACTIVE_EML'
                ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-black dark:border-black font-semibold shadow-xs'
                : 'bg-neutral-100 dark:bg-[#222222] border-neutral-300 dark:border-black text-neutral-700 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-[#2a2a2a]'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${isUploaded ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
            <span>{isUploaded ? 'Active Ingested .EML' : 'Active Target'}</span>
          </button>

          {PRESET_SCENARIOS.map((p) => (
            <button
              key={p.id}
              onClick={() => {
                setSelectedPresetId(p.id);
                resetToPreset(p.id);
              }}
              className={`px-3 py-1.5 rounded-full text-xs font-mono transition-all cursor-pointer border ${
                selectedPresetId === p.id
                  ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-black dark:border-black font-semibold shadow-xs'
                  : 'bg-neutral-100 dark:bg-[#222222] border-neutral-300 dark:border-black text-neutral-700 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-[#2a2a2a]'
              }`}
            >
              {p.category}
            </button>
          ))}
        </div>
      </div>

      {/* Top Section: Urgency Meter & Intent Classification */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Intent Badge Card */}
        <div className="md:col-span-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <span className="text-[10px] font-mono uppercase text-neutral-600 dark:text-neutral-400 font-semibold">Classified Email Intent</span>
            <div
              className={`text-2xl font-extrabold font-mono ${
                nlp_analysis.intent === 'BEC' || nlp_analysis.intent === 'Phishing'
                  ? 'text-rose-600 dark:text-rose-500'
                  : nlp_analysis.intent === 'Legitimate'
                  ? 'text-emerald-600 dark:text-emerald-500'
                  : 'text-amber-600 dark:text-amber-500'
              }`}
            >
              {nlp_analysis.intent}
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              {nlp_analysis.summary}
            </p>
          </div>

          {nlp_analysis.impersonation_target && (
            <div className="p-3 rounded-2xl border border-rose-500/20 bg-rose-500/5 text-xs font-mono text-rose-600 dark:text-rose-500 font-medium">
              Target Impersonated: {nlp_analysis.impersonation_target}
            </div>
          )}
        </div>

        {/* Urgency Gauge Card */}
        <div className="md:col-span-8 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-bold text-neutral-900 dark:text-white">
              <Zap className="w-5 h-5 text-amber-500" />
              <span>Urgency & Psychological Coercion Meter</span>
            </div>
            <span
              className={`text-xl font-mono font-extrabold ${
                nlp_analysis.urgency_score > 75
                  ? 'text-rose-600 dark:text-rose-500'
                  : nlp_analysis.urgency_score > 40
                  ? 'text-amber-600 dark:text-amber-500'
                  : 'text-emerald-600 dark:text-emerald-500'
              }`}
            >
              {nlp_analysis.urgency_score} / 100
            </span>
          </div>

          {/* Meter progress bar */}
          <div className="w-full bg-neutral-100 dark:bg-[#282828] h-3 rounded-full overflow-hidden border border-neutral-300 dark:border-black">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                nlp_analysis.urgency_score > 75
                  ? 'bg-rose-500'
                  : nlp_analysis.urgency_score > 40
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${nlp_analysis.urgency_score}%` }}
            ></div>
          </div>

          {/* Urgency Cues list */}
          <div className="space-y-2 pt-2">
            <span className="text-xs font-bold text-neutral-800 dark:text-neutral-300">Identified Psychological Triggers:</span>
            <div className="space-y-1.5">
              {nlp_analysis.urgency_cues.map((cue, idx) => (
                <div key={idx} className="flex items-start gap-2 text-xs text-rose-600 dark:text-rose-500 font-medium">
                  <Flame className="w-3.5 h-3.5 text-rose-600 dark:text-rose-500 shrink-0 mt-0.5" />
                  <span>{cue}</span>
                </div>
              ))}
              {nlp_analysis.urgency_cues.length === 0 && (
                <span className="text-xs text-neutral-500 dark:text-neutral-400">No coercive or artificial urgency triggers detected.</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Social Engineering Tactics & Financial Fraud Vectors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Social Engineering Tactics */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center gap-2 text-neutral-900 dark:text-white font-bold text-base">
            <Brain className="w-5 h-5" />
            <h3>Social Engineering Vectors</h3>
          </div>

          <div className="space-y-2.5">
            {nlp_analysis.social_engineering_tactics.map((tactic, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] text-xs text-neutral-800 dark:text-neutral-200 flex items-start gap-2.5"
              >
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-500 shrink-0 mt-0.5" />
                <span>{tactic}</span>
              </div>
            ))}
            {nlp_analysis.social_engineering_tactics.length === 0 && (
              <div className="p-4 text-xs text-neutral-500 dark:text-neutral-400">No deceptive social engineering lures detected.</div>
            )}
          </div>
        </div>

        {/* Financial Fraud Patterns */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center gap-2 text-rose-600 dark:text-rose-500 font-bold text-base">
            <DollarSign className="w-5 h-5" />
            <h3>Financial Fraud & Wire Diversion Patterns</h3>
          </div>

          <div className="space-y-2.5">
            {nlp_analysis.financial_fraud_patterns.map((pattern, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-2xl border border-rose-500/20 bg-rose-500/5 text-xs text-rose-600 dark:text-rose-500 font-medium flex items-start gap-2.5"
              >
                <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-500 shrink-0 mt-0.5" />
                <span>{pattern}</span>
              </div>
            ))}
            {nlp_analysis.financial_fraud_patterns.length === 0 && (
              <div className="p-4 text-xs text-neutral-500 dark:text-neutral-400">No unauthorized wire transfers or invoice tampering cues found.</div>
            )}
          </div>
        </div>
      </div>

      {/* Extracted Links & Malicious Attachments */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Links Scanner */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-neutral-900 dark:text-white font-bold text-base">
              <LinkIcon className="w-5 h-5" />
              <h3>Extracted URLs & Obfuscation Scanner</h3>
            </div>
            <span className="text-xs font-mono text-neutral-600 dark:text-neutral-400">{nlp_analysis.detected_links.length} Links</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {nlp_analysis.detected_links.map((link, idx) => (
              <div
                key={idx}
                className={`p-3.5 rounded-2xl border ${
                  link.risk_level === 'Critical'
                    ? 'border-rose-500/30 bg-rose-500/5'
                    : 'border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]'
                } space-y-2`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-neutral-600 dark:text-neutral-400 font-semibold">TARGET URL</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    link.risk_level === 'Critical' ? 'bg-rose-500 text-white' : 'bg-emerald-500 text-white'
                  }`}>
                    {link.risk_level} Risk
                  </span>
                </div>
                <div className="text-neutral-900 dark:text-white break-all">{link.url}</div>
                {link.flags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {link.flags.map((flag, fIdx) => (
                      <span key={fIdx} className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-600 dark:text-rose-400 font-mono">
                        {flag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {nlp_analysis.detected_links.length === 0 && (
              <div className="p-4 text-xs text-neutral-500 dark:text-neutral-400 font-sans">No embedded hyperlinks found in the message body.</div>
            )}
          </div>
        </div>

        {/* Attachments Scanner */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-amber-600 dark:text-amber-500 font-bold text-base">
              <FileWarning className="w-5 h-5" />
              <h3>Attachment & Payload Indicators</h3>
            </div>
            <span className="text-xs font-mono text-neutral-600 dark:text-neutral-400">{nlp_analysis.attachment_indicators.length} Attachments</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {nlp_analysis.attachment_indicators.map((att, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-2xl border border-rose-500/30 bg-rose-500/5 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-neutral-600 dark:text-neutral-400 font-semibold">DISGUISED CONTAINER</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500 text-white">
                    {att.risk_level}
                  </span>
                </div>
                <div className="font-bold text-rose-600 dark:text-rose-500">{att.filename}</div>
                <div className="flex flex-wrap gap-1 pt-1">
                  {att.flags.map((flag, fIdx) => (
                    <span key={fIdx} className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-600 dark:text-rose-400 font-mono">
                      {flag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {nlp_analysis.attachment_indicators.length === 0 && (
              <div className="p-4 text-xs text-neutral-500 dark:text-neutral-400 font-sans">No executable containers (.iso, .exe, .lnk) or suspicious archives referenced.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
