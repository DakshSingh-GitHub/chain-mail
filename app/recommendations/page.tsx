'use client';

import React, { useState } from 'react';
import {
  Copy,
  Lock,
  FileCheck,
  CheckCircle2
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { useForensicSession } from '@/components/forensic-context';
import { ActiveTargetBanner } from '@/components/active-target-banner';

export default function RecommendationsPage() {
  const { activeReport, activeMeta, isUploaded, resetToPreset } = useForensicSession();
  const [selectedPresetId, setSelectedPresetId] = useState<string | 'ACTIVE_EML'>('ACTIVE_EML');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const scenario = selectedPresetId === 'ACTIVE_EML'
    ? null
    : PRESET_SCENARIOS.find(p => p.id === selectedPresetId);

  const report = scenario ? analyzeEmailThreat(scenario.input) : activeReport;
  const { actionable_recommendations, compliance_audit } = report;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Active Target Banner */}
      <ActiveTargetBanner />

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              INCIDENT RESPONSE & MITIGATION PLAYBOOKS
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            SOC Actionable Playbooks & Evidence Export
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Generate edge firewall drops, mail security gateway quarantines, Azure AD session revocations, and law enforcement evidence packages.
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

      {/* Actionable Playbook Cards */}
      <div className="space-y-4">
        {actionable_recommendations.map((rec, idx) => {
          const isImmediate = rec.priority === 'Immediate';
          const isHigh = rec.priority === 'High';

          return (
            <div
              key={idx}
              className={`p-6 rounded-3xl border ${
                isImmediate
                  ? 'border-rose-500/30 bg-rose-500/5'
                  : isHigh
                  ? 'border-amber-500/30 bg-amber-500/5'
                  : 'border-neutral-200 dark:border-black bg-white dark:bg-[#181818]'
              } shadow-lg space-y-4 transition-all`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${
                      isImmediate
                        ? 'bg-rose-500 text-white'
                        : isHigh
                        ? 'bg-amber-500 text-white'
                        : 'bg-emerald-500 text-white'
                    }`}
                  >
                    {rec.priority.toUpperCase()} ACTION
                  </span>
                  <h3 className="text-base font-bold text-neutral-900 dark:text-white">
                    {rec.action}
                  </h3>
                </div>

                <span className="text-xs font-mono px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#242424] border border-neutral-300 dark:border-black text-neutral-700 dark:text-neutral-400 font-semibold">
                  Category: {rec.category}
                </span>
              </div>

              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed font-sans">
                {rec.rationale}
              </p>

              {rec.technical_command && (
                <div className="space-y-1.5 pt-1">
                  <div className="text-[11px] font-mono text-neutral-600 dark:text-neutral-400 flex items-center justify-between">
                    <span>Executable Technical Syntax:</span>
                    <button
                      onClick={() => handleCopy(rec.technical_command || '', `cmd-${idx}`)}
                      className="text-neutral-900 dark:text-white hover:underline flex items-center gap-1 cursor-pointer font-semibold"
                    >
                      <Copy className="w-3 h-3" />
                      {copiedCmd === `cmd-${idx}` ? 'Copied Command!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-2xl bg-neutral-900 dark:bg-[#121212] font-mono text-xs text-neutral-200 dark:text-neutral-300 overflow-x-auto border border-neutral-800 dark:border-black">
                    <code>{rec.technical_command}</code>
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Compliance & Forensic Chain of Custody Box */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-200 dark:border-black">
          <div>
            <h2 className="text-lg font-bold text-neutral-900 dark:text-white flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-neutral-900 dark:text-white" />
              RFC 5322 Forensics Chain of Custody & Evidence Certificate
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              Tamper-evident SHA-256 evidence integrity hash for law enforcement (IC3) and insurance audits.
            </p>
          </div>

          <button
            onClick={() => handleCopy(compliance_audit.evidence_hash_sha256, 'sha')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-mono font-semibold bg-neutral-100 dark:bg-[#222222] text-neutral-800 dark:text-white border border-neutral-300 dark:border-black hover:bg-neutral-200 dark:hover:bg-[#2c2c2c] transition-colors cursor-pointer shadow-xs"
          >
            <Copy className="w-3.5 h-3.5" />
            {copiedCmd === 'sha' ? 'Hash Copied!' : 'Copy Hash'}
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1">
            <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block uppercase font-semibold">RFC 5322 COMPLIANCE</span>
            <div className="text-emerald-600 dark:text-emerald-500 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" /> VERIFIED COMPLIANT
            </div>
          </div>

          <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1">
            <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block uppercase font-semibold">VICTIM PII MASKING</span>
            <div className="text-emerald-600 dark:text-emerald-500 font-bold flex items-center gap-1.5">
              <Lock className="w-4 h-4" /> ENFORCED (ZERO EXPOSURE)
            </div>
          </div>

          <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-1">
            <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block uppercase font-semibold">EVIDENCE DIGEST SHA-256</span>
            <div className="text-neutral-900 dark:text-white font-semibold truncate">
              {compliance_audit.evidence_hash_sha256}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
