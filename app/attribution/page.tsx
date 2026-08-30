'use client';

import React, { useState } from 'react';
import {
  Target,
  Copy
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';
import { analyzeEmailThreat } from '@/lib/forensic-engine';

export default function AttributionPage() {
  const [selectedPresetId, setSelectedPresetId] = useState('bec-wire-transfer');
  const [copiedIoC, setCopiedIoC] = useState<string | null>(null);

  const scenario = PRESET_SCENARIOS.find(p => p.id === selectedPresetId) || PRESET_SCENARIOS[0];
  const report = analyzeEmailThreat(scenario.input);
  const { attribution_confidence } = report;

  const handleCopyIoCs = () => {
    const stixData = {
      type: 'bundle',
      id: `bundle--${report.incident_id}`,
      spec_version: '2.1',
      objects: attribution_confidence.indicators_of_compromise.map((ioc, idx) => ({
        type: 'indicator',
        id: `indicator--${idx + 1}`,
        pattern: `[${ioc.type.toLowerCase()}:value = '${ioc.value}']`,
        description: ioc.description,
        name: `${ioc.type} IoC - ${attribution_confidence.associated_campaign || 'Threat'}`,
        confidence: attribution_confidence.confidence_score
      }))
    };

    navigator.clipboard.writeText(JSON.stringify(stixData, null, 2));
    setCopiedIoC('stix');
    setTimeout(() => setCopiedIoC(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              CAMPAIGN CORRELATION & ADVERSARY ATTRIBUTION
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            Threat Actor Attribution & IoC Intelligence
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Assessing mailbox state compromise vs direct adversary infrastructure, correlating campaign signatures, and exporting STIX 2.1 IoCs.
          </p>
        </div>

        {/* Case Switcher */}
        <div className="flex flex-wrap items-center gap-1.5">
          {PRESET_SCENARIOS.map((p) => (
            <button
              key={p.id}
              onClick={() => setSelectedPresetId(p.id)}
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

      {/* Account State & Confidence Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Account State */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-3">
          <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Assessed Account State</span>
          <div className="text-lg font-bold text-neutral-900 dark:text-white">
            {attribution_confidence.account_state}
          </div>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            {attribution_confidence.account_state === 'Compromised Legitimate Account'
              ? 'Cryptographic signatures match authentic vendor identity, but originating IP indicates credential hijacking / residential SOCKS proxy.'
              : attribution_confidence.account_state === 'Purely Spoofed Domain'
              ? 'Adversary spoofed envelope and display name from disposable lookalike infrastructure.'
              : attribution_confidence.account_state === 'Direct Malicious Infrastructure'
              ? 'Originates directly from attacker bulletproof VPS or reverse proxy node.'
              : 'Verified authentic communication from legitimate enterprise gateway.'}
          </p>
        </div>

        {/* Attribution Confidence Level */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-3">
          <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Attribution Confidence</span>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-extrabold font-mono text-neutral-900 dark:text-white">
              {attribution_confidence.confidence_level}
            </span>
            <span className="text-xs font-mono text-neutral-600 dark:text-neutral-400">
              ({attribution_confidence.confidence_score}% Heuristic Match)
            </span>
          </div>
          <div className="w-full bg-neutral-200 dark:bg-[#282828] h-2 rounded-full overflow-hidden border border-neutral-300 dark:border-black">
            <div
              className="h-full bg-neutral-900 dark:bg-white rounded-full"
              style={{ width: `${attribution_confidence.confidence_score}%` }}
            ></div>
          </div>
        </div>

        {/* Associated Campaign */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-3">
          <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">Associated Threat Campaign</span>
          <div className="text-lg font-bold text-rose-600 dark:text-rose-500 font-mono">
            {attribution_confidence.associated_campaign || 'None (Benign Activity)'}
          </div>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Fingerprinted against global cyber threat intelligence threat matrices and active telemetry pulses.
          </p>
        </div>
      </div>

      {/* Threat Actor Profiler */}
      {attribution_confidence.threat_actor && (
        <div className="p-6 sm:p-8 rounded-3xl border border-neutral-200 dark:border-black bg-neutral-900 dark:bg-[#161616] text-white shadow-2xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-800 dark:border-black">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono bg-rose-500/20 text-rose-400 border border-rose-500/30">
                <Target className="w-3.5 h-3.5" />
                CORRELATED ADVERSARY PROFILE
              </div>
              <h2 className="text-2xl font-extrabold text-white">
                {attribution_confidence.threat_actor.name}
              </h2>
            </div>
            <div className="flex flex-wrap gap-2 text-xs font-mono">
              {attribution_confidence.threat_actor.aliases.map((alias, idx) => (
                <span key={idx} className="px-2.5 py-1 rounded-lg bg-[#222222] text-neutral-300 border border-neutral-800 dark:border-black">
                  {alias}
                </span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
            <div className="space-y-1">
              <span className="text-neutral-400 font-mono text-[10px] block">CATEGORY & MOTIVATION</span>
              <div className="font-semibold text-neutral-200">{attribution_confidence.threat_actor.category}</div>
              <p className="text-neutral-400 text-[11px]">{attribution_confidence.threat_actor.motivation}</p>
            </div>

            <div className="space-y-1">
              <span className="text-neutral-400 font-mono text-[10px] block">COMMON TTPs & TECHNIQUES</span>
              <ul className="space-y-1 text-neutral-300">
                {attribution_confidence.threat_actor.common_techniques.map((tech, idx) => (
                  <li key={idx} className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-white"></span>
                    <span>{tech}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="space-y-1">
              <span className="text-neutral-400 font-mono text-[10px] block">FREQUENT TARGET SECTORS</span>
              <ul className="space-y-1 text-neutral-300">
                {attribution_confidence.threat_actor.target_sectors.map((sec, idx) => (
                  <li key={idx} className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
                    <span>{sec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Extracted Indicators of Compromise (IoCs) */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-neutral-200 dark:border-black">
          <div>
            <h2 className="text-lg font-bold text-neutral-900 dark:text-white">
              Correlated Indicators of Compromise (IoCs)
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">Exportable forensic artifacts for SIEM ingestion and edge blocking</p>
          </div>

          <button
            onClick={handleCopyIoCs}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-semibold font-mono text-white bg-neutral-950 hover:bg-neutral-800 dark:text-black dark:bg-white dark:hover:bg-neutral-200 border border-neutral-950 dark:border-black transition-colors cursor-pointer shadow-xs"
          >
            <Copy className="w-3.5 h-3.5" />
            {copiedIoC === 'stix' ? 'STIX 2.1 Copied!' : 'Export STIX 2.1 Bundle'}
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-neutral-200 dark:border-black text-neutral-600 dark:text-neutral-400 uppercase bg-neutral-50 dark:bg-[#141414]">
              <tr>
                <th className="py-3 px-4">Observable Type</th>
                <th className="py-3 px-4">Indicator Value</th>
                <th className="py-3 px-4">Forensic Description</th>
                <th className="py-3 px-4">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-900">
              {attribution_confidence.indicators_of_compromise.map((ioc, idx) => (
                <tr key={idx} className="hover:bg-neutral-50 dark:hover:bg-[#202020] transition-colors">
                  <td className="py-3 px-4 font-bold text-neutral-900 dark:text-white">{ioc.type}</td>
                  <td className="py-3 px-4 font-semibold text-neutral-900 dark:text-white max-w-sm break-all">{ioc.value}</td>
                  <td className="py-3 px-4 text-neutral-600 dark:text-neutral-400 font-sans">{ioc.description}</td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                        ioc.verdict === 'Malicious'
                          ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
                          : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                      }`}
                    >
                      {ioc.verdict}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
