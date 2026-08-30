'use client';

import React, { useState } from 'react';
import {
  AlertTriangle,
  FileText
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { useForensicSession } from '@/components/forensic-context';
import { ActiveTargetBanner } from '@/components/active-target-banner';

export default function HeaderForensicsPage() {
  const { activeReport, activeMeta, isUploaded, resetToPreset } = useForensicSession();
  const [selectedPresetId, setSelectedPresetId] = useState<string | 'ACTIVE_EML'>('ACTIVE_EML');

  const scenario = selectedPresetId === 'ACTIVE_EML'
    ? null
    : PRESET_SCENARIOS.find(p => p.id === selectedPresetId);

  const report = scenario ? analyzeEmailThreat(scenario.input) : activeReport;
  const { header_forensics } = report;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Active Target Banner */}
      <ActiveTargetBanner />

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              RFC 5322 & CRYPTOGRAPHIC FORENSICS
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            Header & Protocol Forensics Inspector
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Hop-by-hop relay latency inspection, cryptographic authentication alignment, and spoofed envelope divergence scanner.
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

      {/* Authentication Protocols Alignment Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* SPF */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-neutral-100 dark:bg-[#242424] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white flex items-center justify-center font-bold font-mono text-xs">
                SPF
              </div>
              <div>
                <h3 className="font-bold text-sm text-neutral-900 dark:text-white">Sender Policy Framework</h3>
                <span className="text-[10px] text-neutral-500 dark:text-neutral-400 font-mono">RFC 7208</span>
              </div>
            </div>
            <span
              className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold ${
                header_forensics.spf.status === 'PASS'
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                  : header_forensics.spf.status === 'SOFTFAIL'
                  ? 'bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20'
                  : 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
              }`}
            >
              {header_forensics.spf.status}
            </span>
          </div>

          <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {header_forensics.spf.details}
          </p>

          <div className="pt-3 border-t border-neutral-200 dark:border-black flex items-center justify-between text-xs font-mono">
            <span className="text-neutral-600 dark:text-neutral-400">Alignment:</span>
            <span className={header_forensics.spf.alignment === 'ALIGNED' ? 'text-emerald-600 dark:text-emerald-500 font-bold' : 'text-rose-600 dark:text-rose-500 font-bold'}>
              {header_forensics.spf.alignment}
            </span>
          </div>
        </div>

        {/* DKIM */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-neutral-100 dark:bg-[#242424] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white flex items-center justify-center font-bold font-mono text-xs">
                DKIM
              </div>
              <div>
                <h3 className="font-bold text-sm text-neutral-900 dark:text-white">DomainKeys Identified Mail</h3>
                <span className="text-[10px] text-neutral-500 dark:text-neutral-400 font-mono">RFC 6376</span>
              </div>
            </div>
            <span
              className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold ${
                header_forensics.dkim.status === 'PASS'
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                  : header_forensics.dkim.status === 'NEUTRAL'
                  ? 'bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20'
                  : 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
              }`}
            >
              {header_forensics.dkim.status}
            </span>
          </div>

          <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {header_forensics.dkim.details}
          </p>

          <div className="pt-3 border-t border-neutral-200 dark:border-black flex items-center justify-between text-xs font-mono">
            <span className="text-neutral-600 dark:text-neutral-400">Signature Alignment:</span>
            <span className={header_forensics.dkim.alignment === 'ALIGNED' ? 'text-emerald-600 dark:text-emerald-500 font-bold' : 'text-rose-600 dark:text-rose-500 font-bold'}>
              {header_forensics.dkim.alignment}
            </span>
          </div>
        </div>

        {/* DMARC */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-neutral-100 dark:bg-[#242424] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white flex items-center justify-center font-bold font-mono text-xs">
                DMARC
              </div>
              <div>
                <h3 className="font-bold text-sm text-neutral-900 dark:text-white">Domain-based Auth & Policy</h3>
                <span className="text-[10px] text-neutral-500 dark:text-neutral-400 font-mono">RFC 7489</span>
              </div>
            </div>
            <span
              className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold ${
                header_forensics.dmarc.status === 'PASS'
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                  : 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
              }`}
            >
              {header_forensics.dmarc.status}
            </span>
          </div>

          <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {header_forensics.dmarc.details}
          </p>

          <div className="pt-3 border-t border-neutral-200 dark:border-black flex items-center justify-between text-xs font-mono">
            <span className="text-neutral-600 dark:text-neutral-400">Enforcement Policy:</span>
            <span className="text-neutral-900 dark:text-white font-bold uppercase">
              {header_forensics.dmarc.policy || 'none'}
            </span>
          </div>
        </div>
      </div>

      {/* Domain Homoglyph & Lookalike Comparison */}
      {header_forensics.domain_lookalike.is_lookalike && (
        <div className="p-6 rounded-3xl border border-rose-500/30 bg-rose-500/5 shadow-xl space-y-4">
          <div className="flex items-center gap-2 text-rose-600 dark:text-rose-500 font-bold text-sm">
            <AlertTriangle className="w-5 h-5" />
            <span>Visual Homoglyph / Typosquatting Anomaly Detected</span>
          </div>
          <p className="text-xs text-neutral-700 dark:text-neutral-300">
            The sender domain uses deceptive character substitutions to spoof organizational trust:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-3 rounded-2xl bg-white dark:bg-[#1e1e1e] border border-neutral-300 dark:border-black">
              <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">DISPLAY SENDER DOMAIN</span>
              <span className="font-bold text-rose-600 dark:text-rose-500">{header_forensics.domain_lookalike.display_domain}</span>
            </div>
            <div className="p-3 rounded-2xl bg-white dark:bg-[#1e1e1e] border border-neutral-300 dark:border-black">
              <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">ACTUAL ENVELOPE DOMAIN</span>
              <span className="font-bold text-neutral-900 dark:text-neutral-200">{header_forensics.domain_lookalike.actual_domain}</span>
            </div>
            <div className="p-3 rounded-2xl bg-white dark:bg-[#1e1e1e] border border-neutral-300 dark:border-black">
              <span className="text-[10px] text-neutral-600 dark:text-neutral-400 block font-semibold">DECEPTION TECHNIQUE</span>
              <span className="font-bold text-neutral-900 dark:text-white">{header_forensics.domain_lookalike.technique}</span>
            </div>
          </div>
        </div>
      )}

      {/* Relay Hops Timeline */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-6">
        <div className="flex items-center justify-between pb-4 border-b border-neutral-200 dark:border-black">
          <div>
            <h2 className="text-lg font-bold text-neutral-900 dark:text-white">
              Hop-by-Hop Transmission Relay Chain
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">Chronological MTA progression from client submission to recipient gateway</p>
          </div>
          <span className="text-xs font-mono px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#242424] text-neutral-800 dark:text-neutral-300 border border-neutral-300 dark:border-black font-semibold">
            {header_forensics.hops.length} Sequential Hops
          </span>
        </div>

        <div className="space-y-4">
          {header_forensics.hops.map((hop) => (
            <div
              key={hop.hop_number}
              className={`p-5 rounded-2xl border ${
                hop.is_anomalous
                  ? 'border-rose-500/40 bg-rose-500/5'
                  : 'border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]'
              } space-y-3 transition-all`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-xl bg-neutral-200 dark:bg-[#282828] text-neutral-900 dark:text-white border border-neutral-300 dark:border-black flex items-center justify-center font-mono font-bold text-sm">
                    {hop.hop_number}
                  </div>
                  <div>
                    <div className="font-mono font-bold text-sm text-neutral-900 dark:text-white flex items-center gap-2">
                      <span>{hop.from_ip || 'IP Unresolved'}</span>
                      {hop.is_earliest_reliable && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-950 text-white dark:bg-white dark:text-black font-bold">
                          EARLIEST RELIABLE ORIGIN
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-neutral-500 dark:text-neutral-400">
                      {hop.geo?.city}, {hop.geo?.country} • {hop.geo?.isp}
                    </div>
                  </div>
                </div>

                <div className="text-right font-mono text-xs">
                  <span className="text-neutral-600 dark:text-neutral-400">Protocol: </span>
                  <span className="text-neutral-900 dark:text-white font-semibold">{hop.protocol}</span>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono bg-white/60 dark:bg-[#121212] p-3 rounded-xl border border-neutral-200 dark:border-black">
                <div>
                  <span className="text-neutral-600 dark:text-neutral-400">FROM: </span>
                  <span className="text-neutral-900 dark:text-neutral-200">{hop.from_host}</span>
                </div>
                <div>
                  <span className="text-neutral-600 dark:text-neutral-400">BY: </span>
                  <span className="text-neutral-900 dark:text-neutral-200">{hop.by_host}</span>
                </div>
              </div>

              {hop.is_anomalous && (
                <div className="text-xs text-rose-600 dark:text-rose-500 font-medium flex items-center gap-1.5 pt-1">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{hop.anomaly_reason}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Raw Header Field Breakdown */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-4">
        <h2 className="text-lg font-bold text-neutral-900 dark:text-white">Envelope Identity Field Alignment</h2>
        <div className="space-y-2 font-mono text-xs">
          <div className="p-3 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
            <span className="text-neutral-600 dark:text-neutral-400">From Header:</span>
            <span className="text-neutral-900 dark:text-white font-semibold">{header_forensics.from_header}</span>
          </div>
          <div className="p-3 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
            <span className="text-neutral-600 dark:text-neutral-400">Return-Path:</span>
            <span className="text-neutral-900 dark:text-white font-semibold">{header_forensics.return_path}</span>
          </div>
          <div className="p-3 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
            <span className="text-neutral-600 dark:text-neutral-400">Reply-To:</span>
            <span className="text-rose-600 dark:text-rose-500 font-semibold">{header_forensics.reply_to_header || 'Not Set'}</span>
          </div>
          <div className="p-3 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
            <span className="text-neutral-600 dark:text-neutral-400">Message-ID:</span>
            <span className="text-neutral-700 dark:text-neutral-400 truncate max-w-sm">{header_forensics.message_id}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
