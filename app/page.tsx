'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  Upload,
  ArrowRight,
  ShieldCheck,
  FileCode,
  MapPin,
  Brain,
  Terminal,
  ChevronRight,
  Copy
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';

export default function LandingPage() {
  const [selectedPresetIndex, setSelectedPresetIndex] = useState(0);
  const activeScenario = PRESET_SCENARIOS[selectedPresetIndex];
  const [copied, setCopied] = useState(false);

  const copySampleHeaders = () => {
    navigator.clipboard.writeText(activeScenario.input.raw_headers);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-16 sm:space-y-24 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-12">
      {/* Hero Section */}
      <section className="relative pt-4 sm:pt-12 text-center space-y-6 sm:space-y-8">
        

        {/* Main Heading */}
        <div className="max-w-4xl mx-auto space-y-3 sm:space-y-4">
          <h1 className="text-3xl sm:text-5xl md:text-6xl font-extrabold tracking-tight font-sans text-neutral-950 dark:text-white leading-[1.15]">
            Dissect Raw Headers. <br className="hidden sm:inline" />
            <span className="text-neutral-600 dark:text-neutral-400">
              Detect Spoofing & Trace Email Origin.
            </span>
          </h1>
          <p className="text-sm sm:text-base md:text-lg text-neutral-700 dark:text-neutral-300 max-w-2xl mx-auto leading-relaxed">
            Upload raw <code className="font-mono text-neutral-900 dark:text-white bg-neutral-200/80 dark:bg-[#222222] px-1.5 py-0.5 rounded border border-neutral-300 dark:border-black">*.eml</code> files or analyze ingested SMTP headers to uncover Business Email Compromise (BEC), credential phishing, spoofed domains, and origin transmission hops.
          </p>
        </div>

        {/* Primary Action Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4 pt-2">
          <Link
            href="/analyzer"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-full font-semibold text-xs sm:text-sm transition-all border border-neutral-950 dark:border-black bg-neutral-950 text-white hover:bg-neutral-800 dark:bg-white dark:text-black dark:hover:bg-neutral-200 shadow-md"
          >
            <Upload className="w-4 h-4" />
            Upload .EML / Select from 100 Emails
            <ArrowRight className="w-4 h-4" />
          </Link>

          <Link
            href="/dashboard"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-full font-semibold text-xs sm:text-sm transition-all border border-neutral-300 dark:border-black bg-white dark:bg-[#1e1e1e] hover:bg-neutral-100 dark:hover:bg-[#282828] text-neutral-900 dark:text-neutral-200 shadow-xs"
          >
            <Terminal className="w-4 h-4" />
            SOC Operations Center
          </Link>
        </div>

        {/* Live Interactive Ingestion & Header Verification Preview */}
        <div className="pt-6 max-w-5xl mx-auto">
          <div className="rounded-3xl border border-neutral-300 dark:border-black bg-white dark:bg-[#181818] shadow-2xl p-4 sm:p-6 text-left transition-all">
            {/* Header controls bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-neutral-200 dark:border-black pb-4 mb-5">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span className="text-xs font-mono text-neutral-700 dark:text-neutral-400 font-medium">Live Ingestion Preview</span>
              </div>

              {/* Scenario Switcher Tabs */}
              <div className="flex flex-wrap items-center gap-1.5">
                {PRESET_SCENARIOS.slice(0, 3).map((scenario, idx) => (
                  <button
                    key={scenario.id}
                    onClick={() => setSelectedPresetIndex(idx)}
                    className={`px-3 py-1 rounded-full text-xs font-mono transition-all cursor-pointer border ${
                      selectedPresetIndex === idx
                        ? 'bg-neutral-950 text-white border-neutral-950 dark:bg-white dark:text-black dark:border-black font-semibold shadow-xs'
                        : 'bg-neutral-100 dark:bg-[#222222] border-neutral-300 dark:border-black text-neutral-700 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-[#2c2c2c]'
                    }`}
                  >
                    {scenario.category}
                  </button>
                ))}
              </div>
            </div>

            {/* Simulation Preview Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Forensic Verdict & Metrics */}
              <div className="lg:col-span-5 space-y-4">
                <div className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase text-neutral-600 dark:text-neutral-400 font-medium">Classification</span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20">
                      {activeScenario.threatLevel.toUpperCase()}
                    </span>
                  </div>
                  <h3 className="text-sm sm:text-base font-bold text-neutral-900 dark:text-white">{activeScenario.name}</h3>
                  <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed font-sans">
                    {activeScenario.description}
                  </p>

                  <div className="pt-2 border-t border-neutral-200 dark:border-black flex items-center justify-between">
                    <span className="text-xs text-neutral-600 dark:text-neutral-400">Risk Score (Lower = Safer):</span>
                    <span className="text-sm font-mono font-bold text-rose-600 dark:text-rose-500">96 / 100 (High Risk)</span>
                  </div>
                </div>

                {/* Protocol matrix status */}
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2.5 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]">
                    <div className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">SPF</div>
                    <div className="text-xs font-bold text-amber-600 dark:text-amber-500 mt-0.5">SOFTFAIL</div>
                  </div>
                  <div className="p-2.5 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]">
                    <div className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">DKIM</div>
                    <div className="text-xs font-bold text-rose-600 dark:text-rose-500 mt-0.5">FAIL</div>
                  </div>
                  <div className="p-2.5 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e]">
                    <div className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 uppercase font-semibold">DMARC</div>
                    <div className="text-xs font-bold text-rose-600 dark:text-rose-500 mt-0.5">REJECT</div>
                  </div>
                </div>

                <div className="flex items-center justify-between p-3 rounded-xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] text-xs text-neutral-800 dark:text-neutral-300 font-mono">
                  <span className="flex items-center gap-1.5 truncate">
                    <MapPin className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />
                    Origin: {activeScenario.input.metadata?.enriched_ip} (RU / Tor Node)
                  </span>
                  <Link href="/analyzer" className="underline hover:text-neutral-950 dark:hover:text-white shrink-0 ml-2 font-semibold">
                    Inspect &rarr;
                  </Link>
                </div>
              </div>

              {/* Right Column: Code / Raw Terminal view */}
              <div className="lg:col-span-7 flex flex-col">
                <div className="relative flex-1 rounded-2xl border border-neutral-300 dark:border-black bg-[#121212] text-neutral-300 p-4 font-mono text-xs overflow-hidden">
                  <div className="flex items-center justify-between pb-2 border-b border-neutral-800 mb-3 text-[11px] text-neutral-400">
                    <span>Ingested SMTP Headers Stream</span>
                    <button
                      onClick={copySampleHeaders}
                      className="flex items-center gap-1 hover:text-white transition-colors cursor-pointer"
                    >
                      <Copy className="w-3 h-3" />
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="overflow-x-auto text-[11px] leading-relaxed text-neutral-300 max-h-56">
                    <code>{activeScenario.input.raw_headers.slice(0, 480)}...</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4 Essential Core Capabilities */}
      <section className="space-y-8 sm:space-y-12">
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            Core Email Forensic Capabilities
          </h2>
          <p className="text-xs sm:text-sm text-neutral-600 dark:text-neutral-400">
            ChainMail inspects every header layer, cryptographic signature, and transmission hop with zero hallucinations.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
          {/* Capability 1: Header Forensics */}
          <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all space-y-4 shadow-md">
            <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black flex items-center justify-center text-neutral-900 dark:text-white">
              <FileCode className="w-5 h-5" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-neutral-900 dark:text-white">
                1. RFC 5322 Header & Protocol Security Audit
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Evaluates SPF records, 2048-bit DKIM cryptographic signatures, and DMARC enforcement. Detects visual Unicode homoglyphs, lookalike domains, and envelope divergence between From, Return-Path, and Reply-To.
              </p>
            </div>
            <Link
              href="/header-forensics"
              className="inline-flex items-center gap-1 text-xs font-semibold text-neutral-800 dark:text-neutral-300 hover:text-black dark:hover:text-white pt-1"
            >
              Inspect Header Protocols <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Capability 2: Origin Traceability */}
          <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all space-y-4 shadow-md">
            <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black flex items-center justify-center text-neutral-900 dark:text-white">
              <MapPin className="w-5 h-5" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-neutral-900 dark:text-white">
                2. Reverse Hop Routing & Origin GeoLocation
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Traverses multiline <code className="font-mono text-neutral-900 dark:text-white bg-neutral-200/80 dark:bg-[#242424] px-1 rounded border border-neutral-300 dark:border-transparent">Received:</code> chains inward to isolate the earliest untrusted client node, flagging Tor exit relays, bulletproof hosting providers, and residential proxies.
              </p>
            </div>
            <Link
              href="/traceability"
              className="inline-flex items-center gap-1 text-xs font-semibold text-neutral-800 dark:text-neutral-300 hover:text-black dark:hover:text-white pt-1"
            >
              Inspect Origin Geo <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Capability 3: NLP Behavioral */}
          <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all space-y-4 shadow-md">
            <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black flex items-center justify-center text-neutral-900 dark:text-white">
              <Brain className="w-5 h-5" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-neutral-900 dark:text-white">
                3. NLP Behavioral & Wire Fraud Analysis
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Analyzes subject lines and bodies for artificial urgency triggers, CEO authority coercion, fraudulent wire transfers (IBAN/SWIFT/Escrow diversion), and reverse proxy credential harvesting links.
              </p>
            </div>
            <Link
              href="/nlp-threats"
              className="inline-flex items-center gap-1 text-xs font-semibold text-neutral-800 dark:text-neutral-300 hover:text-black dark:hover:text-white pt-1"
            >
              Inspect NLP Vectors <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {/* Capability 4: SOC Playbooks */}
          <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all space-y-4 shadow-md">
            <div className="w-10 h-10 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black flex items-center justify-center text-neutral-900 dark:text-white">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-neutral-900 dark:text-white">
                4. Actionable SOC Playbooks & STIX 2.1 IoCs
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Provides ready-to-execute perimeter firewall drop rules (iptables), Exchange domain block scripts, Azure AD token revokers, and cryptographic SHA-256 evidence certificates.
              </p>
            </div>
            <Link
              href="/recommendations"
              className="inline-flex items-center gap-1 text-xs font-semibold text-neutral-800 dark:text-neutral-300 hover:text-black dark:hover:text-white pt-1"
            >
              Inspect SOC Playbooks <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </section>

      {/* Bottom CTA Banner */}
      <section className="text-center py-8 sm:py-12 space-y-6">
        <h2 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
          Begin an Email Forensics Investigation
        </h2>
        <p className="text-xs sm:text-sm text-neutral-600 dark:text-neutral-400 max-w-lg mx-auto">
          Ingest an `.eml` file, test sample threats, or explore the live 100-email threat dataset.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4">
          <Link
            href="/analyzer"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-full font-semibold text-xs sm:text-sm text-white bg-neutral-950 hover:bg-neutral-800 dark:text-black dark:bg-white dark:hover:bg-neutral-200 border border-neutral-950 dark:border-black shadow-lg transition-all"
          >
            <Upload className="w-4 h-4" />
            Upload .EML / Threat Queue (100 Emails)
          </Link>
          <Link
            href="/dashboard"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-full font-semibold text-xs sm:text-sm border border-neutral-300 dark:border-black bg-white dark:bg-[#181818] text-neutral-900 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-[#242424] transition-all"
          >
            Launch SOC Dashboard
          </Link>
        </div>
      </section>
    </div>
  );
}
