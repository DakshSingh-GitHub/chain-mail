'use client';

import React, { useState } from 'react';
import {
  Globe,
  Radio,
  Server,
  Info
} from 'lucide-react';
import { PRESET_SCENARIOS } from '@/lib/presets';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { useForensicSession } from '@/components/forensic-context';
import { ActiveTargetBanner } from '@/components/active-target-banner';

export default function TraceabilityPage() {
  const { activeReport, activeMeta, isUploaded, resetToPreset } = useForensicSession();
  const [selectedPresetId, setSelectedPresetId] = useState<string | 'ACTIVE_EML'>('ACTIVE_EML');

  const scenario = selectedPresetId === 'ACTIVE_EML'
    ? null
    : PRESET_SCENARIOS.find(p => p.id === selectedPresetId);

  const report = scenario ? analyzeEmailThreat(scenario.input) : activeReport;
  const { traceability_map } = report;

  // Compute map SVG coordinates from lat/lon (-180 to 180 -> 0 to 800, 90 to -90 -> 0 to 400)
  const mapX = ((traceability_map.geolocation_estimate.longitude + 180) / 360) * 800;
  const mapY = ((90 - traceability_map.geolocation_estimate.latitude) / 180) * 400;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
      {/* Active Target Banner */}
      <ActiveTargetBanner />

      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              ORIGIN TRACEABILITY & INFRASTRUCTURE ASSESSMENT
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            Transmission Routing & GeoLocation Engine
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Reconstructing origin paths, isolating earliest reliable SMTP hops, and classifying adversary hosting infrastructure.
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

      {/* World Map Visualizer Card */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-neutral-200 dark:border-black">
          <div>
            <h2 className="text-lg font-bold text-neutral-900 dark:text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-neutral-600 dark:text-neutral-300" />
              Global Transmission Routing Map
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              Resolved Geographic Coordinates: {traceability_map.geolocation_estimate.latitude.toFixed(4)}° N, {traceability_map.geolocation_estimate.longitude.toFixed(4)}° E
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20">
              {traceability_map.infrastructure_type}
            </span>
          </div>
        </div>

        {/* SVG World Map Plottable Canvas */}
        <div className="relative w-full h-72 sm:h-96 rounded-2xl border border-neutral-300 dark:border-black bg-neutral-900 dark:bg-[#121212] overflow-hidden flex items-center justify-center">
          {/* Subtle grid lines */}
          <div className="absolute inset-0 cyber-grid opacity-30"></div>

          {/* SVG Map Base with Continents representation */}
          <svg
            viewBox="0 0 800 400"
            className="w-full h-full text-neutral-800 fill-current opacity-50"
          >
            {/* North America */}
            <path d="M120,60 Q180,50 220,90 Q240,140 180,180 Q130,160 100,100 Z" />
            {/* South America */}
            <path d="M220,200 Q270,220 250,320 Q210,340 200,240 Z" />
            {/* Europe */}
            <path d="M420,70 Q480,60 500,110 Q450,140 410,100 Z" />
            {/* Africa */}
            <path d="M410,150 Q490,160 480,270 Q410,290 390,200 Z" />
            {/* Asia */}
            <path d="M520,70 Q680,60 700,160 Q600,210 510,130 Z" />
            {/* Australia */}
            <path d="M640,250 Q710,240 700,310 Q630,310 640,250 Z" />
          </svg>

          {/* Plotted Origin Node with Pulse */}
          <div
            className="absolute transform -translate-x-1/2 -translate-y-1/2 group cursor-pointer z-10"
            style={{ left: `${(mapX / 800) * 100}%`, top: `${(mapY / 400) * 100}%` }}
          >
            <div className="relative flex items-center justify-center">
              <span className="animate-ping absolute inline-flex h-8 w-8 rounded-full bg-rose-500 opacity-60"></span>
              <span className="relative inline-flex rounded-full h-4 w-4 bg-rose-500 border-2 border-white shadow-lg"></span>
            </div>

            {/* Hover Tooltip Card */}
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-56 p-2.5 rounded-xl bg-[#1e1e1e] border border-black text-white text-[11px] font-mono shadow-2xl pointer-events-none z-20">
              <div className="text-white font-bold">{traceability_map.earliest_reliable_ip}</div>
              <div className="text-neutral-300">{traceability_map.geolocation_estimate.city}, {traceability_map.geolocation_estimate.country}</div>
              <div className="text-rose-400 font-semibold">{traceability_map.infrastructure_type}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Origin Intelligence & Domain Intelligence Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Origin IP Intelligence */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center gap-2 text-neutral-900 dark:text-white font-bold text-base">
            <Server className="w-5 h-5" />
            <h3>Earliest Reliable Origin Node</h3>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">Resolved IP:</span>
              <span className="text-neutral-900 dark:text-white font-bold">{traceability_map.earliest_reliable_ip}</span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">City / Country:</span>
              <span className="text-neutral-900 dark:text-white font-semibold">
                {traceability_map.geolocation_estimate.city}, {traceability_map.geolocation_estimate.country} ({traceability_map.geolocation_estimate.country_code})
              </span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">Autonomous System:</span>
              <span className="text-neutral-900 dark:text-white font-semibold">
                {traceability_map.geolocation_estimate.asn}
              </span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">ISP / Organization:</span>
              <span className="text-neutral-900 dark:text-white font-semibold truncate max-w-xs">
                {traceability_map.geolocation_estimate.isp}
              </span>
            </div>

            <div className="p-3 rounded-2xl border border-rose-500/30 bg-rose-500/5 flex items-center justify-between">
              <span className="text-rose-600 dark:text-rose-500 font-bold">Infrastructure Risk:</span>
              <span className="text-rose-600 dark:text-rose-500 font-extrabold">{traceability_map.infrastructure_risk_score}/100</span>
            </div>
          </div>
        </div>

        {/* Domain WHOIS Intelligence */}
        <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-4">
          <div className="flex items-center gap-2 text-neutral-900 dark:text-white font-bold text-base">
            <Radio className="w-5 h-5" />
            <h3>Domain WHOIS & DNS Intelligence</h3>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">Domain Name:</span>
              <span className="text-neutral-900 dark:text-white font-bold">{traceability_map.domain_intelligence.domain}</span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">Domain Age:</span>
              <span className={`font-bold ${traceability_map.domain_intelligence.is_newly_registered ? 'text-rose-600 dark:text-rose-500' : 'text-emerald-600 dark:text-emerald-500'}`}>
                {traceability_map.domain_intelligence.domain_age_days} Days {traceability_map.domain_intelligence.is_newly_registered && '(BURNER DOMAIN)'}
              </span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">Registrar:</span>
              <span className="text-neutral-900 dark:text-white font-semibold">
                {traceability_map.domain_intelligence.registrar}
              </span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">DMARC Policy Enforced:</span>
              <span className={traceability_map.domain_intelligence.dmarc_enforced ? 'text-emerald-600 dark:text-emerald-500 font-bold' : 'text-rose-600 dark:text-rose-500 font-bold'}>
                {traceability_map.domain_intelligence.dmarc_enforced ? 'ENFORCED (REJECT)' : 'NONE / UNENFORCED'}
              </span>
            </div>

            <div className="p-3 rounded-2xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] flex items-center justify-between">
              <span className="text-neutral-600 dark:text-neutral-400 font-semibold">Primary MX:</span>
              <span className="text-neutral-900 dark:text-white font-semibold truncate max-w-xs">
                {traceability_map.domain_intelligence.mx_records?.[0] || 'mail.secureshield-mx.net'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Earliest Reliable Hop Selection Algorithm Explanation */}
      <div className="p-6 rounded-3xl border border-neutral-200 dark:border-black bg-neutral-50 dark:bg-[#181818] space-y-3">
        <div className="flex items-center gap-2 font-bold text-sm text-neutral-900 dark:text-white">
          <Info className="w-4 h-4 text-neutral-500 dark:text-neutral-400" />
          Earliest Reliable Hop Selection Algorithm (RFC 5322 Section 3.6.7)
        </div>
        <p className="text-xs text-neutral-700 dark:text-neutral-300 leading-relaxed">
          The earliest reliable hop is calculated by traversing the <code className="font-mono bg-neutral-200/80 dark:bg-[#282828] px-1 py-0.5 rounded border border-neutral-300 dark:border-black text-neutral-900 dark:text-neutral-200">Received:</code> header chain from the outermost authenticated mail transfer agent (MTA) inward. Private LAN / internal gateways (RFC 1918) and trusted cloud ingress relays (e.g. Cloudflare, Mimecast, Google Workspace) are verified, isolating the earliest untrusted client node: <code className="font-mono text-neutral-900 dark:text-white font-bold">{traceability_map.earliest_reliable_ip}</code>.
        </p>
      </div>
    </div>
  );
}
