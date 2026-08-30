'use client';

import React from 'react';
import Link from 'next/link';
import { useForensicSession } from './forensic-context';
import { parseEmlFileContent } from '@/lib/eml-parser';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import {
  FileText,
  Upload,
  Sparkles,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  SlidersHorizontal
} from 'lucide-react';

export function ActiveTargetBanner({ title, subtitle }: { title?: string; subtitle?: string }) {
  const { activeReport, activeMeta, isUploaded, setActiveEmail, resetToPreset } = useForensicSession();

  const handleQuickUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        if (!content) return;

        const parsed = parseEmlFileContent(content);
        const rep = analyzeEmailThreat(parsed);
        const subjectMatch = parsed.raw_headers.match(/Subject:\s*([^\r\n]+)/i);
        const fromMatch = parsed.raw_headers.match(/From:\s*"?([^"<]+)"?\s*<([^>]+)>/i);

        setActiveEmail(parsed, rep, {
          id: `EML-${Date.now().toString().slice(-4)}`,
          subject: subjectMatch?.[1] || file.name,
          senderName: fromMatch?.[1] || 'External Sender',
          senderEmail: fromMatch?.[2] || 'sender@external.net',
          isUploaded: true,
          fileName: file.name
        });
      };
      reader.readAsText(file);
    }
  };

  const isCritical = activeReport.fraud_risk_score >= 70;
  const isSuspicious = activeReport.fraud_risk_score >= 35 && activeReport.fraud_risk_score < 70;

  return (
    <div className="p-4 sm:p-5 rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-lg space-y-3">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-neutral-200 dark:border-black">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-bold flex items-center gap-1.5 border ${
            isUploaded
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-400'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-800 dark:text-amber-300'
          }`}>
            <span className={`w-2 h-2 rounded-full ${isUploaded ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
            <span>{isUploaded ? 'Active Ingested .EML Target' : 'Active Forensic Session'}</span>
          </div>

          <span className="text-xs font-mono font-bold text-neutral-900 dark:text-white truncate max-w-xs sm:max-w-md">
            {activeMeta.subject}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-bold border ${
            isCritical
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-400'
              : isSuspicious
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-400'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-400'
          }`}>
            {activeReport.threat_classification} ({activeReport.fraud_risk_score}/100)
          </span>

          <label className="px-3 py-1 rounded-full text-[11px] font-mono font-semibold border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#242424] text-neutral-800 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-[#2c2c2c] cursor-pointer flex items-center gap-1.5 transition-colors shadow-2xs">
            <Upload className="w-3 h-3" />
            <span>Inject .EML</span>
            <input
              type="file"
              accept=".eml,.txt,.msg"
              className="hidden"
              onChange={handleQuickUpload}
            />
          </label>

          <Link
            href="/analyzer"
            className="px-3 py-1 rounded-full text-[11px] font-mono font-semibold border border-neutral-950 dark:border-black bg-neutral-950 text-white dark:bg-white dark:text-black hover:opacity-90 flex items-center gap-1 transition-opacity shadow-xs"
          >
            <span>Open Workbench</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-neutral-600 dark:text-neutral-400">
        <div className="flex items-center gap-3 truncate">
          <span>From: <strong className="text-neutral-900 dark:text-neutral-200">{activeMeta.senderEmail}</strong></span>
          <span>• Origin IP: <strong className="text-neutral-900 dark:text-neutral-200">{activeReport.traceability_map.earliest_reliable_ip}</strong></span>
          <span>• Country: <strong className="text-neutral-900 dark:text-neutral-200">{activeReport.traceability_map.geolocation_estimate.country}</strong></span>
        </div>
        {activeReport.engine_mode === 'ai-gemini' && (
          <div className="flex items-center gap-1 text-amber-700 dark:text-amber-400 font-semibold">
            <Sparkles className="w-3 h-3" />
            <span>Gemini AI Dissection Active</span>
          </div>
        )}
      </div>
    </div>
  );
}
