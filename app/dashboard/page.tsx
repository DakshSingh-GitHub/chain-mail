'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import {
  Globe,
  ArrowUpRight,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Terminal,
  Crosshair,
  Search,
  Upload
} from 'lucide-react';
import { MOCK_100_EMAILS } from '@/lib/mock-emails';
import { analyzeEmailThreat } from '@/lib/forensic-engine';

export default function DashboardPage() {
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  // Real statistics computed directly from the 100 email dataset
  const totalCount = MOCK_100_EMAILS.length;
  const threatCount = useMemo(() => MOCK_100_EMAILS.filter(m => m.isSpoofed).length, []);
  const safeCount = useMemo(() => MOCK_100_EMAILS.filter(m => !m.isSpoofed).length, []);
  const becCount = useMemo(() => MOCK_100_EMAILS.filter(m => m.category === 'BEC').length, []);

  // Generate real-time analyzed incidents from our dataset
  const incidents = useMemo(() => {
    return MOCK_100_EMAILS.map((mail) => {
      const report = analyzeEmailThreat(mail.input);
      return {
        id: mail.id,
        name: mail.subject,
        classification: report.threat_classification,
        riskScore: report.fraud_risk_score,
        originIp: report.traceability_map.earliest_reliable_ip,
        originCountry: report.traceability_map.geolocation_estimate.country,
        infra: report.traceability_map.infrastructure_type,
        campaign: report.attribution_confidence.associated_campaign || 'None (Benign)',
        accountState: report.attribution_confidence.account_state,
        timestamp: mail.date,
        subject: mail.subject,
        from: mail.senderEmail,
        isSpoofed: mail.isSpoofed,
        threatLevel: mail.threatLevel
      };
    });
  }, []);

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesCategory =
        filterCategory === 'ALL' ||
        (filterCategory === 'BEC' && inc.classification === 'BEC') ||
        (filterCategory === 'PHISHING' && inc.classification === 'Phishing') ||
        (filterCategory === 'SPOOFED' && inc.isSpoofed) ||
        (filterCategory === 'SAFE' && !inc.isSpoofed);

      const matchesSearch =
        searchTerm === '' ||
        inc.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.from.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.originIp.includes(searchTerm) ||
        inc.id.toLowerCase().includes(searchTerm.toLowerCase());

      return matchesCategory && matchesSearch;
    });
  }, [incidents, filterCategory, searchTerm]);

  const totalPages = Math.ceil(filteredIncidents.length / itemsPerPage) || 1;
  const paginatedIncidents = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredIncidents.slice(start, start + itemsPerPage);
  }, [filteredIncidents, currentPage]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6 sm:space-y-8 pb-12">
      {/* Top Banner: Real Ingestion Operations Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl border border-black bg-white dark:bg-[#181818] shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span className="text-xs font-mono uppercase font-bold text-neutral-600 dark:text-neutral-400 tracking-wider">
              EMAIL THREAT OPERATIONS & INGESTION QUEUE
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-neutral-900 dark:text-white">
            Forensic Operations Dashboard
          </h1>
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Real-time inspection feed, origin hop geolocation, and cryptographic protocol audit for ingested emails.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <Link
            href="/analyzer"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-full text-xs font-semibold text-white bg-neutral-950 hover:bg-neutral-800 dark:text-black dark:bg-white dark:hover:bg-neutral-200 border border-neutral-950 dark:border-black shadow-sm transition-all"
          >
            <Upload className="w-4 h-4" />
            Upload .EML / Ingest
          </Link>
          <Link
            href="/api-docs"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-full text-xs font-medium border border-neutral-300 dark:border-black bg-white dark:bg-[#1e1e1e] hover:bg-neutral-100 dark:hover:bg-[#282828] text-neutral-800 dark:text-neutral-300 transition-colors"
          >
            <FileCode className="w-4 h-4" />
            API Schema
          </Link>
        </div>
      </div>

      {/* Real Queue Telemetry Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-4 sm:p-5 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-md">
          <span className="text-xs text-neutral-600 dark:text-neutral-400 font-sans block mb-1">Total Ingestion Queue</span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-neutral-900 dark:text-white">{totalCount} Emails</div>
          <span className="text-[11px] text-neutral-500 dark:text-neutral-400 font-mono mt-1 block">Live Mock Dataset</span>
        </div>

        <div className="p-4 sm:p-5 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-md">
          <span className="text-xs text-neutral-600 dark:text-neutral-400 font-sans block mb-1">Spoofed & Malicious</span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-rose-600 dark:text-rose-500">{threatCount} Threats</div>
          <span className="text-[11px] text-rose-600 dark:text-rose-400 font-mono mt-1 block">High/Critical Risk (70-99/100)</span>
        </div>

        <div className="p-4 sm:p-5 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-md">
          <span className="text-xs text-neutral-600 dark:text-neutral-400 font-sans block mb-1">Verified Authentic / Safe</span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-500">{safeCount} Clean</div>
          <span className="text-[11px] text-emerald-600 dark:text-emerald-400 font-mono mt-1 block">Low Risk (0-15/100)</span>
        </div>

        <div className="p-4 sm:p-5 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-md">
          <span className="text-xs text-neutral-600 dark:text-neutral-400 font-sans block mb-1">BEC Wire Transfers</span>
          <div className="text-xl sm:text-2xl font-bold font-mono text-amber-600 dark:text-amber-500">{becCount} Detected</div>
          <span className="text-[11px] text-amber-600 dark:text-amber-400 font-mono mt-1 block">Payment Diversion Vectors</span>
        </div>
      </div>

      {/* Quick Launchpad to Forensic Investigation Modules */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <Link
          href="/analyzer"
          className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all group flex items-start gap-3 shadow-md"
        >
          <div className="p-2.5 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-neutral-900 dark:text-white group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              Threat Analyzer
            </div>
            <div className="text-[11px] text-neutral-500 dark:text-neutral-400 mt-0.5">Upload .eml or select email</div>
          </div>
        </Link>

        <Link
          href="/header-forensics"
          className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all group flex items-start gap-3 shadow-md"
        >
          <div className="p-2.5 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white">
            <FileCode className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-neutral-900 dark:text-white group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              Header Forensics
            </div>
            <div className="text-[11px] text-neutral-500 dark:text-neutral-400 mt-0.5">SPF/DKIM/DMARC relay inspector</div>
          </div>
        </Link>

        <Link
          href="/traceability"
          className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all group flex items-start gap-3 shadow-md"
        >
          <div className="p-2.5 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white">
            <Globe className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-neutral-900 dark:text-white group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              Origin GeoLocation
            </div>
            <div className="text-[11px] text-neutral-500 dark:text-neutral-400 mt-0.5">Map hops & TOR/VPN flags</div>
          </div>
        </Link>

        <Link
          href="/attribution"
          className="p-4 rounded-2xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] hover:bg-neutral-50 dark:hover:bg-[#1e1e1e] transition-all group flex items-start gap-3 shadow-md"
        >
          <div className="p-2.5 rounded-xl bg-neutral-100 dark:bg-[#222222] border border-neutral-300 dark:border-black text-neutral-900 dark:text-white">
            <Crosshair className="w-4 h-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-neutral-900 dark:text-white group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              Threat Attribution
            </div>
            <div className="text-[11px] text-neutral-500 dark:text-neutral-400 mt-0.5">Actor profiling & STIX IoCs</div>
          </div>
        </Link>
      </div>

      {/* Main Incident Investigation Feed Table */}
      <div className="rounded-3xl border border-neutral-200 dark:border-black bg-white dark:bg-[#181818] shadow-xl overflow-hidden">
        {/* Table Filter / Controls Header */}
        <div className="p-4 sm:p-6 border-b border-neutral-200 dark:border-black flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base sm:text-lg font-bold text-neutral-900 dark:text-white">
              Ingested Threat Queue & Incident Feed
            </h2>
            <p className="text-xs text-neutral-600 dark:text-neutral-400">
              Select any incident to inspect its full header analysis and forensic trail (Lower Risk Score = Safer)
            </p>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-400" />
              <input
                type="text"
                placeholder="Search subject, IP, or sender..."
                value={searchTerm}
                onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                className="pl-8 pr-3 py-1.5 rounded-full text-xs font-mono border border-neutral-300 dark:border-black bg-neutral-50 dark:bg-[#1e1e1e] text-neutral-800 dark:text-neutral-200 focus:outline-none focus:border-neutral-400 w-full sm:w-60"
              />
            </div>

            {/* Filter Tabs */}
            <div className="flex flex-wrap items-center gap-1 p-1 rounded-full border border-neutral-300 dark:border-black bg-neutral-100 dark:bg-[#1e1e1e]">
              {[
                { id: 'ALL', label: 'All' },
                { id: 'SPOOFED', label: 'Spoofed' },
                { id: 'SAFE', label: 'Safe' },
                { id: 'BEC', label: 'BEC' },
                { id: 'PHISHING', label: 'Phishing' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => { setFilterCategory(tab.id); setCurrentPage(1); }}
                  className={`px-3 py-1 rounded-full text-xs font-mono font-medium transition-all cursor-pointer ${
                    filterCategory === tab.id
                      ? 'bg-neutral-950 text-white dark:bg-white dark:text-black font-semibold shadow-xs'
                      : 'text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table List */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-neutral-200 dark:border-black text-neutral-600 dark:text-neutral-400 font-mono uppercase bg-neutral-100 dark:bg-[#141414]">
              <tr>
                <th className="py-3 px-4">Case ID</th>
                <th className="py-3 px-4">Status & Type</th>
                <th className="py-3 px-4">Subject & Sender</th>
                <th className="py-3 px-4">Origin Node & Country</th>
                <th className="py-3 px-4">Risk Score (0-100)</th>
                <th className="py-3 px-4">Campaign / Attribution</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 dark:divide-neutral-900 font-mono">
              {paginatedIncidents.map((inc) => {
                const isCritical = inc.threatLevel === 'Critical';
                const isHigh = inc.threatLevel === 'High';
                const isClean = inc.threatLevel === 'Clean';

                return (
                  <tr
                    key={inc.id}
                    className="hover:bg-neutral-50 dark:hover:bg-[#1f1f1f] transition-colors"
                  >
                    {/* Case ID */}
                    <td className="py-4 px-4 font-semibold text-neutral-900 dark:text-white">
                      {inc.id}
                    </td>

                    {/* Threat Classification Badge */}
                    <td className="py-4 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold ${
                          isCritical
                            ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20'
                            : isHigh
                            ? 'bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20'
                            : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20'
                        }`}
                      >
                        {isCritical && <AlertTriangle className="w-3 h-3" />}
                        {isClean && <CheckCircle2 className="w-3 h-3" />}
                        {inc.classification}
                      </span>
                    </td>

                    {/* Subject & Pretext */}
                    <td className="py-4 px-4 max-w-xs font-sans">
                      <div className="font-semibold text-neutral-900 dark:text-white line-clamp-1">
                        {inc.subject}
                      </div>
                      <div className="text-[11px] text-neutral-500 dark:text-neutral-400 line-clamp-1 mt-0.5">
                        {inc.from}
                      </div>
                    </td>

                    {/* Origin IP & Geo */}
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-1.5 font-semibold text-neutral-800 dark:text-neutral-200">
                        <Globe className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400" />
                        <span>{inc.originIp}</span>
                      </div>
                      <div className="text-[11px] text-neutral-500 dark:text-neutral-400">
                        {inc.originCountry} • {inc.infra}
                      </div>
                    </td>

                    {/* Risk Score (Lower = Safer) */}
                    <td className="py-4 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-neutral-200 dark:bg-[#282828] h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              inc.riskScore > 70
                                ? 'bg-rose-500'
                                : inc.riskScore > 35
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${inc.riskScore}%` }}
                          ></div>
                        </div>
                        <span
                          className={`font-bold ${
                            inc.riskScore > 70
                              ? 'text-rose-600 dark:text-rose-500'
                              : inc.riskScore > 35
                              ? 'text-amber-600 dark:text-amber-500'
                              : 'text-emerald-600 dark:text-emerald-500'
                          }`}
                        >
                          {inc.riskScore}/100
                        </span>
                      </div>
                    </td>

                    {/* Attribution / Campaign */}
                    <td className="py-4 px-4 font-sans text-xs">
                      <div className="font-medium text-neutral-800 dark:text-neutral-200">
                        {inc.campaign}
                      </div>
                      <div className="text-[11px] text-neutral-500 dark:text-neutral-400">
                        {inc.accountState}
                      </div>
                    </td>

                    {/* Action Button */}
                    <td className="py-4 px-4 text-right">
                      <Link
                        href={`/analyzer?mailId=${inc.id}`}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-sans font-medium border border-neutral-300 dark:border-black bg-white dark:bg-white text-neutral-900 dark:text-black hover:bg-neutral-100 dark:hover:bg-neutral-200 transition-colors shadow-xs"
                      >
                        Inspect <ArrowUpRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between p-4 border-t border-neutral-200 dark:border-black text-xs font-mono">
            <span className="text-neutral-600 dark:text-neutral-400">
              Showing page {currentPage} of {totalPages} ({filteredIncidents.length} incidents)
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
