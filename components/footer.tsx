'use client';

import React from 'react';
import Link from 'next/link';
import { useTheme } from './theme-provider';
import { ShieldCheck, Terminal, Globe, Lock, Cpu, ArrowUpRight } from 'lucide-react';

export function Footer() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <footer
      className={`border-t transition-colors mt-auto py-12 px-4 sm:px-6 lg:px-8 ${
        isDark ? 'bg-[#121212] border-black text-neutral-400' : 'bg-neutral-50 border-neutral-300 text-neutral-600'
      }`}
    >
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
        {/* Col 1: Brand & Status */}
        <div className="space-y-4 md:col-span-1">
          <div className="flex items-center gap-2">
            <div className={`w-7 h-7 rounded-lg flex items-center justify-center border ${
              isDark ? 'bg-[#1e1e1e] border-black text-white' : 'bg-neutral-900 border-neutral-900 text-white'
            }`}>
              <ShieldCheck className="w-4 h-4" />
            </div>
            <span className="font-bold text-base font-mono tracking-tight text-neutral-900 dark:text-white">ChainMail</span>
          </div>
          <p className="text-xs leading-relaxed text-neutral-600 dark:text-neutral-400">
            Autonomous Email Threat Detection, Origin Traceability, and Forensic Intelligence Engine for security operations & digital incident response.
          </p>
          
        </div>

        {/* Col 2: Forensics Suite */}
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-900 dark:text-white mb-3">Forensics Suite</h4>
          <ul className="space-y-2 text-xs">
            <li>
              <Link href="/analyzer" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                Live Threat Analyzer <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
            <li>
              <Link href="/header-forensics" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                Header & Protocol Forensics <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
            <li>
              <Link href="/traceability" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                Origin GeoLocation & Hops <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
            <li>
              <Link href="/nlp-threats" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                NLP & Behavioral Social Eng <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
          </ul>
        </div>

        {/* Col 3: Threat Intel & SOC */}
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-900 dark:text-white mb-3">Threat Intelligence</h4>
          <ul className="space-y-2 text-xs">
            <li>
              <Link href="/dashboard" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                SOC Operations Center <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
            <li>
              <Link href="/attribution" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                Attribution & Campaigns <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
            <li>
              <Link href="/recommendations" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                Incident Response Playbooks <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
            <li>
              <Link href="/api-docs" className="hover:text-neutral-950 dark:hover:text-white transition-colors flex items-center gap-1">
                REST Engine Schema <ArrowUpRight className="w-3 h-3 opacity-60" />
              </Link>
            </li>
          </ul>
        </div>

        {/* Col 4: Compliance & RFC Specs */}
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-900 dark:text-white mb-3">Standards & Protocols</h4>
          <div className="space-y-2 text-xs text-neutral-600 dark:text-neutral-400">
            <div className="flex items-center gap-2">
              <Lock className="w-3.5 h-3.5" />
              <span>RFC 5322 Internet Message Format</span>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="w-3.5 h-3.5" />
              <span>RFC 7208 SPF / RFC 6376 DKIM</span>
            </div>
            <div className="flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5" />
              <span>RFC 7489 DMARC Policy Enforcement</span>
            </div>
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5" />
              <span>STIX 2.1 & MITRE ATT&CK Mapping</span>
            </div>
          </div>
        </div>
      </div>

      <div className={`pt-6 border-t flex flex-col sm:flex-row items-center justify-between gap-4 text-xs ${
        isDark ? 'border-black text-neutral-500' : 'border-neutral-300 text-neutral-500'
      }`}>
        <div>
          © {new Date().getFullYear()} ChainMail Intelligence Platform. Built for Digital Forensics & Cyber Defense.
        </div>
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1 font-mono text-[11px]">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Zero Hallucination Mode Active
          </span>
          <span className="text-neutral-600">|</span>
          <span>PII Masking Guaranteed</span>
        </div>
      </div>
    </footer>
  );
}
