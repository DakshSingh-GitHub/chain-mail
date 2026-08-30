'use client';

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTheme } from './theme-provider';
import { ThemeToggle } from './theme-toggle';
import {
  ShieldAlert,
  ChevronDown,
  Activity,
  Terminal,
  FileCode,
  MapPin,
  Brain,
  Crosshair,
  ShieldCheck,
  Code,
  LayoutDashboard,
  Menu,
  X
} from 'lucide-react';

interface SubMenuItem {
  title: string;
  description: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
}

export function Navbar() {
  const pathname = usePathname();
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navRef = useRef<HTMLDivElement>(null);

  // Close dropdowns on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (navRef.current && !navRef.current.contains(event.target as Node)) {
        setActiveDropdown(null);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const closeMenus = () => {
    setActiveDropdown(null);
    setMobileMenuOpen(false);
  };

  const forensicsItems: SubMenuItem[] = [
    {
      title: 'Live Threat Analyzer',
      description: 'Ingest raw headers, email body & metadata with instant AI heuristics',
      href: '/analyzer',
      icon: Terminal,
      badge: 'Core'
    },
    {
      title: 'Header & Protocol Forensics',
      description: 'Hop-by-hop relay latency, SPF/DKIM/DMARC alignment & spoofing checks',
      href: '/header-forensics',
      icon: FileCode
    },
    {
      title: 'Origin Traceability & Geo',
      description: 'Earliest reliable IP extraction, world hop map & TOR/VPN flags',
      href: '/traceability',
      icon: MapPin
    },
    {
      title: 'NLP & Behavioral Analysis',
      description: 'Urgency metrics, wire fraud detection, and obfuscated link scanner',
      href: '/nlp-threats',
      icon: Brain
    }
  ];

  const threatIntelItems: SubMenuItem[] = [
    {
      title: 'Attribution & Campaigns',
      description: 'Threat actor profiling, IoC extraction & Account Takeover (ATO) correlation',
      href: '/attribution',
      icon: Crosshair
    },
    {
      title: 'Incident Playbooks & SOC',
      description: 'Firewall block generation, email quarantine rules & evidence export',
      href: '/recommendations',
      icon: ShieldCheck,
      badge: 'Action'
    }
  ];

  const isLanding = pathname === '/';

  return (
    <header className="fixed top-4 inset-x-0 z-50 px-4 sm:px-6 max-w-7xl mx-auto pointer-events-none" ref={navRef}>
      <nav
        className={`pointer-events-auto w-full rounded-full transition-all duration-200 backdrop-blur-xl border px-4 sm:px-6 py-2.5 flex items-center justify-between shadow-lg ${
          isDark
            ? 'bg-[#181818]/95 border-black shadow-2xl shadow-black/80 text-neutral-200'
            : 'bg-white/95 border-neutral-300 shadow-lg shadow-neutral-900/5 text-neutral-800'
        }`}
      >
        {/* Brand / Logo */}
        <Link href="/" onClick={closeMenus} className="flex items-center gap-3 group shrink-0">
          <div className={`relative flex items-center justify-center w-8 h-8 rounded-full p-0.5 border ${
            isDark ? 'bg-[#242424] border-black text-white' : 'bg-neutral-100 border-neutral-300 text-neutral-900'
          }`}>
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-sm sm:text-base tracking-tight font-mono text-neutral-950 dark:text-white">ChainMail</span>
            </div>
            <span className="text-[10px] text-neutral-600 dark:text-neutral-400 font-sans hidden sm:inline">Threat Intelligence Engine</span>
          </div>
        </Link>

        {/* Desktop Navigation Menus */}
        {!isLanding && (
          <div className="hidden lg:flex items-center gap-1">
          {/* Forensics Suite Dropdown */}
          <div className="relative">
            <button
              onClick={() => setActiveDropdown(activeDropdown === 'forensics' ? null : 'forensics')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all ${
                pathname.startsWith('/analyzer') || pathname.startsWith('/header-forensics') || pathname.startsWith('/traceability') || pathname.startsWith('/nlp-threats')
                  ? isDark ? 'bg-[#252525] text-white border border-black' : 'bg-neutral-100 text-neutral-900 border border-neutral-300'
                  : isDark ? 'hover:bg-[#252525] text-neutral-300' : 'hover:bg-neutral-100 text-neutral-700'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              Forensics Engine
              <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${activeDropdown === 'forensics' ? 'rotate-180' : ''}`} />
            </button>

            {activeDropdown === 'forensics' && (
              <div
                className={`absolute top-full left-0 mt-3 w-80 rounded-2xl p-2 border backdrop-blur-2xl shadow-2xl transition-all ${
                  isDark ? 'bg-[#1a1a1a]/98 border-black shadow-black' : 'bg-white/98 border-neutral-300 shadow-neutral-900/15'
                }`}
              >
                <div className={`px-3 py-2 border-b mb-1 ${isDark ? 'border-neutral-800' : 'border-neutral-200'}`}>
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-neutral-400">Forensic Investigation Tools</span>
                </div>
                <div className="space-y-1">
                  {forensicsItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = pathname === item.href;
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        onClick={closeMenus}
                        className={`flex items-start gap-3 p-2.5 rounded-xl transition-all group ${
                          isActive
                            ? isDark ? 'bg-[#282828] text-white border border-black' : 'bg-neutral-100 text-neutral-900 border border-neutral-300'
                            : isDark ? 'hover:bg-[#222222] text-neutral-300' : 'hover:bg-neutral-50 text-neutral-700'
                        }`}
                      >
                        <div className={`p-2 rounded-lg shrink-0 border ${isDark ? 'bg-[#242424] border-black text-white' : 'bg-neutral-100 border-neutral-200 text-neutral-800'}`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-1">
                            <span className="text-xs font-semibold">{item.title}</span>
                            {item.badge && (
                              <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-medium border ${
                                isDark ? 'bg-[#282828] text-neutral-300 border-black' : 'bg-neutral-100 text-neutral-600 border-neutral-300'
                              }`}>
                                {item.badge}
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-neutral-400 line-clamp-1 mt-0.5">{item.description}</p>
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Threat Intel Dropdown */}
          <div className="relative">
            <button
              onClick={() => setActiveDropdown(activeDropdown === 'intel' ? null : 'intel')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all ${
                pathname.startsWith('/attribution') || pathname.startsWith('/recommendations')
                  ? isDark ? 'bg-[#252525] text-white border border-black' : 'bg-neutral-100 text-neutral-900 border border-neutral-300'
                  : isDark ? 'hover:bg-[#252525] text-neutral-300' : 'hover:bg-neutral-100 text-neutral-700'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5" />
              Threat Intel
              <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${activeDropdown === 'intel' ? 'rotate-180' : ''}`} />
            </button>

            {activeDropdown === 'intel' && (
              <div
                className={`absolute top-full left-0 mt-3 w-80 rounded-2xl p-2 border backdrop-blur-2xl shadow-2xl transition-all ${
                  isDark ? 'bg-[#1a1a1a]/98 border-black shadow-black' : 'bg-white/98 border-neutral-300 shadow-neutral-900/15'
                }`}
              >
                <div className={`px-3 py-2 border-b mb-1 ${isDark ? 'border-neutral-800' : 'border-neutral-200'}`}>
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-neutral-400">Adversary Attribution & SOC</span>
                </div>
                <div className="space-y-1">
                  {threatIntelItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = pathname === item.href;
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        onClick={closeMenus}
                        className={`flex items-start gap-3 p-2.5 rounded-xl transition-all group ${
                          isActive
                            ? isDark ? 'bg-[#282828] text-white border border-black' : 'bg-neutral-100 text-neutral-900 border border-neutral-300'
                            : isDark ? 'hover:bg-[#222222] text-neutral-300' : 'hover:bg-neutral-50 text-neutral-700'
                        }`}
                      >
                        <div className={`p-2 rounded-lg shrink-0 border ${isDark ? 'bg-[#242424] border-black text-white' : 'bg-neutral-100 border-neutral-200 text-neutral-800'}`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-1">
                            <span className="text-xs font-semibold">{item.title}</span>
                            {item.badge && (
                              <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-medium border ${
                                isDark ? 'bg-[#282828] text-neutral-300 border-black' : 'bg-neutral-100 text-neutral-600 border-neutral-300'
                              }`}>
                                {item.badge}
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-neutral-400 line-clamp-1 mt-0.5">{item.description}</p>
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Engine API */}
          <Link
            href="/api-docs"
            onClick={closeMenus}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all ${
              pathname === '/api-docs'
                ? isDark ? 'bg-[#252525] text-white border border-black' : 'bg-neutral-100 text-neutral-900 border border-neutral-300'
                : isDark ? 'hover:bg-[#252525] text-neutral-300' : 'hover:bg-neutral-100 text-neutral-700'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            API & Docs
          </Link>
        </div>
        )}

        {/* Right Actions: Theme Toggle + Launch Dashboard */}
        <div className="flex items-center gap-2 sm:gap-3">
          <ThemeToggle />

          {!isLanding && (
            <>
              <Link
                href="/dashboard"
                onClick={closeMenus}
                className={`relative group inline-flex items-center gap-2 px-3.5 sm:px-4 py-1.5 sm:py-2 rounded-full font-medium text-xs transition-all duration-150 border ${
                  isDark
                    ? 'bg-white text-black border-black hover:bg-neutral-200 font-semibold shadow-md'
                    : 'bg-neutral-900 text-white border-neutral-900 hover:bg-neutral-800 font-semibold shadow-md'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" />
                <span className="font-semibold tracking-wide">Launch Dashboard</span>
              </Link>

              {/* Mobile menu trigger */}
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className={`lg:hidden p-2 rounded-full border ${
                  isDark ? 'bg-[#242424] border-black text-neutral-300' : 'bg-neutral-100 border-neutral-300 text-neutral-700'
                }`}
                aria-label="Toggle Navigation"
              >
                {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </button>
            </>
          )}
        </div>
      </nav>

      {/* Mobile Menu Overlay */}
      {!isLanding && mobileMenuOpen && (
        <div
          className={`lg:hidden pointer-events-auto mt-2 rounded-3xl p-4 border backdrop-blur-2xl shadow-2xl transition-all max-h-[80vh] overflow-y-auto ${
            isDark ? 'bg-[#181818]/98 border-black text-neutral-200' : 'bg-white/98 border-neutral-300 text-neutral-800 shadow-neutral-900/20'
          }`}
        >
          <div className="space-y-4">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-neutral-400 mb-2 px-2">Forensics Engine</div>
              <div className="space-y-1">
                {forensicsItems.map((item) => {
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={closeMenus}
                      className={`flex items-center gap-3 p-2 rounded-xl text-xs font-medium border ${
                        pathname === item.href
                          ? isDark ? 'bg-[#252525] text-white border-black' : 'bg-neutral-100 text-neutral-900 border-neutral-300'
                          : isDark ? 'hover:bg-[#222222] border-transparent' : 'hover:bg-neutral-100 border-transparent'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      <span>{item.title}</span>
                    </Link>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-neutral-400 mb-2 px-2">Threat Intel</div>
              <div className="space-y-1">
                {threatIntelItems.map((item) => {
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={closeMenus}
                      className={`flex items-center gap-3 p-2 rounded-xl text-xs font-medium border ${
                        pathname === item.href
                          ? isDark ? 'bg-[#252525] text-white border-black' : 'bg-neutral-100 text-neutral-900 border-neutral-300'
                          : isDark ? 'hover:bg-[#222222] border-transparent' : 'hover:bg-neutral-100 border-transparent'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      <span>{item.title}</span>
                    </Link>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-neutral-400 mb-2 px-2">Developer & API</div>
              <div className="space-y-1">
                <Link
                  href="/api-docs"
                  onClick={closeMenus}
                  className={`flex items-center gap-3 p-2 rounded-xl text-xs font-medium border ${
                    pathname === '/api-docs'
                      ? isDark ? 'bg-[#252525] text-white border-black' : 'bg-neutral-100 text-neutral-900 border-neutral-300'
                      : isDark ? 'hover:bg-[#222222] border-transparent' : 'hover:bg-neutral-100 border-transparent'
                  }`}
                >
                  <Code className="w-4 h-4" />
                  <span>AI Engine REST API</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
