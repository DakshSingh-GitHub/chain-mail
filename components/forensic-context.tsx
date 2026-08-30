'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { EmailAnalysisInput, ForensicReport } from '@/lib/types';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { PRESET_SCENARIOS } from '@/lib/presets';

export interface ActiveEmailMeta {
  id: string;
  subject: string;
  senderName: string;
  senderEmail: string;
  isUploaded: boolean;
  fileName?: string;
  engineMode?: 'ai-gemini' | 'heuristic-offline';
  modelName?: string;
  latencyMs?: number;
  date?: string;
}

interface ForensicContextType {
  activeInput: EmailAnalysisInput;
  activeReport: ForensicReport;
  activeMeta: ActiveEmailMeta;
  isUploaded: boolean;
  setActiveEmail: (
    input: EmailAnalysisInput,
    report?: ForensicReport,
    meta?: Partial<ActiveEmailMeta>
  ) => void;
  resetToPreset: (presetId: string) => void;
}

const STORAGE_KEY = 'chainmail_active_forensic_session';

const defaultScenario = PRESET_SCENARIOS[0];
const defaultInitialReport = analyzeEmailThreat(defaultScenario.input);

const ForensicContext = createContext<ForensicContextType | undefined>(undefined);

export function ForensicProvider({ children }: { children: React.ReactNode }) {
  const [activeInput, setActiveInput] = useState<EmailAnalysisInput>(defaultScenario.input);
  const [activeReport, setActiveReport] = useState<ForensicReport>(defaultInitialReport);
  const [activeMeta, setActiveMeta] = useState<ActiveEmailMeta>({
    id: defaultScenario.id,
    subject: defaultScenario.name,
    senderName: 'Marcus Vance (CEO)',
    senderEmail: 'marcus.vance@acmecorp-globaI.com',
    isUploaded: false,
    engineMode: 'heuristic-offline',
    modelName: 'Gemini 2.5 Flash',
    date: new Date().toISOString()
  });

  // Load persisted session on initial mount
  useEffect(() => {
    try {
      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.input && parsed.report && parsed.meta) {
            setActiveInput(parsed.input);
            setActiveReport(parsed.report);
            setActiveMeta(parsed.meta);
          }
        }
      }
    } catch (err) {
      console.warn('Could not restore forensic session from storage:', err);
    }
  }, []);

  // Setter for active email payload
  const setActiveEmail = useCallback(
    (
      input: EmailAnalysisInput,
      report?: ForensicReport,
      meta?: Partial<ActiveEmailMeta>
    ) => {
      const computedReport = report || analyzeEmailThreat(input);
      const subjectMatch = input.raw_headers.match(/Subject:\s*([^\r\n]+)/i);
      const fromMatch = input.raw_headers.match(/From:\s*"?([^"<]+)"?\s*<([^>]+)>/i);

      const updatedMeta: ActiveEmailMeta = {
        id: meta?.id || `INC-${Date.now().toString().slice(-6)}`,
        subject: meta?.subject || subjectMatch?.[1] || 'Target Email Payload',
        senderName: meta?.senderName || fromMatch?.[1] || 'External Sender',
        senderEmail: meta?.senderEmail || fromMatch?.[2] || 'sender@external.net',
        isUploaded: meta?.isUploaded ?? false,
        fileName: meta?.fileName,
        engineMode: computedReport.engine_mode || meta?.engineMode || 'heuristic-offline',
        modelName: computedReport.model_name || meta?.modelName || 'Gemini 2.5 Flash',
        latencyMs: computedReport.analysis_latency_ms || meta?.latencyMs,
        date: meta?.date || new Date().toISOString()
      };

      setActiveInput(input);
      setActiveReport(computedReport);
      setActiveMeta(updatedMeta);

      try {
        if (typeof window !== 'undefined') {
          localStorage.setItem(
            STORAGE_KEY,
            JSON.stringify({
              input,
              report: computedReport,
              meta: updatedMeta
            })
          );
          window.dispatchEvent(new CustomEvent('chainmail_forensic_session_updated'));
        }
      } catch (err) {
        console.warn('Failed to persist forensic session:', err);
      }
    },
    []
  );

  const resetToPreset = useCallback((presetId: string) => {
    const target = PRESET_SCENARIOS.find((p) => p.id === presetId) || defaultScenario;
    const computed = analyzeEmailThreat(target.input);
    const subjectMatch = target.input.raw_headers.match(/Subject:\s*([^\r\n]+)/i);
    const fromMatch = target.input.raw_headers.match(/From:\s*"?([^"<]+)"?\s*<([^>]+)>/i);

    const meta: ActiveEmailMeta = {
      id: target.id,
      subject: target.name,
      senderName: fromMatch?.[1] || 'Sender',
      senderEmail: fromMatch?.[2] || 'sender@domain.com',
      isUploaded: false,
      engineMode: 'heuristic-offline',
      modelName: 'Gemini 2.5 Flash',
      date: new Date().toISOString()
    };

    setActiveInput(target.input);
    setActiveReport(computed);
    setActiveMeta(meta);

    try {
      if (typeof window !== 'undefined') {
        localStorage.setItem(
          STORAGE_KEY,
          JSON.stringify({
            input: target.input,
            report: computed,
            meta
          })
        );
        window.dispatchEvent(new CustomEvent('chainmail_forensic_session_updated'));
      }
    } catch (err) {
      console.warn('Failed to persist reset preset:', err);
    }
  }, []);

  return (
    <ForensicContext.Provider
      value={{
        activeInput,
        activeReport,
        activeMeta,
        isUploaded: activeMeta.isUploaded,
        setActiveEmail,
        resetToPreset
      }}
    >
      {children}
    </ForensicContext.Provider>
  );
}

export function useForensicSession() {
  const context = useContext(ForensicContext);
  if (!context) {
    throw new Error('useForensicSession must be used within a ForensicProvider');
  }
  return context;
}
