import { NextRequest, NextResponse } from 'next/server';
import { analyzeEmailThreat } from '@/lib/forensic-engine';
import { analyzeEmailWithGemini } from '@/lib/gemini-engine';
import { EmailAnalysisInput } from '@/lib/types';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    
    if (!body || (!body.raw_headers && !body.email_body)) {
      return NextResponse.json(
        {
          error: 'Bad Request',
          message: 'Missing required payload. Please provide "raw_headers" and "email_body".'
        },
        { status: 400 }
      );
    }

    const input: EmailAnalysisInput = {
      raw_headers: body.raw_headers || '',
      email_body: body.email_body || '',
      metadata: body.metadata || {}
    };

    // Determine if user wants AI analysis or explicit engine mode
    const requestedMode = body.engine_mode || req.headers.get('x-engine-mode') || 'auto'; // 'ai' | 'heuristic' | 'auto'
    const envApiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    const model = body.model || 'gemini-2.5-flash';

    let report;
    let usedAi = false;
    let aiError: string | null = null;

    if (requestedMode !== 'heuristic' && envApiKey) {
      try {
        report = await analyzeEmailWithGemini(input, envApiKey, model);
        usedAi = true;
      } catch (err: unknown) {
        console.warn('Gemini AI analysis failed, falling back to deterministic heuristic engine:', err);
        aiError = err instanceof Error ? err.message : 'Unknown AI engine error';
        report = analyzeEmailThreat(input);
        report.engine_mode = 'heuristic-offline';
      }
    } else {
      report = analyzeEmailThreat(input);
      report.engine_mode = 'heuristic-offline';
    }

    return NextResponse.json({
      ...report,
      _meta: {
        engine_mode: usedAi ? 'ai-gemini' : 'heuristic-offline',
        model_name: usedAi ? model : 'Deterministic Heuristics Engine',
        ai_error: aiError,
        has_api_key_configured: Boolean(envApiKey)
      }
    });
  } catch (error: unknown) {
    console.error('Forensic Analysis Error:', error);
    return NextResponse.json(
      {
        error: 'Internal Server Error',
        message: error instanceof Error ? error.message : 'An error occurred while executing the forensic engine.'
      },
      { status: 500 }
    );
  }
}


