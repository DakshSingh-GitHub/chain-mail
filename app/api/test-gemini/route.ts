import { NextRequest, NextResponse } from 'next/server';
import { testGeminiApiKey } from '@/lib/gemini-engine';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const apiKey = body.apiKey || req.headers.get('x-gemini-api-key') || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    const model = body.model || 'gemini-2.5-flash';

    if (!apiKey) {
      return NextResponse.json(
        {
          success: false,
          message: 'No API key provided. Please pass "apiKey" in request or configure GEMINI_API_KEY in environment.'
        },
        { status: 400 }
      );
    }

    const result = await testGeminiApiKey(apiKey, model);
    return NextResponse.json(result);
  } catch (error: unknown) {
    return NextResponse.json(
      {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to test Gemini API key'
      },
      { status: 500 }
    );
  }
}

