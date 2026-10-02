import { NextRequest, NextResponse } from 'next/server';
import { verifyWebhook, createVerificationDiagnostic } from '@/lib/adapters';
import { ProviderType } from '@/lib/core/types';

// Default test secrets for demonstration and simulation
const DEFAULT_TEST_SECRETS: Record<ProviderType, string> = {
  github: process.env.GITHUB_WEBHOOK_SECRET || 'gh_webhook_secret_demo_987654321',
  stripe: process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_stripe_secret_1234567890abcdef',
  slack: process.env.SLACK_SIGNING_SECRET || 'slack_signing_secret_demo_abcdef123456',
  shopify: process.env.SHOPIFY_WEBHOOK_SECRET || 'shpss_shopify_secret_demo_789012345678',
};

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ provider: string }> }
) {
  try {
    const { provider } = await context.params;
    const providerLower = provider.toLowerCase() as ProviderType;

    const validProviders: ProviderType[] = ['github', 'stripe', 'slack', 'shopify'];
    if (!validProviders.includes(providerLower)) {
      return NextResponse.json(
        {
          valid: false,
          error: `Unsupported provider: ${provider}. Supported providers are: ${validProviders.join(', ')}`,
        },
        { status: 400 }
      );
    }

    // Convert Next.js headers to a record
    const headersRecord: Record<string, string | string[] | undefined> = {};
    request.headers.forEach((value, key) => {
      headersRecord[key.toLowerCase()] = value;
    });

    // Read the raw body as Buffer
    const arrayBuffer = await request.arrayBuffer();
    const rawBody = Buffer.from(arrayBuffer);

    // Get secret from custom header or fallback to environment/default test secret
    const customSecret = request.headers.get('x-webhookradar-secret');
    const secret = customSecret || DEFAULT_TEST_SECRETS[providerLower];

    // Optional custom tolerance from header
    const customTolerance = request.headers.get('x-timestamp-tolerance');
    const toleranceSeconds = customTolerance ? parseInt(customTolerance, 10) : 300;

    const startTime = performance.now();

    // Verify webhook using unified adapter
    const result = await verifyWebhook(
      providerLower,
      {
        headers: headersRecord,
        rawBody,
        secret,
      },
      toleranceSeconds
    );

    const latencyMs = Number((performance.now() - startTime).toFixed(3));

    // Create sanitized diagnostic object (zero secrets exposed)
    const diagnostic = createVerificationDiagnostic(result, {
      headers: headersRecord,
      rawBody,
      secret,
    });

    const statusCode = !result.valid
      ? (result.reason?.toLowerCase().includes('missing') || result.reason?.toLowerCase().includes('replay') || result.reason?.toLowerCase().includes('timestamp') ? 400 : 401)
      : 200;

    // Log to SQLite security audit ledger
    try {
      const { logWebhookToDb } = await import('@/lib/db');
      logWebhookToDb({
        id: `evt_${Date.now()}_${Math.random().toString(36).substring(7)}`,
        provider: providerLower,
        scenario: 'live_ingress',
        valid: result.valid,
        statusCode,
        latencyMs,
        timestampDrift: result.timestampDrift,
        reason: result.reason,
        headersJson: JSON.stringify(headersRecord),
        payloadSnippet: rawBody.toString('utf-8').slice(0, 300),
      });
    } catch (e) {
      // Non-blocking logging
    }

    if (!result.valid) {
      return NextResponse.json(
        {
          ...result,
          latencyMs,
          diagnostic,
        },
        { status: statusCode }
      );
    }

    return NextResponse.json({
      ...result,
      latencyMs,
      diagnostic,
      receivedBytes: rawBody.length,
    });
  } catch (error) {
    return NextResponse.json(
      {
        valid: false,
        error: 'Internal server error during webhook verification',
      },
      { status: 500 }
    );
  }
}
