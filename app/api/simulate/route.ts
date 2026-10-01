import { NextRequest, NextResponse } from 'next/server';
import { computeHmacSha256, hexToBase64 } from '@/lib/core/crypto';
import { toUnixTimestamp } from '@/lib/core/timestamp';
import { verifyWebhook, createVerificationDiagnostic } from '@/lib/adapters';
import { ProviderType } from '@/lib/core/types';

const SAMPLE_PAYLOADS: Record<ProviderType, Record<string, unknown>> = {
  github: {
    action: 'push',
    ref: 'refs/heads/main',
    repository: {
      id: 98765432,
      name: 'WebhookRadar',
      full_name: 'rocky24m/WebhookRadar',
      private: false,
    },
    sender: {
      login: 'rocky24m',
      id: 1234567,
    },
    head_commit: {
      id: '6bff4b5',
      message: 'feat(power): package reusable webhook-verifier Kiro power',
      timestamp: new Date().toISOString(),
    },
  },
  stripe: {
    id: 'evt_test_3O4P5Q2eZvKYlo2C1',
    object: 'event',
    api_version: '2023-10-16',
    created: toUnixTimestamp(Date.now()),
    type: 'payment_intent.succeeded',
    data: {
      object: {
        id: 'pi_3O4P5Q2eZvKYlo2C0',
        amount: 25000,
        currency: 'usd',
        status: 'succeeded',
        customer: 'cus_P92kL10mOp',
      },
    },
  },
  slack: {
    token: 'xoxb-verification-token',
    team_id: 'T012AB34C',
    api_app_id: 'A012BC34D',
    event: {
      type: 'app_mention',
      user: 'U012CD34E',
      text: '@WebhookRadar audit current endpoints for timing vulnerabilities',
      ts: (Date.now() / 1000).toFixed(6),
      channel: 'C012EF34G',
    },
    type: 'event_callback',
  },
  shopify: {
    id: 820982911946154500,
    topic: 'orders/create',
    domain: 'my-store.myshopify.com',
    current_total_price: '199.00',
    currency: 'USD',
    financial_status: 'paid',
    created_at: new Date().toISOString(),
    line_items: [
      {
        id: 1,
        title: 'WebhookRadar Pro Subscription',
        price: '199.00',
        quantity: 1,
      },
    ],
  },
};

const TEST_SECRETS: Record<ProviderType, string> = {
  github: 'gh_webhook_secret_demo_987654321',
  stripe: 'whsec_test_stripe_secret_1234567890abcdef',
  slack: 'slack_signing_secret_demo_abcdef123456',
  shopify: 'shpss_shopify_secret_demo_789012345678',
};

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const provider: ProviderType = body.provider || 'stripe';
    const scenario: 'valid' | 'tampered_signature' | 'replay_attack' | 'corrupted_payload' =
      body.scenario || 'valid';

    const secret = TEST_SECRETS[provider];
    let payloadObj = { ...SAMPLE_PAYLOADS[provider] };

    // If corrupted payload scenario, tamper with body after signature
    let payloadString = JSON.stringify(payloadObj, null, 2);
    const nowSeconds = toUnixTimestamp(Date.now());
    let timestamp = nowSeconds;

    if (scenario === 'replay_attack') {
      // Simulate an old webhook from 15 minutes ago (900 seconds)
      timestamp = nowSeconds - 900;
    }

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'user-agent': `WebhookRadar-Simulator/${provider}`,
    };

    // Construct valid signatures per provider
    if (provider === 'github') {
      const validSig = computeHmacSha256(secret, payloadString);
      headers['x-hub-signature-256'] =
        scenario === 'tampered_signature'
          ? `sha256=${validSig.slice(0, -4)}dead`
          : `sha256=${validSig}`;
    } else if (provider === 'stripe') {
      const signedPayload = `${timestamp}.${payloadString}`;
      const validSig = computeHmacSha256(secret, signedPayload);
      const sigToUse =
        scenario === 'tampered_signature'
          ? `${validSig.slice(0, -4)}beef`
          : validSig;
      headers['stripe-signature'] = `t=${timestamp},v1=${sigToUse}`;
    } else if (provider === 'slack') {
      const signedPayload = `v0:${timestamp}:${payloadString}`;
      const validSig = computeHmacSha256(secret, signedPayload);
      const sigToUse =
        scenario === 'tampered_signature'
          ? `v0=${validSig.slice(0, -4)}cafe`
          : `v0=${validSig}`;
      headers['x-slack-signature'] = sigToUse;
      headers['x-slack-request-timestamp'] = timestamp.toString();
    } else if (provider === 'shopify') {
      const validHexSig = computeHmacSha256(secret, payloadString);
      const validBase64 = hexToBase64(validHexSig);
      headers['x-shopify-hmac-sha256'] =
        scenario === 'tampered_signature'
          ? validBase64.replace(/^[A-Za-z0-9]/, 'Z')
          : validBase64;
      headers['x-shopify-webhook-timestamp'] = timestamp.toString();
    }

    if (scenario === 'corrupted_payload') {
      // Intentionally alter one character in the payload body after signature was generated
      payloadString = payloadString.replace('"private": false', '"private": true')
        .replace('"status": "succeeded"', '"status": "fraudulent"')
        .replace('"paid"', '"refunded"');
    }

    const startTime = performance.now();

    // Verify using our unified adapter
    const result = await verifyWebhook(provider, {
      headers,
      rawBody: Buffer.from(payloadString),
      secret,
    });

    const latencyMs = Number((performance.now() - startTime).toFixed(3));
    const diagnostic = createVerificationDiagnostic(result, {
      headers,
      rawBody: Buffer.from(payloadString),
      secret,
    });

    return NextResponse.json({
      scenario,
      provider,
      result,
      latencyMs,
      diagnostic,
      simulatedRequest: {
        headers,
        timestamp,
        bodySnippet: payloadString.slice(0, 300) + '...',
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to run simulation' },
      { status: 500 }
    );
  }
}
