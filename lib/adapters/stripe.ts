/**
 * Stripe Webhook Adapter
 * 
 * Implements Stripe's webhook signature verification with timestamp validation.
 * 
 * Stripe signature format:
 * - Header: Stripe-Signature
 * - Format: t=<timestamp>,v1=<signature>,v1=<signature>...
 * - Algorithm: HMAC-SHA256 over "${timestamp}.${rawBody}"
 * - Timestamp validation: Required (prevents replay attacks)
 * 
 * Stripe can send multiple v1 signatures (for key rotation).
 * We must verify against at least one of them.
 * 
 * @see https://stripe.com/docs/webhooks/signatures
 * @see .kiro/specs/webhook-verification-engine.md#req-provider-002
 */

import { computeHmacSha256, timingSafeVerify } from '@/lib/core/crypto';
import { isTimestampValid, toUnixTimestamp } from '@/lib/core/timestamp';
import type {
  WebhookVerificationRequest,
  WebhookVerificationResult,
} from '@/lib/core/types';

/**
 * Parsed Stripe signature header components
 */
interface StripeSignatureComponents {
  timestamp: number;
  signatures: string[];
}

/**
 * Verifies Stripe webhook signature with timestamp validation
 * 
 * Stripe webhooks include a Stripe-Signature header with format:
 * t=<timestamp>,v1=<signature1>,v1=<signature2>
 * 
 * The signature is computed over the signed payload: "${timestamp}.${rawBody}"
 * 
 * @param request - Webhook verification request containing headers, rawBody, and secret
 * @param toleranceSeconds - Maximum allowed timestamp age (default: 300 seconds)
 * @returns Verification result with success status and diagnostic information
 * 
 * @example
 * ```typescript
 * const request = {
 *   headers: { 'stripe-signature': 't=1609459200,v1=abc123...' },
 *   rawBody: Buffer.from('{"type":"payment_intent.succeeded"}'),
 *   secret: process.env.STRIPE_WEBHOOK_SECRET!
 * };
 * 
 * const result = verifyStripeWebhook(request, 300);
 * if (result.valid) {
 *   // Process webhook
 * }
 * ```
 */
export function verifyStripeWebhook(
  request: WebhookVerificationRequest,
  toleranceSeconds: number = 300
): WebhookVerificationResult {
  const signatureHeader = getHeader(request.headers, 'stripe-signature');
  
  // 1. Check if signature header is present
  if (!signatureHeader) {
    return {
      valid: false,
      provider: 'stripe',
      reason: 'Missing stripe-signature header',
    };
  }
  
  // 2. Parse signature components
  let components: StripeSignatureComponents;
  try {
    components = parseStripeSignature(signatureHeader);
  } catch (error) {
    return {
      valid: false,
      provider: 'stripe',
      reason: 'Invalid signature header format',
    };
  }
  
  // 3. Validate timestamp to prevent replay attacks
  const currentTime = toUnixTimestamp(Date.now());
  const timestampValidation = isTimestampValid(
    components.timestamp,
    currentTime,
    toleranceSeconds
  );
  
  if (!timestampValidation.valid) {
    return {
      valid: false,
      provider: 'stripe',
      reason: timestampValidation.reason || 'Timestamp validation failed',
      timestampDrift: timestampValidation.driftSeconds,
    };
  }
  
  // 4. Ensure rawBody is a string for Stripe's signed payload format
  const bodyString = Buffer.isBuffer(request.rawBody)
    ? request.rawBody.toString('utf8')
    : request.rawBody;
  
  // 5. Construct signed payload: "${timestamp}.${body}"
  const signedPayload = `${components.timestamp}.${bodyString}`;
  
  // 6. Compute expected signature
  const expectedSignature = computeHmacSha256(request.secret, signedPayload);
  
  // 7. Verify against at least one provided signature (timing-safe)
  const isValid = components.signatures.some((receivedSignature) => {
    return timingSafeVerify(expectedSignature, receivedSignature);
  });
  
  if (!isValid) {
    return {
      valid: false,
      provider: 'stripe',
      reason: 'Signature verification failed',
      timestampDrift: timestampValidation.driftSeconds,
    };
  }
  
  // 8. Success
  return {
    valid: true,
    provider: 'stripe',
    timestampDrift: timestampValidation.driftSeconds,
  };
}

/**
 * Parses Stripe signature header into components
 * 
 * Format: t=<timestamp>,v1=<sig1>,v1=<sig2>,...
 * 
 * @param header - Stripe-Signature header value
 * @returns Parsed timestamp and signature array
 * @throws Error if header format is invalid
 */
function parseStripeSignature(header: string): StripeSignatureComponents {
  const pairs = header.split(',').map(pair => pair.trim());
  
  let timestamp: number | undefined;
  const signatures: string[] = [];
  
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    
    if (!key || !value) {
      throw new Error('Invalid key=value pair in signature header');
    }
    
    if (key === 't') {
      timestamp = parseInt(value, 10);
      if (isNaN(timestamp)) {
        throw new Error('Invalid timestamp format');
      }
    } else if (key.startsWith('v')) {
      // v1, v2, etc. (Stripe uses v1 currently)
      signatures.push(value);
    }
  }
  
  if (timestamp === undefined) {
    throw new Error('Missing timestamp (t=) in signature header');
  }
  
  if (signatures.length === 0) {
    throw new Error('Missing signature (v1=) in signature header');
  }
  
  return { timestamp, signatures };
}

/**
 * Helper to extract header value (case-insensitive)
 */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const lowerName = name.toLowerCase();
  
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName) {
      if (Array.isArray(value)) {
        return value[0];
      }
      return value;
    }
  }
  
  return undefined;
}
