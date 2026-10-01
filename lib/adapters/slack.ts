/**
 * Slack Webhook Adapter
 * 
 * Implements Slack's request signing verification with timestamp validation.
 * 
 * Slack signature format:
 * - Headers: X-Slack-Signature, X-Slack-Request-Timestamp
 * - Signature Format: v0=<hex-signature>
 * - Algorithm: HMAC-SHA256 over "v0:${timestamp}:${rawBody}"
 * - Timestamp validation: Required (prevents replay attacks)
 * 
 * @see https://api.slack.com/authentication/verifying-requests-from-slack
 * @see .kiro/specs/webhook-verification-engine.md#req-provider-003
 */

import { computeHmacSha256, timingSafeVerify } from '@/lib/core/crypto';
import { isTimestampValid } from '@/lib/core/timestamp';
import type {
  WebhookVerificationRequest,
  WebhookVerificationResult,
} from '@/lib/core/types';

/**
 * Verifies Slack webhook signature with timestamp validation
 * 
 * Slack webhooks include two headers:
 * - X-Slack-Signature: v0=<signature>
 * - X-Slack-Request-Timestamp: <unix-timestamp>
 * 
 * The signature is computed over the versioned payload: "v0:${timestamp}:${rawBody}"
 * 
 * @param request - Webhook verification request containing headers, rawBody, and secret
 * @param toleranceSeconds - Maximum allowed timestamp age (default: 300 seconds)
 * @returns Verification result with success status and diagnostic information
 * 
 * @example
 * ```typescript
 * const request = {
 *   headers: {
 *     'x-slack-signature': 'v0=abc123...',
 *     'x-slack-request-timestamp': '1609459200'
 *   },
 *   rawBody: Buffer.from('{"type":"url_verification"}'),
 *   secret: process.env.SLACK_SIGNING_SECRET!
 * };
 * 
 * const result = verifySlackWebhook(request, 300);
 * if (result.valid) {
 *   // Process webhook
 * }
 * ```
 */
export function verifySlackWebhook(
  request: WebhookVerificationRequest,
  toleranceSeconds: number = 300
): WebhookVerificationResult {
  const signatureHeader = getHeader(request.headers, 'x-slack-signature');
  const timestampHeader = getHeader(request.headers, 'x-slack-request-timestamp');
  
  // 1. Check if signature header is present
  if (!signatureHeader) {
    return {
      valid: false,
      provider: 'slack',
      reason: 'Missing x-slack-signature header',
    };
  }
  
  // 2. Check if timestamp header is present
  if (!timestampHeader) {
    return {
      valid: false,
      provider: 'slack',
      reason: 'Missing x-slack-request-timestamp header',
    };
  }
  
  // 3. Parse timestamp
  const timestamp = parseInt(timestampHeader, 10);
  if (isNaN(timestamp)) {
    return {
      valid: false,
      provider: 'slack',
      reason: 'Invalid timestamp format',
    };
  }
  
  // 4. Validate timestamp to prevent replay attacks
  const currentTime = Math.floor(Date.now() / 1000);
  const timestampValidation = isTimestampValid(
    timestamp,
    currentTime,
    toleranceSeconds
  );
  
  if (!timestampValidation.valid) {
    return {
      valid: false,
      provider: 'slack',
      reason: timestampValidation.reason || 'Timestamp validation failed',
      timestampDrift: timestampValidation.driftSeconds,
    };
  }
  
  // 5. Extract signature (remove 'v0=' prefix)
  if (!signatureHeader.startsWith('v0=')) {
    return {
      valid: false,
      provider: 'slack',
      reason: 'Invalid signature format (expected v0= prefix)',
    };
  }
  
  const receivedSignature = signatureHeader.slice(3); // Remove 'v0=' prefix
  
  // 6. Ensure rawBody is a string for Slack's signed payload format
  const bodyString = Buffer.isBuffer(request.rawBody)
    ? request.rawBody.toString('utf8')
    : request.rawBody;
  
  // 7. Construct versioned signed payload: "v0:${timestamp}:${body}"
  const signedPayload = `v0:${timestamp}:${bodyString}`;
  
  // 8. Compute expected signature
  const expectedSignature = computeHmacSha256(request.secret, signedPayload);
  
  // 9. Timing-safe comparison
  const isValid = timingSafeVerify(expectedSignature, receivedSignature);
  
  if (!isValid) {
    return {
      valid: false,
      provider: 'slack',
      reason: 'Signature verification failed',
      timestampDrift: timestampValidation.driftSeconds,
    };
  }
  
  // 10. Success
  return {
    valid: true,
    provider: 'slack',
    timestampDrift: timestampValidation.driftSeconds,
  };
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
