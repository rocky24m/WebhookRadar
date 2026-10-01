/**
 * GitHub Webhook Adapter
 * 
 * Implements GitHub's webhook signature verification using HMAC-SHA256.
 * 
 * GitHub signature format:
 * - Header: X-Hub-Signature-256
 * - Format: sha256=<64-character-hex-signature>
 * - Algorithm: HMAC-SHA256 over raw request body
 * - No timestamp validation (GitHub doesn't provide webhook timestamps)
 * 
 * @see https://docs.github.com/en/webhooks/securing-your-webhooks
 * @see .kiro/specs/webhook-verification-engine.md#req-provider-001
 */

import { computeHmacSha256, timingSafeVerify } from '@/lib/core/crypto';
import type {
  WebhookVerificationRequest,
  WebhookVerificationResult,
} from '@/lib/core/types';

/**
 * Verifies GitHub webhook signature
 * 
 * GitHub webhooks include X-Hub-Signature-256 header with format: sha256=<signature>
 * The signature is computed over the raw request body using HMAC-SHA256.
 * 
 * @param request - Webhook verification request containing headers, rawBody, and secret
 * @returns Verification result with success status and diagnostic information
 * 
 * @example
 * ```typescript
 * const request = {
 *   headers: { 'x-hub-signature-256': 'sha256=abc123...' },
 *   rawBody: Buffer.from('{"action":"opened"}'),
 *   secret: process.env.GITHUB_WEBHOOK_SECRET!
 * };
 * 
 * const result = verifyGitHubWebhook(request);
 * if (result.valid) {
 *   // Process webhook
 * }
 * ```
 */
export function verifyGitHubWebhook(
  request: WebhookVerificationRequest
): WebhookVerificationResult {
  const signatureHeader = getHeader(request.headers, 'x-hub-signature-256');
  
  // 1. Check if signature header is present
  if (!signatureHeader) {
    return {
      valid: false,
      provider: 'github',
      reason: 'Missing x-hub-signature-256 header',
    };
  }
  
  // 2. Extract signature (remove 'sha256=' prefix)
  if (!signatureHeader.startsWith('sha256=')) {
    return {
      valid: false,
      provider: 'github',
      reason: 'Invalid signature format (expected sha256= prefix)',
    };
  }
  
  const receivedSignature = signatureHeader.slice(7); // Remove 'sha256=' prefix
  
  // 3. Ensure rawBody is a Buffer for consistent signature computation
  const payload = Buffer.isBuffer(request.rawBody)
    ? request.rawBody
    : Buffer.from(request.rawBody);
  
  // 4. Compute expected signature using pure function
  const expectedSignature = computeHmacSha256(request.secret, payload);
  
  // 5. Timing-safe comparison
  const isValid = timingSafeVerify(expectedSignature, receivedSignature);
  
  if (!isValid) {
    return {
      valid: false,
      provider: 'github',
      reason: 'Signature verification failed',
    };
  }
  
  // 6. Success
  return {
    valid: true,
    provider: 'github',
  };
}

/**
 * Helper to extract header value (case-insensitive)
 * 
 * HTTP headers are case-insensitive, so we need to search for the header
 * regardless of casing used by the client.
 */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const lowerName = name.toLowerCase();
  
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName) {
      // Handle string array (multiple values)
      if (Array.isArray(value)) {
        return value[0]; // Return first value
      }
      return value;
    }
  }
  
  return undefined;
}
