/**
 * Shopify Webhook Adapter
 * 
 * Implements Shopify's webhook signature verification with base64 decoding.
 * 
 * Shopify signature format:
 * - Header: X-Shopify-Hmac-SHA256
 * - Format: <base64-encoded-signature>
 * - Algorithm: HMAC-SHA256 over raw request body
 * - Encoding: Base64 (must convert to hex for comparison)
 * - Timestamp header: X-Shopify-Webhook-Timestamp (optional validation)
 * 
 * @see https://shopify.dev/docs/apps/webhooks/configuration/https#step-5-verify-the-webhook
 * @see .kiro/specs/webhook-verification-engine.md#req-provider-004
 */

import {
  computeHmacSha256,
  timingSafeVerify,
  base64ToHex,
} from '@/lib/core/crypto';
import { isTimestampValid } from '@/lib/core/timestamp';
import type {
  WebhookVerificationRequest,
  WebhookVerificationResult,
} from '@/lib/core/types';

/**
 * Verifies Shopify webhook signature with optional timestamp validation
 * 
 * Shopify webhooks include X-Shopify-Hmac-SHA256 header with base64-encoded signature.
 * The signature is computed over the raw request body using HMAC-SHA256.
 * 
 * Optionally validates X-Shopify-Webhook-Timestamp if present.
 * 
 * @param request - Webhook verification request containing headers, rawBody, and secret
 * @param toleranceSeconds - Maximum allowed timestamp age (default: 300 seconds)
 * @returns Verification result with success status and diagnostic information
 * 
 * @example
 * ```typescript
 * const request = {
 *   headers: {
 *     'x-shopify-hmac-sha256': 'YWJjMTIz...', // base64 encoded
 *     'x-shopify-webhook-timestamp': '1609459200' // optional
 *   },
 *   rawBody: Buffer.from('{"id":123}'),
 *   secret: process.env.SHOPIFY_WEBHOOK_SECRET!
 * };
 * 
 * const result = verifyShopifyWebhook(request, 300);
 * if (result.valid) {
 *   // Process webhook
 * }
 * ```
 */
export function verifyShopifyWebhook(
  request: WebhookVerificationRequest,
  toleranceSeconds: number = 300
): WebhookVerificationResult {
  const signatureHeader = getHeader(request.headers, 'x-shopify-hmac-sha256');
  const timestampHeader = getHeader(request.headers, 'x-shopify-webhook-timestamp');
  
  // 1. Check if signature header is present
  if (!signatureHeader) {
    return {
      valid: false,
      provider: 'shopify',
      reason: 'Missing x-shopify-hmac-sha256 header',
    };
  }
  
  // 2. Optional: Validate timestamp if present
  let timestampDrift: number | undefined;
  
  if (timestampHeader) {
    const timestamp = parseInt(timestampHeader, 10);
    
    if (!isNaN(timestamp)) {
      const currentTime = Math.floor(Date.now() / 1000);
      const timestampValidation = isTimestampValid(
        timestamp,
        currentTime,
        toleranceSeconds
      );
      
      if (!timestampValidation.valid) {
        return {
          valid: false,
          provider: 'shopify',
          reason: timestampValidation.reason || 'Timestamp validation failed',
          timestampDrift: timestampValidation.driftSeconds,
        };
      }
      
      timestampDrift = timestampValidation.driftSeconds;
    }
  }
  
  // 3. Convert base64 signature to hex for comparison
  const receivedSignatureHex = base64ToHex(signatureHeader);
  
  if (!receivedSignatureHex) {
    return {
      valid: false,
      provider: 'shopify',
      reason: 'Invalid base64 signature format',
      timestampDrift,
    };
  }
  
  // 4. Ensure rawBody is a Buffer for consistent signature computation
  const payload = Buffer.isBuffer(request.rawBody)
    ? request.rawBody
    : Buffer.from(request.rawBody);
  
  // 5. Compute expected signature using pure function
  const expectedSignature = computeHmacSha256(request.secret, payload);
  
  // 6. Timing-safe comparison
  const isValid = timingSafeVerify(expectedSignature, receivedSignatureHex);
  
  if (!isValid) {
    return {
      valid: false,
      provider: 'shopify',
      reason: 'Signature verification failed',
      timestampDrift,
    };
  }
  
  // 7. Success
  return {
    valid: true,
    provider: 'shopify',
    timestampDrift,
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
