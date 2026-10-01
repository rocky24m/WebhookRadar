/**
 * Unified Webhook Verification Dispatcher
 * 
 * This module provides a single entry point for verifying webhooks from
 * multiple providers (GitHub, Stripe, Slack, Shopify).
 * 
 * The dispatcher automatically routes to the appropriate provider-specific
 * adapter based on the provider type, handling errors and edge cases gracefully.
 * 
 * @see .kiro/specs/webhook-verification-engine.md#phase-3-provider-adapters
 */

import { verifyGitHubWebhook } from './github';
import { verifyStripeWebhook } from './stripe';
import { verifySlackWebhook } from './slack';
import { verifyShopifyWebhook } from './shopify';
import { redactSensitiveString } from '@/lib/core/crypto';
import type {
  ProviderType,
  WebhookVerificationRequest,
  WebhookVerificationResult,
  VerificationDiagnostic,
} from '@/lib/core/types';

/**
 * Verifies webhook signature for any supported provider
 * 
 * This is the main entry point for webhook verification. It dispatches to the
 * appropriate provider-specific adapter and handles errors gracefully.
 * 
 * @param provider - The webhook provider type ('github' | 'stripe' | 'slack' | 'shopify')
 * @param request - Webhook verification request containing headers, rawBody, and secret
 * @param toleranceSeconds - Maximum allowed timestamp age for providers that validate timestamps
 * @returns Verification result with success status and diagnostic information
 * 
 * @example
 * ```typescript
 * // GitHub webhook verification
 * const githubResult = await verifyWebhook('github', {
 *   headers: { 'x-hub-signature-256': 'sha256=abc...' },
 *   rawBody: Buffer.from('{"action":"opened"}'),
 *   secret: process.env.GITHUB_WEBHOOK_SECRET!
 * });
 * 
 * // Stripe webhook verification with custom tolerance
 * const stripeResult = await verifyWebhook('stripe', {
 *   headers: { 'stripe-signature': 't=1609459200,v1=abc...' },
 *   rawBody: Buffer.from('{"type":"payment_intent.succeeded"}'),
 *   secret: process.env.STRIPE_WEBHOOK_SECRET!
 * }, 600); // 10 minutes tolerance
 * ```
 */
export async function verifyWebhook(
  provider: ProviderType,
  request: WebhookVerificationRequest,
  toleranceSeconds?: number
): Promise<WebhookVerificationResult> {
  try {
    // Validate request structure
    if (!request.headers || !request.rawBody || !request.secret) {
      return {
        valid: false,
        provider,
        reason: 'Invalid request: missing required fields (headers, rawBody, or secret)',
      };
    }
    
    // Dispatch to appropriate provider adapter
    switch (provider) {
      case 'github':
        return verifyGitHubWebhook(request);
      
      case 'stripe':
        return verifyStripeWebhook(request, toleranceSeconds);
      
      case 'slack':
        return verifySlackWebhook(request, toleranceSeconds);
      
      case 'shopify':
        return verifyShopifyWebhook(request, toleranceSeconds);
      
      default:
        // This should never happen with proper TypeScript typing,
        // but handle it gracefully for runtime safety
        return {
          valid: false,
          provider: provider as ProviderType,
          reason: `Unknown provider: ${provider}`,
        };
    }
  } catch (error) {
    // Catch any unexpected errors and return sanitized error message
    // Never expose internal error details that could leak sensitive information
    return {
      valid: false,
      provider,
      reason: 'Internal verification error',
    };
  }
}

/**
 * Creates a sanitized verification diagnostic for logging
 * 
 * This function constructs a diagnostic object suitable for logging that
 * contains useful debugging information while redacting all sensitive data.
 * 
 * @param result - Verification result from verifyWebhook
 * @param request - Original verification request (will be sanitized)
 * @returns Diagnostic object with redacted sensitive data
 * 
 * @example
 * ```typescript
 * const result = await verifyWebhook('github', request);
 * const diagnostic = createVerificationDiagnostic(result, request);
 * 
 * console.log(diagnostic);
 * // {
 * //   provider: 'github',
 * //   checkedAt: '2026-10-01T14:00:00.000Z',
 * //   status: 'SUCCESS',
 * //   sanitizedDetails: {
 * //     hasSignatureHeader: true,
 * //     payloadSize: 1234,
 * //     secretPrefix: 'whsec_12...ab'
 * //   }
 * // }
 * ```
 */
export function createVerificationDiagnostic(
  result: WebhookVerificationResult,
  request: WebhookVerificationRequest
): VerificationDiagnostic {
  // Determine which headers are present (without exposing values)
  const headerKeys = Object.keys(request.headers).map(k => k.toLowerCase());
  
  // Get payload size for diagnostics
  const payloadSize = Buffer.isBuffer(request.rawBody)
    ? request.rawBody.length
    : Buffer.byteLength(request.rawBody, 'utf8');
  
  return {
    provider: result.provider,
    checkedAt: new Date().toISOString(),
    status: result.valid ? 'SUCCESS' : 'FAILED',
    sanitizedDetails: {
      // Include non-sensitive diagnostic information
      headerKeys, // List of headers present (no values)
      payloadSize, // Size in bytes
      secretPrefix: redactSensitiveString(request.secret), // Redacted secret
      timestampDrift: result.timestampDrift, // Drift is not sensitive
      failureReason: result.reason, // Generic failure reason (no secrets)
    },
  };
}

/**
 * Re-export provider-specific adapters for direct use
 * 
 * These can be imported directly when you know the provider type at compile time:
 * 
 * import { verifyGitHubWebhook } from '@/lib/adapters';
 */
export {
  verifyGitHubWebhook,
  verifyStripeWebhook,
  verifySlackWebhook,
  verifyShopifyWebhook,
};

/**
 * Re-export types for convenience
 */
export type {
  ProviderType,
  WebhookVerificationRequest,
  WebhookVerificationResult,
  VerificationDiagnostic,
} from '@/lib/core/types';
