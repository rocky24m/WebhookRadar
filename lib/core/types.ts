/**
 * Core Type Definitions for WebhookRadar
 * 
 * These types define the contracts for the functional core verification pipeline.
 * All types are immutable and designed for pure functional operations.
 */

/**
 * Supported webhook providers
 */
export type ProviderType = 'github' | 'stripe' | 'slack' | 'shopify';

/**
 * Webhook verification request containing raw payload and headers
 * 
 * @property headers - HTTP headers from the incoming webhook request
 * @property rawBody - Raw request body as Buffer or string (preserved for signature verification)
 * @property secret - Provider-specific webhook secret for HMAC verification
 */
export interface WebhookVerificationRequest {
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer | string;
  secret: string;
}

/**
 * Result of webhook verification process
 * 
 * @property valid - Whether the webhook signature and timestamp verification succeeded
 * @property provider - The webhook provider type
 * @property reason - Human-readable reason for failure (generic, no sensitive data exposed)
 * @property timestampDrift - Time difference in seconds between webhook timestamp and server time (for diagnostics)
 */
export interface WebhookVerificationResult {
  valid: boolean;
  provider: ProviderType;
  reason?: string;
  timestampDrift?: number;
}

/**
 * Result of timestamp validation with diagnostic information
 * 
 * @property valid - Whether the timestamp is within acceptable tolerance
 * @property driftSeconds - Absolute time difference in seconds from current server time
 * @property reason - Specific reason for failure (e.g., "Timestamp too old", "Timestamp in future")
 */
export interface TimestampValidationResult {
  valid: boolean;
  driftSeconds: number;
  reason?: string;
}

/**
 * Diagnostic information for verification attempts
 * All sensitive data must be redacted before populating this structure
 * 
 * @property provider - Provider name for routing and analytics
 * @property checkedAt - ISO 8601 timestamp when verification was performed
 * @property status - Verification outcome status
 * @property sanitizedDetails - Additional diagnostic data (all secrets/signatures redacted)
 */
export interface VerificationDiagnostic {
  provider: ProviderType;
  checkedAt: string;
  status: 'SUCCESS' | 'FAILED';
  sanitizedDetails: Record<string, unknown>;
}

/**
 * Default timestamp tolerance in seconds (5 minutes)
 * Webhooks older than this are rejected as potential replay attempts
 */
export const DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300;

/**
 * Maximum allowed future timestamp drift in seconds
 * Protects against clock skew while preventing far-future attacks
 */
export const FUTURE_TIMESTAMP_TOLERANCE_SECONDS = 10;
