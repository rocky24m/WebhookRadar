/**
 * Cryptographic Utilities for WebhookRadar
 * 
 * This module provides pure, deterministic cryptographic functions for webhook verification.
 * All functions are timing-safe to prevent side-channel attacks.
 * 
 * SECURITY REQUIREMENTS:
 * - MUST use crypto.timingSafeEqual for all signature comparisons
 * - MUST preserve raw request body buffers for signature computation
 * - MUST NOT log or expose raw secrets, signatures, or tokens
 * 
 * @see .kiro/steering/security-and-reliability.md
 */

import { createHmac, createHash, timingSafeEqual } from 'crypto';

/**
 * Computes HMAC-SHA256 digest of payload using provided secret
 * 
 * Pure function: Same input always produces same output
 * No side effects: No I/O, no mutations, no logging
 * 
 * @param secret - Secret key for HMAC computation
 * @param payload - Data to compute HMAC over (Buffer or string)
 * @returns Hex-encoded HMAC-SHA256 digest (64 characters)
 * 
 * @example
 * ```typescript
 * const signature = computeHmacSha256('my-secret', Buffer.from('payload data'));
 * // Returns: "a1b2c3d4..." (64 hex chars)
 * ```
 */
export function computeHmacSha256(
  secret: string,
  payload: Buffer | string
): string {
  const hmac = createHmac('sha256', secret);
  hmac.update(payload);
  return hmac.digest('hex');
}

/**
 * Timing-safe signature verification using constant-time comparison
 * 
 * SECURITY: This function prevents timing side-channel attacks by:
 * 1. Hashing both inputs to fixed-size SHA-256 digests (32 bytes each)
 * 2. Using crypto.timingSafeEqual for constant-time comparison
 * 3. Never short-circuiting on length mismatch before timing-safe check
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param expected - Expected signature value (from computed HMAC)
 * @param actual - Actual signature value (from webhook header)
 * @returns true if signatures match, false otherwise
 * 
 * @example
 * ```typescript
 * const expected = computeHmacSha256('secret', payload);
 * const actual = request.headers['x-signature'];
 * const valid = timingSafeVerify(expected, actual);
 * ```
 * 
 * @remarks
 * Why hash before comparison?
 * - timingSafeEqual requires equal-length buffers
 * - Webhook signatures may vary in length (hex, base64, prefixed)
 * - Hashing normalizes both to fixed 32-byte SHA-256 digests
 * - Prevents timing leaks from length checks
 * 
 * @see https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b
 * @see .kiro/steering/security-and-reliability.md#1-timing-safe-hmac-verification
 */
export function timingSafeVerify(expected: string, actual: string): boolean {
  try {
    // Hash both inputs to fixed-size 32-byte digests
    // This prevents timing leaks from length differences
    const expectedHash = createHash('sha256').update(expected).digest();
    const actualHash = createHash('sha256').update(actual).digest();
    
    // Constant-time comparison (always compares all 32 bytes)
    return timingSafeEqual(expectedHash, actualHash);
  } catch (error) {
    // Gracefully handle invalid input (non-comparable types, encoding errors)
    // Returning false is safe - we never expose the error details
    return false;
  }
}

/**
 * Redacts sensitive string for safe logging and diagnostics
 * 
 * Shows only the first 8 and last 2 characters of secrets/tokens
 * to maintain format visibility while protecting sensitive data.
 * 
 * Pure function: No side effects, deterministic output
 * 
 * @param val - Sensitive string to redact (secret, token, signature, etc.)
 * @returns Redacted string with middle characters replaced by "..."
 * 
 * @example
 * ```typescript
 * redactSensitiveString('whsec_1234567890abcdefghijklmnopqrstuvwxyz')
 * // Returns: "whsec_12...yz"
 * 
 * redactSensitiveString('short')
 * // Returns: "[REDACTED]" (too short to safely show any chars)
 * 
 * redactSensitiveString('')
 * // Returns: "[REDACTED]"
 * ```
 * 
 * @remarks
 * Redaction strategy:
 * - Strings < 12 chars: fully redacted (too short to show safely)
 * - Strings >= 12 chars: show first 8 + "..." + last 2
 * - Preserves format prefixes (whsec_, sk_test_, etc.) for debugging
 * - Never exposes enough entropy to brute-force or reconstruct
 */
export function redactSensitiveString(val: string): string {
  // Strings shorter than 12 characters are fully redacted
  // (not enough characters to safely reveal any portion)
  if (val.length < 12) {
    return '[REDACTED]';
  }
  
  // Show first 8 characters (usually includes provider prefix like "whsec_")
  // and last 2 characters (helps distinguish different secrets in logs)
  const prefix = val.slice(0, 8);
  const suffix = val.slice(-2);
  
  return `${prefix}...${suffix}`;
}

/**
 * Converts base64-encoded string to hex-encoded string
 * 
 * Used for providers like Shopify that send signatures in base64 format
 * while we compute HMAC in hex format for comparison.
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param base64String - Base64-encoded signature
 * @returns Hex-encoded equivalent string
 * 
 * @example
 * ```typescript
 * const base64Sig = "YWJjZGVm"; // base64 for "abcdef"
 * const hexSig = base64ToHex(base64Sig);
 * // Returns: "616263646566" (hex encoding of "abcdef")
 * ```
 */
export function base64ToHex(base64String: string): string {
  try {
    const buffer = Buffer.from(base64String, 'base64');
    return buffer.toString('hex');
  } catch (error) {
    // Invalid base64 input - return empty string to fail verification
    return '';
  }
}

/**
 * Converts hex-encoded string to base64-encoded string
 * 
 * Inverse operation of base64ToHex.
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param hexString - Hex-encoded string
 * @returns Base64-encoded equivalent string
 * 
 * @example
 * ```typescript
 * const hexSig = "616263646566";
 * const base64Sig = hexToBase64(hexSig);
 * // Returns: "YWJjZGVm"
 * ```
 */
export function hexToBase64(hexString: string): string {
  try {
    const buffer = Buffer.from(hexString, 'hex');
    return buffer.toString('base64');
  } catch (error) {
    // Invalid hex input - return empty string to fail verification
    return '';
  }
}
