/**
 * Timestamp Validation Utilities for WebhookRadar
 * 
 * This module provides pure functions for validating webhook timestamps
 * to prevent replay attacks.
 * 
 * SECURITY REQUIREMENTS:
 * - MUST validate timestamps with configurable tolerance (default 300s)
 * - MUST reject timestamps too far in the future (prevents clock manipulation)
 * - MUST accept current server time as parameter (enables deterministic testing)
 * 
 * @see .kiro/steering/security-and-reliability.md#2-replay-attack-prevention
 * @see .kiro/steering/architecture-and-testing.md#2-functional-core-principles
 */

import {
  TimestampValidationResult,
  DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
  FUTURE_TIMESTAMP_TOLERANCE_SECONDS,
} from './types';

/**
 * Validates webhook timestamp to prevent replay attacks
 * 
 * Pure function:
 * - Accepts current server time as parameter (no Date.now() inside)
 * - Deterministic: same inputs always produce same output
 * - No side effects: no I/O, no mutations, no logging
 * 
 * Validation rules:
 * - Timestamp must be within `toleranceSeconds` of current server time (past)
 * - Timestamp must not be more than `FUTURE_TIMESTAMP_TOLERANCE_SECONDS` ahead (future)
 * - Time drift is calculated symmetrically (absolute value)
 * 
 * @param timestamp - Unix timestamp from webhook (seconds since epoch)
 * @param currentServerTime - Current server time (seconds since epoch)
 * @param toleranceSeconds - Maximum allowed age in seconds (default: 300 = 5 minutes)
 * @returns Validation result with drift diagnostic and specific failure reason
 * 
 * @example
 * ```typescript
 * const webhookTimestamp = 1609459200; // 2021-01-01 00:00:00 UTC
 * const serverTime = 1609459300;       // 2021-01-01 00:01:40 UTC (100s later)
 * 
 * const result = isTimestampValid(webhookTimestamp, serverTime, 300);
 * // Returns: { valid: true, driftSeconds: 100 }
 * 
 * const expiredResult = isTimestampValid(webhookTimestamp, serverTime + 400, 300);
 * // Returns: { valid: false, driftSeconds: 500, reason: "Timestamp too old..." }
 * ```
 * 
 * @remarks
 * Why accept currentServerTime as parameter?
 * - Enables deterministic property-based testing
 * - No dependency on system clock (Date.now())
 * - Easy to test edge cases (exact tolerance boundary, future timestamps)
 * - Follows Functional Core principle: pure functions only
 */
export function isTimestampValid(
  timestamp: number,
  currentServerTime: number,
  toleranceSeconds: number = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS
): TimestampValidationResult {
  // Calculate absolute time difference
  const driftSeconds = Math.abs(currentServerTime - timestamp);
  
  // Check if timestamp is too far in the future (more than 10 seconds ahead)
  // This protects against clock manipulation attacks
  if (timestamp > currentServerTime + FUTURE_TIMESTAMP_TOLERANCE_SECONDS) {
    return {
      valid: false,
      driftSeconds,
      reason: `Timestamp too far in future (${driftSeconds}s ahead, max allowed: ${FUTURE_TIMESTAMP_TOLERANCE_SECONDS}s)`,
    };
  }
  
  // Check if timestamp is too old (beyond tolerance window)
  // This prevents replay attacks with captured old webhooks
  if (timestamp < currentServerTime - toleranceSeconds) {
    return {
      valid: false,
      driftSeconds,
      reason: `Timestamp too old (${driftSeconds}s ago, max allowed: ${toleranceSeconds}s)`,
    };
  }
  
  // Timestamp is within acceptable window
  return {
    valid: true,
    driftSeconds,
  };
}

/**
 * Converts milliseconds to Unix timestamp (seconds)
 * 
 * JavaScript Date.now() returns milliseconds, but webhook timestamps
 * are typically in seconds. This pure utility handles the conversion.
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param milliseconds - Time in milliseconds (e.g., from Date.now())
 * @returns Unix timestamp in seconds (integer)
 * 
 * @example
 * ```typescript
 * const now = Date.now(); // 1609459200000 (milliseconds)
 * const unixTimestamp = toUnixTimestamp(now); // 1609459200 (seconds)
 * ```
 * 
 * @remarks
 * Property: Monotonic ordering preserved
 * - If ms1 < ms2, then toUnixTimestamp(ms1) <= toUnixTimestamp(ms2)
 * - Enables property-based testing of ordering invariants
 */
export function toUnixTimestamp(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}

/**
 * Calculates time drift between webhook timestamp and server time
 * 
 * Returns signed drift (negative = past, positive = future)
 * Useful for diagnostics and logging.
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param timestamp - Unix timestamp from webhook (seconds)
 * @param currentServerTime - Current server time (seconds)
 * @returns Signed drift in seconds (negative = webhook is older, positive = webhook is newer)
 * 
 * @example
 * ```typescript
 * const webhookTime = 1609459200;
 * const serverTime = 1609459300;
 * 
 * getTimestampDrift(webhookTime, serverTime); // Returns: -100 (webhook is 100s old)
 * getTimestampDrift(serverTime, webhookTime); // Returns: 100 (webhook is 100s in future)
 * ```
 */
export function getTimestampDrift(
  timestamp: number,
  currentServerTime: number
): number {
  return timestamp - currentServerTime;
}

/**
 * Parses timestamp from various string formats
 * 
 * Handles common timestamp formats:
 * - Unix timestamp string: "1609459200"
 * - ISO 8601: "2021-01-01T00:00:00Z"
 * - Milliseconds string: "1609459200000"
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param timestampString - Timestamp as string
 * @returns Unix timestamp in seconds, or null if parsing fails
 * 
 * @example
 * ```typescript
 * parseTimestamp("1609459200"); // Returns: 1609459200
 * parseTimestamp("2021-01-01T00:00:00Z"); // Returns: 1609459200
 * parseTimestamp("invalid"); // Returns: null
 * ```
 */
export function parseTimestamp(timestampString: string): number | null {
  try {
    // Try parsing as integer (Unix timestamp in seconds)
    const parsed = parseInt(timestampString, 10);
    
    // Validate that it's a reasonable Unix timestamp
    // (between year 2000 and year 2100)
    if (parsed >= 946684800 && parsed <= 4102444800) {
      return parsed;
    }
    
    // Try parsing as ISO 8601 date
    const dateMs = Date.parse(timestampString);
    if (!isNaN(dateMs)) {
      return toUnixTimestamp(dateMs);
    }
    
    // Could not parse timestamp
    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Validates that a timestamp is a valid Unix timestamp
 * 
 * Checks that the timestamp is:
 * - A finite number
 * - Within reasonable bounds (year 2000 to year 2100)
 * - Not negative
 * 
 * Pure function: Deterministic, no side effects
 * 
 * @param timestamp - Value to validate as Unix timestamp
 * @returns true if valid Unix timestamp, false otherwise
 * 
 * @example
 * ```typescript
 * isValidUnixTimestamp(1609459200); // true
 * isValidUnixTimestamp(-1); // false (negative)
 * isValidUnixTimestamp(NaN); // false (not a number)
 * isValidUnixTimestamp(999999999999); // false (year 33658 - unreasonable)
 * ```
 */
export function isValidUnixTimestamp(timestamp: number): boolean {
  // Must be a finite number
  if (!Number.isFinite(timestamp)) {
    return false;
  }
  
  // Must be non-negative
  if (timestamp < 0) {
    return false;
  }
  
  // Must be within reasonable bounds
  // 946684800 = 2000-01-01 00:00:00 UTC
  // 4102444800 = 2100-01-01 00:00:00 UTC
  if (timestamp < 946684800 || timestamp > 4102444800) {
    return false;
  }
  
  return true;
}
