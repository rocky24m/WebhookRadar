/**
 * Property-Based Tests for Timestamp Validation Invariants
 * 
 * These tests verify replay attack prevention properties that must hold
 * for ALL possible timestamp combinations and drift scenarios.
 * 
 * Uses fast-check to generate hundreds of random timestamp scenarios
 * and verify that validation logic correctly prevents replay attacks
 * while allowing legitimate webhooks.
 * 
 * @see .kiro/steering/architecture-and-testing.md#5-property-based-testing-standards
 * @see .kiro/specs/webhook-verification-engine.md#phase-2-property-based-tests
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  isTimestampValid,
  toUnixTimestamp,
  getTimestampDrift,
  parseTimestamp,
  isValidUnixTimestamp,
} from '@/lib/core/timestamp';
import {
  DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
  FUTURE_TIMESTAMP_TOLERANCE_SECONDS,
} from '@/lib/core/types';

describe('Timestamp Invariants - Property-Based Tests', () => {
  describe('Invariant 6: Window Tolerance', () => {
    it('should accept timestamps within tolerance window (past drift)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }), // server time (reasonable Unix timestamp)
          fc.integer({ min: 0, max: 300 }), // drift within default tolerance
          fc.integer({ min: 1, max: 3600 }), // tolerance setting (1 second to 1 hour)
          (serverTime, drift, tolerance) => {
            // Timestamp is in the past, within tolerance
            const timestamp = serverTime - drift;
            
            const result = isTimestampValid(timestamp, serverTime, tolerance);
            
            // Invariant: Timestamps within tolerance MUST be valid
            if (drift <= tolerance) {
              expect(result.valid).toBe(true);
              expect(result.driftSeconds).toBe(drift);
              expect(result.reason).toBeUndefined();
            } else {
              expect(result.valid).toBe(false);
              expect(result.reason).toBeDefined();
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept timestamps within future tolerance (future drift)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 0, max: 10 }), // future drift within FUTURE_TIMESTAMP_TOLERANCE_SECONDS
          (serverTime, futureDrift) => {
            const timestamp = serverTime + futureDrift;
            
            const result = isTimestampValid(timestamp, serverTime, DEFAULT_TIMESTAMP_TOLERANCE_SECONDS);
            
            // Invariant: Future timestamps within 10 seconds MUST be valid
            expect(result.valid).toBe(true);
            expect(result.driftSeconds).toBe(futureDrift);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should validate correctly at exact tolerance boundaries', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1, max: 3600 }),
          (serverTime, tolerance) => {
            // Test exact boundary: timestamp = serverTime - tolerance (last valid second)
            const boundaryTimestamp = serverTime - tolerance;
            const result = isTimestampValid(boundaryTimestamp, serverTime, tolerance);
            
            // Invariant: Exact boundary MUST be valid
            expect(result.valid).toBe(true);
            expect(result.driftSeconds).toBe(tolerance);
            
            // Test one second past boundary (first invalid second)
            const expiredTimestamp = serverTime - tolerance - 1;
            const expiredResult = isTimestampValid(expiredTimestamp, serverTime, tolerance);
            
            // Invariant: One second past boundary MUST be invalid
            expect(expiredResult.valid).toBe(false);
            expect(expiredResult.reason).toContain('too old');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should correctly validate for any tolerance value (1s to 1 hour)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 0, max: 3600 }),
          fc.integer({ min: 1, max: 3600 }),
          (serverTime, drift, tolerance) => {
            const timestamp = serverTime - drift;
            const result = isTimestampValid(timestamp, serverTime, tolerance);
            
            // Invariant: Valid if and only if drift <= tolerance
            const expectedValid = drift <= tolerance;
            expect(result.valid).toBe(expectedValid);
            
            // Invariant: Drift MUST be calculated correctly
            expect(result.driftSeconds).toBe(drift);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 7: Future Drift Protection', () => {
    it('should reject timestamps more than 10 seconds in future', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 11, max: 10000 }), // drift > FUTURE_TIMESTAMP_TOLERANCE_SECONDS
          (serverTime, futureDrift) => {
            const futureTimestamp = serverTime + futureDrift;
            
            const result = isTimestampValid(futureTimestamp, serverTime, DEFAULT_TIMESTAMP_TOLERANCE_SECONDS);
            
            // Invariant: Future timestamps beyond 10s MUST be rejected
            expect(result.valid).toBe(false);
            expect(result.reason).toBeDefined();
            expect(result.reason).toContain('future');
            expect(result.driftSeconds).toBe(futureDrift);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should provide clear diagnostic reason for future timestamp rejection', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 11, max: 1000 }),
          (serverTime, futureDrift) => {
            const futureTimestamp = serverTime + futureDrift;
            const result = isTimestampValid(futureTimestamp, serverTime, 300);
            
            // Invariant: Reason MUST mention "future" and drift amount
            expect(result.valid).toBe(false);
            expect(result.reason).toMatch(/future/i);
            expect(result.reason).toContain(futureDrift.toString());
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject all timestamps where drift < -10 seconds', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: -10000, max: -11 }), // negative drift (future timestamp)
          (serverTime, negativeDrift) => {
            const timestamp = serverTime - negativeDrift; // results in future timestamp
            const result = isTimestampValid(timestamp, serverTime, 300);
            
            // Invariant: Any drift < -10 MUST be rejected
            expect(result.valid).toBe(false);
            expect(result.reason).toBeDefined();
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 8: Expired Replay Protection', () => {
    it('should reject timestamps older than default 300 seconds', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 301, max: 100000 }), // drift > DEFAULT_TIMESTAMP_TOLERANCE_SECONDS
          (serverTime, oldDrift) => {
            const oldTimestamp = serverTime - oldDrift;
            
            const result = isTimestampValid(oldTimestamp, serverTime);
            
            // Invariant: Expired timestamps MUST be rejected
            expect(result.valid).toBe(false);
            expect(result.reason).toBeDefined();
            expect(result.reason).toContain('too old');
            expect(result.driftSeconds).toBe(oldDrift);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should provide clear diagnostic reason for expired timestamp rejection', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 301, max: 10000 }),
          (serverTime, oldDrift) => {
            const oldTimestamp = serverTime - oldDrift;
            const result = isTimestampValid(oldTimestamp, serverTime, 300);
            
            // Invariant: Reason MUST mention "old" or "expired" and drift amount
            expect(result.valid).toBe(false);
            expect(result.reason).toMatch(/old|expired/i);
            expect(result.reason).toContain(oldDrift.toString());
            expect(result.reason).toContain('300'); // tolerance value
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should consistently reject replayed old webhooks regardless of server time', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }), // original server time
          fc.integer({ min: 301, max: 1000 }), // age of replayed webhook
          fc.integer({ min: 0, max: 10000 }), // additional time passed
          (originalServerTime, replayAge, additionalTime) => {
            const webhookTimestamp = originalServerTime - replayAge;
            const currentServerTime = originalServerTime + additionalTime;
            
            const result = isTimestampValid(webhookTimestamp, currentServerTime, 300);
            
            // Invariant: Old webhooks MUST remain invalid as time passes
            expect(result.valid).toBe(false);
            expect(result.reason).toContain('too old');
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 9: Drift Anti-Symmetry', () => {
    it('should satisfy anti-symmetry: drift(A,B) === -drift(B,A)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1000000000, max: 2000000000 }),
          (timestampA, timestampB) => {
            const driftAB = getTimestampDrift(timestampA, timestampB);
            const driftBA = getTimestampDrift(timestampB, timestampA);
            
            // Invariant: Anti-symmetry property MUST hold
            expect(driftAB).toBe(-driftBA);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should calculate zero drift for identical timestamps', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          (timestamp) => {
            const drift = getTimestampDrift(timestamp, timestamp);
            
            // Invariant: Identical timestamps MUST have zero drift
            expect(drift).toBe(0);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce negative drift when timestamp is in the past', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1, max: 10000 }),
          (serverTime, pastOffset) => {
            const pastTimestamp = serverTime - pastOffset;
            const drift = getTimestampDrift(pastTimestamp, serverTime);
            
            // Invariant: Past timestamps MUST produce negative drift
            expect(drift).toBeLessThan(0);
            expect(drift).toBe(-pastOffset);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce positive drift when timestamp is in the future', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1, max: 10000 }),
          (serverTime, futureOffset) => {
            const futureTimestamp = serverTime + futureOffset;
            const drift = getTimestampDrift(futureTimestamp, serverTime);
            
            // Invariant: Future timestamps MUST produce positive drift
            expect(drift).toBeGreaterThan(0);
            expect(drift).toBe(futureOffset);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should maintain drift magnitude regardless of direction', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1, max: 10000 }),
          (serverTime, offset) => {
            const pastTimestamp = serverTime - offset;
            const futureTimestamp = serverTime + offset;
            
            const pastDrift = getTimestampDrift(pastTimestamp, serverTime);
            const futureDrift = getTimestampDrift(futureTimestamp, serverTime);
            
            // Invariant: Magnitude MUST be equal for same offset
            expect(Math.abs(pastDrift)).toBe(Math.abs(futureDrift));
            expect(Math.abs(pastDrift)).toBe(offset);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Additional Timestamp Utilities Invariants', () => {
    it('should preserve ordering when converting milliseconds to Unix timestamp (monotonic)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 9999999999000 }),
          fc.integer({ min: 0, max: 9999999999000 }),
          (ms1, ms2) => {
            const unix1 = toUnixTimestamp(ms1);
            const unix2 = toUnixTimestamp(ms2);
            
            // Invariant: Ordering MUST be preserved (monotonic property)
            if (ms1 < ms2) {
              expect(unix1).toBeLessThanOrEqual(unix2);
            } else if (ms1 > ms2) {
              expect(unix1).toBeGreaterThanOrEqual(unix2);
            } else {
              expect(unix1).toBe(unix2);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should validate all reasonable Unix timestamps as valid', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 946684800, max: 4102444800 }), // Year 2000 to Year 2100
          (timestamp) => {
            // Invariant: All timestamps in reasonable range MUST be valid
            expect(isValidUnixTimestamp(timestamp)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject timestamps outside reasonable bounds', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.integer({ min: -1000000, max: -1 }), // negative timestamps
            fc.integer({ min: 4102444801, max: 9999999999 }), // far future (> year 2100)
            fc.constant(NaN),
            fc.constant(Infinity),
            fc.constant(-Infinity)
          ),
          (invalidTimestamp) => {
            // Invariant: Invalid timestamps MUST be rejected
            expect(isValidUnixTimestamp(invalidTimestamp)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should parse Unix timestamp strings correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          (timestamp) => {
            const timestampString = timestamp.toString();
            const parsed = parseTimestamp(timestampString);
            
            // Invariant: Valid Unix timestamp strings MUST parse correctly
            expect(parsed).toBe(timestamp);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle invalid timestamp strings gracefully', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant('invalid'),
            fc.constant('not-a-number'),
            fc.constant(''),
            fc.string({ minLength: 1, maxLength: 20 }).filter(s => isNaN(parseInt(s, 10)))
          ),
          (invalidString) => {
            const parsed = parseTimestamp(invalidString);
            
            // Invariant: Invalid strings MUST return null (not throw)
            expect(parsed).toBeNull();
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce deterministic results for same inputs', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1000000000, max: 2000000000 }),
          fc.integer({ min: 1, max: 3600 }),
          (timestamp, serverTime, tolerance) => {
            // Call validation twice with same inputs
            const result1 = isTimestampValid(timestamp, serverTime, tolerance);
            const result2 = isTimestampValid(timestamp, serverTime, tolerance);
            
            // Invariant: Results MUST be identical (deterministic)
            expect(result1.valid).toBe(result2.valid);
            expect(result1.driftSeconds).toBe(result2.driftSeconds);
            expect(result1.reason).toBe(result2.reason);
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
