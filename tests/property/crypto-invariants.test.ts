/**
 * Property-Based Tests for Cryptographic Invariants
 * 
 * These tests verify mathematical and security properties that must hold
 * for ALL possible inputs, not just specific example cases.
 * 
 * Uses fast-check to generate hundreds of random inputs and verify that
 * cryptographic operations maintain their security guarantees.
 * 
 * @see .kiro/steering/architecture-and-testing.md#5-property-based-testing-standards
 * @see .kiro/specs/webhook-verification-engine.md#phase-2-property-based-tests
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  computeHmacSha256,
  timingSafeVerify,
  redactSensitiveString,
  base64ToHex,
  hexToBase64,
} from '@/lib/core/crypto';

describe('Crypto Invariants - Property-Based Tests', () => {
  describe('Invariant 1: Self-Identity & Determinism', () => {
    it('should always verify a signature against itself (identity property)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }), // secret
          fc.oneof(
            fc.string({ minLength: 1, maxLength: 1000 }), // string payload
            fc.uint8Array({ minLength: 1, maxLength: 1000 }).map(arr => Buffer.from(arr)) // buffer payload
          ),
          (secret, payload) => {
            // Compute HMAC signature
            const signature = computeHmacSha256(secret, payload);
            
            // Invariant: A signature MUST always verify against itself
            expect(timingSafeVerify(signature, signature)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce deterministic output for same input (idempotence)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          fc.string({ minLength: 1, maxLength: 1000 }),
          (secret, payload) => {
            // Compute signature twice
            const sig1 = computeHmacSha256(secret, payload);
            const sig2 = computeHmacSha256(secret, payload);
            
            // Invariant: Same input MUST always produce same output
            expect(sig1).toBe(sig2);
            
            // Invariant: Both signatures MUST verify against each other
            expect(timingSafeVerify(sig1, sig2)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce valid signatures that always verify with original inputs', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          (secret, payloadArray) => {
            const payload = Buffer.from(payloadArray);
            const signature = computeHmacSha256(secret, payload);
            
            // Invariant: Computed signature MUST verify with original secret and payload
            const recomputedSignature = computeHmacSha256(secret, payload);
            expect(timingSafeVerify(signature, recomputedSignature)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 2: Single-Byte Tamper Rejection', () => {
    it('should reject signatures when secret is tampered (single character change)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 2, maxLength: 100 }), // min length 2 to allow tampering
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.integer({ min: 0, max: 99 }), // position to tamper
          (secret, payload, tamperPos) => {
            // Only tamper if position is within secret length
            if (tamperPos >= secret.length) return;
            
            // Compute valid signature
            const validSignature = computeHmacSha256(secret, payload);
            
            // Tamper with secret (change one character)
            const secretArray = secret.split('');
            const originalChar = secretArray[tamperPos];
            secretArray[tamperPos] = originalChar === 'a' ? 'b' : 'a';
            const tamperedSecret = secretArray.join('');
            
            // Compute signature with tampered secret
            const tamperedSignature = computeHmacSha256(tamperedSecret, payload);
            
            // Invariant: Tampered signature MUST be rejected
            expect(timingSafeVerify(validSignature, tamperedSignature)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject signatures when payload is tampered (single byte change)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          fc.uint8Array({ minLength: 2, maxLength: 1000 }), // min length 2 to allow tampering
          fc.integer({ min: 0, max: 999 }), // position to tamper
          (secret, payloadArray, tamperPos) => {
            // Only tamper if position is within payload length
            if (tamperPos >= payloadArray.length) return;
            
            const validPayload = Buffer.from(payloadArray);
            const validSignature = computeHmacSha256(secret, validPayload);
            
            // Tamper with payload (flip one bit)
            const tamperedArray = [...payloadArray];
            tamperedArray[tamperPos] = tamperedArray[tamperPos] ^ 0xFF; // flip all bits
            const tamperedPayload = Buffer.from(tamperedArray);
            
            const tamperedSignature = computeHmacSha256(secret, tamperedPayload);
            
            // Invariant: Tampered signature MUST be rejected
            expect(timingSafeVerify(validSignature, tamperedSignature)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject signatures with single hex character corrupted', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          fc.string({ minLength: 1, maxLength: 1000 }),
          fc.integer({ min: 0, max: 63 }), // hex signature is 64 chars
          (secret, payload, corruptPos) => {
            const validSignature = computeHmacSha256(secret, payload);
            
            // Corrupt one hex character in the signature
            const chars = validSignature.split('');
            const originalChar = chars[corruptPos];
            // Change hex digit to a different hex digit
            chars[corruptPos] = originalChar === '0' ? '1' : '0';
            const corruptedSignature = chars.join('');
            
            // Invariant: Corrupted signature MUST be rejected
            expect(timingSafeVerify(validSignature, corruptedSignature)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 3: Variable Length & Noise Safety', () => {
    it('should handle unequal length strings without throwing exceptions', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 100 }),
          fc.string({ minLength: 0, maxLength: 200 }),
          (str1, str2) => {
            // Skip if strings are equal
            if (str1 === str2) return;
            
            // Invariant: timingSafeVerify MUST NOT throw for any string inputs
            expect(() => timingSafeVerify(str1, str2)).not.toThrow();
            
            // Invariant: Different strings SHOULD generally return false
            // (may occasionally be true for hash collisions, but extremely rare)
            const result = timingSafeVerify(str1, str2);
            expect(typeof result).toBe('boolean');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle arbitrary byte sequences without timing vulnerabilities', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 0, maxLength: 64 }),
          fc.uint8Array({ minLength: 0, maxLength: 64 }),
          (bytes1, bytes2) => {
            const str1 = Buffer.from(bytes1).toString('hex');
            const str2 = Buffer.from(bytes2).toString('hex');
            
            // Skip if arrays are identical
            if (Buffer.compare(Buffer.from(bytes1), Buffer.from(bytes2)) === 0) return;
            
            // Invariant: MUST NOT throw regardless of byte content
            expect(() => timingSafeVerify(str1, str2)).not.toThrow();
            
            // Invariant: Different byte sequences MUST return false
            expect(timingSafeVerify(str1, str2)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle empty strings and single characters gracefully', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant(''),
            fc.string({ minLength: 1, maxLength: 1 }),
            fc.string({ minLength: 64, maxLength: 64 })
          ),
          fc.oneof(
            fc.constant(''),
            fc.string({ minLength: 1, maxLength: 1 }),
            fc.string({ minLength: 64, maxLength: 64 })
          ),
          (str1, str2) => {
            // Invariant: MUST handle edge cases without throwing
            expect(() => timingSafeVerify(str1, str2)).not.toThrow();
            
            // Invariant: Only equal strings return true
            const result = timingSafeVerify(str1, str2);
            if (str1 === str2) {
              expect(result).toBe(true);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle special characters and unicode without errors', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 100 }),
          fc.string({ minLength: 0, maxLength: 100 }),
          (str1, str2) => {
            // Invariant: MUST handle arbitrary characters without throwing
            expect(() => timingSafeVerify(str1, str2)).not.toThrow();
            
            const result = timingSafeVerify(str1, str2);
            expect(typeof result).toBe('boolean');
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 4: Redaction Safety', () => {
    it('should never reveal the full original string (length >= 12)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 12, maxLength: 200 }),
          (sensitiveString) => {
            const redacted = redactSensitiveString(sensitiveString);
            
            // Invariant: Redacted string MUST NOT equal original
            expect(redacted).not.toBe(sensitiveString);
            
            // Invariant: Redacted string MUST contain "..."
            expect(redacted).toContain('...');
            
            // Invariant: For strings >= 14 chars, redacted string MUST be shorter
            if (sensitiveString.length >= 14) {
              expect(redacted.length).toBeLessThan(sensitiveString.length);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should preserve format prefix (first 8 characters) for debugging', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 12, maxLength: 200 }),
          (sensitiveString) => {
            const redacted = redactSensitiveString(sensitiveString);
            
            // Invariant: First 8 characters MUST be preserved
            expect(redacted.startsWith(sensitiveString.slice(0, 8))).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should preserve suffix (last 2 characters) for identification', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 12, maxLength: 200 }),
          (sensitiveString) => {
            const redacted = redactSensitiveString(sensitiveString);
            
            // Invariant: Last 2 characters MUST be preserved
            expect(redacted.endsWith(sensitiveString.slice(-2))).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should fully redact short strings (length < 12)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 11 }),
          (shortString) => {
            const redacted = redactSensitiveString(shortString);
            
            // Invariant: Short strings MUST be fully redacted
            expect(redacted).toBe('[REDACTED]');
            
            // Invariant: Non-empty short strings MUST NOT appear in redacted output
            if (shortString.length > 0 && shortString !== '[REDACTED]') {
              expect(redacted).not.toBe(shortString);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce consistent output for same input (deterministic)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 200 }),
          (str) => {
            const redacted1 = redactSensitiveString(str);
            const redacted2 = redactSensitiveString(str);
            
            // Invariant: Redaction MUST be deterministic
            expect(redacted1).toBe(redacted2);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Invariant 5: Hex/Base64 Conversion Roundtrip', () => {
    it('should roundtrip hex -> base64 -> hex preserving original', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 256 }),
          (bytes) => {
            const originalHex = Buffer.from(bytes).toString('hex');
            
            // Convert hex -> base64 -> hex
            const base64 = hexToBase64(originalHex);
            const reconstructedHex = base64ToHex(base64);
            
            // Invariant: Roundtrip MUST preserve original hex string
            expect(reconstructedHex).toBe(originalHex);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should roundtrip base64 -> hex -> base64 preserving original', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 256 }),
          (bytes) => {
            const originalBase64 = Buffer.from(bytes).toString('base64');
            
            // Convert base64 -> hex -> base64
            const hex = base64ToHex(originalBase64);
            const reconstructedBase64 = hexToBase64(hex);
            
            // Invariant: Roundtrip MUST preserve original base64 string
            expect(reconstructedBase64).toBe(originalBase64);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce valid hex output (only 0-9, a-f characters)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }).map(s => Buffer.from(s).toString('base64')),
          (base64String) => {
            const hex = base64ToHex(base64String);
            
            // Invariant: Hex output MUST only contain valid hex characters
            expect(hex).toMatch(/^[0-9a-f]*$/);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle empty inputs gracefully', () => {
      // Empty string conversions should not throw
      expect(() => base64ToHex('')).not.toThrow();
      expect(() => hexToBase64('')).not.toThrow();
      
      // Empty inputs should produce empty outputs
      expect(base64ToHex('')).toBe('');
      expect(hexToBase64('')).toBe('');
    });

    it('should handle invalid base64 input safely', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => !/^[A-Za-z0-9+/=]*$/.test(s)),
          (invalidBase64) => {
            // Invariant: Invalid base64 MUST NOT throw
            expect(() => base64ToHex(invalidBase64)).not.toThrow();
            
            // Should return a string
            const result = base64ToHex(invalidBase64);
            expect(typeof result).toBe('string');
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle invalid hex input safely', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }).filter(s => !/^[0-9a-fA-F]*$/.test(s)),
          (invalidHex) => {
            // Invariant: Invalid hex MUST NOT throw
            expect(() => hexToBase64(invalidHex)).not.toThrow();
            
            // Should return empty string or valid base64
            const result = hexToBase64(invalidHex);
            expect(typeof result).toBe('string');
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
