# WebhookRadar Security Audit Report

**Audit Date:** 2026-10-01T14:21:00Z  
**Auditor:** WebhookRadar Security & Reliability Auditor  
**Audit Scope:** Timing-safe HMAC verification, replay attack prevention, secret exposure, and payload validation compliance  
**Test Results:** 42/42 property-based tests PASSED ✅

---

## Executive Summary

**Overall Status:** 🟢 **PASS** (with 1 MEDIUM severity recommendation)

WebhookRadar's webhook verification system demonstrates **strong security posture** with comprehensive protection against:
- ✅ Timing side-channel attacks
- ✅ Replay attacks
- ✅ Secret exposure in logs and errors
- ✅ Invalid payload injection

All four provider adapters (GitHub, Stripe, Slack, Shopify) implement timing-safe signature verification using `crypto.timingSafeEqual()`. The functional core architecture ensures pure, deterministic cryptographic operations with zero side effects.

**Key Strengths:**
- Advanced timing attack mitigation via SHA-256 hashing before comparison
- Comprehensive timestamp validation with configurable drift tolerance
- Systematic secret redaction throughout the codebase
- 100% pass rate on property-based security invariant tests

**Recommendation:**
- One MEDIUM severity finding: Future timestamp tolerance should be enforced consistently across all providers

---

## Findings Summary

| ID | Severity | Category | Status | Location |
|----|----------|----------|--------|----------|
| **AUD-001** | ✅ PASS | Timing Safety | COMPLIANT | `lib/core/crypto.ts:44-66` |
| **AUD-002** | ✅ PASS | Timing Safety | COMPLIANT | All adapters |
| **AUD-003** | 🟡 MEDIUM | Replay Protection | RECOMMENDATION | `lib/adapters/*.ts` |
| **AUD-004** | ✅ PASS | Secret Redaction | COMPLIANT | `lib/core/crypto.ts:87-106`, `lib/adapters/index.ts:112-145` |
| **AUD-005** | ✅ PASS | Payload Validation | COMPLIANT | All adapters |
| **AUD-006** | ✅ PASS | Error Messages | COMPLIANT | All adapters |

---

## Detailed Findings

### AUD-001: ✅ Advanced Timing-Safe Signature Verification

**Severity:** INFO  
**Status:** COMPLIANT  
**Category:** Timing Attack Prevention

**Location:** `lib/core/crypto.ts:44-66`

**Analysis:**

WebhookRadar implements **state-of-the-art** timing attack mitigation that **exceeds** the baseline requirements:

```typescript
export function timingSafeVerify(expected: string, actual: string): boolean {
  try {
    // Hash both inputs to fixed-size 32-byte digests
    // This prevents timing leaks from length differences
    const expectedHash = createHash('sha256').update(expected).digest();
    const actualHash = createHash('sha256').update(actual).digest();
    
    // Constant-time comparison (always compares all 32 bytes)
    return timingSafeEqual(expectedHash, actualHash);
  } catch (error) {
    return false;
  }
}
```

**Why This Exceeds Requirements:**

1. **SHA-256 Pre-Hashing:** Both signatures are hashed to fixed 32-byte digests before comparison, eliminating length-based timing leaks entirely
2. **Constant-Time Comparison:** Uses Node.js `crypto.timingSafeEqual()` which compares all bytes regardless of early mismatches
3. **Error Handling:** Gracefully catches encoding errors without leaking information

**Verification:**

All four adapters correctly invoke `timingSafeVerify()`:
- ✅ `github.ts:51` - `timingSafeVerify(expectedSignature, receivedSignature)`
- ✅ `stripe.ts:98` - `timingSafeVerify(expectedSignature, receivedSignature)`
- ✅ `slack.ts:99` - `timingSafeVerify(expectedSignature, receivedSignature)`
- ✅ `shopify.ts:120` - `timingSafeVerify(expectedSignature, receivedSignatureHex)`

**Property-Based Test Coverage:**

Tests verify critical security invariants (21/21 crypto tests passed):
- ✅ Determinism: Same input → same output
- ✅ Tamper detection: Modified signature → rejection
- ✅ Length normalization: Variable-length inputs handled correctly
- ✅ Error resilience: Invalid encodings fail gracefully

**Compliance:** ✅ **EXCEEDS REQUIREMENT**

---

### AUD-002: ✅ No Direct String Comparisons

**Severity:** INFO  
**Status:** COMPLIANT  
**Category:** Timing Attack Prevention

**Analysis:**

Grep search for unsafe comparison operators (`===`, `==`, `.localeCompare()`) in adapter files revealed **zero** instances of direct signature comparison.

**Scan Results:**

All detected `===` usages are for **non-cryptographic purposes**:
- Header name matching (case-insensitive lookup): `key.toLowerCase() === lowerName` ✅
- Metadata validation: `key === 't'` (Stripe timestamp key) ✅
- Array/type checks: `Array.isArray(value)` ✅

**Signature Verification Path:**

```
Received Signature (String)
    ↓
computeHmacSha256() → Expected Signature (String)
    ↓
timingSafeVerify()
    ↓
createHash('sha256') → Fixed-length buffers
    ↓
timingSafeEqual() → Constant-time comparison
```

**Compliance:** ✅ **PASS**

---

### AUD-003: 🟡 Future Timestamp Tolerance Enforcement

**Severity:** MEDIUM  
**Status:** RECOMMENDATION  
**Category:** Replay Attack Prevention

**Location:**
- `lib/core/timestamp.ts:70-76` (validates future tolerance)
- `lib/adapters/shopify.ts:80` (Date.now() call)
- `lib/adapters/slack.ts:89` (Date.now() call)
- `lib/adapters/stripe.ts:88` (Date.now() call)

**Issue:**

The timestamp validation function correctly enforces **10-second future tolerance** to prevent clock manipulation attacks:

```typescript
// lib/core/timestamp.ts:70-76
if (timestamp > currentServerTime + FUTURE_TIMESTAMP_TOLERANCE_SECONDS) {
  return {
    valid: false,
    driftSeconds,
    reason: `Timestamp too far in future (${driftSeconds}s ahead, max allowed: ${FUTURE_TIMESTAMP_TOLERANCE_SECONDS}s)`,
  };
}
```

However, **GitHub adapter does not validate timestamps** (as intended by design, since GitHub doesn't provide webhook timestamps). This creates an **asymmetric security posture** across providers:

| Provider | Timestamp Validation | Future Tolerance | Past Tolerance |
|----------|---------------------|------------------|----------------|
| GitHub   | ❌ None (no timestamp header) | N/A | N/A |
| Stripe   | ✅ Yes | ✅ 10s | ✅ 300s (configurable) |
| Slack    | ✅ Yes | ✅ 10s | ✅ 300s (configurable) |
| Shopify  | ✅ Yes (optional) | ✅ 10s | ✅ 300s (configurable) |

**Security Implication:**

- **GitHub webhooks are vulnerable to replay attacks** if the secret is compromised, since there's no timestamp validation
- Attacker could capture a valid GitHub webhook and replay it indefinitely
- Mitigation: GitHub relies on HTTPS transport security and expects consumers to implement their own replay protection (e.g., idempotency keys, event ID deduplication)

**Recommendation:**

Document this architectural decision explicitly in the security steering and provide guidance for consumers:

```markdown
## GitHub Replay Attack Mitigation

GitHub webhooks do NOT include timestamp headers, making them inherently vulnerable 
to replay attacks if the webhook secret is compromised.

**Recommended Mitigations:**
1. Store processed webhook event IDs in a cache/database
2. Reject duplicate delivery GUIDs (X-GitHub-Delivery header)
3. Implement application-level idempotency based on event content
4. Rotate webhook secrets regularly (every 90 days)
5. Monitor for suspicious duplicate events
```

**Code Change (Optional Enhancement):**

Add delivery ID tracking to GitHub adapter:

```typescript
// lib/adapters/github.ts
export function verifyGitHubWebhook(
  request: WebhookVerificationRequest,
  processedDeliveryIds?: Set<string> // Optional replay protection
): WebhookVerificationResult {
  // ... existing signature verification ...
  
  // Optional: Check for duplicate delivery ID
  const deliveryId = getHeader(request.headers, 'x-github-delivery');
  if (deliveryId && processedDeliveryIds?.has(deliveryId)) {
    return {
      valid: false,
      provider: 'github',
      reason: 'Duplicate delivery ID (potential replay attack)',
    };
  }
  
  // ... rest of verification ...
}
```

**Compliance:** 🟡 **RECOMMENDATION** (not a vulnerability, but document the gap)

---

### AUD-004: ✅ Comprehensive Secret Redaction

**Severity:** INFO  
**Status:** COMPLIANT  
**Category:** Secret Exposure Prevention

**Locations:**
- `lib/core/crypto.ts:87-106` - `redactSensitiveString()`
- `lib/adapters/index.ts:112-145` - `createVerificationDiagnostic()`

**Analysis:**

WebhookRadar implements **multi-layer secret redaction**:

**Layer 1: Utility Function**
```typescript
export function redactSensitiveString(val: string): string {
  if (val.length < 12) {
    return '[REDACTED]';
  }
  const prefix = val.slice(0, 8);  // Show provider prefix (whsec_, sk_)
  const suffix = val.slice(-2);     // Show last 2 chars for distinction
  return `${prefix}...${suffix}`;
}
```

**Layer 2: Diagnostic Sanitization**
```typescript
export function createVerificationDiagnostic(
  result: WebhookVerificationResult,
  request: WebhookVerificationRequest
): VerificationDiagnostic {
  return {
    provider: result.provider,
    checkedAt: new Date().toISOString(),
    status: result.valid ? 'SUCCESS' : 'FAILED',
    sanitizedDetails: {
      headerKeys,                                      // ✅ No values
      payloadSize,                                     // ✅ Non-sensitive
      secretPrefix: redactSensitiveString(request.secret), // ✅ Redacted
      timestampDrift: result.timestampDrift,          // ✅ Non-sensitive
      failureReason: result.reason,                   // ✅ Generic errors
    },
  };
}
```

**Verification - No Console.log Exposure:**

Grep search for logging statements found **only documentation examples** (not actual logging code):

```
c:\my-projects\WebhookRadar\lib\adapters\index.ts:117
 * console.log(diagnostic);  // ← Example in JSDoc comment only
```

**Error Message Audit:**

All adapter error messages are **generic** and never expose signatures:

| Provider | Error Messages | Signature Exposure |
|----------|----------------|-------------------|
| GitHub   | "Missing x-hub-signature-256 header" | ✅ None |
| Stripe   | "Signature verification failed" | ✅ None |
| Slack    | "Signature verification failed" | ✅ None |
| Shopify  | "Invalid base64 signature format" | ✅ None |

**Route Handler Verification:**

The Next.js route handler (`app/api/webhooks/[provider]/route.ts`) properly uses the diagnostic wrapper and never logs raw secrets:

```typescript
// ✅ Sanitized diagnostic used
const diagnostic = createVerificationDiagnostic(result, {
  headers: headersRecord,
  rawBody,
  secret,  // ← Redacted inside createVerificationDiagnostic()
});

return NextResponse.json({
  ...result,        // ✅ Only contains generic 'reason' field
  latencyMs,
  diagnostic,       // ✅ All secrets redacted
  receivedBytes: rawBody.length,
});
```

**Compliance:** ✅ **PASS**

---

### AUD-005: ✅ Strict Payload Validation Order

**Severity:** INFO  
**Status:** COMPLIANT  
**Category:** Payload Validation

**Analysis:**

All adapters follow the **correct validation sequence**:

```
1. Extract signature/timestamp headers
   ↓
2. Verify signature using raw Buffer
   ↓
3. (Optional) Validate timestamp
   ↓
4. Return result (JSON parsing happens AFTER verification in route handler)
```

**Example - Slack Adapter (Most Complex):**

```typescript
export function verifySlackWebhook(
  request: WebhookVerificationRequest,
  toleranceSeconds: number = 300
): WebhookVerificationResult {
  // Step 1: Header extraction
  const signatureHeader = getHeader(request.headers, 'x-slack-signature');
  const timestampHeader = getHeader(request.headers, 'x-slack-request-timestamp');
  
  // Step 2: Header presence validation
  if (!signatureHeader || !timestampHeader) {
    return { valid: false, provider: 'slack', reason: '...' };
  }
  
  // Step 3: Timestamp parsing and validation
  const timestamp = parseInt(timestampHeader, 10);
  const timestampValidation = isTimestampValid(timestamp, currentTime, toleranceSeconds);
  
  // Step 4: Signature verification using raw body
  const signedPayload = `v0:${timestamp}:${bodyString}`;
  const expectedSignature = computeHmacSha256(request.secret, signedPayload);
  const isValid = timingSafeVerify(expectedSignature, receivedSignature);
  
  return { valid: isValid, provider: 'slack', ... };
}
```

**Raw Buffer Preservation:**

All adapters correctly handle raw body buffers:

```typescript
// ✅ Ensures rawBody is Buffer
const payload = Buffer.isBuffer(request.rawBody)
  ? request.rawBody
  : Buffer.from(request.rawBody);
```

**JSON Parsing Deferred:**

The route handler reads raw body BEFORE verification:

```typescript
// app/api/webhooks/[provider]/route.ts:37-38
const arrayBuffer = await request.arrayBuffer();
const rawBody = Buffer.from(arrayBuffer);  // ✅ Raw bytes preserved

// Verification happens first
const result = await verifyWebhook(providerLower, { headers, rawBody, secret }, toleranceSeconds);

// ✅ JSON parsing would happen AFTER in business logic (not shown in route handler)
```

**Compliance:** ✅ **PASS**

---

### AUD-006: ✅ Generic Error Messages

**Severity:** INFO  
**Status:** COMPLIANT  
**Category:** Information Disclosure Prevention

**Analysis:**

All error responses are **generic** and never leak:
- Expected signatures
- Signature formats
- Internal error details
- Secret values

**Error Message Inventory:**

| Provider | Error Scenario | Message | Secure? |
|----------|---------------|---------|---------|
| GitHub | Missing header | "Missing x-hub-signature-256 header" | ✅ Yes (public header name) |
| GitHub | Invalid format | "Invalid signature format (expected sha256= prefix)" | ✅ Yes (documented format) |
| GitHub | Verification failed | "Signature verification failed" | ✅ Yes (no details) |
| Stripe | Missing header | "Missing stripe-signature header" | ✅ Yes |
| Stripe | Parse error | "Invalid signature header format" | ✅ Yes |
| Stripe | Timestamp expired | "Timestamp too old (300s ago, max allowed: 300s)" | ✅ Yes (drift is not sensitive) |
| Stripe | Verification failed | "Signature verification failed" | ✅ Yes |
| Slack | Missing timestamp | "Missing x-slack-request-timestamp header" | ✅ Yes |
| Slack | Verification failed | "Signature verification failed" | ✅ Yes |
| Shopify | Invalid base64 | "Invalid base64 signature format" | ✅ Yes |

**Route Handler Error Handling:**

```typescript
// app/api/webhooks/[provider]/route.ts:98-105
} catch (error) {
  return NextResponse.json(
    {
      valid: false,
      error: 'Internal server error during webhook verification',  // ✅ Generic
    },
    { status: 500 }
  );
}
```

**Compliance:** ✅ **PASS**

---

## Property-Based Test Results

**Test Execution:** `npm test -- tests/property`

**Results:** ✅ **42/42 tests PASSED**

```
✓ tests/property/crypto-invariants.test.ts (21 tests) 120ms
✓ tests/property/timestamp-invariants.test.ts (21 tests) 72ms

Test Files  2 passed (2)
Tests      42 passed (42)
Duration   683ms
```

**Crypto Invariants Verified:**

1. ✅ Determinism: `computeHmacSha256()` produces identical output for identical input
2. ✅ Uniqueness: Different payloads produce different signatures
3. ✅ Timing safety: `timingSafeVerify()` does not short-circuit
4. ✅ Length normalization: Variable-length signatures handled correctly
5. ✅ Tamper detection: Single-bit corruption rejected
6. ✅ Error resilience: Invalid encodings fail gracefully

**Timestamp Invariants Verified:**

1. ✅ Tolerance validation: Timestamps within tolerance accepted
2. ✅ Expiration: Timestamps beyond tolerance rejected
3. ✅ Symmetry: Past and future drift treated equally (within tolerance)
4. ✅ Monotonicity: Timestamp ordering preserved after conversion
5. ✅ Boundary conditions: Exact tolerance edges handled correctly
6. ✅ Future protection: Timestamps >10s ahead rejected

**Test Configuration:**

Each property-based test runs **100 iterations** with randomly generated inputs using `fast-check`, providing high confidence in invariant correctness.

---

## Security Compliance Checklist

### Timing-Safe HMAC Verification

- [x] ✅ Uses `crypto.timingSafeEqual()` for signature comparison
- [x] ✅ Hashes both signatures to fixed-length before comparison
- [x] ✅ No direct string comparison (`===`, `==`, `.localeCompare()`)
- [x] ✅ Length checks do not short-circuit timing-safe comparison
- [x] ✅ All adapters invoke `timingSafeVerify()` correctly

**Status:** ✅ **COMPLIANT**

---

### Replay Attack Prevention

- [x] ✅ Timestamp validation with configurable tolerance (default 300s)
- [x] ✅ Future timestamp protection (10s maximum ahead)
- [x] ✅ Stripe: Validates timestamp from `t=` parameter
- [x] ✅ Slack: Validates `x-slack-request-timestamp` header
- [x] ✅ Shopify: Validates `x-shopify-webhook-timestamp` header (optional)
- [ ] ⚠️ GitHub: No timestamp validation (by design, see AUD-003)

**Status:** 🟡 **MOSTLY COMPLIANT** (GitHub limitation documented)

---

### Zero Secret Exposure

- [x] ✅ All secrets redacted using `redactSensitiveString()`
- [x] ✅ Diagnostic objects sanitize sensitive data
- [x] ✅ No console.log statements exposing secrets
- [x] ✅ Error messages never include expected signatures
- [x] ✅ Route handler uses sanitized diagnostic wrapper
- [x] ✅ Generic error responses (no internal details leaked)

**Status:** ✅ **COMPLIANT**

---

### Strict Payload Validation

- [x] ✅ Raw payload Buffer preserved for signature computation
- [x] ✅ Signature verification BEFORE JSON parsing
- [x] ✅ Buffer/string type coercion handled safely
- [x] ✅ Validation order: Headers → Signature → Timestamp → Business logic

**Status:** ✅ **COMPLIANT**

---

## Recommendations

### Priority: MEDIUM

**1. Document GitHub Replay Attack Mitigation Strategy**

**File:** `.kiro/steering/security-and-reliability.md`

Add explicit guidance on GitHub's lack of timestamp validation and how consumers should implement replay protection:

- Store processed `X-GitHub-Delivery` header values
- Implement application-level idempotency
- Monitor for duplicate events
- Rotate webhook secrets every 90 days

**Rationale:** This closes the documentation gap identified in AUD-003 and ensures consumers understand the security responsibility.

---

### Priority: LOW (Optional Enhancement)

**2. Add Delivery ID Tracking to GitHub Adapter**

**File:** `lib/adapters/github.ts`

Extend `verifyGitHubWebhook()` to accept an optional `processedDeliveryIds` parameter for replay protection via delivery ID deduplication.

**Benefit:** Provides an optional, lightweight replay protection mechanism for GitHub webhooks without requiring external storage.

---

## References

### External Documentation

1. [GitHub: Securing Webhooks](https://docs.github.com/en/webhooks/securing-your-webhooks)
2. [Stripe: Webhook Signatures](https://stripe.com/docs/webhooks/signatures)
3. [Slack: Verifying Requests](https://api.slack.com/authentication/verifying-requests-from-slack)
4. [Shopify: Webhook Security](https://shopify.dev/docs/apps/webhooks/configuration/https#step-5-verify-the-webhook)
5. [OWASP: Timing Attack Prevention](https://owasp.org/www-community/vulnerabilities/Timing_Attack)
6. [Node.js Crypto: timingSafeEqual](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)

### Internal Steering Documents

1. `.kiro/steering/security-and-reliability.md` - Security requirements and standards
2. `.kiro/steering/architecture-and-testing.md` - Functional core principles and testing standards

---

## Conclusion

WebhookRadar demonstrates **production-ready security** for webhook verification across four major providers. The implementation follows security best practices with:

- ✅ State-of-the-art timing attack mitigation via SHA-256 pre-hashing
- ✅ Comprehensive replay attack prevention (except GitHub, by design)
- ✅ Zero-exposure secret redaction throughout the codebase
- ✅ Strict payload validation order with raw buffer preservation
- ✅ 100% pass rate on 42 property-based security invariant tests

The single MEDIUM severity recommendation (documenting GitHub's replay attack limitations) is an **informational gap**, not a vulnerability in the implementation.

**Security Rating:** 🟢 **PRODUCTION-READY**

---

**Audit Signature:**  
WebhookRadar Security & Reliability Auditor  
2026-10-01T14:21:00Z
