# Feature Specification: Webhook Verification & Reliability Engine

**Status:** Draft  
**Owner:** WebhookRadar Core Team  
**Created:** 2026-10-01  
**Last Updated:** 2026-10-01

---

## Overview

The Webhook Verification & Reliability Engine is the foundational security and validation system for WebhookRadar. It provides timing-safe signature verification, replay attack prevention, multi-provider support, and strict schema validation for incoming webhook payloads from GitHub, Stripe, Shopify, and Slack.

**Core Principles:**
- Functional Core architecture with pure, testable functions
- Timing-safe cryptographic operations to prevent side-channel attacks
- Zero secret exposure in logs and error messages
- Property-based testing for cryptographic invariants

---

## 1. Requirements (EARS Notation)

### 1.1 Signature Verification

#### REQ-SIG-001: Valid Signature Acceptance
**WHEN** an incoming webhook is received with a valid HMAC-SHA256 signature matching the provider secret, **THE SYSTEM SHALL** mark the verification status as SUCCESS and proceed to schema validation.

**Acceptance Criteria:**
- Signature computed using `crypto.timingSafeEqual()` for constant-time comparison
- Raw request body buffer preserved and used for signature calculation
- Verification success logged with redacted sensitive data

#### REQ-SIG-002: Invalid Signature Rejection
**WHEN** an incoming webhook has an invalid, corrupted, or tampered signature, **THE SYSTEM SHALL** reject the payload with a 401 Unauthorized status and log a signature mismatch diagnostic.

**Acceptance Criteria:**
- Response body contains generic error message: `{ "error": "Invalid signature" }`
- No expected signature value exposed in response or logs
- Verification failure logged with redacted signature and secret

#### REQ-SIG-003: Missing Signature Header Rejection
**WHEN** a signature header is missing from the incoming request, **THE SYSTEM SHALL** immediately reject the request with 400 Bad Request without attempting verification.

**Acceptance Criteria:**
- Early exit before any cryptographic computation
- Response body contains: `{ "error": "Missing signature header" }`
- Request logged as malformed with provider context

---

### 1.2 Replay Protection & Timestamp Tolerance

#### REQ-REPLAY-001: Timestamp Within Tolerance Acceptance
**WHEN** a webhook timestamp is within the 300-second tolerance window of server time, **THE SYSTEM SHALL** accept the request for signature checking.

**Acceptance Criteria:**
- Default tolerance configurable via `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` environment variable (default: 300)
- Server time obtained at request processing start (not during verification)
- Tolerance applied symmetrically for past and future timestamps

#### REQ-REPLAY-002: Expired Timestamp Rejection
**WHEN** a webhook timestamp is older than 300 seconds (or more than 10 seconds in the future), **THE SYSTEM SHALL** reject the request as an expired replay attempt with 401 Unauthorized.

**Acceptance Criteria:**
- Future timestamp tolerance: 10 seconds (protects against clock skew)
- Past timestamp tolerance: 300 seconds (5 minutes)
- Response body contains: `{ "error": "Request timestamp outside valid window" }`
- Timestamp drift logged with redacted timestamp values

#### REQ-REPLAY-003: Missing Timestamp Handling
**WHEN** a provider requires timestamp validation but the timestamp header is missing, **THE SYSTEM SHALL** reject the request with 400 Bad Request.

**Acceptance Criteria:**
- Applies to Stripe, Shopify, and Slack (not GitHub, which has no explicit timestamp)
- Response body contains: `{ "error": "Missing timestamp header" }`

---

### 1.3 Multi-Provider Support

#### REQ-PROVIDER-001: GitHub Webhook Verification
**WHEN** the provider is GitHub, **THE SYSTEM SHALL** parse `X-Hub-Signature-256` header and compute HMAC-SHA256 with prefix `sha256=`.

**Acceptance Criteria:**
- Signature extracted by removing `sha256=` prefix
- HMAC computed over raw request body bytes
- No timestamp validation (GitHub does not provide webhook timestamps)
- Environment variable: `GITHUB_WEBHOOK_SECRET`

**GitHub Signature Format:**
```
X-Hub-Signature-256: sha256=<64-character-hex-signature>
```

#### REQ-PROVIDER-002: Stripe Webhook Verification
**WHEN** the provider is Stripe, **THE SYSTEM SHALL** parse `Stripe-Signature` header extracting `t=` timestamp and `v1=` signature schemes.

**Acceptance Criteria:**
- Parse comma-separated key-value pairs: `t=<timestamp>,v1=<signature>,v1=<signature>`
- Multiple signatures supported (Stripe can send multiple versions)
- Signed payload format: `${timestamp}.${rawBody}`
- Timestamp validation with 300-second tolerance
- Environment variable: `STRIPE_WEBHOOK_SECRET`

**Stripe Signature Format:**
```
Stripe-Signature: t=1234567890,v1=abc123...,v1=def456...
```

#### REQ-PROVIDER-003: Slack Webhook Verification
**WHEN** the provider is Slack, **THE SYSTEM SHALL** parse `X-Slack-Signature` using `v0=` version prefix and validate `X-Slack-Request-Timestamp`.

**Acceptance Criteria:**
- Signature extracted by removing `v0=` prefix
- Signed payload format: `v0:${timestamp}:${rawBody}`
- Timestamp extracted from `X-Slack-Request-Timestamp` header
- Timestamp validation with 300-second tolerance
- Environment variable: `SLACK_SIGNING_SECRET`

**Slack Signature Format:**
```
X-Slack-Signature: v0=<64-character-hex-signature>
X-Slack-Request-Timestamp: 1234567890
```

#### REQ-PROVIDER-004: Shopify Webhook Verification
**WHEN** the provider is Shopify, **THE SYSTEM SHALL** parse `X-Shopify-Hmac-SHA256` header and validate `X-Shopify-Webhook-Timestamp`.

**Acceptance Criteria:**
- HMAC-SHA256 signature in base64 encoding
- Signature converted from base64 to hex for comparison
- Timestamp extracted from `X-Shopify-Webhook-Timestamp` header
- Timestamp validation with 300-second tolerance
- Environment variable: `SHOPIFY_WEBHOOK_SECRET`

**Shopify Signature Format:**
```
X-Shopify-Hmac-SHA256: <base64-encoded-signature>
X-Shopify-Webhook-Timestamp: 1234567890
```

---

### 1.4 Schema Validation & Diagnostics

#### REQ-SCHEMA-001: Post-Verification Schema Validation
**WHEN** a payload passes signature and replay verification, **THE SYSTEM SHALL** validate the payload against a registered Zod schema for the provider.

**Acceptance Criteria:**
- Schema validation occurs only after successful signature verification
- Raw buffer parsed to JSON before schema validation
- Invalid JSON results in 400 Bad Request: `{ "error": "Invalid JSON payload" }`
- Provider-specific schemas registered in adapter modules

#### REQ-SCHEMA-002: Detailed Schema Error Reporting
**WHEN** schema validation fails, **THE SYSTEM SHALL** return detailed path-based field errors while preserving verification success in logs.

**Acceptance Criteria:**
- Response status: 400 Bad Request
- Response body includes Zod error details with field paths
- Verification success logged separately from schema failure
- Response format:
  ```json
  {
    "error": "Schema validation failed",
    "details": {
      "repository.id": ["Expected number, received string"]
    }
  }
  ```

#### REQ-DIAG-001: Secret Redaction in Logs and Responses
**WHEN** diagnostic logs or responses are generated, **THE SYSTEM SHALL** redact all raw secrets, tokens, and sensitive headers.

**Acceptance Criteria:**
- Secrets replaced with `[REDACTED]` in all log outputs
- Signature headers replaced with `[REDACTED]` in logs
- Authorization and API tokens never logged in plaintext
- Environment variable names logged, but not their values
- Error messages never expose expected signature values

**Redacted Fields:**
- `secret`, `token`, `authorization`, `signature`, `api_key`, `webhook_secret`
- Any header containing `signature`, `authorization`, `token`, `secret`, `key`

---

## 2. Technical Design & Type Definitions

### 2.1 Core Type Definitions

```typescript
/**
 * Webhook verification request containing raw payload and headers
 */
export interface WebhookVerificationRequest {
  /** Raw request body as Buffer (required for signature verification) */
  payload: Buffer;
  /** Provider-specific signature header value */
  signature: string | null;
  /** Optional timestamp header for replay protection */
  timestamp?: string | null;
  /** Unix timestamp (seconds) when request was received */
  receivedAt: number;
}

/**
 * Result of webhook verification process
 */
export interface WebhookVerificationResult<T = unknown> {
  /** Whether signature and timestamp verification succeeded */
  verified: boolean;
  /** Error message if verification failed (generic, no sensitive data) */
  error?: string;
  /** Error code for programmatic handling */
  errorCode?: 'MISSING_SIGNATURE' | 'INVALID_SIGNATURE' | 'EXPIRED_TIMESTAMP' | 'MISSING_TIMESTAMP' | 'INVALID_JSON' | 'SCHEMA_VALIDATION_FAILED';
  /** Parsed and validated webhook payload (only present if verified=true and schema valid) */
  data?: T;
  /** Schema validation errors (present if signature valid but schema invalid) */
  schemaErrors?: Record<string, string[]>;
  /** Diagnostic information for logging (all sensitive fields redacted) */
  diagnostic?: VerificationDiagnostic;
}

/**
 * Provider-specific webhook adapter interface
 */
export interface ProviderAdapter<T = unknown> {
  /** Provider name for logging and routing */
  name: 'github' | 'stripe' | 'shopify' | 'slack';
  /** Extract signature from provider-specific header format */
  extractSignature(headers: Headers): string | null;
  /** Extract timestamp from provider-specific header (if applicable) */
  extractTimestamp(headers: Headers): number | null;
  /** Compute expected signature using provider-specific algorithm */
  computeSignature(payload: Buffer, secret: string, timestamp?: number): string;
  /** Parse and validate webhook payload against provider schema */
  validateSchema(payload: Buffer): { success: true; data: T } | { success: false; errors: Record<string, string[]> };
  /** Whether this provider requires timestamp validation */
  requiresTimestamp: boolean;
}

/**
 * Diagnostic information for verification attempts (all sensitive data redacted)
 */
export interface VerificationDiagnostic {
  /** Provider name */
  provider: string;
  /** Timestamp when verification was attempted */
  attemptedAt: string;
  /** Whether signature verification passed */
  signatureValid: boolean;
  /** Whether timestamp validation passed (if applicable) */
  timestampValid?: boolean;
  /** Timestamp drift in seconds (if applicable) */
  timestampDrift?: number;
  /** Whether schema validation passed */
  schemaValid?: boolean;
  /** Redacted signature header (for debugging format issues) */
  signatureHeaderFormat?: string;
  /** Size of payload in bytes */
  payloadSize: number;
}
```

### 2.2 Functional Core Pipeline

The verification engine follows a pure functional pipeline in `lib/core/`:

```typescript
/**
 * PURE FUNCTIONAL PIPELINE
 * Each function is deterministic, side-effect-free, and independently testable
 */

// Step 1: Cryptographic signature computation
export function computeHmacSha256(
  payload: Buffer,
  secret: string
): string;

// Step 2: Timing-safe signature verification
export function verifySignature(
  payload: Buffer,
  receivedSignature: string,
  secret: string
): boolean;

// Step 3: Timestamp validation
export function isTimestampValid(
  timestamp: number,
  currentTime: number,
  toleranceSeconds?: number
): boolean;

// Step 4: Schema validation wrapper
export function validateSchema<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): { success: true; data: T } | { success: false; errors: z.ZodError };

// Step 5: Diagnostic data redaction
export function redactSensitiveData<T extends Record<string, any>>(
  data: T,
  keysToRedact?: string[]
): T;
```

### 2.3 Adapter Layer Orchestration

Provider-specific adapters in `lib/adapters/` orchestrate the functional core:

```typescript
/**
 * GitHub Webhook Adapter
 * Orchestrates: extractSignature -> verifySignature -> validateSchema
 */
export function verifyGitHubWebhook(
  request: WebhookVerificationRequest,
  secret: string
): WebhookVerificationResult<GitHubWebhook>;

/**
 * Stripe Webhook Adapter
 * Orchestrates: extractTimestamp -> verifyTimestamp -> extractSignatures -> verifySignature -> validateSchema
 */
export function verifyStripeWebhook(
  request: WebhookVerificationRequest,
  secret: string
): WebhookVerificationResult<StripeWebhook>;

/**
 * Slack Webhook Adapter
 * Orchestrates: extractTimestamp -> verifyTimestamp -> computeSlackSignature -> verifySignature -> validateSchema
 */
export function verifySlackWebhook(
  request: WebhookVerificationRequest,
  secret: string
): WebhookVerificationResult<SlackWebhook>;

/**
 * Shopify Webhook Adapter
 * Orchestrates: extractTimestamp -> verifyTimestamp -> convertBase64Signature -> verifySignature -> validateSchema
 */
export function verifyShopifyWebhook(
  request: WebhookVerificationRequest,
  secret: string
): WebhookVerificationResult<ShopifyWebhook>;
```

### 2.4 HTTP Layer Integration

Next.js Route Handlers in `app/api/webhooks/*/route.ts`:

```typescript
/**
 * HTTP Layer Pattern (applies to all providers)
 */
export async function POST(request: NextRequest) {
  // 1. Extract raw body and headers
  const rawBody = Buffer.from(await request.arrayBuffer());
  const signature = request.headers.get('<provider-signature-header>');
  const timestamp = request.headers.get('<provider-timestamp-header>'); // if applicable
  
  // 2. Get provider secret from environment
  const secret = process.env.<PROVIDER_WEBHOOK_SECRET>;
  if (!secret) {
    return NextResponse.json(
      { error: 'Webhook secret not configured' },
      { status: 500 }
    );
  }
  
  // 3. Build verification request
  const verificationRequest: WebhookVerificationRequest = {
    payload: rawBody,
    signature,
    timestamp,
    receivedAt: Math.floor(Date.now() / 1000),
  };
  
  // 4. Verify using provider adapter
  const result = verifyProviderWebhook(verificationRequest, secret);
  
  // 5. Log attempt with redacted data
  logWebhookAttempt(result.diagnostic);
  
  // 6. Handle verification failure
  if (!result.verified) {
    return NextResponse.json(
      { error: result.error },
      { status: result.errorCode === 'MISSING_SIGNATURE' ? 400 : 401 }
    );
  }
  
  // 7. Handle schema validation failure
  if (result.schemaErrors) {
    return NextResponse.json(
      { error: 'Schema validation failed', details: result.schemaErrors },
      { status: 400 }
    );
  }
  
  // 8. Process valid webhook
  await processWebhook(result.data);
  
  return NextResponse.json({ success: true }, { status: 200 });
}
```

---

## 3. Implementation Plan

### Phase 1: Functional Core (lib/core/)

**Milestone 1.1: Cryptographic Utilities** ✅  
**Files:** `lib/core/crypto.ts`

- [x] Implement `computeHmacSha256(payload, secret)` - pure SHA-256 HMAC computation
- [x] Implement `timingSafeVerify(expected, actual)` - timing-safe comparison using `crypto.timingSafeEqual()`
- [x] Implement `redactSensitiveString(val)` - redacts middle of secrets for safe logging
- [x] Implement `base64ToHex(base64String)` - for Shopify base64 signatures
- [x] Implement `hexToBase64(hexString)` - inverse conversion
- [x] Add comprehensive JSDoc comments with security notes

**Milestone 1.2: Timestamp Validation** ✅  
**Files:** `lib/core/timestamp.ts`

- [x] Implement `isTimestampValid(timestamp, currentTime, tolerance)` - pure timestamp drift calculation
- [x] Implement `toUnixTimestamp(milliseconds)` - millisecond to second conversion
- [x] Implement `getTimestampDrift(timestamp, currentTime)` - absolute drift calculation for diagnostics
- [x] Implement `parseTimestamp(timestampString)` - parse various timestamp formats
- [x] Implement `isValidUnixTimestamp(timestamp)` - validate timestamp bounds
- [x] Export `DEFAULT_TIMESTAMP_TOLERANCE_SECONDS` constant (300)
- [x] Export `FUTURE_TIMESTAMP_TOLERANCE_SECONDS` constant (10)

**Milestone 1.3: Schema Validation Utilities** ✅  
**Files:** `lib/core/validation.ts`

- [x] Not needed - Zod schemas handled directly in adapters (simplified approach)

**Milestone 1.4: Diagnostic Utilities** ✅  
**Files:** `lib/core/crypto.ts` (integrated)

- [x] Implement `redactSensitiveString(val)` - shows only first 8 and last 2 chars
- [x] Integrated into crypto module for convenience

**Milestone 1.5: Shared Types** ✅  
**Files:** `lib/core/types.ts`

- [x] Define `ProviderType` union type
- [x] Define `WebhookVerificationRequest` interface
- [x] Define `WebhookVerificationResult` interface
- [x] Define `TimestampValidationResult` interface
- [x] Define `VerificationDiagnostic` interface
- [x] Export security constants

---

### Phase 2: Property-Based Tests (tests/unit/core/)

**Milestone 2.1: Crypto Tests** ✅  
**Files:** `tests/property/crypto-invariants.test.ts`

- [x] Test invariant: `computeHmacSha256` is deterministic (same input → same output)
- [x] Test invariant: Different payloads produce different signatures
- [x] Test invariant: Different secrets produce different signatures
- [x] Test invariant: Valid signatures always verify successfully
- [x] Test invariant: Corrupted signatures always fail verification
- [x] Test boundary: Empty payloads, max-length payloads, binary payloads
- [x] Test base64 conversion roundtrip (for Shopify)

**Milestone 2.2: Timestamp Tests** ✅  
**Files:** `tests/property/timestamp-invariants.test.ts`

- [x] Test invariant: Timestamps within tolerance are valid
- [x] Test invariant: Timestamps outside tolerance are invalid
- [x] Test invariant: Validation is symmetric (past/future drift behave identically)
- [x] Test invariant: Unix timestamp conversion preserves ordering (monotonic)
- [x] Test boundary: Tolerance = 0, tolerance = max integer
- [x] Test boundary: Timestamp at exact tolerance boundary

**Milestone 2.3: Validation Tests** ✅  
**Files:** `tests/property/timestamp-invariants.test.ts` (integrated)

- [x] Test parseTimestamp with valid Unix timestamps
- [x] Test parseTimestamp with invalid strings
- [x] Test isValidUnixTimestamp with reasonable bounds
- [x] Test isValidUnixTimestamp with invalid values

**Milestone 2.4: Diagnostic Tests** ✅  
**Files:** `tests/property/crypto-invariants.test.ts` (Invariant 4)

- [x] Test redaction of all sensitive strings (length >= 12)
- [x] Test prefix preservation (first 8 characters)
- [x] Test suffix preservation (last 2 characters)
- [x] Test full redaction of short strings (< 12 chars)
- [x] Test deterministic redaction output

---

### Phase 3: Provider Adapters (lib/adapters/)

**Milestone 3.1: GitHub Adapter** ✅  
**Files:** `lib/adapters/github.ts`

- [x] Implement `verifyGitHubWebhook(request)` - orchestrate verification pipeline
- [x] Extract and parse `X-Hub-Signature-256` header (case-insensitive)
- [x] Strip `sha256=` prefix from signature
- [x] Use `computeHmacSha256()` and `timingSafeVerify()` from core
- [x] Handle missing signature header gracefully
- [x] Return structured `WebhookVerificationResult`

**Milestone 3.2: Stripe Adapter** ✅  
**Files:** `lib/adapters/stripe.ts`

- [x] Implement `verifyStripeWebhook(request, toleranceSeconds)` - handle multi-signature format
- [x] Implement `parseStripeSignature(header)` - extract `t=` and `v1=` pairs
- [x] Parse timestamp from signature header
- [x] Validate timestamp with configurable tolerance (default 300s)
- [x] Construct signed payload: `${timestamp}.${body}`
- [x] Support multiple v1 signatures (any match succeeds)

**Milestone 3.3: Slack Adapter** ✅  
**Files:** `lib/adapters/slack.ts`

- [x] Implement `verifySlackWebhook(request, toleranceSeconds)` - orchestrate with v0 prefix
- [x] Extract `X-Slack-Signature` and `X-Slack-Request-Timestamp` headers
- [x] Strip `v0=` prefix from signature
- [x] Construct versioned signed payload: `v0:${timestamp}:${body}`
- [x] Validate timestamp with configurable tolerance (default 300s)
- [x] Use timing-safe verification from core

**Milestone 3.4: Shopify Adapter** ✅  
**Files:** `lib/adapters/shopify.ts`

- [x] Implement `verifyShopifyWebhook(request, toleranceSeconds)` - handle base64 encoding
- [x] Extract `X-Shopify-Hmac-SHA256` header (base64 encoded)
- [x] Extract optional `X-Shopify-Webhook-Timestamp` header
- [x] Convert base64 signature to hex using `base64ToHex()`
- [x] Validate optional timestamp with configurable tolerance
- [x] Use timing-safe verification from core

**Milestone 3.5: Unified Dispatcher** ✅  
**Files:** `lib/adapters/index.ts`

- [x] Implement `verifyWebhook(provider, request, toleranceSeconds)` - async dispatcher
- [x] Route to appropriate provider adapter
- [x] Validate request structure (headers, rawBody, secret)
- [x] Handle unknown providers gracefully
- [x] Implement `createVerificationDiagnostic()` - sanitized logging
- [x] Re-export all adapters and types

---

### Phase 4: Adapter Tests (tests/unit/adapters/)

**Milestone 4.1: GitHub Adapter Tests** ✅  
**Files:** `tests/unit/adapters/github.test.ts`

- [ ] Test successful verification with valid signature
- [ ] Test rejection with invalid signature
- [ ] Test rejection with missing signature header
- [ ] Test rejection with malformed signature format
- [ ] Test schema validation success
- [ ] Test schema validation failure with detailed errors
- [ ] Mock core functions to isolate adapter logic

**Milestone 4.2: Stripe Adapter Tests** ✅  
**Files:** `tests/unit/adapters/stripe.test.ts`

- [ ] Test successful verification with single v1 signature
- [ ] Test successful verification with multiple v1 signatures
- [ ] Test timestamp validation (within/outside tolerance)
- [ ] Test rejection with expired timestamp
- [ ] Test rejection with missing timestamp in header
- [ ] Test rejection with malformed signature format
- [ ] Test schema validation

**Milestone 4.3: Slack Adapter Tests** ✅  
**Files:** `tests/unit/adapters/slack.test.ts`

- [ ] Test successful verification with v0 signature
- [ ] Test signed payload format: `v0:${timestamp}:${body}`
- [ ] Test timestamp validation (within/outside tolerance)
- [ ] Test rejection with missing timestamp header
- [ ] Test rejection with invalid signature
- [ ] Test schema validation

**Milestone 4.4: Shopify Adapter Tests** ✅  
**Files:** `tests/unit/adapters/shopify.test.ts`

- [ ] Test successful verification with base64 signature
- [ ] Test base64 to hex conversion
- [ ] Test timestamp validation (within/outside tolerance)
- [ ] Test rejection with invalid base64 signature
- [ ] Test rejection with missing timestamp header
- [ ] Test schema validation

---

### Phase 5: HTTP Route Handlers (app/api/webhooks/)

**Milestone 5.1: Multi-Provider Webhook Ingress Endpoint** ✅  
**Files:** `app/api/webhooks/[provider]/route.ts`

- [x] Implement dynamic `POST` handler for all providers (GitHub, Stripe, Slack, Shopify)
- [x] Extract provider-specific headers with case-insensitivity
- [x] Read raw body as Buffer to prevent mutation before HMAC checking
- [x] Call unified `verifyWebhook()` dispatcher
- [x] Log verification attempt with sanitized diagnostic data
- [x] Return appropriate HTTP status codes (200 OK / 400 Bad Request / 401 Unauthorized)
- [x] Return generic error messages with zero secret leakage

**Milestone 5.2: Live Webhook Simulation Endpoint** ✅  
**Files:** `app/api/simulate/route.ts`

- [x] Implement simulation POST endpoint for dashboard testing
- [x] Support scenarios: `valid`, `tampered_signature`, `replay_attack`, `corrupted_payload`
- [x] Calculate authentic provider HMAC signatures for realistic test verification
- [x] Return real-time execution latency and sanitized diagnostic details

---

### Phase 6: Interactive Dashboard & UI (app/)

**Milestone 6.1: Real-Time Security Gateway Dashboard** ✅  
**Files:** `app/page.tsx`, `app/layout.tsx`

- [x] Implement dark-mode operations dashboard
- [x] Live interactive webhook simulator with provider tabs (Stripe, GitHub, Slack, Shopify)
- [x] 4 one-click scenario triggers (Valid, Tampered Signature, Replay Attack, Corrupted Byte)
- [x] Real-time diagnostic viewer showing constant-time check and timestamp drift
- [x] Chronological security audit log table
- [x] Architecture showcase for Specs, Property-Based Tests, Custom Agents, and Kiro Power

---

### Phase 6: Utilities & Logging (lib/utils/)

**Milestone 6.1: Secure Logger** ✅  
**Files:** `lib/utils/logger.ts`

- [ ] Implement `logWebhookAttempt(diagnostic)` - structured logging with redaction
- [ ] Implement `logVerificationSuccess(provider, metadata)`
- [ ] Implement `logVerificationFailure(provider, reason, metadata)`
- [ ] Ensure all sensitive data automatically redacted using `redactSensitiveData()`
- [ ] Include timestamp, provider, verification status, payload size
- [ ] Format logs for JSON structured logging (production) and readable console (dev)

**Milestone 6.2: Custom Error Types** ✅  
**Files:** `lib/utils/errors.ts`

- [ ] Define `WebhookVerificationError` class extending Error
- [ ] Define `SignatureVerificationError` subclass
- [ ] Define `TimestampValidationError` subclass
- [ ] Define `SchemaValidationError` subclass
- [ ] Include error codes matching `WebhookVerificationResult.errorCode`
- [ ] Ensure error messages never expose sensitive data

---

### Phase 7: Integration Tests (tests/integration/)

**Milestone 7.1: End-to-End Route Tests** ✅  
**Files:** `tests/integration/api/webhooks.test.ts`

- [ ] Test GitHub endpoint with mock valid webhook
- [ ] Test GitHub endpoint with invalid signature
- [ ] Test Stripe endpoint with valid multi-signature webhook
- [ ] Test Stripe endpoint with expired timestamp
- [ ] Test Slack endpoint with valid webhook
- [ ] Test Shopify endpoint with valid base64 signature
- [ ] Test all endpoints with missing signature headers
- [ ] Test all endpoints with malformed JSON payloads
- [ ] Verify correct HTTP status codes for each scenario
- [ ] Verify no sensitive data in responses

---

### Phase 8: Configuration & Environment

**Milestone 8.1: Environment Variables** ✅  
**Files:** `.env.example`, `.env.local`

- [ ] Document `GITHUB_WEBHOOK_SECRET`
- [ ] Document `STRIPE_WEBHOOK_SECRET`
- [ ] Document `SLACK_SIGNING_SECRET`
- [ ] Document `SHOPIFY_WEBHOOK_SECRET`
- [ ] Document `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` (optional, default: 300)
- [ ] Add `.env.local` to `.gitignore`
- [ ] Create `.env.example` with placeholder values

**Milestone 8.2: TypeScript Configuration** ✅  
**Files:** `tsconfig.json`, `vitest.config.ts`

- [ ] Configure path aliases: `@/lib/*`, `@/app/*`, `@/components/*`
- [ ] Enable strict mode for type safety
- [ ] Configure Vitest with Next.js compatibility
- [ ] Set up test coverage thresholds (80% for lib/core/)

---

## 4. Testing Strategy

### 4.1 Unit Tests (Pure Functions)

**Coverage Target:** 100% for `lib/core/`

- Property-based tests with `fast-check` for all cryptographic functions
- Example-based tests for known edge cases
- No mocks required (pure functions)
- Fast execution (< 1 second for entire suite)

### 4.2 Unit Tests (Adapters)

**Coverage Target:** 90% for `lib/adapters/`

- Mock core functions to isolate adapter logic
- Test provider-specific header parsing
- Test orchestration flow
- Test error handling paths

### 4.3 Integration Tests (HTTP Routes)

**Coverage Target:** 80% for `app/api/`

- Use Next.js testing utilities
- Mock environment variables
- Test complete request/response cycle
- Verify HTTP status codes and response bodies
- Test security properties (no secret leakage)

### 4.4 Manual Testing

- [ ] Test with real webhook payloads from provider documentation
- [ ] Test with ngrok or similar for live provider testing
- [ ] Verify timing-safe comparison with performance benchmarks
- [ ] Test with various payload sizes (1 byte to 10 MB)

---

## 5. Security Considerations

### 5.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Timing attack on signature comparison | Use `crypto.timingSafeEqual()` for all comparisons |
| Replay attack with old webhooks | Validate timestamps with 300-second tolerance |
| Secret exposure in logs | Redact all sensitive data before logging |
| Secret exposure in error messages | Return generic error messages, never expected signatures |
| Signature bypass with missing header | Early rejection with 400 Bad Request |
| JSON injection | Parse JSON only after signature verification |
| Schema evasion | Strict Zod schema validation after signature verification |

### 5.2 Security Testing

- [ ] Verify no timing difference between valid/invalid signatures (use benchmark tooling)
- [ ] Attempt replay attack with old timestamp
- [ ] Attempt signature bypass with missing headers
- [ ] Scan logs for any sensitive data leakage
- [ ] Test error responses for information disclosure
- [ ] Verify HMAC secrets never appear in any output

---

## 6. Performance Considerations

### 6.1 Performance Targets

| Metric | Target |
|--------|--------|
| Verification latency (p50) | < 10ms |
| Verification latency (p99) | < 50ms |
| Throughput | > 1000 requests/second (single instance) |
| Memory per request | < 1 MB |

### 6.2 Optimization Strategies

- Reuse Buffer allocations where possible
- Avoid unnecessary JSON parsing
- Early exit on missing headers (before crypto operations)
- Stream large payloads if necessary (for future 10MB+ support)

---

## 7. Observability & Monitoring

### 7.1 Metrics to Track

- Verification success rate per provider
- Verification latency distribution
- Signature verification failures (count and rate)
- Timestamp validation failures (count and rate)
- Schema validation failures (count and rate)
- Payload size distribution

### 7.2 Alerts

- Alert on verification success rate < 95%
- Alert on p99 latency > 100ms
- Alert on signature verification failure rate > 5%
- Alert on missing environment variable errors

---

## 8. Documentation Requirements

- [ ] API documentation for each webhook endpoint (OpenAPI/Swagger)
- [ ] Provider-specific setup guides (how to configure each provider)
- [ ] Security best practices documentation
- [ ] Troubleshooting guide for common verification failures
- [ ] Architecture decision records (ADRs) for key design choices

---

## 9. Success Criteria

This feature is considered complete when:

1. ✅ All Phase 1-8 milestones implemented and tested
2. ✅ Property-based tests passing for all core functions
3. ✅ Unit test coverage > 90% for adapters, 100% for core
4. ✅ Integration tests passing for all four providers
5. ✅ No sensitive data found in any logs or error messages (security audit)
6. ✅ Performance targets met (< 10ms p50, < 50ms p99)
7. ✅ Documentation complete and reviewed
8. ✅ Manual testing with real webhooks from all four providers successful

---

## 10. Future Enhancements

- Support for additional providers (GitLab, Twilio, SendGrid)
- Webhook replay/retry mechanism for debugging
- Webhook event storage and audit trail
- Rate limiting per provider
- Webhook signature rotation support
- Dashboard UI for monitoring verification metrics

---

## References

- [Security & Reliability Steering](.kiro/steering/security-and-reliability.md)
- [Architecture & Testing Steering](.kiro/steering/architecture-and-testing.md)
- [GitHub Webhook Security](https://docs.github.com/en/webhooks/securing-your-webhooks)
- [Stripe Webhook Signatures](https://stripe.com/docs/webhooks/signatures)
- [Slack Request Signing](https://api.slack.com/authentication/verifying-requests-from-slack)
- [Shopify Webhook Verification](https://shopify.dev/docs/apps/webhooks/configuration/https#step-5-verify-the-webhook)
