# Architecture and Testing Standards for WebhookRadar

This document defines the architectural patterns, directory structure, and testing conventions for WebhookRadar.

---

## 1. Clean Architecture & Functional Core

**MANDATE:** Enforce strict separation of concerns using the Functional Core, Imperative Shell pattern.

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                     UI Layer (React)                        │
│              components/, app/*/page.tsx                    │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  HTTP Layer (Next.js)                       │
│                   app/api/*/route.ts                        │
│         (I/O, Request/Response, Side Effects)               │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Adapter Layer (Provider-Specific)              │
│                   lib/adapters/                             │
│     (GitHub, Stripe, Shopify, Slack implementations)        │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Functional Core (Pure Logic)                   │
│                     lib/core/                               │
│   (Deterministic, no I/O, no side effects, easy to test)   │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
webhookradar/
├── app/
│   ├── api/
│   │   ├── webhooks/
│   │   │   ├── github/route.ts       # GitHub webhook endpoint
│   │   │   ├── stripe/route.ts       # Stripe webhook endpoint
│   │   │   ├── shopify/route.ts      # Shopify webhook endpoint
│   │   │   └── slack/route.ts        # Slack webhook endpoint
│   │   └── status/route.ts           # Health check endpoint
│   ├── dashboard/
│   │   └── page.tsx                  # Dashboard UI
│   └── layout.tsx
├── components/
│   ├── ui/                           # shadcn/ui components
│   ├── WebhookList.tsx               # Webhook event list
│   ├── WebhookDetails.tsx            # Event detail view
│   └── ProviderCard.tsx              # Provider status card
├── lib/
│   ├── core/                         # ⭐ FUNCTIONAL CORE (Pure)
│   │   ├── crypto.ts                 # HMAC, signature verification
│   │   ├── timestamp.ts              # Timestamp validation
│   │   ├── validation.ts             # Schema validation utilities
│   │   └── types.ts                  # Shared type definitions
│   ├── adapters/                     # Provider-specific logic
│   │   ├── github.ts                 # GitHub webhook adapter
│   │   ├── stripe.ts                 # Stripe webhook adapter
│   │   ├── shopify.ts                # Shopify webhook adapter
│   │   └── slack.ts                  # Slack webhook adapter
│   └── utils/
│       ├── logger.ts                 # Logging with redaction
│       └── errors.ts                 # Custom error types
└── tests/
    ├── unit/
    │   ├── core/                     # Tests for lib/core/
    │   └── adapters/                 # Tests for lib/adapters/
    └── integration/
        └── api/                      # API endpoint tests
```

---

## 2. Functional Core Principles

### lib/core/: Pure, Deterministic Functions

**Rules:**
- ✅ **Pure functions only** (same input → same output)
- ✅ **No side effects** (no I/O, no mutations, no network calls, no logging)
- ✅ **Deterministic** (no `Date.now()`, no `Math.random()`)
- ✅ **Easy to test** (no mocks required)
- ✅ **Accept time as parameter** (for testability)

### Example: lib/core/crypto.ts

```typescript
import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Pure function: Computes HMAC-SHA256 signature
 * No side effects, fully deterministic
 */
export function computeHmacSha256(
  payload: Buffer,
  secret: string
): string {
  return createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
}

/**
 * Pure function: Timing-safe signature comparison
 * No side effects, returns boolean
 */
export function verifySignature(
  payload: Buffer,
  receivedSignature: string,
  secret: string
): boolean {
  const expectedSignature = computeHmacSha256(payload, secret);
  
  try {
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');
    const receivedBuffer = Buffer.from(receivedSignature, 'hex');
    
    if (expectedBuffer.length !== receivedBuffer.length) {
      return false;
    }
    
    return timingSafeEqual(expectedBuffer, receivedBuffer);
  } catch {
    return false;
  }
}
```

### Example: lib/core/timestamp.ts

```typescript
/**
 * Pure function: Validates timestamp within tolerance
 * Accepts current time as parameter (no Date.now() inside)
 */
export function isTimestampValid(
  timestamp: number,
  currentTime: number,
  toleranceSeconds: number = 300
): boolean {
  const timeDifference = Math.abs(currentTime - timestamp);
  return timeDifference <= toleranceSeconds;
}

/**
 * Pure function: Converts milliseconds to Unix timestamp
 */
export function toUnixTimestamp(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}
```

### Example: lib/core/validation.ts

```typescript
import { z } from 'zod';

/**
 * Pure function: Validates data against schema
 * Returns result object, no exceptions
 */
export function validateSchema<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): { success: true; data: T } | { success: false; errors: z.ZodError } {
  const result = schema.safeParse(data);
  
  if (result.success) {
    return { success: true, data: result.data };
  }
  
  return { success: false, errors: result.error };
}
```

---

## 3. Adapter Layer: Provider-Specific Logic

### lib/adapters/: Orchestrates Core Functions

**Rules:**
- ✅ Imports pure functions from `lib/core/`
- ✅ Handles provider-specific header parsing
- ✅ Orchestrates validation flow
- ✅ May perform side effects (logging, metrics)
- ✅ Returns structured results

### Example: lib/adapters/github.ts

```typescript
import { verifySignature } from '@/lib/core/crypto';
import { isTimestampValid, toUnixTimestamp } from '@/lib/core/timestamp';
import { z } from 'zod';

const GitHubWebhookSchema = z.object({
  action: z.string(),
  repository: z.object({
    id: z.number(),
    name: z.string(),
    full_name: z.string(),
  }),
  sender: z.object({
    id: z.number(),
    login: z.string(),
  }),
});

export type GitHubWebhook = z.infer<typeof GitHubWebhookSchema>;

export interface GitHubVerificationResult {
  verified: boolean;
  error?: string;
  webhook?: GitHubWebhook;
}

/**
 * Adapter function: Orchestrates GitHub webhook verification
 * Uses pure functions from lib/core/
 */
export function verifyGitHubWebhook(
  payload: Buffer,
  signatureHeader: string | null,
  secret: string,
  currentTime?: number
): GitHubVerificationResult {
  // 1. Validate signature header presence
  if (!signatureHeader) {
    return { verified: false, error: 'Missing signature header' };
  }
  
  // 2. Extract signature (GitHub format: sha256=...)
  const signature = signatureHeader.replace('sha256=', '');
  
  // 3. Verify signature using pure function
  if (!verifySignature(payload, signature, secret)) {
    return { verified: false, error: 'Invalid signature' };
  }
  
  // 4. Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload.toString('utf8'));
  } catch {
    return { verified: false, error: 'Invalid JSON' };
  }
  
  // 5. Validate schema
  const result = GitHubWebhookSchema.safeParse(parsed);
  if (!result.success) {
    return { verified: false, error: 'Schema validation failed' };
  }
  
  return { verified: true, webhook: result.data };
}
```

---

## 4. HTTP Layer: Next.js Route Handlers

### app/api/: Request/Response Handling

**Rules:**
- ✅ Handles HTTP-specific concerns (headers, status codes)
- ✅ Reads request body as Buffer
- ✅ Calls adapter functions
- ✅ Returns appropriate HTTP responses
- ✅ Logs with redacted sensitive data

### Example: app/api/webhooks/github/route.ts

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { verifyGitHubWebhook } from '@/lib/adapters/github';
import { logWebhookAttempt } from '@/lib/utils/logger';

export async function POST(request: NextRequest) {
  // 1. Extract headers and raw body
  const signature = request.headers.get('x-hub-signature-256');
  const rawBody = Buffer.from(await request.arrayBuffer());
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  
  // 2. Validate environment configuration
  if (!secret) {
    return NextResponse.json(
      { error: 'Webhook secret not configured' },
      { status: 500 }
    );
  }
  
  // 3. Verify webhook using adapter
  const result = verifyGitHubWebhook(
    rawBody,
    signature,
    secret,
    Date.now()
  );
  
  // 4. Log attempt (with redacted data)
  logWebhookAttempt({
    provider: 'github',
    verified: result.verified,
    error: result.error,
  });
  
  // 5. Handle verification failure
  if (!result.verified) {
    return NextResponse.json(
      { error: result.error || 'Verification failed' },
      { status: 401 }
    );
  }
  
  // 6. Process webhook (business logic)
  const webhook = result.webhook!;
  // ... store in database, trigger actions, etc.
  
  return NextResponse.json({ success: true }, { status: 200 });
}
```

---

## 5. Property-Based Testing Standards

**MANDATE:** All functions in `lib/core/` MUST have property-based tests using `vitest` and `fast-check`.

### Why Property-Based Testing?

Property-based testing verifies system **invariants** across thousands of randomly generated inputs, catching edge cases that example-based tests miss.

### Testing Invariants

| Invariant | Description |
|-----------|-------------|
| **Identity** | Encoding then decoding returns original value |
| **Idempotence** | Applying operation twice = applying once |
| **Commutativity** | Order of operations doesn't matter |
| **Associativity** | Grouping of operations doesn't matter |
| **Inverse** | Operation has a reverse operation |
| **Boundary** | Function behaves correctly at limits |

### Example: tests/unit/core/crypto.test.ts

```typescript
import { describe, it, expect } from 'vitest';
import { fc } from 'fast-check';
import { computeHmacSha256, verifySignature } from '@/lib/core/crypto';

describe('crypto', () => {
  describe('computeHmacSha256', () => {
    it('should produce deterministic output for same input', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          (payloadArray, secret) => {
            const payload = Buffer.from(payloadArray);
            const sig1 = computeHmacSha256(payload, secret);
            const sig2 = computeHmacSha256(payload, secret);
            
            // Invariant: Same input → same output
            expect(sig1).toBe(sig2);
          }
        )
      );
    });
    
    it('should produce different signatures for different payloads', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          (payload1Array, payload2Array, secret) => {
            const payload1 = Buffer.from(payload1Array);
            const payload2 = Buffer.from(payload2Array);
            
            // Skip if payloads are identical
            if (Buffer.compare(payload1, payload2) === 0) return;
            
            const sig1 = computeHmacSha256(payload1, secret);
            const sig2 = computeHmacSha256(payload2, secret);
            
            // Invariant: Different payloads → different signatures
            expect(sig1).not.toBe(sig2);
          }
        )
      );
    });
  });
  
  describe('verifySignature', () => {
    it('should accept valid signatures', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          (payloadArray, secret) => {
            const payload = Buffer.from(payloadArray);
            const signature = computeHmacSha256(payload, secret);
            
            // Invariant: Computed signature is always valid
            expect(verifySignature(payload, signature, secret)).toBe(true);
          }
        )
      );
    });
    
    it('should reject signatures with corrupted bytes', () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 1000 }),
          fc.string({ minLength: 1, maxLength: 100 }),
          fc.integer({ min: 0, max: 63 }), // hex string position
          (payloadArray, secret, corruptPosition) => {
            const payload = Buffer.from(payloadArray);
            const validSignature = computeHmacSha256(payload, secret);
            
            // Corrupt one hex character
            const chars = validSignature.split('');
            if (corruptPosition >= chars.length) return;
            
            chars[corruptPosition] = chars[corruptPosition] === '0' ? '1' : '0';
            const corruptedSignature = chars.join('');
            
            // Invariant: Corrupted signature is rejected
            expect(verifySignature(payload, corruptedSignature, secret)).toBe(false);
          }
        )
      );
    });
  });
});
```

### Example: tests/unit/core/timestamp.test.ts

```typescript
import { describe, it, expect } from 'vitest';
import { fc } from 'fast-check';
import { isTimestampValid, toUnixTimestamp } from '@/lib/core/timestamp';

describe('timestamp', () => {
  describe('isTimestampValid', () => {
    it('should accept timestamps within tolerance', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 9999999999 }), // Unix timestamp
          fc.integer({ min: 0, max: 300 }), // Drift within tolerance
          fc.integer({ min: 1, max: 600 }), // Tolerance
          (baseTime, drift, tolerance) => {
            const timestamp = baseTime;
            const currentTime = baseTime + drift;
            
            // Invariant: Timestamp within tolerance is valid
            const valid = isTimestampValid(timestamp, currentTime, tolerance);
            expect(valid).toBe(drift <= tolerance);
          }
        )
      );
    });
    
    it('should reject timestamps outside tolerance', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 9999999999 }),
          fc.integer({ min: 301, max: 10000 }), // Drift exceeds default 300s
          (baseTime, drift) => {
            const timestamp = baseTime;
            const currentTime = baseTime + drift;
            
            // Invariant: Timestamp outside tolerance is invalid
            expect(isTimestampValid(timestamp, currentTime, 300)).toBe(false);
          }
        )
      );
    });
    
    it('should be symmetric (past and future)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1000000000, max: 9999999999 }),
          fc.integer({ min: 0, max: 300 }),
          (baseTime, drift) => {
            const timestamp = baseTime;
            const futureTime = baseTime + drift;
            const pastTime = baseTime - drift;
            
            // Invariant: Same drift in past or future → same result
            const futureValid = isTimestampValid(timestamp, futureTime, 300);
            const pastValid = isTimestampValid(timestamp, pastTime, 300);
            expect(futureValid).toBe(pastValid);
          }
        )
      );
    });
  });
  
  describe('toUnixTimestamp', () => {
    it('should preserve ordering (monotonic)', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 9999999999000 }),
          fc.integer({ min: 0, max: 9999999999000 }),
          (ms1, ms2) => {
            const unix1 = toUnixTimestamp(ms1);
            const unix2 = toUnixTimestamp(ms2);
            
            // Invariant: Ordering preserved after conversion
            if (ms1 < ms2) {
              expect(unix1).toBeLessThanOrEqual(unix2);
            } else if (ms1 > ms2) {
              expect(unix1).toBeGreaterThanOrEqual(unix2);
            } else {
              expect(unix1).toBe(unix2);
            }
          }
        )
      );
    });
  });
});
```

---

## 6. Testing Checklist

### For Every Function in lib/core/

- [ ] Has at least one property-based test
- [ ] Tests core invariants (identity, idempotence, etc.)
- [ ] Uses `fast-check` generators for arbitrary inputs
- [ ] Tests boundary conditions (empty arrays, max integers)
- [ ] Has example-based tests for known edge cases
- [ ] No mocks required (pure functions)

### For Every Adapter in lib/adapters/

- [ ] Has unit tests with mocked core functions
- [ ] Tests error handling (missing headers, invalid JSON)
- [ ] Tests provider-specific parsing logic
- [ ] Validates schema enforcement

### For Every Route Handler in app/api/

- [ ] Has integration tests with mock requests
- [ ] Tests authentication/authorization
- [ ] Validates HTTP status codes
- [ ] Tests error responses

---

## 7. Code Organization Rules

### Import Order

```typescript
// 1. Node built-ins
import { createHmac } from 'crypto';

// 2. External libraries
import { z } from 'zod';

// 3. Internal core (pure functions)
import { verifySignature } from '@/lib/core/crypto';

// 4. Internal adapters
import { verifyGitHubWebhook } from '@/lib/adapters/github';

// 5. Internal utilities
import { logWebhookAttempt } from '@/lib/utils/logger';

// 6. Types
import type { GitHubWebhook } from '@/lib/adapters/github';
```

### Naming Conventions

| Type | Convention | Example |
|------|-----------|---------|
| Pure functions | Verb + noun | `computeHmacSha256`, `validateTimestamp` |
| Adapter functions | Verb + provider | `verifyGitHubWebhook` |
| Route handlers | HTTP method | `POST`, `GET` |
| Types/Interfaces | PascalCase | `GitHubWebhook`, `VerificationResult` |
| Constants | UPPER_SNAKE_CASE | `DEFAULT_TOLERANCE_SECONDS` |

---

## References

- [Functional Core, Imperative Shell - Gary Bernhardt](https://www.destroyallsoftware.com/screencasts/catalog/functional-core-imperative-shell)
- [Property-Based Testing - fast-check](https://fast-check.dev/)
- [Clean Architecture - Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
