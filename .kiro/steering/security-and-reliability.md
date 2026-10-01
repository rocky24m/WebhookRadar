# Security and Reliability Standards for WebhookRadar

This document defines mandatory security practices for all webhook processing, signature verification, and sensitive data handling in WebhookRadar.

---

## 1. Timing-Safe HMAC Verification

**MANDATE:** All signature comparisons MUST use `crypto.timingSafeEqual()` to prevent timing side-channel attacks.

### Why This Matters

Standard string comparison (`===`, `==`, `String.prototype.localeCompare()`) short-circuits on the first differing character, leaking information about the expected signature through response timing. Attackers can exploit this to recover valid signatures byte-by-byte.

### DO: Timing-Safe Comparison

```typescript
import { createHmac, timingSafeEqual } from 'crypto';

function verifySignature(
  payload: Buffer,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  // Convert both to buffers of equal length
  const expectedBuffer = Buffer.from(expectedSignature, 'hex');
  const receivedBuffer = Buffer.from(signature, 'hex');
  
  // Length check before timing-safe comparison
  if (expectedBuffer.length !== receivedBuffer.length) {
    return false;
  }
  
  // Timing-safe comparison
  return timingSafeEqual(expectedBuffer, receivedBuffer);
}
```

### DON'T: Direct String Comparison (INSECURE)

```typescript
// ❌ NEVER DO THIS - Vulnerable to timing attacks
function verifySignatureInsecure(
  payload: Buffer,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  // ❌ This leaks timing information!
  return signature === expectedSignature;
}
```

### Implementation Checklist

| Provider | Signature Header | Timing-Safe Verification Required |
|----------|-----------------|-----------------------------------|
| GitHub   | `x-hub-signature-256` | ✅ Yes |
| Stripe   | `stripe-signature` | ✅ Yes |
| Shopify  | `x-shopify-hmac-sha256` | ✅ Yes |
| Slack    | `x-slack-signature` | ✅ Yes |

---

## 2. Replay Attack Prevention

**MANDATE:** All webhook handlers MUST validate timestamps with a configurable drift tolerance (default: 300 seconds / 5 minutes).

### Timestamp Validation Strategy

```typescript
const DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300; // 5 minutes

function validateTimestamp(
  timestamp: number,
  toleranceSeconds: number = DEFAULT_TIMESTAMP_TOLERANCE_SECONDS
): boolean {
  const currentTime = Math.floor(Date.now() / 1000);
  const timeDifference = Math.abs(currentTime - timestamp);
  
  return timeDifference <= toleranceSeconds;
}
```

### Provider-Specific Timestamp Extraction

| Provider | Timestamp Source | Format |
|----------|-----------------|---------|
| GitHub   | Request time (implicit) | Unix timestamp |
| Stripe   | `stripe-signature` header (`t=...`) | Unix timestamp (seconds) |
| Shopify  | `x-shopify-webhook-timestamp` | Unix timestamp (seconds) |
| Slack    | `x-slack-request-timestamp` | Unix timestamp (seconds) |

### Example: Stripe Timestamp Validation

```typescript
function parseStripeSignature(header: string): {
  timestamp: number;
  signatures: string[];
} {
  const pairs = header.split(',').map(pair => pair.split('='));
  const timestamp = parseInt(pairs.find(([key]) => key === 't')?.[1] ?? '0', 10);
  const signatures = pairs
    .filter(([key]) => key.startsWith('v'))
    .map(([, sig]) => sig);
  
  return { timestamp, signatures };
}

function verifyStripeWebhook(
  payload: Buffer,
  signatureHeader: string,
  secret: string
): boolean {
  const { timestamp, signatures } = parseStripeSignature(signatureHeader);
  
  // 1. Validate timestamp to prevent replay attacks
  if (!validateTimestamp(timestamp)) {
    return false;
  }
  
  // 2. Verify signature
  const signedPayload = `${timestamp}.${payload.toString('utf8')}`;
  const expectedSignature = createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
  
  // 3. Check if any provided signature matches (timing-safe)
  return signatures.some(sig => {
    try {
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');
      const receivedBuffer = Buffer.from(sig, 'hex');
      return expectedBuffer.length === receivedBuffer.length &&
             timingSafeEqual(expectedBuffer, receivedBuffer);
    } catch {
      return false;
    }
  });
}
```

---

## 3. Zero Secret Exposure

**MANDATE:** Secrets, authorization tokens, and signature strings MUST be redacted in all logging, diagnostics, and API responses.

### Logging Standards

```typescript
// ✅ DO: Redact sensitive data
function logWebhookVerification(result: {
  provider: string;
  signature: string;
  secret: string;
  verified: boolean;
}) {
  console.log({
    provider: result.provider,
    signature: '[REDACTED]',
    secret: '[REDACTED]',
    verified: result.verified,
    timestamp: new Date().toISOString(),
  });
}

// ❌ DON'T: Log raw secrets or signatures
function logWebhookVerificationInsecure(result: {
  provider: string;
  signature: string;
  secret: string;
  verified: boolean;
}) {
  // ❌ This exposes secrets in logs!
  console.log(result);
}
```

### Safe Error Messages

```typescript
// ✅ DO: Generic error messages
if (!verifySignature(payload, signature, secret)) {
  return new Response(
    JSON.stringify({ error: 'Invalid signature' }),
    { status: 401 }
  );
}

// ❌ DON'T: Expose signature details
if (!verifySignature(payload, signature, secret)) {
  // ❌ This leaks expected signature format!
  return new Response(
    JSON.stringify({
      error: 'Signature mismatch',
      expected: expectedSignature,
      received: signature
    }),
    { status: 401 }
  );
}
```

### Redaction Utility

```typescript
function redactSensitiveData<T extends Record<string, any>>(
  data: T,
  keysToRedact: string[] = ['secret', 'signature', 'token', 'authorization']
): T {
  const redacted = { ...data };
  
  for (const key of keysToRedact) {
    if (key in redacted) {
      redacted[key] = '[REDACTED]';
    }
  }
  
  return redacted;
}
```

---

## 4. Strict Payload Validation

**MANDATE:** Raw payload buffers MUST be preserved for signature verification. Parsed JSON MUST be validated with Zod schemas.

### Validation Flow

```
Raw Request Body (Buffer)
      ↓
[1. Signature Verification] ← Uses raw buffer
      ↓
[2. JSON Parsing]
      ↓
[3. Schema Validation with Zod] ← Uses parsed object
      ↓
[4. Business Logic]
```

### Implementation Pattern

```typescript
import { z } from 'zod';

// Define strict schemas for each provider
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

async function handleGitHubWebhook(request: Request) {
  // 1. Read raw body as buffer (preserve for signature verification)
  const rawBody = Buffer.from(await request.arrayBuffer());
  const signature = request.headers.get('x-hub-signature-256') ?? '';
  const secret = process.env.GITHUB_WEBHOOK_SECRET!;
  
  // 2. Verify signature using raw buffer
  if (!verifyGitHubSignature(rawBody, signature, secret)) {
    return new Response(
      JSON.stringify({ error: 'Invalid signature' }),
      { status: 401 }
    );
  }
  
  // 3. Parse JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return new Response(
      JSON.stringify({ error: 'Invalid JSON' }),
      { status: 400 }
    );
  }
  
  // 4. Validate with Zod schema
  const result = GitHubWebhookSchema.safeParse(parsed);
  if (!result.success) {
    return new Response(
      JSON.stringify({
        error: 'Schema validation failed',
        details: result.error.format(),
      }),
      { status: 400 }
    );
  }
  
  // 5. Process validated webhook
  const webhook = result.data;
  // ... business logic
  
  return new Response(JSON.stringify({ success: true }), { status: 200 });
}
```

### Schema Validation Rules

| Validation Layer | Tool | Purpose |
|------------------|------|---------|
| Raw Body Integrity | `crypto.timingSafeEqual()` | Verify signature before parsing |
| JSON Structure | `JSON.parse()` | Ensure valid JSON format |
| Type Safety | `zod` | Enforce expected schema and types |
| Business Logic | Custom validators | Domain-specific validation rules |

---

## Security Checklist for All Webhook Handlers

- [ ] Uses `crypto.timingSafeEqual()` for signature verification
- [ ] Validates timestamps with configurable tolerance (default: 300s)
- [ ] Redacts secrets, tokens, and signatures in all logs and errors
- [ ] Preserves raw request body buffer for signature verification
- [ ] Parses JSON only after successful signature verification
- [ ] Validates parsed payload with Zod schema
- [ ] Returns generic error messages (no signature details)
- [ ] Implements rate limiting to prevent abuse
- [ ] Logs verification attempts with redacted sensitive data
- [ ] Uses environment variables for all secrets (never hardcoded)

---

## References

- [OWASP: Timing Attack Prevention](https://owasp.org/www-community/vulnerabilities/Timing_Attack)
- [Node.js Crypto: timingSafeEqual](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b)
- [Stripe: Webhook Signatures](https://stripe.com/docs/webhooks/signatures)
- [GitHub: Webhook Security](https://docs.github.com/en/webhooks/securing-your-webhooks)
