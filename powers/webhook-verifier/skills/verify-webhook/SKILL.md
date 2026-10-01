---
name: verify-webhook
description: Audit and verify incoming webhook signatures using timing-safe HMAC-SHA256 verification, replay attack prevention, and provider-specific validation for GitHub, Stripe, Slack, and Shopify.
---

# Webhook Verification Skill

This skill teaches agents how to securely verify webhook signatures from multiple providers using timing-safe cryptographic operations and replay attack prevention.

## Security Principles

### 1. Timing-Safe Signature Verification

**CRITICAL:** Always use `crypto.timingSafeEqual()` for signature comparison to prevent timing side-channel attacks.

**Why:** Standard string comparison (`===`, `==`) short-circuits on the first differing character, leaking timing information that attackers can exploit to recover valid signatures byte-by-byte.

**Implementation:**
```typescript
import { createHmac, createHash, timingSafeEqual } from 'crypto';

// ✅ CORRECT: Timing-safe verification
function verifySignature(expected: string, actual: string): boolean {
  // Hash both inputs to fixed-size SHA-256 digests (32 bytes)
  const expectedHash = createHash('sha256').update(expected).digest();
  const actualHash = createHash('sha256').update(actual).digest();
  
  // Constant-time comparison (always compares all 32 bytes)
  return timingSafeEqual(expectedHash, actualHash);
}

// ❌ INCORRECT: Vulnerable to timing attacks
function verifySignatureInsecure(expected: string, actual: string): boolean {
  return expected === actual; // NEVER DO THIS!
}
```

### 2. Replay Attack Prevention

**CRITICAL:** Validate webhook timestamps to prevent replay attacks with captured old webhooks.

**Default Tolerances:**
- **Past timestamps:** 300 seconds (5 minutes) maximum age
- **Future timestamps:** 10 seconds maximum (clock skew protection)

**Implementation:**
```typescript
function isTimestampValid(
  timestamp: number,
  currentTime: number,
  toleranceSeconds: number = 300
): boolean {
  const drift = Math.abs(currentTime - timestamp);
  
  // Reject timestamps too far in the future (> 10 seconds)
  if (timestamp > currentTime + 10) {
    return false;
  }
  
  // Reject timestamps too old (> toleranceSeconds)
  if (timestamp < currentTime - toleranceSeconds) {
    return false;
  }
  
  return true;
}
```

### 3. Secret Redaction

**CRITICAL:** Never log or expose raw secrets, tokens, or signature values.

**Implementation:**
```typescript
function redactSensitiveString(val: string): string {
  if (val.length < 12) {
    return '[REDACTED]';
  }
  // Show first 8 chars + "..." + last 2 chars
  return `${val.slice(0, 8)}...${val.slice(-2)}`;
}

// Usage in logs
console.log({
  secret: redactSensitiveString(secret), // "whsec_12...ab"
  signature: '[REDACTED]',
  verified: true
});
```

---

## Provider-Specific Verification

### GitHub Webhooks

**Headers:**
- `X-Hub-Signature-256`: `sha256=<64-character-hex-signature>`

**Algorithm:**
- HMAC-SHA256 over raw request body
- No timestamp validation (GitHub doesn't provide timestamps)

**Example:**
```typescript
function verifyGitHubWebhook(
  headers: Record<string, string>,
  rawBody: Buffer,
  secret: string
): boolean {
  const signatureHeader = headers['x-hub-signature-256'];
  if (!signatureHeader?.startsWith('sha256=')) {
    return false;
  }
  
  const receivedSignature = signatureHeader.slice(7); // Remove "sha256="
  const expectedSignature = createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  
  return verifySignature(expectedSignature, receivedSignature);
}
```

**Documentation:** https://docs.github.com/en/webhooks/securing-your-webhooks

---

### Stripe Webhooks

**Headers:**
- `Stripe-Signature`: `t=<timestamp>,v1=<sig1>,v1=<sig2>,...`

**Algorithm:**
- HMAC-SHA256 over `"${timestamp}.${rawBody}"`
- Timestamp validation required (300s tolerance)
- Supports multiple v1 signatures (key rotation)

**Example:**
```typescript
function verifyStripeWebhook(
  headers: Record<string, string>,
  rawBody: string,
  secret: string
): boolean {
  const signatureHeader = headers['stripe-signature'];
  if (!signatureHeader) return false;
  
  // Parse: t=1609459200,v1=abc...,v1=def...
  const pairs = signatureHeader.split(',').map(p => p.split('='));
  const timestamp = parseInt(pairs.find(([k]) => k === 't')?.[1] ?? '0');
  const signatures = pairs.filter(([k]) => k.startsWith('v')).map(([, v]) => v);
  
  // Validate timestamp
  const currentTime = Math.floor(Date.now() / 1000);
  if (!isTimestampValid(timestamp, currentTime, 300)) {
    return false;
  }
  
  // Construct signed payload
  const signedPayload = `${timestamp}.${rawBody}`;
  const expectedSignature = createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
  
  // Verify against any v1 signature (timing-safe)
  return signatures.some(sig => verifySignature(expectedSignature, sig));
}
```

**Documentation:** https://stripe.com/docs/webhooks/signatures

---

### Slack Webhooks

**Headers:**
- `X-Slack-Signature`: `v0=<hex-signature>`
- `X-Slack-Request-Timestamp`: `<unix-timestamp>`

**Algorithm:**
- HMAC-SHA256 over `"v0:${timestamp}:${rawBody}"`
- Timestamp validation required (300s tolerance)

**Example:**
```typescript
function verifySlackWebhook(
  headers: Record<string, string>,
  rawBody: string,
  secret: string
): boolean {
  const signatureHeader = headers['x-slack-signature'];
  const timestampHeader = headers['x-slack-request-timestamp'];
  
  if (!signatureHeader?.startsWith('v0=') || !timestampHeader) {
    return false;
  }
  
  const receivedSignature = signatureHeader.slice(3); // Remove "v0="
  const timestamp = parseInt(timestampHeader);
  
  // Validate timestamp
  const currentTime = Math.floor(Date.now() / 1000);
  if (!isTimestampValid(timestamp, currentTime, 300)) {
    return false;
  }
  
  // Construct versioned signed payload
  const signedPayload = `v0:${timestamp}:${rawBody}`;
  const expectedSignature = createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
  
  return verifySignature(expectedSignature, receivedSignature);
}
```

**Documentation:** https://api.slack.com/authentication/verifying-requests-from-slack

---

### Shopify Webhooks

**Headers:**
- `X-Shopify-Hmac-SHA256`: `<base64-encoded-signature>`
- `X-Shopify-Webhook-Timestamp`: `<unix-timestamp>` (optional)

**Algorithm:**
- HMAC-SHA256 over raw request body
- Base64-encoded signature (must convert to hex)
- Optional timestamp validation

**Example:**
```typescript
function verifyShopifyWebhook(
  headers: Record<string, string>,
  rawBody: Buffer,
  secret: string
): boolean {
  const signatureHeader = headers['x-shopify-hmac-sha256'];
  if (!signatureHeader) return false;
  
  // Convert base64 signature to hex
  const receivedSignatureHex = Buffer.from(signatureHeader, 'base64')
    .toString('hex');
  
  // Optional: validate timestamp if present
  const timestampHeader = headers['x-shopify-webhook-timestamp'];
  if (timestampHeader) {
    const timestamp = parseInt(timestampHeader);
    const currentTime = Math.floor(Date.now() / 1000);
    if (!isTimestampValid(timestamp, currentTime, 300)) {
      return false;
    }
  }
  
  // Compute expected signature
  const expectedSignature = createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  
  return verifySignature(expectedSignature, receivedSignatureHex);
}
```

**Documentation:** https://shopify.dev/docs/apps/webhooks/configuration/https

---

## Using the Unified Verifier

For projects using the WebhookRadar library:

```typescript
import { verifyWebhook } from '@/lib/adapters';

// GitHub
const githubResult = await verifyWebhook('github', {
  headers: request.headers,
  rawBody: Buffer.from(await request.arrayBuffer()),
  secret: process.env.GITHUB_WEBHOOK_SECRET!
});

// Stripe with custom tolerance (10 minutes)
const stripeResult = await verifyWebhook('stripe', {
  headers: request.headers,
  rawBody: Buffer.from(await request.arrayBuffer()),
  secret: process.env.STRIPE_WEBHOOK_SECRET!
}, 600);

// Slack
const slackResult = await verifyWebhook('slack', {
  headers: request.headers,
  rawBody: Buffer.from(await request.arrayBuffer()),
  secret: process.env.SLACK_SIGNING_SECRET!
});

// Shopify
const shopifyResult = await verifyWebhook('shopify', {
  headers: request.headers,
  rawBody: Buffer.from(await request.arrayBuffer()),
  secret: process.env.SHOPIFY_WEBHOOK_SECRET!
});

if (!result.valid) {
  console.error(`Verification failed: ${result.reason}`);
  return new Response('Unauthorized', { status: 401 });
}
```

---

## Security Checklist

When auditing webhook verification code, ensure:

- [ ] Uses `crypto.timingSafeEqual()` for all signature comparisons
- [ ] Hashes both inputs to fixed-size digests before comparison
- [ ] Validates timestamps with configurable tolerance (default: 300s)
- [ ] Rejects future timestamps beyond 10 seconds (clock skew)
- [ ] Redacts secrets, tokens, and signatures in all logs
- [ ] Preserves raw request body buffer for signature verification
- [ ] Parses JSON only after successful signature verification
- [ ] Returns generic error messages (never exposes expected signatures)
- [ ] Uses environment variables for secrets (never hardcoded)
- [ ] Handles missing headers gracefully

---

## Property-Based Testing

Verify webhook verification logic with property-based tests:

```typescript
import { fc } from 'fast-check';

// Test: Valid signatures always verify
fc.assert(
  fc.property(
    fc.uint8Array({ minLength: 1, maxLength: 1000 }),
    fc.string({ minLength: 1, maxLength: 100 }),
    (payloadArray, secret) => {
      const payload = Buffer.from(payloadArray);
      const signature = createHmac('sha256', secret)
        .update(payload)
        .digest('hex');
      
      // Invariant: Computed signature MUST always verify
      expect(verifySignature(signature, signature)).toBe(true);
    }
  )
);

// Test: Corrupted signatures always fail
fc.assert(
  fc.property(
    fc.uint8Array({ minLength: 1, maxLength: 1000 }),
    fc.string({ minLength: 1, maxLength: 100 }),
    fc.integer({ min: 0, max: 63 }),
    (payloadArray, secret, corruptPos) => {
      const payload = Buffer.from(payloadArray);
      const validSignature = createHmac('sha256', secret)
        .update(payload)
        .digest('hex');
      
      // Corrupt one character
      const chars = validSignature.split('');
      chars[corruptPos] = chars[corruptPos] === '0' ? '1' : '0';
      const corruptedSignature = chars.join('');
      
      // Invariant: Corrupted signature MUST be rejected
      expect(verifySignature(validSignature, corruptedSignature)).toBe(false);
    }
  )
);
```

---

## Common Pitfalls

### ❌ Don't: Use direct string comparison
```typescript
// VULNERABLE to timing attacks!
return expectedSignature === receivedSignature;
```

### ✅ Do: Use timing-safe comparison
```typescript
return timingSafeEqual(
  createHash('sha256').update(expectedSignature).digest(),
  createHash('sha256').update(receivedSignature).digest()
);
```

### ❌ Don't: Skip timestamp validation
```typescript
// VULNERABLE to replay attacks!
const expectedSignature = createHmac('sha256', secret).update(body).digest('hex');
return timingSafeVerify(expectedSignature, receivedSignature);
```

### ✅ Do: Always validate timestamps (except GitHub)
```typescript
if (!isTimestampValid(timestamp, Date.now() / 1000, 300)) {
  return false;
}
```

### ❌ Don't: Log raw secrets
```typescript
// EXPOSES secrets in logs!
console.log({ secret, signature, verified: true });
```

### ✅ Do: Redact sensitive data
```typescript
console.log({
  secret: redactSensitiveString(secret),
  signature: '[REDACTED]',
  verified: true
});
```

---

## Resources

- **Official Documentation:**
  - GitHub: https://docs.github.com/en/webhooks/securing-your-webhooks
  - Stripe: https://stripe.com/docs/webhooks/signatures
  - Slack: https://api.slack.com/authentication/verifying-requests-from-slack
  - Shopify: https://shopify.dev/docs/apps/webhooks/configuration/https

- **Security References:**
  - OWASP Timing Attack: https://owasp.org/www-community/vulnerabilities/Timing_Attack
  - Node.js crypto.timingSafeEqual: https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b

- **WebhookRadar Repository:**
  - GitHub: https://github.com/rocky24m/WebhookRadar
  - Full implementation with property-based tests
