import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

const DATA_DIR = path.join(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'webhooks.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS webhook_events (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    scenario TEXT NOT NULL,
    valid INTEGER NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    timestamp_drift INTEGER DEFAULT 0,
    reason TEXT,
    headers_json TEXT,
    payload_snippet TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS security_alerts (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    provider TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Insert seed records if empty
const countStmt = db.prepare('SELECT COUNT(*) as count FROM webhook_events');
const { count } = countStmt.get();

if (count === 0) {
  const insertEvent = db.prepare(`
    INSERT INTO webhook_events (id, provider, scenario, valid, status_code, latency_ms, timestamp_drift, reason, headers_json, payload_snippet, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))
  `);

  const insertAlert = db.prepare(`
    INSERT INTO security_alerts (id, event_id, provider, alert_type, severity, description, created_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now', ?))
  `);

  const seeds = [
    {
      id: 'evt_stripe_01',
      provider: 'stripe',
      scenario: 'payment_intent.succeeded',
      valid: 1,
      code: 200,
      latency: 0.182,
      drift: 0,
      reason: 'Valid constant-time HMAC-SHA256 match',
      offset: '-10 minutes',
    },
    {
      id: 'evt_stripe_02',
      provider: 'stripe',
      scenario: 'tampered_signature',
      valid: 0,
      code: 401,
      latency: 0.211,
      drift: 0,
      reason: 'Signature mismatch (tampered v1 digest rejected)',
      offset: '-8 minutes',
      alert: { type: 'TAMPERED_SIGNATURE', severity: 'CRITICAL' },
    },
    {
      id: 'evt_stripe_03',
      provider: 'stripe',
      scenario: 'replay_attack',
      valid: 0,
      code: 400,
      latency: 0.145,
      drift: 940,
      reason: 'Replay attack: Timestamp expired (940s > 300s window)',
      offset: '-6 minutes',
      alert: { type: 'REPLAY_ATTACK', severity: 'HIGH' },
    },
    {
      id: 'evt_github_01',
      provider: 'github',
      scenario: 'push',
      valid: 1,
      code: 200,
      latency: 0.165,
      drift: 0,
      reason: 'Valid X-Hub-Signature-256 match',
      offset: '-4 minutes',
    },
    {
      id: 'evt_github_02',
      provider: 'github',
      scenario: 'tampered_signature',
      valid: 0,
      code: 401,
      latency: 0.198,
      drift: 0,
      reason: 'Signature mismatch (invalid sha256 hex digest)',
      offset: '-3 minutes',
      alert: { type: 'TAMPERED_SIGNATURE', severity: 'CRITICAL' },
    },
    {
      id: 'evt_slack_01',
      provider: 'slack',
      scenario: 'app_mention',
      valid: 1,
      code: 200,
      latency: 0.224,
      drift: 2,
      reason: 'Valid v0 HMAC-SHA256 signature with request timestamp',
      offset: '-2 minutes',
    },
    {
      id: 'evt_shopify_01',
      provider: 'shopify',
      scenario: 'orders/create',
      valid: 1,
      code: 200,
      latency: 0.245,
      drift: 0,
      reason: 'Valid Base64-encoded HMAC-SHA256 signature verified',
      offset: '-1 minute',
    },
  ];

  for (const s of seeds) {
    insertEvent.run(
      s.id,
      s.provider,
      s.scenario,
      s.valid,
      s.code,
      s.latency,
      s.drift,
      s.reason,
      '{"content-type":"application/json"}',
      `{"sample":"payload_${s.provider}"}`,
      s.offset
    );

    if (s.alert) {
      insertAlert.run(
        `alt_${s.id}`,
        s.id,
        s.provider,
        s.alert.type,
        s.alert.severity,
        s.reason,
        s.offset
      );
    }
  }

  console.log('Seeded database with initial security events and alerts successfully!');
} else {
  console.log(`Database already has ${count} records.`);
}
