// @ts-ignore - node:sqlite is built into Node 22+
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { ProviderType } from '@/lib/core/types';

type SQLiteDatabase = any;

// Ensure data directory exists
const DATA_DIR = path.join(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'webhooks.db');

let dbInstance: DatabaseSync | null = null;

function getDatabase(): DatabaseSync {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(DB_PATH);
    initializeSchema(dbInstance);
  }
  return dbInstance;
}

function initializeSchema(db: DatabaseSync) {
  // Webhook audit trail table
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

    CREATE INDEX IF NOT EXISTS idx_events_provider ON webhook_events(provider);
    CREATE INDEX IF NOT EXISTS idx_events_valid ON webhook_events(valid);
    CREATE INDEX IF NOT EXISTS idx_events_created ON webhook_events(created_at);
  `);
}

export interface WebhookEventRecord {
  id: string;
  provider: ProviderType;
  scenario: string;
  valid: boolean;
  statusCode: number;
  latencyMs: number;
  timestampDrift?: number;
  reason?: string;
  headersJson?: string;
  payloadSnippet?: string;
}

export function logWebhookToDb(record: WebhookEventRecord): void {
  try {
    const db = getDatabase();
    const insertStmt = db.prepare(`
      INSERT INTO webhook_events (
        id, provider, scenario, valid, status_code, latency_ms, timestamp_drift, reason, headers_json, payload_snippet
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
      record.id,
      record.provider,
      record.scenario,
      record.valid ? 1 : 0,
      record.statusCode,
      record.latencyMs,
      record.timestampDrift ?? 0,
      record.reason ?? 'Verified successfully',
      record.headersJson ?? '{}',
      record.payloadSnippet ?? ''
    );

    // If verification failed, record security alert
    if (!record.valid) {
      const alertStmt = db.prepare(`
        INSERT INTO security_alerts (id, event_id, provider, alert_type, severity, description)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      const alertType = record.reason?.toLowerCase().includes('replay')
        ? 'REPLAY_ATTACK'
        : record.reason?.toLowerCase().includes('tampered')
        ? 'TAMPERED_SIGNATURE'
        : 'INVALID_SIGNATURE';

      const severity = alertType === 'REPLAY_ATTACK' ? 'HIGH' : 'CRITICAL';

      alertStmt.run(
        `alt_${Math.random().toString(36).substring(7)}`,
        record.id,
        record.provider,
        alertType,
        severity,
        record.reason ?? 'Signature validation failure'
      );
    }
  } catch (error) {
    console.error('Failed to log webhook event to SQLite:', error);
  }
}

export function getRecentEventsFromDb(limit = 20): Array<{
  id: string;
  provider: ProviderType;
  scenario: string;
  valid: boolean;
  statusCode: number;
  latencyMs: number;
  timestampDrift: number;
  reason: string;
  createdAt: string;
}> {
  try {
    const db = getDatabase();
    const stmt = db.prepare(`
      SELECT id, provider, scenario, valid, status_code as statusCode, latency_ms as latencyMs, timestamp_drift as timestampDrift, reason, created_at as createdAt
      FROM webhook_events
      ORDER BY created_at DESC
      LIMIT ?
    `);

    const rows = stmt.all(limit) as Array<{
      id: string;
      provider: string;
      scenario: string;
      valid: number;
      statusCode: number;
      latencyMs: number;
      timestampDrift: number;
      reason: string;
      createdAt: string;
    }>;

    return rows.map((r) => ({
      ...r,
      provider: r.provider as ProviderType,
      valid: r.valid === 1,
    }));
  } catch (error) {
    console.error('Failed to read from SQLite:', error);
    return [];
  }
}
