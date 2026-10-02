#!/usr/bin/env node
import { DatabaseSync } from 'node:sqlite';
import readline from 'node:readline';
import path from 'node:path';

// Parse arguments for --db-path
let dbPath = path.resolve(process.cwd(), 'data', 'webhooks.db');
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--db-path' && args[i + 1]) {
    dbPath = path.resolve(args[i + 1]);
    i++;
  }
}

// Connect to SQLite database using Node 22 native DatabaseSync
let db;
try {
  db = new DatabaseSync(dbPath);
} catch (err) {
  process.stderr.write(`[mcp-sqlite] Failed to open database at ${dbPath}: ${err.message}\n`);
}

const TOOLS = [
  {
    name: 'read_query',
    description: 'Execute a read-only SELECT query against the WebhookRadar SQLite ledger to inspect webhook verification events, replay attempts, and security alerts.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'The SELECT SQL query to execute on the security ledger.',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'list_tables',
    description: 'List all tables present in the WebhookRadar security ledger SQLite database.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'describe_table',
    description: 'Inspect the schema and columns of a specific table in the security ledger.',
    inputSchema: {
      type: 'object',
      properties: {
        table_name: {
          type: 'string',
          description: 'Name of the table to describe (e.g. webhook_events, security_alerts).',
        },
      },
      required: ['table_name'],
    },
  },
];

function sendResponse(id, result, error = null) {
  const payload = {
    jsonrpc: '2.0',
    id,
  };
  if (error) {
    payload.error = error;
  } else {
    payload.result = result;
  }
  process.stdout.write(JSON.stringify(payload) + '\n');
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch (err) {
    sendResponse(null, null, { code: -32700, message: 'Parse error' });
    return;
  }

  const { id, method, params } = msg;

  if (method === 'initialize') {
    sendResponse(id, {
      protocolVersion: '2024-11-05',
      capabilities: {
        tools: {},
      },
      serverInfo: {
        name: 'webhookradar-sqlite-ledger',
        version: '1.0.0',
      },
    });
    return;
  }

  if (method === 'notifications/initialized') {
    // Client acknowledgement, no response needed
    return;
  }

  if (method === 'tools/list') {
    sendResponse(id, {
      tools: TOOLS,
    });
    return;
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};

    if (!db) {
      sendResponse(id, {
        content: [{ type: 'text', text: `Database connection unavailable: ${dbPath}` }],
        isError: true,
      });
      return;
    }

    try {
      if (toolName === 'read_query') {
        const query = (toolArgs.query || '').trim();
        // Guardrail: enforce read-only
        const lower = query.toLowerCase();
        if (
          lower.startsWith('insert') ||
          lower.startsWith('update') ||
          lower.startsWith('delete') ||
          lower.startsWith('drop') ||
          lower.startsWith('alter')
        ) {
          sendResponse(id, {
            content: [{ type: 'text', text: 'Error: read_query only allows read-only statements (SELECT, PRAGMA, EXPLAIN).' }],
            isError: true,
          });
          return;
        }

        const stmt = db.prepare(query);
        const rows = stmt.all();
        sendResponse(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify(rows, null, 2),
            },
          ],
          isError: false,
        });
        return;
      }

      if (toolName === 'list_tables') {
        const stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';");
        const rows = stmt.all();
        sendResponse(id, {
          content: [{ type: 'text', text: JSON.stringify(rows.map((r) => r.name), null, 2) }],
          isError: false,
        });
        return;
      }

      if (toolName === 'describe_table') {
        const tableName = toolArgs.table_name?.replace(/[^a-zA-Z0-9_]/g, '');
        const stmt = db.prepare(`PRAGMA table_info(${tableName});`);
        const rows = stmt.all();
        sendResponse(id, {
          content: [{ type: 'text', text: JSON.stringify(rows, null, 2) }],
          isError: false,
        });
        return;
      }

      sendResponse(id, {
        content: [{ type: 'text', text: `Unknown tool: ${toolName}` }],
        isError: true,
      });
    } catch (err) {
      sendResponse(id, {
        content: [{ type: 'text', text: `Database error: ${err.message}` }],
        isError: true,
      });
    }
    return;
  }

  // Fallback for unknown methods
  if (id !== undefined && id !== null) {
    sendResponse(id, null, {
      code: -32601,
      message: `Method not found: ${method}`,
    });
  }
});
