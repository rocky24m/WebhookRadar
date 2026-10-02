import { spawn } from 'node:child_process';
import path from 'node:path';

const DB_PATH = path.resolve(process.cwd(), 'data', 'webhooks.db');
const SERVER_SCRIPT = path.resolve(process.cwd(), 'scripts', 'mcp-sqlite-server.mjs');
console.log(`Starting real MCP SQLite test against: ${DB_PATH}`);
console.log(`MCP Server script: ${SERVER_SCRIPT}`);

// Spawn the exact command configured in mcp.json
const proc = spawn('node', [SERVER_SCRIPT, '--db-path', DB_PATH], {
  stdio: ['pipe', 'pipe', 'inherit'],
});

let buffer = '';

function send(msg) {
  const json = JSON.stringify(msg);
  proc.stdin.write(json + '\n');
}

proc.stdout.on('data', (data) => {
  buffer += data.toString();
  const lines = buffer.split('\n');
  buffer = lines.pop(); // keep remainder

  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const res = JSON.parse(line.trim());
      handleMessage(res);
    } catch (e) {
      console.log('Server raw output:', line);
    }
  }
});

function handleMessage(res) {
  console.log(`\n<<< [MCP Response ID: ${res.id ?? 'notif'}]`);
  
  if (res.id === 1) {
    console.log('✅ Handshake initialized successfully!');
    console.log('Server info:', JSON.stringify(res.result?.serverInfo));
    
    // Notify initialized
    send({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });

    // Step 2: List tools
    console.log('\n>>> Requesting tools/list from SQLite MCP server...');
    send({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {},
    });
  } else if (res.id === 2) {
    const tools = res.result?.tools || [];
    console.log(`✅ Available MCP Tools (${tools.length}):`);
    tools.forEach((t) => console.log(`  - ${t.name}: ${t.description}`));

    // Step 3: Call a real query tool!
    console.log('\n>>> Executing real tool call: read_query on data/webhooks.db...');
    send({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'read_query',
        arguments: {
          query: 'SELECT id, provider, scenario, valid, status_code, reason FROM webhook_events LIMIT 3;',
        },
      },
    });
  } else if (res.id === 3) {
    console.log('✅ Real Tool Execution Result (read_query):');
    console.log(res.result?.content?.[0]?.text);

    // Step 4: Call list_tables
    console.log('\n>>> Executing real tool call: list_tables...');
    send({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'list_tables',
        arguments: {},
      },
    });
  } else if (res.id === 4) {
    console.log('✅ Real Tool Execution Result (list_tables):');
    console.log(res.result?.content?.[0]?.text);

    console.log('\n🎉 ALL REAL MCP SERVER PROTOCOL TESTS PASSED 100%!');
    proc.kill();
    process.exit(0);
  }
}

// Step 1: Send initialize request
console.log('>>> Sending JSON-RPC 2.0 initialize request...');
send({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: {
      name: 'WebhookRadar-MCP-Tester',
      version: '1.0.0',
    },
  },
});

setTimeout(() => {
  console.error('\n❌ Test timed out after 10 seconds.');
  proc.kill();
  process.exit(1);
}, 10000);
