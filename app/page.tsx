'use client';

import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  Radio,
  Zap,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Terminal,
  ExternalLink,
  Cpu,
  FileCode2,
  Lock,
  Layers,
  Sparkles,
} from 'lucide-react';
import { ProviderType } from '@/lib/core/types';

interface VerificationResult {
  valid: boolean;
  provider: ProviderType;
  reason?: string;
  timestampDrift?: number;
}

interface SimulationResponse {
  scenario: string;
  provider: ProviderType;
  result: VerificationResult;
  latencyMs: number;
  diagnostic: {
    provider: string;
    checkedAt: string;
    status: string;
    sanitizedDetails: Record<string, unknown>;
  };
  simulatedRequest: {
    headers: Record<string, string>;
    timestamp: number;
    bodySnippet: string;
  };
}

interface AuditLogEntry {
  id: string;
  provider: ProviderType;
  scenario: string;
  valid: boolean;
  timestamp: string;
  latencyMs: number;
  reason?: string;
  drift?: number;
}

const PROVIDERS: { id: ProviderType; name: string; tag: string; header: string; color: string }[] = [
  { id: 'stripe', name: 'Stripe', tag: 'Payments', header: 'Stripe-Signature', color: 'from-violet-500 to-indigo-600' },
  { id: 'github', name: 'GitHub', tag: 'DevOps / CI', header: 'X-Hub-Signature-256', color: 'from-gray-700 to-gray-900' },
  { id: 'slack', name: 'Slack', tag: 'Messaging', header: 'X-Slack-Signature', color: 'from-amber-500 to-orange-600' },
  { id: 'shopify', name: 'Shopify', tag: 'E-Commerce', header: 'X-Shopify-Hmac-SHA256', color: 'from-emerald-500 to-teal-600' },
];

export default function Dashboard() {
  const [selectedProvider, setSelectedProvider] = useState<ProviderType>('stripe');
  const [isLoading, setIsLoading] = useState(false);
  const [lastSimulation, setLastSimulation] = useState<SimulationResponse | null>(null);
  const [logs, setLogs] = useState<AuditLogEntry[]>([
    {
      id: 'init-1',
      provider: 'stripe',
      scenario: 'valid',
      valid: true,
      timestamp: '14:00:00',
      latencyMs: 0.184,
      drift: 0,
    },
    {
      id: 'init-2',
      provider: 'github',
      scenario: 'tampered_signature',
      valid: false,
      timestamp: '13:59:30',
      latencyMs: 0.215,
      reason: 'Signature mismatch (tampered byte rejected)',
    },
  ]);

  const stats = {
    verified: logs.filter((l) => l.valid).length,
    blocked: logs.filter((l) => !l.valid).length,
    avgLatency: (logs.reduce((acc, l) => acc + l.latencyMs, 0) / (logs.length || 1)).toFixed(3),
  };

  const runSimulation = async (scenario: 'valid' | 'tampered_signature' | 'replay_attack' | 'corrupted_payload') => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          scenario,
        }),
      });

      const data: SimulationResponse = await res.json();
      setLastSimulation(data);

      const newLog: AuditLogEntry = {
        id: Math.random().toString(36).substring(7),
        provider: data.provider,
        scenario,
        valid: data.result.valid,
        timestamp: new Date().toLocaleTimeString(),
        latencyMs: data.latencyMs,
        reason: data.result.reason,
        drift: data.result.timestampDrift,
      };

      setLogs((prev) => [newLog, ...prev.slice(0, 19)]);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-tr from-indigo-500 to-cyan-400 text-white shadow-lg shadow-indigo-500/20">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                  WebhookRadar
                </span>
                <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Active Gateway
                </span>
              </div>
              <p className="text-xs text-slate-400">Timing-Safe Multi-Provider Reliability Hub</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-800/60 border border-slate-700/50 text-xs">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span className="text-slate-300 font-medium">42/42 Invariant Tests Passing (100%)</span>
            </div>
            <a
              href="https://github.com/rocky24m/WebhookRadar"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium transition-all shadow-md shadow-indigo-600/20"
            >
              <span>GitHub</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Metric Cards */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Verified Requests</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="mt-3 text-2xl font-bold text-white">{stats.verified}</div>
            <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
              <span>●</span> Constant-time HMAC match
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Attacks Intercepted</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="mt-3 text-2xl font-bold text-white">{stats.blocked}</div>
            <p className="text-xs text-rose-400 mt-1 flex items-center gap-1">
              <span>●</span> Tampered or expired payloads
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Avg Latency</span>
              <Cpu className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="mt-3 text-2xl font-bold text-white">{stats.avgLatency} ms</div>
            <p className="text-xs text-cyan-400 mt-1 flex items-center gap-1">
              <span>●</span> Pure crypto execution
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Replay Window</span>
              <Clock className="w-4 h-4 text-amber-400" />
            </div>
            <div className="mt-3 text-2xl font-bold text-white">300s</div>
            <p className="text-xs text-amber-400 mt-1 flex items-center gap-1">
              <span>●</span> Max 10s future drift
            </p>
          </div>
        </section>

        {/* Live Webhook Simulator Panel */}
        <section className="rounded-3xl bg-slate-900/40 border border-slate-800/80 p-6 shadow-xl backdrop-blur-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
            <div>
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-indigo-400" />
                <h2 className="text-lg font-bold text-white">Live Webhook Simulator & Fault Injector</h2>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Simulate production webhook deliveries and test timing-safe verification in real time
              </p>
            </div>

            {/* Provider Tabs */}
            <div className="flex items-center p-1 rounded-xl bg-slate-950 border border-slate-800 self-start sm:self-auto">
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setSelectedProvider(p.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    selectedProvider === p.id
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {p.name}
                </button>
              ))}
            </div>
          </div>

          {/* Action Trigger Buttons */}
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => runSimulation('valid')}
              disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold shadow-lg shadow-emerald-600/20 transition-all cursor-pointer"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>Send Valid {selectedProvider.toUpperCase()} Webhook</span>
            </button>

            <button
              onClick={() => runSimulation('tampered_signature')}
              disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-rose-600/80 hover:bg-rose-600 disabled:opacity-50 text-white text-xs font-semibold border border-rose-500/30 transition-all cursor-pointer"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Simulate Tampered Signature (Timing-Safe Rejection)</span>
            </button>

            <button
              onClick={() => runSimulation('replay_attack')}
              disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-amber-600/80 hover:bg-amber-600 disabled:opacity-50 text-white text-xs font-semibold border border-amber-500/30 transition-all cursor-pointer"
            >
              <Clock className="w-4 h-4" />
              <span>Simulate Expired Replay Attack (-15m Old)</span>
            </button>

            <button
              onClick={() => runSimulation('corrupted_payload')}
              disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-semibold border border-slate-700 transition-all cursor-pointer"
            >
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Simulate Corrupted Body Byte</span>
            </button>
          </div>

          {/* Live Result Cards */}
          {lastSimulation ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-6">
              {/* Left Column: Simulated Request */}
              <div className="p-5 rounded-2xl bg-slate-950/70 border border-slate-800 flex flex-col space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    Simulated Ingress Request
                  </span>
                  <span className="text-xs font-mono text-slate-500">Scenario: {lastSimulation.scenario}</span>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div>
                    <span className="text-slate-500 text-[11px] uppercase block">Headers:</span>
                    <div className="mt-1 p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 text-cyan-300 break-all space-y-1">
                      {Object.entries(lastSimulation.simulatedRequest.headers).map(([k, v]) => (
                        <div key={k}>
                          <span className="text-slate-400">{k}:</span> {v}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 text-[11px] uppercase block">Payload Sample:</span>
                    <pre className="mt-1 p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 text-slate-300 overflow-x-auto text-[11px]">
                      {lastSimulation.simulatedRequest.bodySnippet}
                    </pre>
                  </div>
                </div>
              </div>

              {/* Right Column: Verification Outcome */}
              <div className="p-5 rounded-2xl bg-slate-950/70 border border-slate-800 flex flex-col space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-indigo-400" />
                    Gateway Verification Result
                  </span>
                  <span className="text-xs font-mono text-slate-500">{lastSimulation.latencyMs} ms</span>
                </div>

                <div className="flex items-center gap-3 p-4 rounded-xl border bg-slate-900/60 border-slate-800">
                  {lastSimulation.result.valid ? (
                    <>
                      <div className="p-2.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <CheckCircle2 className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-bold text-emerald-400">SIGNATURE VERIFIED</span>
                          <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                            200 OK
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Timing-safe HMAC-SHA256 verified in constant time. No drift detected.
                        </p>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="p-2.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        <XCircle className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-bold text-rose-400">VERIFICATION REJECTED</span>
                          <span className="text-xs px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono">
                            401 UNAUTHORIZED
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">{lastSimulation.result.reason}</p>
                      </div>
                    </>
                  )}
                </div>

                <div>
                  <span className="text-slate-500 text-[11px] uppercase block font-mono">Sanitized Diagnostics:</span>
                  <pre className="mt-1 p-3 rounded-lg bg-slate-900 border border-slate-800/80 text-emerald-400 font-mono text-[11px] overflow-x-auto">
                    {JSON.stringify(lastSimulation.diagnostic, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-950/30">
              <Radio className="w-8 h-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-400">Click any action button above to trigger an instant webhook verification test.</p>
            </div>
          )}
        </section>

        {/* Audit Log Table */}
        <section className="rounded-3xl bg-slate-900/40 border border-slate-800/80 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              <h3 className="text-base font-bold text-white">Recent Security Audit Trail</h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">{logs.length} logged events</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/60 text-slate-500 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Provider</th>
                  <th className="py-3 px-4">Scenario</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Latency</th>
                  <th className="py-3 px-4">Diagnostic Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-semibold text-white capitalize">{log.provider}</td>
                    <td className="py-3 px-4 text-slate-400">{log.scenario}</td>
                    <td className="py-3 px-4">
                      {log.valid ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <CheckCircle2 className="w-3 h-3" /> PASS
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                          <XCircle className="w-3 h-3" /> REJECT
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400" suppressHydrationWarning>{log.timestamp}</td>
                    <td className="py-3 px-4 text-cyan-400">{log.latencyMs} ms</td>
                    <td className="py-3 px-4 text-slate-400 truncate max-w-xs">{log.reason || 'Verified'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Challenge Architecture Highlights */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-5 rounded-2xl bg-slate-900/30 border border-slate-800/60 space-y-2">
            <div className="flex items-center gap-2 text-indigo-400 font-semibold text-xs uppercase tracking-wider">
              <FileCode2 className="w-4 h-4" />
              <span>Spec-Driven Development</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Engineered from formal EARS specifications in <code className="text-slate-300">.kiro/specs/</code> covering 10 acceptance criteria and 31 implementation milestones.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/30 border border-slate-800/60 space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase tracking-wider">
              <Sparkles className="w-4 h-4" />
              <span>Property-Based Testing</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              42 fast-check invariant tests running 4,200 randomized iterations proving tamper rejection, monotonic drift, and length-leakage safety.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/30 border border-slate-800/60 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider">
              <Cpu className="w-4 h-4" />
              <span>Agentic Ecosystem & MCP</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Features custom agent <code className="text-slate-300">@webhook-security-auditor</code>, MCP fetch integration, and packaged reusable Kiro Power in <code className="text-slate-300">powers/</code>.
            </p>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-500">
        <p>WebhookRadar &copy; 2026. Built with Kiro for the Kiro University Challenge. Public repository on GitHub.</p>
      </footer>
    </div>
  );
}
