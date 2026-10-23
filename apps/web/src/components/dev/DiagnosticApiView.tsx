import React, { useState, useEffect } from 'react';
import { 
  FileCode, 
  Layers, 
  Radio, 
  ShieldCheck, 
  Send, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Copy, 
  Lock,
  ListFilter
} from 'lucide-react';

interface DiagnosticApiViewProps {
  currentRole: string;
}

export const DiagnosticApiView: React.FC<DiagnosticApiViewProps> = ({ currentRole }) => {
  const [subTab, setSubTab] = useState<'openapi' | 'tester' | 'events' | 'queues'>('openapi');
  const [openApiSpec, setOpenApiSpec] = useState<any>(null);
  const [queues, setQueues] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [endpoint, setEndpoint] = useState<string>('/api/v1/health');
  const [method, setMethod] = useState<'GET' | 'POST'>('GET');
  const [idempotencyKey, setIdempotencyKey] = useState<string>('');
  const [requestBody, setRequestBody] = useState<string>('{}');
  const [response, setResponse] = useState<any>(null);
  const [statusCode, setStatusCode] = useState<number | null>(null);

  useEffect(() => {
    fetchOpenApi();
    fetchQueues();
  }, []);

  const fetchOpenApi = async () => {
    try {
      const res = await fetch('/api/v1/openapi.json');
      if (res.ok) {
        const json = await res.json();
        setOpenApiSpec(json.data || json);
      }
    } catch {
      // Ignored
    }
  };

  const fetchQueues = async () => {
    try {
      const res = await fetch('/api/v1/queues', {
        headers: { 'X-Principal-Roles': currentRole },
      });
      if (res.ok) {
        const json = await res.json();
        setQueues(json.data || []);
      }
    } catch {
      // Ignored
    }
  };

  const handleExecuteRequest = async () => {
    setLoading(true);
    setResponse(null);
    setStatusCode(null);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Principal-Roles': currentRole,
      'X-Principal-Id': `usr-engineer-${currentRole}`,
    };

    if (idempotencyKey) {
      headers['Idempotency-Key'] = idempotencyKey;
    }

    try {
      const options: RequestInit = {
        method,
        headers,
      };

      if (method === 'POST') {
        options.body = requestBody;
      }

      const res = await fetch(endpoint, options);
      setStatusCode(res.status);
      const json = await res.json().catch(() => ({ raw: 'Non-JSON response' }));
      setResponse(json);
    } catch (err: any) {
      setStatusCode(0);
      setResponse({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub Navigation */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2 text-xs font-mono">
          <button
            onClick={() => setSubTab('openapi')}
            className={`px-3 py-1.5 rounded-md flex items-center space-x-1.5 ${
              subTab === 'openapi' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>OpenAPI 3.1 Spec</span>
          </button>

          <button
            onClick={() => setSubTab('tester')}
            className={`px-3 py-1.5 rounded-md flex items-center space-x-1.5 ${
              subTab === 'tester' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Send className="w-3.5 h-3.5" />
            <span>Contract & Idempotency Tester</span>
          </button>

          <button
            onClick={() => setSubTab('events')}
            className={`px-3 py-1.5 rounded-md flex items-center space-x-1.5 ${
              subTab === 'events' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Event Catalog</span>
          </button>

          <button
            onClick={() => setSubTab('queues')}
            className={`px-3 py-1.5 rounded-md flex items-center space-x-1.5 ${
              subTab === 'queues' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Queue Ownership Registry</span>
          </button>
        </div>

        <button
          onClick={() => {
            fetchOpenApi();
            fetchQueues();
          }}
          className="text-xs font-mono text-slate-400 hover:text-slate-200 flex items-center space-x-1"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* 1. OpenAPI 3.1 Tab */}
      {subTab === 'openapi' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="font-semibold text-slate-200 text-sm">
                  {openApiSpec?.info?.title || 'CAIM Enterprise Intelligence & Lifecycle API'}
                </h3>
                <p className="text-slate-400 text-xs mt-0.5">
                  Version: <span className="text-cyan-400">{openApiSpec?.info?.version || '2.0.1'}</span> • OAS: 3.1.0
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[11px]">
                Valid OpenAPI 3.1.0
              </span>
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
                <h4 className="text-slate-300 font-semibold mb-2 flex items-center space-x-1.5">
                  <Lock className="w-3.5 h-3.5 text-amber-400" />
                  <span>Security Schemes</span>
                </h4>
                <div className="space-y-1 text-[11px] text-slate-400">
                  <p>• <strong className="text-slate-300">BearerAuth</strong>: HTTP Bearer JWT token</p>
                  <p>• <strong className="text-slate-300">ApiKeyAuth</strong>: Header <code className="text-cyan-300">X-Principal-Id</code></p>
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
                <h4 className="text-slate-300 font-semibold mb-2 flex items-center space-x-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Documented API Families</span>
                </h4>
                <div className="space-y-1 text-[11px] text-slate-400">
                  <p>• Agent Registry & Discovery (<code className="text-cyan-300">/api/v1/agents</code>)</p>
                  <p>• Intelligence & Analysis (<code className="text-cyan-300">/api/v1/analysis/runs</code>)</p>
                  <p>• Validation & Policy Gates (<code className="text-cyan-300">/api/v1/policy/evaluations</code>)</p>
                  <p>• System & Readiness (<code className="text-cyan-300">/api/v1/health</code>, <code className="text-cyan-300">/api/v1/ready</code>)</p>
                </div>
              </div>
            </div>

            <div className="mt-4">
              <h4 className="text-slate-300 font-semibold mb-2">Raw OpenAPI 3.1 Document</h4>
              <pre className="bg-slate-950 p-3 rounded border border-slate-800 max-h-96 overflow-auto text-cyan-300 text-[11px]">
                {JSON.stringify(openApiSpec, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* 2. Interactive Tester Tab */}
      {subTab === 'tester' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4">
            <h3 className="font-semibold text-slate-200 text-sm">Contract, Auth & Idempotency Playground</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div>
                <label className="text-slate-400 text-[11px] block mb-1">Method</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="text-slate-400 text-[11px] block mb-1">Endpoint Path</label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 text-[11px] block mb-1">Idempotency-Key (Optional)</label>
                <input
                  type="text"
                  value={idempotencyKey}
                  placeholder="e.g. idem-test-100"
                  onChange={(e) => setIdempotencyKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 placeholder:text-slate-600"
                />
              </div>
            </div>

            {method === 'POST' && (
              <div>
                <label className="text-slate-400 text-[11px] block mb-1">Request JSON Body</label>
                <textarea
                  value={requestBody}
                  onChange={(e) => setRequestBody(e.target.value)}
                  rows={4}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 font-mono text-[11px]"
                />
              </div>
            )}

            <div className="flex items-center space-x-2">
              <button
                onClick={handleExecuteRequest}
                disabled={loading}
                className="bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded font-semibold flex items-center space-x-1.5"
              >
                {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Send Request</span>
              </button>

              <button
                onClick={() => {
                  setEndpoint('/api/v1/agents');
                  setMethod('POST');
                  setIdempotencyKey(`idem-${Date.now()}`);
                  setRequestBody(JSON.stringify({ agentId: `agent-sample-${Date.now().toString().slice(-4)}`, canonicalName: 'Sample Agent', framework: 'TypeScript' }, null, 2));
                }}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-2 rounded text-[11px]"
              >
                Preset: Create Agent
              </button>

              <button
                onClick={() => {
                  setEndpoint('/api/v1/policy/evaluations');
                  setMethod('POST');
                  setRequestBody(JSON.stringify({ agentVersionId: 'av-fin-v100', forceBlock: true }, null, 2));
                }}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-2 rounded text-[11px]"
              >
                Preset: Test 422 Policy Block
              </button>
            </div>
          </div>

          {statusCode !== null && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-300">Response Status:</span>
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                  statusCode >= 200 && statusCode < 300 
                    ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400' 
                    : statusCode >= 400 && statusCode < 500
                    ? 'bg-amber-500/10 border border-amber-500/20 text-amber-400'
                    : 'bg-rose-500/10 border border-rose-500/20 text-rose-400'
                }`}>
                  HTTP {statusCode}
                </span>
              </div>
              <pre className="bg-slate-950 p-3 rounded border border-slate-800 max-h-72 overflow-auto text-cyan-300 text-[11px]">
                {JSON.stringify(response, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* 3. Event Catalog Tab */}
      {subTab === 'events' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <h3 className="font-semibold text-slate-200 text-sm mb-3">Architecture V2.0.1 Domain Event Catalog</h3>
            <div className="space-y-3">
              {[
                {
                  eventType: 'agent.registered.v1',
                  domain: 'AGENT',
                  producer: 'service-agent-registry',
                  subscribers: ['queue:knowledge:sync', 'queue:audit:log'],
                  desc: 'Emitted when a new canonical agent is created in the registry',
                },
                {
                  eventType: 'agent.version_created.v1',
                  domain: 'AGENT',
                  producer: 'service-agent-registry',
                  subscribers: ['queue:source:ingestion', 'queue:analysis:dispatch'],
                  desc: 'Emitted when a new agent version is registered for discovery/ingestion',
                },
                {
                  eventType: 'analysis.completed.v1',
                  domain: 'ANALYSIS',
                  producer: 'service-analysis',
                  subscribers: ['queue:validation:run', 'queue:knowledge:projection'],
                  desc: 'Emitted when all analysis stages complete and intelligence claims are established',
                },
                {
                  eventType: 'policy.gate_evaluated.v1',
                  domain: 'POLICY',
                  producer: 'service-policy',
                  subscribers: ['queue:packaging:signing', 'queue:audit:log'],
                  desc: 'Emitted when packaging policy gate evaluates release readiness',
                },
                {
                  eventType: 'package.signed.v1',
                  domain: 'PACKAGING',
                  producer: 'service-packaging',
                  subscribers: ['queue:shipping:delivery', 'queue:audit:log'],
                  desc: 'Emitted when KMS signs an immutable package bundle with Ed25519',
                },
                {
                  eventType: 'package.shipped.v1',
                  domain: 'SHIPPING',
                  producer: 'service-shipping',
                  subscribers: ['queue:audit:log', 'queue:notifications:dispatch'],
                  desc: 'Emitted when a signed package bundle is shipped to target registry/bucket',
                },
              ].map((evt) => (
                <div key={evt.eventType} className="p-3 bg-slate-950 border border-slate-800 rounded">
                  <div className="flex items-center justify-between">
                    <span className="text-cyan-400 font-bold">{evt.eventType}</span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">{evt.domain}</span>
                  </div>
                  <p className="text-slate-400 text-[11px] mt-1">{evt.desc}</p>
                  <div className="mt-2 text-[10px] text-slate-400 flex items-center space-x-4">
                    <span>Producer: <code className="text-indigo-300">{evt.producer}</code></span>
                    <span>Subscribers: <code className="text-emerald-300">{evt.subscribers.join(', ')}</code></span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 4. Queue Ownership Registry Tab */}
      {subTab === 'queues' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <h3 className="font-semibold text-slate-200 text-sm mb-3">Queue Ownership & Dead-Letter Routing Registry</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <th className="pb-2 font-medium">Queue Key</th>
                    <th className="pb-2 font-medium">Domain</th>
                    <th className="pb-2 font-medium">Owning Service</th>
                    <th className="pb-2 font-medium">Concurrency</th>
                    <th className="pb-2 font-medium">Max Lease</th>
                    <th className="pb-2 font-medium">DLQ Key</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-[11px]">
                  {queues.map((q) => (
                    <tr key={q.queue_key} className="hover:bg-slate-800/30">
                      <td className="py-2 text-cyan-300 font-medium">{q.queue_key}</td>
                      <td className="py-2 text-slate-300">{q.domain}</td>
                      <td className="py-2 text-indigo-300">{q.owning_service}</td>
                      <td className="py-2 text-emerald-400 font-bold">{q.concurrency_limit}</td>
                      <td className="py-2 text-slate-400">{q.max_lease_duration_ms / 1000}s</td>
                      <td className="py-2 text-rose-400">{q.dead_letter_queue_key}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
