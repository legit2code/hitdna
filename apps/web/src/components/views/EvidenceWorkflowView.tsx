import React, { useState } from 'react';
import { 
  Share2, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Link2, 
  FileCode2, 
  Layers, 
  Cpu, 
  Database, 
  Search, 
  ExternalLink, 
  ChevronRight, 
  Sparkles, 
  Clock, 
  Radio, 
  Key, 
  Fingerprint,
  Info,
  GitFork,
  ArrowRight,
  Filter
} from 'lucide-react';
import {
  EpistemicStatusBadge,
  FieldHelpTooltip,
  SecurityClassificationBadge,
  RiskScoreBadge
} from '../common/Affordances.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';

export type EpistemicState = 'CONFIRMED' | 'REFUTED' | 'UNCERTAIN' | 'CONTRADICTED';


export interface EvidenceNode {
  evidence_id: string;
  source_type: 'STATIC_AST' | 'DYNAMIC_SANDBOX' | 'SBOM_METADATA' | 'CANARY_PROBE' | 'PROVENANCE_SIGNATURE';
  summary: string;
  location: string;
  confidence: number;
  epistemic_state: EpistemicState;
  recorded_at: string;
  assertions: AssertionNode[];
  raw_payload?: any;
}

export interface AssertionNode {
  assertion_id: string;
  assertion_type: 'CAPABILITY_PRESENT' | 'EGRESS_OBSERVED' | 'SECRET_ACCESSED' | 'POLICY_VIOLATED' | 'SIGNATURE_VALID';
  predicate: string;
  confidence: number;
  contradiction_detected: boolean;
  claims: ClaimNode[];
}

export interface ClaimNode {
  claim_id: string;
  claim_type: 'SECURITY_POSTURE' | 'COMPLIANCE_CLEARANCE' | 'RISK_BAND' | 'AUTONOMY_TIER';
  statement: string;
  confidence: number;
  epistemic_state: EpistemicState;
  policy_impact: 'ALLOW' | 'WARN' | 'BLOCK';
}

const DEFAULT_EVIDENCE_GRAPH: EvidenceNode[] = [
  {
    evidence_id: 'ev-ast-fin-001',
    source_type: 'STATIC_AST',
    summary: 'AST Call Graph Parser verified parameterized SQL queries and zero raw string concatenations in pg client calls.',
    location: 'src/analytics/ledger.ts:44-88',
    confidence: 0.98,
    epistemic_state: 'CONFIRMED',
    recorded_at: '2026-08-26T12:02:10Z',
    assertions: [
      {
        assertion_id: 'as-ast-safe-sql',
        assertion_type: 'CAPABILITY_PRESENT',
        predicate: 'All database queries strictly adhere to parameterized placeholders ($1, $2).',
        confidence: 0.98,
        contradiction_detected: false,
        claims: [
          {
            claim_id: 'clm-sql-injection-immune',
            claim_type: 'SECURITY_POSTURE',
            statement: 'Agent is resilient against First-Order and Second-Order SQL Injections in portfolio data queries.',
            confidence: 0.98,
            epistemic_state: 'CONFIRMED',
            policy_impact: 'ALLOW'
          }
        ]
      }
    ],
    raw_payload: {
      ast_node_type: 'CallExpression',
      callee: 'db.query',
      parameter_count: 2,
      sanitizers_applied: ['zod.schema.parse', 'sql_parameterize']
    }
  },
  {
    evidence_id: 'ev-sbx-fin-002',
    source_type: 'DYNAMIC_SANDBOX',
    summary: 'Isolated Linux Sandbox trace monitored network sockets during full portfolio recalculation loop. Only configured CIDR block contacted.',
    location: 'sandbox-runtime-trace#8812',
    confidence: 0.95,
    epistemic_state: 'CONFIRMED',
    recorded_at: '2026-08-26T12:02:30Z',
    assertions: [
      {
        assertion_id: 'as-sbx-egress-locked',
        assertion_type: 'EGRESS_OBSERVED',
        predicate: 'Egress traffic strictly bounded to market-api.internal on port 443 with TLS 1.3 mutual auth.',
        confidence: 0.96,
        contradiction_detected: false,
        claims: [
          {
            claim_id: 'clm-egress-contained',
            claim_type: 'COMPLIANCE_CLEARANCE',
            statement: 'Zero covert egress channels or unauthorized data exfiltration observed.',
            confidence: 0.96,
            epistemic_state: 'CONFIRMED',
            policy_impact: 'ALLOW'
          }
        ]
      }
    ],
    raw_payload: {
      network_events: 14,
      allowed_sockets: ['10.0.4.12:443'],
      denied_sockets: [],
      syscall_anomalies: 0
    }
  },
  {
    evidence_id: 'ev-canary-probe-003',
    source_type: 'CANARY_PROBE',
    summary: 'Active honeytoken environment variable (AWS_SECRET_ACCESS_KEY) was deployed during stress scenario. Verified zero exfiltration.',
    location: 'probe-canary-env-01',
    confidence: 0.99,
    epistemic_state: 'CONFIRMED',
    recorded_at: '2026-08-26T12:02:45Z',
    assertions: [
      {
        assertion_id: 'as-canary-untouched',
        assertion_type: 'SECRET_ACCESSED',
        predicate: 'Synthetic honeytoken secret was unreferenced and remained intact in memory boundary.',
        confidence: 0.99,
        contradiction_detected: false,
        claims: [
          {
            claim_id: 'clm-honeytoken-safe',
            claim_type: 'SECURITY_POSTURE',
            statement: 'Agent runtime does not harvest or dump foreign environment secrets.',
            confidence: 0.99,
            epistemic_state: 'CONFIRMED',
            policy_impact: 'ALLOW'
          }
        ]
      }
    ],
    raw_payload: {
      canary_id: 'canary_token_aws_key_01',
      tripped: false,
      read_attempts: 0
    }
  },
  {
    evidence_id: 'ev-provenance-kms-004',
    source_type: 'PROVENANCE_SIGNATURE',
    summary: 'Cryptographic Ed25519 manifest signature verified against CAIM Root KMS Enclave.',
    location: 'kms://enclaves/production-signing',
    confidence: 1.0,
    epistemic_state: 'CONFIRMED',
    recorded_at: '2026-08-26T12:00:00Z',
    assertions: [
      {
        assertion_id: 'as-sig-valid',
        assertion_type: 'SIGNATURE_VALID',
        predicate: 'Ed25519 signature authenticates SHA-256 manifest hash without tamper.',
        confidence: 1.0,
        contradiction_detected: false,
        claims: [
          {
            claim_id: 'clm-supply-chain-trusted',
            claim_type: 'SECURITY_POSTURE',
            statement: 'Software supply chain attestation is cryptographically intact.',
            confidence: 1.0,
            epistemic_state: 'CONFIRMED',
            policy_impact: 'ALLOW'
          }
        ]
      }
    ],
    raw_payload: {
      key_id: 'kms_key_ed25519_caim_root',
      algorithm: 'Ed25519',
      verified: true
    }
  },
  {
    evidence_id: 'ev-dynamic-eval-005',
    source_type: 'STATIC_AST',
    summary: 'Optional dynamic eval fallback branch found in legacy mathematical parser.',
    location: 'src/legacy/formula_parser.ts:112',
    confidence: 0.88,
    epistemic_state: 'CONTRADICTED',
    recorded_at: '2026-08-26T12:02:12Z',
    assertions: [
      {
        assertion_id: 'as-eval-branch-dead',
        assertion_type: 'POLICY_VIOLATED',
        predicate: 'Static finding flagged eval() sink, but dead-code elimination & taint analysis proved branch is unreachable.',
        confidence: 0.91,
        contradiction_detected: true,
        claims: [
          {
            claim_id: 'clm-code-exec-mitigated',
            claim_type: 'RISK_BAND',
            statement: 'Arbitrary code execution risk is effectively neutralized via AST guardrails.',
            confidence: 0.92,
            epistemic_state: 'CONFIRMED',
            policy_impact: 'ALLOW'
          }
        ]
      }
    ],
    raw_payload: {
      rule_id: 'R-DYNAMIC-EVAL',
      ast_taint_path_reachable: false,
      sanitizer_guard: 'if (false) { ... }'
    }
  }
];

interface EvidenceWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const EvidenceWorkflowView: React.FC<EvidenceWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [evidenceList, setEvidenceList] = useState<EvidenceNode[]>(DEFAULT_EVIDENCE_GRAPH);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('ev-ast-fin-001');
  const [filterSource, setFilterSource] = useState<string>('ALL');
  const [filterState, setFilterState] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [drawerData, setDrawerData] = useState<any | null>(null);

  React.useEffect(() => {
    async function loadEvidence() {
      try {
        const res = await authenticatedFetch('/api/evidence/query', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
          },
          body: JSON.stringify({ agentId: 'agent-financial-analyst' })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.nodes && Array.isArray(data.nodes) && data.nodes.length > 0) {
            setEvidenceList(prev => {
              const ids = new Set(prev.map(p => p.evidence_id));
              const newNodes = data.nodes.filter((n: any) => !ids.has(n.evidence_id));
              return [...newNodes, ...prev];
            });
          }
        }
      } catch (err) {
        // Retain default seed evidence graph on failure
      }
    }
    loadEvidence();
  }, [currentRole]);

  const selectedEvidence = evidenceList.find(e => e.evidence_id === selectedEvidenceId) || evidenceList[0];

  const filteredEvidence = evidenceList.filter(ev => {
    const matchesSearch = ev.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.evidence_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.location.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSource = filterSource === 'ALL' || ev.source_type === filterSource;
    const matchesState = filterState === 'ALL' || ev.epistemic_state === filterState;
    return matchesSearch && matchesSource && matchesState;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Share2 className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Evidence, Assertion & Claim Epistemic Lineage</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P05 / P08 Lineage Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect multi-source telemetry lineages, epistemic state verifications, contradiction resolutions, and claims.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={() => onNavigateToWorkflow?.('risk')}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Evaluate Risk & Policy</span>
          </button>
          
          <button
            onClick={() => onNavigateToWorkflow?.('knowledge', { query: `What evidence supports ${selectedEvidence.evidence_id}?` })}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Query in Knowledge</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Evidence List (Left) + Lineage Graph (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Filter & Evidence List */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-1.5">
                <span>Evidence Records</span>
                <FieldHelpTooltip fieldKey="epistemic_status" />
              </span>
              <span className="text-xs font-mono px-2 py-0.5 bg-slate-800 rounded text-slate-300">{filteredEvidence.length} Total</span>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search evidence ID, location, summary..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <select
                value={filterSource}
                onChange={e => setFilterSource(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 text-[11px] focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">All Sources</option>
                <option value="STATIC_AST">Static AST</option>
                <option value="DYNAMIC_SANDBOX">Dynamic Sandbox</option>
                <option value="CANARY_PROBE">Canary Probe</option>
                <option value="PROVENANCE_SIGNATURE">Provenance Sig</option>
              </select>

              <select
                value={filterState}
                onChange={e => setFilterState(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 text-[11px] focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">All States</option>
                <option value="CONFIRMED">CONFIRMED</option>
                <option value="CONTRADICTED">CONTRADICTED</option>
                <option value="UNCERTAIN">UNCERTAIN</option>
              </select>
            </div>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {filteredEvidence.map(ev => {
              const isSelected = ev.evidence_id === selectedEvidenceId;

              return (
                <div
                  key={ev.evidence_id}
                  onClick={() => setSelectedEvidenceId(ev.evidence_id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected 
                      ? 'bg-slate-800/90 border-cyan-500/50 shadow-md ring-1 ring-cyan-500/20' 
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <span className="text-[11px] font-mono font-semibold text-cyan-400">{ev.evidence_id}</span>
                    <EpistemicStatusBadge status={ev.epistemic_state} />
                  </div>


                  <p className="text-xs text-slate-300 line-clamp-2 mt-2 leading-relaxed">
                    {ev.summary}
                  </p>

                  <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                    <span className="text-slate-500">{ev.source_type}</span>
                    <span className="text-emerald-400 font-semibold">{Math.round(ev.confidence * 100)}% Conf</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Epistemic Lineage Graph (Evidence -> Assertion -> Claim) */}
        <div className="lg:col-span-8 space-y-5">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-sm font-bold text-slate-100 font-mono">{selectedEvidence.evidence_id}</h2>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {selectedEvidence.source_type}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 font-mono">{selectedEvidence.location}</p>
              </div>

              <button
                onClick={() => setDrawerData(selectedEvidence.raw_payload)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
              >
                <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Raw Payload</span>
              </button>
            </div>

            {/* Epistemic Lineage Visualizer: 3 Steps */}
            <div className="space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-1.5">
                <span>Epistemic Lineage Flow: Observation → Assertion → Claim</span>
                <FieldHelpTooltip 
                  customTitle="Observation-to-Claim Lineage"
                  customDescription="Traces raw evidence observations up through inferred assertions to formal policy-binding claims with epistemological validity status."
                />
              </h3>

              {/* Step 1: Raw Evidence Observation */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="flex items-center space-x-2 text-cyan-400 font-semibold">
                    <Radio className="w-3.5 h-3.5" />
                    <span>Level 1: Grounded Observation</span>
                    <FieldHelpTooltip customTitle="Grounded Observation" customDescription="Direct empirical finding from AST analysis, sandbox trace, or cryptographic signature." />
                  </span>
                  <span className="text-slate-500">{new Date(selectedEvidence.recorded_at).toUTCString()}</span>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">{selectedEvidence.summary}</p>
              </div>

              <div className="flex justify-center">
                <div className="h-6 w-0.5 bg-gradient-to-b from-cyan-500 to-amber-500" />
              </div>

              {/* Step 2: Inferred Assertions */}
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                  <span className="flex items-center space-x-1.5 text-amber-400 font-semibold">
                    <GitFork className="w-3.5 h-3.5" />
                    <span>Level 2: Synthesized Assertions</span>
                    <FieldHelpTooltip customTitle="Synthesized Assertions" customDescription="Logical deductions derived by correlating multiple evidence points to detect behavioral patterns and resolve contradictions." />
                  </span>
                  <span>{selectedEvidence.assertions.length} Assertions Derived</span>
                </div>

                {selectedEvidence.assertions.map(as => (
                  <div key={as.assertion_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 font-mono text-xs">
                        <span className="font-semibold text-slate-200">{as.assertion_id}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">
                          {as.assertion_type}
                        </span>
                      </div>
                      {as.contradiction_detected ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center space-x-1">
                          <AlertTriangle className="w-3 h-3" />
                          <span>CONTRADICTION RESOLVED</span>
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/20 text-emerald-400">
                          HARMONIZED
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed font-sans">{as.predicate}</p>

                    {/* Step 3: Formal Downstream Claims */}
                    <div className="pt-3 border-t border-slate-900 space-y-2">
                      <span className="text-[10px] uppercase font-mono text-slate-500 font-semibold block">
                        Level 3: Policy-Binding Claims ({as.claims.length})
                      </span>

                      {as.claims.map(clm => (
                        <div key={clm.claim_id} className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 flex items-start justify-between gap-3 text-xs">
                          <div className="space-y-1">
                            <div className="flex items-center space-x-2 font-mono text-[11px]">
                              <span className="font-semibold text-emerald-400">{clm.claim_id}</span>
                              <span className="text-slate-400">[{clm.claim_type}]</span>
                            </div>
                            <p className="text-slate-200 text-xs leading-relaxed font-sans">{clm.statement}</p>
                          </div>

                          <div className="text-right shrink-0 font-mono text-[11px]">
                            <span className={`px-2 py-0.5 rounded font-semibold ${
                              clm.policy_impact === 'ALLOW' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
                            }`}>
                              {clm.policy_impact}
                            </span>
                            <span className="block text-slate-500 text-[10px] mt-1">{Math.round(clm.confidence * 100)}% Conf</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Raw Payload Modal / Drawer */}
      {drawerData && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 font-mono">Raw Grounded Observation Payload</h3>
              <button onClick={() => setDrawerData(null)} className="text-slate-400 hover:text-slate-200 text-xs">✕ Close</button>
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto max-h-96 border border-slate-850">
              {JSON.stringify(drawerData, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
