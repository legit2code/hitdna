import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Scale, 
  Sliders, 
  CheckCircle2, 
  XCircle, 
  FileText, 
  Sparkles, 
  Play, 
  RotateCcw, 
  Lock, 
  ExternalLink,
  ChevronRight,
  TrendingDown,
  TrendingUp,
  Cpu,
  Info,
  Shield,
  Layers,
  Award
} from 'lucide-react';
import { DiagnosticMetricsCard } from './DiagnosticMetricsCard.tsx';
import { DiagnosticStatusBadge } from './DiagnosticStatusBadge.tsx';

interface DiagnosticDecisionViewProps {
  currentRole: string;
}

export const DiagnosticDecisionView: React.FC<DiagnosticDecisionViewProps> = ({ currentRole }) => {
  const [scoringModels, setScoringModels] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [selectedModelKey, setSelectedModelKey] = useState<string>('SCORE-MODEL-V1');
  const [selectedPolicyKey, setSelectedPolicyKey] = useState<string>('POLICY-V1-DEFAULT');
  const [useAiSynthesis, setUseAiSynthesis] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<any | null>(null);
  const [overrideReason, setOverrideReason] = useState<string>('');
  const [overrideOutcome, setOverrideOutcome] = useState<string>('ALLOW_WITH_WARNING');
  const [overrideHistory, setOverrideHistory] = useState<any[]>([]);
  const [activeOverride, setActiveOverride] = useState<any | null>(null);
  const [activeTabSection, setActiveTabSection] = useState<'decision' | 'risks' | 'scoring' | 'policy' | 'recommendations' | 'use-cases'>('decision');

  // Load models and policies
  useEffect(() => {
    fetchModelsAndPolicies();
  }, []);

  const fetchModelsAndPolicies = async () => {
    try {
      const [modelsRes, policiesRes] = await Promise.all([
        fetch('/api/dev/decision/scoring-models', { headers: { 'X-Role': currentRole } }),
        fetch('/api/dev/decision/policies', { headers: { 'X-Role': currentRole } }),
      ]);
      if (modelsRes.ok) setScoringModels(await modelsRes.json());
      if (policiesRes.ok) setPolicies(await policiesRes.json());
    } catch (err) {
      console.error('Failed to load decision configurations', err);
    }
  };

  const runDecisionSuite = async (scenarioType: 'CLEAN' | 'CANARY_TRIP' | 'LOW_CONFIDENCE' | 'CRITICAL_INJECTION' | 'EGRESS_VIOLATION') => {
    setLoading(true);
    const runId = `run-${Date.now()}`;
    let payload: any = {
      analysisRunId: runId,
      entityRefId: 'agent-v2-production',
      scoreModelKey: selectedModelKey,
      policyKey: selectedPolicyKey,
      useAiSynthesis,
      confidenceScore: 0.95,
      promptInjectionScore: 0.1,
      staticFindings: [],
      dynamicEvents: [],
      compositionVulnerabilities: [],
      canariesTripped: [],
      evidenceList: [
        { evidence_id: `ev-ast-${runId.substring(0, 6)}`, summary: 'Static AST Call Graph Parser Evidence' },
        { evidence_id: `ev-sbx-${runId.substring(0, 6)}`, summary: 'Dynamic Sandbox Telemetry Trace' },
      ],
    };

    if (scenarioType === 'CANARY_TRIP') {
      // High score potential but Canary leak hard quarantine
      payload.canariesTripped = [{ canary_id: 'canary-honeytoken-1', token_type: 'AWS_KEY', tripped_at: new Date().toISOString() }];
      payload.dynamicEvents = [{ event_type: 'CANARY_ACCESS', path: '/run/secrets/canary.env', process_name: 'agent_eval' }];
      payload.staticFindings = [];
    } else if (scenarioType === 'LOW_CONFIDENCE') {
      // Moderate score with low confidence (< 0.70) requiring manual review
      payload.confidenceScore = 0.55;
      payload.staticFindings = [{ rule_id: 'R-DYNAMIC-EVAL', category: 'CODE_EXECUTION', title: 'Dynamic eval usage in plugin loader', severity: 'MEDIUM' }];
    } else if (scenarioType === 'CRITICAL_INJECTION') {
      // Critical injection sink hard block
      payload.staticFindings = [
        { rule_id: 'R-PROMPT-INJECTION-SINK', category: 'PROMPT_INJECTION', title: 'Direct unsanitized input to execute_sql sink', severity: 'CRITICAL' },
        { rule_id: 'R-SUBPROCESS-SINK', category: 'CODE_EXECUTION', title: 'Unvalidated shell exec call', severity: 'HIGH' },
      ];
      payload.promptInjectionScore = 0.92;
    } else if (scenarioType === 'EGRESS_VIOLATION') {
      // Egress violation leading to restriction
      payload.dynamicEvents = [{ event_type: 'EGRESS_VIOLATION', target: '203.0.113.88:443', process_name: 'curl' }];
    }

    try {
      const res = await fetch('/api/dev/decision/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        setResult(data);
        setActiveOverride(data.active_override || null);
        fetchOverrideHistory(runId);
      }
    } catch (err) {
      console.error('Failed to run decision suite', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchOverrideHistory = async (runId: string) => {
    try {
      const res = await fetch(`/api/dev/decision/overrides/${runId}`, {
        headers: { 'X-Role': currentRole },
      });
      if (res.ok) {
        const data = await res.json();
        setOverrideHistory(data.history || []);
        setActiveOverride(data.active || null);
      }
    } catch (err) {
      console.error('Failed to fetch overrides', err);
    }
  };

  const handleApplyOverride = async () => {
    if (!result) return;
    if (!overrideReason || overrideReason.trim().length < 10) {
      alert('Override reason must be at least 10 characters.');
      return;
    }

    try {
      const res = await fetch('/api/dev/decision/overrides', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({
          analysisRunId: result.analysis_run_id,
          originalOutcome: result.policy_decision.outcome,
          overriddenOutcome: overrideOutcome,
          reason: overrideReason,
          approverId: 'security-operator-01',
          approverRole: currentRole,
          justificationDetails: `Operator manual signoff override under ISO-27001 exception procedure.`,
        }),
      });
      if (res.ok) {
        setOverrideReason('');
        fetchOverrideHistory(result.analysis_run_id);
      }
    } catch (err) {
      console.error('Failed to apply override', err);
    }
  };

  const handleRevokeOverride = async (overrideId: string) => {
    if (!result) return;
    try {
      const res = await fetch('/api/dev/decision/overrides/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({
          overrideId,
          revokerId: 'security-operator-01',
        }),
      });
      if (res.ok) {
        fetchOverrideHistory(result.analysis_run_id);
      }
    } catch (err) {
      console.error('Failed to revoke override', err);
    }
  };

  const getOutcomeColor = (outcome: string) => {
    switch (outcome) {
      case 'ALLOW': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'ALLOW_WITH_WARNING': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'REQUIRE_REVIEW': return 'text-sky-400 bg-sky-500/10 border-sky-500/30';
      case 'RESTRICT': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'QUARANTINE': return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'DENY_SHIPPING': return 'text-red-500 bg-red-500/20 border-red-500/40';
      default: return 'text-slate-400 bg-slate-800 border-slate-700';
    }
  };

  return (
    <div className="space-y-6 font-mono" id="diagnostic-decision-view">
      {/* Top Banner & Simulator Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Scale className="w-5 h-5 text-indigo-400" />
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Risk, Scoring & Policy Decision Engine (Architecture V2.0.1)
              </h2>
              <span className="text-[10px] bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 px-2 py-0.5 rounded">
                P21 Standard
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Versioned scoring models • Hard policy blocks • Evidence validation • Audit override trail • 3+3 Use-case intelligence
            </p>
          </div>

          {/* Model & Policy Selectors */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="flex items-center space-x-1.5 bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800">
              <span className="text-slate-500">Scoring:</span>
              <select
                value={selectedModelKey}
                onChange={(e) => setSelectedModelKey(e.target.value)}
                className="bg-transparent text-cyan-300 font-semibold focus:outline-none cursor-pointer"
                id="select-scoring-model"
              >
                {scoringModels.map((m) => (
                  <option key={m.model_key} value={m.model_key} className="bg-slate-900">
                    {m.name} ({m.version})
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center space-x-1.5 bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800">
              <span className="text-slate-500">Policy:</span>
              <select
                value={selectedPolicyKey}
                onChange={(e) => setSelectedPolicyKey(e.target.value)}
                className="bg-transparent text-indigo-300 font-semibold focus:outline-none cursor-pointer"
                id="select-policy-engine"
              >
                {policies.map((p) => (
                  <option key={p.policy_key} value={p.policy_key} className="bg-slate-900">
                    {p.name} ({p.version})
                  </option>
                ))}
              </select>
            </div>

            <label className="flex items-center space-x-1.5 bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800 cursor-pointer text-slate-300">
              <input
                type="checkbox"
                checked={useAiSynthesis}
                onChange={(e) => setUseAiSynthesis(e.target.checked)}
                className="rounded border-slate-700 text-indigo-500 focus:ring-0"
              />
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              <span>Gemini AI Synthesis</span>
            </label>
          </div>
        </div>

        {/* Diagnostic Preset Scenarios */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-semibold flex items-center gap-1">
            <Play className="w-3 h-3 text-cyan-400" /> Test Scenarios:
          </span>
          <button
            onClick={() => runDecisionSuite('CLEAN')}
            disabled={loading}
            className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-all font-semibold"
            id="scenario-clean-btn"
          >
            Clean Baseline (ALLOW)
          </button>
          <button
            onClick={() => runDecisionSuite('CANARY_TRIP')}
            disabled={loading}
            className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 transition-all font-semibold"
            id="scenario-canary-btn"
          >
            Favorable Score + Canary Trip (Hard QUARANTINE)
          </button>
          <button
            onClick={() => runDecisionSuite('CRITICAL_INJECTION')}
            disabled={loading}
            className="px-2.5 py-1 rounded bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all font-semibold"
            id="scenario-injection-btn"
          >
            Direct Injection Sink (Hard DENY_SHIPPING)
          </button>
          <button
            onClick={() => runDecisionSuite('LOW_CONFIDENCE')}
            disabled={loading}
            className="px-2.5 py-1 rounded bg-sky-500/10 border border-sky-500/20 text-sky-400 hover:bg-sky-500/20 transition-all font-semibold"
            id="scenario-confidence-btn"
          >
            Low Confidence Review (REQUIRE_REVIEW)
          </button>
          <button
            onClick={() => runDecisionSuite('EGRESS_VIOLATION')}
            disabled={loading}
            className="px-2.5 py-1 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400 hover:bg-orange-500/20 transition-all font-semibold"
            id="scenario-egress-btn"
          >
            Egress Anomaly (RESTRICT)
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-10 text-center space-y-3">
          <div className="animate-spin w-6 h-6 border-2 border-indigo-400 border-t-transparent rounded-full mx-auto" />
          <p className="text-xs text-slate-300">Evaluating multi-dimensional risk matrix and policy rules...</p>
        </div>
      )}

      {!loading && !result && (
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-12 text-center space-y-3">
          <Scale className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-300">No Decision Suite Execution Active</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Select a test scenario above or trigger analysis to inspect scores, versioned risk rules, hard policy blocks, recommendations, and use cases.
          </p>
        </div>
      )}

      {!loading && result && (
        <div className="space-y-6">
          {/* Executive Overview Banner */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 uppercase font-semibold">Policy Outcome</span>
              <div className="mt-2 flex items-center justify-between">
                <span className={`text-base font-bold px-2.5 py-1 rounded border uppercase ${getOutcomeColor(activeOverride ? activeOverride.overridden_outcome : result.policy_decision.outcome)}`}>
                  {activeOverride ? activeOverride.overridden_outcome : result.policy_decision.outcome}
                </span>
                {activeOverride && (
                  <span className="text-[10px] bg-amber-500/20 border border-amber-500/40 text-amber-400 px-1.5 py-0.5 rounded">
                    OVERRIDDEN
                  </span>
                )}
              </div>
              <span className="text-[10px] text-slate-500 mt-2">
                Rules: {result.policy_decision.policy_key} ({result.policy_decision.policy_version})
              </span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 uppercase font-semibold">Security Score</span>
              <div className="mt-2 flex items-baseline justify-between">
                <span className="text-3xl font-bold text-cyan-400">
                  {result.score_result.overall_score}<span className="text-xs text-slate-500">/100</span>
                </span>
                <span className="text-xs font-bold text-slate-200 bg-slate-800 px-2 py-0.5 rounded">
                  Grade {result.score_result.grade}
                </span>
              </div>
              <span className="text-[10px] text-slate-500 mt-2">
                Band: {result.score_result.risk_band} • Model: {result.score_result.model_key}
              </span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 uppercase font-semibold">Risk & Policy Conflicts</span>
              <div className="mt-2 flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <span className="text-lg font-bold text-slate-100">
                  {result.risks.length} <span className="text-xs font-normal text-slate-400">Risks Identified</span>
                </span>
              </div>
              <span className="text-[10px] text-slate-500 mt-2">
                {result.policy_decision.score_override_applied ? (
                  <span className="text-amber-400 font-semibold">Hard Policy Rule Overrode Score</span>
                ) : (
                  'Score aligns with policy outcome'
                )}
              </span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 uppercase font-semibold">Execution Confidence</span>
              <div className="mt-2 flex items-baseline justify-between">
                <span className="text-2xl font-bold text-emerald-400">
                  {(result.confidence_score * 100).toFixed(0)}%
                </span>
                <span className="text-[10px] text-slate-400">
                  {result.duration_ms}ms runtime
                </span>
              </div>
              <span className="text-[10px] text-slate-500 mt-2">
                {result.recommendations.length} Actionable Recs • {result.use_case_evaluations.length} Use-cases
              </span>
            </div>
          </div>

          {/* Hard Block / Policy Conflict Alert */}
          {result.policy_decision.score_override_applied && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3.5 flex items-start space-x-3 text-xs">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-amber-300 uppercase">Policy Override Notice: </span>
                <span className="text-slate-300">{result.policy_decision.score_vs_policy_notes}</span>
              </div>
            </div>
          )}

          {/* Navigation Tabs for Sections */}
          <div className="flex border-b border-slate-800 text-xs">
            <button
              onClick={() => setActiveTabSection('decision')}
              className={`px-4 py-2 border-b-2 font-semibold transition-all ${
                activeTabSection === 'decision'
                  ? 'border-indigo-400 text-indigo-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Executive Summary
            </button>
            <button
              onClick={() => setActiveTabSection('scoring')}
              className={`px-4 py-2 border-b-2 font-semibold transition-all ${
                activeTabSection === 'scoring'
                  ? 'border-indigo-400 text-indigo-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Score Dimensions ({result.score_result.dimensions.length})
            </button>
            <button
              onClick={() => setActiveTabSection('risks')}
              className={`px-4 py-2 border-b-2 font-semibold transition-all ${
                activeTabSection === 'risks'
                  ? 'border-indigo-400 text-indigo-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Risk Matrix ({result.risks.length})
            </button>
            <button
              onClick={() => setActiveTabSection('policy')}
              className={`px-4 py-2 border-b-2 font-semibold transition-all ${
                activeTabSection === 'policy'
                  ? 'border-indigo-400 text-indigo-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Policy Rules & Overrides
            </button>
            <button
              onClick={() => setActiveTabSection('recommendations')}
              className={`px-4 py-2 border-b-2 font-semibold transition-all ${
                activeTabSection === 'recommendations'
                  ? 'border-indigo-400 text-indigo-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Evidence Recommendations ({result.recommendations.length})
            </button>
            <button
              onClick={() => setActiveTabSection('use-cases')}
              className={`px-4 py-2 border-b-2 font-semibold transition-all ${
                activeTabSection === 'use-cases'
                  ? 'border-indigo-400 text-indigo-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Use-Case Suitability (3+3 Matrix)
            </button>
          </div>

          {/* TAB 1: Executive Summary */}
          {activeTabSection === 'decision' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                <h3 className="text-xs font-bold text-slate-200 uppercase">Policy Evaluation Breakdown</h3>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded border border-slate-800/80">
                  {result.policy_decision.evaluation_summary}
                </p>

                {result.policy_decision.reasons.length > 0 && (
                  <div className="space-y-2 mt-3">
                    <span className="text-[11px] text-slate-400 font-semibold">Triggered Policy Reasons:</span>
                    <div className="space-y-1.5">
                      {result.policy_decision.reasons.map((r: any, idx: number) => (
                        <div
                          key={idx}
                          className={`p-2.5 rounded border text-xs flex items-start justify-between ${
                            r.is_blocking ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' : 'bg-slate-950 border-slate-800 text-slate-300'
                          }`}
                        >
                          <div>
                            <span className="font-bold">{r.rule_name || r.rule_key}: </span>
                            <span>{r.reason_text}</span>
                            {r.evidence_ids && r.evidence_ids.length > 0 && (
                              <div className="mt-1 flex items-center gap-1 text-[10px] text-slate-400">
                                <FileText className="w-3 h-3 text-cyan-400" />
                                <span>Evidence: {r.evidence_ids.join(', ')}</span>
                              </div>
                            )}
                          </div>
                          {r.is_blocking && (
                            <span className="text-[10px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold uppercase shrink-0">
                              Blocking Rule
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: Scoring Dimensions */}
          {activeTabSection === 'scoring' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xs font-bold text-slate-200 uppercase">
                    Scoring Model Dimensions • {result.score_result.model_key} ({result.score_result.model_version})
                  </h3>
                  <span className="text-xs text-cyan-400 font-bold">
                    Composite Score: {result.score_result.overall_score}/100
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {result.score_result.dimensions.map((dim: any) => (
                    <div key={dim.dimension_key} className="bg-slate-950 border border-slate-800 rounded p-3 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-200">{dim.name}</span>
                        <span className="text-xs font-bold text-cyan-400">{dim.score}/100</span>
                      </div>
                      <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${
                            dim.score >= 80 ? 'bg-emerald-500' : dim.score >= 60 ? 'bg-amber-500' : 'bg-rose-500'
                          }`}
                          style={{ width: `${Math.max(5, dim.score)}%` }}
                        />
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-slate-400">
                        <span>Weight: {(dim.weight * 100).toFixed(0)}%</span>
                        <span>Deductions: -{dim.deductions}</span>
                      </div>
                      {dim.deduction_reasons.length > 0 && (
                        <div className="text-[10px] text-rose-400 bg-rose-500/5 p-1.5 rounded border border-rose-500/10">
                          {dim.deduction_reasons.join('; ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Risk Matrix */}
          {activeTabSection === 'risks' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <h3 className="text-xs font-bold text-slate-200 uppercase mb-3">
                  Evaluated Risk Items ({result.risks.length})
                </h3>

                {result.risks.length === 0 ? (
                  <p className="text-xs text-emerald-400">No active unmitigated risks identified.</p>
                ) : (
                  <div className="space-y-2">
                    {result.risks.map((risk: any) => (
                      <div
                        key={risk.risk_id}
                        className="bg-slate-950 border border-slate-800 rounded p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                                risk.severity === 'CRITICAL'
                                  ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                  : risk.severity === 'HIGH'
                                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                                  : risk.severity === 'MEDIUM'
                                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                  : 'bg-slate-800 text-slate-300'
                              }`}
                            >
                              {risk.severity}
                            </span>
                            <span className="font-bold text-slate-200">{risk.title}</span>
                            <span className="text-[10px] text-slate-500">({risk.risk_type})</span>
                          </div>
                          <p className="text-slate-400 text-xs">{risk.description}</p>
                          <div className="flex items-center space-x-3 text-[10px] text-slate-500">
                            <span>Likelihood: {risk.likelihood}</span>
                            <span>Impact: {risk.impact}</span>
                            <span>Rule: {risk.rule_id}</span>
                          </div>
                        </div>

                        <div className="shrink-0 text-[10px] text-right space-y-1">
                          <div className="text-slate-400">
                            Evidence Links ({risk.evidence_links.length}):
                          </div>
                          <div className="flex flex-wrap gap-1 justify-end">
                            {risk.evidence_links.map((e: any, idx: number) => (
                              <span key={idx} className="bg-slate-900 border border-slate-700 px-1.5 py-0.5 rounded text-cyan-300">
                                {e.evidence_id}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: Policy Overrides & Audit Trail */}
          {activeTabSection === 'policy' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-200 uppercase flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-indigo-400" />
                    Authorized Policy Override & Governance Sign-Off
                  </h3>
                  <span className="text-[10px] text-slate-400">
                    Operator Audit Procedure ISO-27001
                  </span>
                </div>

                {/* Apply Override Form */}
                <div className="bg-slate-950 border border-slate-800 rounded p-3 space-y-3">
                  <span className="text-xs font-semibold text-slate-300">Request Role-Based Override:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                    <div>
                      <label className="text-[10px] text-slate-400">Target Override Outcome</label>
                      <select
                        value={overrideOutcome}
                        onChange={(e) => setOverrideOutcome(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 mt-1"
                        id="override-outcome-select"
                      >
                        <option value="ALLOW">ALLOW</option>
                        <option value="ALLOW_WITH_WARNING">ALLOW_WITH_WARNING</option>
                        <option value="REQUIRE_REVIEW">REQUIRE_REVIEW</option>
                        <option value="RESTRICT">RESTRICT</option>
                        <option value="QUARANTINE">QUARANTINE</option>
                        <option value="DENY_SHIPPING">DENY_SHIPPING</option>
                      </select>
                    </div>

                    <div className="sm:col-span-2">
                      <label className="text-[10px] text-slate-400">Justification & Exception Audit Reason (Min 10 Chars)</label>
                      <div className="flex gap-2 mt-1">
                        <input
                          type="text"
                          value={overrideReason}
                          onChange={(e) => setOverrideReason(e.target.value)}
                          placeholder="e.g. Approved exception by SecOps Lead for internal staging deployment"
                          className="flex-1 bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                          id="override-reason-input"
                        />
                        <button
                          onClick={handleApplyOverride}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-bold text-xs shrink-0"
                          id="apply-override-btn"
                        >
                          Sign & Apply
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Audit History */}
                <div>
                  <h4 className="text-xs font-bold text-slate-300 mb-2">Override Audit Trail ({overrideHistory.length}):</h4>
                  {overrideHistory.length === 0 ? (
                    <p className="text-xs text-slate-500">No overrides applied to this analysis run.</p>
                  ) : (
                    <div className="space-y-2">
                      {overrideHistory.map((ovr: any) => (
                        <div
                          key={ovr.override_id}
                          className="bg-slate-950 border border-slate-800 rounded p-3 text-xs flex items-center justify-between"
                        >
                          <div className="space-y-1">
                            <div className="flex items-center space-x-2">
                              <span
                                className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                                  ovr.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-400'
                                }`}
                              >
                                {ovr.status}
                              </span>
                              <span className="text-slate-400">
                                {ovr.original_outcome} ➔ <strong className="text-slate-100">{ovr.overridden_outcome}</strong>
                              </span>
                              <span className="text-[10px] text-slate-500">by {ovr.approver_id} ({ovr.approver_role})</span>
                            </div>
                            <p className="text-slate-300 italic">"{ovr.reason}"</p>
                          </div>

                          {ovr.status === 'ACTIVE' && (
                            <button
                              onClick={() => handleRevokeOverride(ovr.override_id)}
                              className="px-2 py-1 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 hover:bg-rose-500/20 text-xs"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: Evidence-Backed Recommendations */}
          {activeTabSection === 'recommendations' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <h3 className="text-xs font-bold text-slate-200 uppercase mb-3">
                  Actionable Security Recommendations ({result.recommendations.length})
                </h3>

                <div className="space-y-2.5">
                  {result.recommendations.map((rec: any) => (
                    <div key={rec.recommendation_id} className="bg-slate-950 border border-slate-800 rounded p-3 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                              rec.priority === 'P0'
                                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                : rec.priority === 'P1'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {rec.priority}
                          </span>
                          <span className="font-bold text-slate-200">{rec.title}</span>
                          <span className="text-[10px] text-slate-500">[{rec.recommendation_type}]</span>
                        </div>
                        <span className="text-[10px] text-slate-400">Effort: {rec.effort_estimate}</span>
                      </div>

                      <p className="text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-800/60">
                        {rec.action_steps}
                      </p>

                      <div className="flex items-center space-x-2 text-[10px] text-slate-500">
                        <span>Supporting Evidence:</span>
                        {rec.evidence_ids.map((eid: string, idx: number) => (
                          <span key={idx} className="bg-slate-900 border border-slate-700 px-1 py-0.5 rounded text-cyan-300">
                            {eid}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: Use-Case Suitability (3+3 Matrix) */}
          {activeTabSection === 'use-cases' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold text-slate-200 uppercase">
                    Use-Case Intelligence Matrix (Standard V1 Profile: 3 Positive + 3 Negative)
                  </h3>
                  <span className="text-[10px] bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 px-2 py-0.5 rounded">
                    Mandatory 6-Case Audit
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.use_case_evaluations.map((uc: any) => (
                    <div
                      key={uc.evaluation_id}
                      className={`p-3.5 rounded border text-xs space-y-2 ${
                        uc.category === 'POSITIVE'
                          ? uc.suitability === 'APPROVED'
                            ? 'bg-emerald-500/5 border-emerald-500/20'
                            : uc.suitability === 'CONDITIONALLY_APPROVED'
                            ? 'bg-amber-500/5 border-amber-500/20'
                            : 'bg-rose-500/5 border-rose-500/20'
                          : 'bg-slate-950 border-slate-800'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                            uc.category === 'POSITIVE' ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                          }`}>
                            {uc.category}
                          </span>
                          <h4 className="font-bold text-slate-200 mt-1">{uc.title}</h4>
                        </div>
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase shrink-0 ${
                            uc.suitability === 'APPROVED'
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                              : uc.suitability === 'CONDITIONALLY_APPROVED'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          }`}
                        >
                          {uc.suitability}
                        </span>
                      </div>

                      <p className="text-slate-400 text-[11px] leading-relaxed">
                        {uc.justification}
                      </p>

                      <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
                        <span>Suitability Score: {(uc.suitability_score * 100).toFixed(0)}%</span>
                        <span>Evidence: {uc.evidence_ids.join(', ')}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
