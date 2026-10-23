import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  PlayCircle,
  RefreshCw,
  Search,
  Filter,
  Layers,
  Sparkles,
  GitFork,
  FileCode2,
  Lock,
  Database,
  Cpu,
  Fingerprint,
  Scale,
  Gauge,
  Sliders,
  Award
} from 'lucide-react';
import {
  GoldenCorpusFamily,
  GoldenTestFixture,
  EvaluationRun,
  ReleaseGateDecision,
  RegressionThresholds,
  GOLDEN_CORPUS_FIXTURES,
  PRODUCTION_REGRESSION_THRESHOLDS
} from '../../../../../packages/contracts/src/evaluation.ts';
import { FieldHelpTooltip } from '../common/Affordances.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';

interface GoldenCorpusWorkflowViewProps {
  currentRole: string;
}

export const GoldenCorpusWorkflowView: React.FC<GoldenCorpusWorkflowViewProps> = ({ currentRole }) => {
  const [activeTab, setActiveTab] = useState<'fixtures' | 'evaluator' | 'thresholds' | 'verification'>('evaluator');
  const [fixtures, setFixtures] = useState<GoldenTestFixture[]>(GOLDEN_CORPUS_FIXTURES);
  const [selectedFamily, setSelectedFamily] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedFixture, setSelectedFixture] = useState<GoldenTestFixture | null>(GOLDEN_CORPUS_FIXTURES[0]);

  // Evaluator State
  const [engineVersion, setEngineVersion] = useState<string>('v2.1.0-candidate');
  const [baselineVersion, setBaselineVersion] = useState<string>('v2.0.1-certified');
  const [isConclusionChanging, setIsConclusionChanging] = useState<boolean>(true);
  const [simulateRegression, setSimulateRegression] = useState<boolean>(false);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  
  const [currentRun, setCurrentRun] = useState<EvaluationRun | null>(null);
  const [currentDecision, setCurrentDecision] = useState<ReleaseGateDecision | null>(null);

  // Verification Test State
  const [verificationResults, setVerificationResults] = useState<{
    passed: boolean;
    testResults: Array<{ name: string; status: 'PASS' | 'FAIL'; details: string }>;
  } | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);

  // Initialize with a baseline evaluation run
  useEffect(() => {
    handleRunEvaluation(false);
  }, []);

  const handleRunEvaluation = async (simulate: boolean = simulateRegression) => {
    setEvaluating(true);
    try {
      const res = await authenticatedFetch('/api/dev/evaluation/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          engineVersion,
          baselineEngineVersion: baselineVersion,
          isConclusionChanging,
          simulateRegression: simulate
        })
      });

      if (res.ok) {
        const data = await res.json();
        setCurrentRun(data.run);
        setCurrentDecision(data.decision);
      } else {
        const errData = await res.json().catch(() => ({}));
        setCurrentRun(null);
        setCurrentDecision({
          engineVersion,
          evaluatedAt: new Date().toISOString(),
          isConclusionChanging,
          canDeployToProduction: false,
          gateStatus: 'BLOCKED',
          summary: errData.error || 'Evaluation service unavailable.',
          blockingReasons: [errData.error || 'Service request returned failure'],
          evaluationRunId: 'err-' + Date.now(),
        });
      }
    } catch (err: any) {
      setCurrentRun(null);
      setCurrentDecision({
        engineVersion,
        evaluatedAt: new Date().toISOString(),
        isConclusionChanging,
        canDeployToProduction: false,
        gateStatus: 'BLOCKED',
        summary: err?.message || 'Network error executing evaluation.',
        blockingReasons: [err?.message || 'Network error'],
        evaluationRunId: 'err-' + Date.now(),
      });
    } finally {
      setEvaluating(false);
    }
  };

  const handleRunVerification = async () => {
    setVerifying(true);
    try {
      const res = await authenticatedFetch('/api/dev/evaluation/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      });
      if (res.ok) {
        setVerificationResults(await res.json());
      } else {
        setVerificationResults({
          passed: false,
          testResults: [{ name: 'Evaluation Verification Service', status: 'FAIL', details: 'Endpoint returned failure' }]
        });
      }
    } catch {
      setVerificationResults({
        passed: false,
        testResults: [{ name: 'Evaluation Verification Service', status: 'FAIL', details: 'Network unreachable' }]
      });
    } finally {
      setVerifying(false);
    }
  };

  const filteredFixtures = fixtures.filter(f => {
    const matchesFamily = selectedFamily === 'ALL' || f.family === selectedFamily;
    const matchesSearch = f.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          f.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          f.fixtureId.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFamily && matchesSearch;
  });

  const familiesList: GoldenCorpusFamily[] = Array.from(new Set(fixtures.map(f => f.family)));

  return (
    <div className="space-y-6">
      {/* Top Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden shadow-lg">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <Award className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                  P31 — Golden Corpus & Release Gate Evaluations
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono">
                    19 Families Active
                  </span>
                  <FieldHelpTooltip customTitle="Golden Corpus Evaluation" customDescription="Exhaustive benchmark suite comparing candidate release versions against baseline ground-truth test cases to ensure zero safety or policy regressions." />
                </h2>
                <p className="text-sm text-slate-400 font-mono">
                  Automated CI Release Gates • Zero Policy Regressions • 100% RLS Tenant Isolation • NFR-EVAL
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => handleRunEvaluation(false)}
              disabled={evaluating}
              className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition shadow-md disabled:opacity-50"
              id="run-golden-eval-btn"
            >
              <PlayCircle className={`w-4 h-4 ${evaluating ? 'animate-spin' : ''}`} />
              <span>{evaluating ? 'Evaluating...' : 'Run Golden Evaluation'}</span>
            </button>

            <button
              onClick={handleRunVerification}
              disabled={verifying}
              className="flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm font-semibold border border-slate-700 transition disabled:opacity-50"
              id="run-p31-verify-btn"
            >
              <ShieldCheck className={`w-4 h-4 text-emerald-400 ${verifying ? 'animate-spin' : ''}`} />
              <span>Verify Release Gates</span>
            </button>
          </div>
        </div>

        {/* View Navigation Tabs */}
        <div className="flex space-x-2 border-t border-slate-800/80 pt-4 mt-6">
          <button
            onClick={() => setActiveTab('evaluator')}
            className={`px-4 py-2 rounded-lg text-sm font-semibold transition flex items-center space-x-2 ${
              activeTab === 'evaluator'
                ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Scale className="w-4 h-4" />
            <span>Release Gate Decision Engine</span>
          </button>

          <button
            onClick={() => setActiveTab('fixtures')}
            className={`px-4 py-2 rounded-lg text-sm font-semibold transition flex items-center space-x-2 ${
              activeTab === 'fixtures'
                ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>19 Golden Corpus Families ({fixtures.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('thresholds')}
            className={`px-4 py-2 rounded-lg text-sm font-semibold transition flex items-center space-x-2 ${
              activeTab === 'thresholds'
                ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Gauge className="w-4 h-4" />
            <span>NFR-EVAL Thresholds Matrix</span>
          </button>

          <button
            onClick={() => setActiveTab('verification')}
            className={`px-4 py-2 rounded-lg text-sm font-semibold transition flex items-center space-x-2 ${
              activeTab === 'verification'
                ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Verification Test Suite</span>
          </button>
        </div>
      </div>

      {/* TAB 1: RELEASE GATE DECISION ENGINE */}
      {activeTab === 'evaluator' && currentRun && currentDecision && (
        <div className="space-y-6">
          {/* Release Gate Decision Banner */}
          <div className={`p-6 rounded-xl border ${
            currentDecision.canDeployToProduction
              ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
              : 'bg-rose-950/20 border-rose-500/40 text-rose-300'
          }`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start space-x-4">
                <div className={`p-3 rounded-xl ${
                  currentDecision.canDeployToProduction ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
                }`}>
                  {currentDecision.canDeployToProduction ? (
                    <ShieldCheck className="w-8 h-8" />
                  ) : (
                    <ShieldAlert className="w-8 h-8" />
                  )}
                </div>
                <div>
                  <div className="flex items-center space-x-3">
                    <h3 className="text-xl font-bold">
                      {currentDecision.canDeployToProduction
                        ? 'PRODUCTION RELEASE GATE: CLEARED (PASSED)'
                        : 'PRODUCTION RELEASE GATE: REJECTED (REGRESSION DETECTED)'}
                    </h3>
                    <span className={`text-xs px-2.5 py-1 rounded font-mono font-bold uppercase ${
                      currentDecision.canDeployToProduction
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    }`}>
                      {currentDecision.gateStatus}
                    </span>
                    <FieldHelpTooltip customTitle="Production Release Gate" customDescription="Automated gate enforcing strict mathematical non-regression invariant: blocking any release that degrades security score or introduces new taint reachability." />
                  </div>
                  <p className="text-sm mt-1 opacity-90">{currentDecision.summary}</p>
                  <div className="flex items-center space-x-4 text-xs font-mono mt-2 text-slate-400">
                    <span>Candidate: <strong className="text-slate-200">{currentDecision.engineVersion}</strong></span>
                    <span>Evaluated: {new Date(currentDecision.evaluatedAt).toLocaleTimeString()}</span>
                    <span>Conclusion-Affecting: <strong>{currentDecision.isConclusionChanging ? 'YES' : 'NO'}</strong></span>
                    <span>Attestation: <strong className="text-cyan-400">{currentRun.signatureSha256.substring(0, 18)}...</strong></span>
                  </div>
                </div>
              </div>

              <div className="flex flex-col items-end gap-2">
                <div className="flex items-center space-x-2">
                  <label className="text-xs text-slate-300 font-mono flex items-center space-x-1.5 cursor-pointer bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
                    <input
                      type="checkbox"
                      checked={simulateRegression}
                      onChange={(e) => {
                        setSimulateRegression(e.target.checked);
                        handleRunEvaluation(e.target.checked);
                      }}
                      className="rounded border-slate-700 text-rose-500 focus:ring-rose-500"
                    />
                    <span className="text-rose-400 font-semibold">Simulate Regression Tripwire</span>
                  </label>
                </div>
              </div>
            </div>

            {/* Blocking Violations List if any */}
            {currentDecision.blockingReasons.length > 0 && (
              <div className="mt-4 pt-4 border-t border-rose-500/30 space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 font-mono flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Release Blocking Violations:
                </h4>
                <div className="space-y-1">
                  {currentDecision.blockingReasons.map((reason, idx) => (
                    <div key={idx} className="text-xs font-mono bg-rose-900/30 text-rose-200 px-3 py-1.5 rounded border border-rose-500/20">
                      • {reason}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Key Metric Scorecards Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-mono">F1-Score</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${
                currentRun.metrics.f1Score >= PRODUCTION_REGRESSION_THRESHOLDS.minF1Score ? 'text-emerald-400' : 'text-rose-400'
              }`}>
                {(currentRun.metrics.f1Score * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Min: {(PRODUCTION_REGRESSION_THRESHOLDS.minF1Score * 100)}%</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-mono">Policy Regressions</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${
                currentRun.metrics.policyRegressionCount === 0 ? 'text-emerald-400' : 'text-rose-400'
              }`}>
                {currentRun.metrics.policyRegressionCount}
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Max allowed: 0</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-mono">Taint Path Recall</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${
                currentRun.metrics.taintPathRecall >= PRODUCTION_REGRESSION_THRESHOLDS.minTaintRecall ? 'text-emerald-400' : 'text-rose-400'
              }`}>
                {(currentRun.metrics.taintPathRecall * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Min: {(PRODUCTION_REGRESSION_THRESHOLDS.minTaintRecall * 100)}%</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-mono">RLS Tenant Negative</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${
                currentRun.metrics.rlsAuthorizationNegativePassRate === 1.0 ? 'text-emerald-400' : 'text-rose-400'
              }`}>
                {(currentRun.metrics.rlsAuthorizationNegativePassRate * 100).toFixed(0)}%
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Target: 100% Zero-Leak</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-mono">RAG MRR & Recall@5</div>
              <div className="text-2xl font-bold font-mono mt-1 text-cyan-400">
                {(currentRun.metrics.meanReciprocalRank * 100).toFixed(0)}%
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Recall: {(currentRun.metrics.recallAtK * 100).toFixed(0)}%</div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <div className="text-xs text-slate-400 font-mono">Unsupported Claims</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${
                currentRun.metrics.unsupportedClaimRate <= PRODUCTION_REGRESSION_THRESHOLDS.maxUnsupportedClaimRate ? 'text-emerald-400' : 'text-rose-400'
              }`}>
                {(currentRun.metrics.unsupportedClaimRate * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-0.5">Max: {(PRODUCTION_REGRESSION_THRESHOLDS.maxUnsupportedClaimRate * 100)}%</div>
            </div>
          </div>

          {/* Fixture Execution Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="font-bold text-slate-200 flex items-center gap-2 text-sm">
                <FileCode2 className="w-4 h-4 text-cyan-400" />
                Evaluated Fixture Results Matrix ({currentRun.results.length} Fixtures)
              </h3>
              <span className="text-xs font-mono text-slate-400">
                Pass: {currentRun.results.filter(r => r.passedGates).length} / {currentRun.results.length}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                  <tr>
                    <th className="py-3 px-4">Fixture ID</th>
                    <th className="py-3 px-4">Corpus Family</th>
                    <th className="py-3 px-4">Actual Verdict</th>
                    <th className="py-3 px-4">Calculated Risk</th>
                    <th className="py-3 px-4">Grounding / RLS</th>
                    <th className="py-3 px-4">Latency</th>
                    <th className="py-3 px-4">Gate Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850">
                  {currentRun.results.map((res) => (
                    <tr key={res.fixtureId} className="hover:bg-slate-850/50">
                      <td className="py-3 px-4 font-semibold text-slate-200">{res.fixtureId}</td>
                      <td className="py-3 px-4 text-cyan-400">{res.family}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          res.actualVerdict === 'CLEARED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                          res.actualVerdict === 'BLOCKED' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                          'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}>
                          {res.actualVerdict}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">{(res.calculatedRiskScore * 100).toFixed(1)}%</td>
                      <td className="py-3 px-4">
                        <div className="space-x-1">
                          <span className="text-slate-400">RAG: {res.ragGroundingScorePct.toFixed(0)}%</span>
                          <span className={res.rlsAccessGranted ? 'text-rose-400' : 'text-emerald-400'}>
                            RLS: {res.rlsAccessGranted ? 'ALLOWED' : 'BLOCKED'}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-400">{res.latencyMs}ms</td>
                      <td className="py-3 px-4">
                        {res.passedGates ? (
                          <span className="flex items-center text-emerald-400 gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            PASS
                          </span>
                        ) : (
                          <span className="flex items-center text-rose-400 gap-1 font-bold">
                            <XCircle className="w-3.5 h-3.5" />
                            REGRESSION
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: 19 GOLDEN CORPUS FIXTURES BROWSER */}
      {activeTab === 'fixtures' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Filter & List */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-slate-200 text-sm">Corpus Families</h3>
              <span className="text-xs font-mono text-slate-400">{filteredFixtures.length} items</span>
            </div>

            {/* Search and Family Filters */}
            <div className="space-y-2">
              <div className="relative">
                <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search fixtures..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <select
                value={selectedFamily}
                onChange={(e) => setSelectedFamily(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">ALL FAMILIES (19)</option>
                {familiesList.map(fam => (
                  <option key={fam} value={fam}>{fam}</option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
              {filteredFixtures.map(f => (
                <div
                  key={f.fixtureId}
                  onClick={() => setSelectedFixture(f)}
                  className={`p-3 rounded-lg border cursor-pointer transition ${
                    selectedFixture?.fixtureId === f.fixtureId
                      ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-300'
                      : 'bg-slate-950/60 border-slate-850 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-semibold">{f.fixtureId}</span>
                    <span className={`text-[10px] px-1.5 py-0.2 rounded uppercase ${
                      f.groundTruth.expectedVerdict === 'CLEARED' ? 'text-emerald-400 bg-emerald-500/10' : 'text-rose-400 bg-rose-500/10'
                    }`}>
                      {f.groundTruth.expectedVerdict}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-slate-200 mt-1">{f.name}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">{f.family}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Right 2 Columns: Fixture Inspector */}
          {selectedFixture && (
            <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center space-x-3">
                    <h3 className="text-lg font-bold text-slate-100">{selectedFixture.name}</h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono">
                      {selectedFixture.family}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{selectedFixture.description}</p>
                </div>
                <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                  {selectedFixture.fixtureId}
                </span>
              </div>

              {/* Ground Truth Assertions Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 font-mono text-xs">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase">Expected Verdict</div>
                  <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedFixture.groundTruth.expectedVerdict}</div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase">Expected Risk Range</div>
                  <div className="text-sm font-bold text-slate-200 mt-0.5">
                    {(selectedFixture.groundTruth.expectedRiskScoreMin * 100)}% - {(selectedFixture.groundTruth.expectedRiskScoreMax * 100)}%
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase">Adversarial Probing</div>
                  <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedFixture.isAdversarial ? 'YES (Harmful Probe)' : 'NO (Benign)'}</div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase">RAG Grounding Pass</div>
                  <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedFixture.groundTruth.expectedRagGroundingPass ? 'TRUE' : 'FALSE'}</div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase">RLS Cross-Tenant Allowed</div>
                  <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedFixture.groundTruth.expectedRlsAccessAllowed ? 'YES' : 'NO (BLOCKED)'}</div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-400 text-[10px] uppercase">Required Citations</div>
                  <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedFixture.groundTruth.requiredCitationsCount} Citations</div>
                </div>
              </div>

              {/* Taint Flow Assertions */}
              {selectedFixture.groundTruth.expectedTaintFlows.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-300 font-mono uppercase tracking-wider">
                    Expected Taint Paths ({selectedFixture.groundTruth.expectedTaintFlows.length})
                  </h4>
                  <div className="space-y-1.5">
                    {selectedFixture.groundTruth.expectedTaintFlows.map((flow, idx) => (
                      <div key={idx} className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs font-mono flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="text-rose-400 font-semibold">{flow.source}</span>
                          <span className="text-slate-500">───►</span>
                          <span className="text-amber-400 font-semibold">{flow.sink}</span>
                        </div>
                        <span className="text-[10px] text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded uppercase">
                          Malicious Flow
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Expected Vulnerability Identifiers */}
              {selectedFixture.groundTruth.expectedVulnerabilityIds.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-300 font-mono uppercase tracking-wider">
                    Expected Vulnerability Signatures
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedFixture.groundTruth.expectedVulnerabilityIds.map(vuln => (
                      <span key={vuln} className="bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2.5 py-1 rounded text-xs font-mono font-semibold">
                        {vuln}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: NFR-EVAL THRESHOLDS MATRIX */}
      {activeTab === 'thresholds' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Gauge className="w-5 h-5 text-cyan-400" />
              NFR-EVAL CI Release Gate Quality Thresholds
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Strict numeric boundaries enforced automatically on all conclusion-changing engine updates.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <h4 className="text-sm font-bold text-cyan-400 border-b border-slate-800 pb-2">Classification & Flow Standards</h4>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Minimum F1-Score:</span>
                <span className="text-slate-200 font-bold">≥ {(PRODUCTION_REGRESSION_THRESHOLDS.minF1Score * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Minimum Precision:</span>
                <span className="text-slate-200 font-bold">≥ {(PRODUCTION_REGRESSION_THRESHOLDS.minPrecision * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Minimum Recall:</span>
                <span className="text-slate-200 font-bold">≥ {(PRODUCTION_REGRESSION_THRESHOLDS.minRecall * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Minimum Taint Path Recall:</span>
                <span className="text-slate-200 font-bold">≥ {(PRODUCTION_REGRESSION_THRESHOLDS.minTaintRecall * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Allowed Policy Regressions:</span>
                <span className="text-rose-400 font-bold">0 (Zero Tolerance)</span>
              </div>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <h4 className="text-sm font-bold text-cyan-400 border-b border-slate-800 pb-2">RAG, Epistemic & Security Boundaries</h4>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">RLS Tenant Negative Pass Rate:</span>
                <span className="text-emerald-400 font-bold">100% (Zero-Leak)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Information Retrieval MRR:</span>
                <span className="text-slate-200 font-bold">≥ {(PRODUCTION_REGRESSION_THRESHOLDS.minMRR * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Information Retrieval Recall@5:</span>
                <span className="text-slate-200 font-bold">≥ {(PRODUCTION_REGRESSION_THRESHOLDS.minRecallAtK * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Max Unsupported Claim Rate:</span>
                <span className="text-slate-200 font-bold">≤ {(PRODUCTION_REGRESSION_THRESHOLDS.maxUnsupportedClaimRate * 100)}%</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-900">
                <span className="text-slate-400">Contradiction Disclosure Rate:</span>
                <span className="text-emerald-400 font-bold">100% (Required)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: VERIFICATION TEST SUITE RUNNER */}
      {activeTab === 'verification' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                P31 Golden Corpus & Release Gate Verification Suite
              </h3>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Automated end-to-end tests validating release gate enforcement and regression detection.
              </p>
            </div>
            <button
              onClick={handleRunVerification}
              disabled={verifying}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold font-mono flex items-center space-x-2 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
              <span>{verifying ? 'Running Suite...' : 'Execute Suite'}</span>
            </button>
          </div>

          {verificationResults ? (
            <div className="space-y-4">
              <div className={`p-4 rounded-xl border flex items-center justify-between ${
                verificationResults.passed
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
              }`}>
                <div className="flex items-center space-x-3 font-mono text-sm">
                  {verificationResults.passed ? (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <XCircle className="w-6 h-6 text-rose-400" />
                  )}
                  <div>
                    <span className="font-bold">
                      {verificationResults.passed ? 'ALL EVALUATION VERIFICATION GATES PASSED (100%)' : 'SOME EVALUATION GATES FAILED'}
                    </span>
                    <div className="text-xs text-slate-400 mt-0.5">
                      {verificationResults.testResults.length} test assertions executed against golden baseline standards.
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                {verificationResults.testResults.map((test, idx) => (
                  <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="font-bold text-slate-200">{test.name}</span>
                      <span className={`px-2 py-0.5 rounded font-bold uppercase ${
                        test.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}>
                        {test.status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono">{test.details}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 text-xs font-mono">
              Click &quot;Execute Suite&quot; or &quot;Verify Release Gates&quot; to run automated test assertions.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
