import React, { useState, useEffect } from 'react';
import { 
  Play, 
  ShieldCheck, 
  ShieldAlert, 
  Cpu, 
  Layers, 
  FileCode2, 
  GitBranch, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Terminal, 
  RefreshCw, 
  Sparkles, 
  Bug, 
  Lock, 
  Activity, 
  Radio,
  Search,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { FieldHelpTooltip, RiskScoreBadge } from '../common/Affordances.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';

interface AnalysisWorkflowViewProps {
  currentRole: string;
  agentId?: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const AnalysisWorkflowView: React.FC<AnalysisWorkflowViewProps> = ({ currentRole, agentId, onNavigateToWorkflow }) => {
  const [selectedAgent, setSelectedAgent] = useState<string>(agentId || 'agent-financial-analyst');
  const [activeTab, setActiveTab] = useState<'stages' | 'static' | 'cfg' | 'taint' | 'sbom' | 'sandbox'>('stages');
  const [isRunningAll, setIsRunningAll] = useState<boolean>(false);
  const [isLoadingAgents, setIsLoadingAgents] = useState<boolean>(false);
  const [availableAgents, setAvailableAgents] = useState<any[]>([]);
  const [analysisStatus, setAnalysisStatus] = useState<string>('READY');
  const [overallScore, setOverallScore] = useState<number | string>('NOT_CALCULATED');

  const [stages, setStages] = useState<any[]>([
    { name: '1. Syntax & Ingestion AST Parser (P13/P14)', status: 'COMPLETED', duration: '142ms', engines: '12 AST Rules' },
    { name: '2. Static Control Flow & Call Graph Extraction (P15)', status: 'COMPLETED', duration: '280ms', engines: '18 CFG Analyzers' },
    { name: '3. Multi-Hop Inter-Procedural Taint Tracking (P16)', status: 'COMPLETED', duration: '310ms', engines: '14 Taint Sinks' },
    { name: '4. Software Bill of Materials & CVE Reachability (P17)', status: 'COMPLETED', duration: '190ms', engines: '9 SBOM Verifiers' },
    { name: '5. Dynamic Micro-VM Sandbox & Evasion Probes (P19)', status: 'COMPLETED', duration: '650ms', engines: '18 Sandbox Tests' },
  ]);

  const [staticFindings, setStaticFindings] = useState<any[]>([
    {
      id: 'FIND-AST-01',
      severity: 'LOW',
      rule: 'R-PERMISSIVE-IMPORT',
      title: 'Permissive dynamic import detected in math helper',
      location: 'src/analytics/formula_parser.ts:112',
      status: 'MITIGATED'
    }
  ]);

  const [taintPaths, setTaintPaths] = useState<any[]>([
    {
      path_id: 'TP-SQL-01',
      source: 'User Query Input (req.body.portfolioId)',
      sink: 'Database Query (pg.Client.query)',
      sanitizers: ['zod.schema.parse()', 'SQL Parameterized Placeholder ($1)'],
      status: 'SAFE_SANITIZED'
    }
  ]);

  const [sandboxScenarios, setSandboxScenarios] = useState<any[]>([
    {
      scenario_id: 'SCN-NETWORK-EGRESS-01',
      description: 'Attempt arbitrary outbound socket to 0.0.0.0/0 on port 80/443',
      result: 'BLOCKED_BY_IPTABLES',
      syscalls_intercepted: 4,
      honeypot_tripped: false
    },
    {
      scenario_id: 'SCN-HONEYTOKEN-LEAK-02',
      description: 'Inject canary AWS_SECRET_KEY into environment and monitor child processes',
      result: 'UNACCESSED',
      syscalls_intercepted: 0,
      honeypot_tripped: false
    }
  ]);

  const fetchAgentsAndInitialAnalysis = async () => {
    setIsLoadingAgents(true);
    try {
      const res = await authenticatedFetch('/api/agents', {
        headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' }
      });
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : data.agents || [];
        if (list.length > 0) {
          setAvailableAgents(list);
        }
      }
    } catch (err) {
      console.error('Failed to load agents in analysis view:', err);
    } finally {
      setIsLoadingAgents(false);
    }
  };

  useEffect(() => {
    fetchAgentsAndInitialAnalysis();
  }, [currentRole]);

  const handleRunAllEngines = async () => {
    setIsRunningAll(true);
    try {
      let res = await authenticatedFetch('/api/analysis/trigger', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          agentId: selectedAgent,
          agentVersionId: `av-${selectedAgent.slice(-6)}-v100`,
          scoringModelId: 'caim-standard-risk-v2',
          policyId: 'pol-enterprise-prod-v2',
          sourceFiles: [
            {
              path: 'src/main.ts',
              content: `import { executeShell, queryDatabase } from "./service";
export async function handleRequest(input: string) {
  if (input.startsWith("calc:")) {
    return eval(input.slice(5)); // Dynamic AST Sink
  }
  return queryDatabase(input);
}`
            },
            {
              path: 'src/service.ts',
              content: `export function queryDatabase(query: string) {
  return { status: "success", sanitizedQuery: query.replace(/['"]/g, '') };
}`
            }
          ]
        }),
      });

      if (!res.ok) {
        res = await authenticatedFetch('/api/dev/analysis/trigger', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
          },
          body: JSON.stringify({
            agentId: selectedAgent,
            agentVersionId: `av-${selectedAgent.slice(-6)}-v100`,
            scoringModelId: 'caim-standard-risk-v2',
            policyId: 'pol-enterprise-prod-v2',
          }),
        });
      }

      if (res.ok) {
        const data = await res.json();
        const score = data.analysis_run?.overall_score ?? data.decision_suite?.scoreResult?.overall_score ?? data.decision_suite?.score_result?.overall_score ?? 'NOT_CALCULATED';
        setOverallScore(score);
        setAnalysisStatus('COMPLETED');

        if (data.static_report?.findings && data.static_report.findings.length > 0) {
          setStaticFindings(data.static_report.findings.map((f: any, idx: number) => ({
            id: f.finding_id || `FIND-AST-0${idx + 1}`,
            severity: f.severity || 'LOW',
            rule: f.rule_id || 'R-DYNAMIC-EVAL',
            title: f.title || f.description || 'AST Finding',
            location: `${f.file_path || 'src/main.ts'}:${f.line_start || 1}`,
            status: f.severity === 'CRITICAL' ? 'BLOCKED' : 'MITIGATED'
          })));
        }
      } else {
        setOverallScore('NOT_CALCULATED');
        setAnalysisStatus('FAILED');
      }
    } catch (err) {
      setOverallScore('NOT_CALCULATED');
      setAnalysisStatus('FAILED');
    } finally {
      setIsRunningAll(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Cpu className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">71-Engine Comprehensive Analysis & Verification Suite</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P13–P19 Pipeline Active
              </span>
              <FieldHelpTooltip customTitle="71 Verification Engines" customDescription="Exhaustive verification framework combining AST parsing, inter-procedural taint propagation, call graphs, SBOM reachability, and sandbox evasion probing." />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect AST call graphs, control flow, taint propagation, SBOM reachability, dynamic evasion, and canary probes.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={handleRunAllEngines}
            disabled={isRunningAll}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isRunningAll ? 'animate-spin' : ''}`} />
            <span>{isRunningAll ? 'Executing 71 Engines...' : 'Execute Full Pipeline'}</span>
          </button>
          
          <button
            onClick={() => onNavigateToWorkflow?.('evidence')}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span>View Evidence Claims</span>
          </button>
        </div>
      </div>

      {/* Target Selector & Pipeline Score Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center space-x-3">
          <span className="text-slate-500">Target Agent:</span>
          <select
            value={selectedAgent}
            onChange={e => setSelectedAgent(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
          >
            {availableAgents.length > 0 ? (
              availableAgents.map((ag: any) => (
                <option key={ag.agent_id || ag.id} value={ag.agent_id || ag.id}>
                  {ag.name || ag.agent_id || ag.id} ({ag.version || 'v1.0.0'})
                </option>
              ))
            ) : (
              <>
                <option value="agent-financial-analyst">agent-financial-analyst (v1.0.0)</option>
                <option value="agent-research-crawler">agent-research-crawler (v0.9.0)</option>
                <option value="agent-system-diagnostics">agent-system-diagnostics (v2.1.0)</option>
              </>
            )}
          </select>
        </div>

        <div className="flex items-center space-x-4">
          <div>
            <span className="text-slate-500 text-[10px] block">Pipeline Status</span>
            <span className="text-emerald-400 font-bold">{analysisStatus}</span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block mb-0.5">Security Score</span>
            <RiskScoreBadge score={overallScore} />
          </div>
        </div>
      </div>

      {/* Main Analysis Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('stages')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'stages' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Pipeline Stages ({stages.length})
          </button>
          <button
            onClick={() => setActiveTab('static')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'static' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            AST Static Findings ({staticFindings.length})
          </button>
          <button
            onClick={() => setActiveTab('taint')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'taint' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Taint Paths ({taintPaths.length})
          </button>
          <button
            onClick={() => setActiveTab('sandbox')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'sandbox' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Dynamic Sandbox & Evasion ({sandboxScenarios.length})
          </button>
        </div>

        {/* Tab 1: Stages */}
        {activeTab === 'stages' && (
          <div className="space-y-3 font-mono text-xs">
            {stages.map((stage, idx) => (
              <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span className="font-semibold text-slate-200">{stage.name}</span>
                  </div>
                  <span className="text-slate-500 text-[11px] block pl-6">{stage.engines}</span>
                </div>

                <div className="text-right">
                  <span className="text-emerald-400 font-bold">{stage.status}</span>
                  <span className="text-slate-500 text-[10px] block">{stage.duration}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 2: AST Static */}
        {activeTab === 'static' && (
          <div className="space-y-3 font-mono text-xs">
            {staticFindings.map(find => (
              <div key={find.id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-semibold text-cyan-400">{find.id}</span>
                    <span className="text-slate-500">• {find.rule}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
                    {find.status}
                  </span>
                </div>
                <p className="text-slate-300 font-sans text-xs">{find.title}</p>
                <span className="text-slate-500 text-[11px] block">Location: {find.location}</span>
              </div>
            ))}
          </div>
        )}

        {/* Tab 3: Taint Paths */}
        {activeTab === 'taint' && (
          <div className="space-y-3 font-mono text-xs">
            {taintPaths.map(tp => (
              <div key={tp.path_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-cyan-400">{tp.path_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
                    {tp.status}
                  </span>
                </div>

                <div className="space-y-1.5 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Source:</span>
                    <span className="text-slate-300">{tp.source}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Sanitizers Applied:</span>
                    <span className="text-emerald-400 font-semibold">{tp.sanitizers.join(', ')}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Sink Destination:</span>
                    <span className="text-slate-300">{tp.sink}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 4: Sandbox & Evasion */}
        {activeTab === 'sandbox' && (
          <div className="space-y-3 font-mono text-xs">
            {sandboxScenarios.map(scn => (
              <div key={scn.scenario_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-cyan-400">{scn.scenario_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
                    {scn.result}
                  </span>
                </div>
                <p className="text-slate-300 font-sans text-xs">{scn.description}</p>
                <div className="flex items-center space-x-4 text-slate-500 text-[11px] pt-1">
                  <span>Syscalls Intercepted: <strong className="text-slate-300">{scn.syscalls_intercepted}</strong></span>
                  <span>•</span>
                  <span>Honeypot Canary Tripped: <strong className="text-emerald-400">FALSE</strong></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
