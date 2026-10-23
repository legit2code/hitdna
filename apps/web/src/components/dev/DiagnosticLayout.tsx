import React, { useState, useEffect } from 'react';
import { 
  Terminal, 
  Activity, 
  Workflow, 
  Layers, 
  Skull, 
  ShieldAlert, 
  ShieldCheck, 
  RefreshCw,
  Clock,
  ExternalLink,
  Search,
  Code2,
  Network,
  GitFork,
  Package,
  Box,
  Scale,
  Sparkles,
  Fingerprint,
  Globe,
  Bot,
  Share2,
  GitCompare,
  UserCheck,
  Lock,
  Cpu,
  Award
} from 'lucide-react';
import { DiagnosticRoleGuard } from './DiagnosticRoleGuard.tsx';
import { DiagnosticSystemView } from './DiagnosticSystemView.tsx';
import { DiagnosticWorkflowsView } from './DiagnosticWorkflowsView.tsx';
import { DiagnosticJobsView } from './DiagnosticJobsView.tsx';
import { DiagnosticDlqView } from './DiagnosticDlqView.tsx';
import { DiagnosticDiscoveryView } from './DiagnosticDiscoveryView.tsx';
import { DiagnosticSyntaxView } from './DiagnosticSyntaxView.tsx';
import { DiagnosticCaneView } from './DiagnosticCaneView.tsx';
import { DiagnosticStaticAnalysisView } from './DiagnosticStaticAnalysisView.tsx';
import { DiagnosticCompositionView } from './DiagnosticCompositionView.tsx';
import { DiagnosticSandboxView } from './DiagnosticSandboxView.tsx';
import { DiagnosticDecisionView } from './DiagnosticDecisionView.tsx';
import { DiagnosticGroundingView } from './DiagnosticGroundingView.tsx';
import { DiagnosticPackagingView } from './DiagnosticPackagingView.tsx';
import { DiagnosticApiView } from './DiagnosticApiView.tsx';
import { AgentsWorkflowView } from '../views/AgentsWorkflowView.tsx';
import { DiscoveryWorkflowView } from '../views/DiscoveryWorkflowView.tsx';
import { AnalysisWorkflowView } from '../views/AnalysisWorkflowView.tsx';
import { EvidenceWorkflowView } from '../views/EvidenceWorkflowView.tsx';
import { RiskPolicyWorkflowView } from '../views/RiskPolicyWorkflowView.tsx';
import { KnowledgeWorkflowView } from '../views/KnowledgeWorkflowView.tsx';
import { ModificationWorkflowView } from '../views/ModificationWorkflowView.tsx';
import { PackagesWorkflowView } from '../views/PackagesWorkflowView.tsx';
import { OperationsWorkflowView } from '../views/OperationsWorkflowView.tsx';
import { GovernanceWorkflowView } from '../views/GovernanceWorkflowView.tsx';
import { ObservabilityWorkflowView } from '../views/ObservabilityWorkflowView.tsx';
import { GoldenCorpusWorkflowView } from '../views/GoldenCorpusWorkflowView.tsx';
import { TraceabilityDodWorkflowView } from '../views/TraceabilityDodWorkflowView.tsx';
import { ProductionHardeningView } from '../views/ProductionHardeningView.tsx';

export type DiagnosticTab = 
  | 'production-hardening'
  | 'traceability'
  | 'evaluation'
  | 'observability'
  | 'agents'
  | 'evidence'
  | 'modification'
  | 'risk'
  | 'knowledge'
  | 'analysis'
  | 'discovery'
  | 'packages'
  | 'operations'
  | 'governance'
  | 'system' 
  | 'workflows' 
  | 'jobs' 
  | 'dlq' 
  | 'syntax' 
  | 'cane' 
  | 'static-analysis' 
  | 'composition' 
  | 'sandbox' 
  | 'decision' 
  | 'grounding' 
  | 'packaging' 
  | 'api';

export const DiagnosticLayout: React.FC = () => {
  // Determine initial tab from pathname or default to 'agents'
  const getInitialTab = (): DiagnosticTab => {
    const path = window.location.pathname;
    if (path.includes('/dev/overview') || path.includes('/dev/system')) return 'system';
    if (path.includes('/dev/hardening') || path.includes('/dev/rc') || path.includes('/dev/production')) return 'production-hardening';
    if (path.includes('/dev/traceability') || path.includes('/dev/dod') || path.includes('/dev/rtm')) return 'traceability';
    if (path.includes('/dev/evaluation') || path.includes('/dev/golden') || path.includes('/dev/gates')) return 'evaluation';
    if (path.includes('/dev/observability') || path.includes('/dev/telemetry') || path.includes('/dev/traces') || path.includes('/dev/cost')) return 'observability';
    if (path.includes('/dev/agents')) return 'agents';
    if (path.includes('/dev/evidence') || path.includes('/dev/claims') || path.includes('/dev/lineage')) return 'evidence';
    if (path.includes('/dev/modification') || path.includes('/dev/diff') || path.includes('/dev/approvals') || path.includes('/dev/versions') || path.includes('/dev/changes')) return 'modification';
    if (path.includes('/dev/risk') || path.includes('/dev/policy')) return 'risk';
    if (path.includes('/dev/knowledge') || path.includes('/dev/rag')) return 'knowledge';
    if (path.includes('/dev/analysis') || path.includes('/dev/engines')) return 'analysis';
    if (path.includes('/dev/packages') || path.includes('/dev/bundle')) return 'packages';
    if (path.includes('/dev/operations') || path.includes('/dev/workers')) return 'operations';
    if (path.includes('/dev/governance') || path.includes('/dev/audit') || path.includes('/dev/admin')) return 'governance';
    if (path.includes('/dev/workflows')) return 'workflows';
    if (path.includes('/dev/jobs')) return 'jobs';
    if (path.includes('/dev/dlq')) return 'dlq';
    if (path.includes('/dev/discovery')) return 'discovery';
    if (path.includes('/dev/syntax')) return 'syntax';
    if (path.includes('/dev/cane') || path.includes('/dev/ontology')) return 'cane';
    if (path.includes('/dev/static') || path.includes('/dev/cfg')) return 'static-analysis';
    if (path.includes('/dev/composition') || path.includes('/dev/sbom') || path.includes('/dev/reachability')) return 'composition';
    if (path.includes('/dev/sandbox') || path.includes('/dev/runtime') || path.includes('/dev/evasion')) return 'sandbox';
    if (path.includes('/dev/decision')) return 'decision';
    if (path.includes('/dev/grounding') || path.includes('/dev/synthesis')) return 'grounding';
    if (path.includes('/dev/packaging') || path.includes('/dev/attestation') || path.includes('/dev/shipping')) return 'packaging';
    if (path.includes('/dev/api') || path.includes('/dev/events') || path.includes('/dev/queues')) return 'api';
    return 'agents';
  };

  const [activeTab, setActiveTab] = useState<DiagnosticTab>(getInitialTab);
  const [workflowParams, setWorkflowParams] = useState<any>({});
  const [currentRole, setCurrentRole] = useState<string>('analyst');
  const [authorized, setAuthorized] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  // Live telemetry state
  const [systemData, setSystemData] = useState<any | null>(null);
  const [workflows, setWorkflows] = useState<any[]>([]);
  const [jobs, setJobs] = useState<any[]>([]);
  const [dlqEntries, setDlqEntries] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [autoRefreshSec, setAutoRefreshSec] = useState<number>(10);

  // Sync tab with URL
  const setTabAndUrl = (tab: DiagnosticTab) => {
    setActiveTab(tab);
    window.history.pushState({}, '', `/dev/${tab}`);
  };

  // Handle browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      setActiveTab(getInitialTab());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Fetch telemetry from backend APIs with current role header
  const fetchTelemetry = async () => {
    setLoading(true);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Role': currentRole,
    };

    try {
      const [sysRes, wfRes, jobsRes, dlqRes] = await Promise.all([
        fetch('/api/dev/system', { headers }),
        fetch('/api/dev/workflows', { headers }),
        fetch('/api/dev/jobs', { headers }),
        fetch('/api/dev/dlq', { headers }),
      ]);

      if (sysRes.status === 403 || wfRes.status === 403) {
        setAuthorized(false);
        const errData = await sysRes.json().catch(() => ({}));
        setAuthError(errData.error || 'Access Denied: Requires operator or admin role.');
        setLoading(false);
        return;
      }

      setAuthorized(true);
      setAuthError(null);

      if (sysRes.ok) setSystemData(await sysRes.json());
      if (wfRes.ok) setWorkflows(await wfRes.json());
      if (jobsRes.ok) setJobs(await jobsRes.json());
      if (dlqRes.ok) setDlqEntries(await dlqRes.json());
    } catch (err: any) {
      setAuthError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Initial load and role change re-fetch
  useEffect(() => {
    fetchTelemetry();
  }, [currentRole]);

  // Auto-refresh interval timer
  useEffect(() => {
    if (autoRefreshSec <= 0) return;
    const interval = setInterval(() => {
      fetchTelemetry();
    }, autoRefreshSec * 1000);
    return () => clearInterval(interval);
  }, [autoRefreshSec, currentRole]);

  // Specific single item inspectors
  const handleSelectWorkflow = async (id: string) => {
    const res = await fetch(`/api/dev/workflows/${id}`, {
      headers: { 'X-Role': currentRole },
    });
    if (!res.ok) throw new Error('Failed to load workflow details');
    return res.json();
  };

  const handleSelectJob = async (jobId: string) => {
    const res = await fetch(`/api/dev/jobs/${jobId}`, {
      headers: { 'X-Role': currentRole },
    });
    if (!res.ok) throw new Error('Failed to load job details');
    return res.json();
  };

  const handleSelectDlq = async (dlqId: string) => {
    const res = await fetch(`/api/dev/dlq/${dlqId}`, {
      headers: { 'X-Role': currentRole },
    });
    if (!res.ok) throw new Error('Failed to load dead letter details');
    return res.json();
  };

  const handleSeedData = async () => {
    try {
      await fetch('/api/dev/seed-sample', {
        method: 'POST',
        headers: { 'X-Role': currentRole },
      });
      fetchTelemetry();
    } catch {
      // Ignored
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased flex flex-col selection:bg-cyan-900 selection:text-cyan-100">
      {/* Top Banner: VISIBLY LABELED INTERNAL ENGINEERING CONSOLE */}
      <div className="bg-gradient-to-r from-amber-600/20 via-slate-900 to-amber-600/20 border-b border-amber-500/40 px-4 py-1.5 text-center text-xs font-mono font-bold tracking-wider text-amber-300 flex items-center justify-center space-x-2">
        <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
        <span>INTERNAL ENGINEERING CONSOLE • DIAGNOSTIC ONLY • NO PRODUCT DOMAINS</span>
        <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
      </div>

      {/* Main Console Header */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-lg bg-cyan-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Terminal className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="font-semibold text-slate-100 text-sm sm:text-base tracking-tight font-mono">
                  CAIM Control Plane Diagnostics
                </h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                  P09A Shell
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block font-mono">
                Real Orchestration • Leases • Job Queues • Outbox • Dead-Letter Quarantine
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Auto-refresh selector */}
            <div className="hidden sm:flex items-center space-x-1 bg-slate-950 px-2 py-1 rounded border border-slate-800 text-xs font-mono">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400 text-[11px]">Poll:</span>
              <select
                value={autoRefreshSec}
                onChange={(e) => setAutoRefreshSec(parseInt(e.target.value, 10))}
                className="bg-transparent text-slate-200 text-[11px] focus:outline-none cursor-pointer"
              >
                <option value={5} className="bg-slate-900">5s</option>
                <option value={10} className="bg-slate-900">10s</option>
                <option value={30} className="bg-slate-900">30s</option>
                <option value={0} className="bg-slate-900">Off</option>
              </select>
            </div>

            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>P09 Control Plane Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Role Guard Bar */}
      <DiagnosticRoleGuard
        currentRole={currentRole}
        onRoleChange={(role) => setCurrentRole(role)}
        authorized={authorized}
        error={authError}
      />

      {/* Navigation Subnav Bar for Core Workflows & Diagnostic Tools */}
      <div className="border-b border-slate-800 bg-slate-900/70 sticky top-16 z-40 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2.5 flex flex-col gap-2">
          {/* Main User Workflows Tier */}
          <div className="flex items-center space-x-1 overflow-x-auto pb-1 text-xs font-mono">
            <span className="text-slate-500 font-semibold px-2 uppercase text-[10px] tracking-wider shrink-0">Workflows:</span>

            <button
              onClick={() => setTabAndUrl('system')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'system'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-overview-btn"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => setTabAndUrl('production-hardening')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'production-hardening'
                  ? 'bg-indigo-600 text-white shadow ring-1 ring-indigo-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-hardening-btn"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Hardening & RC (P35)</span>
            </button>

            <button
              onClick={() => setTabAndUrl('traceability')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'traceability'
                  ? 'bg-emerald-600 text-white shadow ring-1 ring-emerald-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-traceability-btn"
            >
              <Award className="w-3.5 h-3.5" />
              <span>Traceability & DoD (P34)</span>
            </button>

            <button
              onClick={() => setTabAndUrl('evaluation')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'evaluation'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-evaluation-btn"
            >
              <Scale className="w-3.5 h-3.5" />
              <span>Golden Corpus & Gates</span>
            </button>
            
            <button
              onClick={() => setTabAndUrl('observability')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'observability'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-observability-btn"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Observability & Traces</span>
            </button>

            <button
              onClick={() => setTabAndUrl('agents')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'agents'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-agents-workflow-btn"
            >
              <Bot className="w-3.5 h-3.5" />
              <span>Agents</span>
            </button>

            <button
              onClick={() => setTabAndUrl('discovery')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'discovery'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-discovery-workflow-btn"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Discovery</span>
            </button>

            <button
              onClick={() => setTabAndUrl('analysis')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'analysis'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-analysis-workflow-btn"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>71-Analysis</span>
            </button>

            <button
              onClick={() => setTabAndUrl('evidence')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'evidence'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-evidence-workflow-btn"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>Evidence Lineage</span>
            </button>

            <button
              onClick={() => setTabAndUrl('risk')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'risk'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-risk-policy-btn"
            >
              <Scale className="w-3.5 h-3.5" />
              <span>Risk & Policy</span>
            </button>

            <button
              onClick={() => setTabAndUrl('knowledge')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'knowledge'
                  ? 'bg-amber-600 text-white shadow ring-1 ring-amber-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-knowledge-btn"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Knowledge RAG</span>
            </button>

            <button
              onClick={() => setTabAndUrl('modification')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'modification'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-modification-btn"
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Modification & Approvals</span>
            </button>

            <button
              onClick={() => setTabAndUrl('packages')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'packages'
                  ? 'bg-emerald-600 text-white shadow ring-1 ring-emerald-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-packages-btn"
            >
              <Package className="w-3.5 h-3.5" />
              <span>Packages & Attestation</span>
            </button>

            <button
              onClick={() => setTabAndUrl('operations')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'operations'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-operations-btn"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Operations & DLQ</span>
            </button>

            <button
              onClick={() => setTabAndUrl('governance')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'governance'
                  ? 'bg-purple-600 text-white shadow ring-1 ring-purple-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-governance-btn"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Governance & Audit</span>
            </button>

            <button
              onClick={() => setTabAndUrl('api')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all shrink-0 ${
                activeTab === 'api'
                  ? 'bg-cyan-600 text-white shadow ring-1 ring-cyan-400/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80'
              }`}
              id="nav-dev-api-btn"
            >
              <Globe className="w-3.5 h-3.5" />
              <span>API Registry</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Diagnostic Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {authorized ? (
          <>
            {activeTab === 'production-hardening' && (
              <ProductionHardeningView />
            )}

            {activeTab === 'traceability' && (
              <TraceabilityDodWorkflowView />
            )}

            {activeTab === 'evaluation' && (
              <GoldenCorpusWorkflowView
                currentRole={currentRole}
              />
            )}

            {activeTab === 'observability' && (
              <ObservabilityWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'agents' && (
              <AgentsWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'discovery' && (
              <DiscoveryWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'analysis' && (
              <AnalysisWorkflowView
                currentRole={currentRole}
                agentId={workflowParams?.agentId}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'evidence' && (
              <EvidenceWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'risk' && (
              <RiskPolicyWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'knowledge' && (
              <KnowledgeWorkflowView
                currentRole={currentRole}
                initialQuery={workflowParams?.query}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'modification' && (
              <ModificationWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'packages' && (
              <PackagesWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'operations' && (
              <OperationsWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'governance' && (
              <GovernanceWorkflowView
                currentRole={currentRole}
                onNavigateToWorkflow={(wf, params) => {
                  setWorkflowParams(params || {});
                  setTabAndUrl(wf as DiagnosticTab);
                }}
              />
            )}

            {activeTab === 'system' && (
              <DiagnosticSystemView
                systemData={systemData}
                loading={loading}
                onRefresh={fetchTelemetry}
                onSeedData={handleSeedData}
              />
            )}

            {activeTab === 'workflows' && (
              <DiagnosticWorkflowsView
                workflows={workflows}
                loading={loading}
                onRefresh={fetchTelemetry}
                onSelectWorkflow={handleSelectWorkflow}
              />
            )}

            {activeTab === 'jobs' && (
              <DiagnosticJobsView
                jobs={jobs}
                loading={loading}
                onRefresh={fetchTelemetry}
                onSelectJob={handleSelectJob}
              />
            )}

            {activeTab === 'dlq' && (
              <DiagnosticDlqView
                dlqEntries={dlqEntries}
                loading={loading}
                onRefresh={fetchTelemetry}
                onSelectDlq={handleSelectDlq}
              />
            )}

            {activeTab === 'syntax' && (
              <DiagnosticSyntaxView
                currentRole={currentRole}
              />
            )}

            {activeTab === 'cane' && (
              <DiagnosticCaneView />
            )}

            {activeTab === 'static-analysis' && (
              <DiagnosticStaticAnalysisView currentRole={currentRole} />
            )}

            {activeTab === 'composition' && (
              <DiagnosticCompositionView currentRole={currentRole} />
            )}

            {activeTab === 'sandbox' && (
              <DiagnosticSandboxView currentRole={currentRole} />
            )}

            {activeTab === 'decision' && (
              <DiagnosticDecisionView currentRole={currentRole} />
            )}

            {activeTab === 'grounding' && (
              <DiagnosticGroundingView currentRole={currentRole} />
            )}

            {activeTab === 'packaging' && (
              <DiagnosticPackagingView currentRole={currentRole} />
            )}

            {activeTab === 'api' && (
              <DiagnosticApiView currentRole={currentRole} />
            )}
          </>
        ) : (
          <div className="py-20 text-center space-y-3 font-mono">
            <ShieldAlert className="w-10 h-10 text-rose-400 mx-auto" />
            <h2 className="text-base font-bold text-slate-200">Diagnostic Access Restricted</h2>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              You are currently viewing this console as <code className="text-rose-400">{currentRole}</code>.
              Internal engineering diagnostics require an authorized operator or admin role.
            </p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-3 text-center text-xs text-slate-400 font-mono">
        CAIM Engineering Console • P09 Control Plane Diagnostic Boundary • No Speculative Domain Routes
      </footer>
    </div>
  );
};
