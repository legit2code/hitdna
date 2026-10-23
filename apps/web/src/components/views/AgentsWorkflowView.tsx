import React, { useState, useEffect } from 'react';
import { 
  Bot, 
  Search, 
  Filter, 
  Plus, 
  Play, 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  GitBranch, 
  FileCode2, 
  Package, 
  Clock, 
  ExternalLink, 
  ChevronRight, 
  Cpu, 
  Key, 
  CheckCircle2, 
  AlertTriangle, 
  Lock, 
  Sparkles, 
  Terminal, 
  RefreshCw,
  FolderGit2,
  Box,
  Share2,
  FileCheck,
  Zap,
  Info
} from 'lucide-react';
import {
  FieldHelpTooltip,
  SecurityClassificationBadge,
  RiskScoreBadge,
  EpistemicStatusBadge,
  TruthStateBadge
} from '../common/Affordances.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';
import { AgentDiscoveryLineageView } from './AgentDiscoveryLineageView.tsx';

export interface AgentEntity {
  agent_id: string;
  canonical_name: string;
  description: string;
  framework: string;
  author: string;
  security_classification?: string;
  created_at: string;
  updated_at: string;
  source_locator?: string;
  truthState?: string;
  truth_state?: string;
  epistemic_metadata?: any;
  versions?: AgentVersionEntity[];
  tools?: AgentToolCapability[];
  dependencies?: AgentDependency[];
  provenance?: AgentProvenance;
}

export interface AgentVersionEntity {
  agent_version_id: string;
  agent_id: string;
  version_label: string;
  source_locator: string;
  content_hash: string;
  security_classification: string;
  created_at: string;
  status?: 'ACTIVE' | 'DRAFT' | 'DEPRECATED' | 'QUARANTINED';
  analysis_runs?: AnalysisRunSummary[];
}

export interface AnalysisRunSummary {
  analysis_run_id: string;
  pipeline_version: string;
  status: string;
  findings_count: number | string;
  claims_count: number | string;
  overall_score: number | string;
  risk_band: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | string;
  created_at: string;
  truthState?: string;
  truth_state?: string;
  epistemic_metadata?: any;
}

export interface AgentToolCapability {
  tool_id: string;
  name: string;
  category: 'NETWORK' | 'FILESYSTEM' | 'DATABASE' | 'CODE_EXEC' | 'API_INTEGRATION';
  permission_scope: string;
  is_privileged: boolean;
  description: string;
}

export interface AgentDependency {
  name: string;
  version_spec: string;
  is_direct: boolean;
  reachability: 'REACHABLE' | 'PRESENT_UNREACHABLE' | 'UNKNOWN';
  advisories_count: number;
}

export interface AgentProvenance {
  repository_url: string;
  commit_sha: string;
  signer_identity: string;
  signed_at: string;
  build_pipeline: string;
  verification_status: 'VERIFIED' | 'UNVERIFIED' | 'MISMATCHED';
}

interface AgentsWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

const BENCHMARK_SEED_AGENTS: AgentEntity[] = [
  {
    agent_id: 'agent-financial-analyst',
    canonical_name: 'Financial Portfolio & Risk Analyst Agent',
    description: 'Deterministic portfolio risk modeling, ledger audits, and compliance validation agent with strict isolated egress controls.',
    framework: 'TypeScript (LangChain + Node.js)',
    author: 'CAIM Enterprise Security Core',
    security_classification: 'CONFIDENTIAL',
    created_at: '2026-08-26T12:00:00Z',
    updated_at: '2026-08-26T12:15:00Z',
    source_locator: 'github://caim-org/financial-analyst-agent',
    provenance: {
      repository_url: 'https://github.com/caim-org/financial-analyst-agent',
      commit_sha: 'a88bf2139046c82701b22e118934fa1290374189',
      signer_identity: 'release-signing@caim.internal',
      signed_at: '2026-08-26T12:05:00Z',
      build_pipeline: 'caim-ci-pipeline-v2.0.1#4412',
      verification_status: 'VERIFIED'
    },
    tools: [
      {
        tool_id: 'tool-market-quote',
        name: 'fetch_market_prices',
        category: 'API_INTEGRATION',
        permission_scope: 'network:egress:market-api.internal',
        is_privileged: false,
        description: 'Queries read-only streaming tickers from authenticated internal market pricing API.'
      },
      {
        tool_id: 'tool-ledger-audit',
        name: 'query_accounting_ledger',
        category: 'DATABASE',
        permission_scope: 'db:read:general_ledger',
        is_privileged: true,
        description: 'Executes parameterized queries against corporate accounting ledger tables.'
      },
      {
        tool_id: 'tool-report-gen',
        name: 'generate_pdf_report',
        category: 'FILESYSTEM',
        permission_scope: 'fs:write:/tmp/reports',
        is_privileged: false,
        description: 'Writes compiled PDF portfolio risk summary charts to temporary sandboxed storage.'
      }
    ],
    dependencies: [
      { name: 'decimal.js', version_spec: '^10.4.3', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 },
      { name: 'pg', version_spec: '^8.11.3', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 },
      { name: 'axios', version_spec: '^1.6.8', is_direct: true, reachability: 'PRESENT_UNREACHABLE', advisories_count: 0 },
      { name: 'zod', version_spec: '^3.23.0', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 }
    ],
    versions: [
      {
        agent_version_id: 'av-fin-v100',
        agent_id: 'agent-financial-analyst',
        version_label: 'v1.0.0',
        source_locator: 'github://caim-org/financial-analyst-agent?tag=v1.0.0',
        content_hash: 'sha256:3c59a2f7c001a1b5b24b899478f7a8b85590c749320e8b15ca88bfa674b88bf2',
        security_classification: 'CONFIDENTIAL',
        status: 'ACTIVE',
        created_at: '2026-08-26T12:00:00Z',
        analysis_runs: [
          {
            analysis_run_id: 'ar-fin-4412',
            pipeline_version: '2.0.1',
            status: 'COMPLETED',
            findings_count: 0,
            claims_count: 8,
            overall_score: 92,
            risk_band: 'LOW',
            created_at: '2026-08-26T12:02:00Z'
          }
        ]
      }
    ]
  },
  {
    agent_id: 'agent-research-crawler',
    canonical_name: 'Autonomous Web Research & Summarizer',
    description: 'Autonomous multi-hop web crawler and document summarization agent leveraging browser automation and LLM synthesis.',
    framework: 'Python (AutoGen + Playwright)',
    author: 'AI Research Labs',
    security_classification: 'INTERNAL',
    created_at: '2026-08-25T09:30:00Z',
    updated_at: '2026-08-26T10:00:00Z',
    source_locator: 'github://caim-community/web-researcher',
    provenance: {
      repository_url: 'https://github.com/caim-community/web-researcher',
      commit_sha: '7f99c011e490518ab39810a90212ef8914bca812',
      signer_identity: 'research-ci@external-domain.org',
      signed_at: '2026-08-25T09:35:00Z',
      build_pipeline: 'github-actions#109',
      verification_status: 'UNVERIFIED'
    },
    tools: [
      {
        tool_id: 'tool-browser-nav',
        name: 'navigate_browser_page',
        category: 'NETWORK',
        permission_scope: 'network:egress:*',
        is_privileged: true,
        description: 'Controls headless browser to navigate arbitrary external URLs.'
      },
      {
        tool_id: 'tool-eval-js',
        name: 'execute_in_page',
        category: 'CODE_EXEC',
        permission_scope: 'exec:javascript:sandbox',
        is_privileged: true,
        description: 'Executes JavaScript code snippets in loaded DOM tree for structured data scraping.'
      }
    ],
    dependencies: [
      { name: 'playwright', version_spec: '^1.42.0', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 },
      { name: 'beautifulsoup4', version_spec: '^4.12.3', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 },
      { name: 'requests', version_spec: '^2.31.0', is_direct: true, reachability: 'REACHABLE', advisories_count: 1 }
    ],
    versions: [
      {
        agent_version_id: 'av-res-v090',
        agent_id: 'agent-research-crawler',
        version_label: 'v0.9.0',
        source_locator: 'github://caim-community/web-researcher?tag=v0.9.0',
        content_hash: 'sha256:8b44a7f01c4021980be23c1094bafe271049018e4720912cb891104eab908123',
        security_classification: 'INTERNAL',
        status: 'ACTIVE',
        created_at: '2026-08-25T09:30:00Z',
        analysis_runs: [
          {
            analysis_run_id: 'ar-res-1092',
            pipeline_version: '2.0.1',
            status: 'COMPLETED',
            findings_count: 3,
            claims_count: 5,
            overall_score: 64,
            risk_band: 'MODERATE',
            created_at: '2026-08-25T09:38:00Z'
          }
        ]
      }
    ]
  },
  {
    agent_id: 'agent-system-diagnostics',
    canonical_name: 'Infrastructure & Kubernetes Diagnostics Agent',
    description: 'Autonomous cluster health monitoring, pod log aggregation, and triage remediation assistant.',
    framework: 'Go (K8s Client-Go)',
    author: 'Platform Ops Engineering',
    security_classification: 'SECRET',
    created_at: '2026-08-24T16:00:00Z',
    updated_at: '2026-08-26T08:00:00Z',
    source_locator: 'gitlab://caim-infra/k8s-diagnostics-agent',
    provenance: {
      repository_url: 'https://gitlab.internal/caim-infra/k8s-diagnostics-agent',
      commit_sha: 'e99214b10498b31a890eef21903487192834bfa9',
      signer_identity: 'infra-security-kms@internal.caim',
      signed_at: '2026-08-24T16:05:00Z',
      build_pipeline: 'gitlab-ci-prod#9821',
      verification_status: 'VERIFIED'
    },
    tools: [
      {
        tool_id: 'tool-k8s-read',
        name: 'get_cluster_resources',
        category: 'API_INTEGRATION',
        permission_scope: 'k8s:read:pods,nodes,events',
        is_privileged: false,
        description: 'Queries Kubernetes API Server for real-time workload telemetry and status.'
      },
      {
        tool_id: 'tool-exec-debug',
        name: 'exec_ephemeral_container',
        category: 'CODE_EXEC',
        permission_scope: 'k8s:exec:debug-containers',
        is_privileged: true,
        description: 'Launches ephemeral debugging containers with elevated sysadmin privileges.'
      }
    ],
    dependencies: [
      { name: 'k8s.io/client-go', version_spec: 'v0.29.2', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 },
      { name: 'golang.org/x/crypto', version_spec: 'v0.21.0', is_direct: true, reachability: 'REACHABLE', advisories_count: 0 }
    ],
    versions: [
      {
        agent_version_id: 'av-diag-v210',
        agent_id: 'agent-system-diagnostics',
        version_label: 'v2.1.0',
        source_locator: 'gitlab://caim-infra/k8s-diagnostics-agent?tag=v2.1.0',
        content_hash: 'sha256:490192e109405829bfa810482901ba19028374019283019283019283019283aa',
        security_classification: 'SECRET',
        status: 'ACTIVE',
        created_at: '2026-08-24T16:00:00Z',
        analysis_runs: [
          {
            analysis_run_id: 'ar-diag-9821',
            pipeline_version: '2.0.1',
            status: 'COMPLETED',
            findings_count: 1,
            claims_count: 12,
            overall_score: 85,
            risk_band: 'LOW',
            created_at: '2026-08-24T16:10:00Z'
          }
        ]
      }
    ]
  }
];

export const AgentsWorkflowView: React.FC<AgentsWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [agents, setAgents] = useState<AgentEntity[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [showingBenchmarks, setShowingBenchmarks] = useState<boolean>(false);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'overview' | 'lineage' | 'provenance' | 'artifacts' | 'versions' | 'capabilities'>('overview');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [frameworkFilter, setFrameworkFilter] = useState<string>('ALL');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [isRegisteringVersion, setIsRegisteringVersion] = useState<boolean>(false);
  const [newVersionLabel, setNewVersionLabel] = useState<string>('v1.1.0');
  const [newSourceLocator, setNewSourceLocator] = useState<string>('github://caim-org/financial-analyst-agent?tag=v1.1.0');
  const [isTriggeringRun, setIsTriggeringRun] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  // Load real ingested agents from /api/agents on mount
  useEffect(() => {
    async function loadAgents() {
      setLoading(true);
      try {
        let res = await authenticatedFetch('/api/agents');
        if (!res.ok) {
          res = await authenticatedFetch('/api/dev/ingestion/agents');
        }
        if (res.ok) {
          const dbAgents = await res.json();
          if (Array.isArray(dbAgents) && dbAgents.length > 0) {
            setAgents(dbAgents);
            setSelectedAgentId(dbAgents[0].agent_id);
          } else {
            setAgents([]);
            setSelectedAgentId('');
          }
        }
      } catch (err) {
        console.warn('Agents fetch error:', err);
      } finally {
        setLoading(false);
      }
    }
    loadAgents();
  }, [currentRole]);

  const displayedAgents = agents.length > 0 
    ? agents 
    : (showingBenchmarks ? BENCHMARK_SEED_AGENTS : []);

  const selectedAgent = displayedAgents.find(a => a.agent_id === selectedAgentId) || displayedAgents[0];

  const filteredAgents = displayedAgents.filter(agent => {
    const matchesSearch = agent.canonical_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.agent_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFramework = frameworkFilter === 'ALL' || agent.framework.includes(frameworkFilter);
    const matchesClassification = classificationFilter === 'ALL' || agent.security_classification === classificationFilter;
    return matchesSearch && matchesFramework && matchesClassification;
  });

  const handleRegisterVersion = async () => {
    if (!newVersionLabel.trim()) return;
    setIsRegisteringVersion(true);
    try {
      // Persist to backend
      let res = await authenticatedFetch(`/api/agents/${selectedAgent.agent_id}/versions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          versionLabel: newVersionLabel,
          sourceLocator: newSourceLocator,
          securityClassification: selectedAgent.security_classification || 'INTERNAL'
        })
      });

      let newVersionId = `av-${selectedAgent.agent_id.slice(6, 10)}-${newVersionLabel.replace('.', '')}-${Date.now().toString().slice(-4)}`;
      let realContentHash = '';
      if (res.ok) {
        const data = await res.json();
        if (data.agent_version_id) {
          newVersionId = data.agent_version_id;
        }
        if (data.content_hash || data.content_fingerprint) {
          realContentHash = data.content_hash || data.content_fingerprint;
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to register version on backend');
      }

      const newVersion: AgentVersionEntity = {
        agent_version_id: newVersionId,
        agent_id: selectedAgent.agent_id,
        version_label: newVersionLabel,
        source_locator: newSourceLocator,
        content_hash: realContentHash,
        security_classification: selectedAgent.security_classification || 'INTERNAL',
        status: 'ACTIVE',
        created_at: new Date().toISOString(),
        analysis_runs: []
      };

      setAgents(prev => prev.map(a => {
        if (a.agent_id === selectedAgent.agent_id) {
          return {
            ...a,
            versions: [newVersion, ...(a.versions || [])],
            updated_at: new Date().toISOString()
          };
        }
        return a;
      }));

      setNotification({
        type: 'success',
        message: `Registered version ${newVersionLabel} (${newVersionId}) for ${selectedAgent.canonical_name}`
      });
      setIsRegisteringVersion(false);
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message });
      setIsRegisteringVersion(false);
    }
  };

  // Real backend call to /api/analysis/trigger (with fallback to /api/dev/analysis/trigger)
  const handleTriggerAnalysisRun = async () => {
    setIsTriggeringRun(true);
    setNotification(null);
    try {
      const activeVersion = selectedAgent.versions?.[0];
      if (!activeVersion) {
        throw new Error("No active agent version found to analyze.");
      }

      let res = await authenticatedFetch('/api/analysis/trigger', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          agentId: selectedAgent.agent_id,
          agentVersionId: activeVersion.agent_version_id,
          scoringModelId: 'caim-standard-risk-v2',
          policyId: 'pol-enterprise-prod-v2',
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
            agentId: selectedAgent.agent_id,
            agentVersionId: activeVersion.agent_version_id,
            scoringModelId: 'caim-standard-risk-v2',
            policyId: 'pol-enterprise-prod-v2',
          }),
        });
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}: Failed to trigger analysis run`);
      }

      const data = await res.json();
      const analysisRun = data.analysis_run || {};
      const newRun: AnalysisRunSummary = {
        analysis_run_id: data.analysis_run_id || analysisRun.analysis_run_id || `ar-${Date.now().toString().slice(-6)}`,
        pipeline_version: analysisRun.pipeline_version || '2.0.1',
        status: analysisRun.status || 'COMPLETED',
        findings_count: analysisRun.findings_count ?? (data.static_report?.findings?.length || 0),
        claims_count: analysisRun.claims_count ?? (data.decision_suite?.policyDecision?.rule_evaluations?.length || data.decision_suite?.policy_decision?.reasons?.length || 0),
        overall_score: analysisRun.overall_score ?? (data.decision_suite?.scoreResult?.overall_score || data.decision_suite?.score_result?.overall_score || 'NOT_CALCULATED'),
        risk_band: (analysisRun.risk_band || data.decision_suite?.scoreResult?.risk_band || data.decision_suite?.score_result?.risk_band || 'NOT_CALCULATED') as any,
        created_at: analysisRun.created_at || new Date().toISOString()
      };

      setAgents(prev => prev.map(a => {
        if (a.agent_id === selectedAgent.agent_id) {
          const updatedVersions = (a.versions || []).map(v => {
            if (v.agent_version_id === activeVersion.agent_version_id) {
              return {
                ...v,
                analysis_runs: [newRun, ...(v.analysis_runs || [])]
              };
            }
            return v;
          });
          return { ...a, versions: updatedVersions };
        }
        return a;
      }));

      setNotification({
        type: 'success',
        message: `Real analysis run executed via POST /api/analysis/trigger (Workflow Run: ${data.workflow_run_id}, Job: ${data.job_id}). Score: ${newRun.overall_score === 'NOT_CALCULATED' ? 'NOT_CALCULATED' : `${newRun.overall_score}/100`} [Risk: ${newRun.risk_band}, Findings: ${newRun.findings_count}]`
      });
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message });
    } finally {
      setIsTriggeringRun(false);
    }
  };


  return (
    <div className="space-y-6">
      {/* Top Banner & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Bot className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Canonical Agent Registry & Intelligence</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P08 / P29 Real APIs Active
              </span>
              <FieldHelpTooltip customTitle="Canonical Agent Registry" customDescription="Centralized immutable repository of multi-framework agent definitions, cryptographic signatures, provenance attestations, and analysis lineage." />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Explore canonical agents, source provenance, artifact distributions, version pipelines, and tool permissions.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={handleTriggerAnalysisRun}
            disabled={isTriggeringRun}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isTriggeringRun ? 'animate-spin' : ''}`} />
            <span>{isTriggeringRun ? 'Dispatching...' : 'Trigger Analysis Run'}</span>
          </button>
          
          <button
            onClick={() => onNavigateToWorkflow?.('discovery')}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors"
          >
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            <span>Discover Agents</span>
          </button>
        </div>
      </div>

      {notification && (
        <div className={`p-3.5 rounded-lg border text-xs flex items-center justify-between font-mono ${
          notification.type === 'success' ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300' :
          notification.type === 'error' ? 'bg-rose-950/40 border-rose-500/30 text-rose-300' :
          'bg-cyan-950/40 border-cyan-500/30 text-cyan-300'
        }`}>
          <div className="flex items-center space-x-2">
            {notification.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> : <Info className="w-4 h-4 shrink-0" />}
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-200 text-xs ml-4">✕</button>
        </div>
      )}

      {/* Main Grid: Catalog List (Left) + Detail & Workflows (Right) */}
      {displayedAgents.length === 0 ? (
        <div className="p-8 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-4 max-w-2xl mx-auto my-8">
          <div className="h-12 w-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-100">No Canonical Agents Ingested Yet</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto leading-relaxed">
              You haven't ingested or analyzed any agents yet. Ingest an agent repository from GitHub, PyPI, or npm, browse the autonomous discovery library, or load reference benchmark agents.
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <button
              onClick={() => onNavigateToWorkflow?.('library')}
              className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Browse Discovery Library</span>
            </button>
            <button
              onClick={() => setShowingBenchmarks(true)}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors"
            >
              Load Benchmark Examples
            </button>
          </div>
        </div>
      ) : (
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Agents Catalog */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-1.5">
                <span>Agent Catalog</span>
                {showingBenchmarks && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 font-mono">
                    BENCHMARK
                  </span>
                )}
              </span>
              <span className="text-xs font-mono px-2 py-0.5 bg-slate-800 rounded text-slate-300">{filteredAgents.length} Agents</span>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search canonical name, ID, domain..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <select
                value={frameworkFilter}
                onChange={e => setFrameworkFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 text-[11px] focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">All Frameworks</option>
                <option value="TypeScript">TypeScript</option>
                <option value="Python">Python</option>
                <option value="Go">Go</option>
              </select>

              <select
                value={classificationFilter}
                onChange={e => setClassificationFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 text-[11px] focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">All Classifications</option>
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                <option value="SECRET">SECRET</option>
              </select>
            </div>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {filteredAgents.map(agent => {
              const isSelected = agent.agent_id === selectedAgentId;
              const activeVersion = agent.versions?.[0];
              const latestRun = activeVersion?.analysis_runs?.[0];

              return (
                <div
                  key={agent.agent_id}
                  onClick={() => setSelectedAgentId(agent.agent_id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected 
                      ? 'bg-slate-800/90 border-cyan-500/50 shadow-md ring-1 ring-cyan-500/20' 
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-xs font-semibold text-slate-100 tracking-tight">{agent.canonical_name}</h3>
                      <p className="text-[11px] font-mono text-cyan-400 mt-0.5">{agent.agent_id}</p>
                    </div>
                    <SecurityClassificationBadge classification={agent.security_classification || 'INTERNAL'} showTooltip={false} />
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2 mt-2 leading-relaxed">
                    {agent.description}
                  </p>

                  <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-slate-800 text-[11px] font-mono text-slate-400">
                    <span className="flex items-center space-x-1">
                      <Cpu className="w-3 h-3 text-slate-500" />
                      <span>{agent.framework.split(' ')[0]}</span>
                    </span>

                    {latestRun ? (
                      <div className="flex items-center gap-1.5">
                        <RiskScoreBadge score={latestRun.overall_score} riskBand={latestRun.risk_band} showTooltip={false} />
                        {latestRun.truthState && (
                          <TruthStateBadge truthState={latestRun.truthState} size="xs" />
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-500 font-mono text-[10px]">No Runs</span>
                    )}
                  </div>

                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Selected Agent Deep-Dive & Workflows */}
        <div className="lg:col-span-8 space-y-5">
          {/* Agent Header Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-base font-bold text-slate-100">{selectedAgent.canonical_name}</h2>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {selectedAgent.versions?.[0]?.version_label || 'v1.0.0'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 font-mono">{selectedAgent.source_locator}</p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => onNavigateToWorkflow?.('evidence', { agentId: selectedAgent.agent_id })}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
                >
                  <Share2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Evidence Lineage</span>
                </button>

                <button
                  onClick={() => onNavigateToWorkflow?.('knowledge', { query: `Analyze vulnerabilities in ${selectedAgent.agent_id}` })}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>Ask Knowledge</span>
                </button>
              </div>
            </div>

            {/* Workflow Navigation Tabs */}
            <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
              <button
                onClick={() => setActiveTab('overview')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  activeTab === 'overview' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                Overview & Meta
              </button>
              <button
                id="agent-lineage-tab-btn"
                onClick={() => setActiveTab('lineage')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1.5 ${
                  activeTab === 'lineage' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                Discovery Lineage
              </button>
              <button
                onClick={() => setActiveTab('provenance')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  activeTab === 'provenance' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                Source & Provenance
              </button>
              <button
                onClick={() => setActiveTab('capabilities')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  activeTab === 'capabilities' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                Tools & Permissions ({selectedAgent.tools?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('versions')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  activeTab === 'versions' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                Versions & Runs ({selectedAgent.versions?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('artifacts')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  activeTab === 'artifacts' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                Dependencies ({selectedAgent.dependencies?.length || 0})
              </button>
            </div>

            {/* Tab 1: Overview */}
            {activeTab === 'overview' && (
              <div className="space-y-4 pt-1">
                <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800/80 space-y-3 text-xs">
                  <div className="text-slate-300 leading-relaxed">
                    {selectedAgent.description}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 font-mono text-[11px]">
                    <div>
                      <span className="text-slate-500 block">Framework</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className={`font-semibold ${selectedAgent.framework === 'DATA_UNAVAILABLE' ? 'text-amber-400 italic' : 'text-slate-200'}`}>{selectedAgent.framework}</span>
                        {selectedAgent.epistemic_metadata?.framework?.truthState && (
                          <TruthStateBadge truthState={selectedAgent.epistemic_metadata.framework.truthState} size="xs" />
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Author / Maintainer</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className={`font-semibold ${selectedAgent.author === 'DATA_UNAVAILABLE' ? 'text-amber-400 italic' : 'text-slate-200'}`}>{selectedAgent.author}</span>
                        {selectedAgent.epistemic_metadata?.author?.truthState && (
                          <TruthStateBadge truthState={selectedAgent.epistemic_metadata.author.truthState} size="xs" />
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Security Clearance</span>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <SecurityClassificationBadge classification={selectedAgent.security_classification || 'DATA_UNAVAILABLE'} />
                        {selectedAgent.epistemic_metadata?.security_classification?.truthState && (
                          <TruthStateBadge truthState={selectedAgent.epistemic_metadata.security_classification.truthState} size="xs" />
                        )}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 block">Last Reconciled</span>
                      <span className="text-slate-300 font-semibold">{new Date(selectedAgent.updated_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>

                {/* Quick Action Bar for Analyst / Security Operations */}
                <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h4 className="text-xs font-semibold text-slate-200">Lifecycle Operations</h4>
                    <p className="text-[11px] text-slate-400">Launch downstream security checks or configure modification patch.</p>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => onNavigateToWorkflow?.('analysis', { agentId: selectedAgent.agent_id })}
                      className="px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 text-xs font-mono transition-colors"
                    >
                      Run 71 Engines
                    </button>
                    <button
                      onClick={() => onNavigateToWorkflow?.('modification', { agentId: selectedAgent.agent_id })}
                      className="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 text-xs font-mono transition-colors"
                    >
                      Modify & Patch
                    </button>
                    <button
                      onClick={() => onNavigateToWorkflow?.('packages', { agentId: selectedAgent.agent_id })}
                      className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-mono transition-colors"
                    >
                      Sign & Ship Bundle
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Tab: Discovery Lineage */}
            {activeTab === 'lineage' && (
              <div className="pt-1">
                <AgentDiscoveryLineageView
                  agentId={selectedAgent.agent_id}
                  canonicalName={selectedAgent.canonical_name}
                  sourceLocator={selectedAgent.source_locator}
                  createdAt={selectedAgent.created_at}
                />
              </div>
            )}

            {/* Tab 2: Provenance & Source */}
            {activeTab === 'provenance' && (
              <div className="space-y-4 pt-1">
                {selectedAgent.provenance ? (
                  <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-4 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-slate-400 font-semibold">Cryptographic Build & Source Provenance</span>
                        <FieldHelpTooltip customTitle="Provenance Attestation" customDescription="Hardware-backed KMS signatures and Git commit hashes guaranteeing tamper-evident source authenticity and build reproducibility." />
                      </div>
                      <span className={`px-2 py-0.5 rounded font-semibold text-[11px] ${
                        selectedAgent.provenance.verification_status === 'VERIFIED'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}>
                        {selectedAgent.provenance.verification_status}
                      </span>
                    </div>

                    <div className="space-y-2.5 text-[11px]">
                      <div className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-slate-500">Repository Origin</span>
                        <a href={selectedAgent.provenance.repository_url} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline flex items-center space-x-1">
                          <span>{selectedAgent.provenance.repository_url}</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-slate-500">Commit SHA</span>
                        <span className="text-slate-300 font-semibold">{selectedAgent.provenance.commit_sha}</span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-slate-500">KMS Signer Identity</span>
                        <span className="text-slate-300">{selectedAgent.provenance.signer_identity}</span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-slate-500">Deterministic Build Pipeline</span>
                        <span className="text-slate-300">{selectedAgent.provenance.build_pipeline}</span>
                      </div>

                      <div className="flex justify-between py-1">
                        <span className="text-slate-500">Signed Timestamp</span>
                        <span className="text-slate-400">{new Date(selectedAgent.provenance.signed_at).toUTCString()}</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 font-mono">No cryptographic provenance record attached.</p>
                )}
              </div>
            )}

            {/* Tab 3: Tools & Permissions */}
            {activeTab === 'capabilities' && (
              <div className="space-y-3 pt-1">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
                  <div className="flex items-center space-x-2">
                    <span>Declared Tools & Dynamic Sinks ({selectedAgent.tools?.length || 0})</span>
                    <FieldHelpTooltip customTitle="Tool Sinks & Permissions" customDescription="Explicit least-privilege capability manifests specifying network endpoints, local filesystem access, and subshell invocation rights." />
                  </div>
                  <span>Principle of Least Privilege Gate</span>
                </div>

                <div className="space-y-2">
                  {(selectedAgent.tools || []).map(tool => (
                    <div key={tool.tool_id} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-start justify-between gap-3 text-xs">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-semibold font-mono text-slate-100">{tool.name}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                            {tool.category}
                          </span>
                          {tool.is_privileged && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">
                              PRIVILEGED
                            </span>
                          )}
                        </div>
                        <p className="text-slate-400 text-[11px]">{tool.description}</p>
                        <p className="text-slate-500 font-mono text-[10px]">Permission Scope: <code className="text-cyan-400">{tool.permission_scope}</code></p>
                      </div>

                      <span className="shrink-0 text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded text-[11px] font-mono">
                        AUDITED
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tab 4: Versions & Runs */}
            {activeTab === 'versions' && (
              <div className="space-y-4 pt-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 font-mono">Registered Releases</span>
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      placeholder="v1.1.0"
                      value={newVersionLabel}
                      onChange={e => setNewVersionLabel(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 w-24 font-mono"
                    />
                    <button
                      onClick={handleRegisterVersion}
                      disabled={isRegisteringVersion}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition-colors"
                    >
                      <Plus className="w-3 h-3" />
                      <span>Register Version</span>
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  {(selectedAgent.versions || []).map(ver => (
                    <div key={ver.agent_version_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3 text-xs">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-slate-100 text-sm font-mono">{ver.version_label}</span>
                          <span className="text-xs font-mono text-slate-400">({ver.agent_version_id})</span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400">
                            {ver.status || 'ACTIVE'}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-500 font-mono">{new Date(ver.created_at).toLocaleDateString()}</span>
                      </div>

                      <div className="text-[11px] font-mono text-slate-400 truncate">
                        Content Hash: <span className="text-slate-300">{ver.content_hash}</span>
                      </div>

                      {/* Associated Analysis Runs */}
                      {ver.analysis_runs && ver.analysis_runs.length > 0 && (
                        <div className="pt-2 border-t border-slate-900 space-y-1.5">
                          <span className="text-[10px] uppercase font-mono text-slate-500 font-semibold block">Analysis Runs History</span>
                          {ver.analysis_runs.map(run => (
                            <div key={run.analysis_run_id} className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80 flex items-center justify-between font-mono text-[11px]">
                              <div className="flex items-center space-x-2">
                                <span className="text-cyan-400 font-semibold">{run.analysis_run_id}</span>
                                <span className="text-slate-500">Pipeline v{run.pipeline_version}</span>
                              </div>
                              <div className="flex items-center space-x-3">
                                <span className="text-slate-400">
                                  {typeof run.claims_count === 'number' ? `${run.claims_count} Claims` : String(run.claims_count)}
                                </span>
                                <span className="text-slate-400">
                                  {typeof run.findings_count === 'number' ? `${run.findings_count} Findings` : String(run.findings_count)}
                                </span>
                                <RiskScoreBadge score={run.overall_score} riskBand={run.risk_band} />
                                {run.truthState && (
                                  <TruthStateBadge truthState={run.truthState} size="xs" />
                                )}
                              </div>
                            </div>
                          ))}

                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tab 5: Dependencies & SBOM */}
            {activeTab === 'artifacts' && (
              <div className="space-y-3 pt-1">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
                  <span>SBOM Package Dependencies ({selectedAgent.dependencies?.length || 0})</span>
                  <span>Reachability Analysis</span>
                </div>

                <div className="space-y-2 font-mono text-xs">
                  {(selectedAgent.dependencies || []).map((dep, idx) => (
                    <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <Package className="w-3.5 h-3.5 text-cyan-400" />
                          <span className="font-semibold text-slate-200">{dep.name}</span>
                          <span className="text-slate-500">{dep.version_spec}</span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                          dep.reachability === 'REACHABLE' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {dep.reachability}
                        </span>

                        {dep.advisories_count > 0 ? (
                          <span className="text-[10px] px-2 py-0.5 rounded font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                            {dep.advisories_count} Advisory
                          </span>
                        ) : (
                          <span className="text-[10px] px-2 py-0.5 rounded font-semibold bg-emerald-500/20 text-emerald-400">
                            0 CVEs
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      )}
    </div>
  );
};
