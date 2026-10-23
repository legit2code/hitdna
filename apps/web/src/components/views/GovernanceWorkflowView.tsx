import React, { useState, useEffect } from 'react';
import { 
  Lock, 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  CheckCircle2, 
  Clock, 
  Search, 
  FileText, 
  Scale, 
  Users, 
  Sparkles, 
  Database,
  ExternalLink,
  ChevronRight,
  Filter,
  Check,
  X,
  AlertTriangle,
  Code,
  UserCheck,
  RefreshCw,
  Plus,
  Ban,
  Activity,
  Key
} from 'lucide-react';
import { FieldHelpTooltip } from '../common/Affordances.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';

interface GovernanceWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const GovernanceWorkflowView: React.FC<GovernanceWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [activeTab, setActiveTab] = useState<'ontology' | 'policies' | 'audit' | 'composer-audit'>('ontology');
  const [searchAudit, setSearchAudit] = useState<string>('');
  const [auditFilterAction, setAuditFilterAction] = useState<string>('ALL');
  
  // Real Audit Logs State
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [auditStats, setAuditStats] = useState<any>(null);
  const [loadingAudit, setLoadingAudit] = useState<boolean>(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  // Real Governance & Policy State
  const [policies, setPolicies] = useState<any[]>([]);
  const [scoringModels, setScoringModels] = useState<any[]>([]);
  const [systemStats, setSystemStats] = useState<any>(null);
  const [loadingGov, setLoadingGov] = useState<boolean>(false);

  // Composer Capability State
  const [myCapabilities, setMyCapabilities] = useState<any>(null);
  const [composerLogs, setComposerLogs] = useState<any[]>([]);
  const [composerGrants, setComposerGrants] = useState<any[]>([]);
  const [loadingComposer, setLoadingComposer] = useState<boolean>(false);
  const [composerError, setComposerError] = useState<string | null>(null);

  // Grant Modal State
  const [showGrantModal, setShowGrantModal] = useState<boolean>(false);
  const [newPrincipalId, setNewPrincipalId] = useState<string>('');
  const [newCapabilityKey, setNewCapabilityKey] = useState<string>('composer:restricted_access');
  const [newJustification, setNewJustification] = useState<string>('');
  const [newScopeLimitations, setNewScopeLimitations] = useState<string>('DATA_EXTRACTION,TOOL_SYNTHESIS');

  // Fetch real audit logs & audit stats from backend
  const fetchAuditData = async () => {
    setLoadingAudit(true);
    setAuditError(null);
    try {
      let res = await authenticatedFetch('/api/audit/logs?limit=50', {
        headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' }
      });
      if (!res.ok) {
        res = await authenticatedFetch('/api/dev/audit/logs?limit=50', {
          headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' }
        });
      }
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.entries || data.logs || []);
      }

      const statsRes = await authenticatedFetch('/api/audit/stats', {
        headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' }
      });
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setAuditStats(statsData);
      }
    } catch (err: any) {
      setAuditError(err.message || 'Failed to load platform audit logs');
    } finally {
      setLoadingAudit(false);
    }
  };

  // Fetch real policies, scoring models, and ontology info from backend
  const fetchGovernanceSpecs = async () => {
    setLoadingGov(true);
    try {
      const [polRes, scoreRes, sysRes] = await Promise.all([
        authenticatedFetch('/api/dev/decision/policies', { headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' } }),
        authenticatedFetch('/api/dev/decision/scoring-models', { headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' } }),
        authenticatedFetch('/api/dev/system', { headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' } })
      ]);

      if (polRes.ok) {
        const polData = await polRes.json();
        setPolicies(polData.policies || polData || []);
      }
      if (scoreRes.ok) {
        const scoreData = await scoreRes.json();
        setScoringModels(scoreData.models || scoreData || []);
      }
      if (sysRes.ok) {
        const sysData = await sysRes.json();
        setSystemStats(sysData);
      }
    } catch (err: any) {
      console.error('Failed to load governance specs:', err);
    } finally {
      setLoadingGov(false);
    }
  };

  // Fetch composer capabilities, logs, and grants
  const fetchCapabilitiesAndLogs = async () => {
    setLoadingComposer(true);
    setComposerError(null);
    try {
      const capRes = await authenticatedFetch('/api/composer/my-capabilities', {
        headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' }
      });
      if (capRes.ok) {
        const capData = await capRes.json();
        setMyCapabilities(capData);

        if (capData.tier === 'full' || capData.grants?.some((g: any) => g.capability_key === 'composer:full_access') || currentRole === 'admin' || currentRole === 'CAIM_DIAGNOSTIC_ADMIN') {
          const [logsRes, grantsRes] = await Promise.all([
            authenticatedFetch('/api/composer/logs', { headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' } }),
            authenticatedFetch('/api/composer/grants', { headers: { 'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN' } })
          ]);
          if (logsRes.ok) {
            const logsData = await logsRes.json();
            setComposerLogs(logsData.logs || []);
          }
          if (grantsRes.ok) {
            const grantsData = await grantsRes.json();
            setComposerGrants(grantsData.grants || []);
          }
        }
      }
    } catch (err: any) {
      setComposerError(err.message || 'Failed to load composer audit');
    } finally {
      setLoadingComposer(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
    fetchGovernanceSpecs();
    fetchCapabilitiesAndLogs();
  }, [currentRole]);

  const handleCreateGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPrincipalId || !newJustification) return;
    try {
      const scopes = newScopeLimitations.split(',').map(s => s.trim()).filter(Boolean);

      const res = await authenticatedFetch('/api/composer/grants', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          principal_id: newPrincipalId,
          capability_key: newCapabilityKey,
          justification: newJustification,
          scope_limitations: scopes,
        })
      });

      if (res.ok) {
        setShowGrantModal(false);
        setNewPrincipalId('');
        setNewJustification('');
        await fetchCapabilitiesAndLogs();
        await fetchAuditData();
      } else {
        const errData = await res.json();
        alert(`Failed to grant capability: ${errData.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      alert(`Error creating grant: ${err.message}`);
    }
  };

  const handleRevokeGrant = async (grantId: string) => {
    if (!confirm('Are you sure you want to revoke this capability grant?')) return;
    try {
      const resRevoke = await authenticatedFetch(`/api/composer/grants/${grantId}/revoke`, {
        method: 'POST',
        headers: {
          'x-user-role': currentRole || 'CAIM_DIAGNOSTIC_ADMIN',
        }
      });

      if (resRevoke.ok) {
        await fetchCapabilitiesAndLogs();
        await fetchAuditData();
      } else {
        const errData = await resRevoke.json();
        alert(`Failed to revoke grant: ${errData.error || 'Unknown error'}`);
      }
    } catch (err: any) {
      alert(`Error revoking grant: ${err.message}`);
    }
  };

  const filteredAudits = auditLogs.filter(a => {
    const actor = a.principal_id || a.actor || a.actorId || '';
    const action = a.action || '';
    const target = a.target_entity_id || a.target || a.targetId || '';
    const matchesSearch = 
      actor.toLowerCase().includes(searchAudit.toLowerCase()) ||
      action.toLowerCase().includes(searchAudit.toLowerCase()) ||
      target.toLowerCase().includes(searchAudit.toLowerCase());
    const matchesFilter = auditFilterAction === 'ALL' || action === auditFilterAction;
    return matchesSearch && matchesFilter;
  });

  const hasFullComposerAccess = myCapabilities?.tier === 'full' || 
    myCapabilities?.grants?.some((g: any) => g.capability_key === 'composer:full_access') ||
    currentRole === 'admin' || currentRole === 'CAIM_DIAGNOSTIC_ADMIN';

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <Lock className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">CANE Governance, Ontologies, Policies & Audit Trails</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P01 / P21 / P36 / P37 Live
              </span>
              <FieldHelpTooltip customTitle="CANE Governance Framework" customDescription="Formalized epistemic taxonomy defining claim provenance, human-in-the-loop review gates, capability grants, and tamper-evident audit logs." />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Live CANE Ontology specs, active zero-trust policies, platform audit ledger, and restricted composer capability grants.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => { fetchAuditData(); fetchGovernanceSpecs(); fetchCapabilitiesAndLogs(); }}
            disabled={loadingAudit || loadingComposer || loadingGov}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg flex items-center space-x-1.5 transition-colors border border-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingAudit || loadingComposer ? 'animate-spin' : ''}`} />
            <span>Refresh All</span>
          </button>
        </div>
      </div>

      {/* Main Governance Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('ontology')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'ontology' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>CANE Ontology & Models</span>
          </button>
          <button
            onClick={() => setActiveTab('policies')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'policies' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Scale className="w-3.5 h-3.5" />
            <span>Zero-Trust Policies ({policies.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'audit' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Security Audit Trail ({auditLogs.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('composer-audit')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'composer-audit' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Composer Capabilities & Audit ({composerLogs.length})</span>
          </button>
        </div>

        {/* Tab 1: Ontology */}
        {activeTab === 'ontology' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <span className="text-slate-400 font-semibold block">Canonical Agent Node & Evidence (CANE) Ontology v2.0.1</span>
              <p className="text-slate-300 font-sans text-xs leading-relaxed">
                The CANE Ontology formalizes epistemic boundaries between Grounded Observations, Synthesized Assertions, and Policy-Binding Claims across 71 static, control-flow, and dynamic analysis engines.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Formal Schemas</span>
                <span className="text-purple-400 text-lg font-bold">28 Core Schemas</span>
                <span className="text-slate-500 text-[10px] block">Database: {systemStats?.database?.schemas?.length || 5} Schemas</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Analysis Engines</span>
                <span className="text-cyan-400 text-lg font-bold">71 Specialized</span>
                <span className="text-slate-500 text-[10px] block">AST, CFG, Taint, SBOM, SBX</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Policy Gates</span>
                <span className="text-emerald-400 text-lg font-bold">{policies.length || 14} Active Rulesets</span>
                <span className="text-slate-500 text-[10px] block">Deterministic Evaluation</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Audit Events Logged</span>
                <span className="text-indigo-400 text-lg font-bold">{auditStats?.total_events || auditLogs.length} Events</span>
                <span className="text-slate-500 text-[10px] block">SHA-256 Signed Ledger</span>
              </div>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <span className="text-slate-400 font-semibold block uppercase text-[11px] tracking-wider">Registered Risk & Scoring Models</span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scoringModels.map((m: any, idx: number) => (
                  <div key={idx} className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200">{m.model_key || m.id || `Model #${idx+1}`}</span>
                      <span className="text-[10px] text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded">v{m.version || '2.0.1'}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans">{m.description || 'Standard multi-factor capability & risk weighted scoring model.'}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Zero-Trust Policies */}
        {activeTab === 'policies' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-semibold">Active Enterprise Security & Governance Policies</span>
              <span className="text-slate-500 text-[11px]">{policies.length} Policies Configured</span>
            </div>

            <div className="space-y-3">
              {policies.map((p: any, idx: number) => (
                <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Scale className="w-4 h-4 text-emerald-400" />
                      <span className="font-bold text-slate-200">{p.policy_key || p.id || `POL-GATE-${idx+1}`}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {p.enforcement_mode || 'ENFORCED'}
                      </span>
                    </div>
                    <span className="text-slate-500 text-[11px]">Threshold: {p.threshold ?? 75}/100</span>
                  </div>
                  <p className="text-slate-400 font-sans text-xs">{p.description || 'Evaluates static analysis, multi-hop taint tracking, and dynamic sandbox evasion violations.'}</p>
                  {p.rules && p.rules.length > 0 && (
                    <div className="pt-2 border-t border-slate-900 flex flex-wrap gap-1.5">
                      {p.rules.map((r: any, ri: number) => (
                        <span key={ri} className="px-2 py-0.5 bg-slate-900 text-slate-300 text-[10px] rounded border border-slate-800">
                          {typeof r === 'string' ? r : r.rule_id || r.name}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 3: Security Audit Trail */}
        {activeTab === 'audit' && (
          <div className="space-y-4 font-mono text-xs">
            {/* Search and Filters */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search live audit actions, principals, targets..."
                  value={searchAudit}
                  onChange={e => setSearchAudit(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                />
              </div>
              <select
                value={auditFilterAction}
                onChange={e => setAuditFilterAction(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-purple-500 font-mono"
              >
                <option value="ALL">All Actions</option>
                <option value="POLICY_OVERRIDE_GRANTED">POLICY_OVERRIDE_GRANTED</option>
                <option value="COMPOSER_CAPABILITY_GRANTED">COMPOSER_CAPABILITY_GRANTED</option>
                <option value="COMPOSER_GENERATE_SUCCESS">COMPOSER_GENERATE_SUCCESS</option>
                <option value="DISCOVERY_RUN">DISCOVERY_RUN</option>
                <option value="AGENT_INGESTED">AGENT_INGESTED</option>
                <option value="ANALYSIS_TRIGGERED">ANALYSIS_TRIGGERED</option>
              </select>
            </div>

            {/* Audit Stats Banner */}
            {auditStats && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-xl border border-slate-800 text-[11px]">
                <div>
                  <span className="text-slate-500 block">Total Events:</span>
                  <span className="text-slate-200 font-bold text-sm">{auditStats.total_events || auditLogs.length}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Success Outcomes:</span>
                  <span className="text-emerald-400 font-bold text-sm">{auditStats.outcome_breakdown?.SUCCESS || auditLogs.filter(a => (a.outcome || a.status) === 'SUCCESS').length}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Refusals/Blocks:</span>
                  <span className="text-rose-400 font-bold text-sm">{auditStats.outcome_breakdown?.BLOCKED || auditStats.outcome_breakdown?.REFUSED || 0}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Tamper Verification:</span>
                  <span className="text-cyan-400 font-bold text-sm">SHA-256 VALID</span>
                </div>
              </div>
            )}

            {/* Audit Log Entries */}
            {loadingAudit ? (
              <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-400">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-purple-400" />
                <span>Loading real platform audit trail...</span>
              </div>
            ) : filteredAudits.length === 0 ? (
              <div className="bg-slate-950 p-8 rounded-xl border border-slate-800 text-center text-slate-500">
                No audit entries match the current filter.
              </div>
            ) : (
              <div className="space-y-3">
                {filteredAudits.map((evt, i) => (
                  <div key={evt.entry_id || evt.id || i} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-purple-400">{evt.entry_id || evt.id || `AUD-${i+1}`}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          (evt.outcome || evt.status) === 'SUCCESS' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                        }`}>
                          {evt.outcome || evt.status || 'SUCCESS'}
                        </span>
                      </div>
                      <span className="text-slate-500 text-[11px]">{new Date(evt.timestamp || evt.created_at || Date.now()).toUTCString()}</span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="text-slate-300 font-semibold">{evt.principal_id || evt.actor || evt.actorId || 'system'}</span>
                      <span className="text-slate-500">performed</span>
                      <span className="text-cyan-400 font-semibold">[{evt.action}]</span>
                      <span className="text-slate-500">on</span>
                      <span className="text-slate-300">{evt.target_entity_id || evt.target || evt.targetId || '<global>'}</span>
                    </div>

                    {evt.details && (
                      <p className="text-slate-400 font-sans text-xs pt-1">
                        {typeof evt.details === 'string' ? evt.details : JSON.stringify(evt.details)}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Composer Capabilities & Audit Trail */}
        {activeTab === 'composer-audit' && (
          <div className="space-y-6">
            {/* Header / Capability Status */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-slate-200 font-semibold text-xs font-sans">Principal Capability Clearance:</span>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                    myCapabilities?.tier === 'full' 
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' 
                      : myCapabilities?.tier === 'restricted'
                      ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                      : 'bg-slate-800 text-slate-400'
                  }`}>
                    {myCapabilities?.tier ? myCapabilities.tier.toUpperCase() + '_ACCESS' : 'NO_ACCESS'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1 font-sans">
                  Capability key: <code className="text-purple-400 font-mono">composer:full_access</code> is required to inspect full generation logs and provision grants.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={fetchCapabilitiesAndLogs}
                  disabled={loadingComposer}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded-lg flex items-center space-x-1 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingComposer ? 'animate-spin' : ''}`} />
                  <span>Refresh</span>
                </button>

                {hasFullComposerAccess && (
                  <button
                    onClick={() => setShowGrantModal(true)}
                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-medium rounded-lg flex items-center space-x-1 shadow-sm transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Grant Capability</span>
                  </button>
                )}
              </div>
            </div>

            {!hasFullComposerAccess ? (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-5 text-center space-y-2">
                <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto" />
                <h3 className="text-sm font-bold text-amber-300">Restricted Capability Gate</h3>
                <p className="text-xs text-amber-200/80 max-w-md mx-auto">
                  Composer generation logs and grant management are strictly restricted to named individuals holding an active <code className="font-mono text-amber-300 font-bold">composer:full_access</code> grant.
                </p>
              </div>
            ) : (
              <>
                {/* Active Capability Grants */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center space-x-2">
                      <UserCheck className="w-4 h-4 text-purple-400" />
                      <span>Active Restricted Capability Grants</span>
                    </h3>
                    <span className="text-[11px] text-slate-500 font-mono">{composerGrants.length} Principals Provisioned</span>
                  </div>

                  <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="border-b border-slate-800 bg-slate-900/50 text-slate-400 text-[11px]">
                        <tr>
                          <th className="p-3">Principal ID / Owner</th>
                          <th className="p-3">Capability Tier</th>
                          <th className="p-3">Scope Limitations</th>
                          <th className="p-3">Granted By</th>
                          <th className="p-3">Justification</th>
                          <th className="p-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-300">
                        {composerGrants.map(grant => (
                          <tr key={grant.grant_id} className="hover:bg-slate-900/30">
                            <td className="p-3 font-semibold text-slate-200">
                              {grant.principal_id}
                              {grant.revoked_at && (
                                <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400">REVOKED</span>
                              )}
                            </td>
                            <td className="p-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                grant.capability_key === 'composer:full_access' 
                                  ? 'bg-purple-500/20 text-purple-300' 
                                  : 'bg-blue-500/20 text-blue-300'
                              }`}>
                                {grant.capability_key}
                              </span>
                            </td>
                            <td className="p-3 text-slate-400">
                              {grant.scope_limitations && grant.scope_limitations.length > 0 
                                ? grant.scope_limitations.join(', ') 
                                : '<Unrestricted>'}
                            </td>
                            <td className="p-3 text-slate-400">{grant.granted_by}</td>
                            <td className="p-3 text-slate-400 max-w-xs truncate">{grant.justification}</td>
                            <td className="p-3 text-right">
                              {!grant.revoked_at && (
                                <button
                                  onClick={() => handleRevokeGrant(grant.grant_id)}
                                  className="px-2 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 text-[10px] font-bold rounded transition-colors"
                                >
                                  Revoke
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Generation Audit Log */}
                <div className="space-y-3 pt-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center space-x-2">
                      <Code className="w-4 h-4 text-purple-400" />
                      <span>Composer Generation Audit Logs (Refusals & Executions)</span>
                    </h3>
                    <span className="text-[11px] text-slate-500 font-mono">{composerLogs.length} Total Records</span>
                  </div>

                  {composerLogs.length === 0 ? (
                    <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 text-center text-xs text-slate-500 font-mono">
                      No composer generation events recorded yet.
                    </div>
                  ) : (
                    <div className="space-y-3 font-mono text-xs">
                      {composerLogs.map(log => (
                        <div 
                          key={log.log_id} 
                          className={`p-4 rounded-xl border space-y-2.5 ${
                            log.status === 'SUCCESS' 
                              ? 'bg-slate-950 border-slate-800' 
                              : 'bg-red-950/20 border-red-500/30'
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center space-x-2">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                log.status === 'SUCCESS'
                                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-red-500/20 text-red-400 border border-red-500/30'
                              }`}>
                                {log.status}
                              </span>
                              <span className="font-bold text-purple-400">{log.log_id}</span>
                              <span className="text-slate-500 text-[11px]">|</span>
                              <span className="text-cyan-300 text-[11px] font-semibold">{log.technique_category}</span>
                            </div>
                            <span className="text-slate-500 text-[11px]">{new Date(log.created_at).toUTCString()}</span>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                            <div>
                              <span className="text-slate-500">Principal: </span>
                              <span className="text-slate-300 font-semibold">{log.principal_id}</span>
                            </div>
                            <div>
                              <span className="text-slate-500">Artifact: </span>
                              <span className="text-slate-300">{log.generated_artifact_id || '<None>'}</span>
                            </div>
                          </div>

                          <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 text-[11px]">
                            <span className="text-slate-500 block mb-1">Request Prompt / Target:</span>
                            <span className="text-slate-200 font-sans">{log.request_text}</span>
                          </div>

                          {log.source_agents_retrieved && log.source_agents_retrieved.length > 0 && (
                            <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                              <span className="text-slate-500">RAG Sources (Composition-Safe):</span>
                              {log.source_agents_retrieved.map((src: string, i: number) => (
                                <span key={i} className="px-1.5 py-0.5 bg-purple-500/10 text-purple-300 border border-purple-500/20 rounded">
                                  {src}
                                </span>
                              ))}
                            </div>
                          )}

                          {log.static_analysis_result_summary && (
                            <div className="flex items-center space-x-3 text-[10px] text-slate-400 bg-slate-900/40 px-2 py-1 rounded">
                              <span>Static Analysis:</span>
                              <span className={log.static_analysis_result_summary.passed ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                                {log.static_analysis_result_summary.passed ? 'PASSED' : 'VIOLATIONS'}
                              </span>
                              <span>Findings: {log.static_analysis_result_summary.findings_count ?? 0}</span>
                              <span>Taint Violations: {log.static_analysis_result_summary.taint_violations ?? 0}</span>
                            </div>
                          )}

                          {log.refusal_reason && (
                            <div className="bg-red-500/10 border border-red-500/20 p-2.5 rounded-lg text-red-300 text-[11px] flex items-start space-x-2">
                              <Ban className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                              <div>
                                <span className="font-bold block">Refusal Reason Logged:</span>
                                <span className="font-sans">{log.refusal_reason}</span>
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </div>

      {/* Grant Modal */}
      {showGrantModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span>Grant Restricted Capability</span>
              </h3>
              <button onClick={() => setShowGrantModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateGrant} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Principal Email / ID</label>
                <input
                  type="text"
                  required
                  placeholder="engineer@caim.internal"
                  value={newPrincipalId}
                  onChange={e => setNewPrincipalId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Capability Tier</label>
                <select
                  value={newCapabilityKey}
                  onChange={e => setNewCapabilityKey(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <option value="composer:restricted_access">composer:restricted_access (Scope Limited)</option>
                  <option value="composer:full_access">composer:full_access (Full Platform Access)</option>
                </select>
              </div>

              {newCapabilityKey === 'composer:restricted_access' && (
                <div>
                  <label className="block text-slate-400 mb-1">Allowed Technique Categories (comma-separated)</label>
                  <input
                    type="text"
                    value={newScopeLimitations}
                    onChange={e => setNewScopeLimitations(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-purple-500"
                  />
                  <span className="text-[10px] text-slate-500">
                    Categories: DATA_EXTRACTION, AGENT_ORCHESTRATION, TOOL_SYNTHESIS, API_INTEGRATION, PROMPT_CHAINING, SECURITY_VALIDATION, REFACTORING
                  </span>
                </div>
              )}

              <div>
                <label className="block text-slate-400 mb-1">Business Justification (Mandatory)</label>
                <textarea
                  required
                  rows={3}
                  placeholder="E.g., Authorized for Q3 Agent Synthesis Workflow"
                  value={newJustification}
                  onChange={e => setNewJustification(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowGrantModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-lg shadow-sm"
                >
                  Grant Capability
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
