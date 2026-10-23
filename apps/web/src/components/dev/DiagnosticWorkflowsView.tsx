import React, { useState } from 'react';
import { 
  Workflow, 
  Search, 
  RefreshCw, 
  ExternalLink, 
  Layers, 
  CheckCircle2, 
  Clock, 
  XCircle, 
  PlayCircle,
  FileCode2,
  GitFork,
  Eye
} from 'lucide-react';
import { DiagnosticStatusBadge } from './DiagnosticStatusBadge.tsx';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

interface WorkflowRunSummary {
  workflow_run_id: string;
  workflow_key: string;
  version: string;
  workflow_name: string;
  status: string;
  correlation_id: string;
  started_at: string;
  completed_at?: string | null;
  created_at: string;
  total_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
}

interface DiagnosticWorkflowsViewProps {
  workflows: WorkflowRunSummary[];
  loading: boolean;
  onRefresh: () => void;
  onSelectWorkflow: (id: string) => Promise<any>;
}

export const DiagnosticWorkflowsView: React.FC<DiagnosticWorkflowsViewProps> = ({
  workflows,
  loading,
  onRefresh,
  onSelectWorkflow,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedRunDetail, setSelectedRunDetail] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const filteredWorkflows = workflows.filter((wf) => {
    const matchesSearch =
      wf.workflow_run_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      wf.correlation_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      wf.workflow_key.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || wf.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleInspect = async (id: string) => {
    setDetailLoading(true);
    try {
      const details = await onSelectWorkflow(id);
      setSelectedRunDetail(details);
    } catch {
      // Handled
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header & Filtering */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
              <Workflow className="w-5 h-5 text-cyan-400" />
              <span>Workflow Run Coordinator State</span>
            </h2>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {workflows.length} Runs Recorded
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            State transitions, DAG steps, execution stages, and distributed correlation tracking.
          </p>
        </div>

        <button
          onClick={onRefresh}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter & Search Controls */}
      <div className="flex flex-wrap items-center gap-3 bg-slate-900/40 p-3 rounded-lg border border-slate-800 text-xs font-mono">
        <div className="flex-1 min-w-[240px] relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by Run ID, Correlation ID, or Workflow Key..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-1.5">
          <span className="text-slate-400 text-[11px]">Status:</span>
          {['ALL', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                statusFilter === s
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Workflow Runs List Table */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
        {loading && workflows.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
            Loading workflow run records...
          </div>
        ) : filteredWorkflows.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            No workflow runs match current filters or search criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Workflow Run ID</th>
                  <th className="py-3 px-4">Workflow & Version</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Correlation ID</th>
                  <th className="py-3 px-4">Child Jobs</th>
                  <th className="py-3 px-4">Started / Elapsed</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredWorkflows.map((wf) => {
                  const started = new Date(wf.started_at);
                  const completed = wf.completed_at ? new Date(wf.completed_at) : null;
                  const elapsedMs = (completed ? completed.getTime() : Date.now()) - started.getTime();
                  const elapsedSec = Math.max(0, Math.floor(elapsedMs / 1000));

                  return (
                    <tr key={wf.workflow_run_id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-semibold text-slate-200">
                        <span className="text-cyan-300">{wf.workflow_run_id.slice(0, 8)}</span>
                        <span className="text-slate-500">...{wf.workflow_run_id.slice(-4)}</span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-200">{wf.workflow_name}</div>
                        <div className="text-[11px] text-slate-400">
                          {wf.workflow_key} <span className="text-slate-600">v{wf.version}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <DiagnosticStatusBadge status={wf.status} size="sm" pulse={wf.status === 'RUNNING'} />
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <span className="px-1.5 py-0.5 bg-slate-950 rounded border border-slate-800 text-[11px]">
                          {wf.correlation_id}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-1.5">
                          <span className="text-slate-200 font-semibold">{wf.completed_jobs}</span>
                          <span className="text-slate-500">/</span>
                          <span className="text-slate-400">{wf.total_jobs}</span>
                          {wf.failed_jobs > 0 && (
                            <span className="text-rose-400 text-[10px] ml-1">({wf.failed_jobs} failed)</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        <div>{started.toLocaleTimeString()}</div>
                        <div className="text-slate-500">{elapsedSec}s elapsed</div>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleInspect(wf.workflow_run_id)}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] font-medium border border-slate-700 transition-colors inline-flex items-center space-x-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Workflow Inspection Modal / Drawer */}
      {selectedRunDetail && (
        <div className="bg-slate-900/90 rounded-xl border border-cyan-500/30 p-5 space-y-4 ring-1 ring-cyan-500/20">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                  <GitFork className="w-4 h-4 text-cyan-400" />
                  <span>Workflow Execution DAG Detail: {selectedRunDetail.workflow_name}</span>
                </h3>
                <DiagnosticStatusBadge status={selectedRunDetail.status} size="sm" />
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Run ID: <code className="text-cyan-300">{selectedRunDetail.workflow_run_id}</code> • Correlation ID: <code className="text-slate-300">{selectedRunDetail.correlation_id}</code>
              </p>
            </div>
            <button
              onClick={() => setSelectedRunDetail(null)}
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono"
            >
              Close
            </button>
          </div>

          {/* Steps & Jobs List */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
              Associated Jobs & DAG Stages ({selectedRunDetail.jobs?.length || 0})
            </h4>

            {selectedRunDetail.jobs && selectedRunDetail.jobs.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {selectedRunDetail.jobs.map((job: any) => (
                  <div key={job.job_id} className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200 text-[11px]">{job.queue_key}</span>
                      <DiagnosticStatusBadge status={job.status} size="sm" />
                    </div>
                    <div className="mt-2 text-[11px] text-slate-400 space-y-1">
                      <div>Job ID: <span className="text-slate-300">{job.job_id}</span></div>
                      <div>Idempotency Key: <span className="text-slate-300">{job.idempotency_key}</span></div>
                      <div>Attempts Recorded: <span className="text-cyan-300">{job.attempts_count}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-500">No child jobs dispatched yet for this workflow run.</p>
            )}
          </div>

          {/* Raw Workflow Definition & State Payload */}
          <DiagnosticJsonDrawer
            title="Workflow Definition & Payload Payload"
            data={selectedRunDetail}
            defaultExpanded={true}
          />
        </div>
      )}
    </div>
  );
};
