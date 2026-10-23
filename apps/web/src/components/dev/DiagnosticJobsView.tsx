import React, { useState } from 'react';
import { 
  Layers, 
  Search, 
  RefreshCw, 
  Filter, 
  Eye, 
  CheckCircle2, 
  Clock, 
  AlertCircle, 
  XCircle,
  Timer,
  Cpu,
  Hash,
  Shield
} from 'lucide-react';
import { DiagnosticStatusBadge } from './DiagnosticStatusBadge.tsx';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

interface JobSummary {
  job_id: string;
  workflow_run_id?: string | null;
  stage_run_id?: string | null;
  queue_key: string;
  idempotency_key: string;
  priority: number;
  status: string;
  next_attempt_at?: string | null;
  payload: any;
  created_at: string;
  attempts_count: number;
  last_attempt?: {
    job_attempt_id: string;
    attempt_no: number;
    worker_id: string;
    leased_at: string;
    lease_expires_at: string;
    completed_at?: string | null;
    failure_class?: string | null;
    failure_code?: string | null;
    error_message?: string | null;
    lease_active: boolean;
  } | null;
}

interface DiagnosticJobsViewProps {
  jobs: JobSummary[];
  loading: boolean;
  onRefresh: () => void;
  onSelectJob: (jobId: string) => Promise<any>;
}

export const DiagnosticJobsView: React.FC<DiagnosticJobsViewProps> = ({
  jobs,
  loading,
  onRefresh,
  onSelectJob,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [queueFilter, setQueueFilter] = useState('ALL');
  const [selectedJobDetail, setSelectedJobDetail] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Extract unique queues
  const availableQueues = Array.from(new Set(jobs.map((j) => j.queue_key).filter(Boolean)));

  const filteredJobs = jobs.filter((j) => {
    const matchesSearch =
      j.job_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      j.idempotency_key.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (j.last_attempt?.worker_id || '').toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'ALL' || j.status === statusFilter;
    const matchesQueue = queueFilter === 'ALL' || j.queue_key === queueFilter;

    return matchesSearch && matchesStatus && matchesQueue;
  });

  const handleInspectJob = async (jobId: string) => {
    setDetailLoading(true);
    try {
      const details = await onSelectJob(jobId);
      setSelectedJobDetail(details);
    } catch {
      // Handled
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              <span>Jobs, Leases & Attempts State</span>
            </h2>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {jobs.length} Jobs Total
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Durable references, heartbeat visibility timeouts, retry classification, and worker executions.
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

      {/* Filter & Search Bar */}
      <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800 space-y-3 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex-1 min-w-[240px] relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search by Job ID, Idempotency Key, or Worker ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {availableQueues.length > 0 && (
            <div className="flex items-center space-x-1.5">
              <span className="text-slate-400 text-[11px]">Queue:</span>
              <select
                value={queueFilter}
                onChange={(e) => setQueueFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-slate-200 rounded px-2.5 py-1 text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Queues ({jobs.length})</option>
                {availableQueues.map((q) => (
                  <option key={q} value={q}>
                    {q}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {/* Status Filters */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-800/80">
          <span className="text-slate-400 text-[11px] mr-1">Status:</span>
          {['ALL', 'QUEUED', 'LEASED', 'RUNNING', 'RETRYING', 'COMPLETED', 'FAILED', 'DEAD_LETTER'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors ${
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

      {/* Jobs Table */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
        {loading && jobs.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
            Loading job & lease records...
          </div>
        ) : filteredJobs.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            No jobs match current filter or search criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Job ID & Queue</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Idempotency Key</th>
                  <th className="py-3 px-4">Worker & Lease</th>
                  <th className="py-3 px-4">Attempts & Failures</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredJobs.map((job) => {
                  const hasActiveLease = job.last_attempt?.lease_active ?? false;

                  return (
                    <tr key={job.job_id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-200">
                          <span className="text-cyan-300">{job.job_id.slice(0, 8)}</span>
                          <span className="text-slate-500">...{job.job_id.slice(-4)}</span>
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          <span className="px-1.5 py-0.5 bg-slate-950 rounded border border-slate-800">
                            {job.queue_key}
                          </span>
                          <span className="text-slate-600 ml-1.5">Pri: {job.priority}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <DiagnosticStatusBadge status={job.status} size="sm" pulse={job.status === 'RUNNING' || job.status === 'LEASED'} />
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <div className="truncate max-w-xs text-[11px] text-slate-300 font-mono" title={job.idempotency_key}>
                          {job.idempotency_key}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        {job.last_attempt ? (
                          <div className="text-[11px] space-y-0.5">
                            <div className="text-slate-300 flex items-center space-x-1">
                              <Cpu className="w-3 h-3 text-cyan-400" />
                              <span className="truncate max-w-[140px]">{job.last_attempt.worker_id}</span>
                            </div>
                            <div>
                              {hasActiveLease ? (
                                <span className="text-emerald-400 font-semibold flex items-center space-x-1">
                                  <Timer className="w-3 h-3" />
                                  <span>Lease Active</span>
                                </span>
                              ) : job.last_attempt.completed_at ? (
                                <span className="text-slate-500">Completed</span>
                              ) : (
                                <span className="text-amber-400">Lease Expired</span>
                              )}
                            </div>
                          </div>
                        ) : (
                          <span className="text-slate-600">Unassigned</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-[11px]">
                          <div className="text-slate-300 font-semibold">
                            Attempt #{job.attempts_count}
                          </div>
                          {job.last_attempt?.failure_code && (
                            <div className="text-rose-400 text-[10px] truncate max-w-[160px]" title={job.last_attempt.failure_code}>
                              {job.last_attempt.failure_code}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {new Date(job.created_at).toLocaleTimeString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleInspectJob(job.job_id)}
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

      {/* Selected Job Detail Modal */}
      {selectedJobDetail && (
        <div className="bg-slate-900/90 rounded-xl border border-cyan-500/30 p-5 space-y-4 ring-1 ring-cyan-500/20">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                  <Hash className="w-4 h-4 text-cyan-400" />
                  <span>Job Inspector: {selectedJobDetail.job_id}</span>
                </h3>
                <DiagnosticStatusBadge status={selectedJobDetail.status} size="sm" />
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Queue: <code className="text-cyan-300">{selectedJobDetail.queue_key}</code> • Idempotency Key: <code className="text-slate-300">{selectedJobDetail.idempotency_key}</code>
              </p>
            </div>
            <button
              onClick={() => setSelectedJobDetail(null)}
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono"
            >
              Close
            </button>
          </div>

          {/* Job Attempt History */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
              Job Attempt History ({selectedJobDetail.attempts?.length || 0} Recorded)
            </h4>

            {selectedJobDetail.attempts && selectedJobDetail.attempts.length > 0 ? (
              <div className="space-y-2">
                {selectedJobDetail.attempts.map((att: any) => (
                  <div key={att.job_attempt_id} className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/90 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 bg-slate-800 text-cyan-300 font-bold rounded">
                          Attempt #{att.attempt_no}
                        </span>
                        <span className="text-slate-400 text-[11px]">Worker: {att.worker_id}</span>
                      </div>
                      <span className="text-[11px] text-slate-500">
                        Leased: {new Date(att.leased_at).toLocaleTimeString()}
                      </span>
                    </div>

                    {att.failure_code && (
                      <div className="mt-2 p-2 bg-rose-950/30 border border-rose-500/30 rounded text-[11px] text-rose-300">
                        <div className="font-semibold">{att.failure_code} ({att.failure_class || 'Unknown'})</div>
                        <div className="text-rose-300/80 mt-0.5">{att.error_message}</div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs font-mono text-slate-500">No attempts executed yet.</p>
            )}
          </div>

          {/* Job Payload (Durable References Only) */}
          <DiagnosticJsonDrawer
            title="Durable Job Payload (Max 64KB Reference Enforcement)"
            data={selectedJobDetail.payload}
            defaultExpanded={true}
          />
        </div>
      )}
    </div>
  );
};
