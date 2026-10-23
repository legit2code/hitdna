import React, { useState } from 'react';
import { 
  Skull, 
  Search, 
  RefreshCw, 
  Eye, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  FileText, 
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  Hash
} from 'lucide-react';
import { DiagnosticStatusBadge } from './DiagnosticStatusBadge.tsx';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

interface DeadLetterJobSummary {
  dead_letter_job_id: string;
  job_id: string;
  queue_key: string;
  idempotency_key: string;
  final_failure_code: string;
  payload_snapshot_locator?: string | null;
  dead_lettered_at: string;
  resolution_state: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
  resolution_notes?: string | null;
  error_message?: string | null;
  payload: any;
  replay_eligible: boolean;
  replay_policy_reason: string;
}

interface DiagnosticDlqViewProps {
  dlqEntries: DeadLetterJobSummary[];
  loading: boolean;
  onRefresh: () => void;
  onSelectDlq: (id: string) => Promise<any>;
}

export const DiagnosticDlqView: React.FC<DiagnosticDlqViewProps> = ({
  dlqEntries,
  loading,
  onRefresh,
  onSelectDlq,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedDlqDetail, setSelectedDlqDetail] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const filteredEntries = dlqEntries.filter((e) => {
    return (
      e.dead_letter_job_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.job_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.final_failure_code.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.queue_key.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  const handleInspect = async (id: string) => {
    setDetailLoading(true);
    try {
      const details = await onSelectDlq(id);
      setSelectedDlqDetail(details);
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
              <Skull className="w-5 h-5 text-rose-400" />
              <span>Dead-Letter Queue (DLQ) & Poison Quarantine</span>
            </h2>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300">
              {dlqEntries.length} Quarantined Jobs
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Unrecoverable failure isolation, payload snapshots, and audited replay qualification policies.
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

      {/* Filter / Search Bar */}
      <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800 text-xs font-mono">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by DLQ ID, Job ID, Queue, or Failure Code (e.g. ERR_POISON_PILL_PAYLOAD)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* DLQ Table */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
        {loading && dlqEntries.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
            Loading dead-letter records...
          </div>
        ) : filteredEntries.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">
            {dlqEntries.length === 0 ? "Dead-letter queue is completely empty (no poison or failed jobs quarantined)." : "No DLQ entries match search term."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">DLQ / Job ID</th>
                  <th className="py-3 px-4">Queue Key</th>
                  <th className="py-3 px-4">Final Failure Code & Error</th>
                  <th className="py-3 px-4">Resolution</th>
                  <th className="py-3 px-4">Replay Eligibility</th>
                  <th className="py-3 px-4">Dead Lettered At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEntries.map((dlq) => (
                  <tr key={dlq.dead_letter_job_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-rose-300">
                        {dlq.dead_letter_job_id.slice(0, 8)}...{dlq.dead_letter_job_id.slice(-4)}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Job: <span className="text-slate-300">{dlq.job_id.slice(0, 8)}...</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      <span className="px-2 py-0.5 bg-slate-950 rounded border border-slate-800 text-[11px]">
                        {dlq.queue_key}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-rose-400 text-[11px]">
                        {dlq.final_failure_code}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate max-w-xs mt-0.5">
                        {dlq.error_message}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <DiagnosticStatusBadge status={dlq.resolution_state} size="sm" />
                    </td>
                    <td className="py-3 px-4">
                      {dlq.replay_eligible ? (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold">
                          <ShieldCheck className="w-3 h-3" />
                          <span>ELIGIBLE</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-semibold" title={dlq.replay_policy_reason}>
                          <ShieldAlert className="w-3 h-3" />
                          <span>FATAL / INELIGIBLE</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(dlq.dead_lettered_at).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleInspect(dlq.dead_letter_job_id)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] font-medium border border-slate-700 transition-colors inline-flex items-center space-x-1"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected DLQ Detail Modal */}
      {selectedDlqDetail && (
        <div className="bg-slate-900/90 rounded-xl border border-rose-500/30 p-5 space-y-4 ring-1 ring-rose-500/20">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                  <Skull className="w-4 h-4 text-rose-400" />
                  <span>DLQ Incident Analysis: {selectedDlqDetail.dead_letter_job_id}</span>
                </h3>
                <DiagnosticStatusBadge status={selectedDlqDetail.resolution_state} size="sm" />
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Final Failure Code: <code className="text-rose-400 font-bold">{selectedDlqDetail.final_failure_code}</code>
              </p>
            </div>
            <button
              onClick={() => setSelectedDlqDetail(null)}
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono"
            >
              Close
            </button>
          </div>

          {/* Replay Qualification Banner */}
          <div className={`p-3 rounded-lg border text-xs font-mono ${
            selectedDlqDetail.replay_eligible 
              ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300' 
              : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
          }`}>
            <div className="font-semibold flex items-center space-x-1.5">
              {selectedDlqDetail.replay_eligible ? (
                <>
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Audited Replay Authorization Policy: APPROVED</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>Audited Replay Authorization Policy: RESTRICTED</span>
                </>
              )}
            </div>
            <p className="text-[11px] mt-1 opacity-90">{selectedDlqDetail.replay_policy_reason}</p>
          </div>

          {/* Attempt Execution Timeline */}
          {selectedDlqDetail.job_attempts && selectedDlqDetail.job_attempts.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                Failed Execution Attempts ({selectedDlqDetail.job_attempts.length})
              </h4>
              <div className="space-y-1.5">
                {selectedDlqDetail.job_attempts.map((att: any) => (
                  <div key={att.job_attempt_id} className="p-2.5 bg-slate-950/80 rounded border border-slate-800 text-xs font-mono flex items-start justify-between">
                    <div>
                      <div className="font-semibold text-slate-200">Attempt #{att.attempt_no} on {att.worker_id}</div>
                      <div className="text-rose-400 text-[11px] mt-0.5">{att.failure_code}: {att.error_message}</div>
                    </div>
                    <span className="text-slate-500 text-[10px]">
                      {att.completed_at ? new Date(att.completed_at).toLocaleTimeString() : 'N/A'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Payload Snapshot Locator */}
          {selectedDlqDetail.payload_snapshot_locator && (
            <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono flex items-center justify-between">
              <span className="text-slate-400">Payload Snapshot Locator:</span>
              <span className="text-cyan-300 font-semibold">{selectedDlqDetail.payload_snapshot_locator}</span>
            </div>
          )}

          {/* Quarantined Payload Snapshot */}
          <DiagnosticJsonDrawer
            title="Quarantined Payload Snapshot (Durable Reference)"
            data={selectedDlqDetail.payload}
            defaultExpanded={true}
          />
        </div>
      )}
    </div>
  );
};
