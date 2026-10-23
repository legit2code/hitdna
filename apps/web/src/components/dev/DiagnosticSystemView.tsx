import React from 'react';
import { 
  Server, 
  Database, 
  Layers, 
  Cpu, 
  HardDrive, 
  GitBranch, 
  Activity, 
  CheckCircle2, 
  FileCode2, 
  RefreshCw,
  Zap
} from 'lucide-react';
import { DiagnosticStatusBadge } from './DiagnosticStatusBadge.tsx';
import { DiagnosticMetricsCard } from './DiagnosticMetricsCard.tsx';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

interface DiagnosticSystemViewProps {
  systemData: any;
  loading: boolean;
  onRefresh: () => void;
  onSeedData: () => void;
}

export const DiagnosticSystemView: React.FC<DiagnosticSystemViewProps> = ({
  systemData,
  loading,
  onRefresh,
  onSeedData,
}) => {
  if (loading && !systemData) {
    return (
      <div className="flex items-center justify-center py-20 text-slate-400 font-mono text-xs">
        <RefreshCw className="w-5 h-5 animate-spin mr-2 text-cyan-400" />
        Polling system and infrastructure telemetry...
      </div>
    );
  }

  if (!systemData) {
    return (
      <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400 font-mono text-xs">
        No system telemetry available. Ensure server is active and diagnostic role is authorized.
      </div>
    );
  }

  const { runtime, database, storage, queue, metadata } = systemData;

  return (
    <div className="space-y-6">
      {/* Top Controls & Status Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              <span>System & Infrastructure Health</span>
            </h2>
            <DiagnosticStatusBadge status={systemData.status} size="sm" pulse />
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Uptime: {Math.floor(systemData.uptimeSeconds / 60)}m {systemData.uptimeSeconds % 60}s • Polled at {new Date(systemData.timestamp).toLocaleTimeString()}
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={onSeedData}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
            title="Seed/verify diagnostic test records"
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Verify Test Samples</span>
          </button>
          <button
            onClick={onRefresh}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <DiagnosticMetricsCard
          title="Database Tables"
          value={database.tablesCount}
          subtitle={`Across ${database.schemas.length} verified schemas`}
          icon={<Database className="w-4 h-4" />}
          badge="PostgreSQL Schema"
          badgeVariant="emerald"
        />
        <DiagnosticMetricsCard
          title="Migration Head"
          value={`v${database.migrationHead.version}`}
          subtitle={database.migrationHead.filename}
          icon={<GitBranch className="w-4 h-4" />}
          badge={`${database.totalMigrations} Migrations`}
          badgeVariant="cyan"
        />
        <DiagnosticMetricsCard
          title="Active Leases"
          value={queue.activeLeases}
          subtitle={`${queue.expiredLeases} expired / reaped`}
          icon={<Layers className="w-4 h-4" />}
          badge={queue.activeLeases > 0 ? "Lease Lock Active" : "Idle"}
          badgeVariant={queue.activeLeases > 0 ? "cyan" : "slate"}
        />
        <DiagnosticMetricsCard
          title="Memory RSS"
          value={`${runtime.memoryUsageMb.rss} MB`}
          subtitle={`Heap: ${runtime.memoryUsageMb.heapUsed}MB / ${runtime.memoryUsageMb.heapTotal}MB`}
          icon={<Cpu className="w-4 h-4" />}
          badge={runtime.nodeVersion}
          badgeVariant="slate"
        />
      </div>

      {/* Database & Schema Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>Database & Migration Subsystem</span>
            </h3>
            <DiagnosticStatusBadge status={database.connected ? "HEALTHY" : "DISCONNECTED"} size="sm" />
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Driver & Engine:</span>
              <span className="text-slate-200 font-semibold">{database.driver}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Current Migration Head:</span>
              <span className="text-emerald-400 font-semibold truncate max-w-xs">{database.migrationHead.filename}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Total Migrations Applied:</span>
              <span className="text-slate-200">{database.totalMigrations} SQL files</span>
            </div>
            <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="text-slate-400 mb-1.5">Registered Postgres Schemas:</div>
              <div className="flex flex-wrap gap-1.5">
                {database.schemas.map((s: string) => (
                  <span key={s} className="px-2 py-0.5 bg-slate-800 text-cyan-300 rounded text-[11px]">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Queue & Storage Telemetry */}
        <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <HardDrive className="w-4 h-4 text-cyan-400" />
              <span>Storage & Queue Control Plane</span>
            </h3>
            <DiagnosticStatusBadge status={storage.status} size="sm" />
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Storage Backend:</span>
              <span className="text-slate-200">{storage.backend}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Max Queue Body Limit:</span>
              <span className="text-cyan-300 font-semibold">{storage.maxQueuePayloadBytes / 1024} KB (Durable Ref Only)</span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Total Jobs In Queue DB:</span>
              <span className="text-slate-200 font-semibold">{queue.totalJobs}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Dead Letter Jobs (DLQ):</span>
              <span className={queue.deadLetterCount > 0 ? "text-rose-400 font-semibold" : "text-slate-400"}>
                {queue.deadLetterCount}
              </span>
            </div>
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <span className="text-slate-400">Pending Outbox Events:</span>
              <span className="text-amber-400 font-semibold">{queue.pendingOutboxEvents}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Queue Job Status Breakdown */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Queue Jobs Status Distribution</span>
        </h3>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 text-xs font-mono">
          {Object.entries(queue.statusBreakdown).map(([statusKey, count]) => (
            <div key={statusKey} className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 text-center">
              <div className="text-slate-400 text-[10px] uppercase mb-1">{statusKey}</div>
              <div className="text-lg font-bold text-slate-100">{count as number}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Raw Diagnostic JSON */}
      <DiagnosticJsonDrawer
        title="Raw System Diagnostic Telemetry"
        data={systemData}
        defaultExpanded={false}
      />
    </div>
  );
};
