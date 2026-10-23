/**
 * Architecture V2.0.1 - Scheduled Background Workers Contracts
 *
 * Defines contracts and telemetry interfaces for independently controllable
 * background workers writing real status to ops.jobs.
 */

export interface ScheduledWorkerStatus {
  worker_id: string;
  name: string;
  queue_key: string;
  active: boolean;
  is_running: boolean;
  interval_ms: number;
  last_run_at: string | null;
  next_run_at: string | null;
  last_run_duration_ms: number;
  total_runs_count: number;
  last_job_id: string | null;
  last_error: string | null;
  metrics: Record<string, any>;
}

export interface IScheduledWorker {
  readonly workerId: string;
  readonly name: string;
  readonly queueKey: string;
  start(intervalMs?: number): void;
  stop(): void;
  getStatus(): ScheduledWorkerStatus;
  runCycle(): Promise<any>;
}
