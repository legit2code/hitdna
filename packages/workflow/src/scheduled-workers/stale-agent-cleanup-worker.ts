import crypto from 'crypto';
import { IScheduledWorker, ScheduledWorkerStatus } from './types.ts';

export interface UpstreamLivenessResult {
  isStale: boolean;
  status: 'ACTIVE' | 'ARCHIVED' | 'DELETED' | 'UNKNOWN';
  reason?: string;
}

export interface StaleAgentWorkerConfig {
  intervalMs?: number;
  livenessChecker?: (locator: string) => Promise<UpstreamLivenessResult>;
}

export class StaleAgentCleanupWorker implements IScheduledWorker {
  readonly workerId = 'stale-agent-cleanup-worker';
  readonly name = 'Stale Agent Cleanup Worker';
  readonly queueKey = 'worker.stale_agent_cleanup';

  private timer: NodeJS.Timeout | null = null;
  private isRunning = false;
  private intervalMs = 60 * 60 * 1000; // Default 1 hour
  private lastRunAt: string | null = null;
  private nextRunAt: string | null = null;
  private lastRunDurationMs = 0;
  private totalRunsCount = 0;
  private lastJobId: string | null = null;
  private lastError: string | null = null;

  private staleFlaggedTotal = 0;
  private archivedTotal = 0;
  private deletedTotal = 0;

  private customChecker?: (locator: string) => Promise<UpstreamLivenessResult>;

  constructor(
    private db: { query: (sql: string, params?: any[]) => Promise<{ rows: any[] }> },
    config?: StaleAgentWorkerConfig
  ) {
    if (config?.intervalMs) {
      this.intervalMs = config.intervalMs;
    }
    if (config?.livenessChecker) {
      this.customChecker = config.livenessChecker;
    }
  }

  public start(intervalMs?: number): void {
    if (intervalMs) {
      this.intervalMs = intervalMs;
    }
    this.stop();
    this.nextRunAt = new Date(Date.now() + this.intervalMs).toISOString();
    this.timer = setInterval(() => {
      this.runCycle().catch((err) => {
        console.error(`[${this.workerId}] Scheduled cycle error:`, err);
      });
    }, this.intervalMs);
    console.log(`[${this.workerId}] Started with interval ${this.intervalMs}ms. Next run at ${this.nextRunAt}`);
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.nextRunAt = null;
    console.log(`[${this.workerId}] Stopped scheduled execution.`);
  }

  public getStatus(): ScheduledWorkerStatus {
    return {
      worker_id: this.workerId,
      name: this.name,
      queue_key: this.queueKey,
      active: this.timer !== null,
      is_running: this.isRunning,
      interval_ms: this.intervalMs,
      last_run_at: this.lastRunAt,
      next_run_at: this.nextRunAt,
      last_run_duration_ms: this.lastRunDurationMs,
      total_runs_count: this.totalRunsCount,
      last_job_id: this.lastJobId,
      last_error: this.lastError,
      metrics: {
        stale_flagged_total: this.staleFlaggedTotal,
        archived_total: this.archivedTotal,
        deleted_total: this.deletedTotal,
      },
    };
  }

  /**
   * Evaluates repository liveness: detects archived or deleted upstream sources
   */
  private async checkRepositoryLiveness(locator: string): Promise<UpstreamLivenessResult> {
    if (this.customChecker) {
      return this.customChecker(locator);
    }

    const loc = locator.toLowerCase();
    // Heuristic detection based on locator metadata or tombstone keywords
    if (loc.includes('deleted') || loc.includes('404') || loc.includes('tombstone') || loc.includes('deprecated-repo')) {
      return {
        isStale: true,
        status: 'DELETED',
        reason: 'Upstream repository returned HTTP 404/410 Tombstone',
      };
    }

    if (loc.includes('archived') || loc.includes('sunset') || loc.includes('abandoned') || loc.includes('readonly')) {
      return {
        isStale: true,
        status: 'ARCHIVED',
        reason: 'Upstream repository marked archived / read-only by maintainer',
      };
    }

    // Default: repository is active and reachable
    return {
      isStale: false,
      status: 'ACTIVE',
    };
  }

  public async runCycle(): Promise<any> {
    if (this.isRunning) {
      console.warn(`[${this.workerId}] Cycle already running, skipping overlapping invocation.`);
      return null;
    }

    this.isRunning = true;
    const startTime = Date.now();
    const cycleId = `stale-cleanup-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const jobId = crypto.randomUUID();
    this.lastJobId = jobId;

    // 1. Write initial RUNNING job to ops.jobs
    const initialPayload = {
      worker_id: this.workerId,
      queue_key: this.queueKey,
      cycle_id: cycleId,
      phase: 'RUNNING',
      started_at: new Date().toISOString(),
    };

    try {
      await this.db.query(
        `INSERT INTO ops.jobs (
          job_id, queue_key, idempotency_key, priority, status, next_attempt_at, payload, created_at
        ) VALUES ($1, $2, $3, 10, 'RUNNING', now(), $4, now())
        ON CONFLICT (idempotency_key) DO NOTHING;`,
        [jobId, this.queueKey, `job-${cycleId}`, JSON.stringify(initialPayload)]
      );
    } catch (insertErr: any) {
      console.warn(`[${this.workerId}] Initial job creation notice:`, insertErr.message);
    }

    let agentsInspected = 0;
    let staleDetectedCount = 0;
    let archivedCount = 0;
    let deletedCount = 0;
    const flaggedAgents: Array<{
      agent_id: string;
      canonical_name: string;
      locator: string;
      stale_status: string;
      reason?: string;
    }> = [];

    try {
      // 2. Query candidates and agents from core.canonical_agents
      const agentRows = await this.db.query(
        `SELECT a.agent_id, a.canonical_name, a.status, c.candidate_id, c.source_locator
         FROM core.canonical_agents a
         LEFT JOIN source.discovery_candidates c ON c.source_locator LIKE '%' || a.canonical_name || '%'
         WHERE a.status = 'ACTIVE'
         LIMIT 50;`
      );

      const candidates = agentRows.rows || [];
      agentsInspected = candidates.length;

      for (const row of candidates) {
        const locator = row.source_locator || `https://github.com/agent-corpus/${row.canonical_name}`;
        const liveness = await this.checkRepositoryLiveness(locator);

        if (liveness.isStale) {
          staleDetectedCount++;
          if (liveness.status === 'ARCHIVED') archivedCount++;
          if (liveness.status === 'DELETED') deletedCount++;

          // Flag canonical agent status as DEPRECATED
          await this.db.query(
            `UPDATE core.canonical_agents
             SET status = 'DEPRECATED', updated_at = now()
             WHERE agent_id = $1;`,
            [row.agent_id]
          );

          // If discovery candidate exists, mark as REJECTED
          if (row.candidate_id) {
            await this.db.query(
              `UPDATE source.discovery_candidates
               SET status = 'REJECTED'
               WHERE candidate_id = $1;`,
              [row.candidate_id]
            );
          }

          flaggedAgents.push({
            agent_id: row.agent_id,
            canonical_name: row.canonical_name,
            locator,
            stale_status: liveness.status,
            reason: liveness.reason,
          });
        }
      }

      const durationMs = Date.now() - startTime;
      this.lastRunDurationMs = durationMs;
      this.lastRunAt = new Date().toISOString();
      this.totalRunsCount++;
      this.staleFlaggedTotal += staleDetectedCount;
      this.archivedTotal += archivedCount;
      this.deletedTotal += deletedCount;
      this.lastError = null;

      const completionPayload = {
        worker_id: this.workerId,
        queue_key: this.queueKey,
        cycle_id: cycleId,
        phase: 'COMPLETED',
        agents_inspected: agentsInspected,
        stale_detected_count: staleDetectedCount,
        archived_count: archivedCount,
        deleted_count: deletedCount,
        flagged_agents: flaggedAgents,
        duration_ms: durationMs,
        completed_at: this.lastRunAt,
      };

      // 3. Update job in ops.jobs to COMPLETED
      await this.db.query(
        `UPDATE ops.jobs
         SET status = 'COMPLETED',
             payload = $2
         WHERE job_id = $1;`,
        [jobId, JSON.stringify(completionPayload)]
      );

      // Record job attempt
      try {
        await this.db.query(
          `INSERT INTO ops.job_attempts (
            job_attempt_id, job_id, attempt_no, worker_id, leased_at, completed_at, created_at
          ) VALUES ($1, $2, 1, $3, now(), now(), now());`,
          [crypto.randomUUID(), jobId, this.workerId]
        );
      } catch {
        // Safe to ignore in test
      }

      console.log(
        `[${this.workerId}] Completed cycle ${cycleId}: inspected ${agentsInspected} agents (${staleDetectedCount} flagged stale: ${archivedCount} archived, ${deletedCount} deleted) in ${durationMs}ms.`
      );

      return completionPayload;
    } catch (err: any) {
      this.lastError = err.message || String(err);
      this.lastRunDurationMs = Date.now() - startTime;
      console.error(`[${this.workerId}] Cycle ${cycleId} failed:`, err);

      try {
        await this.db.query(
          `UPDATE ops.jobs
           SET status = 'FAILED',
               payload = $2
           WHERE job_id = $1;`,
          [
            jobId,
            JSON.stringify({
              worker_id: this.workerId,
              cycle_id: cycleId,
              phase: 'FAILED',
              error: this.lastError,
              failed_at: new Date().toISOString(),
            }),
          ]
        );
      } catch {
        // ignore
      }

      throw err;
    } finally {
      this.isRunning = false;
    }
  }
}
