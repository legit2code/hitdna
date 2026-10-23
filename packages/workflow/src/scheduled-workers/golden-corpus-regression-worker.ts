import crypto from 'crypto';
import { IScheduledWorker, ScheduledWorkerStatus } from './types.ts';
import { globalEvaluationEngine, GoldenCorpusEvaluationEngine } from '../evaluation.ts';

export interface GoldenCorpusWorkerConfig {
  intervalMs?: number;
  engineVersion?: string;
  baselineEngineVersion?: string;
  evaluationEngine?: GoldenCorpusEvaluationEngine;
}

export class GoldenCorpusRegressionWorker implements IScheduledWorker {
  readonly workerId = 'golden-corpus-regression-worker';
  readonly name = 'Golden Corpus Regression Worker';
  readonly queueKey = 'worker.golden_corpus_regression';

  private timer: NodeJS.Timeout | null = null;
  private isRunning = false;
  private intervalMs = 30 * 60 * 1000; // Default 30 minutes
  private lastRunAt: string | null = null;
  private nextRunAt: string | null = null;
  private lastRunDurationMs = 0;
  private totalRunsCount = 0;
  private lastJobId: string | null = null;
  private lastError: string | null = null;

  private evaluationsPassedTotal = 0;
  private regressionsCaughtTotal = 0;
  private lastAccuracy = 1.0;
  private lastGateStatus = 'PASSED';

  private engineVersion = 'v2.1.0-decision-engine';
  private baselineEngineVersion = 'v2.0.1-certified';
  private evaluationEngine: GoldenCorpusEvaluationEngine;

  constructor(
    private db: { query: (sql: string, params?: any[]) => Promise<{ rows: any[] }> },
    config?: GoldenCorpusWorkerConfig
  ) {
    if (config?.intervalMs) {
      this.intervalMs = config.intervalMs;
    }
    if (config?.engineVersion) {
      this.engineVersion = config.engineVersion;
    }
    if (config?.baselineEngineVersion) {
      this.baselineEngineVersion = config.baselineEngineVersion;
    }
    this.evaluationEngine = config?.evaluationEngine || globalEvaluationEngine;
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
        evaluations_passed_total: this.evaluationsPassedTotal,
        regressions_caught_total: this.regressionsCaughtTotal,
        last_gate_status: this.lastGateStatus,
        last_accuracy: this.lastAccuracy,
        evaluated_families_count: 19,
      },
    };
  }

  public async runCycle(options?: { simulateRegression?: boolean }): Promise<any> {
    if (this.isRunning) {
      console.warn(`[${this.workerId}] Cycle already running, skipping overlapping invocation.`);
      return null;
    }

    this.isRunning = true;
    const startTime = Date.now();
    const cycleId = `golden-eval-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const jobId = crypto.randomUUID();
    this.lastJobId = jobId;

    // 1. Write RUNNING job to ops.jobs
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

    try {
      // 2. Execute authoritative Golden Corpus evaluation across 19 benchmark families
      const evalRun = await this.evaluationEngine.evaluateEngineVersion({
        engineVersion: this.engineVersion,
        baselineEngineVersion: this.baselineEngineVersion,
        isConclusionChanging: true,
      });

      const releaseDecision = this.evaluationEngine.getReleaseGateDecision(evalRun);
      this.lastGateStatus = evalRun.gateStatus;
      this.lastAccuracy = evalRun.metrics.taintPathRecall;

      const durationMs = Date.now() - startTime;
      this.lastRunDurationMs = durationMs;
      this.lastRunAt = new Date().toISOString();
      this.totalRunsCount++;

      if (releaseDecision.canDeployToProduction) {
        this.evaluationsPassedTotal++;
      } else {
        this.regressionsCaughtTotal++;
      }
      this.lastError = null;

      const completionPayload = {
        worker_id: this.workerId,
        queue_key: this.queueKey,
        cycle_id: cycleId,
        phase: 'COMPLETED',
        evaluation_run_id: evalRun.runId,
        engine_version: evalRun.engineVersion,
        baseline_engine_version: evalRun.baselineEngineVersion,
        gate_status: evalRun.gateStatus,
        can_deploy: releaseDecision.canDeployToProduction,
        summary: releaseDecision.summary,
        families_evaluated: evalRun.evaluatedFamilies.length,
        regression_violations_count: evalRun.regressionViolations.length,
        regression_violations: evalRun.regressionViolations,
        metrics: {
          taint_path_recall: evalRun.metrics.taintPathRecall,
          f1_score: evalRun.metrics.f1Score,
          policy_regression_count: evalRun.metrics.policyRegressionCount,
          rls_negative_pass_rate: evalRun.metrics.rlsAuthorizationNegativePassRate,
        },
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
        `[${this.workerId}] Completed cycle ${cycleId}: evaluated ${evalRun.evaluatedFamilies.length} families (${evalRun.gateStatus}) in ${durationMs}ms.`
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
