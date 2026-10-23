import crypto from 'node:crypto';
import {
  QueueAdapter,
  JobRecord,
  JobAttemptRecord,
  DeadLetterJobRecord,
  QueueMessage,
  EnqueueJobOptions,
  DequeueOptions,
  DurableReferencePayload,
  JobStatus,
  CorrelationContext,
} from './types.ts';
import {
  JobExecutionError,
  LeaseExpiredError,
  PoisonPillJobError,
  classifyError,
} from './errors.ts';
import { shouldRetry, calculateBackoffMs } from './retry.ts';
import {
  LifecycleStateMachineService,
  LifecycleEntityKind,
} from '../../lifecycle/src/index.ts';

export interface DatabaseClientLike {
  query(sql: string, params?: unknown[]): Promise<{ rows: any[]; rowCount?: number }>;
}

export function generateUuid(): string {
  return crypto.randomUUID();
}

// Invariant: Queues carry durable references, never large artifact bodies (>64KB payload check)
const MAX_QUEUE_PAYLOAD_BYTES = 64 * 1024;

export class PgQueueAdapter implements QueueAdapter {
  constructor(private db: DatabaseClientLike) {}

  /**
   * Enqueue a job into the ops.jobs table with idempotency guarantees.
   * If an idempotency key matches an existing job, returns the existing job.
   */
  async enqueue<T = DurableReferencePayload>(
    queueKey: string,
    payload: T,
    options: EnqueueJobOptions = {}
  ): Promise<JobRecord<T>> {
    const serializedPayload = JSON.stringify(payload ?? {});
    if (serializedPayload.length > MAX_QUEUE_PAYLOAD_BYTES) {
      throw new PoisonPillJobError(
        `Payload size (${serializedPayload.length} bytes) exceeds maximum queue limit (${MAX_QUEUE_PAYLOAD_BYTES} bytes). Queues must carry durable references only.`
      );
    }

    const idempotencyKey =
      options.idempotencyKey ||
      `${queueKey}:${options.workflowRunId || 'standalone'}:${generateUuid()}`;

    // Check if job with idempotency_key already exists
    const existing = await this.db.query(
      `SELECT * FROM ops.jobs WHERE idempotency_key = $1;`,
      [idempotencyKey]
    );

    if (existing.rows && existing.rows.length > 0) {
      const job = existing.rows[0];
      return {
        ...job,
        payload: typeof job.payload === 'string' ? JSON.parse(job.payload) : job.payload,
      } as JobRecord<T>;
    }

    const jobId = generateUuid();
    const priority = options.priority ?? 10;
    const delayMs = options.delayMs ?? 0;
    const nextAttemptAt = new Date(Date.now() + delayMs).toISOString();

    const insertRes = await this.db.query(
      `INSERT INTO ops.jobs (
        job_id,
        workflow_run_id,
        stage_run_id,
        queue_key,
        idempotency_key,
        priority,
        status,
        next_attempt_at,
        payload,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, 'QUEUED', $7, $8, now())
      RETURNING *;`,
      [
        jobId,
        options.workflowRunId || null,
        options.stageRunId || null,
        queueKey,
        idempotencyKey,
        priority,
        nextAttemptAt,
        serializedPayload,
      ]
    );

    const createdJob = insertRes.rows[0];

    // Record initial state transition in lifecycle log
    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: null,
          toState: 'QUEUED',
          action: 'ENQUEUE',
          transitionReason: `Job enqueued to ${queueKey}`,
          actorRef: 'system_service:queue_adapter',
          correlationId: options.correlationContext?.correlationId || idempotencyKey,
        },
        { dbClient: this.db }
      );
    } catch {
      // Best effort transition recording on initial queue
    }

    return {
      ...createdJob,
      payload: typeof createdJob.payload === 'string' ? JSON.parse(createdJob.payload) : createdJob.payload,
    } as JobRecord<T>;
  }

  /**
   * Atomically dequeue the highest priority, ready job using lease locks.
   */
  async dequeue<T = DurableReferencePayload>(
    queueKey: string,
    workerId: string,
    options: DequeueOptions = {}
  ): Promise<QueueMessage<T> | null> {
    const leaseDurationMs = options.leaseDurationMs ?? 30000;
    const nowIso = new Date().toISOString();
    const leaseExpiresAt = new Date(Date.now() + leaseDurationMs).toISOString();

    let candidate: any = null;

    try {
      // Atomic claim with FOR UPDATE SKIP LOCKED and expired lease reclaiming (PostgreSQL 16)
      const candidateRes = await this.db.query(
        `WITH candidate AS (
           SELECT job_id FROM ops.jobs
           WHERE queue_key = $1
             AND (
               (status = 'QUEUED' AND next_attempt_at <= now())
               OR (status = 'LEASED' AND EXISTS (
                 SELECT 1 FROM ops.job_attempts ja
                 WHERE ja.job_id = ops.jobs.job_id
                   AND ja.completed_at IS NULL
                   AND ja.lease_expires_at < now()
               ))
             )
           ORDER BY priority ASC, created_at ASC
           FOR UPDATE SKIP LOCKED
           LIMIT 1
         )
         UPDATE ops.jobs j
         SET status = 'LEASED'
         FROM candidate
         WHERE j.job_id = candidate.job_id
         RETURNING j.*;`,
        [queueKey]
      );

      if (candidateRes.rows && candidateRes.rows.length > 0) {
        candidate = candidateRes.rows[0];
      }
    } catch {
      // Compatibility fallback for environments (such as pg-mem) without SKIP LOCKED AST support
      const fallbackRes = await this.db.query(
        `SELECT * FROM ops.jobs
         WHERE queue_key = $1
           AND status = 'QUEUED'
           AND next_attempt_at <= now()
         ORDER BY priority ASC, created_at ASC
         LIMIT 1;`,
        [queueKey]
      );

      if (fallbackRes.rows && fallbackRes.rows.length > 0) {
        const jobId = fallbackRes.rows[0].job_id;
        const updateRes = await this.db.query(
          `UPDATE ops.jobs
           SET status = 'LEASED'
           WHERE job_id = $1 AND status = 'QUEUED'
           RETURNING *;`,
          [jobId]
        );
        if (updateRes.rows && updateRes.rows.length > 0) {
          candidate = updateRes.rows[0];
        }
      }
    }

    if (!candidate) {
      return null;
    }

    const jobId = candidate.job_id;

    // Determine attempt number
    const attemptsCountRes = await this.db.query(
      `SELECT count(*)::int as count FROM ops.job_attempts WHERE job_id = $1;`,
      [jobId]
    );
    const prevAttempts = parseInt(attemptsCountRes.rows[0]?.count || '0', 10);
    const attemptNo = prevAttempts + 1;
    const jobAttemptId = generateUuid();

    // Insert new attempt record
    await this.db.query(
      `INSERT INTO ops.job_attempts (
        job_attempt_id,
        job_id,
        attempt_no,
        worker_id,
        leased_at,
        lease_expires_at,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, now());`,
      [jobAttemptId, jobId, attemptNo, workerId, nowIso, leaseExpiresAt]
    );

    // Record lifecycle state transition
    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: 'QUEUED',
          toState: 'LEASED',
          action: 'LEASE',
          transitionReason: `Job leased by worker ${workerId} for attempt ${attemptNo}`,
          actorRef: workerId,
          correlationId: candidate.idempotency_key,
        },
        { dbClient: this.db }
      );
    } catch {
      // Ignore transition non-blocking errors
    }

    const parsedPayload =
      typeof candidate.payload === 'string'
        ? JSON.parse(candidate.payload)
        : candidate.payload;

    return {
      messageId: jobAttemptId,
      jobId,
      queueKey,
      payload: parsedPayload as T,
      attemptNo,
      leaseExpiresAt,
      workerId,
      correlationContext: {
        correlationId: candidate.idempotency_key,
      },
      job: {
        ...candidate,
        status: 'LEASED',
        payload: parsedPayload,
      } as JobRecord<T>,
    };
  }

  /**
   * Heartbeat to extend active lease duration.
   */
  async extendLease(
    jobId: string,
    attemptNo: number,
    workerId: string,
    extendDurationMs = 30000
  ): Promise<boolean> {
    const newExpiresAt = new Date(Date.now() + extendDurationMs).toISOString();

    const res = await this.db.query(
      `UPDATE ops.job_attempts
       SET lease_expires_at = $1
       WHERE job_id = $2
         AND attempt_no = $3
         AND worker_id = $4
         AND completed_at IS NULL
       RETURNING *;`,
      [newExpiresAt, jobId, attemptNo, workerId]
    );

    return (res.rowCount ?? res.rows.length) > 0;
  }

  /**
   * Mark job as successfully completed.
   */
  async ack(
    jobId: string,
    attemptNo: number,
    workerId: string,
    result?: unknown
  ): Promise<boolean> {
    const nowIso = new Date().toISOString();

    // Mark attempt completed
    await this.db.query(
      `UPDATE ops.job_attempts
       SET completed_at = $1
       WHERE job_id = $2 AND attempt_no = $3 AND worker_id = $4;`,
      [nowIso, jobId, attemptNo, workerId]
    );

    // Get current job state
    const jobRes = await this.db.query(`SELECT status FROM ops.jobs WHERE job_id = $1;`, [jobId]);
    const fromState = jobRes.rows[0]?.status || 'RUNNING';

    // Mark job completed
    const updateJob = await this.db.query(
      `UPDATE ops.jobs
       SET status = 'COMPLETED'
       WHERE job_id = $1
       RETURNING *;`,
      [jobId]
    );

    // Record lifecycle state transition
    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: fromState === 'COMPLETED' ? 'RUNNING' : fromState,
          toState: 'COMPLETED',
          action: 'COMPLETE',
          transitionReason: `Job successfully executed by worker ${workerId}`,
          actorRef: workerId,
          correlationId: jobId,
        },
        { dbClient: this.db }
      );
    } catch {
      // Ignore transition error on ack
    }

    return (updateJob.rowCount ?? updateJob.rows.length) > 0;
  }

  /**
   * Negative acknowledgment: classifies failure, schedules retry or moves to dead letter.
   */
  async nack(
    jobId: string,
    attemptNo: number,
    workerId: string,
    error: unknown,
    delayMsOverride?: number,
    policyOverrides?: Partial<any>
  ): Promise<boolean> {
    const nowIso = new Date().toISOString();
    const classified = classifyError(error);
    const retryEvaluation = shouldRetry(attemptNo, error, policyOverrides);

    // Update attempt with failure classification
    await this.db.query(
      `UPDATE ops.job_attempts
       SET completed_at = $1,
           failure_class = $2,
           failure_code = $3,
           error_message = $4
       WHERE job_id = $5 AND attempt_no = $6 AND worker_id = $7;`,
      [
        nowIso,
        classified.failureClass,
        classified.failureCode,
        classified.message,
        jobId,
        attemptNo,
        workerId,
      ]
    );

    if (retryEvaluation.retry) {
      const delayMs = delayMsOverride ?? retryEvaluation.delayMs;
      const nextAttemptAt = new Date(Date.now() + delayMs).toISOString();

      await this.db.query(
        `UPDATE ops.jobs
         SET status = 'QUEUED',
             next_attempt_at = $1
         WHERE job_id = $2;`,
        [nextAttemptAt, jobId]
      );

      try {
        await LifecycleStateMachineService.transitionState(
          {
            entityRefId: jobId,
            entityKind: 'JOB',
            fromState: 'RUNNING',
            toState: 'RETRYING',
            action: 'SCHEDULE_RETRY',
            transitionReason: retryEvaluation.reason,
            actorRef: workerId,
            correlationId: jobId,
          },
          { dbClient: this.db }
        );
      } catch {
        // Fallback
      }

      return true;
    } else {
      // Retries exhausted or non-retryable error -> DLQ or FAILED
      if (classified.classification === 'POISON_PILL' || attemptNo >= 5) {
        return this.deadLetter(
          jobId,
          attemptNo,
          workerId,
          classified.failureCode,
          classified.message
        );
      } else {
        await this.db.query(
          `UPDATE ops.jobs
           SET status = 'FAILED'
           WHERE job_id = $1;`,
          [jobId]
        );

        try {
          await LifecycleStateMachineService.transitionState(
            {
              entityRefId: jobId,
              entityKind: 'JOB',
              fromState: 'RUNNING',
              toState: 'FAILED',
              action: 'FAIL',
              transitionReason: classified.message,
              actorRef: workerId,
              correlationId: jobId,
            },
            { dbClient: this.db }
          );
        } catch {
          // Fallback
        }

        return false;
      }
    }
  }

  /**
   * Route job directly to Dead Letter Queue (ops.dead_letter_jobs).
   */
  async deadLetter(
    jobId: string,
    attemptNo: number,
    workerId: string,
    finalFailureCode: string,
    errorMessage?: string,
    locator?: string
  ): Promise<boolean> {
    const nowIso = new Date().toISOString();
    const dlqId = generateUuid();

    // Mark attempt completed if not already
    await this.db.query(
      `UPDATE ops.job_attempts
       SET completed_at = COALESCE(completed_at, $1),
           failure_code = $2,
           error_message = COALESCE(error_message, $3)
       WHERE job_id = $4 AND attempt_no = $5;`,
      [nowIso, finalFailureCode, errorMessage || 'Poison payload or exhausted retries', jobId, attemptNo]
    );

    // Update job status to DEAD_LETTER
    await this.db.query(
      `UPDATE ops.jobs
       SET status = 'DEAD_LETTER'
       WHERE job_id = $1;`,
      [jobId]
    );

    // Insert into ops.dead_letter_jobs
    await this.db.query(
      `INSERT INTO ops.dead_letter_jobs (
        dead_letter_job_id,
        job_id,
        final_failure_code,
        payload_snapshot_locator,
        dead_lettered_at,
        resolution_state
      ) VALUES ($1, $2, $3, $4, $5, 'UNRESOLVED');`,
      [dlqId, jobId, finalFailureCode, locator || null, nowIso]
    );

    // Record lifecycle state transition
    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: 'RUNNING',
          toState: 'DEAD_LETTER',
          action: 'DEAD_LETTER',
          transitionReason: `Job dead-lettered with code ${finalFailureCode}: ${errorMessage || ''}`,
          actorRef: workerId,
          correlationId: jobId,
        },
        { dbClient: this.db }
      );
    } catch {
      // Ignore transition error
    }

    return true;
  }

  /**
   * Reaps expired leases (e.g. from crashed workers) and re-enqueues them.
   */
  async reapExpiredLeases(): Promise<number> {
    // Find job attempts that have expired without completion
    const expiredRes = await this.db.query(
      `SELECT ja.job_id, ja.attempt_no, ja.worker_id, j.status
       FROM ops.job_attempts ja
       JOIN ops.jobs j ON ja.job_id = j.job_id
       WHERE (j.status = 'LEASED' OR j.status = 'RUNNING')
         AND ja.completed_at IS NULL
         AND ja.lease_expires_at < now();`
    );

    let reapedCount = 0;
    for (const row of expiredRes.rows || []) {
      const jobId = row.job_id;
      const attemptNo = row.attempt_no;

      // Mark expired attempt
      await this.db.query(
        `UPDATE ops.job_attempts
         SET completed_at = now(),
             failure_class = 'LeaseExpiredError',
             failure_code = 'ERR_LEASE_EXPIRED',
             error_message = 'Worker node heartbeat timed out or crashed'
         WHERE job_id = $1 AND attempt_no = $2;`,
        [jobId, attemptNo]
      );

      // If attempt count >= 5, DLQ it, otherwise re-queue
      if (attemptNo >= 5) {
        await this.deadLetter(
          jobId,
          attemptNo,
          row.worker_id || 'system_reaper',
          'ERR_LEASE_EXPIRED_MAX_RETRIES',
          'Repeated worker crash or lease expiry'
        );
      } else {
        await this.db.query(
          `UPDATE ops.jobs
           SET status = 'QUEUED',
               next_attempt_at = now()
           WHERE job_id = $1;`,
          [jobId]
        );

        try {
          await LifecycleStateMachineService.transitionState(
            {
              entityRefId: jobId,
              entityKind: 'JOB',
              fromState: 'LEASED',
              toState: 'QUEUED',
              action: 'LEASE_EXPIRED',
              transitionReason: `Lease expired after worker ${row.worker_id} crashed; returned to queue`,
              actorRef: 'system_service:lease_reaper',
              correlationId: jobId,
            },
            { dbClient: this.db }
          );
        } catch {
          // Ignore
        }
      }
      reapedCount++;
    }

    return reapedCount;
  }
}
