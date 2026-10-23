import {
  WorkerHandler,
  WorkerContext,
  WorkerRegistrationOptions,
  QueueMessage,
  DurableReferencePayload,
  JobRecord,
} from './types.ts';
import {
  JobExecutionError,
  LeaseExpiredError,
  JobCancelledError,
  classifyError,
} from './errors.ts';
import { DatabaseClientLike, PgQueueAdapter, generateUuid } from './queue.ts';
import { WorkflowRunCoordinator } from './coordinator.ts';
import {
  LifecycleStateMachineService,
} from '../../lifecycle/src/index.ts';

export class WorkerSdk {
  private handlers: Map<
    string,
    {
      handler: WorkerHandler<any, any>;
      options: WorkerRegistrationOptions;
    }
  > = new Map();
  private queueAdapter: PgQueueAdapter;
  private coordinator: WorkflowRunCoordinator;
  private activeTimers: Set<any> = new Set();
  private isShuttingDown = false;

  constructor(
    private db: DatabaseClientLike,
    private workerId = `worker-${generateUuid().substring(0, 8)}`,
    queueAdapter?: PgQueueAdapter,
    coordinator?: WorkflowRunCoordinator
  ) {
    this.queueAdapter = queueAdapter || new PgQueueAdapter(db);
    this.coordinator = coordinator || new WorkflowRunCoordinator(db, this.queueAdapter);
  }

  /**
   * Register a domain worker handler for a specific jobType or queueKey.
   */
  registerHandler<T = DurableReferencePayload, R = unknown>(
    jobTypeOrQueueKey: string,
    handler: WorkerHandler<T, R>,
    options: WorkerRegistrationOptions = {}
  ): this {
    this.handlers.set(jobTypeOrQueueKey, {
      handler,
      options: {
        queueKey: options.queueKey || jobTypeOrQueueKey,
        leaseDurationMs: options.leaseDurationMs || 30000,
        heartbeatIntervalMs: options.heartbeatIntervalMs || 10000,
        ...options,
      },
    });
    return this;
  }

  /**
   * Processes a single job message with full lease management, heartbeats,
   * idempotency checks, state transitions, and error handling.
   */
  async processJobMessage<T = DurableReferencePayload, R = unknown>(
    message: QueueMessage<T>
  ): Promise<{
    success: boolean;
    result?: R;
    error?: string;
    cancelled?: boolean;
    duplicateBypassed?: boolean;
  }> {
    const { jobId, attemptNo, queueKey, payload, correlationContext } = message;
    const jobType = (payload as any)?.jobType;
    const registration = (jobType ? this.handlers.get(jobType) : undefined) || this.handlers.get(queueKey);

    if (!registration) {
      const err = new Error(`No registered worker handler for job type '${jobType}' or queue '${queueKey}'`);
      await this.queueAdapter.deadLetter(
        jobId,
        attemptNo,
        this.workerId,
        'ERR_NO_HANDLER_REGISTERED',
        err.message
      );
      return { success: false, error: err.message };
    }

    // Invariant: Duplicate delivery guard. If job was already marked COMPLETED by a previous attempt,
    // immediately acknowledge without duplicating authoritative stage results.
    const jobStatusRes = await this.db.query(
      `SELECT status, workflow_run_id, stage_run_id FROM ops.jobs WHERE job_id = $1;`,
      [jobId]
    );
    const currentStatus = jobStatusRes.rows[0]?.status;

    if (currentStatus === 'COMPLETED') {
      await this.queueAdapter.ack(jobId, attemptNo, this.workerId);
      return { success: true, duplicateBypassed: true };
    }

    if (currentStatus === 'CANCELLED') {
      return { success: false, cancelled: true, error: 'Job was cancelled' };
    }

    // Transition from LEASED -> RUNNING
    await this.db.query(
      `UPDATE ops.jobs SET status = 'RUNNING' WHERE job_id = $1;`,
      [jobId]
    );

    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: jobId,
          entityKind: 'JOB',
          fromState: 'LEASED',
          toState: 'RUNNING',
          action: 'START',
          transitionReason: `Worker ${this.workerId} started execution (attempt ${attemptNo})`,
          actorRef: this.workerId,
          correlationId: correlationContext.correlationId,
        },
        { dbClient: this.db }
      );
    } catch {
      // Non-blocking
    }

    // Setup background heartbeat timer
    const heartbeatInterval = registration.options.heartbeatIntervalMs || 10000;
    const leaseDuration = registration.options.leaseDurationMs || 30000;

    let heartbeatTimer: any = null;
    let heartbeatActive = true;

    const performHeartbeat = async (): Promise<boolean> => {
      if (!heartbeatActive || this.isShuttingDown) return false;
      const renewed = await this.queueAdapter.extendLease(
        jobId,
        attemptNo,
        this.workerId,
        leaseDuration
      );
      return renewed;
    };

    heartbeatTimer = setInterval(async () => {
      try {
        const ok = await performHeartbeat();
        if (!ok) {
          heartbeatActive = false;
          clearInterval(heartbeatTimer);
        }
      } catch {
        heartbeatActive = false;
        clearInterval(heartbeatTimer);
      }
    }, heartbeatInterval);
    this.activeTimers.add(heartbeatTimer);

    // Build WorkerContext
    const context: WorkerContext = {
      jobId,
      attemptNo,
      workerId: this.workerId,
      correlationId: correlationContext.correlationId,
      causationId: correlationContext.causationId,
      heartbeat: performHeartbeat,
      isCancelled: async () => {
        const check = await this.db.query(
          `SELECT status FROM ops.jobs WHERE job_id = $1;`,
          [jobId]
        );
        return check.rows[0]?.status === 'CANCELLED';
      },
      logger: {
        info: (msg, meta) => console.log(`[${this.workerId}][INFO] ${msg}`, meta ?? ''),
        warn: (msg, meta) => console.warn(`[${this.workerId}][WARN] ${msg}`, meta ?? ''),
        error: (msg, meta) => console.error(`[${this.workerId}][ERROR] ${msg}`, meta ?? ''),
      },
    };

    try {
      // Execute domain worker handler
      const result = await registration.handler(payload, context);

      // Check if job was cancelled during execution
      if (await context.isCancelled()) {
        throw new JobCancelledError('Job was cancelled during execution');
      }

      // Stop heartbeat
      heartbeatActive = false;
      clearInterval(heartbeatTimer);
      this.activeTimers.delete(heartbeatTimer);

      // Acknowledge completion in queue
      await this.queueAdapter.ack(jobId, attemptNo, this.workerId, result);

      // If job belongs to a workflow run, notify coordinator
      const workflowRunId = message.job.workflow_run_id;
      if (workflowRunId) {
        await this.coordinator.onJobCompleted(workflowRunId, jobId, result);
      }

      return { success: true, result };
    } catch (err: any) {
      // Stop heartbeat
      heartbeatActive = false;
      clearInterval(heartbeatTimer);
      this.activeTimers.delete(heartbeatTimer);

      const isCancelled = err instanceof JobCancelledError;
      if (!isCancelled) {
        // Nack with retry classification
        const willRetry = await this.queueAdapter.nack(
          jobId,
          attemptNo,
          this.workerId,
          err,
          undefined,
          registration.options.retryPolicy
        );

        const workflowRunId = message.job.workflow_run_id;
        if (workflowRunId && !willRetry) {
          await this.coordinator.onJobFailed(workflowRunId, jobId, err);
        }
      }

      return {
        success: false,
        error: err.message || String(err),
        cancelled: isCancelled,
      };
    }
  }

  /**
   * Polls the queue for one job and processes it.
   */
  async pollAndProcessOnce<T = DurableReferencePayload, R = unknown>(
    queueKey: string
  ): Promise<boolean> {
    if (this.isShuttingDown) return false;

    const message = await this.queueAdapter.dequeue<T>(queueKey, this.workerId);
    if (!message) {
      return false;
    }

    await this.processJobMessage<T, R>(message);
    return true;
  }

  /**
   * Continuous polling loop for standalone worker processes.
   */
  async startPollingLoop(queueKey: string, intervalMs = 1000): Promise<void> {
    while (!this.isShuttingDown) {
      try {
        const processed = await this.pollAndProcessOnce(queueKey);
        if (!processed) {
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
      } catch (err) {
        console.error(`[WorkerSdk] Error in polling loop for queue ${queueKey}:`, err);
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      }
    }
  }

  /**
   * Graceful shutdown of all active timers.
   */
  shutdown(): void {
    this.isShuttingDown = true;
    for (const timer of this.activeTimers) {
      clearInterval(timer);
    }
    this.activeTimers.clear();
  }
}
