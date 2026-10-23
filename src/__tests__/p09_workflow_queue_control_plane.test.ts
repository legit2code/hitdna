import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import {
  PgQueueAdapter,
  WorkflowRunCoordinator,
  OutboxService,
  OutboxDispatcher,
  WorkerSdk,
  calculateBackoffMs,
  shouldRetry,
  classifyError,
  PoisonPillJobError,
  TransientJobError,
  PermanentJobError,
  JobCancelledError,
  DEFAULT_RETRY_POLICY,
} from '@caim/workflow';

describe('P09 — Workflow, Queue, Job, Lease & Outbox Control Plane', () => {
  let db: any;
  let queueAdapter: PgQueueAdapter;
  let coordinator: WorkflowRunCoordinator;
  let outboxService: OutboxService;
  let outboxDispatcher: OutboxDispatcher;
  let workerSdk: WorkerSdk;

  beforeEach(async () => {
    const memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    db = new pg.Client();
    await db.connect();
    queueAdapter = new PgQueueAdapter(db);
    coordinator = new WorkflowRunCoordinator(db, queueAdapter);
    outboxService = new OutboxService(db);
    outboxDispatcher = new OutboxDispatcher(db, outboxService);
    workerSdk = new WorkerSdk(db, 'worker-test-1', queueAdapter, coordinator);
  });

  afterEach(() => {
    workerSdk.shutdown();
  });

  describe('1. Queue Invariant: Durable References Only', () => {
    it('enforces payload constraint preventing large artifact bodies (>64KB)', async () => {
      const hugeString = 'A'.repeat(70 * 1024);
      const largePayload = {
        jobType: 'test',
        hugeData: hugeString,
      };

      await expect(
        queueAdapter.enqueue('test-queue', largePayload as any)
      ).rejects.toThrow(/exceeds maximum queue limit.*Queues must carry durable references only/);
    });

    it('successfully enqueues durable references with locators and hashes', async () => {
      const durablePayload = {
        jobType: 'discovery',
        entityRefId: '11111111-1111-4111-8111-111111111111',
        storageLocator: 's3://artifacts/raw/sha256:abc12345.tar.gz',
        contentHash: 'sha256:abc12345def67890',
        parameters: { depth: 2 },
      };

      const job = await queueAdapter.enqueue('discovery-queue', durablePayload, {
        idempotencyKey: 'disc:run:1',
      });

      expect(job).toBeDefined();
      expect(job.job_id).toBeDefined();
      expect(job.status).toBe('QUEUED');
      expect(job.payload.storageLocator).toBe('s3://artifacts/raw/sha256:abc12345.tar.gz');
    });
  });

  describe('2. Simulation 1: Duplicate Delivery & Idempotency', () => {
    it('returns the same existing job when enqueueing with an identical idempotency key', async () => {
      const payload = {
        jobType: 'static-analysis',
        agentVersionId: '22222222-2222-4222-8222-222222222222',
      };
      const idempotencyKey = 'static-run:version-1:stage-1';

      const job1 = await queueAdapter.enqueue('static-queue', payload, { idempotencyKey });
      const job2 = await queueAdapter.enqueue('static-queue', payload, { idempotencyKey });

      expect(job1.job_id).toBe(job2.job_id);

      // Verify only 1 row exists in ops.jobs
      const countRes = await db.query(
        `SELECT count(*)::int as count FROM ops.jobs WHERE idempotency_key = $1;`,
        [idempotencyKey]
      );
      expect(countRes.rows[0].count).toBe(1);
    });

    it('does not duplicate authoritative stage execution on duplicate message delivery', async () => {
      let executionCount = 0;

      workerSdk.registerHandler('idempotent-job', async () => {
        executionCount++;
        return { calculatedScore: 98.5 };
      });

      const job = await queueAdapter.enqueue('idempotent-queue', { jobType: 'idempotent-job' }, {
        idempotencyKey: 'idempotent:test:1',
      });

      // First delivery: worker processes and completes
      const msg1 = await queueAdapter.dequeue('idempotent-queue', 'worker-test-1');
      expect(msg1).not.toBeNull();
      const res1 = await workerSdk.processJobMessage(msg1!);
      expect(res1.success).toBe(true);
      expect(executionCount).toBe(1);

      // Duplicate delivery simulation: message re-delivered to worker
      const res2 = await workerSdk.processJobMessage(msg1!);
      expect(res2.success).toBe(true);
      expect(res2.duplicateBypassed).toBe(true);
      // Execution handler was NOT called a second time
      expect(executionCount).toBe(1);
    });
  });

  describe('3. Simulation 2: Worker Crash After Lease & Lease Expiration Recovery', () => {
    it('re-enqueues job when worker crashes and lease expires, allowing another worker to complete it', async () => {
      const payload = { jobType: 'heavy-task', stageRunId: '33333333-3333-4333-8333-333333333333' };
      const job = await queueAdapter.enqueue('heavy-queue', payload, {
        idempotencyKey: 'heavy:stage:1',
      });

      // Worker 1 leases the job with a short lease (1ms)
      const msg1 = await queueAdapter.dequeue('heavy-queue', 'worker-crashed-node', {
        leaseDurationMs: 1,
      });
      expect(msg1).not.toBeNull();
      expect(msg1?.jobId).toBe(job.job_id);

      // Simulate worker crash: worker does not ack, lease expires
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Coordinator / Reaper runs lease recovery
      const reaped = await queueAdapter.reapExpiredLeases();
      expect(reaped).toBe(1);

      // Verify job is back in QUEUED state
      const checkJob = await db.query(`SELECT status FROM ops.jobs WHERE job_id = $1;`, [job.job_id]);
      expect(checkJob.rows[0].status).toBe('QUEUED');

      // Worker 2 leases and completes the job successfully
      workerSdk.registerHandler('heavy-task', async (p) => {
        return { recovered: true, target: p.stageRunId };
      });

      const msg2 = await queueAdapter.dequeue('heavy-queue', 'worker-test-1');
      expect(msg2).not.toBeNull();
      expect(msg2?.attemptNo).toBe(2);

      const processRes = await workerSdk.processJobMessage(msg2!);
      expect(processRes.success).toBe(true);

      // Final job status is COMPLETED
      const finalJob = await db.query(`SELECT status FROM ops.jobs WHERE job_id = $1;`, [job.job_id]);
      expect(finalJob.rows[0].status).toBe('COMPLETED');
    });
  });

  describe('4. Simulation 3: Committed Result + Reliable Outbox Event', () => {
    it('records domain outbox event and reliably delivers to subscriber without loss', async () => {
      let deliveredEvent: any = null;

      outboxDispatcher.registerSubscriber({
        name: 'test-event-subscriber',
        eventTypeFilter: 'ANALYSIS_STAGE_COMPLETED',
        handler: async (evt) => {
          deliveredEvent = evt;
        },
      });

      // Simulate transactional write of domain outbox event
      const eventRecord = await outboxService.writeEvent({
        eventType: 'ANALYSIS_STAGE_COMPLETED',
        correlationId: 'corr-tx-100',
        causationId: 'cause-job-50',
        payload: {
          analysisRunId: '44444444-4444-4444-8444-444444444444',
          stage: 'STATIC_ANALYSIS',
          status: 'SUCCESS',
        },
      });

      expect(eventRecord.status).toBe('PENDING');

      // Dispatch pending events
      const dispatchStats = await outboxDispatcher.dispatchPending();
      expect(dispatchStats.deliveredCount).toBe(1);
      expect(deliveredEvent).not.toBeNull();
      expect(deliveredEvent.event_type).toBe('ANALYSIS_STAGE_COMPLETED');
      expect(deliveredEvent.payload.stage).toBe('STATIC_ANALYSIS');

      // Verify ops.outbox_deliveries audit record
      const deliveryRows = await db.query(
        `SELECT * FROM ops.outbox_deliveries WHERE event_id = $1;`,
        [eventRecord.event_id]
      );
      expect(deliveryRows.rows.length).toBe(1);
      expect(deliveryRows.rows[0].status).toBe('DELIVERED');
      expect(deliveryRows.rows[0].target_subscriber).toBe('test-event-subscriber');
    });
  });

  describe('5. Simulation 4: Poison Job → Dead-Letter Queue (DLQ)', () => {
    it('routes fatal poison pill error directly to ops.dead_letter_jobs', async () => {
      workerSdk.registerHandler('poison-job', async () => {
        throw new PoisonPillJobError('Malformed payload: byte corrupted at index 42');
      });

      const job = await queueAdapter.enqueue('poison-queue', { jobType: 'poison-job' }, {
        idempotencyKey: 'poison:test:1',
      });

      const msg = await queueAdapter.dequeue('poison-queue', 'worker-test-1');
      expect(msg).not.toBeNull();

      const res = await workerSdk.processJobMessage(msg!);
      expect(res.success).toBe(false);

      // Verify job is marked DEAD_LETTER
      const jobRes = await db.query(`SELECT status FROM ops.jobs WHERE job_id = $1;`, [job.job_id]);
      expect(jobRes.rows[0].status).toBe('DEAD_LETTER');

      // Verify ops.dead_letter_jobs entry exists with UNRESOLVED resolution state
      const dlqRes = await db.query(
        `SELECT * FROM ops.dead_letter_jobs WHERE job_id = $1;`,
        [job.job_id]
      );
      expect(dlqRes.rows.length).toBe(1);
      expect(dlqRes.rows[0].final_failure_code).toBe('ERR_POISON_PILL_PAYLOAD');
      expect(dlqRes.rows[0].resolution_state).toBe('UNRESOLVED');
    });

    it('routes job to DLQ after exhausting maximum retries on transient errors', async () => {
      workerSdk.registerHandler('exhaust-retries-job', async () => {
        throw new TransientJobError('Persistent downstream network timeout');
      }, {
        retryPolicy: { initialDelayMs: 0, multiplier: 1, maxAttempts: 5, enableJitter: false, maxDelayMs: 0 },
      });

      const job = await queueAdapter.enqueue('retry-queue', { jobType: 'exhaust-retries-job' }, {
        idempotencyKey: 'retry:test:exhaust',
      });

      // Simulate 5 consecutive retry attempts
      for (let attempt = 1; attempt <= 5; attempt++) {
        const msg = await queueAdapter.dequeue('retry-queue', 'worker-test-1');
        expect(msg).not.toBeNull();
        await workerSdk.processJobMessage(msg!);
      }

      // After 5 attempts, job is moved to DEAD_LETTER
      const jobRes = await db.query(`SELECT status FROM ops.jobs WHERE job_id = $1;`, [job.job_id]);
      expect(jobRes.rows[0].status).toBe('DEAD_LETTER');

      const dlqRes = await db.query(
        `SELECT * FROM ops.dead_letter_jobs WHERE job_id = $1;`,
        [job.job_id]
      );
      expect(dlqRes.rows.length).toBe(1);
    });
  });

  describe('6. Simulation 5: Workflow DAG, Dependency Blocking & Cancellation', () => {
    it('executes multi-step pipeline DAG with dependency resolution in sequence', async () => {
      // Register workflow definition: Discovery -> StaticAnalysis & SemanticAnalysis -> DecisionRisk
      await coordinator.registerWorkflowDefinition('caim-pipeline', '1.0.0', {
        name: 'Full CAIM Analysis Pipeline',
        steps: [
          { stepKey: 'discovery', jobType: 'discovery', queueKey: 'discovery-queue', dependsOn: [] },
          { stepKey: 'static_analysis', jobType: 'static', queueKey: 'static-queue', dependsOn: ['discovery'] },
          { stepKey: 'semantic_analysis', jobType: 'semantic', queueKey: 'semantic-queue', dependsOn: ['discovery'] },
          { stepKey: 'decision_risk', jobType: 'decision', queueKey: 'decision-queue', dependsOn: ['static_analysis', 'semantic_analysis'] },
        ],
      });

      // Register worker handlers
      workerSdk.registerHandler('discovery', async () => ({ artifacts: 5 }));
      workerSdk.registerHandler('static', async () => ({ findings: 2 }));
      workerSdk.registerHandler('semantic', async () => ({ concepts: 12 }));
      workerSdk.registerHandler('decision', async () => ({ policyDecision: 'APPROVED' }));

      // Start workflow
      const { workflowRun, initialJobs } = await coordinator.startWorkflowRun({
        workflowKey: 'caim-pipeline',
        version: '1.0.0',
        correlationId: 'corr-pipeline-1',
      });

      expect(workflowRun.status).toBe('RUNNING');
      expect(initialJobs.length).toBe(1); // Only discovery step is unblocked

      // Step 1: Execute Discovery
      const discMsg = await queueAdapter.dequeue('discovery-queue', 'worker-test-1');
      expect(discMsg).not.toBeNull();
      await workerSdk.processJobMessage(discMsg!);

      // Downstream steps static & semantic are now unblocked in parallel
      const staticMsg = await queueAdapter.dequeue('static-queue', 'worker-test-1');
      const semanticMsg = await queueAdapter.dequeue('semantic-queue', 'worker-test-1');
      expect(staticMsg).not.toBeNull();
      expect(semanticMsg).not.toBeNull();

      // Attempting to dequeue decision before static & semantic finish returns null
      const prematureDecisionMsg = await queueAdapter.dequeue('decision-queue', 'worker-test-1');
      expect(prematureDecisionMsg).toBeNull();

      // Step 2 & 3: Complete static and semantic
      await workerSdk.processJobMessage(staticMsg!);
      await workerSdk.processJobMessage(semanticMsg!);

      // Step 4: Decision step is now unblocked
      const decisionMsg = await queueAdapter.dequeue('decision-queue', 'worker-test-1');
      expect(decisionMsg).not.toBeNull();
      await workerSdk.processJobMessage(decisionMsg!);

      // Verify entire workflow completed
      const finalRun = await db.query(
        `SELECT status FROM ops.workflow_runs WHERE workflow_run_id = $1;`,
        [workflowRun.workflow_run_id]
      );
      expect(finalRun.rows[0].status).toBe('COMPLETED');
    });

    it('cancels workflow run and terminates all pending / queued child jobs', async () => {
      await coordinator.registerWorkflowDefinition('cancellable-pipeline', '1.0.0', {
        name: 'Cancellable Pipeline',
        steps: [
          { stepKey: 'step1', jobType: 's1', queueKey: 's1-q', dependsOn: [] },
          { stepKey: 'step2', jobType: 's2', queueKey: 's2-q', dependsOn: ['step1'] },
        ],
      });

      const { workflowRun } = await coordinator.startWorkflowRun({
        workflowKey: 'cancellable-pipeline',
        version: '1.0.0',
        correlationId: 'corr-cancel-1',
      });

      // Operator cancels workflow
      const cancelled = await coordinator.cancelWorkflowRun(
        workflowRun.workflow_run_id,
        'Operator cancelled run due to policy violation',
        'analyst:jane_doe'
      );
      expect(cancelled).toBe(true);

      // Verify workflow run state is CANCELLED
      const runCheck = await db.query(
        `SELECT status FROM ops.workflow_runs WHERE workflow_run_id = $1;`,
        [workflowRun.workflow_run_id]
      );
      expect(runCheck.rows[0].status).toBe('CANCELLED');

      // Verify child jobs are CANCELLED
      const jobsCheck = await db.query(
        `SELECT status FROM ops.jobs WHERE workflow_run_id = $1;`,
        [workflowRun.workflow_run_id]
      );
      for (const j of jobsCheck.rows) {
        expect(j.status).toBe('CANCELLED');
      }

      // No jobs are available for dequeue
      const s1Msg = await queueAdapter.dequeue('s1-q', 'worker-test-1');
      expect(s1Msg).toBeNull();
    });
  });

  describe('7. Simulation 6: Orchestrator Restart & In-Flight Reconciliation', () => {
    it('recovers active workflow runs and uncompleted jobs on orchestrator reboot', async () => {
      await coordinator.registerWorkflowDefinition('restart-pipeline', '1.0.0', {
        name: 'Restart Recovery Pipeline',
        steps: [
          { stepKey: 'stepA', jobType: 'stepA', queueKey: 'stepA-q', dependsOn: [] },
          { stepKey: 'stepB', jobType: 'stepB', queueKey: 'stepB-q', dependsOn: ['stepA'] },
        ],
      });

      workerSdk.registerHandler('stepA', async () => ({ doneA: true }));
      workerSdk.registerHandler('stepB', async () => ({ doneB: true }));

      const { workflowRun } = await coordinator.startWorkflowRun({
        workflowKey: 'restart-pipeline',
        version: '1.0.0',
        correlationId: 'corr-restart-1',
      });

      // Complete stepA
      const msgA = await queueAdapter.dequeue('stepA-q', 'worker-test-1');
      expect(msgA).not.toBeNull();
      await workerSdk.processJobMessage(msgA!);

      // Simulate orchestrator crash / restart by creating a new coordinator instance
      const newCoordinator = new WorkflowRunCoordinator(db, queueAdapter);

      // Run orchestrator recovery reconciliation
      const recoveryStats = await newCoordinator.reconcileAndRecover();
      expect(recoveryStats.recoveredWorkflowsCount).toBeGreaterThanOrEqual(1);

      // Verify stepB is available and can complete the workflow
      const msgB = await queueAdapter.dequeue('stepB-q', 'worker-test-1');
      expect(msgB).not.toBeNull();
      await workerSdk.processJobMessage(msgB!);

      const finalRun = await db.query(
        `SELECT status FROM ops.workflow_runs WHERE workflow_run_id = $1;`,
        [workflowRun.workflow_run_id]
      );
      expect(finalRun.rows[0].status).toBe('COMPLETED');
    });
  });

  describe('8. Backoff Calculation & Classification Unit Tests', () => {
    it('calculates exponential backoff within bounds with jitter', () => {
      const delay1 = calculateBackoffMs(1, { initialDelayMs: 1000, multiplier: 2, enableJitter: false });
      const delay2 = calculateBackoffMs(2, { initialDelayMs: 1000, multiplier: 2, enableJitter: false });
      const delay3 = calculateBackoffMs(3, { initialDelayMs: 1000, multiplier: 2, enableJitter: false });

      expect(delay1).toBe(1000);
      expect(delay2).toBe(2000);
      expect(delay3).toBe(4000);
    });

    it('correctly classifies error taxonomy', () => {
      const err1 = new Error('Connection timeout 504 Gateway Timeout');
      const class1 = classifyError(err1);
      expect(class1.classification).toBe('TRANSIENT');
      expect(class1.retryable).toBe(true);

      const err2 = new Error('429 Too Many Requests: quota exceeded');
      const class2 = classifyError(err2);
      expect(class2.classification).toBe('RATE_LIMITED');
      expect(class2.retryable).toBe(true);

      const err3 = new Error('Zod error: schema violation in payload');
      const class3 = classifyError(err3);
      expect(class3.classification).toBe('POISON_PILL');
      expect(class3.retryable).toBe(false);
    });
  });
});
