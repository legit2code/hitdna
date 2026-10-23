import {
  WorkflowDefinitionRecord,
  WorkflowDefinitionPayload,
  WorkflowStepDefinition,
  WorkflowRunRecord,
  WorkflowRunStatus,
  WorkflowRunContext,
  JobRecord,
  CorrelationContext,
  DurableReferencePayload,
} from './types.ts';
import {
  JobExecutionError,
  WorkflowCancelledError,
  DependencyFailedError,
} from './errors.ts';
import { DatabaseClientLike, PgQueueAdapter, generateUuid } from './queue.ts';
import {
  LifecycleStateMachineService,
  LifecycleEntityKind,
} from '../../lifecycle/src/index.ts';

export interface CreateWorkflowRunOptions {
  workflowKey: string;
  version?: string;
  agentId?: string;
  agentVersionId?: string;
  analysisRunId?: string;
  correlationId?: string;
  causationId?: string;
  metadata?: Record<string, unknown>;
}

export class WorkflowRunCoordinator {
  private queueAdapter: PgQueueAdapter;

  constructor(
    private db: DatabaseClientLike,
    queueAdapter?: PgQueueAdapter
  ) {
    this.queueAdapter = queueAdapter || new PgQueueAdapter(db);
  }

  /**
   * Register a workflow definition in ops.workflow_definitions.
   */
  async registerWorkflowDefinition(
    workflowKey: string,
    version: string,
    definition: WorkflowDefinitionPayload
  ): Promise<WorkflowDefinitionRecord> {
    const defId = generateUuid();
    const payloadJson = JSON.stringify(definition);

    const existing = await this.db.query(
      `SELECT * FROM ops.workflow_definitions WHERE workflow_key = $1 AND version = $2;`,
      [workflowKey, version]
    );

    if (existing.rows && existing.rows.length > 0) {
      return existing.rows[0] as WorkflowDefinitionRecord;
    }

    const res = await this.db.query(
      `INSERT INTO ops.workflow_definitions (
        workflow_definition_id,
        workflow_key,
        version,
        status,
        definition_payload,
        created_at
      ) VALUES ($1, $2, $3, 'ACTIVE', $4, now())
      RETURNING *;`,
      [defId, workflowKey, version, payloadJson]
    );

    return res.rows[0] as WorkflowDefinitionRecord;
  }

  /**
   * Start a new workflow run and schedule its initial root jobs.
   */
  async startWorkflowRun(options: CreateWorkflowRunOptions): Promise<{
    workflowRun: WorkflowRunRecord;
    initialJobs: JobRecord[];
  }> {
    const version = options.version || '1.0.0';
    const correlationId = options.correlationId || generateUuid();
    const workflowRunId = generateUuid();

    // Fetch workflow definition
    const defRes = await this.db.query(
      `SELECT * FROM ops.workflow_definitions WHERE workflow_key = $1 AND version = $2;`,
      [options.workflowKey, version]
    );

    if (!defRes.rows || defRes.rows.length === 0) {
      throw new Error(`Workflow definition not found for key: ${options.workflowKey}, version: ${version}`);
    }

    const workflowDef = defRes.rows[0] as WorkflowDefinitionRecord;
    const defPayload: WorkflowDefinitionPayload =
      typeof workflowDef.definition_payload === 'string'
        ? JSON.parse(workflowDef.definition_payload)
        : workflowDef.definition_payload;

    // Create workflow run in ops.workflow_runs
    const runRes = await this.db.query(
      `INSERT INTO ops.workflow_runs (
        workflow_run_id,
        workflow_definition_id,
        agent_id,
        agent_version_id,
        analysis_run_id,
        status,
        correlation_id,
        started_at,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, 'RUNNING', $6, now(), now())
      RETURNING *;`,
      [
        workflowRunId,
        workflowDef.workflow_definition_id,
        options.agentId || null,
        options.agentVersionId || null,
        options.analysisRunId || null,
        correlationId,
      ]
    );

    const workflowRun = runRes.rows[0] as WorkflowRunRecord;

    // Record lifecycle state transitions: null -> PENDING -> RUNNING
    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: workflowRunId,
          entityKind: 'WORKFLOW_RUN',
          fromState: null,
          toState: 'PENDING',
          action: 'INITIALIZE',
          transitionReason: `Workflow run initialized for ${options.workflowKey}`,
          actorRef: 'system_service:coordinator',
          correlationId,
        },
        { dbClient: this.db }
      );

      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: workflowRunId,
          entityKind: 'WORKFLOW_RUN',
          fromState: 'PENDING',
          toState: 'RUNNING',
          action: 'START',
          transitionReason: `Workflow execution started`,
          actorRef: 'system_service:coordinator',
          correlationId,
        },
        { dbClient: this.db }
      );
    } catch {
      // Non-blocking
    }

    // Identify root steps (no dependsOn or empty dependsOn)
    const initialJobs: JobRecord[] = [];
    const rootSteps = defPayload.steps.filter((s) => !s.dependsOn || s.dependsOn.length === 0);

    const context: WorkflowRunContext = {
      workflowRunId,
      workflowKey: options.workflowKey,
      correlationId,
      causationId: options.causationId,
      agentId: options.agentId,
      agentVersionId: options.agentVersionId,
      analysisRunId: options.analysisRunId,
      stepResults: {},
      metadata: options.metadata,
    };

    for (const step of rootSteps) {
      const payload: DurableReferencePayload = step.payloadFactory
        ? step.payloadFactory(context)
        : {
            jobType: step.jobType,
            workflowRunId,
            agentVersionId: options.agentVersionId,
            analysisRunId: options.analysisRunId,
            parameters: { stepKey: step.stepKey },
          };

      const idempotencyKey = `wf:${workflowRunId}:${step.stepKey}`;
      const job = await this.queueAdapter.enqueue(step.queueKey, payload, {
        workflowRunId,
        idempotencyKey,
        priority: step.priority ?? 10,
        correlationContext: {
          correlationId,
          causationId: workflowRunId,
        },
      });

      initialJobs.push(job);
    }

    return { workflowRun, initialJobs };
  }

  /**
   * Called when a job completes to evaluate downstream dependencies and progress the workflow.
   */
  async onJobCompleted(
    workflowRunId: string,
    completedJobId: string,
    result?: unknown
  ): Promise<{
    workflowCompleted: boolean;
    unblockedJobs: JobRecord[];
  }> {
    // Check if workflow run is active
    const runRes = await this.db.query(
      `SELECT wr.*, wd.definition_payload
       FROM ops.workflow_runs wr
       JOIN ops.workflow_definitions wd ON wr.workflow_definition_id = wd.workflow_definition_id
       WHERE wr.workflow_run_id = $1;`,
      [workflowRunId]
    );

    if (!runRes.rows || runRes.rows.length === 0) {
      return { workflowCompleted: false, unblockedJobs: [] };
    }

    const run = runRes.rows[0];
    if (run.status !== 'RUNNING') {
      return { workflowCompleted: run.status === 'COMPLETED', unblockedJobs: [] };
    }

    const defPayload: WorkflowDefinitionPayload =
      typeof run.definition_payload === 'string'
        ? JSON.parse(run.definition_payload)
        : run.definition_payload;

    // Query all existing jobs for this workflow run
    const jobsRes = await this.db.query(
      `SELECT * FROM ops.jobs WHERE workflow_run_id = $1;`,
      [workflowRunId]
    );
    const existingJobs = jobsRes.rows as JobRecord[];

    // Build completed step keys map from idempotency_keys
    const completedStepKeys = new Set<string>();
    const existingStepKeys = new Set<string>();

    for (const j of existingJobs) {
      const parts = j.idempotency_key.split(':');
      const stepKey = parts[2] || j.idempotency_key;
      existingStepKeys.add(stepKey);
      if (j.status === 'COMPLETED' || j.job_id === completedJobId) {
        completedStepKeys.add(stepKey);
      }
    }

    const unblockedJobs: JobRecord[] = [];

    // Check all steps in workflow definition
    for (const step of defPayload.steps) {
      // If already scheduled, skip
      if (existingStepKeys.has(step.stepKey)) {
        continue;
      }

      // Check if all dependencies are completed
      const dependencies = step.dependsOn || [];
      const allDepsMet = dependencies.every((dep) => completedStepKeys.has(dep));

      if (allDepsMet) {
        const payload: DurableReferencePayload = step.payloadFactory
          ? step.payloadFactory({
              workflowRunId,
              workflowKey: run.workflow_key || 'workflow',
              correlationId: run.correlation_id,
              agentId: run.agent_id,
              agentVersionId: run.agent_version_id,
              analysisRunId: run.analysis_run_id,
              stepResults: {},
            })
          : {
              jobType: step.jobType,
              workflowRunId,
              agentVersionId: run.agent_version_id,
              analysisRunId: run.analysis_run_id,
              parameters: { stepKey: step.stepKey },
            };

        const idempotencyKey = `wf:${workflowRunId}:${step.stepKey}`;
        const newJob = await this.queueAdapter.enqueue(step.queueKey, payload, {
          workflowRunId,
          idempotencyKey,
          priority: step.priority ?? 10,
          correlationContext: {
            correlationId: run.correlation_id,
            causationId: completedJobId,
          },
        });

        unblockedJobs.push(newJob);
        existingStepKeys.add(step.stepKey);
      }
    }

    // Check if entire workflow has completed
    const allWorkflowStepsCompleted = defPayload.steps.every((s) =>
      completedStepKeys.has(s.stepKey)
    );

    if (allWorkflowStepsCompleted) {
      await this.db.query(
        `UPDATE ops.workflow_runs
         SET status = 'COMPLETED',
             completed_at = now()
         WHERE workflow_run_id = $1;`,
        [workflowRunId]
      );

      try {
        await LifecycleStateMachineService.transitionState(
          {
            entityRefId: workflowRunId,
            entityKind: 'WORKFLOW_RUN',
            fromState: 'RUNNING',
            toState: 'COMPLETED',
            action: 'COMPLETE',
            transitionReason: 'All workflow pipeline steps completed successfully',
            actorRef: 'system_service:coordinator',
            correlationId: run.correlation_id,
          },
          { dbClient: this.db }
        );
      } catch {
        // Ignore
      }

      return { workflowCompleted: true, unblockedJobs };
    }

    return { workflowCompleted: false, unblockedJobs };
  }

  /**
   * Called when a critical step fails to terminate workflow run and cancel pending steps.
   */
  async onJobFailed(
    workflowRunId: string,
    failedJobId: string,
    error: unknown
  ): Promise<void> {
    const errorMsg = error instanceof Error ? error.message : String(error);

    // Cancel all remaining non-terminal jobs for this workflow
    await this.db.query(
      `UPDATE ops.jobs
       SET status = 'CANCELLED'
       WHERE workflow_run_id = $1 AND status IN ('QUEUED', 'LEASED', 'RUNNING', 'RETRYING');`,
      [workflowRunId]
    );

    // Transition workflow run to FAILED
    await this.db.query(
      `UPDATE ops.workflow_runs
       SET status = 'FAILED',
           completed_at = now()
       WHERE workflow_run_id = $1 AND status = 'RUNNING';`,
      [workflowRunId]
    );

    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: workflowRunId,
          entityKind: 'WORKFLOW_RUN',
          fromState: 'RUNNING',
          toState: 'FAILED',
          action: 'FAIL',
          transitionReason: `Workflow terminated due to critical job failure (${failedJobId}): ${errorMsg}`,
          actorRef: 'system_service:coordinator',
          correlationId: workflowRunId,
        },
        { dbClient: this.db }
      );
    } catch {
      // Ignore
    }
  }

  /**
   * Cancel an in-flight workflow run.
   */
  async cancelWorkflowRun(
    workflowRunId: string,
    reason = 'Workflow cancelled by operator',
    actorRef = 'operator'
  ): Promise<boolean> {
    const runRes = await this.db.query(
      `SELECT * FROM ops.workflow_runs WHERE workflow_run_id = $1;`,
      [workflowRunId]
    );

    if (!runRes.rows || runRes.rows.length === 0) {
      return false;
    }

    const run = runRes.rows[0];
    if (run.status === 'COMPLETED' || run.status === 'FAILED' || run.status === 'CANCELLED') {
      return false;
    }

    // Cancel queued and running jobs
    await this.db.query(
      `UPDATE ops.jobs
       SET status = 'CANCELLED'
       WHERE workflow_run_id = $1 AND status IN ('QUEUED', 'LEASED', 'RUNNING', 'RETRYING');`,
      [workflowRunId]
    );

    // Update workflow run status
    await this.db.query(
      `UPDATE ops.workflow_runs
       SET status = 'CANCELLED',
           completed_at = now()
       WHERE workflow_run_id = $1;`,
      [workflowRunId]
    );

    try {
      await LifecycleStateMachineService.transitionState(
        {
          entityRefId: workflowRunId,
          entityKind: 'WORKFLOW_RUN',
          fromState: run.status,
          toState: 'CANCELLED',
          action: 'CANCEL',
          transitionReason: reason,
          actorRef,
          correlationId: run.correlation_id,
        },
        { dbClient: this.db }
      );
    } catch {
      // Ignore
    }

    return true;
  }

  /**
   * Orchestrator Restart Recovery: Reconciles all active workflows, reaps expired leases,
   * unblocks ready steps, and prevents any accepted job from being silently lost.
   */
  async reconcileAndRecover(): Promise<{
    reapedLeasesCount: number;
    recoveredWorkflowsCount: number;
    unblockedJobsCount: number;
  }> {
    // 1. Reap any expired leases from crashed workers
    const reapedLeasesCount = await this.queueAdapter.reapExpiredLeases();

    // 2. Query all in-progress workflow runs
    const activeRunsRes = await this.db.query(
      `SELECT wr.*, wd.definition_payload
       FROM ops.workflow_runs wr
       JOIN ops.workflow_definitions wd ON wr.workflow_definition_id = wd.workflow_definition_id
       WHERE wr.status = 'RUNNING';`
    );

    let recoveredWorkflowsCount = 0;
    let unblockedJobsCount = 0;

    for (const run of activeRunsRes.rows || []) {
      recoveredWorkflowsCount++;
      const workflowRunId = run.workflow_run_id;

      // Check the latest completed job to trigger dependency evaluation
      const jobsRes = await this.db.query(
        `SELECT * FROM ops.jobs WHERE workflow_run_id = $1;`,
        [workflowRunId]
      );
      const jobs = jobsRes.rows as JobRecord[];
      const completedJobs = jobs.filter((j) => j.status === 'COMPLETED');

      for (const compJob of completedJobs) {
        const evalResult = await this.onJobCompleted(workflowRunId, compJob.job_id);
        unblockedJobsCount += evalResult.unblockedJobs.length;
      }
    }

    return {
      reapedLeasesCount,
      recoveredWorkflowsCount,
      unblockedJobsCount,
    };
  }
}
