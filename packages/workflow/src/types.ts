import { LifecycleEntityKind } from '../../lifecycle/src/index.ts';

export type JobStatus =
  | 'QUEUED'
  | 'LEASED'
  | 'RUNNING'
  | 'RETRYING'
  | 'COMPLETED'
  | 'FAILED'
  | 'DEAD_LETTER'
  | 'CANCELLED';

export type WorkflowRunStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'PAUSED'
  | 'AWAITING_APPROVAL'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type ErrorClassification =
  | 'TRANSIENT'
  | 'PERMANENT'
  | 'RATE_LIMITED'
  | 'POISON_PILL'
  | 'CANCELLED';

export type OutboxEventStatus = 'PENDING' | 'DELIVERED' | 'FAILED' | 'DEAD_LETTER';
export type OutboxDeliveryStatus = 'PENDING' | 'DELIVERED' | 'FAILED';
export type DeadLetterResolutionState = 'UNRESOLVED' | 'REPLAYED' | 'DISCARDED' | 'RESOLVED_MANUALLY';

export interface CorrelationContext {
  correlationId: string;
  causationId?: string;
  traceId?: string;
}

export interface DurableReferencePayload {
  jobType: string;
  entityRefId?: string;
  workflowRunId?: string;
  stageRunId?: string;
  analysisRunId?: string;
  agentVersionId?: string;
  storageLocator?: string;
  contentHash?: string;
  parameters?: Record<string, unknown>;
}

export interface JobRecord<T = DurableReferencePayload> {
  job_id: string;
  workflow_run_id: string | null;
  stage_run_id: string | null;
  queue_key: string;
  idempotency_key: string;
  priority: number;
  status: JobStatus;
  next_attempt_at: string;
  payload: T;
  created_at: string;
}

export interface JobAttemptRecord {
  job_attempt_id: string;
  job_id: string;
  attempt_no: number;
  worker_id: string | null;
  leased_at: string | null;
  lease_expires_at: string | null;
  completed_at: string | null;
  failure_class: string | null;
  failure_code: string | null;
  error_message: string | null;
  created_at: string;
}

export interface DeadLetterJobRecord {
  dead_letter_job_id: string;
  job_id: string;
  final_failure_code: string;
  payload_snapshot_locator: string | null;
  dead_lettered_at: string;
  resolution_state: DeadLetterResolutionState;
}

export interface OutboxEventRecord<T = unknown> {
  event_id: string;
  event_type: string;
  aggregate_entity_ref_id: string | null;
  payload: T;
  schema_version: string;
  correlation_id: string;
  causation_id: string | null;
  status: OutboxEventStatus;
  occurred_at: string;
  published_at: string | null;
}

export interface OutboxDeliveryRecord {
  delivery_id: string;
  event_id: string;
  target_subscriber: string;
  status: OutboxDeliveryStatus;
  attempt_count: number;
  delivered_at: string | null;
  last_error: string | null;
}

export interface WorkflowDefinitionRecord {
  workflow_definition_id: string;
  workflow_key: string;
  version: string;
  status: 'ACTIVE' | 'DEPRECATED' | 'DRAFT';
  definition_payload: WorkflowDefinitionPayload;
  created_at: string;
}

export interface WorkflowRunRecord {
  workflow_run_id: string;
  workflow_definition_id: string;
  agent_id: string | null;
  agent_version_id: string | null;
  analysis_run_id: string | null;
  status: WorkflowRunStatus;
  correlation_id: string;
  started_at: string;
  completed_at: string | null;
  created_at: string;
}

export interface WorkflowStepDefinition {
  stepKey: string;
  jobType: string;
  queueKey: string;
  dependsOn?: string[];
  priority?: number;
  timeoutMs?: number;
  retryPolicy?: RetryPolicy;
  payloadFactory?: (context: WorkflowRunContext) => DurableReferencePayload;
}

export interface WorkflowDefinitionPayload {
  name: string;
  description?: string;
  steps: WorkflowStepDefinition[];
}

export interface WorkflowRunContext {
  workflowRunId: string;
  workflowKey: string;
  correlationId: string;
  causationId?: string;
  agentId?: string;
  agentVersionId?: string;
  analysisRunId?: string;
  stepResults: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface RetryPolicy {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  multiplier: number;
  enableJitter: boolean;
  retryableErrorClasses?: string[];
  nonRetryableErrorCodes?: string[];
}

export interface EnqueueJobOptions {
  workflowRunId?: string;
  stageRunId?: string;
  idempotencyKey?: string;
  priority?: number;
  delayMs?: number;
  correlationContext?: CorrelationContext;
}

export interface DequeueOptions {
  leaseDurationMs?: number;
  limit?: number;
}

export interface QueueMessage<T = DurableReferencePayload> {
  messageId: string;
  jobId: string;
  queueKey: string;
  payload: T;
  attemptNo: number;
  leaseExpiresAt: string;
  workerId: string;
  correlationContext: CorrelationContext;
  job: JobRecord<T>;
}

export interface QueueAdapter {
  enqueue<T = DurableReferencePayload>(
    queueKey: string,
    payload: T,
    options?: EnqueueJobOptions
  ): Promise<JobRecord<T>>;
  dequeue<T = DurableReferencePayload>(
    queueKey: string,
    workerId: string,
    options?: DequeueOptions
  ): Promise<QueueMessage<T> | null>;
  extendLease(
    jobId: string,
    attemptNo: number,
    workerId: string,
    extendDurationMs: number
  ): Promise<boolean>;
  ack(jobId: string, attemptNo: number, workerId: string, result?: unknown): Promise<boolean>;
  nack(
    jobId: string,
    attemptNo: number,
    workerId: string,
    error: unknown,
    delayMs?: number
  ): Promise<boolean>;
  deadLetter(
    jobId: string,
    attemptNo: number,
    workerId: string,
    finalFailureCode: string,
    errorMessage?: string,
    locator?: string
  ): Promise<boolean>;
}

export interface WorkerContext {
  jobId: string;
  attemptNo: number;
  workerId: string;
  correlationId: string;
  causationId?: string;
  heartbeat: () => Promise<boolean>;
  isCancelled: () => Promise<boolean>;
  logger: {
    info: (msg: string, meta?: unknown) => void;
    warn: (msg: string, meta?: unknown) => void;
    error: (msg: string, meta?: unknown) => void;
  };
}

export type WorkerHandler<T = DurableReferencePayload, R = unknown> = (
  payload: T,
  context: WorkerContext
) => Promise<R>;

export interface WorkerRegistrationOptions {
  queueKey?: string;
  concurrency?: number;
  leaseDurationMs?: number;
  heartbeatIntervalMs?: number;
  pollIntervalMs?: number;
  retryPolicy?: RetryPolicy;
}
