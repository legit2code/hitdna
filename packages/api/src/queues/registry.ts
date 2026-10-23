import { z } from 'zod';

export interface RetryPolicy {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  multiplier: number;
  enableJitter: boolean;
}

export interface QueueOwnershipRecord {
  queueKey: string;
  domain: string;
  owningService: string;
  description: string;
  concurrencyLimit: number;
  maxLeaseDurationMs: number;
  retryPolicy: RetryPolicy;
  deadLetterQueueKey: string;
  payloadSchema: z.ZodType<any>;
}

export class QueueOwnershipRegistry {
  private static instance: QueueOwnershipRegistry;
  private readonly queues = new Map<string, QueueOwnershipRecord>();

  constructor() {
    this.registerDefaults();
  }

  public static getInstance(): QueueOwnershipRegistry {
    if (!QueueOwnershipRegistry.instance) {
      QueueOwnershipRegistry.instance = new QueueOwnershipRegistry();
    }
    return QueueOwnershipRegistry.instance;
  }

  public register(queue: QueueOwnershipRecord): void {
    this.queues.set(queue.queueKey, queue);
  }

  public get(queueKey: string): QueueOwnershipRecord | undefined {
    return this.queues.get(queueKey);
  }

  public listAll(): QueueOwnershipRecord[] {
    return Array.from(this.queues.values());
  }

  public validatePayload(queueKey: string, payload: unknown): { valid: boolean; errors?: string[] } {
    const q = this.get(queueKey);
    if (!q) {
      return { valid: false, errors: [`Unregistered queue key: '${queueKey}'`] };
    }
    const result = q.payloadSchema.safeParse(payload);
    if (!result.success) {
      return {
        valid: false,
        errors: result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
      };
    }
    return { valid: true };
  }

  private registerDefaults(): void {
    const defaultRetry: RetryPolicy = {
      maxAttempts: 3,
      initialDelayMs: 1000,
      maxDelayMs: 30000,
      multiplier: 2,
      enableJitter: true,
    };

    this.register({
      queueKey: 'queue:source:ingestion',
      domain: 'SOURCE',
      owningService: 'service-source',
      description: 'Ingests agent source bundles and calculates initial content hashes',
      concurrencyLimit: 8,
      maxLeaseDurationMs: 60000,
      retryPolicy: defaultRetry,
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        agentVersionId: z.string(),
        sourceLocator: z.string().optional(),
      }),
    });

    this.register({
      queueKey: 'queue:analysis:syntax',
      domain: 'ANALYSIS',
      owningService: 'service-analysis',
      description: 'Executes AST extraction and static syntax intelligence',
      concurrencyLimit: 16,
      maxLeaseDurationMs: 45000,
      retryPolicy: defaultRetry,
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        analysisRunId: z.string(),
        agentVersionId: z.string(),
      }),
    });

    this.register({
      queueKey: 'queue:analysis:taint',
      domain: 'ANALYSIS',
      owningService: 'service-analysis',
      description: 'Executes interprocedural taint flow analysis and sink reachability',
      concurrencyLimit: 12,
      maxLeaseDurationMs: 90000,
      retryPolicy: defaultRetry,
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        analysisRunId: z.string(),
        agentVersionId: z.string(),
      }),
    });

    this.register({
      queueKey: 'queue:validation:run',
      domain: 'LIFECYCLE',
      owningService: 'service-lifecycle',
      description: 'Executes deterministic test plans in isolated test runtime',
      concurrencyLimit: 6,
      maxLeaseDurationMs: 120000,
      retryPolicy: defaultRetry,
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        validationPlanId: z.string(),
        agentVersionId: z.string(),
      }),
    });

    this.register({
      queueKey: 'queue:packaging:signing',
      domain: 'PACKAGING',
      owningService: 'service-packaging',
      description: 'Assembles deterministic Merkle deliverables and invokes KMS Ed25519 signing boundary',
      concurrencyLimit: 4,
      maxLeaseDurationMs: 30000,
      retryPolicy: { ...defaultRetry, maxAttempts: 2 },
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        packageId: z.string(),
        agentVersionId: z.string(),
      }),
    });

    this.register({
      queueKey: 'queue:shipping:delivery',
      domain: 'SHIPPING',
      owningService: 'service-shipping',
      description: 'Dispatches signed package bundles to OCI / S3 / Webhook targets and writes delivery receipts',
      concurrencyLimit: 8,
      maxLeaseDurationMs: 60000,
      retryPolicy: defaultRetry,
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        packageId: z.string(),
        targetType: z.string(),
        targetLocator: z.string(),
      }),
    });

    this.register({
      queueKey: 'queue:dlq:dead-letter',
      domain: 'WORKFLOW',
      owningService: 'service-workflow',
      description: 'Terminal holding queue for poison-pill or exhausted retry failures',
      concurrencyLimit: 2,
      maxLeaseDurationMs: 300000,
      retryPolicy: { maxAttempts: 1, initialDelayMs: 0, maxDelayMs: 0, multiplier: 1, enableJitter: false },
      deadLetterQueueKey: 'queue:dlq:dead-letter',
      payloadSchema: z.object({
        jobId: z.string(),
        finalFailureCode: z.string(),
      }),
    });
  }
}
