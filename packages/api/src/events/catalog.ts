import { z } from 'zod';
import { EventEnvelope, createEventEnvelope } from './envelope.ts';

export interface EventDefinition<TPayload = unknown> {
  eventType: string;
  version: string;
  domain: 'AGENT' | 'ANALYSIS' | 'LIFECYCLE' | 'POLICY' | 'PACKAGING' | 'SHIPPING' | 'KNOWLEDGE' | 'WORKFLOW';
  description: string;
  producerService: string;
  subscriberQueues: string[];
  payloadSchema: z.ZodType<TPayload>;
}

export class EventCatalogRegistry {
  private static instance: EventCatalogRegistry;
  private readonly definitions = new Map<string, EventDefinition<any>>();

  constructor() {
    this.registerDefaults();
  }

  public static getInstance(): EventCatalogRegistry {
    if (!EventCatalogRegistry.instance) {
      EventCatalogRegistry.instance = new EventCatalogRegistry();
    }
    return EventCatalogRegistry.instance;
  }

  public register<T>(definition: EventDefinition<T>): void {
    this.definitions.set(definition.eventType, definition);
  }

  public get(eventType: string): EventDefinition<any> | undefined {
    return this.definitions.get(eventType);
  }

  public listAll(): EventDefinition<any>[] {
    return Array.from(this.definitions.values());
  }

  public validateAndWrap<T>(
    eventType: string,
    params: {
      aggregateId: string;
      aggregateType: string;
      correlationId: string;
      causationId?: string | null;
      producerService: string;
      producerVersion: string;
      payload: T;
    }
  ): EventEnvelope<T> {
    const def = this.get(eventType);
    if (!def) {
      throw new Error(`Unregistered event type: '${eventType}'`);
    }

    // Validate payload against registered Zod schema
    const validatedPayload = def.payloadSchema.parse(params.payload);

    return createEventEnvelope({
      event_type: eventType,
      schema_version: def.version,
      aggregate_id: params.aggregateId,
      aggregate_type: params.aggregateType,
      correlation_id: params.correlationId,
      causation_id: params.causationId,
      producer: {
        service_name: params.producerService,
        version: params.producerVersion,
      },
      payload: validatedPayload,
    });
  }

  private registerDefaults(): void {
    // 1. Agent Domain
    this.register({
      eventType: 'agent.registered.v1',
      version: '2.0.1',
      domain: 'AGENT',
      description: 'Emitted when a new canonical agent is created in the registry',
      producerService: 'service-agent-registry',
      subscriberQueues: ['queue:knowledge:sync', 'queue:audit:log'],
      payloadSchema: z.object({
        agentId: z.string(),
        canonicalName: z.string(),
        framework: z.string(),
        author: z.string(),
      }),
    });

    this.register({
      eventType: 'agent.version_created.v1',
      version: '2.0.1',
      domain: 'AGENT',
      description: 'Emitted when a new agent version is registered for discovery/ingestion',
      producerService: 'service-agent-registry',
      subscriberQueues: ['queue:source:ingestion', 'queue:analysis:dispatch'],
      payloadSchema: z.object({
        agentId: z.string(),
        agentVersionId: z.string(),
        versionLabel: z.string(),
        contentHash: z.string(),
      }),
    });

    // 2. Analysis Domain
    this.register({
      eventType: 'analysis.requested.v1',
      version: '2.0.1',
      domain: 'ANALYSIS',
      description: 'Emitted to trigger multi-phase intelligence analysis (static, taint, reachability, scoring)',
      producerService: 'service-workflow',
      subscriberQueues: ['queue:analysis:syntax', 'queue:analysis:taint'],
      payloadSchema: z.object({
        analysisRunId: z.string(),
        agentVersionId: z.string(),
        pipelineVersion: z.string(),
      }),
    });

    this.register({
      eventType: 'analysis.completed.v1',
      version: '2.0.1',
      domain: 'ANALYSIS',
      description: 'Emitted when all analysis stages complete and intelligence claims are established',
      producerService: 'service-analysis',
      subscriberQueues: ['queue:validation:run', 'queue:knowledge:projection'],
      payloadSchema: z.object({
        analysisRunId: z.string(),
        agentVersionId: z.string(),
        findingsCount: z.number(),
        claimsCount: z.number(),
        riskScore: z.number(),
        riskBand: z.string(),
        status: z.enum(['COMPLETED', 'PARTIAL']),
      }),
    });

    // 3. Lifecycle & Validation Domain
    this.register({
      eventType: 'validation.evaluated.v1',
      version: '2.0.1',
      domain: 'LIFECYCLE',
      description: 'Emitted when deterministic validation test suite concludes on an agent version',
      producerService: 'service-lifecycle',
      subscriberQueues: ['queue:policy:eval', 'queue:audit:log'],
      payloadSchema: z.object({
        validationRunId: z.string(),
        agentVersionId: z.string(),
        verdict: z.enum(['APPROVED_FOR_RELEASE', 'REJECTED_REGRESSION', 'INCONCLUSIVE']),
        testsTotal: z.number(),
        testsPassed: z.number(),
      }),
    });

    // 4. Policy Gate Domain
    this.register({
      eventType: 'policy.gate_evaluated.v1',
      version: '2.0.1',
      domain: 'POLICY',
      description: 'Emitted when packaging policy gate evaluates release readiness',
      producerService: 'service-policy',
      subscriberQueues: ['queue:packaging:signing', 'queue:audit:log'],
      payloadSchema: z.object({
        packageId: z.string(),
        agentVersionId: z.string(),
        policyOutcome: z.enum(['ALLOW', 'ALLOW_WITH_WARNING', 'REQUIRE_REVIEW', 'RESTRICT', 'QUARANTINE', 'DENY_SHIPPING']),
        allowed: z.boolean(),
        blockers: z.array(z.string()),
      }),
    });

    // 5. Packaging & Shipping Domain
    this.register({
      eventType: 'package.signed.v1',
      version: '2.0.1',
      domain: 'PACKAGING',
      description: 'Emitted when KMS signs an immutable package bundle with Ed25519',
      producerService: 'service-packaging',
      subscriberQueues: ['queue:shipping:delivery', 'queue:audit:log'],
      payloadSchema: z.object({
        packageId: z.string(),
        manifestHash: z.string(),
        keyId: z.string(),
        signatureScheme: z.string(),
      }),
    });

    this.register({
      eventType: 'package.shipped.v1',
      version: '2.0.1',
      domain: 'SHIPPING',
      description: 'Emitted when a signed package bundle is successfully shipped to a target registry/bucket',
      producerService: 'service-shipping',
      subscriberQueues: ['queue:audit:log', 'queue:notifications:dispatch'],
      payloadSchema: z.object({
        shipmentId: z.string(),
        packageId: z.string(),
        targetType: z.string(),
        targetLocator: z.string(),
        receiptLocator: z.string(),
        transferSizeBytes: z.number(),
      }),
    });
  }
}
