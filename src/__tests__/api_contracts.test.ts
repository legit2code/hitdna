import { describe, it, expect, beforeEach } from 'vitest';
import { 
  ApplicationApiRouter, 
  ApiRequestContext,
  IdempotencyManager,
  EventCatalogRegistry,
  QueueOwnershipRegistry,
  OpenApiGenerator,
  createSuccessEnvelope,
  createErrorEnvelope,
  mapErrorToEnvelope,
  ValidationError,
  ConflictError,
  PolicyBlockedError,
  DependencyFailureError,
  registerFastifyApiRoutes
} from '@caim/api';
import { SecurityClassificationRank } from '@caim/auth';
import { createTestRequestContext } from './helpers/test-auth-context.ts';

describe('P27 — Public/Internal API, Events & Queue Contract Completion', () => {
  let router: ApplicationApiRouter;

  beforeEach(() => {
    IdempotencyManager.getInstance().clear();
    const rawRouter = new ApplicationApiRouter();
    router = new Proxy(rawRouter, {
      get(target, prop, receiver) {
        const orig = Reflect.get(target, prop, receiver);
        if (typeof orig === 'function' && !['getOpenApi', 'getEventCatalog', 'getQueueRegistry'].includes(String(prop))) {
          return function(req: any, ...args: any[]) {
            const ctx = req ? createTestRequestContext(req) : req;
            return (orig as any).call(target, ctx, ...args);
          };
        }
        return orig;
      }
    });
  });

  // 1. Success & Error Envelopes
  describe('Standard Success & Error Envelopes', () => {
    it('generates compliant success envelope with required metadata', () => {
      const envelope = createSuccessEnvelope({ message: 'Operation succeeded' }, { page: 1, limit: 20, total: 100 });
      expect(envelope.success).toBe(true);
      expect(envelope.data).toEqual({ message: 'Operation succeeded' });
      expect(envelope.meta.request_id).toMatch(/^req-/);
      expect(envelope.meta.timestamp).toBeDefined();
      expect(envelope.meta.page).toBe(1);
      expect(envelope.meta.limit).toBe(20);
      expect(envelope.meta.total).toBe(100);
    });

    it('generates compliant sanitized error envelope with retryability taxonomy', () => {
      const envelope = createErrorEnvelope({
        code: 'DEPENDENCY_FAILURE',
        message: 'Downstream AST parser timed out',
        details: { worker: 'node-02' },
        retryable: true,
        retry_after_ms: 1500,
      });

      expect(envelope.success).toBe(false);
      expect(envelope.error.code).toBe('DEPENDENCY_FAILURE');
      expect(envelope.error.message).toBe('Downstream AST parser timed out');
      expect(envelope.error.retryable).toBe(true);
      expect(envelope.error.retry_after_ms).toBe(1500);
      expect(envelope.error.request_id).toMatch(/^req-/);
      expect(envelope.error.timestamp).toBeDefined();
    });
  });

  // 2. Health & Readiness
  describe('System Health & Readiness Contracts', () => {
    it('returns valid liveness health check', async () => {
      const res = await router.getHealth({ headers: {} });
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      if (res.body.success) {
        const data = res.body.data as any;
        expect(data.status).toBe('UP');
        expect(data.uptime_seconds).toBeGreaterThanOrEqual(0);
      }
    });

    it('returns complete subsystem readiness check (DB, Queues, KMS, Catalog)', async () => {
      const res = await router.getReadiness({ headers: {} });
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      if (res.body.success) {
        const data = res.body.data as any;
        expect(data.status).toBe('READY');
        expect(data.checks.database_pool.status).toBe('HEALTHY');
        expect(data.checks.workflow_queue.status).toBe('HEALTHY');
        expect(data.checks.kms_signing_enclave.status).toBe('HEALTHY');
        expect(data.checks.event_catalog.status).toBe('HEALTHY');
        expect(data.checks.queue_registry.status).toBe('HEALTHY');
      }
    });
  });

  // 3. Authentication & Authorization Gates
  describe('Authentication & Authorization Gate Enforcement', () => {
    it('rejects unauthenticated requests on protected mutation endpoints (401)', async () => {
      const res = await router.createAgent({
        headers: {}, // Anonymous
        body: { agentId: 'test-agent', canonicalName: 'Test' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      if (!res.body.success) {
        const err = (res.body as any).error;
        expect(err.code).toBe('UNAUTHENTICATED');
        expect(err.retryable).toBe(false);
      }
    });

    it('rejects authenticated principals with insufficient roles (403)', async () => {
      const res = await router.createAgent({
        headers: {
          'x-principal-id': 'usr-regular',
          'x-principal-roles': 'user', // Does not have analyst or admin
        },
        body: { agentId: 'test-agent', canonicalName: 'Test' },
      });

      expect(res.statusCode).toBe(403);
      expect(res.body.success).toBe(false);
      if (!res.body.success) {
        const err = (res.body as any).error;
        expect(err.code).toBe('FORBIDDEN');
        expect(err.retryable).toBe(false);
      }
    });

    it('permits authorized principals with required roles', async () => {
      const res = await router.createAgent({
        headers: {
          'x-principal-id': 'usr-analyst-1',
          'x-principal-roles': 'analyst',
        },
        body: { agentId: 'agent-custom-security', canonicalName: 'Security Analyzer' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      if (res.body.success) {
        const data = res.body.data as any;
        expect(data.agent_id).toBe('agent-custom-security');
      }
    });
  });

  // 4. Schema Validation & Safe Error Details
  describe('Request Schema Validation & Safe Error Mapping', () => {
    it('returns structured validation breakdown without leaking internals (400)', async () => {
      const res = await router.createAgent({
        headers: { 'x-principal-roles': 'admin' },
        body: { canonicalName: '' }, // Missing agentId and empty canonicalName
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      if (!res.body.success) {
        const err = (res.body as any).error;
        expect(err.code).toBe('VALIDATION_FAILED');
        expect(Array.isArray(err.details)).toBe(true);
      }
    });
  });

  // 5. Command Idempotency
  describe('Command Idempotency & Conflict Controls', () => {
    it('replays identical cached response on duplicate idempotent requests', async () => {
      const req: ApiRequestContext = {
        headers: {
          'x-principal-id': 'usr-approver-01',
          'x-principal-roles': 'release_approver',
          'idempotency-key': 'idem-signoff-7788',
        },
        body: {
          agentVersionId: 'av-fin-v100',
          decision: 'APPROVED',
          rationale: 'Security suite passed all boundary checks',
        },
      };

      // First call
      const res1 = await router.submitApproval(req);
      expect(res1.statusCode).toBe(201);
      expect(res1.body.success).toBe(true);
      const originalApprovalId = res1.body.success ? (res1.body.data as any).approval_id : null;

      // Replay call with exact same idempotency key
      const res2 = await router.submitApproval(req);
      expect(res2.statusCode).toBe(201);
      expect(res2.body.success).toBe(true);
      expect(res2.headers?.['X-Idempotency-Replayed']).toBe('true');
      if (res2.body.success) {
        expect((res2.body.data as any).approval_id).toBe(originalApprovalId);
        expect(res2.body.meta.idempotency_replayed).toBe(true);
      }
    });

    it('rejects concurrent executions with same in-flight idempotency key (409 Conflict)', async () => {
      const manager = IdempotencyManager.getInstance();
      manager.acquire('idem-in-flight-99', 'usr-test');

      const res = await router.createAgent({
        headers: {
          'x-principal-id': 'usr-test',
          'x-principal-roles': 'admin',
          'idempotency-key': 'idem-in-flight-99',
        },
        body: { agentId: 'agent-conflict', canonicalName: 'Agent Conflict' },
      });

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
      if (!res.body.success) {
        const err = (res.body as any).error;
        expect(err.code).toBe('CONFLICT_IDEMPOTENCY');
      }
    });
  });

  // 6. Retryable Dependency Failure
  describe('Retryable Dependency Failure Handling', () => {
    it('returns retryable 503 with retry_after_ms on downstream worker timeout', async () => {
      const res = await router.createAnalysisRun({
        headers: { 'x-principal-roles': 'analyst' },
        body: {
          agentVersionId: 'av-fin-v100',
          simulateDependencyFailure: true,
        },
      });

      expect(res.statusCode).toBe(503);
      expect(res.body.success).toBe(false);
      if (!res.body.success) {
        const err = (res.body as any).error;
        expect(err.code).toBe('DEPENDENCY_FAILURE');
        expect(err.retryable).toBe(true);
        expect(err.retry_after_ms).toBe(2000);
      }
    });
  });

  // 7. Partial Analysis & Policy Gate Block
  describe('Partial Analysis & Policy Gate Block Contracts', () => {
    it('handles partial analysis with explicit warning metadata', async () => {
      const res = await router.createAnalysisRun({
        headers: { 'x-principal-roles': 'analyst' },
        body: {
          agentVersionId: 'av-fin-v100',
          simulatePartial: true,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      if (res.body.success) {
        const data = res.body.data as any;
        expect(data.status).toBe('PARTIAL');
        expect(res.body.meta.warning).toContain('PARTIAL stage coverage');
      }
    });

    it('returns 422 Policy Block when gate denies release readiness', async () => {
      const res = await router.evaluatePolicyGate({
        headers: { 'x-principal-roles': 'analyst' },
        body: {
          agentVersionId: 'av-fin-v100',
          forceBlock: true,
        },
      });

      expect(res.statusCode).toBe(422);
      expect(res.body.success).toBe(false);
      if (!res.body.success) {
        const err = (res.body as any).error;
        expect(err.code).toBe('POLICY_BLOCKED');
        expect(err.retryable).toBe(false);
      }
    });
  });

  // 8. Pagination & Filtering
  describe('Pagination & Filtering Conventions', () => {
    it('paginates and filters agent listings correctly', async () => {
      const res = await router.listAgents({
        headers: {},
        query: { page: 1, limit: 1, sort_by: 'canonical_name', sort_order: 'asc' },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      if (res.body.success) {
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(res.body.meta.page).toBe(1);
        expect(res.body.meta.limit).toBe(1);
        expect(res.body.meta.total).toBeGreaterThanOrEqual(1);
      }
    });
  });

  // 9. OpenAPI 3.1 Document Generation
  describe('OpenAPI 3.1 Specification Generation', () => {
    it('generates valid OpenAPI 3.1 document from contracts', async () => {
      const res = await router.getOpenApiSpec({ headers: {} });
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      if (res.body.success) {
        const spec = res.body.data as any;
        expect(spec.openapi).toBe('3.1.0');
        expect(spec.info.title).toContain('CAIM Enterprise');
        expect(spec.paths['/agents']).toBeDefined();
        expect(spec.paths['/health']).toBeDefined();
        expect(spec.paths['/ready']).toBeDefined();
        expect(spec.components.securitySchemes.BearerAuth).toBeDefined();
      }
    });
  });

  // 10. Event Catalog & Queue Ownership Registry
  describe('Event Catalog & Queue Ownership Registry', () => {
    it('validates and wraps domain events using registered Zod schemas', () => {
      const catalog = EventCatalogRegistry.getInstance();
      const event = catalog.validateAndWrap('agent.registered.v1', {
        aggregateId: 'agent-123',
        aggregateType: 'AGENT',
        correlationId: 'corr-001',
        producerService: 'service-agent-registry',
        producerVersion: '2.0.1',
        payload: {
          agentId: 'agent-123',
          canonicalName: 'Test Agent',
          framework: 'TypeScript',
          author: 'Security Team',
        },
      });

      expect(event.event_type).toBe('agent.registered.v1');
      expect(event.schema_version).toBe('2.0.1');
      expect(event.payload.canonicalName).toBe('Test Agent');
    });

    it('maintains queue ownership mappings and validates job payloads', () => {
      const registry = QueueOwnershipRegistry.getInstance();
      const queue = registry.get('queue:analysis:syntax');
      expect(queue).toBeDefined();
      expect(queue?.owningService).toBe('service-analysis');
      expect(queue?.concurrencyLimit).toBe(16);

      const validPayload = registry.validatePayload('queue:analysis:syntax', {
        analysisRunId: 'ar-100',
        agentVersionId: 'av-100',
      });
      expect(validPayload.valid).toBe(true);

      const invalidPayload = registry.validatePayload('queue:analysis:syntax', {
        analysisRunId: 12345, // invalid type
      });
      expect(invalidPayload.valid).toBe(false);
    });
  });

  // 11. Fastify Adapter Interface
  describe('Fastify Adapter Interface', () => {
    it('registers Fastify route handlers with identical contract outcomes', async () => {
      const routeMap = new Map<string, Function>();
      const mockFastify = {
        get: (path: string, handler: Function) => routeMap.set(`GET ${path}`, handler),
        post: (path: string, handler: Function) => routeMap.set(`POST ${path}`, handler),
      };

      registerFastifyApiRoutes(mockFastify as any, router);

      expect(routeMap.has('GET /api/v1/health')).toBe(true);
      expect(routeMap.has('GET /api/v1/ready')).toBe(true);
      expect(routeMap.has('GET /api/v1/openapi.json')).toBe(true);
      expect(routeMap.has('POST /api/v1/agents')).toBe(true);

      // Invoke Fastify health handler
      const healthHandler = routeMap.get('GET /api/v1/health')!;
      let replyData: any;
      let replyStatus = 0;
      const mockReply = {
        code: (code: number) => {
          replyStatus = code;
          return {
            send: (body: any) => {
              replyData = body;
              return body;
            },
          };
        },
      };

      await healthHandler({ headers: {} }, mockReply);
      expect(replyStatus).toBe(200);
      expect(replyData.success).toBe(true);
      expect(replyData.data.status).toBe('UP');
    });
  });
});
