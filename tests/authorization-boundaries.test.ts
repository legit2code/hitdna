/**
 * PROMPT 5 — AUTHORIZATION BOUNDARIES REPAIR TEST SUITE
 *
 * Verifies server-side authorization defects independently from authentication:
 * 1. Break-Glass Operation (Part A):
 *    - Anonymous break-glass denied (401 / UnauthorizedAccessError)
 *    - Ordinary user break-glass denied (403 / UnauthorizedAccessError)
 *    - Authorized privileged user allowed (200 / execution success, reports MFA status)
 * 2. Worker Management (Part B):
 *    - Normal user worker management denied (403 Forbidden)
 *    - Operator/Admin worker management allowed (200 OK)
 *    - Narrow capability ('worker.manage') allowed (200 OK)
 * 3. Tenant Invitations (Part C):
 *    - Forged invitation denied
 *    - Expired invitation denied
 *    - Valid invitation accepted (cryptographic and opaque)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import express, { Request, Response, NextFunction } from 'express';
import { Server } from 'http';
import { 
  AuthService, 
  CapabilityGrantService, 
  PlatformAuditService, 
  createServerAuthHelper,
  executeWithAuditedOverride,
  UnauthorizedAccessError,
  tenantInvitationManager,
  signAccessToken,
  createAnonymousPrincipal,
  PrincipalContext,
  BusinessRole,
  getMfaSecurityStatus
} from '@caim/auth';
import { 
  requireProductUserAccess, 
  requireWorkerManagementAccess 
} from '../apps/server/middleware/security.ts';
import { registerAdminRoutes } from '../apps/server/routes/admin.routes.ts';
import { registerWorkersRoutes } from '../apps/server/routes/workers.routes.ts';
import { registerAuthRoutes } from '../apps/server/routes/auth.routes.ts';
import { registerDiscoveryRoutes } from '../apps/server/routes/discovery.routes.ts';

describe('Prompt 5 — Server-Side Authorization Boundaries Repair', () => {
  let app: express.Application;
  let server: Server;
  let baseUrl: string;
  let authService: AuthService;
  let platformAuditService: PlatformAuditService;
  let capabilityGrantService: CapabilityGrantService;

  // Mock scheduled worker map
  const mockScheduledWorkerMap = new Map<string, any>();
  const mockWorker = {
    name: 'test-scanner-worker',
    getStatus: () => ({ name: 'test-scanner-worker', isRunning: false, intervalMs: 5000 }),
    start: () => {},
    stop: () => {},
    runCycle: async () => ({ scanned: 10 }),
  };
  mockScheduledWorkerMap.set('test-worker-1', mockWorker);

  const mockContainer: any = {
    authService: null,
    platformAuditService: null,
    capabilityGrantService: null,
    authHelper: null,
    autonomousWorker: { 
      getStatus: () => ({ running: true }),
      runDiscoveryCycle: async () => ({ scanned: 5 }),
    },
    scheduledWorkerMap: mockScheduledWorkerMap,
    rateLimiterEngine: { checkRateLimit: () => ({ allowed: true }) },
    csrfProtectionEngine: { validateCsrfToken: () => true },
    sourceRegistry: {},
    discoveryEngine: {},
    braveSearchProvider: {},
    queryStrategyRegistry: {},
    freshnessScheduler: {},
    artifactClassifier: {},
    identityResolver: {},
    manualReviewQueue: {},
    recursiveExpansionEngine: {},
    discoveryLineageService: {},
    handleProductDiscoveryRun: (_req: any, res: any) => res.json({ success: true }),
    handleReportDiscoveryCycle: (_req: any, res: any) => res.json({ success: true }),
    config: { env: 'test' },
  };

  beforeAll(async () => {
    authService = new AuthService();
    platformAuditService = new PlatformAuditService({
      query: async () => ({ rows: [] }),
    });
    capabilityGrantService = new CapabilityGrantService();
    const authHelper = createServerAuthHelper();

    mockContainer.authService = authService;
    mockContainer.platformAuditService = platformAuditService;
    mockContainer.capabilityGrantService = capabilityGrantService;
    mockContainer.authHelper = authHelper;

    app = express();
    app.use(express.json());

    // Middleware to extract principal from Authorization Bearer token
    app.use(async (req: Request, _res: Response, next: NextFunction) => {
      try {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          (req as any).principal = await authHelper.authenticateRequest(req.headers as any);
        } else {
          (req as any).principal = {
            principal_id: 'anonymous',
            is_authenticated: false,
            roles: ['anonymous'],
            tenant_id: null,
            accessible_scope_ids: [],
            max_classification_rank: 0,
            is_override_active: false,
            grants: [],
          };
        }
      } catch {
        (req as any).principal = {
          principal_id: 'anonymous',
          is_authenticated: false,
          roles: ['anonymous'],
          tenant_id: null,
          accessible_scope_ids: [],
          max_classification_rank: 0,
          is_override_active: false,
          grants: [],
        };
      }
      next();
    });

    // Mount relevant routes
    registerAdminRoutes(app as any, mockContainer);
    registerWorkersRoutes(app as any, mockContainer);
    registerAuthRoutes(app as any, mockContainer);
    registerDiscoveryRoutes(app as any, mockContainer);

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  beforeEach(() => {
    AuthService.clearInMemoryPrincipals();
    AuthService.seedDevelopmentPrincipals();
    tenantInvitationManager.resetForTesting();
  });

  // =========================================================================
  // PART A — BREAK GLASS TESTS
  // =========================================================================

  describe('Part A — Break Glass Authorization Controls', () => {
    it('anonymous break-glass denied: direct execution with createAnonymousPrincipal() throws UnauthorizedAccessError', async () => {
      const anonPrincipal = createAnonymousPrincipal();

      const dummySink = { logAuditEvent: async () => {} };

      await expect(
        executeWithAuditedOverride(
          anonPrincipal,
          {
            actor_id: 'anonymous',
            action: 'VAULT_ACCESS',
            target_resource_id: 'res-1',
            target_resource_type: 'policy',
            justification: 'Emergency production outage recovery required',
            correlation_id: 'corr-001',
          },
          dummySink,
          async () => 'secret_value'
        )
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('anonymous break-glass denied: anonymous context object throws UnauthorizedAccessError', async () => {
      const anonymousContext: PrincipalContext = {
        principal_id: 'anonymous',
        is_authenticated: false,
        is_service: false,
        roles: ['anonymous'],
        grants: [],
        tenant_id: null,
        accessible_scope_ids: [],
        max_classification_rank: 0,
      };

      const dummySink = { logAuditEvent: async () => {} };

      await expect(
        executeWithAuditedOverride(
          anonymousContext,
          {
            actor_id: 'anonymous',
            action: 'VAULT_ACCESS',
            target_resource_id: 'res-1',
            target_resource_type: 'policy',
            justification: 'Emergency production outage recovery required',
            correlation_id: 'corr-001b',
          },
          dummySink,
          async () => 'secret_value'
        )
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('anonymous break-glass denied: POST /api/v1/audit/override returns 401 Unauthorized', async () => {
      const res = await fetch(`${baseUrl}/api/v1/audit/override`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'VAULT_ACCESS',
          justification: 'Emergency production outage recovery justification here',
          target_resource_id: 'res_vault_override',
        }),
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toMatch(/Unauthorized/i);
    });

    it('ordinary user break-glass denied: direct execution throws UnauthorizedAccessError', async () => {
      const normalUserContext: PrincipalContext = {
        principal_id: 'user-bob-01',
        is_authenticated: true,
        is_service: false,
        roles: ['user'],
        grants: [],
        tenant_id: 'tenant-001',
        accessible_scope_ids: ['scope-1'],
        max_classification_rank: 1,
      };

      const dummySink = { logAuditEvent: async () => {} };

      await expect(
        executeWithAuditedOverride(
          normalUserContext,
          {
            actor_id: 'user-bob-01',
            action: 'VAULT_ACCESS',
            target_resource_id: 'res-1',
            target_resource_type: 'policy',
            justification: 'Emergency production outage recovery required',
            correlation_id: 'corr-002',
          },
          dummySink,
          async () => 'secret_value'
        )
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('ordinary user break-glass denied: POST /api/v1/audit/override returns 403 Forbidden', async () => {
      const userToken = signAccessToken({
        principal_id: 'user-bob-01',
        email: 'bob@example.com',
        roles: ['user'],
        tenant_id: 'tenant-001',
      });

      const res = await fetch(`${baseUrl}/api/v1/audit/override`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          action: 'VAULT_ACCESS',
          justification: 'Emergency production outage recovery justification here',
          target_resource_id: 'res_vault_override',
        }),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toMatch(/Access Denied/i);
    });

    it('break-glass denied if justification is missing or insufficient (<10 chars)', async () => {
      const operatorToken = signAccessToken({
        principal_id: 'operator-alice-01',
        email: 'alice@caim.internal',
        roles: ['operator'],
        tenant_id: 'tenant-001',
      });

      const res = await fetch(`${baseUrl}/api/v1/audit/override`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
        body: JSON.stringify({
          action: 'VAULT_ACCESS',
          justification: 'too short', // < 10 chars
          target_resource_id: 'res_vault_override',
        }),
      });

      expect([400, 403]).toContain(res.status);
      const body = await res.json();
      expect(body.error).toMatch(/justification/i);
    });

    it('authorized privileged user allowed: operator or admin break-glass succeeds and reports MFA status', async () => {
      const operatorToken = signAccessToken({
        principal_id: 'operator-alice-01',
        email: 'alice@caim.internal',
        roles: ['operator'],
        tenant_id: 'tenant-001',
      });

      const res = await fetch(`${baseUrl}/api/v1/audit/override`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
        body: JSON.stringify({
          action: 'MANUAL_INSPECTION',
          justification: 'Emergency investigation of suspicious transaction batch',
          target_resource_id: 'res_vault_override',
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.status).toBe('OVERRIDE_EXECUTED');
      expect(body.elevated_actor).toBe('operator-alice-01');
      expect(body.operation_status).toBe('OPERATION_STUBBED_SAFE_INSPECTION');
      expect(body.underlying_vault_operation).toBe('NOT_EXECUTED_STUB');
      // Must explicitly report MFA status without faking MFA implementation
      expect(body.mfa_report).toBeDefined();
      expect(body.mfa_report.mfa_supported).toBe(false);
      expect(body.mfa_report.mfa_status).toBe('NOT_IMPLEMENTED_BY_PLATFORM');
      expect(body.mfa_report.strongest_control_enforced).toBe('AUTHENTICATED_PRIVILEGED_ROLE_AND_AUDITED_JUSTIFICATION');
    });

    it('authorized privileged user allowed: user holding narrow security.break_glass capability succeeds', async () => {
      const privilegedCapContext: PrincipalContext = {
        principal_id: 'specialist-carol',
        is_authenticated: true,
        is_service: false,
        roles: ['user'],
        grants: [],
        capabilities: ['security.break_glass'],
        tenant_id: 'tenant-001',
        accessible_scope_ids: ['scope-1'],
        max_classification_rank: 1,
      };

      const loggedEvents: any[] = [];
      const recordingSink = {
        logAuditEvent: async (event: any) => { loggedEvents.push(event); },
      };

      const result = await executeWithAuditedOverride(
        privilegedCapContext,
        {
          actor_id: 'specialist-carol',
          action: 'VAULT_ACCESS',
          target_resource_id: 'res-1',
          target_resource_type: 'policy',
          justification: 'Emergency audit investigation authorized by SecOps',
          correlation_id: 'corr-003',
        },
        recordingSink,
        async (elevated) => {
          expect(elevated.is_override_active).toBe(true);
          return 'privileged_operation_success';
        }
      );

      expect(result).toBe('privileged_operation_success');
      expect(loggedEvents.length).toBe(1);
      expect(loggedEvents[0].outcome).toBe('SUCCESS');
      expect(loggedEvents[0].principal_or_service_id).toBe('specialist-carol');
    });
  });

  // =========================================================================
  // PART B — WORKER MANAGEMENT TESTS
  // =========================================================================

  describe('Part B — Operational Worker Management Authorization Controls', () => {
    it('anonymous worker management denied: start/stop/run-now/start-all/stop-all and trigger return 401 Unauthorized', async () => {
      const endpoints = [
        { method: 'POST', url: `${baseUrl}/api/workers/test-worker-1/start` },
        { method: 'POST', url: `${baseUrl}/api/workers/test-worker-1/stop` },
        { method: 'POST', url: `${baseUrl}/api/workers/test-worker-1/run-now` },
        { method: 'POST', url: `${baseUrl}/api/workers/start-all` },
        { method: 'POST', url: `${baseUrl}/api/workers/stop-all` },
        { method: 'POST', url: `${baseUrl}/api/discovery/pipeline/trigger` },
      ];

      for (const ep of endpoints) {
        const res = await fetch(ep.url, {
          method: ep.method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.authenticated).toBe(false);
      }
    });

    it('normal user worker management denied: start/stop/run-now/stop-all and trigger return 403 Forbidden', async () => {
      const normalUserToken = signAccessToken({
        principal_id: 'user-dave-01',
        email: 'dave@example.com',
        roles: ['user'],
        tenant_id: 'tenant-001',
      });

      // 1. Attempt to start a worker
      const startRes = await fetch(`${baseUrl}/api/workers/test-worker-1/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${normalUserToken}`,
        },
        body: JSON.stringify({ intervalMs: 10000 }),
      });
      expect(startRes.status).toBe(403);
      const startBody = await startRes.json();
      expect(startBody.error).toMatch(/worker.manage/i);

      // 2. Attempt to stop a worker
      const stopRes = await fetch(`${baseUrl}/api/workers/test-worker-1/stop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${normalUserToken}`,
        },
      });
      expect(stopRes.status).toBe(403);

      // 3. Attempt to trigger cycle immediately
      const runRes = await fetch(`${baseUrl}/api/workers/test-worker-1/run-now`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${normalUserToken}`,
        },
      });
      expect(runRes.status).toBe(403);

      // 4. Attempt to start all workers
      const startAllRes = await fetch(`${baseUrl}/api/workers/start-all`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${normalUserToken}`,
        },
      });
      expect(startAllRes.status).toBe(403);

      // 5. Attempt to stop all workers
      const stopAllRes = await fetch(`${baseUrl}/api/workers/stop-all`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${normalUserToken}`,
        },
      });
      expect(stopAllRes.status).toBe(403);

      // 6. Attempt to trigger discovery pipeline worker cycle
      const triggerRes = await fetch(`${baseUrl}/api/discovery/pipeline/trigger`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${normalUserToken}`,
        },
        body: JSON.stringify({ queries: ['test'] }),
      });
      expect(triggerRes.status).toBe(403);
    });

    it('operator/admin worker management allowed: operator can start, stop, and trigger discovery cycle', async () => {
      const operatorToken = signAccessToken({
        principal_id: 'operator-eve-01',
        email: 'eve@caim.internal',
        roles: ['operator'],
        tenant_id: 'tenant-001',
      });

      // Start worker
      const startRes = await fetch(`${baseUrl}/api/workers/test-worker-1/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
        body: JSON.stringify({ intervalMs: 20000 }),
      });
      expect(startRes.status).toBe(200);
      const startBody = await startRes.json();
      expect(startBody.success).toBe(true);

      // Stop worker
      const stopRes = await fetch(`${baseUrl}/api/workers/test-worker-1/stop`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
      });
      expect(stopRes.status).toBe(200);
      const stopBody = await stopRes.json();
      expect(stopBody.success).toBe(true);

      // Trigger cycle
      const runRes = await fetch(`${baseUrl}/api/workers/test-worker-1/run-now`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
      });
      expect(runRes.status).toBe(200);
      const runBody = await runRes.json();
      expect(runBody.success).toBe(true);

      // Stop all workers
      const stopAllRes = await fetch(`${baseUrl}/api/workers/stop-all`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
      });
      expect(stopAllRes.status).toBe(200);

      // Trigger discovery pipeline cycle
      const triggerRes = await fetch(`${baseUrl}/api/discovery/pipeline/trigger`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${operatorToken}`,
        },
        body: JSON.stringify({ queries: ['test'] }),
      });
      expect(triggerRes.status).toBe(200);
    });

    it('narrow capability allowed: normal user holding worker.manage capability can manage workers', async () => {
      const specialistToken = signAccessToken({
        principal_id: 'worker-specialist-01',
        email: 'specialist@caim.internal',
        roles: ['user'],
        capabilities: ['worker.manage'],
        tenant_id: 'tenant-001',
      });

      const res = await fetch(`${baseUrl}/api/workers/test-worker-1/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${specialistToken}`,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
    });
  });

  // =========================================================================
  // PART C — TENANT INVITATION TESTS
  // =========================================================================

  describe('Part C — Tenant Invitation Authorization Controls', () => {
    it('forged invitation denied: arbitrary unverified invitation string is rejected', async () => {
      // 1. Direct registration with forged opaque string
      await expect(
        authService.registerPrincipal({
          email: 'attacker1@evil.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: 'inv_tenant_victim_corp_forged',
        })
      ).rejects.toThrow(UnauthorizedAccessError);

      // 2. HTTP public registration with forged opaque string
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'attacker2@evil.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: 'inv_arbitrary_string_not_in_registry',
        }),
      });

      expect([400, 403]).toContain(res.status);
      const body = await res.json();
      expect(body.error).toMatch(/invitation/i);
    });

    it('forged invitation denied: cryptographically tampered signed JWT is rejected', async () => {
      // Create valid signed invitation, then tamper with payload
      const validToken = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-legit-01',
        expiresInSeconds: 3600,
      });

      // Tamper signature
      const tamperedToken = validToken.slice(0, -5) + 'xxxxx';

      await expect(
        authService.registerPrincipal({
          email: 'tamperer@evil.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: tamperedToken,
        })
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('modified tenant denied: valid invitation for Tenant A + request membership in Tenant B is rejected', async () => {
      // 1. Direct registration attempting cross-tenant injection
      const token1 = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-corp-alpha',
        expiresInSeconds: 3600,
      });
      await expect(
        authService.registerPrincipal({
          email: 'cross-tenant-attacker@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: token1,
          tenant_id: 'tenant-corp-victim', // Tampered target tenant!
        })
      ).rejects.toThrow(UnauthorizedAccessError);

      // 2. HTTP registration attempting cross-tenant injection in body
      const token2 = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-corp-alpha',
        expiresInSeconds: 3600,
      });
      const resBody = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'cross-tenant2@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: token2,
          tenant_id: 'tenant-corp-victim',
        }),
      });
      expect(resBody.status).toBe(403);
      const body1 = await resBody.json();
      expect(body1.error).toMatch(/tenant/i);

      // 3. HTTP registration attempting cross-tenant injection via x-tenant-id header
      const token3 = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-corp-alpha',
        expiresInSeconds: 3600,
      });
      const resHeader = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-tenant-id': 'tenant-corp-victim',
        },
        body: JSON.stringify({
          email: 'cross-tenant3@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: token3,
        }),
      });
      expect(resHeader.status).toBe(403);
      const body2 = await resHeader.json();
      expect(body2.error).toMatch(/tenant/i);
    });

    it('modified role denied: normal-user invitation + request admin role is rejected', async () => {
      // 1. Direct registration attempting role escalation
      const token1 = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-corp-alpha',
        intended_role: 'user',
        expiresInSeconds: 3600,
      });
      await expect(
        authService.registerPrincipal({
          email: 'escalation-attacker@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: token1,
          roles: ['admin'], // Tampered role!
        })
      ).rejects.toThrow(UnauthorizedAccessError);

      // 2. HTTP registration attempting role escalation in request body
      const token2 = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-corp-alpha',
        intended_role: 'user',
        expiresInSeconds: 3600,
      });
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'escalation-attacker2@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: token2,
          role: 'admin',
        }),
      });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toMatch(/role/i);
    });

    it('unauthenticated self-registration cannot request privileged admin role (caller role ignored)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'wannabe-admin@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          role: 'admin',
        }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.principal.roles).toEqual(['user']);
      expect(body.principal.roles).not.toContain('admin');
    });

    it('unauthenticated self-registration cannot request arbitrary non-default tenant (caller tenant ignored)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'tenant-joiner@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          tenant_id: 'tenant-restricted-bank',
        }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.principal.tenant_id).not.toBe('tenant-restricted-bank');
      expect(body.principal.tenant_id).toBe('tenant_example_com');
    });

    it('expired invitation denied: expired signed invitation token is rejected', async () => {
      // Create signed token expired 10 seconds ago
      const expiredToken = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-enterprise-01',
        expiresInSeconds: -10,
      });

      await expect(
        authService.registerPrincipal({
          email: 'late-user@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: expiredToken,
        })
      ).rejects.toThrow(UnauthorizedAccessError);

      // HTTP endpoint
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'late-user2@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: expiredToken,
        }),
      });

      expect([400, 403]).toContain(res.status);
      const body = await res.json();
      expect(body.error).toMatch(/expired/i);
    });

    it('expired invitation denied: expired registered opaque invitation is rejected', async () => {
      const expiredRecord = tenantInvitationManager.createOpaqueInvitation({
        tenant_id: 'tenant-enterprise-01',
        expiresInMs: -1000, // already expired
      });

      await expect(
        authService.registerPrincipal({
          email: 'late-opaque@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: expiredRecord.token,
        })
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('revoked invitation denied: explicitly revoked invitation is rejected', async () => {
      const invitation = tenantInvitationManager.createOpaqueInvitation({
        tenant_id: 'tenant-enterprise-01',
        intended_role: 'analyst',
        expiresInMs: 3600 * 1000,
      });

      // Revoke the invitation
      tenantInvitationManager.revokeInvitation(invitation.invitation_id);

      await expect(
        authService.registerPrincipal({
          email: 'revoked-user@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: invitation.token,
        })
      ).rejects.toThrow(UnauthorizedAccessError);

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'revoked-user2@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: invitation.token,
        }),
      });
      expect([400, 403]).toContain(res.status);
      const body = await res.json();
      expect(body.error).toMatch(/revoked/i);
    });

    it('valid invitation accepted: cryptographically signed invitation grants tenant scope and role', async () => {
      const signedToken = tenantInvitationManager.createSignedInvitation({
        tenant_id: 'tenant-enterprise-quantum',
        intended_role: 'analyst',
        expiresInSeconds: 3600,
      });

      const registered = await authService.registerPrincipal({
        email: 'quantum-analyst@example.com',
        password: 'ComplexPassw0rd!2026#Caim',
        invitation_token: signedToken,
      });

      expect(registered.tenant_id).toBe('tenant-enterprise-quantum');
      expect(registered.roles).toEqual(['analyst']);

      // Attempting to reuse the single-use invitation should fail
      await expect(
        authService.registerPrincipal({
          email: 'quantum-analyst-replay@example.com',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: signedToken,
        })
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('valid invitation accepted: opaque registered invitation via HTTP POST /api/auth/register succeeds', async () => {
      const opaqueInvitation = tenantInvitationManager.createOpaqueInvitation({
        tenant_id: 'tenant-corporate-beta',
        intended_role: 'developer' as any,
        expiresInMs: 3600 * 1000,
      });

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'beta-dev@corporate.io',
          password: 'ComplexPassw0rd!2026#Caim',
          invitation_token: opaqueInvitation.token,
        }),
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.principal.tenant_id).toBe('tenant-corporate-beta');
      expect(body.principal.roles).toEqual(['developer']);
    });
  });
});
