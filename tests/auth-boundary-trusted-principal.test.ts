import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express, { Request, Response, NextFunction } from 'express';
import { Server } from 'http';
import { 
  SupabaseServerAuth, 
  signAccessToken, 
  SecurityClassificationRank, 
  createAnonymousPrincipal 
} from '@caim/auth';
import { createApiExpressRouter, ApplicationApiRouter } from '@caim/api';

describe('CAIM Authentication Boundary — Single Authoritative Principal & Zero Header Forgery', () => {
  let app: express.Application;
  let server: Server;
  let baseUrl: string;
  const jwtSecret = 'test-jwt-secret-auth-boundary-32chars!';
  const authHelper = new SupabaseServerAuth({
    jwtSecret,
    serviceSecret: 'test-configured-service-secret-boundary',
    allowDevBypass: false,
  });

  beforeAll(async () => {
    app = express();
    app.use(express.json());

    // 1. Authoritative Primary Authentication Middleware (Matching apps/server/index.ts)
    app.use(async (req: Request, _res: Response, next: NextFunction) => {
      try {
        req.principal = await authHelper.authenticateRequest(req.headers as any);
      } catch {
        req.principal = createAnonymousPrincipal();
      }
      next();
    });

    // 2. Mount API v1 Router using createApiExpressRouter
    const apiRouter = new ApplicationApiRouter();
    app.use('/api/v1', createApiExpressRouter(apiRouter));

    // 3. Mount Discovery Service-to-Service Endpoint (Matching apps/server/index.ts)
    const requireDiscoveryServiceAuth = (req: Request, res: Response, next: NextFunction) => {
      if (
        req.principal?.is_authenticated &&
        (req.principal.is_service ||
         req.principal.service_name === 'service-discovery' ||
         req.principal.roles?.includes('operator') ||
         req.principal.roles?.includes('admin'))
      ) {
        return next();
      }
      return res.status(401).json({
        error: 'Unauthorized: Valid service token or service-identity required',
        authenticated: false,
      });
    };

    app.post('/api/v1/scheduled/discovery/report', requireDiscoveryServiceAuth, (req: Request, res: Response) => {
      res.status(200).json({
        success: true,
        reportedBy: req.principal?.principal_id,
        roles: req.principal?.roles,
        serviceName: req.principal?.service_name,
      });
    });

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const address = server.address() as any;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  describe('1. Forged Role Rejection (No Privilege Escalation)', () => {
    it('rejects unauthenticated request attempting to claim admin role via x-role', async () => {
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-role': 'admin',
          'x-principal-roles': 'admin',
        },
        body: JSON.stringify({
          agentId: 'forged-agent-1',
          canonicalName: 'Forged Agent',
        }),
      });

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects unauthenticated request attempting to claim analyst role via x-principal-roles', async () => {
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-principal-roles': 'analyst',
          'x-principal-id': 'usr-attacker',
        },
        body: JSON.stringify({
          agentId: 'forged-agent-2',
          canonicalName: 'Forged Agent 2',
        }),
      });

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.code).toBe('UNAUTHENTICATED');
    });
  });

  describe('2. Forged Tenant Protection (Tenant-Isolation)', () => {
    it('prevents authenticated user from spoofing tenant via x-tenant-id header', async () => {
      const legitimateToken = signAccessToken(
        {
          principal_id: 'usr-alice',
          email: 'alice@tenant-alpha.com',
          roles: ['analyst'],
          tenant_id: 'tenant-alpha',
          accessible_scope_ids: ['tenant-alpha'],
        },
        { secret: jwtSecret }
      );

      // Alice presents token for tenant-alpha, but includes forged x-tenant-id: tenant-bravo
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${legitimateToken}`,
          'x-tenant-id': 'tenant-bravo', // Attempted tenant override
        },
        body: JSON.stringify({
          agentId: 'agent-alice-alpha',
          canonicalName: 'Alice Alpha Agent',
        }),
      });

      expect(response.status).toBe(201);
      const data = await response.json();
      expect(data.success).toBe(true);
      // The agent should be created under the token's authenticated tenant, not the header
      expect(data.data.tenant_id).toBe('tenant-alpha');
    });
  });

  describe('3. Forged Classification Clearance Rejection', () => {
    it('does not grant VAULT_RESTRICTED clearance when header x-max-classification is sent by standard user', async () => {
      const userToken = signAccessToken(
        {
          principal_id: 'usr-bob',
          email: 'bob@example.com',
          roles: ['user'], // user role clearance is INTERNAL only
          tenant_id: 'tenant-1',
          accessible_scope_ids: ['tenant-1'],
        },
        { secret: jwtSecret }
      );

      // Attempt to access or mutate with forged classification header
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${userToken}`,
          'x-max-classification': 'VAULT_RESTRICTED',
          'x-principal-roles': 'admin',
        },
        body: JSON.stringify({
          agentId: 'agent-bob',
          canonicalName: 'Bob Agent',
        }),
      });

      // Protected endpoint requires analyst or admin — bob has user role
      expect(response.status).toBe(403);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.code).toBe('FORBIDDEN');
    });
  });

  describe('4. Arbitrary Bearer Token Text Vulnerability Elimination', () => {
    it('fails closed (401) on arbitrary Bearer text containing privilege keywords like "admin"', async () => {
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer admin',
        },
        body: JSON.stringify({
          agentId: 'agent-hack-admin',
          canonicalName: 'Hack Admin',
        }),
      });

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.code).toBe('UNAUTHENTICATED');
    });

    it('fails closed (401) on arbitrary Bearer text containing "analyst"', async () => {
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer test-analyst-fake-token',
        },
        body: JSON.stringify({
          agentId: 'agent-hack-analyst',
          canonicalName: 'Hack Analyst',
        }),
      });

      expect(response.status).toBe(401);
    });

    it('fails closed (401) on arbitrary Bearer text containing "approver"', async () => {
      const response = await fetch(`${baseUrl}/api/v1/approvals`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer release-approver-token-bogus',
        },
        body: JSON.stringify({
          agentVersionId: 'av-test-1',
          decision: 'APPROVED',
          rationale: 'Valid rationale 10 chars',
        }),
      });

      expect(response.status).toBe(401);
    });
  });

  describe('5. Missing Credentials Fail-Closed Behavior', () => {
    it('treats requests with no auth credentials and forged headers as unauthenticated (401)', async () => {
      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-principal-id': 'admin-super-user',
          'x-role': 'admin',
          'x-roles': 'admin,release_approver',
          'x-tenant-id': 'tenant-secret',
        },
        body: JSON.stringify({
          agentId: 'agent-super-spoofed',
          canonicalName: 'Spoofed Agent',
        }),
      });

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.code).toBe('UNAUTHENTICATED');
    });
  });

  describe('6. Valid Low-Privilege Token with Forged Headers', () => {
    it('strictly denies access (403) when user token sends x-role: admin to admin/analyst route', async () => {
      const standardUserToken = signAccessToken(
        {
          principal_id: 'usr-charlie',
          email: 'charlie@company.com',
          roles: ['user'],
          tenant_id: 'tenant-acme',
          accessible_scope_ids: ['tenant-acme'],
        },
        { secret: jwtSecret }
      );

      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${standardUserToken}`,
          'x-role': 'admin',
          'x-principal-roles': 'admin',
          'x-max-classification': 'VAULT_RESTRICTED',
        },
        body: JSON.stringify({
          agentId: 'agent-charlie-escalate',
          canonicalName: 'Charlie Escalation Attempt',
        }),
      });

      expect(response.status).toBe(403);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.code).toBe('FORBIDDEN');
    });
  });

  describe('7. Service Identity Forging Protection', () => {
    it('rejects x-service-identity header without valid secret (401)', async () => {
      const response = await fetch(`${baseUrl}/api/v1/scheduled/discovery/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-service-identity': 'service-discovery',
          // Missing x-service-secret
        },
        body: JSON.stringify({ cycleId: 'cycle-spoofed' }),
      });

      expect(response.status).toBe(401);
    });

    it('rejects x-service-identity header with incorrect secret (401)', async () => {
      const response = await fetch(`${baseUrl}/api/v1/scheduled/discovery/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-service-identity': 'service-discovery',
          'x-service-secret': 'wrong-password-guess',
        },
        body: JSON.stringify({ cycleId: 'cycle-spoofed' }),
      });

      expect(response.status).toBe(401);
    });

    it('authenticates with valid service secret and receives scoped operator role (not superuser admin)', async () => {
      const response = await fetch(`${baseUrl}/api/v1/scheduled/discovery/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-service-identity': 'service-discovery',
          'x-service-secret': 'test-configured-service-secret-boundary',
        },
        body: JSON.stringify({ cycleId: 'cycle-valid-1' }),
      });

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.reportedBy).toBe('service:service-discovery');
      expect(data.roles).toContain('operator');
      // Verify discovery service does NOT get superuser admin by default
      expect(data.roles).not.toContain('admin');
    });
  });

  describe('8. Legitimate Authenticated Operations (Positive Test)', () => {
    it('permits authorized analyst to create agents via cryptographic JWT', async () => {
      const analystToken = signAccessToken(
        {
          principal_id: 'usr-analyst-legit',
          email: 'analyst@company.com',
          roles: ['analyst'],
          tenant_id: 'tenant-corp',
          accessible_scope_ids: ['tenant-corp'],
        },
        { secret: jwtSecret }
      );

      const response = await fetch(`${baseUrl}/api/v1/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${analystToken}`,
        },
        body: JSON.stringify({
          agentId: 'agent-legit-analyst',
          canonicalName: 'Legitimate Analyst Agent',
        }),
      });

      expect(response.status).toBe(201);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.agent_id).toBe('agent-legit-analyst');
    });

    it('permits authorized admin to submit approvals via cryptographic JWT', async () => {
      const adminToken = signAccessToken(
        {
          principal_id: 'usr-admin-legit',
          email: 'admin@company.com',
          roles: ['admin'],
          tenant_id: 'tenant-corp',
          accessible_scope_ids: ['tenant-corp'],
        },
        { secret: jwtSecret }
      );

      const response = await fetch(`${baseUrl}/api/v1/approvals`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          agentVersionId: 'av-admin-1',
          decision: 'APPROVED',
          rationale: 'Fully reviewed security requirements',
        }),
      });

      expect(response.status).toBe(201);
      const data = await response.json();
      expect(data.success).toBe(true);
    });
  });
});
