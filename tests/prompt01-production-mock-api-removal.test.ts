import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ApplicationApiRouter } from '@caim/api/router.ts';

describe('PROMPT 01 — Remove Mock Production API and False Product Results', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  beforeEach(() => {
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
  });

  describe('1. Production Fail-Closed Safety Against Map-Backed Domain Persistence', () => {
    it('strictly forbids map-backed listAgents in production without database client', async () => {
      process.env.NODE_ENV = 'production';
      const router = new ApplicationApiRouter({ isProduction: true });

      const response = await router.listAgents({
        headers: {},
        params: {},
        query: {},
        body: {},
        requestId: 'req-prod-01',
        url: '/agents',
        method: 'GET',
      });

      expect(response.statusCode).toBe(500);
      expect((response.body as any).error.message).toMatch(
        /\[FATAL PRODUCTION ERROR\] Map-backed domain persistence is strictly prohibited in production mode for 'listAgents'/
      );
    });

    it('strictly forbids map-backed createAgent in production without database client', async () => {
      process.env.NODE_ENV = 'production';
      const router = new ApplicationApiRouter({ isProduction: true });

      const response = await router.createAgent({
        headers: {},
        params: {},
        query: {},
        body: { canonicalName: 'TestAgent' },
        requestId: 'req-prod-02',
        url: '/agents',
        method: 'POST',
        principal: { principal_id: 'admin-1', roles: ['admin'], tenant_id: 'tenant-1', is_authenticated: true, max_classification_rank: 4 } as any,
      });

      expect(response.statusCode).toBe(500);
      expect((response.body as any).error.message).toMatch(
        /\[FATAL PRODUCTION ERROR\] Map-backed domain persistence is strictly prohibited in production mode for 'createAgent'/
      );
    });

    it('strictly forbids synthetic simulation in production mode on createAnalysisRun', async () => {
      process.env.NODE_ENV = 'production';
      const mockDb = {
        query: async (sql: string) => {
          if (sql.includes('core.agent_versions')) {
            return { rows: [{ agent_version_id: '11111111-1111-1111-1111-111111111111' }] };
          }
          return { rows: [] };
        },
      };
      const router = new ApplicationApiRouter({ isProduction: true, dbClient: mockDb });

      const response = await router.createAnalysisRun({
        headers: {},
        params: {},
        query: {},
        body: {
          agentVersionId: '11111111-1111-1111-1111-111111111111',
          simulatePartial: true,
        },
        requestId: 'req-prod-03',
        url: '/analysis/runs',
        method: 'POST',
        principal: { principal_id: 'admin-1', roles: ['admin'], tenant_id: 'tenant-1', is_authenticated: true, max_classification_rank: 4 } as any,
      });

      expect(response.statusCode).toBe(500);
      expect((response.body as any).error.message).toMatch(/Synthetic analysis simulation is strictly prohibited in production mode/);
    });
  });

  describe('2. Real Readiness Probing (No Static/Fabricated Health Metrics)', () => {
    it('returns NOT_CONFIGURED when dependencies are unconfigured rather than static fake metrics', async () => {
      delete process.env.KMS_KEY_ID;
      delete process.env.SIGNING_KEY_ID;
      delete process.env.E2B_API_KEY;

      const router = new ApplicationApiRouter({ isProduction: false });
      const response = await router.getReadiness({
        headers: {},
        params: {},
        query: {},
        body: {},
        requestId: 'req-ready-01',
        url: '/ready',
        method: 'GET',
      });

      const checks = (response.body as any).data.checks;
      // Must not fabricate static fake values like active_connections: 5 or active_key_id: caim-release-key-01
      expect(checks.database_pool.active_connections).toBeUndefined();
      expect(checks.kms_signing_enclave.active_key_id).toBeUndefined();
      expect(checks.sandbox_provider.status).toBe('NOT_CONFIGURED');
    });

    it('returns UNHEALTHY / NOT_READY in production when database is missing or failing', async () => {
      process.env.NODE_ENV = 'production';
      const failingDb = {
        query: async () => {
          throw new Error('Connection refused at 127.0.0.1:5432');
        },
      };

      const router = new ApplicationApiRouter({ isProduction: true, dbClient: failingDb });
      const response = await router.getReadiness({
        headers: {},
        params: {},
        query: {},
        body: {},
        requestId: 'req-ready-02',
        url: '/ready',
        method: 'GET',
      });

      expect(response.statusCode).toBe(503);
      expect((response.body as any).data.status).toBe('NOT_READY');
      expect((response.body as any).data.checks.database_pool.status).toBe('UNHEALTHY');
      expect((response.body as any).data.checks.database_pool.error).toBe('Connection refused at 127.0.0.1:5432');
    });

    it('returns READY and HEALTHY when database probe SELECT 1 succeeds', async () => {
      process.env.NODE_ENV = 'production';
      const healthyDb = {
        query: async (sql: string) => {
          if (sql.includes('SELECT 1')) return { rows: [{ '?column?': 1 }] };
          return { rows: [] };
        },
      };
      const mockAdapter = {
        verifySchema: async () => ({
          verified: true,
          appliedMigrations: ['0001_initial'],
        }),
      };

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: healthyDb,
        dbAdapter: mockAdapter,
      });

      const response = await router.getReadiness({
        headers: {},
        params: {},
        query: {},
        body: {},
        requestId: 'req-ready-03',
        url: '/ready',
        method: 'GET',
      });

      expect(response.statusCode).toBe(200);
      expect((response.body as any).data.status).toBe('READY');
      expect((response.body as any).data.checks.database_pool.status).toBe('HEALTHY');
      expect((response.body as any).data.checks.database_pool.latency_ms).toBeTypeOf('number');
      expect((response.body as any).data.checks.schema.status).toBe('HEALTHY');
    });
  });

  describe('3. Real Database Queries When Database Client Is Provided', () => {
    it('executes real SQL against canonical_agents for listAgents', async () => {
      const recordedQueries: string[] = [];
      const dbClient = {
        query: async (sql: string, params?: any[]) => {
          recordedQueries.push(sql);
          if (sql.includes('COUNT(*)')) {
            return { rows: [{ count: '1' }] };
          }
          if (sql.includes('core.canonical_agents')) {
            return {
              rows: [
                {
                  agent_id: '22222222-2222-2222-2222-222222222222',
                  canonical_name: 'Production SQL Agent',
                  status: 'ACTIVE',
                  identity_confidence: '0.9800',
                  created_at: new Date().toISOString(),
                  updated_at: new Date().toISOString(),
                },
              ],
            };
          }
          return { rows: [] };
        },
      };

      const router = new ApplicationApiRouter({ dbClient });
      const response = await router.listAgents({
        headers: {},
        params: {},
        query: { page: 1, limit: 10 },
        body: {},
        requestId: 'req-db-01',
        url: '/agents',
        method: 'GET',
      });

      expect(response.statusCode).toBe(200);
      expect((response.body as any).data).toHaveLength(1);
      expect((response.body as any).data[0].canonical_name).toBe('Production SQL Agent');
      expect(recordedQueries.some((q) => q.includes('core.canonical_agents'))).toBe(true);
    });
  });
});
