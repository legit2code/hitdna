import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ApplicationApiRouter } from '@caim/api/router.ts';
import { PolicyBlockedError } from '@caim/api/errors.ts';
import { KmsSignerBoundary } from '@caim/packaging/crypto/kms-boundary.ts';
import { Ed25519Signer } from '@caim/packaging/crypto/signer.ts';
import { createTestRequestContext } from '../src/__tests__/helpers/test-auth-context.ts';

describe('PROMPT 01R — Finish Production API Truthfulness: Policy, Readiness & Auth', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('1. Policy Evaluation Truthfulness & Derivation from Evidence', () => {
    it('returns NOT_VERIFIED (allowed: false) when no completed analysis evidence exists, ignoring caller requestedOutcome', async () => {
      const mockDb = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('FROM core.agent_versions')) {
            return {
              rows: [{ agent_version_id: 'a0000000-0000-0000-0000-000000000001', agent_id: 'ag-1', version_label: '1.0.0' }],
            };
          }
          if (sql.includes('FROM analysis.analysis_runs')) {
            // No completed runs found
            return { rows: [] };
          }
          return { rows: [] };
        },
      };

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: mockDb,
      });

      // Caller attempts to force ALLOW
      const req = createTestRequestContext({
        headers: {
          'x-principal-id': 'user-123',
          'x-principal-roles': 'release_approver',
        },
        body: {
          agentVersionId: 'a0000000-0000-0000-0000-000000000001',
          requestedOutcome: 'ALLOW',
        },
      });

      const response = await router.evaluatePolicyGate(req);

      expect(response.statusCode).toBe(200);
      const data = (response.body as any).data;
      expect(data.allowed).toBe(false);
      expect(data.outcome).toBe('NOT_VERIFIED');
      expect(data.truth_state).toBe('NOT_VERIFIED');
      expect(data.blockers).toContain('PERSISTED_ANALYSIS_EVIDENCE_NOT_FOUND');
    });

    it('blocks release (422 PolicyBlockedError) on unmitigated critical risks despite caller passing requestedOutcome=ALLOW', async () => {
      const versionId = 'b0000000-0000-0000-0000-000000000002';
      const runId = 'r0000000-0000-0000-0000-000000000001';

      const mockDb = {
        query: async (sql: string, params?: any[]) => {
          if (sql.includes('FROM core.agent_versions')) {
            return {
              rows: [{ agent_version_id: versionId, agent_id: 'ag-2', version_label: '2.0.0' }],
            };
          }
          if (sql.includes('FROM analysis.analysis_runs')) {
            return {
              rows: [{
                analysis_run_id: runId,
                status: 'COMPLETED',
                pipeline_version: '2.0.1',
                caim_version: '1.0.0',
                completed_at: new Date().toISOString(),
              }],
            };
          }
          if (sql.includes('FROM intel.policy_decisions')) {
            return { rows: [] }; // compute via PolicyEngine
          }
          if (sql.includes('FROM intel.risks')) {
            return {
              rows: [{
                risk_id: 'risk-crit-1',
                analysis_run_id: runId,
                risk_type: 'CRITICAL_VULNERABILITY',
                severity: 'CRITICAL',
                title: 'Remote Command Injection vulnerability detected in agent handler',
                description: 'Unsanitized input flows directly to child_process.exec',
                mitigated: false,
              }],
            };
          }
          if (sql.includes('FROM intel.score_results')) {
            return {
              rows: [{
                analysis_run_id: runId,
                overall_score: '45.0',
                created_at: new Date().toISOString(),
              }],
            };
          }
          if (sql.includes('FROM analysis.static_findings')) {
            return { rows: [] };
          }
          if (sql.includes('FROM analysis.taint_flows')) {
            return { rows: [] };
          }
          if (sql.includes('FROM intel.policy_overrides')) {
            return { rows: [] };
          }
          return { rows: [] };
        },
      };

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: mockDb,
      });

      // Caller dictates requestedOutcome = ALLOW
      const req = createTestRequestContext({
        headers: {
          'x-principal-id': 'user-admin',
          'x-principal-roles': 'admin',
        },
        body: {
          agentVersionId: versionId,
          requestedOutcome: 'ALLOW',
        },
      });

      const response = await router.evaluatePolicyGate(req);

      // Must fail closed with 422 Policy Block
      expect(response.statusCode).toBe(422);
      const errorBody = (response.body as any).error;
      expect(errorBody.code).toBe('POLICY_BLOCKED');
      expect(errorBody.details.policy_outcome).toBe('DENY_SHIPPING');
    });

    it('strictly forbids forceBlock simulation in production mode', async () => {
      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [] }) },
      });

      const req = createTestRequestContext({
        headers: {
          'x-principal-id': 'user-admin',
          'x-principal-roles': 'admin',
        },
        body: {
          agentVersionId: 'v-test',
          forceBlock: true,
        },
      });

      const response = await router.evaluatePolicyGate(req);

      expect(response.statusCode).toBe(500);
      expect((response.body as any).error.message).toContain('forceBlock simulation is strictly prohibited in production mode');
    });
  });

  describe('2. Readiness Veracity — No False Healthy State from Env Vars', () => {
    it('reports CONFIGURED_NOT_VERIFIED when REDIS_URL exists but active connectivity is unverified', async () => {
      process.env.REDIS_URL = 'redis://production-cluster.internal:6379';

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [{ '?column?': 1 }] }) },
      });

      const response = await router.getReadiness({ headers: {} });
      const checks = (response.body as any).data.checks;

      expect(checks.workflow_queue.status).toBe('CONFIGURED_NOT_VERIFIED');
      expect(checks.workflow_queue.status).not.toBe('HEALTHY');
    });

    it('reports CONFIGURED_NOT_VERIFIED when E2B_API_KEY exists without active sandbox probe', async () => {
      process.env.E2B_API_KEY = 'e2b_prod_live_secret_key_12345';

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [{ '?column?': 1 }] }) },
      });

      const response = await router.getReadiness({ headers: {} });
      const checks = (response.body as any).data.checks;

      expect(checks.sandbox_provider.status).toBe('CONFIGURED_NOT_VERIFIED');
      expect(checks.sandbox_provider.status).not.toBe('HEALTHY');
    });

    it('reports CONFIGURED_NOT_VERIFIED when KMS_KEY_ID exists without capability verification in production', async () => {
      process.env.KMS_KEY_ID = 'projects/p/locations/l/keyRings/r/cryptoKeys/k';

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [{ '?column?': 1 }] }) },
      });

      const response = await router.getReadiness({ headers: {} });
      const checks = (response.body as any).data.checks;

      expect(checks.kms_signing_enclave.status).toBe('CONFIGURED_NOT_VERIFIED');
      expect(checks.kms_signing_enclave.status).not.toBe('HEALTHY');
    });

    it('reports HEALTHY when KMS enclave capability probe succeeds', async () => {
      const { signer } = Ed25519Signer.generateKeyPair('caim-release-key-01');
      const realKmsBoundary = new KmsSignerBoundary(signer);

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [{ '?column?': 1 }] }) },
        container: {
          kmsBoundary: realKmsBoundary,
        },
      });

      const response = await router.getReadiness({ headers: {} });
      const checks = (response.body as any).data.checks;

      expect(checks.kms_signing_enclave.status).toBe('HEALTHY');
      expect(checks.kms_signing_enclave.provider).toBe('kms-enclave');
    });

    it('reports UNHEALTHY when KMS capability probe fails', async () => {
      const failingKms = {
        verifyCapability: async () => ({
          healthy: false,
          error: 'Hardware security module connection timed out after 5000ms',
        }),
      };

      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [{ '?column?': 1 }] }) },
        container: {
          kmsBoundary: failingKms,
        },
      });

      const response = await router.getReadiness({ headers: {} });
      const checks = (response.body as any).data.checks;

      expect(checks.kms_signing_enclave.status).toBe('UNHEALTHY');
      expect(checks.kms_signing_enclave.error).toContain('timed out');
    });

    it('reports LOCAL_REGISTRY_READY for event and queue registries in production', async () => {
      const router = new ApplicationApiRouter({
        isProduction: true,
        dbClient: { query: async () => ({ rows: [{ '?column?': 1 }] }) },
      });

      const response = await router.getReadiness({ headers: {} });
      const checks = (response.body as any).data.checks;

      expect(checks.event_catalog.status).toBe('LOCAL_REGISTRY_READY');
      expect(checks.queue_registry.status).toBe('LOCAL_REGISTRY_READY');
    });
  });

  describe('3. Production API Auth Boundary under /api/v1', () => {
    const router = new ApplicationApiRouter({
      isProduction: false,
      seedEntities: true,
    });

    it('rejects unauthenticated requests to /api/v1/agents with 401', async () => {
      const res = await router.listAgents({
        url: '/api/v1/agents',
        headers: {},
      });

      expect(res.statusCode).toBe(401);
      expect((res.body as any).error.code).toBe('UNAUTHENTICATED');
    });

    it('permits authenticated requests to /api/v1/agents', async () => {
      const req = createTestRequestContext({
        url: '/api/v1/agents',
        headers: {
          'x-principal-id': 'analyst-1',
          'x-principal-roles': 'analyst',
        },
      });

      const res = await router.listAgents(req);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('rejects unauthenticated requests to /api/v1/agents/:agentId with 401', async () => {
      const res = await router.getAgent({
        url: '/api/v1/agents/test-agent',
        params: { agentId: 'test-agent' },
        headers: {},
      });

      expect(res.statusCode).toBe(401);
      expect((res.body as any).error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects unauthenticated requests to /api/v1/agents/:agentId/versions/:versionId with 401', async () => {
      const res = await router.getAgentVersion({
        url: '/api/v1/agents/test-agent/versions/v1',
        params: { agentId: 'test-agent', versionId: 'v1' },
        headers: {},
      });

      expect(res.statusCode).toBe(401);
      expect((res.body as any).error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects unauthenticated requests to /api/v1/analysis/:runId with 401', async () => {
      const res = await router.getAnalysisRun({
        url: '/api/v1/analysis/run-1',
        params: { runId: 'run-1' },
        headers: {},
      });

      expect(res.statusCode).toBe(401);
      expect((res.body as any).error.code).toBe('UNAUTHENTICATED');
    });

    it('rejects unauthenticated requests to /api/v1/analysis/:runId/findings with 401', async () => {
      const res = await router.getAnalysisFindings({
        url: '/api/v1/analysis/run-1/findings',
        params: { runId: 'run-1' },
        headers: {},
      });

      expect(res.statusCode).toBe(401);
      expect((res.body as any).error.code).toBe('UNAUTHENTICATED');
    });
  });
});
