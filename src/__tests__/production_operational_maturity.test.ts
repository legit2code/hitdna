import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { E2BSandboxProvider, SandboxProviderUnavailableError } from '../../workers/sandbox-orchestrator/providers/e2b-provider.ts';
import { SandboxOrchestrationEngine } from '../../workers/sandbox-orchestrator/engine.ts';
import { CapabilityGrantService, AuthorizationStoreUnavailableError } from '@caim/auth/capability.ts';
import { AuthService } from '@caim/auth/service.ts';
import { DiagnosticService } from '@caim/workflow/diagnostic.ts';
import { PostgresDatabaseAdapter } from '@caim/db/postgres-adapter.ts';

describe('PROMPT 5: CAIM Production Operational Maturity', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('Part A & B: Explicit Runtime Modes and Sandbox Isolation', () => {
    it('throws SandboxProviderUnavailableError in production when E2B_API_KEY is missing (no silent simulation fallback)', async () => {
      process.env.NODE_ENV = 'production';
      delete process.env.E2B_API_KEY;
      delete process.env.CAIM_ALLOW_SIMULATION;

      const provider = new E2BSandboxProvider();

      await expect(
        provider.provision({
          sessionId: 'sbx-prod-test-01',
          scenarioId: 'SCN-BENIGN-01',
          scenarioVersion: '1.0.0',
          networkPolicy: {
            type: 'DEFAULT_DENY',
            allowedDomains: [],
            allowedPorts: [],
            allowDns: false,
            interceptEgress: true,
          },
          canaries: [],
          envVars: {},
          files: {},
          resourceQuota: {
            maxDurationMs: 60000,
            maxMemoryMb: 512,
            maxCpuPercentage: 50,
            maxProcessCount: 10,
            maxOutputSizeBytes: 1024 * 1024,
          },
          requireRealSandbox: true,
        })
      ).rejects.toThrow(SandboxProviderUnavailableError);
    });

    it('SandboxOrchestrationEngine records PROVIDER_UNAVAILABLE truth_state without fake success', async () => {
      process.env.NODE_ENV = 'production';
      delete process.env.E2B_API_KEY;
      delete process.env.CAIM_ALLOW_SIMULATION;

      const res = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-BENIGN-01',
        providerType: 'E2B',
        requireRealSandbox: true,
      });

      expect(res.status).toBe('PROVIDER_UNAVAILABLE');
      expect(res.execution_mode).toBe('PROVIDER_UNAVAILABLE');
      expect(res.actual_provider).toBe('NONE');
      expect(res.fallback_reason).toContain('PROVIDER_UNAVAILABLE');
    });
  });

  describe('Part C: Diagnostic Sample Data Seeding Lockout', () => {
    it('throws a fatal error if sample diagnostic data seeding is attempted in production', async () => {
      process.env.NODE_ENV = 'production';
      const diagnosticService = new DiagnosticService(undefined);

      await expect(
        diagnosticService.seedSampleDiagnosticData()
      ).rejects.toThrow(/strictly prohibited in production mode/i);
    });
  });

  describe('Part D: Authorization Fail-Closed Invariants', () => {
    it('CapabilityGrantService fails closed in production when database is missing', async () => {
      process.env.NODE_ENV = 'production';
      const capService = new CapabilityGrantService(undefined);

      // Active grants query must fail closed by returning empty grants (no in-memory fallback grants)
      const grants = await capService.getActiveGrantsForPrincipal('principal-prod-01');
      expect(grants).toEqual([]);

      // Mutations and admin listings must throw AuthorizationStoreUnavailableError
      await expect(
        capService.listGrants()
      ).rejects.toThrow(AuthorizationStoreUnavailableError);

      await expect(
        capService.grantCapability({
          capability_key: 'composer:full_access',
          principal_id: 'principal-prod-01',
          granted_by: 'admin-01',
          justification: 'Production test',
        })
      ).rejects.toThrow(AuthorizationStoreUnavailableError);
    });

    it('AuthService fails closed in production during password login if DB client is missing', async () => {
      process.env.NODE_ENV = 'production';
      const authService = new AuthService(undefined);

      await expect(
        authService.loginWithPassword({ email: 'admin@caim.internal', password: 'AnyPassword123!' })
      ).rejects.toThrow(/database client is not configured in production mode/i);
    });

    it('AuthService rejects seedDevelopmentPrincipals in production', () => {
      process.env.NODE_ENV = 'production';
      const authService = new AuthService(undefined);

      expect(() => {
        authService.seedDevelopmentPrincipals();
      }).toThrow(/strictly prohibited in production mode/i);
    });
  });

  describe('Part E: Schema Verification vs Runtime DDL', () => {
    it('verifySchema method accurately checks schema_migrations and essential production tables', async () => {
      const dbAdapter = new PostgresDatabaseAdapter({
        connectionString: 'postgres://localhost:5432/testdb',
      });

      // Mock pool query to test verifySchema validation
      const originalQuery = dbAdapter.getPool().query.bind(dbAdapter.getPool());
      (dbAdapter.getPool() as any).query = async (sqlText: string, params?: any[]) => {
        const sql = String(sqlText);
        if (sql.includes('information_schema.tables') && sql.includes('schema_migrations')) {
          return { rows: [{ exists: true }] };
        }
        if (sql.includes('SELECT version FROM public.schema_migrations')) {
          return {
            rows: [
              { version: '20260823000001' },
              { version: '20260823000002' },
              { version: '20260823000003' },
              { version: '20260823000004' },
              { version: '20260823000005' },
              { version: '20260823000006' },
              { version: '20260823000007' },
              { version: '20260823000008' },
              { version: '20260823000009' },
              { version: '20260823000010' },
              { version: '20260823000011' },
              { version: '20260823000012' },
              { version: '20260823000013' },
              { version: '20260823000014' },
              { version: '20260823000015' },
              { version: '20260823000016' },
              { version: '20260823000017' },
              { version: '20260823000018' },
              { version: '20260823000019' },
              { version: '20260823000020' },
              { version: '20260823000021' },
              { version: '20260823000022' },
              { version: '20260823000023' },
              { version: '20260823000024' },
              { version: '20260823000025' },
              { version: '20260823000026' },
              { version: '20260823000027' },
              { version: '20260823000028' },
            ],
          };
        }
        if (sql.includes('information_schema.tables')) {
          return { rows: [{ exists: true }] };
        }
        return originalQuery(sqlText, params);
      };

      const result = await dbAdapter.verifySchema();
      expect(result.verified).toBe(true);
      expect(result.missingMigrations.length).toBe(0);
      expect(result.missingTables.length).toBe(0);
      expect(result.appliedMigrations.length).toBeGreaterThanOrEqual(25);
    });
  });
});
