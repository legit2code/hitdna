import { describe, it, expect } from 'vitest';
import { SupabaseServerAuth } from '@caim/auth/server';
import { ScopeBoundaryViolationError } from '@caim/auth/types';
import { StaticAnalysisEngine } from '../workers/static-analysis/engine';
import { ProductionConfigValidator } from '@caim/config/production-validator';
import { runStandaloneDiscoveryCycle } from '../scripts/run-discovery-cycle';

describe('FIX-P02-A / Prompt 1: Hardcoded Authentication Credential Elimination & Tenant Scope Invariants', () => {
  const OLD_COMPROMISED_DISCOVERY_SECRET = 'caim-discovery-service-secret-2026';
  const OLD_COMPROMISED_MESH_SECRET = 'caim-internal-mesh-secret-key-2026';
  const TEST_VALID_CONFIGURED_SECRET = 'test-explicit-configured-service-secret-2026-safe';

  describe('1. Old Compromised Credentials Rejection', () => {
    it('rejects old discovery service secret when no secret is configured', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: undefined,
        discoveryServiceToken: undefined,
        allowDevBypass: false,
      });

      const principalHeader = await auth.authenticateRequest({
        'x-service-identity': 'service-discovery',
        'x-service-secret': OLD_COMPROMISED_DISCOVERY_SECRET,
      });
      expect(principalHeader.is_authenticated).toBe(false);
      expect(principalHeader.is_service).toBe(false);

      const principalBearer = await auth.authenticateRequest({
        'Authorization': `Bearer ${OLD_COMPROMISED_DISCOVERY_SECRET}`,
      });
      expect(principalBearer.is_authenticated).toBe(false);
      expect(principalBearer.is_service).toBe(false);
    });

    it('rejects old internal mesh secret when no secret is configured', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: undefined,
        discoveryServiceToken: undefined,
        allowDevBypass: false,
      });

      const principal = await auth.authenticateRequest({
        'x-service-identity': 'system_service',
        'x-service-secret': OLD_COMPROMISED_MESH_SECRET,
      });
      expect(principal.is_authenticated).toBe(false);
      expect(principal.is_service).toBe(false);
    });

    it('rejects old compromised credentials even when a different valid secret is configured', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: TEST_VALID_CONFIGURED_SECRET,
        allowDevBypass: false,
      });

      const principal = await auth.authenticateRequest({
        'x-service-identity': 'service-discovery',
        'x-service-secret': OLD_COMPROMISED_DISCOVERY_SECRET,
      });
      expect(principal.is_authenticated).toBe(false);
      expect(principal.is_service).toBe(false);

      const principalBearer = await auth.authenticateRequest({
        'Authorization': `Bearer ${OLD_COMPROMISED_DISCOVERY_SECRET}`,
      });
      expect(principalBearer.is_authenticated).toBe(false);
      expect(principalBearer.is_service).toBe(false);
    });
  });

  describe('2. Fail-Closed Authentication on Missing / Unconfigured Credentials', () => {
    it('fails closed when service secret is missing or empty', async () => {
      const auth = new SupabaseServerAuth({});

      const emptySecretResult = await auth.authenticateRequest({
        'x-service-identity': 'service-discovery',
        'x-service-secret': '',
      });
      expect(emptySecretResult.is_authenticated).toBe(false);

      const noSecretResult = await auth.authenticateRequest({
        'x-service-identity': 'service-discovery',
      });
      expect(noSecretResult.is_authenticated).toBe(false);
    });

    it('denies service identity elevation if service header is provided with invalid secret', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: TEST_VALID_CONFIGURED_SECRET,
      });

      const result = await auth.authenticateRequest({
        'x-service-identity': 'service-analysis',
        'x-service-secret': 'invalid-attacker-attempt',
      });
      expect(result.is_authenticated).toBe(false);
      expect(result.roles).not.toContain('admin');
      expect(result.roles).toEqual(['anonymous']);
    });
  });

  describe('3. Valid Explicitly Configured Service Authentication', () => {
    it('authenticates successfully with configured serviceSecret header', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: TEST_VALID_CONFIGURED_SECRET,
      });

      const result = await auth.authenticateRequest({
        'x-service-identity': 'service-discovery',
        'x-service-secret': TEST_VALID_CONFIGURED_SECRET,
      });

      expect(result.is_authenticated).toBe(true);
      expect(result.is_service).toBe(true);
      expect(result.service_name).toBe('service-discovery');
      expect(result.roles).toContain('operator');
      expect(result.roles).not.toContain('admin');
      expect(result.tenant_id).toBeNull();
    });

    it('authenticates successfully with configured discoveryServiceToken Bearer token', async () => {
      const auth = new SupabaseServerAuth({
        discoveryServiceToken: 'scoped-discovery-token-xyz',
      });

      const result = await auth.authenticateRequest({
        'Authorization': 'Bearer scoped-discovery-token-xyz',
      });

      expect(result.is_authenticated).toBe(true);
      expect(result.is_service).toBe(true);
      expect(result.service_name).toBe('service-discovery');
      expect(result.tenant_id).toBeNull();
    });
  });

  describe('4. Tenant Scope Validation & Unauthorized Tenant Substitution Rejection', () => {
    it('rejects arbitrary tenant substitution when service has no authorized tenant scope', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: TEST_VALID_CONFIGURED_SECRET,
        serviceTenantScopes: {}, // No tenant authorization granted
      });

      await expect(
        auth.authenticateRequest({
          'x-service-identity': 'service-discovery',
          'x-service-secret': TEST_VALID_CONFIGURED_SECRET,
          'x-tenant-id': 'tenant-unauthorized-target',
        })
      ).rejects.toThrow(ScopeBoundaryViolationError);
    });

    it('rejects substitution of a tenant not in the service authorized scope list', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: TEST_VALID_CONFIGURED_SECRET,
        serviceTenantScopes: {
          'service-discovery': ['tenant-alpha', 'tenant-beta'],
        },
      });

      await expect(
        auth.authenticateRequest({
          'x-service-identity': 'service-discovery',
          'x-service-secret': TEST_VALID_CONFIGURED_SECRET,
          'x-tenant-id': 'tenant-gamma', // Not in authorized list
        })
      ).rejects.toThrow(ScopeBoundaryViolationError);
    });

    it('permits authorized tenant when explicitly configured in serviceTenantScopes', async () => {
      const auth = new SupabaseServerAuth({
        serviceSecret: TEST_VALID_CONFIGURED_SECRET,
        serviceTenantScopes: {
          'service-discovery': ['tenant-alpha', 'tenant-beta'],
        },
      });

      const result = await auth.authenticateRequest({
        'x-service-identity': 'service-discovery',
        'x-service-secret': TEST_VALID_CONFIGURED_SECRET,
        'x-tenant-id': 'tenant-alpha',
      });

      expect(result.is_authenticated).toBe(true);
      expect(result.tenant_id).toBe('tenant-alpha');
    });

    it('rejects unauthorized tenant on Bearer service token', async () => {
      const auth = new SupabaseServerAuth({
        discoveryServiceToken: 'scoped-discovery-token-xyz',
        serviceTenantScopes: {
          'service-discovery': ['tenant-authorized-only'],
        },
      });

      await expect(
        auth.authenticateRequest({
          'Authorization': 'Bearer scoped-discovery-token-xyz',
          'x-tenant-id': 'tenant-unauthorized-target',
        })
      ).rejects.toThrow(ScopeBoundaryViolationError);
    });
  });

  describe('5. Discovery Cycle Runner Visible Failure on Missing Credential', () => {
    it('fails visibly if serviceToken is absent when reporting is required', async () => {
      const previousToken = process.env.CAIM_DISCOVERY_SERVICE_TOKEN;
      const previousSecret = process.env.SERVICE_TO_SERVICE_SECRET;
      delete process.env.CAIM_DISCOVERY_SERVICE_TOKEN;
      delete process.env.SERVICE_TO_SERVICE_SECRET;

      try {
        await expect(
          runStandaloneDiscoveryCycle({
            apiUrl: 'http://localhost:9999',
            serviceToken: undefined,
            maxCandidatesTotal: 0,
          })
        ).rejects.toThrow(/FATAL CONFIGURATION ERROR: Scoped service credential for discovery runner is missing/);
      } finally {
        if (previousToken) process.env.CAIM_DISCOVERY_SERVICE_TOKEN = previousToken;
        if (previousSecret) process.env.SERVICE_TO_SERVICE_SECRET = previousSecret;
      }
    });
  });

  describe('6. Static Analysis Secret Scanner Regression Coverage', () => {
    it('flags fake fixtures matching old CAIM secret pattern under SA-CRED-001', () => {
      const report = StaticAnalysisEngine.analyze({
        artifactId: 'test-artifact-cred-scan',
        pipelineRunId: 'pipe-cred-1',
        files: [
          {
            path: 'src/agent.ts',
            content: `
              // Test fixture to verify static scanner detects CAIM secret pattern literals
              const fakeMeshKey = "caim-internal-mesh-secret-key-fixture";
              const fakeDiscoveryKey = "caim-discovery-service-secret-fixture";
            `,
          },
        ],
      });

      const secretFindings = report.findings.filter((f) => f.rule_id === 'SA-CRED-001');

      expect(secretFindings.length).toBeGreaterThanOrEqual(2);
      expect(secretFindings[0].description).toContain('Hardcoded credential/API key literal');
    });
  });

  describe('7. Production Validator Rejection of Hardcoded Secrets', () => {
    it('flags default or compromised secrets as CRITICAL in production mode', () => {
      const previousNodeEnv = process.env.NODE_ENV;
      const previousSecret = process.env.SERVICE_TO_SERVICE_SECRET;
      process.env.NODE_ENV = 'production';
      process.env.SERVICE_TO_SERVICE_SECRET = 'caim-internal-mesh-secret-key-2026';

      try {
        const report = ProductionConfigValidator.validate();
        const serviceSecretFinding = report.findings.find((f) => f.key === 'SERVICE_TO_SERVICE_SECRET');

        expect(serviceSecretFinding).toBeDefined();
        expect(serviceSecretFinding?.passed).toBe(false);
        expect(serviceSecretFinding?.severity).toBe('CRITICAL');
        expect(serviceSecretFinding?.message).toContain('Insecure hardcoded or default SERVICE_TO_SERVICE_SECRET');
      } finally {
        process.env.NODE_ENV = previousNodeEnv;
        if (previousSecret) {
          process.env.SERVICE_TO_SERVICE_SECRET = previousSecret;
        } else {
          delete process.env.SERVICE_TO_SERVICE_SECRET;
        }
      }
    });
  });
});
