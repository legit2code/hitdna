import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import { Server } from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {
  ShippingService,
  IShippingTargetAdapter,
  ShippingOptions,
  SignedPackageBundle,
  DeliveryReceipt,
  LocalStagingAdapter,
  OciRegistryAdapter,
  S3StorageAdapter,
  WebhookShippingAdapter,
  DeterministicPackageBundler,
  KmsSignerBoundary,
  PackageBuildInput,
} from '@caim/packaging';
import { registerPackagingRoutes } from '../apps/server/routes/packaging.routes.ts';
import { AuditLogEngine, OpenTelemetryTracer } from '@caim/workflow/observability.ts';

describe('PROMPT 02 — Package Shipping Truth States Architecture', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalOciHost = process.env.OCI_REGISTRY_HOST;
  const originalS3Bucket = process.env.S3_BUCKET_NAME;
  const originalWebhookUrl = process.env.SHIPPING_WEBHOOK_URL;

  let kmsBoundary: KmsSignerBoundary;
  let sampleBundle: SignedPackageBundle;

  const sampleInput: PackageBuildInput = {
    packageId: 'pkg-truth-test-01',
    agentId: 'agent-truth-verifier',
    agentVersionId: 'av-truth-v1',
    versionLabel: '1.0.0',
    createdAt: '2026-09-15T00:00:00Z',
    sourceFiles: {
      'src/main.ts': 'export const run = () => "ok";',
      'package.json': '{"name":"agent-truth","version":"1.0.0"}',
    },
    analysisReport: {
      static_analysis: { findings_count: 0, taint_sinks_reached: 0, status: 'CLEAN' },
      composition_sbom: { components_count: 1, cve_vulnerabilities: 0, status: 'CLEAN' },
      sandbox_behavior: { network_egress_unauthorized: 0, syscall_violations: 0, status: 'PASSED' },
      decision_score: { overall_score: 95, risk_band: 'LOW', confidence: 0.99 },
      recommendation: { verdict: 'APPROVE', allow_shipment: true },
    },
    sbomComponents: [
      { name: 'lodash', version: '4.17.21', type: 'library', purl: 'pkg:npm/lodash@4.17.21' },
    ],
    validationReference: {
      validation_run_id: 'val-run-001',
      validation_plan_version: 'v1.0.0',
      status: 'PASSED',
      verdict: 'APPROVED_FOR_RELEASE',
      risk_reduced: true,
      capabilities_preserved: true,
      completed_at: '2026-09-15T00:00:00Z',
    },
    policyReference: {
      policy_ruleset_version: 'v2.0.1',
      policy_outcome: 'ALLOW',
      risk_score: 95,
      risk_band: 'LOW',
      policy_allowed: true,
      evaluated_at: '2026-09-15T00:00:00Z',
    },
    approvalReferences: [
      {
        approval_id: 'appr-01',
        approver_id: 'usr-sec-lead',
        approver_role: 'SECURITY_AUDITOR',
        decision: 'APPROVED',
        decided_at: '2026-09-15T00:00:00Z',
        rationale: 'Passed full security audit',
      },
      {
        approval_id: 'appr-02',
        approver_id: 'usr-rel-engineer',
        approver_role: 'RELEASE_ENGINEER',
        decision: 'APPROVED',
        decided_at: '2026-09-15T00:00:00Z',
        rationale: 'Production release readiness verified',
      },
    ],
    metadata: {
      author: 'CAIM Core Security Team',
      license: 'Apache-2.0',
      securityClassification: 'RESTRICTED',
      framework: 'TypeScript/Node',
      description: 'Test agent release package',
    },
    provenanceReference: {
      engine_version: '2.0.1',
      ruleset_version: '2026-08-26',
      analysis_run_id: 'ar-res-4412',
      input_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      generated_at: '2026-09-15T00:00:00Z',
    },
  };

  beforeEach(async () => {
    process.env.NODE_ENV = 'test';
    delete process.env.OCI_REGISTRY_HOST;
    delete process.env.S3_BUCKET_NAME;
    delete process.env.SHIPPING_WEBHOOK_URL;

    kmsBoundary = KmsSignerBoundary.createDefault();
    sampleBundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
    if (originalOciHost) process.env.OCI_REGISTRY_HOST = originalOciHost;
    if (originalS3Bucket) process.env.S3_BUCKET_NAME = originalS3Bucket;
    if (originalWebhookUrl) process.env.SHIPPING_WEBHOOK_URL = originalWebhookUrl;
  });

  describe('1. Missing Provider → NOT_CONFIGURED', () => {
    it('returns NOT_CONFIGURED when target provider is not registered in ShippingService', async () => {
      const shippingService = new ShippingService();

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'NON_EXISTENT_PROVIDER' as any,
        { targetLocator: 'target://unknown' }
      );

      expect(receipt.status).toBe('NOT_CONFIGURED');
      expect(receipt.truthState).toBe('NOT_CONFIGURED');
      expect(receipt.receipt_locator).toBeNull();
      expect(receipt.receipt_signature).toBeNull();
      expect(receipt.shipped_at).toBeNull();
      expect(receipt.error).toContain('No shipping provider configured');
    });

    it('returns NOT_CONFIGURED in production when provider lacks configuration credentials', async () => {
      process.env.NODE_ENV = 'production';
      const shippingService = new ShippingService();

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'OCI_REGISTRY',
        { targetLocator: 'registry.internal.caim.security/release' }
      );

      expect(receipt.status).toBe('NOT_CONFIGURED');
      expect(receipt.receipt_locator).toBeNull();
      expect(receipt.receipt_signature).toBeNull();
      expect(receipt.truthState).toBe('NOT_CONFIGURED');
    });
  });

  describe('2. Provider Failure → FAILED', () => {
    it('returns FAILED when adapter execution throws an error', async () => {
      const failingAdapter: IShippingTargetAdapter = {
        targetType: 'FAILING_PROVIDER',
        async ship(): Promise<DeliveryReceipt> {
          throw new Error('Disk quota exceeded on remote target');
        },
        async healthCheck() {
          return { healthy: false, details: 'Failure simulator' };
        },
      };

      const shippingService = new ShippingService([failingAdapter]);

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'FAILING_PROVIDER',
        { targetLocator: 'target://failing' }
      );

      expect(receipt.status).toBe('FAILED');
      expect(receipt.receipt_locator).toBeNull();
      expect(receipt.receipt_signature).toBeNull();
      expect(receipt.error).toContain('Disk quota exceeded');
      expect(receipt.truthState).toBe('UNKNOWN');
    });

    it('returns FAILED when local staging fails to write', async () => {
      // Point to an invalid path that cannot be written
      const adapter = new LocalStagingAdapter({ baseDirectory: '/proc/invalid/cannot/write' });
      const shippingService = new ShippingService([adapter]);

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'LOCAL_STAGING',
        { targetLocator: '/proc/invalid/cannot/write' }
      );

      expect(receipt.status).toBe('FAILED');
      expect(receipt.receipt_locator).toBeNull();
      expect(receipt.receipt_signature).toBeNull();
      expect(receipt.error).toBeDefined();
    });
  });

  describe('3. Development Simulation → SIMULATED_DELIVERY', () => {
    it('returns SIMULATED_DELIVERY in development/test mode without fabricating signatures', async () => {
      process.env.NODE_ENV = 'test';
      const shippingService = new ShippingService();

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'OCI_REGISTRY',
        { targetLocator: 'registry.internal.caim.security/agents/test', simulate: true }
      );

      expect(receipt.status).toBe('SIMULATED_DELIVERY');
      expect(receipt.truthState).toBe('SIMULATED');
      // Crucial: CAIM NEVER reports DELIVERED for simulations
      expect(receipt.status).not.toBe('DELIVERED');
      // Crucial: Never manufacture receipt signatures for simulations
      expect(receipt.receipt_signature).toBeNull();
    });

    it('strictly forbids SIMULATED_DELIVERY in production mode', async () => {
      process.env.NODE_ENV = 'production';
      const shippingService = new ShippingService();

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'S3_STORAGE',
        { targetLocator: 's3://release-bucket/agent', simulate: true }
      );

      // In production, unconfigured or simulated delivery is blocked
      expect(receipt.status).not.toBe('SIMULATED_DELIVERY');
      expect(receipt.status).not.toBe('DELIVERED');
      expect(receipt.status).toBe('NOT_CONFIGURED');
    });
  });

  describe('4. Real Provider Success → DELIVERED', () => {
    it('reports DELIVERED with OBSERVED truth state on real local staging delivery', async () => {
      const stagingDir = path.resolve(`/tmp/caim-staging-test-${Date.now()}`);
      const shippingService = new ShippingService();

      const receipt = await shippingService.shipBundle(
        sampleBundle,
        'LOCAL_STAGING',
        { targetLocator: stagingDir }
      );

      expect(receipt.status).toBe('DELIVERED');
      expect(receipt.truthState).toBe('OBSERVED');
      expect(receipt.receipt_locator).toContain(stagingDir);

      // Verify files were actually delivered to the filesystem
      expect(fs.existsSync(receipt.receipt_locator!)).toBe(true);
      expect(fs.existsSync(path.join(receipt.receipt_locator!, 'src/main.ts'))).toBe(true);

      // Clean up test directory
      fs.rmSync(stagingDir, { recursive: true, force: true });
    });
  });

  describe('5. HTTP API Route Truth State Compliance (/api/packages/ship)', () => {
    let app: express.Express;
    let server: Server;
    let baseUrl: string;
    let shippingService: ShippingService;

    beforeEach(async () => {
      app = express();
      app.use(express.json());
      app.use((req, _res, next) => {
        (req as any).principal = {
          principal_id: 'usr-test-release-approver',
          is_authenticated: true,
          roles: ['release_approver', 'admin', 'operator'],
          max_classification_rank: 4,
        };
        next();
      });

      shippingService = new ShippingService();
      const globalAuditEngine = new AuditLogEngine();
      const globalTracer = new OpenTelemetryTracer();

      const container = {
        kmsBoundary,
        shippingService,
        globalAuditEngine,
        globalTracer,
        platformAuditService: {
          recordEvent: async () => {},
          recordAuditEntry: async () => {},
        },
      } as any;

      registerPackagingRoutes(app, container);

      await new Promise<void>((resolve) => {
        server = app.listen(0, () => {
          const port = (server.address() as any).port;
          baseUrl = `http://127.0.0.1:${port}`;
          resolve();
        });
      });
    });

    afterEach(async () => {
      if (server) {
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
      }
    });

    function serializeBundleForHttp(bundle: SignedPackageBundle) {
      return {
        ...bundle,
        files: Object.fromEntries(bundle.files.entries()),
      };
    }

    it('API returns 400 with NOT_CONFIGURED when target provider does not exist', async () => {
      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: serializeBundleForHttp(sampleBundle),
          targetType: 'UNKNOWN_PROVIDER_TARGET',
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(400);
      expect(data.status).toBe('NOT_CONFIGURED');
      expect(data.receipt.status).toBe('NOT_CONFIGURED');
      expect(data.receipt.receipt_locator).toBeNull();
      expect(data.receipt.receipt_signature).toBeNull();
      expect(data.receipt.truthState).toBe('NOT_CONFIGURED');
    });

    it('API returns 500 with FAILED when provider delivery fails', async () => {
      const failingAdapter: IShippingTargetAdapter = {
        targetType: 'FAILING_HTTP_TARGET',
        async ship(): Promise<DeliveryReceipt> {
          throw new Error('EACCES: permission denied on destination storage');
        },
        async healthCheck() {
          return { healthy: false, details: 'Failing' };
        },
      };
      shippingService.registerAdapter(failingAdapter);

      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: serializeBundleForHttp(sampleBundle),
          targetType: 'FAILING_HTTP_TARGET',
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(500);
      expect(data.status).toBe('FAILED');
      expect(data.receipt.status).toBe('FAILED');
      expect(data.receipt.receipt_signature).toBeNull();
      expect(data.receipt.error).toContain('permission denied');
    });

    it('API returns 200 with SIMULATED_DELIVERY in development simulation', async () => {
      process.env.NODE_ENV = 'test';

      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: serializeBundleForHttp(sampleBundle),
          targetType: 'OCI_REGISTRY',
          options: {
            targetLocator: 'registry.internal.caim.security/dev/agent',
            simulate: true,
          },
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(200);
      expect(data.status).toBe('SIMULATED_DELIVERY');
      expect(data.receipt.status).toBe('SIMULATED_DELIVERY');
      expect(data.receipt.truthState).toBe('SIMULATED');
      // Crucial: CAIM never reports DELIVERED for simulations
      expect(data.receipt.status).not.toBe('DELIVERED');
      expect(data.receipt.receipt_signature).toBeNull();
    });

    it('API returns 200 with DELIVERED only when real provider succeeds', async () => {
      const stagingDir = path.resolve(`/tmp/caim-api-staging-${Date.now()}`);

      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: serializeBundleForHttp(sampleBundle),
          targetType: 'LOCAL_STAGING',
          options: {
            targetLocator: stagingDir,
          },
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(200);
      expect(data.status).toBe('DELIVERED');
      expect(data.truthState).toBe('OBSERVED');
      expect(data.receipt.status).toBe('DELIVERED');
      expect(data.receipt.receipt_locator).toContain(stagingDir);

      // Verify physical delivery
      expect(fs.existsSync(data.receipt.receipt_locator)).toBe(true);

      // Clean up
      fs.rmSync(stagingDir, { recursive: true, force: true });
    });

    // -------------------------------------------------------------------------
    // PROMPT 02R SPECIFIC INTEGRITY TESTS: REJECT FABRICATED BUNDLE INPUT
    // -------------------------------------------------------------------------

    it('PROMPT 02R: package_id only is rejected and not auto-completed', async () => {
      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          package_id: 'non-existent-pkg-001',
          targetType: 'LOCAL_STAGING',
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(400);
      expect(data.success).toBe(false);
      expect(['DATA_UNAVAILABLE', 'INVALID_BUNDLE']).toContain(data.status);
      // Ensure no fabricated receipt was synthesized
      expect(data.receipt).toBeUndefined();
    });

    it('PROMPT 02R: bundle with missing attestation is rejected', async () => {
      const incomplete = serializeBundleForHttp(sampleBundle) as any;
      delete incomplete.attestation;

      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: incomplete,
          targetType: 'LOCAL_STAGING',
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(400);
      expect(data.success).toBe(false);
      expect(['DATA_UNAVAILABLE', 'INVALID_BUNDLE']).toContain(data.status);
      expect(data.receipt).toBeUndefined();
    });

    it('PROMPT 02R: bundle with missing signature is rejected', async () => {
      const incomplete = serializeBundleForHttp(sampleBundle) as any;
      delete incomplete.signature;

      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: incomplete,
          targetType: 'LOCAL_STAGING',
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(400);
      expect(data.success).toBe(false);
      expect(['DATA_UNAVAILABLE', 'INVALID_BUNDLE']).toContain(data.status);
      expect(data.receipt).toBeUndefined();
    });

    it('PROMPT 02R: fabricated APPROVED_FOR_RELEASE payload without valid KMS signature is rejected', async () => {
      const fabricatedBundle = {
        package_id: 'fabricated-pkg-999',
        manifest: {
          manifest_version: '1.0.0',
          agent_id: 'agent-fake',
          version_label: '1.0.0',
          entrypoint: 'src/main.ts',
          contents: [],
          manifest_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          validation_reference: {
            validation_run_id: 'fake-run',
            status: 'PASSED',
            verdict: 'APPROVED_FOR_RELEASE',
            timestamp: new Date().toISOString(),
          },
          policy_reference: {
            policy_outcome: 'ALLOW',
            policy_allowed: true,
            ruleset_version: '1.0.0',
            evaluated_at: new Date().toISOString(),
          },
        },
        manifest_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        files: {},
        attestation: {
          statement_version: '1.0.0',
          predicate_type: 'https://in-toto.io/attestation/release/v1',
          subject: [
            {
              name: 'bundle.tar.gz',
              digest: { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
            },
          ],
          predicate: {
            validation_summary: {
              verdict: 'APPROVED_FOR_RELEASE',
            },
          },
        },
        signature: {
          key_id: 'fake-key-id',
          key_version: '1',
          algorithm: 'Ed25519',
          signature_id: 'fake-sig',
          signature_base64: 'auto-signed', // Fake signature
          signed_at: new Date().toISOString(),
        },
      };

      const res = await fetch(`${baseUrl}/api/packages/ship`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-role': 'CAIM_DIAGNOSTIC_ADMIN',
        },
        body: JSON.stringify({
          bundle: fabricatedBundle,
          targetType: 'LOCAL_STAGING',
        }),
      });

      const data = await res.json();
      expect(res.status).toBe(400);
      expect(data.success).toBe(false);
      expect(data.status).toBe('INVALID_BUNDLE');
      expect(data.receipt).toBeUndefined();
    });
  });
});
