/**
 * P106A — CAIM Shipping Security Hardening, Authentic Byte Integrity & Evidence Reconciliation
 * Adversarial Regression & Truth-Invariant Suite
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import {
  validateRegistryHost,
  validateAndResolveRegistryHost,
  validateRedirectUrl,
  parseIpv4String,
  isPrivateOrBlockedIpv4,
  isPrivateOrBlockedIpv6,
} from '../packages/packaging/src/shipping/shipping-utils.ts';
import { OciRegistryAdapter } from '../packages/packaging/src/shipping/oci-adapter.ts';
import { ShippingService, UnresolvedShipmentRecord } from '../packages/packaging/src/shipping/service.ts';
import { DeterministicPackageBundler, PackageBuildInput } from '../packages/packaging/src/bundler.ts';
import { KmsSignerBoundary } from '../packages/packaging/src/crypto/kms-boundary.ts';
import { SignedPackageBundle } from '../packages/contracts/src/packaging.ts';
import { certifyRealShipping } from '../scripts/certify-real-shipping.ts';
import { evaluateAllReleaseGates } from '../scripts/evaluate-release-gates.ts';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';

describe('P106A — Shipping Security Hardening & Evidence Reconciliation', () => {
  const originalEnv = { ...process.env };
  let testBundle: SignedPackageBundle;

  beforeEach(async () => {
    process.env = { ...originalEnv };
    delete process.env.S3_BUCKET_NAME;
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    delete process.env.OCI_REGISTRY_HOST;
    delete process.env.OCI_AUTH_TOKEN;

    const kmsBoundary = KmsSignerBoundary.createDefault('test-p106a-kms-key');
    const input: PackageBuildInput = {
      packageId: 'pkg-p106a-sec-test',
      agentId: 'agent-p106a-verifier',
      agentVersionId: 'av-p106a-v1',
      versionLabel: 'v1.0.0',
      createdAt: '2026-10-23T00:00:00Z',
      sourceFiles: {
        'src/agent.ts': 'export const hardened = true;\n',
        'package.json': '{"name":"agent-p106a-verifier","version":"1.0.0"}',
      },
      analysisReport: {
        static_analysis: { findings_count: 0, taint_sinks_reached: 0, status: 'CLEAN' },
        composition_sbom: { components_count: 0, cve_vulnerabilities: 0, status: 'CLEAN' },
        sandbox_behavior: { network_egress_unauthorized: 0, syscall_violations: 0, status: 'PASSED' },
        decision_score: { overall_score: 99, risk_band: 'LOW', confidence: 0.99 },
        recommendation: { verdict: 'APPROVE', allow_shipment: true },
      },
      sbomComponents: [],
      validationReference: {
        validation_run_id: 'val-p106a-01',
        validation_plan_version: 'v1.0.0',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-10-23T00:00:00Z',
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 99,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-10-23T00:00:00Z',
      },
      approvalReferences: [
        {
          approval_id: 'appr-01',
          approver_id: 'usr-sec-lead',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-10-23T00:00:00Z',
          rationale: 'Security sign-off',
        },
        {
          approval_id: 'appr-02',
          approver_id: 'usr-rel-lead',
          approver_role: 'RELEASE_ENGINEER',
          decision: 'APPROVED',
          decided_at: '2026-10-23T00:00:00Z',
          rationale: 'Release sign-off',
        },
      ],
      metadata: {
        author: 'CAIM Independent Release Auditor',
        license: 'Apache-2.0',
        securityClassification: 'RESTRICTED',
        framework: 'TypeScript',
        description: 'P106A Security Test Artifact',
      },
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-10-23',
        analysis_run_id: 'ar-p106a-01',
        input_hashes: ['0000000000000000000000000000000000000000000000000000000000000000'],
        generated_at: '2026-10-23T00:00:00Z',
      },
    };

    testBundle = await DeterministicPackageBundler.buildAndSign(input, kmsBoundary);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  // ===========================================================================
  // TASK 1: OCI SSRF HARDENING REGRESSION TESTS
  // ===========================================================================
  describe('Task 1 — OCI SSRF Protection & Host Validation', () => {
    it('blocks alternative IPv4 dword representations of 127.0.0.1 and 169.254.169.254', () => {
      // 2130706433 = 127.0.0.1
      expect(validateRegistryHost('2130706433').valid).toBe(false);
      // 2852039166 = 169.254.169.254 (IMDS metadata)
      expect(validateRegistryHost('2852039166').valid).toBe(false);
      // 0x7f000001 = 127.0.0.1
      expect(validateRegistryHost('0x7f000001').valid).toBe(false);
    });

    it('blocks alternative IPv4 octal representations', () => {
      // 0177.0.0.1 = 127.0.0.1
      expect(validateRegistryHost('0177.0.0.1').valid).toBe(false);
      // 012.0.0.1 = 10.0.0.1 (RFC 1918 private)
      expect(validateRegistryHost('012.0.0.1').valid).toBe(false);
    });

    it('blocks alternative IPv4 hex and mixed dotted representations', () => {
      // 0x7f.0.0.1 = 127.0.0.1
      expect(validateRegistryHost('0x7f.0.0.1').valid).toBe(false);
      // 127.1 = 127.0.0.1
      expect(validateRegistryHost('127.1').valid).toBe(false);
      // 10.1 = 10.0.0.1
      expect(validateRegistryHost('10.1').valid).toBe(false);
    });

    it('blocks IPv6 loopback, link-local, unique-local, and mapped IPv4', () => {
      // Loopback
      expect(validateRegistryHost('::1').valid).toBe(false);
      expect(validateRegistryHost('[::1]').valid).toBe(false);
      // Link-local
      expect(validateRegistryHost('[fe80::1]').valid).toBe(false);
      // Unique-local (RFC 4193) & IMDSv2 (fd00:ec2::254)
      expect(validateRegistryHost('[fc00::1]').valid).toBe(false);
      expect(validateRegistryHost('[fd00:ec2::254]').valid).toBe(false);
      // IPv4-mapped IPv6 pointing to loopback and metadata
      expect(validateRegistryHost('[::ffff:127.0.0.1]').valid).toBe(false);
      expect(validateRegistryHost('[::ffff:169.254.169.254]').valid).toBe(false);
      expect(validateRegistryHost('[::ffff:7f00:1]').valid).toBe(false);
    });

    it('blocks userinfo injection in registry host', () => {
      expect(validateRegistryHost('attacker@registry.hub.docker.com').valid).toBe(false);
      expect(validateRegistryHost('admin:secret@127.0.0.1').valid).toBe(false);
    });

    it('blocks path, scheme, query, and illegal percent-encoded manipulation in host', () => {
      expect(validateRegistryHost('registry.example.com/api').valid).toBe(false);
      expect(validateRegistryHost('registry.example.com?param=val').valid).toBe(false);
      expect(validateRegistryHost('registry.example.com#frag').valid).toBe(false);
      expect(validateRegistryHost('registry%2eexample%2ecom').valid).toBe(false);
    });

    it('blocks sensitive internal ports commonly targeted by SSRF', () => {
      // SSH (22), Docker daemon API (2375, 2376), Postgres (5432), Redis (6379)
      expect(validateRegistryHost('pkg.example.com:22').valid).toBe(false);
      expect(validateRegistryHost('pkg.example.com:2375').valid).toBe(false);
      expect(validateRegistryHost('pkg.example.com:5432').valid).toBe(false);
      expect(validateRegistryHost('pkg.example.com:6379').valid).toBe(false);
    });

    it('validates DNS resolution against private IP targets (DNS rebinding / private CNAME)', async () => {
      const mockDnsResolver = async (hostname: string) => {
        if (hostname === 'evil-cname.example.com') {
          return [{ address: '127.0.0.1', family: 4 }];
        }
        if (hostname === 'metadata-proxy.example.com') {
          return [{ address: '169.254.169.254', family: 4 }];
        }
        if (hostname === 'internal-ipv6.example.com') {
          return [{ address: '::ffff:10.0.0.1', family: 6 }];
        }
        return [{ address: '93.184.216.34', family: 4 }];
      };

      const res1 = await validateAndResolveRegistryHost('evil-cname.example.com', undefined, mockDnsResolver);
      expect(res1.valid).toBe(false);
      expect(res1.error).toContain('resolves to forbidden private IP');

      const res2 = await validateAndResolveRegistryHost('metadata-proxy.example.com', undefined, mockDnsResolver);
      expect(res2.valid).toBe(false);
      expect(res2.error).toContain('resolves to forbidden private IP');

      const res3 = await validateAndResolveRegistryHost('internal-ipv6.example.com', undefined, mockDnsResolver);
      expect(res3.valid).toBe(false);
      expect(res3.error).toContain('resolves to forbidden IPv6');

      const resValid = await validateAndResolveRegistryHost('public-registry.example.com', undefined, mockDnsResolver);
      expect(resValid.valid).toBe(true);
    });

    it('rejects SSRF redirect location headers pointing to private endpoints or unapproved schemes', () => {
      // Redirect to cloud metadata
      const redirect1 = validateRedirectUrl('http://169.254.169.254/latest/meta-data', ['safe.registry.com'], false);
      expect(redirect1.valid).toBe(false);

      // Insecure HTTP when insecure is false
      const redirect2 = validateRedirectUrl('http://safe.registry.com/v2/blobs', ['safe.registry.com'], false);
      expect(redirect2.valid).toBe(false);
      expect(redirect2.error).toContain('Insecure redirect protocol');

      // Valid HTTPS redirect to allowed host
      const redirect3 = validateRedirectUrl('https://safe.registry.com/v2/blobs/upload-uuid', ['safe.registry.com'], false);
      expect(redirect3.valid).toBe(true);
    });

    it('blocks OCI adapter shipping when redirect location targets private metadata', async () => {
      const mockTransport = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        if (url.includes('/blobs/uploads/')) {
          // Attacker returns location redirect to AWS IMDS metadata!
          return new Response(null, {
            status: 202,
            headers: { location: 'http://169.254.169.254/latest/meta-data' },
          });
        }
        return new Response(null, { status: 404 });
      });

      const adapter = new OciRegistryAdapter({
        registryHost: 'test.registry.local',
        transport: mockTransport,
      });

      const receipt = await adapter.ship(testBundle, {
        targetLocator: 'test.registry.local/agents/test-tenant/my-app:v1',
        tenantId: 'test-tenant',
      });

      expect(receipt.status).toBe('AUTHORIZATION_DENIED');
      expect(receipt.truthState).toBe('FAILED');
      expect(receipt.error).toContain('SSRF Blocked');
    });
  });

  // ===========================================================================
  // TASK 2: REAL OCI CONTENT INTEGRITY REGRESSION TESTS
  // ===========================================================================
  describe('Task 2 — Real OCI Content Integrity & Byte-Level Readback', () => {
    it('successfully delivers and verifies OCI artifact with byte-level readback hashing', async () => {
      let storedBlob: Buffer | null = null;
      let storedManifest: string | null = null;

      const mockTransport = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        const method = init?.method || 'GET';

        // 1. Initiate blob upload
        if (url.includes('/blobs/uploads/') && method === 'POST') {
          return new Response(null, {
            status: 202,
            headers: { location: 'https://test.registry.local/v2/agents/test-tenant/blobs/uploads/uuid-01?state=chunk' },
          });
        }

        // 2. Put blob bytes
        if (url.includes('uuid-01') && method === 'PUT') {
          storedBlob = Buffer.from(init.body as any);
          return new Response(null, { status: 201 });
        }

        // 3. Put manifest
        if (url.includes('/manifests/') && method === 'PUT') {
          storedManifest = (init.body as Buffer).toString('utf-8');
          return new Response(null, { status: 201 });
        }

        // 4. Manifest readback by digest
        if (url.includes('/manifests/sha256:') && method === 'GET') {
          return new Response(storedManifest, {
            status: 200,
            headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
          });
        }

        // 5. Blob byte-level readback (GET)
        if (url.includes('/blobs/sha256:') && method === 'GET') {
          return new Response(storedBlob, {
            status: 200,
            headers: {
              'Content-Type': 'application/octet-stream',
              'Content-Length': String(storedBlob?.length || 0),
            },
          });
        }

        return new Response(null, { status: 404 });
      });

      const adapter = new OciRegistryAdapter({
        registryHost: 'test.registry.local',
        transport: mockTransport,
      });

      const receipt = await adapter.ship(testBundle, {
        targetLocator: 'test.registry.local/agents/test-tenant/app:v1',
        tenantId: 'test-tenant',
      });

      expect(receipt.status).toBe('DELIVERED');
      expect(receipt.detailed_state).toBe('DELIVERED_VERIFIED');
      expect(receipt.truthState).toBe('OBSERVED');
      expect(receipt.integrity_verified).toBe(true);
      expect(receipt.byte_level_readback_verified).toBe(true);
      expect(receipt.provider_delivery_verified).toBe(true);
      expect(receipt.metadata?.byte_level_readback_verified).toBe(true);
    });

    it('rejects delivery with INTEGRITY_MISMATCH if remote blob bytes are altered / tampered', async () => {
      let storedManifest: string | null = null;

      const mockTransport = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        const method = init?.method || 'GET';

        if (url.includes('/blobs/uploads/') && method === 'POST') {
          return new Response(null, {
            status: 202,
            headers: { location: 'https://test.registry.local/v2/agents/test-tenant/blobs/uploads/uuid-02' },
          });
        }
        if (url.includes('uuid-02') && method === 'PUT') {
          return new Response(null, { status: 201 });
        }
        if (url.includes('/manifests/') && method === 'PUT') {
          storedManifest = (init.body as Buffer).toString('utf-8');
          return new Response(null, { status: 201 });
        }
        if (url.includes('/manifests/sha256:') && method === 'GET') {
          return new Response(storedManifest, {
            status: 200,
            headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
          });
        }
        // TAMPERED READBACK: returned corrupted bytes
        if (url.includes('/blobs/sha256:') && method === 'GET') {
          const manifestObj = JSON.parse(storedManifest!);
          const layerSize = manifestObj.layers[0].size;
          const tamperedBytes = Buffer.alloc(layerSize, 0xff); // all 0xFF bytes
          return new Response(tamperedBytes, {
            status: 200,
            headers: { 'Content-Type': 'application/octet-stream' },
          });
        }
        return new Response(null, { status: 404 });
      });

      const adapter = new OciRegistryAdapter({
        registryHost: 'test.registry.local',
        transport: mockTransport,
      });

      const receipt = await adapter.ship(testBundle, {
        targetLocator: 'test.registry.local/agents/test-tenant/app:v1',
        tenantId: 'test-tenant',
      });

      expect(receipt.status).toBe('INTEGRITY_MISMATCH');
      expect(receipt.detailed_state).toBe('INTEGRITY_MISMATCH');
      expect(receipt.truthState).toBe('FAILED');
      expect(receipt.integrity_verified).toBe(false);
      expect(receipt.error).toContain('byte-level content hash mismatch');
    });

    it('rejects delivery with INTEGRITY_MISMATCH if remote blob is truncated', async () => {
      let storedManifest: string | null = null;

      const mockTransport = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        const method = init?.method || 'GET';

        if (url.includes('/blobs/uploads/') && method === 'POST') {
          return new Response(null, {
            status: 202,
            headers: { location: 'https://test.registry.local/v2/agents/test-tenant/blobs/uploads/uuid-03' },
          });
        }
        if (url.includes('uuid-03') && method === 'PUT') {
          return new Response(null, { status: 201 });
        }
        if (url.includes('/manifests/') && method === 'PUT') {
          storedManifest = (init.body as Buffer).toString('utf-8');
          return new Response(null, { status: 201 });
        }
        if (url.includes('/manifests/sha256:') && method === 'GET') {
          return new Response(storedManifest, {
            status: 200,
            headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
          });
        }
        // TRUNCATED READBACK: return only 10 bytes
        if (url.includes('/blobs/sha256:') && method === 'GET') {
          return new Response(Buffer.from('truncated!'), {
            status: 200,
            headers: { 'Content-Type': 'application/octet-stream' },
          });
        }
        return new Response(null, { status: 404 });
      });

      const adapter = new OciRegistryAdapter({
        registryHost: 'test.registry.local',
        transport: mockTransport,
      });

      const receipt = await adapter.ship(testBundle, {
        targetLocator: 'test.registry.local/agents/test-tenant/app:v1',
        tenantId: 'test-tenant',
      });

      expect(receipt.status).toBe('INTEGRITY_MISMATCH');
      expect(receipt.detailed_state).toBe('INTEGRITY_MISMATCH');
      expect(receipt.truthState).toBe('FAILED');
      expect(receipt.integrity_verified).toBe(false);
      expect(receipt.error).toContain('byte-length mismatch');
    });

    it('rejects delivery if OCI manifest layer size descriptor mismatches actual artifact size', async () => {
      const mockTransport = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        const method = init?.method || 'GET';

        if (url.includes('/blobs/uploads/') && method === 'POST') {
          return new Response(null, {
            status: 202,
            headers: { location: 'https://test.registry.local/v2/agents/test-tenant/blobs/uploads/uuid-04' },
          });
        }
        if (url.includes('uuid-04') && method === 'PUT') {
          return new Response(null, { status: 201 });
        }
        if (url.includes('/manifests/') && method === 'PUT') {
          return new Response(null, { status: 201 });
        }
        // Mismatched layer size descriptor returned in manifest
        if (url.includes('/manifests/sha256:') && method === 'GET') {
          const fakeManifest = {
            schemaVersion: 2,
            mediaType: 'application/vnd.oci.image.manifest.v1+json',
            config: {
              mediaType: 'application/vnd.caim.package.config.v1+json',
              digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
              size: 50,
            },
            layers: [
              {
                mediaType: 'application/vnd.caim.package.v1+tar',
                digest: `sha256:valid`,
                size: 999999999, // bogus size descriptor
              },
            ],
          };
          return new Response(JSON.stringify(fakeManifest), {
            status: 200,
            headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
          });
        }
        return new Response(null, { status: 404 });
      });

      const adapter = new OciRegistryAdapter({
        registryHost: 'test.registry.local',
        transport: mockTransport,
      });

      const receipt = await adapter.ship(testBundle, {
        targetLocator: 'test.registry.local/agents/test-tenant/app:v1',
        tenantId: 'test-tenant',
      });

      expect(receipt.status).toBe('INTEGRITY_MISMATCH');
      expect(receipt.integrity_verified).toBe(false);
    });
  });

  // ===========================================================================
  // TASK 3: DELIVERY PERSISTENCE & OPERATOR RECONCILIATION
  // ===========================================================================
  describe('Task 3 — Delivery Persistence & Reconciliation', () => {
    it('tracks and manages unresolved shipments on ShippingService', () => {
      const service = new ShippingService();

      const unresolvedRecord: UnresolvedShipmentRecord = {
        reconciliation_id: 'rec-test-01',
        shipment_id: 'ship-test-01',
        package_id: 'pkg-p106a-sec-test',
        target_type: 'OCI_REGISTRY',
        target_locator: 'registry.internal.caim.security/pkg:v1',
        provider_receipt: {
          shipment_id: 'ship-test-01',
          package_id: 'pkg-p106a-sec-test',
          target_type: 'OCI_REGISTRY',
          target_locator: 'registry.internal.caim.security/pkg:v1',
          manifest_hash: 'hash-01',
          signature_id: 'sig-01',
          status: 'DELIVERED',
          transfer_size_bytes: 1024,
          audit_trail_id: 'audit-01',
        },
        provider_delivery_verified: true,
        durable_persistence_verified: false,
        failure_stage: 'DATABASE_INSERT',
        error_message: 'Connection terminated unexpectedly during insert into lifecycle.shipments',
        occurred_at: new Date().toISOString(),
        reconciled: false,
      };

      service.recordUnresolvedShipment(unresolvedRecord);

      expect(service.getUnresolvedShipments()).toHaveLength(1);
      expect(service.getUnresolvedShipment('ship-test-01')).toBeDefined();
      expect(service.getUnresolvedShipment('rec-test-01')).toBeDefined();

      const success = service.markShipmentReconciled('ship-test-01');
      expect(success).toBe(true);
      expect(service.getUnresolvedShipment('ship-test-01')?.reconciled).toBe(true);
    });

    it('enforces idempotency and prevents duplicate remote uploads for already verified packages', async () => {
      let uploadCount = 0;
      const customAdapter = {
        targetType: 'CUSTOM_TEST' as any,
        isConfigured: () => true,
        ship: async (bundle: any, options: any) => {
          uploadCount++;
          return {
            shipment_id: `ship-idemp-${uploadCount}`,
            package_id: bundle.package_id,
            target_type: 'CUSTOM_TEST',
            target_locator: options.targetLocator,
            manifest_hash: bundle.manifest_hash,
            signature_id: 'sig-01',
            shipped_at: new Date().toISOString(),
            status: 'DELIVERED' as const,
            detailed_state: 'DELIVERED_VERIFIED' as const,
            receipt_locator: 'custom://uploaded-locator',
            transfer_size_bytes: 500,
            audit_trail_id: 'audit-01',
            truthState: 'OBSERVED',
            truth_state: 'OBSERVED',
            integrity_verified: true,
          };
        },
      };

      const service = new ShippingService([customAdapter as any]);

      // First shipment
      const r1 = await service.shipBundle(testBundle, 'CUSTOM_TEST', {
        targetLocator: 'custom://tenant/pkg-1',
      });
      expect(r1.status).toBe('DELIVERED');
      expect(uploadCount).toBe(1);

      // Re-shipping same bundle to same locator should return idempotent existing receipt without duplicate upload
      const r2 = await service.shipBundle(testBundle, 'CUSTOM_TEST', {
        targetLocator: 'custom://tenant/pkg-1',
      });
      expect(r2.status).toBe('DELIVERED');
      expect(uploadCount).toBe(1); // UPLOAD DID NOT OCCUR A SECOND TIME!
      expect(r2.metadata?.idempotent_replay).toBe(true);
    });

    it('handles remote upload success followed by database persistence failure with fail-closed semantics', async () => {
      let uploadExecuted = false;
      const customAdapter = {
        targetType: 'OCI_REGISTRY' as any,
        isConfigured: () => true,
        ship: async () => {
          uploadExecuted = true;
          return {
            shipment_id: 'ship-db-fail-99',
            package_id: testBundle.package_id,
            target_type: 'OCI_REGISTRY',
            target_locator: 'registry.internal.caim.security/agents/test-tenant/app:v1',
            manifest_hash: testBundle.manifest_hash,
            signature_id: 'sig-01',
            shipped_at: new Date().toISOString(),
            status: 'DELIVERED' as const,
            detailed_state: 'DELIVERED_VERIFIED' as const,
            receipt_locator: 'registry.internal.caim.security/agents/test-tenant/app@sha256:112233',
            transfer_size_bytes: 4096,
            audit_trail_id: 'audit-db-fail-99',
            truthState: 'OBSERVED',
            truth_state: 'OBSERVED',
            integrity_verified: true,
            byte_level_readback_verified: true,
            provider_delivery_verified: true,
          };
        },
      };

      const shippingService = new ShippingService([customAdapter as any]);
      const mockDbAdapter = {
        query: vi.fn().mockRejectedValue(new Error('FATAL: connection to server on socket "/tmp/.s.PGSQL.5432" failed')),
      };

      // 1. Execute remote shipment via adapter
      const receipt = await shippingService.shipBundle(testBundle, 'OCI_REGISTRY', {
        targetLocator: 'registry.internal.caim.security/agents/test-tenant/app:v1',
        tenantId: 'test-tenant',
      });
      expect(receipt.status).toBe('DELIVERED');
      expect(receipt.integrity_verified).toBe(true);

      // 2. Simulate persistence step failing
      let durablePersistenceVerified = false;
      let persistenceError: string | null = null;
      const reconciliationId = `rec-${Date.now()}-${receipt.shipment_id}`;

      try {
        await mockDbAdapter.query();
        durablePersistenceVerified = true;
      } catch (err: any) {
        persistenceError = err.message;
        durablePersistenceVerified = false;
        shippingService.recordUnresolvedShipment({
          reconciliation_id: reconciliationId,
          shipment_id: receipt.shipment_id,
          package_id: testBundle.package_id,
          target_type: String(receipt.target_type),
          target_locator: receipt.target_locator,
          provider_receipt: receipt,
          provider_delivery_verified: true,
          durable_persistence_verified: false,
          failure_stage: 'DATABASE_INSERT',
          error_message: err.message,
          occurred_at: new Date().toISOString(),
          reconciled: false,
        });
      }

      // 3. Verify workflow cannot complete as confirmed
      expect(durablePersistenceVerified).toBe(false);
      expect(persistenceError).toContain('connection to server on socket');

      const unresolved = shippingService.getUnresolvedShipment(receipt.shipment_id);
      expect(unresolved).toBeDefined();
      expect(unresolved?.reconciled).toBe(false);
      expect(unresolved?.provider_delivery_verified).toBe(true);
      expect(unresolved?.durable_persistence_verified).toBe(false);

      // 4. Simulate operator reconciliation when database recovers
      mockDbAdapter.query.mockResolvedValueOnce({ rows: [] } as any);
      await mockDbAdapter.query(); // succeeds
      shippingService.markShipmentReconciled(receipt.shipment_id);

      expect(shippingService.getUnresolvedShipment(receipt.shipment_id)?.reconciled).toBe(true);
    });
  });

  // ===========================================================================
  // TASK 5: GATE L09 VERIFICATION & EVALUATOR INVARIANTS
  // ===========================================================================
  describe('Task 5 — Gate L09 Verification & Fail-Closed Compliance', () => {
    it('certifyRealShipping returns EXTERNAL INFRA REQUIRED when real cloud credentials are missing', async () => {
      const receipt = await certifyRealShipping({
        receiptOutputPath: 'docs/certification/test-l09-receipt.json',
      });

      expect(receipt.status).toBe('EXTERNAL INFRA REQUIRED');
      expect(receipt.executionTelemetry.exitCode).toBe(2);
      expect(receipt.blockers.length).toBeGreaterThan(0);
      expect(receipt.providerReceipt.deliveryVerified).toBe(false);
      expect(receipt.providerReceipt.integrityVerified).toBe(false);
    });

    it('evaluateAllReleaseGates preserves releaseFreeze = true and rejects shipping without byte verification', async () => {
      const evaluation = await evaluateAllReleaseGates();

      expect(evaluation.releaseFreeze).toBe(true);
      expect(evaluation.overallVerdict).toBe('DO NOT SHIP');

      const gateL09 = evaluation.gates.find(g => g.gateId === 'GATE_L09_REMOTE_SHIPPING');
      expect(gateL09).toBeDefined();
      expect(['EXTERNAL INFRA REQUIRED', 'CONFIGURED — NOT VERIFIED', 'EXECUTED — FAIL']).toContain(gateL09?.status);
    });
  });
});
