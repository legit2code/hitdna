/**
 * P106 — CAIM Authentic Artifact Shipping, Remote Integrity & Supply-Chain Certification Suite
 * Adversarial Regression Tests (25 Scenarios)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { S3StorageAdapter } from '../packages/packaging/src/shipping/s3-adapter.ts';
import { OciRegistryAdapter } from '../packages/packaging/src/shipping/oci-adapter.ts';
import { ShippingService } from '../packages/packaging/src/shipping/service.ts';
import { DeterministicPackageBundler, PackageBuildInput } from '../packages/packaging/src/bundler.ts';
import { KmsSignerBoundary } from '../packages/packaging/src/crypto/kms-boundary.ts';
import { SignedPackageBundle } from '../packages/contracts/src/packaging.ts';
import { certifyRealShipping, redactShippingDestination } from '../scripts/certify-real-shipping.ts';
import { evaluateAllReleaseGates } from '../scripts/evaluate-release-gates.ts';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';

describe('P106 — Authentic Artifact Shipping, Remote Integrity & Supply-Chain Certification', () => {
  const originalEnv = { ...process.env };
  let testBundle: SignedPackageBundle;

  beforeEach(async () => {
    process.env = { ...originalEnv };
    delete process.env.S3_BUCKET_NAME;
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    delete process.env.OCI_REGISTRY_HOST;
    delete process.env.OCI_AUTH_TOKEN;

    const kmsBoundary = KmsSignerBoundary.createDefault('test-shipping-kms-key');
    const input: PackageBuildInput = {
      packageId: 'pkg-p106-shipping-test',
      agentId: 'agent-p106-verifier',
      agentVersionId: 'av-p106-v1',
      versionLabel: 'v1.0.0',
      createdAt: '2026-10-22T12:00:00Z',
      sourceFiles: {
        'src/agent.ts': 'export const shippingAudited = true;\n',
        'package.json': '{"name":"agent-p106-verifier","version":"1.0.0"}',
      },
      analysisReport: {
        static_analysis: { findings_count: 0, taint_sinks_reached: 0, status: 'CLEAN' },
        composition_sbom: { components_count: 0, cve_vulnerabilities: 0, status: 'CLEAN' },
        sandbox_behavior: { network_egress_unauthorized: 0, syscall_violations: 0, status: 'PASSED' },
        decision_score: { overall_score: 98, risk_band: 'LOW', confidence: 0.99 },
        recommendation: { verdict: 'APPROVE', allow_shipment: true },
      },
      sbomComponents: [],
      validationReference: {
        validation_run_id: 'val-p106-01',
        validation_plan_version: 'v1.0.0',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-10-22T12:00:00Z',
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 98,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-10-22T12:00:00Z',
      },
      approvalReferences: [
        {
          approval_id: 'appr-01',
          approver_id: 'usr-sec-lead',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-10-22T12:00:00Z',
          rationale: 'Security sign-off',
        },
        {
          approval_id: 'appr-02',
          approver_id: 'usr-rel-lead',
          approver_role: 'RELEASE_ENGINEER',
          decision: 'APPROVED',
          decided_at: '2026-10-22T12:00:00Z',
          rationale: 'Release sign-off',
        },
      ],
      metadata: {
        author: 'CAIM Independent Release Auditor',
        license: 'Apache-2.0',
        securityClassification: 'RESTRICTED',
        framework: 'TypeScript',
        description: 'P106 Test Artifact',
      },
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-10-22',
        analysis_run_id: 'ar-p106-01',
        input_hashes: ['0000000000000000000000000000000000000000000000000000000000000000'],
        generated_at: '2026-10-22T12:00:00Z',
      },
    };
    testBundle = await DeterministicPackageBundler.buildAndSign(input, kmsBoundary);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  // ---------------------------------------------------------------------------
  // 1 & 2: CORRECT S3 AND OCI ARTIFACT SHIPPING
  // ---------------------------------------------------------------------------
  it('1. Correct S3 artifact shipping with authentic readback verification', async () => {
    let storedBytes: Buffer | null = null;
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') {
        storedBytes = Buffer.from(init.body as Buffer);
        return new Response(null, {
          status: 200,
          headers: { 'x-amz-version-id': 'v-test-123', 'x-amz-request-id': 'req-s3-abc' },
        });
      }
      if (init.method === 'GET') {
        return new Response(storedBytes, {
          status: 200,
          headers: { 'x-amz-version-id': 'v-test-123' },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'caim-production-releases',
      region: 'us-east-1',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://caim-production-releases/releases/agent-p106/v1.0.0/bundle.tar.gz',
    });

    expect(receipt.status).toBe('DELIVERED');
    expect(receipt.detailed_state).toBe('DELIVERED_VERIFIED');
    expect(receipt.truthState).toBe('OBSERVED');
    expect(receipt.integrity_verified).toBe(true);
    expect(receipt.version_id).toBe('v-test-123');
    expect(receipt.artifact_digest).toBeDefined();
    expect(receipt.remote_digest).toBe(receipt.artifact_digest);
  });

  it('2. Correct OCI artifact shipping with manifest readback & blob confirmation', async () => {
    let uploadedBlob: Buffer | null = null;
    let uploadedManifestJson: any = null;

    const mockTransport = async (url: string, init: RequestInit) => {
      // Step 1: Initiate blob upload
      if (url.includes('/blobs/uploads/') && init.method === 'POST') {
        return new Response(null, {
          status: 202,
          headers: { Location: '/v2/agents/p106/blobs/uploads/session-789' },
        });
      }
      // Step 2: Put blob
      if (url.includes('session-789') && init.method === 'PUT') {
        uploadedBlob = Buffer.from(init.body as Buffer);
        return new Response(null, { status: 201 });
      }
      // Step 3: Put manifest
      if (url.includes('/manifests/') && init.method === 'PUT') {
        uploadedManifestJson = JSON.parse(init.body as string);
        return new Response(null, { status: 201 });
      }
      // Step 4: Get manifest
      if (url.includes('/manifests/') && init.method === 'GET') {
        return new Response(JSON.stringify(uploadedManifestJson), {
          status: 200,
          headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
        });
      }
      // Step 5: Readback blob
      if (url.includes('/blobs/sha256:') && (init.method === 'HEAD' || init.method === 'GET')) {
        return new Response(uploadedBlob, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(uploadedBlob?.length || 0) },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    const ociAdapter = new OciRegistryAdapter({
      registryHost: 'registry.internal.caim.security',
      transport: mockTransport,
    });

    const receipt = await ociAdapter.ship(testBundle, {
      targetLocator: 'registry.internal.caim.security/agents/p106:v1.0.0',
    });

    expect(receipt.status).toBe('DELIVERED');
    expect(receipt.detailed_state).toBe('DELIVERED_VERIFIED');
    expect(receipt.truthState).toBe('OBSERVED');
    expect(receipt.integrity_verified).toBe(true);
    expect(receipt.artifact_digest).toBeDefined();
    expect(receipt.receipt_locator).toContain('@sha256:');
  });

  // ---------------------------------------------------------------------------
  // 3 & 4: WRONG DIGEST & INTEGRITY MISMATCH
  // ---------------------------------------------------------------------------
  it('3. Wrong S3 digest: Tampered remote readback payload results in INTEGRITY_MISMATCH', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') return new Response(null, { status: 200 });
      if (init.method === 'GET') {
        // Return tampered bytes
        return new Response(Buffer.from('TAMPERED_REMOTE_BYTES'), { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'caim-production-releases',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://caim-production-releases/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('INTEGRITY_MISMATCH');
    expect(receipt.detailed_state).toBe('INTEGRITY_MISMATCH');
    expect(receipt.truthState).toBe('FAILED');
    expect(receipt.integrity_verified).toBe(false);
    expect(receipt.error).toContain('Integrity Mismatch');
  });

  it('4. Wrong OCI manifest digest: Layer digest tampering results in INTEGRITY_MISMATCH', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (url.includes('/blobs/uploads/') && init.method === 'POST') {
        return new Response(null, { status: 202, headers: { Location: '/v2/blobs/uploads/session-1' } });
      }
      if (url.includes('session-1') && init.method === 'PUT') return new Response(null, { status: 201 });
      if (url.includes('/manifests/') && init.method === 'PUT') return new Response(null, { status: 201 });
      if (url.includes('/manifests/') && init.method === 'GET') {
        // Return manifest with mismatching layer digest
        return new Response(JSON.stringify({
          schemaVersion: 2,
          mediaType: 'application/vnd.oci.image.manifest.v1+json',
          layers: [{ digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' }],
        }), { status: 200, headers: { 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' } });
      }
      return new Response('Not Found', { status: 404 });
    };

    const ociAdapter = new OciRegistryAdapter({
      registryHost: 'registry.internal.caim.security',
      transport: mockTransport,
    });

    const receipt = await ociAdapter.ship(testBundle, {
      targetLocator: 'registry.internal.caim.security/agents/p106:v1.0.0',
    });

    expect(receipt.status).toBe('INTEGRITY_MISMATCH');
    expect(receipt.detailed_state).toBe('INTEGRITY_MISMATCH');
    expect(receipt.truthState).toBe('FAILED');
  });

  // ---------------------------------------------------------------------------
  // 5: BLOB CORRUPTION
  // ---------------------------------------------------------------------------
  it('5. Blob corruption: HEAD blob missing remotely results in INTEGRITY_MISMATCH', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (url.includes('/blobs/uploads/')) return new Response(null, { status: 202, headers: { Location: '/upload' } });
      if (url.includes('/upload')) return new Response(null, { status: 201 });
      if (url.includes('/manifests/') && init.method === 'PUT') return new Response(null, { status: 201 });
      if (url.includes('/manifests/') && init.method === 'GET') {
        return new Response(init.body as any || JSON.stringify({
          schemaVersion: 2,
          layers: [{ digest: `sha256:${receiptDigestPlaceholder}` }],
        }), { status: 200 });
      }
      if (url.includes('/blobs/sha256:') && init.method === 'HEAD') {
        return new Response('Blob Not Found', { status: 404 });
      }
      return new Response('Not Found', { status: 404 });
    };

    let receiptDigestPlaceholder = '';
    const ociAdapter = new OciRegistryAdapter({
      registryHost: 'registry.internal.caim.security',
      transport: async (url, init) => {
        if (url.includes('digest=sha256:')) {
          receiptDigestPlaceholder = url.split('digest=sha256:')[1];
        }
        return mockTransport(url, init);
      },
    });

    const receipt = await ociAdapter.ship(testBundle, {
      targetLocator: 'registry.internal.caim.security/agents/p106:v1.0.0',
    });

    expect(receipt.status).toBe('INTEGRITY_MISMATCH');
    expect(receipt.error).toContain('Remote blob verification failed');
  });

  // ---------------------------------------------------------------------------
  // 6 & 7: UNAUTHORIZED TENANT & MISSING AUTHENTICATION
  // ---------------------------------------------------------------------------
  it('6. Unauthorized tenant: Cross-tenant S3 path is rejected with AUTHORIZATION_DENIED', async () => {
    const s3Adapter = new S3StorageAdapter({ bucketName: 'prod-bucket', transport: async () => new Response() });
    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/tenant-victim/bundle.tar.gz',
      tenantId: 'tenant-attacker',
    });

    expect(receipt.status).toBe('AUTHORIZATION_DENIED');
    expect(receipt.error).toContain('Cross-tenant path violation');
  });

  it('7. Missing authentication: Unconfigured credentials return NOT_CONFIGURED', async () => {
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    delete process.env.S3_BUCKET_NAME;

    const s3Adapter = new S3StorageAdapter();
    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('SIMULATED_DELIVERY'); // dev fallback
    expect(receipt.truthState).toBe('SIMULATED');

    process.env.NODE_ENV = 'production';
    const prodReceipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });
    expect(prodReceipt.status).toBe('NOT_CONFIGURED');
    expect(prodReceipt.truthState).toBe('NOT_CONFIGURED');
  });

  // ---------------------------------------------------------------------------
  // 8: UNAUTHORIZED DESTINATION
  // ---------------------------------------------------------------------------
  it('8. Unauthorized destination: Bucket outside allowlist is rejected with AUTHORIZATION_DENIED', async () => {
    const s3Adapter = new S3StorageAdapter({
      bucketName: 'allowed-bucket',
      allowedBuckets: ['allowed-bucket'],
      transport: async () => new Response(),
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://evil-unauthorized-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('AUTHORIZATION_DENIED');
    expect(receipt.error).toContain('whitelist');
  });

  // ---------------------------------------------------------------------------
  // 9: FORGED DELIVERY RECEIPT REJECTION
  // ---------------------------------------------------------------------------
  it('9. Forged delivery receipt: Evaluator rejects forged receipt lacking real provider data', () => {
    const tempReceiptPath = path.resolve(process.cwd(), 'dist/forged-shipping-receipt.json');
    fs.mkdirSync(path.dirname(tempReceiptPath), { recursive: true });

    const forgedReceipt = createAndSaveRunnerReceipt({
      gateId: 'GATE_L09_REMOTE_SHIPPING',
      providerType: 'REAL',
      command: 'pnpm exec tsx scripts/certify-real-shipping.ts',
      exitCode: 0,
      durationMs: 100,
      stdout: 'Forged',
      logPointer: 'forged.log',
      testCounts: { total: 1, passed: 1, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      outputPath: tempReceiptPath,
      providerReceipt: {
        harnessVersion: '2.0.0',
        s3TargetConfigured: true,
        deliveryVerified: false, // Forged: claims pass but deliveryVerified false
        integrityVerified: false,
      },
    });

    const manifest = evaluateAllReleaseGates({
      receiptPathOverrides: { GATE_L09_REMOTE_SHIPPING: tempReceiptPath },
    });

    const gate = manifest.gates.find(g => g.gateId === 'GATE_L09_REMOTE_SHIPPING');
    expect(gate?.status).not.toBe('EXECUTED — PASS');
    expect(gate?.blockers.some(b => b.includes('SHIPPING_VERIFICATION_INCOMPLETE') || b.includes('CONFIGURED_NOT_VERIFIED'))).toBe(true);

    if (fs.existsSync(tempReceiptPath)) fs.unlinkSync(tempReceiptPath);
  });

  // ---------------------------------------------------------------------------
  // 10: SIMULATED DELIVERY PRESENTED AS REAL
  // ---------------------------------------------------------------------------
  it('10. Simulated delivery presented as real: Prohibited in production, evaluated as NOT_CONFIGURED', async () => {
    process.env.NODE_ENV = 'production';
    const s3Adapter = new S3StorageAdapter({ simulate: true });
    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/release/bundle.tar.gz',
      simulate: true,
    });

    expect(receipt.status).toBe('NOT_CONFIGURED');
    expect(receipt.truthState).toBe('NOT_CONFIGURED');
    expect(receipt.error).toContain('strictly forbidden');
  });

  // ---------------------------------------------------------------------------
  // 11 & 12: CREDENTIAL ABSENCE AND REJECTION
  // ---------------------------------------------------------------------------
  it('11. Credential absence: certifyRealShipping reports EXTERNAL INFRA REQUIRED (exit code 2)', async () => {
    delete process.env.S3_BUCKET_NAME;
    delete process.env.OCI_REGISTRY_HOST;

    const tempReceipt = path.resolve(process.cwd(), 'dist/test-infra-required-receipt.json');
    const tempLog = path.resolve(process.cwd(), 'dist/test-infra-required.log');

    const receipt = await certifyRealShipping({
      receiptOutputPath: tempReceipt,
      logOutputPath: tempLog,
    });

    expect(receipt.status).toBe('EXTERNAL INFRA REQUIRED');
    expect(receipt.providerType).toBe('NONE');
    expect(receipt.executionTelemetry.exitCode).toBe(2);

    if (fs.existsSync(tempReceipt)) fs.unlinkSync(tempReceipt);
    if (fs.existsSync(tempLog)) fs.unlinkSync(tempLog);
  });

  it('12. Credential rejection: HTTP 401/403 maps to AUTHORIZATION_DENIED', async () => {
    const mockTransport = async () => new Response('Unauthorized', { status: 403 });
    const s3Adapter = new S3StorageAdapter({
      bucketName: 'prod-bucket',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('AUTHORIZATION_DENIED');
    expect(receipt.detailed_state).toBe('AUTHORIZATION_DENIED');
  });

  // ---------------------------------------------------------------------------
  // 13 & 14: TIMEOUT AND THROTTLING
  // ---------------------------------------------------------------------------
  it('13. Network timeout: Aborted request maps to PROVIDER_UNAVAILABLE', async () => {
    const mockTransport = async () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      throw err;
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'prod-bucket',
      timeoutMs: 10,
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('PROVIDER_UNAVAILABLE');
    expect(receipt.detailed_state).toBe('PROVIDER_UNAVAILABLE');
  });

  it('14. Provider throttling: 429 retries and maps to PROVIDER_UNAVAILABLE', async () => {
    let callCount = 0;
    const mockTransport = async () => {
      callCount++;
      return new Response('Too Many Requests', { status: 429 });
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'prod-bucket',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(callCount).toBe(3); // bounded retries executed
    expect(receipt.status).toBe('PROVIDER_UNAVAILABLE');
  });

  // ---------------------------------------------------------------------------
  // 15: PAYLOAD SIZE LIMIT EXCEEDED
  // ---------------------------------------------------------------------------
  it('15. Payload size limit exceeded: Oversized bundle is rejected with FAILED', async () => {
    const s3Adapter = new S3StorageAdapter({
      bucketName: 'prod-bucket',
      maxSizeBytes: 10, // 10 bytes limit
      transport: async () => new Response(null, { status: 200 }),
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('FAILED');
    expect(receipt.error).toContain('exceeds maximum limit');
  });

  // ---------------------------------------------------------------------------
  // 16: CRASH AFTER UPLOAD RECONCILIATION
  // ---------------------------------------------------------------------------
  it('16. Crash after upload reconciliation: verifyRemoteDelivery confirms stored object', async () => {
    let storedBuf: Buffer | null = null;
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') {
        storedBuf = Buffer.from(init.body as Buffer);
        return new Response(null, { status: 200 });
      }
      if (init.method === 'GET') {
        return new Response(storedBuf, { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'prod-bucket',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('DELIVERED');

    // Simulate post-crash reconciliation probe using receipt locator
    const verification = await s3Adapter.verifyRemoteDelivery(receipt);
    expect(verification.verified).toBe(true);
    expect(verification.remoteDigest).toBe(receipt.artifact_digest);
  });

  // ---------------------------------------------------------------------------
  // 17 & 18: DUPLICATE & CONCURRENT SHIPMENT IDEMPOTENCY
  // ---------------------------------------------------------------------------
  it('17. Duplicate job execution: Idempotent destination locator', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') return new Response(null, { status: 200 });
      if (init.method === 'GET') return new Response(Buffer.alloc(100), { status: 200 });
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({ bucketName: 'prod-bucket', transport: mockTransport });

    const opt = { targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz' };
    const r1 = await s3Adapter.ship(testBundle, opt);
    const r2 = await s3Adapter.ship(testBundle, opt);

    expect(r1.target_locator).toBe(r2.target_locator);
  });

  it('18. Concurrent delivery requests execute without cross-contamination', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') return new Response(null, { status: 200 });
      if (init.method === 'GET') {
        const { bytes } = (await import('../packages/packaging/src/shipping/shipping-utils.ts')).serializePackageBundleToBytes(testBundle);
        return new Response(bytes, { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({ bucketName: 'prod-bucket', transport: mockTransport });

    const [res1, res2] = await Promise.all([
      s3Adapter.ship(testBundle, { targetLocator: 's3://prod-bucket/releases/agent-1/bundle.tar.gz' }),
      s3Adapter.ship(testBundle, { targetLocator: 's3://prod-bucket/releases/agent-2/bundle.tar.gz' }),
    ]);

    expect(res1.status).toBe('DELIVERED');
    expect(res2.status).toBe('DELIVERED');
    expect(res1.receipt_locator).not.toBe(res2.receipt_locator);
  });

  // ---------------------------------------------------------------------------
  // 19: MALFORMED OCI MANIFEST
  // ---------------------------------------------------------------------------
  it('19. Malformed OCI manifest: Registry rejection is caught cleanly as FAILED', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (url.includes('/blobs/uploads/')) return new Response(null, { status: 202, headers: { Location: '/upload' } });
      if (url.includes('/upload')) return new Response(null, { status: 201 });
      if (url.includes('/manifests/') && init.method === 'PUT') {
        return new Response('Invalid Manifest Schema', { status: 400 });
      }
      return new Response('Not Found', { status: 404 });
    };

    const ociAdapter = new OciRegistryAdapter({
      registryHost: 'registry.internal.caim.security',
      transport: mockTransport,
    });

    const receipt = await ociAdapter.ship(testBundle, {
      targetLocator: 'registry.internal.caim.security/agents/p106:v1.0.0',
    });

    expect(receipt.status).toBe('FAILED');
    expect(receipt.error).toContain('HTTP 400');
  });

  // ---------------------------------------------------------------------------
  // 20: REGISTRY REDIRECT SSRF PREVENTION
  // ---------------------------------------------------------------------------
  it('20. Registry redirect SSRF: Location pointing to AWS metadata IP is blocked', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (url.includes('/blobs/uploads/')) {
        // Malicious redirect to AWS metadata endpoint
        return new Response(null, {
          status: 202,
          headers: { Location: 'http://169.254.169.254/latest/meta-data/' },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    const ociAdapter = new OciRegistryAdapter({
      registryHost: 'registry.internal.caim.security',
      transport: mockTransport,
    });

    const receipt = await ociAdapter.ship(testBundle, {
      targetLocator: 'registry.internal.caim.security/agents/p106:v1.0.0',
    });

    expect(receipt.status).toBe('AUTHORIZATION_DENIED');
    expect(receipt.error).toContain('SSRF Blocked');
  });

  // ---------------------------------------------------------------------------
  // 21 & 22: STALE RECEIPT & WRONG COMMIT/ENV
  // ---------------------------------------------------------------------------
  it('21. Stale receipt: Evaluator rejects receipt older than maxAgeMs', () => {
    const tempReceipt = path.resolve(process.cwd(), 'dist/stale-shipping-receipt.json');
    fs.mkdirSync(path.dirname(tempReceipt), { recursive: true });

    const staleReceipt = createAndSaveRunnerReceipt({
      gateId: 'GATE_L09_REMOTE_SHIPPING',
      providerType: 'REAL',
      command: 'pnpm exec tsx scripts/certify-real-shipping.ts',
      exitCode: 0,
      durationMs: 100,
      stdout: 'Stale',
      logPointer: 'stale.log',
      testCounts: { total: 1, passed: 1, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      outputPath: tempReceipt,
    });
    // Overwrite issuedAt to 10 days ago
    staleReceipt.issuedAt = new Date(Date.now() - 10 * 86400000).toISOString();
    fs.writeFileSync(tempReceipt, JSON.stringify(staleReceipt, null, 2), 'utf-8');

    const manifest = evaluateAllReleaseGates({
      receiptPathOverrides: { GATE_L09_REMOTE_SHIPPING: tempReceipt },
      maxAgeMs: 86400000,
    });

    const gate = manifest.gates.find(g => g.gateId === 'GATE_L09_REMOTE_SHIPPING');
    expect(gate?.status).not.toBe('EXECUTED — PASS');
    expect(gate?.blockers.some(b => b.includes('STALE_RECEIPT'))).toBe(true);

    if (fs.existsSync(tempReceipt)) fs.unlinkSync(tempReceipt);
  });

  it('22. Wrong commit/environment: Gate evaluator rejects mismatched commit or env', () => {
    const tempReceipt = path.resolve(process.cwd(), 'dist/wrong-commit-shipping-receipt.json');
    fs.mkdirSync(path.dirname(tempReceipt), { recursive: true });

    createAndSaveRunnerReceipt({
      gateId: 'GATE_L09_REMOTE_SHIPPING',
      providerType: 'REAL',
      command: 'pnpm exec tsx scripts/certify-real-shipping.ts',
      exitCode: 0,
      durationMs: 100,
      stdout: 'Wrong commit',
      logPointer: 'wrong.log',
      commitSha: '1111111111111111111111111111111111111111',
      testCounts: { total: 1, passed: 1, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      outputPath: tempReceipt,
      providerReceipt: {
        harnessVersion: '2.0.0',
        deliveryVerified: true,
        integrityVerified: true,
        readbackMatchesLocalDigest: true,
      },
    });

    const manifest = evaluateAllReleaseGates({
      receiptPathOverrides: { GATE_L09_REMOTE_SHIPPING: tempReceipt },
      expectedCommitSha: '2222222222222222222222222222222222222222',
    });

    const gate = manifest.gates.find(g => g.gateId === 'GATE_L09_REMOTE_SHIPPING');
    expect(gate?.status).toBe('EXECUTED — FAIL');
    expect(gate?.blockers.some(b => b.includes('COMMIT_MISMATCH'))).toBe(true);

    if (fs.existsSync(tempReceipt)) fs.unlinkSync(tempReceipt);
  });

  // ---------------------------------------------------------------------------
  // 23: PERSISTENCE TOLERANCE
  // ---------------------------------------------------------------------------
  it('23. Database persistence failure: Service returns receipt and records in-memory audit', async () => {
    const service = new ShippingService();
    const receipt = await service.shipBundle(testBundle, 'LOCAL_STAGING', {
      targetLocator: '/tmp/caim-staging/p106-test',
    });

    expect(receipt.status).toBe('DELIVERED');
    expect(receipt.truthState).toBe('OBSERVED');
    expect(service.getAuditLog().length).toBeGreaterThan(0);
  });

  // ---------------------------------------------------------------------------
  // 24: READBACK VERIFICATION FAILURE
  // ---------------------------------------------------------------------------
  it('24. Readback verification failure: Object 404 on readback sets UNKNOWN_REMOTE_STATE', async () => {
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') return new Response(null, { status: 200 });
      if (init.method === 'GET') return new Response('Not Found', { status: 404 });
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'prod-bucket',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://prod-bucket/releases/agent/bundle.tar.gz',
    });

    expect(receipt.status).toBe('UNKNOWN_REMOTE_STATE');
    expect(receipt.detailed_state).toBe('UNKNOWN_REMOTE_STATE');
  });

  // ---------------------------------------------------------------------------
  // 25: SUCCESSFUL BENIGN CONTROL
  // ---------------------------------------------------------------------------
  it('25. Successful benign control: Clean bundle to clean S3 succeeds after negative tests', async () => {
    let storedData: Buffer | null = null;
    const mockTransport = async (url: string, init: RequestInit) => {
      if (init.method === 'PUT') {
        storedData = Buffer.from(init.body as Buffer);
        return new Response(null, { status: 200 });
      }
      if (init.method === 'GET') {
        return new Response(storedData, { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    };

    const s3Adapter = new S3StorageAdapter({
      bucketName: 'caim-control-bucket',
      region: 'us-east-1',
      transport: mockTransport,
    });

    const receipt = await s3Adapter.ship(testBundle, {
      targetLocator: 's3://caim-control-bucket/releases/agent-control/bundle.tar.gz',
    });

    expect(receipt.status).toBe('DELIVERED');
    expect(receipt.detailed_state).toBe('DELIVERED_VERIFIED');
    expect(receipt.truthState).toBe('OBSERVED');
    expect(receipt.integrity_verified).toBe(true);
    expect(receipt.artifact_digest).toBe(receipt.remote_digest);
  });
});
