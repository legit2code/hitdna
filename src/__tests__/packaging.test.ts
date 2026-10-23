import { describe, it, expect, beforeEach } from 'vitest';
import {
  DeterministicPackageBundler,
  KmsSignerBoundary,
  Ed25519Signer,
  SignatureVerifier,
  KeyRegistry,
  PackagingPolicyGate,
  ShippingService,
  OciRegistryAdapter,
  S3StorageAdapter,
  WebhookShippingAdapter,
  LocalStagingAdapter,
  sha256,
  canonicalJson,
  computeManifestRootHash,
  PackageBuildInput,
  SignedPackageBundle
} from '@caim/packaging';

describe('P26 — Packaging, Attestation, Signing & Shipping Module', () => {
  let kmsBoundary: KmsSignerBoundary;
  let sampleInput: PackageBuildInput;

  beforeEach(() => {
    kmsBoundary = KmsSignerBoundary.createDefault('test-release-key-01', 'v1');

    sampleInput = {
      packageId: 'pkg-agent-sample-v1.0.0',
      agentId: 'agent-sample',
      agentVersionId: 'av-sample-v100',
      versionLabel: 'v1.0.0',
      createdAt: '2026-08-26T12:00:00Z',
      sourceFiles: {
        'src/main.ts': 'export function execute() { return "hello world"; }\n',
        'package.json': '{\n  "name": "sample-agent",\n  "version": "1.0.0"\n}\n'
      },
      analysisReport: {
        static_analysis: { findings_count: 0, status: 'CLEAN' },
        decision_score: { overall_score: 95, risk_band: 'LOW' }
      },
      sbomComponents: [
        {
          name: 'lodash',
          version: '4.17.21',
          type: 'library',
          licenses: ['MIT'],
          sha256: 'b0b2e8cf702ff60b377cf3fa096df00bc19e34c9c1ef348f95fe3108c9037c22'
        }
      ],
      validationReference: {
        validation_run_id: 'val-run-001',
        validation_plan_version: 'v2.0.1-std',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-08-26T12:00:00Z'
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 95,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-08-26T12:00:00Z'
      },
      approvalReferences: [
        {
          approval_id: 'appr-sec-01',
          approver_id: 'usr-auditor',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:05:00Z',
          rationale: 'Clean automated audit'
        },
        {
          approval_id: 'appr-admin-02',
          approver_id: 'usr-admin',
          approver_role: 'PLATFORM_ADMIN',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:10:00Z',
          rationale: 'Two-person release approved'
        }
      ],
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-08-26',
        analysis_run_id: 'ar-9921',
        input_hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        generated_at: '2026-08-26T12:00:00Z'
      },
      metadata: {
        author: 'Security Engineering',
        license: 'Apache-2.0',
        securityClassification: 'INTERNAL',
        framework: 'TypeScript',
        description: 'Deterministic Sample Agent Release'
      }
    };
  });

  describe('1. Determinism & Content Hashing', () => {
    it('produces identical manifest hashes for identical inputs regardless of key insertion order', async () => {
      // Build bundle 1
      const bundle1 = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      // Build bundle 2 with perturbed key ordering in sourceFiles
      const perturbedInput: PackageBuildInput = {
        ...sampleInput,
        sourceFiles: {
          'package.json': '{\n  "name": "sample-agent",\n  "version": "1.0.0"\n}\n',
          'src/main.ts': 'export function execute() { return "hello world"; }\n',
        }
      };
      const bundle2 = await DeterministicPackageBundler.buildAndSign(perturbedInput, kmsBoundary);

      expect(bundle1.manifest_hash).toBe(bundle2.manifest_hash);
      expect(bundle1.manifest.contents.length).toBe(bundle2.manifest.contents.length);
      expect(bundle1.files.get('manifest.json')?.sha256).toBe(bundle2.files.get('manifest.json')?.sha256);
    });

    it('generates canonical JSON with sorted keys', () => {
      const obj1 = { z: 1, a: 2, m: { b: 3, a: 4 } };
      const obj2 = { a: 2, m: { a: 4, b: 3 }, z: 1 };

      expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
      expect(canonicalJson(obj1)).toBe('{"a":2,"m":{"a":4,"b":3},"z":1}');
    });
  });

  describe('2. Package Deliverables Generation', () => {
    it('generates all required deterministic deliverables', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      expect(bundle.files.has('manifest.json')).toBe(true);
      expect(bundle.files.has('report.json')).toBe(true);
      expect(bundle.files.has('summary.csv')).toBe(true);
      expect(bundle.files.has('bom.json')).toBe(true);
      expect(bundle.files.has('provenance.json')).toBe(true);
      expect(bundle.files.has('attestation.json')).toBe(true);
      expect(bundle.files.has('src/main.ts')).toBe(true);
      expect(bundle.files.has('package.json')).toBe(true);

      // Verify CycloneDX SBOM format
      const bomContent = JSON.parse(bundle.files.get('bom.json')!.content as string);
      expect(bomContent.bomFormat).toBe('CycloneDX');
      expect(bomContent.specVersion).toBe('1.5');
      expect(bomContent.components.length).toBeGreaterThan(0);

      // Verify summary CSV
      const csvContent = bundle.files.get('summary.csv')!.content as string;
      expect(csvContent).toContain('item_type,identifier,severity,category,status,details');
      expect(csvContent).toContain('VALIDATION');
      expect(csvContent).toContain('POLICY');

      // Verify in-toto attestation
      expect(bundle.attestation._type).toBe('https://in-toto.io/Statement/v1');
      expect(bundle.attestation.predicateType).toBe('https://caim.security/attestation/v1');
      expect(bundle.attestation.subject[0].digest.sha256).toBe(bundle.manifest_hash);
    });
  });

  describe('3. Cryptographic Ed25519 Signatures & Threat Model Boundary', () => {
    it('signs bundle with Ed25519 and includes valid SPKI public key', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      expect(bundle.signature.algorithm).toBe('Ed25519');
      expect(bundle.signature.signature_scheme).toBe('ed25519');
      expect(bundle.signature.key_id).toBe('test-release-key-01');
      expect(bundle.signature.public_key_pem).toContain('BEGIN PUBLIC KEY');

      // Verify using SignatureVerifier
      const verification = SignatureVerifier.verifyBundle(bundle);
      expect(verification.valid).toBe(true);
      expect(verification.tampered).toBe(false);
      expect(verification.signatureVerified).toBe(true);
      expect(verification.manifestHashMatched).toBe(true);
      expect(verification.contentHashesMatched).toBe(true);
      expect(verification.errors.length).toBe(0);
    });

    it('fails verification if any source file is tampered with', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      // Tamper with a source file content
      const tamperedBundle: SignedPackageBundle = {
        ...bundle,
        files: new Map(bundle.files),
      };
      const mainTs = tamperedBundle.files.get('src/main.ts')!;
      tamperedBundle.files.set('src/main.ts', {
        ...mainTs,
        content: mainTs.content + '// MALICIOUS INJECTION\n',
      });

      const verification = SignatureVerifier.verifyBundle(tamperedBundle);
      expect(verification.valid).toBe(false);
      expect(verification.tampered).toBe(true);
      expect(verification.errors.some((e) => e.includes('hash mismatch'))).toBe(true);
    });

    it('fails verification if signature is tampered or forged', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      // Tamper signature base64
      const tamperedBundle: SignedPackageBundle = {
        ...bundle,
        signature: {
          ...bundle.signature,
          signature_base64: 'AAAA' + bundle.signature.signature_base64.slice(4),
        },
      };

      const verification = SignatureVerifier.verifyBundle(tamperedBundle);
      expect(verification.valid).toBe(false);
      expect(verification.signatureVerified).toBe(false);
      expect(verification.tampered).toBe(true);
    });
  });

  describe('4. Policy Gates Pre-Signing & Pre-Shipping', () => {
    it('blocks signing if policy outcome is DENY_SHIPPING without override', async () => {
      const deniedInput: PackageBuildInput = {
        ...sampleInput,
        policyReference: {
          ...sampleInput.policyReference,
          policy_outcome: 'DENY_SHIPPING',
          policy_allowed: false,
        },
      };

      await expect(
        DeterministicPackageBundler.buildAndSign(deniedInput, kmsBoundary)
      ).rejects.toThrow(/Signing blocked by policy gate/);
    });

    it('blocks signing if fewer than 2 distinct approvers signed off', async () => {
      const singleApproverInput: PackageBuildInput = {
        ...sampleInput,
        approvalReferences: [
          {
            approval_id: 'appr-single-01',
            approver_id: 'usr-only-one',
            approver_role: 'SECURITY_AUDITOR',
            decision: 'APPROVED',
            decided_at: '2026-08-26T12:00:00Z',
            rationale: 'Single signoff only',
          },
        ],
      };

      await expect(
        DeterministicPackageBundler.buildAndSign(singleApproverInput, kmsBoundary)
      ).rejects.toThrow(/Two-person security sign-off required/);
    });

    it('blocks signing if validation run is not PASSED', async () => {
      const failedValInput: PackageBuildInput = {
        ...sampleInput,
        validationReference: {
          ...sampleInput.validationReference,
          status: 'FAILED',
          verdict: 'REJECTED_REGRESSION',
        },
      };

      await expect(
        DeterministicPackageBundler.buildAndSign(failedValInput, kmsBoundary)
      ).rejects.toThrow(/Validation run status is FAILED/);
    });
  });

  describe('5. Shipping Target Adapters & Delivery Receipts', () => {
    let shippingService: ShippingService;

    beforeEach(() => {
      shippingService = new ShippingService();
    });

    it('ships bundle to OCI registry and returns immutable DeliveryReceipt', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      const receipt = await shippingService.shipBundle(bundle, 'OCI_REGISTRY', {
        targetLocator: 'registry.internal.caim.security/agents/sample',
      });

      expect(receipt.status).toBe('SIMULATED_DELIVERY');
      expect(receipt.target_type).toBe('OCI_REGISTRY');
      expect(receipt.manifest_hash).toBe(bundle.manifest_hash);
      expect(receipt.transfer_size_bytes).toBeGreaterThan(0);
      expect(receipt.receipt_signature).toBeDefined();

      expect(shippingService.getAuditLog().length).toBe(1);
    });

    it('ships bundle to S3 cloud storage', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      const receipt = await shippingService.shipBundle(bundle, 'S3_STORAGE', {
        targetLocator: 's3://caim-releases/agents/sample',
      });

      expect(receipt.status).toBe('SIMULATED_DELIVERY');
      expect(receipt.target_type).toBe('S3_STORAGE');
      expect(receipt.receipt_locator).toContain('s3://');
    });

    it('ships bundle to Webhook deployment pipeline', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      const receipt = await shippingService.shipBundle(bundle, 'WEBHOOK_DEPLOYMENT', {
        targetLocator: 'https://deploy.internal.caim.security/hooks/agent-release',
      });

      expect(receipt.status).toBe('SIMULATED_DELIVERY');
      expect(receipt.target_type).toBe('WEBHOOK_DEPLOYMENT');
    });

    it('ships bundle to Local Staging directory', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      const receipt = await shippingService.shipBundle(bundle, 'LOCAL_STAGING', {
        targetLocator: '/tmp/caim-staging/sample-agent',
      });

      expect(receipt.status).toBe('DELIVERED');
      expect(receipt.target_type).toBe('LOCAL_STAGING');
    });

    it('blocks shipping if package is tampered', async () => {
      const bundle = await DeterministicPackageBundler.buildAndSign(sampleInput, kmsBoundary);

      const tamperedBundle: SignedPackageBundle = {
        ...bundle,
        manifest: {
          ...bundle.manifest,
          manifest_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        },
        files: new Map(bundle.files),
      };
      const mainTs = tamperedBundle.files.get('src/main.ts')!;
      tamperedBundle.files.set('src/main.ts', {
        ...mainTs,
        content: mainTs.content + '// TAMPERED',
      });

      await expect(
        shippingService.shipBundle(tamperedBundle, 'OCI_REGISTRY', {
          targetLocator: 'registry.internal.caim.security/agents/sample',
        })
      ).rejects.toThrow(/Pre-shipping checks failed/);
    });
  });
});
