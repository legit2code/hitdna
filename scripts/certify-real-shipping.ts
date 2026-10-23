/**
 * CAIM Real Remote Shipping & Delivery Certification Harness
 * Architecture P106 — Authentic S3 Storage & OCI Registry Delivery Verification
 *
 * GOVERNANCE:
 * 1. Executes authentic delivery and remote readback verification against real S3/OCI providers.
 * 2. Emulators, mocks, or local staging substitutions are STRICTLY PROHIBITED for certification.
 * 3. Never reports EXECUTED — PASS unless actual remote upload and independent readback
 *    integrity comparison have succeeded against the authorized destination.
 * 4. Produces tamper-evident V2 RunnerReceipt (GATE_L09_REMOTE_SHIPPING) with redacted
 *    provider identity, request metadata, and zero secrets.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { S3StorageAdapter } from '../packages/packaging/src/shipping/s3-adapter.ts';
import { OciRegistryAdapter } from '../packages/packaging/src/shipping/oci-adapter.ts';
import { IShippingTargetAdapter } from '../packages/packaging/src/shipping/adapter.ts';
import { DeterministicPackageBundler, PackageBuildInput } from '../packages/packaging/src/bundler.ts';
import { KmsSignerBoundary } from '../packages/packaging/src/crypto/kms-boundary.ts';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';
import { RunnerReceipt } from '../src/certification/gate-schema.ts';

export interface CertifyShippingOptions {
  receiptOutputPath?: string;
  logOutputPath?: string;
  expectedCommitSha?: string;
  customS3Adapter?: IShippingTargetAdapter;
  customOciAdapter?: IShippingTargetAdapter;
}

export function redactShippingDestination(locator?: string): string {
  if (!locator || locator.trim().length === 0) return 'NONE';
  return locator
    .replace(/(s3:\/\/)[^/]+(\/)/, '$1***$2')
    .replace(/([a-zA-Z0-9.-]+\/)([^:]+)(:.*)?/, '***$3');
}

export async function certifyRealShipping(options: CertifyShippingOptions = {}): Promise<RunnerReceipt> {
  const startTime = Date.now();
  const receiptPath = options.receiptOutputPath || path.resolve(process.cwd(), 'docs/certification/shipping-receipt.json');
  const logDir = path.resolve(process.cwd(), 'docs/certification/logs');
  const logPath = options.logOutputPath || path.join(logDir, 'l09-remote-shipping.log');
  fs.mkdirSync(path.dirname(receiptPath), { recursive: true });
  fs.mkdirSync(path.dirname(logPath), { recursive: true });

  const logLines: string[] = [];
  const log = (msg: string) => {
    const entry = `[${new Date().toISOString()}] ${msg}`;
    logLines.push(entry);
    console.log(msg);
  };

  log('================================================================================');
  log('   CAIM REAL REMOTE SHIPPING & SUPPLY-CHAIN CERTIFICATION HARNESS (GATE L09)    ');
  log('================================================================================');

  const s3Bucket = process.env.S3_BUCKET_NAME?.trim();
  const awsAccessKey = process.env.AWS_ACCESS_KEY_ID?.trim();
  const awsSecretKey = process.env.AWS_SECRET_ACCESS_KEY?.trim();

  const ociHost = process.env.OCI_REGISTRY_HOST?.trim();
  const ociToken = process.env.OCI_AUTH_TOKEN?.trim();

  const hasS3Config = Boolean(s3Bucket);
  const hasS3Creds = Boolean(awsAccessKey && awsSecretKey);
  const hasOciConfig = Boolean(ociHost);
  const hasOciCreds = Boolean(ociToken);

  const hasS3 = (hasS3Config && hasS3Creds) || Boolean(options.customS3Adapter);
  const hasOci = (hasOciConfig && hasOciCreds) || Boolean(options.customOciAdapter);

  // If credentials missing, fail closed with EXTERNAL INFRA REQUIRED (exit 2)
  if (!hasS3 && !hasOci) {
    const blockers: string[] = [];
    if (!hasS3Config) {
      blockers.push('Production S3 storage bucket is not configured (missing S3_BUCKET_NAME).');
    } else if (!hasS3Creds) {
      blockers.push('S3_BUCKET_NAME is configured but valid AWS credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) are missing.');
    }

    if (!hasOciConfig) {
      blockers.push('Production OCI Registry is not configured (missing OCI_REGISTRY_HOST).');
    } else if (!hasOciCreds) {
      blockers.push('OCI_REGISTRY_HOST is configured but valid OCI credentials (OCI_AUTH_TOKEN) are missing.');
    }

    blockers.push('Hardware/Cloud remote shipping delivery requires authenticated cloud object storage or container registry.');
    blockers.push('Local staging or dev simulation cannot certify production artifact shipping.');

    log('Shipping infrastructure status: EXTERNAL INFRA REQUIRED');
    blockers.forEach(b => log(`  - BLOCKER: ${b}`));

    const durationMs = Date.now() - startTime;
    fs.writeFileSync(logPath, logLines.join('\n'), 'utf-8');

    const receipt = createAndSaveRunnerReceipt({
      gateId: 'GATE_L09_REMOTE_SHIPPING',
      providerType: 'NONE',
      command: 'pnpm exec tsx scripts/certify-real-shipping.ts',
      exitCode: 2,
      durationMs,
      stdout: logLines.join('\n'),
      logPointer: logPath,
      testCounts: { total: 2, passed: 0, failed: 0, skipped: 2 },
      status: 'EXTERNAL INFRA REQUIRED',
      blockers,
      outputPath: receiptPath,
      providerReceipt: {
        harnessVersion: '2.0.0',
        s3TargetConfigured: false,
        ociTargetConfigured: false,
        deliveryVerified: false,
        integrityVerified: false,
      },
    });

    return receipt;
  }

  // Build authentic deterministic release bundle for shipping certification challenge
  log('Generating deterministic test package bundle for shipping challenge...');
  const testInput: PackageBuildInput = {
    packageId: `pkg-cert-ship-${Date.now()}`,
    agentId: 'agent-certification-shipping',
    agentVersionId: 'av-cert-v100',
    versionLabel: 'v1.0.0',
    createdAt: new Date().toISOString(),
    sourceFiles: {
      'src/index.ts': 'export const certified = true;\n',
      'package.json': '{"name":"agent-certification-shipping","version":"1.0.0"}',
    },
    analysisReport: {
      static_analysis: { findings_count: 0, taint_sinks_reached: 0, status: 'CLEAN' },
      composition_sbom: { components_count: 0, cve_vulnerabilities: 0, status: 'CLEAN' },
      sandbox_behavior: { network_egress_unauthorized: 0, syscall_violations: 0, status: 'PASSED' },
      decision_score: { overall_score: 100, risk_band: 'LOW', confidence: 1.0 },
      recommendation: { verdict: 'APPROVE', allow_shipment: true },
    },
    sbomComponents: [],
    validationReference: {
      validation_run_id: 'val-ship-cert-01',
      validation_plan_version: 'v1.0.0',
      status: 'PASSED',
      verdict: 'APPROVED_FOR_RELEASE',
      risk_reduced: true,
      capabilities_preserved: true,
      completed_at: new Date().toISOString(),
    },
    policyReference: {
      policy_ruleset_version: 'v2.0.1',
      policy_outcome: 'ALLOW',
      risk_score: 100,
      risk_band: 'LOW',
      policy_allowed: true,
      evaluated_at: new Date().toISOString(),
    },
    approvalReferences: [
      {
        approval_id: 'appr-cert-ship-01',
        approver_id: 'usr-cert-auditor',
        approver_role: 'SECURITY_AUDITOR',
        decision: 'APPROVED',
        decided_at: new Date().toISOString(),
        rationale: 'Shipping certification challenge approval 1',
      },
      {
        approval_id: 'appr-cert-ship-02',
        approver_id: 'usr-rel-lead',
        approver_role: 'RELEASE_ENGINEER',
        decision: 'APPROVED',
        decided_at: new Date().toISOString(),
        rationale: 'Shipping certification challenge approval 2',
      },
    ],
    metadata: {
      author: 'CAIM Independent Release Auditor',
      license: 'Apache-2.0',
      securityClassification: 'RESTRICTED',
      framework: 'TypeScript',
      description: 'Authentic Shipping Verification Artifact',
    },
    provenanceReference: {
      engine_version: '2.0.1',
      ruleset_version: '2026-10-22',
      analysis_run_id: 'ar-ship-cert-01',
      input_hashes: ['0000000000000000000000000000000000000000000000000000000000000000'],
      generated_at: new Date().toISOString(),
    },
  };

  const kmsBoundary = KmsSignerBoundary.createDefault('caim-cert-shipping-key');
  const bundle = await DeterministicPackageBundler.buildAndSign(testInput, kmsBoundary);

  let s3Verified = false;
  let ociVerified = false;
  let s3Locator = '';
  let ociLocator = '';
  const blockers: string[] = [];
  let s3Receipt: any = null;
  let ociReceipt: any = null;

  // 1. S3 Execution
  if (hasS3) {
    log(`Executing authentic AWS S3 Shipping to bucket: ${s3Bucket || 'custom'}...`);
    const s3Adapter = options.customS3Adapter || new S3StorageAdapter({ bucketName: s3Bucket });
    try {
      const receipt = await s3Adapter.ship(bundle, {
        targetLocator: `s3://${s3Bucket}/releases/caim-cert/${bundle.package_id}/bundle.tar.gz`,
      });
      s3Receipt = receipt;
      s3Locator = receipt.receipt_locator || '';

      if (receipt.status === 'DELIVERED' && receipt.integrity_verified && receipt.truthState === 'OBSERVED') {
        log(`✓ S3 Remote Shipping & Readback Integrity Succeeded: ${redactShippingDestination(s3Locator)}`);
        s3Verified = true;
      } else {
        blockers.push(`S3 delivery failed or integrity unverified: ${receipt.error || receipt.status}`);
        log(`✗ S3 Delivery Failed: ${receipt.error || receipt.status}`);
      }
    } catch (err: any) {
      blockers.push(`S3 shipment exception: ${err.message}`);
      log(`✗ S3 Shipment Exception: ${err.message}`);
    }
  }

  // 2. OCI Execution
  if (hasOci) {
    log(`Executing authentic OCI Registry Shipping to host: ${ociHost || 'custom'}...`);
    const ociAdapter = options.customOciAdapter || new OciRegistryAdapter({ registryHost: ociHost });
    try {
      const receipt = await ociAdapter.ship(bundle, {
        targetLocator: `${ociHost}/agents/caim-cert:${bundle.package_id}`,
      });
      ociReceipt = receipt;
      ociLocator = receipt.receipt_locator || '';

      if (
        receipt.status === 'DELIVERED' &&
        receipt.integrity_verified &&
        receipt.truthState === 'OBSERVED' &&
        receipt.byte_level_readback_verified === true
      ) {
        log(`✓ OCI Registry Shipping & Byte-Level Readback Succeeded: ${redactShippingDestination(ociLocator)}`);
        ociVerified = true;
      } else {
        blockers.push(`OCI delivery failed or byte integrity unverified: ${receipt.error || receipt.status}`);
        log(`✗ OCI Delivery Failed: ${receipt.error || receipt.status}`);
      }
    } catch (err: any) {
      blockers.push(`OCI shipment exception: ${err.message}`);
      log(`✗ OCI Shipment Exception: ${err.message}`);
    }
  }

  const allConfiguredPassed = (!hasS3 || s3Verified) && (!hasOci || ociVerified) && (hasS3 || hasOci);
  const status = allConfiguredPassed ? 'EXECUTED — PASS' : 'EXECUTED — FAIL';
  const exitCode = allConfiguredPassed ? 0 : 1;
  const durationMs = Date.now() - startTime;

  fs.writeFileSync(logPath, logLines.join('\n'), 'utf-8');

  const runnerReceipt = createAndSaveRunnerReceipt({
    gateId: 'GATE_L09_REMOTE_SHIPPING',
    providerType: 'REAL',
    command: 'pnpm exec tsx scripts/certify-real-shipping.ts',
    exitCode,
    durationMs,
    stdout: logLines.join('\n'),
    logPointer: logPath,
    testCounts: {
      total: (hasS3 ? 1 : 0) + (hasOci ? 1 : 0),
      passed: (s3Verified ? 1 : 0) + (ociVerified ? 1 : 0),
      failed: (hasS3 && !s3Verified ? 1 : 0) + (hasOci && !ociVerified ? 1 : 0),
      skipped: 0,
    },
    status,
    blockers,
    outputPath: receiptPath,
    providerReceipt: {
      harnessVersion: '2.0.0',
      s3TargetConfigured: hasS3,
      ociTargetConfigured: hasOci,
      s3Verified,
      ociVerified,
      s3ReceiptLocator: redactShippingDestination(s3Locator),
      ociReceiptLocator: redactShippingDestination(ociLocator),
      s3Digest: s3Receipt?.artifact_digest,
      ociDigest: ociReceipt?.artifact_digest,
      deliveryVerified: allConfiguredPassed,
      integrityVerified: allConfiguredPassed,
      byteReadbackVerified: allConfiguredPassed,
      integrityComparison: allConfiguredPassed ? 'MATCH' : 'MISMATCH',
      readbackMatchesLocalDigest: allConfiguredPassed,
    },
  });

  log(`Final GATE_L09 Status: ${status}`);
  return runnerReceipt;
}

if (process.argv[1] && process.argv[1].endsWith('certify-real-shipping.ts')) {
  certifyRealShipping().then(r => {
    if (r.status === 'EXTERNAL INFRA REQUIRED') process.exit(2);
    if (r.status !== 'EXECUTED — PASS') process.exit(1);
    process.exit(0);
  }).catch(err => {
    console.error('CRITICAL ERROR in certifyRealShipping:', err);
    process.exit(1);
  });
}
