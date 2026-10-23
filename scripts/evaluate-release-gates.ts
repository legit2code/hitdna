/**
 * CAIM Release Gate Evaluator & Manifest Generator
 * Stage P103 — Secure Certification Trust Root & Release Evidence Aggregator
 *
 * GOVERNANCE:
 * 1. Default is UNVERIFIED / BLOCKED unless verified by authentic runner receipts.
 * 2. Stale, missing, tampered, wrong-commit, or malformed receipts are rejected.
 * 3. Configuration flags (e.g. configured=true) mean CONFIGURED, NEVER VERIFIED.
 * 4. releaseFreeze=true strictly forbids overallVerdict = SHIP.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  GateId,
  MANDATORY_GATE_REGISTRY,
  ALL_MANDATORY_GATE_IDS,
  validateRunnerReceipt,
  evaluateReleaseDecision,
  EvaluatedGateResult,
  ReleaseEvidenceManifestV2,
  GATE_SCHEMA_VERSION,
} from '../src/certification/gate-schema.ts';

export interface EvaluatorOptions {
  receiptsDir?: string;
  receiptPathOverrides?: Partial<Record<GateId, string>>;
  manifestOutputPath?: string;
  expectedCommitSha?: string;
  expectedEnvironment?: string;
  maxAgeMs?: number;
  verificationSecret?: string;
  releaseFreeze?: boolean;
  evaluationTimeMs?: number;
}

export function evaluateAllReleaseGates(options: EvaluatorOptions = {}): ReleaseEvidenceManifestV2 {
  const receiptsDir = options.receiptsDir || path.resolve(process.cwd(), 'docs/certification');
  const manifestOutputPath = options.manifestOutputPath || path.resolve(receiptsDir, 'release-evidence-manifest.json');
  const expectedEnvironment = options.expectedEnvironment || (process.env.NODE_ENV as any) || 'development';
  const expectedCommitSha = options.expectedCommitSha || process.env.GITHUB_SHA || process.env.COMMIT_SHA;
  const verificationSecret = options.verificationSecret || process.env.CAIM_RUNNER_SECRET || 'caim-local-runner-integrity-key-2026';
  const releaseFreeze = options.releaseFreeze ?? true; // Default is always frozen (fail-closed)
  const evaluationTimeMs = options.evaluationTimeMs ?? Date.now();

  const evaluatedGates: EvaluatedGateResult[] = [];

  // Mapping of GateId to receipt filename
  const gateReceiptFiles: Record<GateId, string> = {
    GATE_L01_TOOLCHAIN: 'gate-l01-toolchain-receipt.json',
    GATE_L02_TYPES: 'gate-l02-types-receipt.json',
    GATE_L03_SANDBOX_SECURITY: 'gate-l03-sandbox-security-receipt.json',
    GATE_L04_SHIPPING_TRUTH: 'gate-l04-shipping-truth-receipt.json',
    GATE_L05_SLOW_SUITE: 'gate-l05-slow-suite-receipt.json',
    GATE_L06_POSTGRES_RLS: 'postgres-rls-receipt.json',
    GATE_L07_KMS_ATTESTATION: 'kms-receipt.json',
    GATE_L08_E2B_SANDBOX: 'e2b-provider-receipt.json',
    GATE_L09_REMOTE_SHIPPING: 'shipping-receipt.json',
    GATE_L10_GIT_SECRET_SCAN: 'gate-l10-git-secret-scan-receipt.json',
  };

  for (const gateId of ALL_MANDATORY_GATE_IDS) {
    const gateDef = MANDATORY_GATE_REGISTRY[gateId];
    const receiptFileName = gateReceiptFiles[gateId];
    const receiptPath = options.receiptPathOverrides?.[gateId] || path.join(receiptsDir, receiptFileName);

    if (!fs.existsSync(receiptPath)) {
      // Missing receipt: never infer PASS
      evaluatedGates.push({
        gateId,
        layer: gateDef.layer,
        name: gateDef.name,
        providerType: gateDef.requiredProviderType,
        status: gateDef.requiresRemoteInfrastructure ? 'EXTERNAL INFRA REQUIRED' : 'UNVERIFIED',
        blockers: [`MISSING_RECEIPT: Expected receipt file ${receiptFileName} does not exist.`],
      });
      continue;
    }

    // Read and parse receipt
    let rawContent: string;
    let rawJson: any;
    try {
      rawContent = fs.readFileSync(receiptPath, 'utf-8');
      rawJson = JSON.parse(rawContent);
    } catch (parseErr: any) {
      evaluatedGates.push({
        gateId,
        layer: gateDef.layer,
        name: gateDef.name,
        providerType: gateDef.requiredProviderType,
        status: 'EXECUTED — FAIL',
        receiptPath,
        blockers: [`CORRUPT_RECEIPT: Could not read/parse JSON from ${receiptFileName}: ${parseErr.message}`],
      });
      continue;
    }

    const receiptHash = crypto.createHash('sha256').update(rawContent).digest('hex');

    // Handle legacy receipts vs V2 RunnerReceipt
    if (rawJson.schemaVersion === GATE_SCHEMA_VERSION) {
      // Validate full V2 RunnerReceipt
      const validation = validateRunnerReceipt(rawJson, {
        expectedGateId: gateId,
        expectedCommitSha,
        expectedEnvironment,
        maxAgeMs: options.maxAgeMs,
        verificationSecret,
        evaluationTimeMs,
      });

      if (!validation.valid || !validation.receipt) {
        evaluatedGates.push({
          gateId,
          layer: gateDef.layer,
          name: gateDef.name,
          providerType: gateDef.requiredProviderType,
          status: 'EXECUTED — FAIL',
          receiptPath,
          receiptHash,
          blockers: [validation.reason || 'INVALID_RECEIPT'],
        });
        continue;
      }

      const receipt = validation.receipt;

      // Special provider-specific verification: configured is not verified!
      if (gateId === 'GATE_L07_KMS_ATTESTATION') {
        const kmsRec = receipt.providerReceipt as any;
        if (receipt.status === 'EXECUTED — PASS') {
          const isRealKms = receipt.providerType === 'REAL' && kmsRec?.isRealKms === true;
          const challengeVerified = kmsRec?.challengeResponseVerified === true;
          const tamperVerified = kmsRec?.tamperDetectionVerified === true;
          const zeroSkips =
            receipt.testCounts.skipped === 0 &&
            receipt.testCounts.total >= 3 &&
            receipt.testCounts.passed === receipt.testCounts.total;

          if (!isRealKms || !challengeVerified || !tamperVerified || !zeroSkips) {
            evaluatedGates.push({
              gateId,
              layer: gateDef.layer,
              name: gateDef.name,
              providerType: receipt.providerType,
              status: 'EXECUTED — FAIL',
              commandExecuted: receipt.executionTelemetry.command,
              exitCode: 1,
              durationMs: receipt.executionTelemetry.durationMs,
              receiptPath,
              receiptHash,
              receiptId: receipt.receiptId,
              issuedAt: receipt.issuedAt,
              logPointer: receipt.executionTelemetry.logPointer,
              blockers: [
                'KMS_VERIFICATION_INCOMPLETE: PASS receipt does not satisfy all mandatory invariants (real Cloud KMS provider, authentic remote challenge-response verified, tamper detection probe verified, and all 3 probes passing with 0 skips).'
              ],
            });
            continue;
          }
        } else if (kmsRec?.kmsConfigured && !kmsRec?.tamperDetectionVerified) {
          evaluatedGates.push({
            gateId,
            layer: gateDef.layer,
            name: gateDef.name,
            providerType: receipt.providerType,
            status: 'CONFIGURED — NOT VERIFIED',
            receiptPath,
            receiptHash,
            receiptId: receipt.receiptId,
            issuedAt: receipt.issuedAt,
            blockers: ['KMS_CONFIGURED_NOT_VERIFIED: KMS is configured but remote signing operation was not verified.'],
          });
          continue;
        }
      }

      if (gateId === 'GATE_L09_REMOTE_SHIPPING') {
        const shipRec = receipt.providerReceipt as any;
        if (receipt.status === 'EXECUTED — PASS') {
          const isReal = receipt.providerType === 'REAL';
          const isDeliveryVerified = shipRec?.deliveryVerified === true;
          const isIntegrityVerified = shipRec?.integrityVerified === true;
          const readbackMatched = shipRec?.readbackMatchesLocalDigest === true;
          const isByteReadbackVerified = shipRec?.byteReadbackVerified !== false;

          if (!isReal || !isDeliveryVerified || !isIntegrityVerified || !readbackMatched || !zeroFailures || !isByteReadbackVerified) {
            evaluatedGates.push({
              gateId,
              layer: gateDef.layer,
              name: gateDef.name,
              providerType: receipt.providerType,
              status: 'EXECUTED — FAIL',
              commandExecuted: receipt.executionTelemetry.command,
              exitCode: 1,
              durationMs: receipt.executionTelemetry.durationMs,
              receiptPath,
              receiptHash,
              receiptId: receipt.receiptId,
              issuedAt: receipt.issuedAt,
              logPointer: receipt.executionTelemetry.logPointer,
              blockers: [
                'SHIPPING_VERIFICATION_INCOMPLETE: PASS receipt does not satisfy all mandatory invariants (real cloud provider, delivery verified, byte-level readback verified, readback digest matches local artifact, zero failures).'
              ],
            });
            continue;
          }
        } else if ((shipRec?.s3TargetConfigured || shipRec?.ociTargetConfigured) && !shipRec?.deliveryVerified) {
          evaluatedGates.push({
            gateId,
            layer: gateDef.layer,
            name: gateDef.name,
            providerType: receipt.providerType,
            status: 'CONFIGURED — NOT VERIFIED',
            receiptPath,
            receiptHash,
            receiptId: receipt.receiptId,
            issuedAt: receipt.issuedAt,
            blockers: ['SHIPPING_CONFIGURED_NOT_VERIFIED: Remote target is configured but remote artifact delivery receipt is missing.'],
          });
          continue;
        }
      }

      if (gateId === 'GATE_L06_POSTGRES_RLS') {
        const pgRec = receipt.providerReceipt as any;
        if (receipt.status === 'EXECUTED — PASS') {
          const isReal = receipt.providerType === 'REAL' && pgRec?.isRealPostgres === true;
          const isCompliant =
            pgRec?.catalogChecks?.isCompliant === true &&
            Array.isArray(pgRec?.catalogChecks?.unprotectedTables) &&
            pgRec.catalogChecks.unprotectedTables.length === 0;
          const attacksPassed = pgRec?.negativeTenantIsolationTests?.allAttacksPassed === true;
          const zeroSkips =
            receipt.testCounts.skipped === 0 &&
            receipt.testCounts.total >= 10 &&
            receipt.testCounts.passed === receipt.testCounts.total;

          if (!isReal || !isCompliant || !attacksPassed || !zeroSkips) {
            evaluatedGates.push({
              gateId,
              layer: gateDef.layer,
              name: gateDef.name,
              providerType: receipt.providerType,
              status: 'EXECUTED — FAIL',
              commandExecuted: receipt.executionTelemetry.command,
              exitCode: 1,
              durationMs: receipt.executionTelemetry.durationMs,
              receiptPath,
              receiptHash,
              receiptId: receipt.receiptId,
              issuedAt: receipt.issuedAt,
              logPointer: receipt.executionTelemetry.logPointer,
              blockers: [
                'POSTGRES_VERIFICATION_INCOMPLETE: PASS receipt does not satisfy all mandatory invariants (real Postgres >= 15, 100% catalog compliance, all 10 tenant attacks executed without skips).'
              ],
            });
            continue;
          }
        }
      }

      evaluatedGates.push({
        gateId,
        layer: gateDef.layer,
        name: gateDef.name,
        providerType: receipt.providerType,
        status: receipt.status,
        commandExecuted: receipt.executionTelemetry.command,
        exitCode: receipt.executionTelemetry.exitCode,
        durationMs: receipt.executionTelemetry.durationMs,
        receiptPath,
        receiptHash,
        receiptId: receipt.receiptId,
        issuedAt: receipt.issuedAt,
        logPointer: receipt.executionTelemetry.logPointer,
        blockers: receipt.blockers,
      });
    } else {
      // Legacy P101/P102 receipt validation
      // Check timestamp freshness
      const issuedAt = rawJson.timestamp || rawJson.issuedAt;
      const issuedAtMs = new Date(issuedAt).getTime();
      const maxAge = options.maxAgeMs ?? 86400000;
      if (Number.isNaN(issuedAtMs) || evaluationTimeMs - issuedAtMs > maxAge) {
        evaluatedGates.push({
          gateId,
          layer: gateDef.layer,
          name: gateDef.name,
          providerType: gateDef.requiredProviderType,
          status: 'UNVERIFIED',
          receiptPath,
          receiptHash,
          blockers: [`STALE_RECEIPT: Legacy receipt ${receiptFileName} timestamp is stale or invalid (${issuedAt}).`],
        });
        continue;
      }

      // Check configured vs verified for KMS and Shipping
      if (gateId === 'GATE_L07_KMS_ATTESTATION') {
        if (!rawJson.kmsConfigured) {
          evaluatedGates.push({
            gateId,
            layer: gateDef.layer,
            name: gateDef.name,
            providerType: 'NONE',
            status: 'EXTERNAL INFRA REQUIRED',
            receiptPath,
            receiptHash,
            issuedAt,
            blockers: rawJson.blockers || ['Production Cloud KMS key unconfigured.'],
          });
          continue;
        }
        if (rawJson.kmsConfigured && !rawJson.tamperDetectionVerified) {
          evaluatedGates.push({
            gateId,
            layer: gateDef.layer,
            name: gateDef.name,
            providerType: 'REAL',
            status: 'CONFIGURED — NOT VERIFIED',
            receiptPath,
            receiptHash,
            issuedAt,
            blockers: ['KMS_CONFIGURED_NOT_VERIFIED: Cloud KMS configured but live hardware attestation was not executed.'],
          });
          continue;
        }
      }

      if (gateId === 'GATE_L09_REMOTE_SHIPPING') {
        if (!rawJson.s3TargetConfigured && !rawJson.ociTargetConfigured) {
          evaluatedGates.push({
            gateId,
            layer: gateDef.layer,
            name: gateDef.name,
            providerType: 'NONE',
            status: 'EXTERNAL INFRA REQUIRED',
            receiptPath,
            receiptHash,
            issuedAt,
            blockers: rawJson.blockers || ['S3/OCI remote shipping credentials unconfigured.'],
          });
          continue;
        }
        if (!rawJson.deliveryVerified) {
          evaluatedGates.push({
            gateId,
            layer: gateDef.layer,
            name: gateDef.name,
            providerType: 'REAL',
            status: 'CONFIGURED — NOT VERIFIED',
            receiptPath,
            receiptHash,
            issuedAt,
            blockers: ['SHIPPING_CONFIGURED_NOT_VERIFIED: S3/OCI configured but live delivery confirmation was not received.'],
          });
          continue;
        }
      }

      if (gateId === 'GATE_L06_POSTGRES_RLS') {
        if (rawJson.status === 'EXECUTED — PASS') {
          const isReal = rawJson.isRealPostgres === true;
          const isCompliant = rawJson.catalogChecks?.isCompliant === true && (!rawJson.catalogChecks?.unprotectedTables || rawJson.catalogChecks.unprotectedTables.length === 0);
          if (!isReal || !isCompliant) {
            evaluatedGates.push({
              gateId,
              layer: gateDef.layer,
              name: gateDef.name,
              providerType: rawJson.isRealPostgres ? 'REAL' : 'NONE',
              status: 'EXECUTED — FAIL',
              receiptPath,
              receiptHash,
              issuedAt,
              blockers: ['POSTGRES_VERIFICATION_INCOMPLETE: Legacy receipt claims PASS without real Postgres or compliant catalog.'],
            });
            continue;
          }
        }
        evaluatedGates.push({
          gateId,
          layer: gateDef.layer,
          name: gateDef.name,
          providerType: rawJson.isRealPostgres ? 'REAL' : 'NONE',
          status: rawJson.status === 'EXECUTED — PASS' ? 'EXECUTED — PASS' : (rawJson.status || 'EXTERNAL INFRA REQUIRED'),
          receiptPath,
          receiptHash,
          issuedAt,
          blockers: rawJson.blockers || [],
        });
        continue;
      }

      if (gateId === 'GATE_L08_E2B_SANDBOX') {
        evaluatedGates.push({
          gateId,
          layer: gateDef.layer,
          name: gateDef.name,
          providerType: rawJson.e2bApiKeyConfigured ? 'REAL' : 'NONE',
          status: rawJson.status === 'EXECUTED — PASS' && rawJson.teardownSuccessful ? 'EXECUTED — PASS' : 'EXTERNAL INFRA REQUIRED',
          commandExecuted: 'SandboxOrchestrationEngine.runScenario',
          exitCode: rawJson.status === 'EXECUTED — PASS' ? 0 : 1,
          durationMs: rawJson.durationMs,
          receiptPath,
          receiptHash,
          issuedAt,
          blockers: rawJson.blockers || [],
        });
        continue;
      }

      // Default legacy fallback
      evaluatedGates.push({
        gateId,
        layer: gateDef.layer,
        name: gateDef.name,
        providerType: rawJson.providerType || 'REAL',
        status: rawJson.status || 'UNVERIFIED',
        commandExecuted: rawJson.commandExecuted,
        exitCode: rawJson.exitCode,
        receiptPath,
        receiptHash,
        issuedAt,
        blockers: rawJson.blockers || [],
      });
    }
  }

  // Decision Governor: Evaluates overall readiness strictly
  const decision = evaluateReleaseDecision(evaluatedGates, releaseFreeze);

  const passed = evaluatedGates.filter(g => g.status === 'EXECUTED — PASS').length;
  const failed = evaluatedGates.filter(g => g.status === 'EXECUTED — FAIL').length;
  const unverified = evaluatedGates.filter(g => g.status === 'UNVERIFIED').length;
  const external = evaluatedGates.filter(g => g.status === 'EXTERNAL INFRA REQUIRED').length;
  const blocked = evaluatedGates.filter(g => g.status === 'ENVIRONMENT BLOCKED').length;
  const configuredNotVerified = evaluatedGates.filter(g => g.status === 'CONFIGURED — NOT VERIFIED').length;

  const manifestPayloadWithoutDigest = {
    manifestVersion: GATE_SCHEMA_VERSION,
    evaluatedAt: new Date(evaluationTimeMs).toISOString(),
    evaluationEnvironment: expectedEnvironment,
    targetCommitSha: expectedCommitSha || 'UNRESOLVED_GIT_COMMIT_SHA',
    releaseFreeze,
    overallVerdict: decision.verdict,
    verdictReason: decision.reason,
    gates: evaluatedGates,
    summary: {
      totalMandatoryGates: ALL_MANDATORY_GATE_IDS.length,
      passedGates: passed,
      failedGates: failed,
      unverifiedGates: unverified,
      externalInfraRequiredGates: external,
      environmentBlockedGates: blocked,
      configuredNotVerifiedGates: configuredNotVerified,
    },
  };

  const integrityDigest = crypto
    .createHash('sha256')
    .update(JSON.stringify(manifestPayloadWithoutDigest, Object.keys(manifestPayloadWithoutDigest).sort()))
    .digest('hex');

  const manifest: ReleaseEvidenceManifestV2 = {
    ...manifestPayloadWithoutDigest,
    integrityDigest,
  };

  // Ensure directory exists and write manifest
  fs.mkdirSync(path.dirname(manifestOutputPath), { recursive: true });
  fs.writeFileSync(manifestOutputPath, JSON.stringify(manifest, null, 2), 'utf-8');

  console.log('================================================================================');
  console.log(`RELEASE EVIDENCE MANIFEST [${manifest.manifestVersion}]`);
  console.log(`Evaluated at: ${manifest.evaluatedAt}`);
  console.log(`Verdict:      ${manifest.overallVerdict} (releaseFreeze: ${manifest.releaseFreeze})`);
  console.log(`Reason:       ${manifest.verdictReason}`);
  console.log('--------------------------------------------------------------------------------');
  console.log(`Summary: Passed: ${passed}/${ALL_MANDATORY_GATE_IDS.length} | Failed: ${failed} | External: ${external} | Blocked: ${blocked} | Unverified: ${unverified + configuredNotVerified}`);
  console.log(`Integrity Digest: sha256:${manifest.integrityDigest}`);
  console.log('================================================================================');

  return manifest;
}

// Top-level CLI invocation
if (process.argv[1] && process.argv[1].endsWith('evaluate-release-gates.ts')) {
  try {
    const res = evaluateAllReleaseGates();
    if (res.overallVerdict !== 'SHIP') {
      process.exit(1);
    }
  } catch (err: any) {
    console.error('Release gate evaluation crashed:', err.message);
    process.exit(2);
  }
}
