/**
 * Regression Test Suite for P103 Certification Trust Root & Release Aggregator
 * (CERT-04, CERT-09)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  evaluateAllReleaseGates,
} from '../scripts/evaluate-release-gates.ts';
import {
  validateRunnerReceipt,
  evaluateReleaseDecision,
  calculateReceiptHmac,
  RunnerReceipt,
  GATE_SCHEMA_VERSION,
  EvaluatedGateResult,
} from '../src/certification/gate-schema.ts';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';

describe('P103 — Certification Trust Root & Gate Aggregator (CERT-04, CERT-09)', () => {
  let tempDir: string;
  const testSecret = 'test-runner-attestation-secret-key-12345';

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-cert-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  function createValidV2Receipt(overrides: Partial<Parameters<typeof createAndSaveRunnerReceipt>[0]> = {}): RunnerReceipt {
    return createAndSaveRunnerReceipt({
      gateId: 'GATE_L01_TOOLCHAIN',
      providerType: 'REAL',
      command: 'pnpm install --frozen-lockfile',
      exitCode: 0,
      durationMs: 1200,
      stdout: 'Lockfile up to date',
      logPointer: '/tmp/test.log',
      testCounts: { total: 1, passed: 1, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      commitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      environment: 'development',
      secretKey: testSecret,
      ...overrides,
    });
  }

  it('BENIGN CONTROL: Valid fresh signed-runner artifact passes validation', () => {
    const receipt = createValidV2Receipt();
    const validation = validateRunnerReceipt(receipt, {
      expectedGateId: 'GATE_L01_TOOLCHAIN',
      expectedCommitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      expectedEnvironment: 'development',
      verificationSecret: testSecret,
      maxAgeMs: 60000,
    });

    expect(validation.valid).toBe(true);
    expect(validation.receipt?.gateId).toBe('GATE_L01_TOOLCHAIN');
  });

  it('EMPTY ARTIFACT SET: Yields DO NOT SHIP with zero passed gates', () => {
    const manifest = evaluateAllReleaseGates({
      receiptsDir: tempDir,
      manifestOutputPath: path.join(tempDir, 'manifest.json'),
      releaseFreeze: false,
    });

    expect(manifest.overallVerdict).toBe('DO NOT SHIP');
    expect(manifest.summary.passedGates).toBe(0);
    expect(manifest.summary.totalMandatoryGates).toBe(10);
    expect(manifest.gates.every(g => g.status !== 'EXECUTED — PASS')).toBe(true);
  });

  it('REMOVE A RECEIPT: Marks gate UNVERIFIED and yields DO NOT SHIP', () => {
    // Seed 1 receipt only
    createValidV2Receipt({
      gateId: 'GATE_L01_TOOLCHAIN',
      outputPath: path.join(tempDir, 'gate-l01-toolchain-receipt.json'),
      secretKey: testSecret,
    });

    const manifest = evaluateAllReleaseGates({
      receiptsDir: tempDir,
      manifestOutputPath: path.join(tempDir, 'manifest.json'),
      releaseFreeze: false,
    });

    expect(manifest.overallVerdict).toBe('DO NOT SHIP');
    const l02Gate = manifest.gates.find(g => g.gateId === 'GATE_L02_TYPES');
    expect(l02Gate?.status).toBe('UNVERIFIED');
    expect(l02Gate?.blockers[0]).toContain('MISSING_RECEIPT');
  });

  it('FLIP A FAILED RECEIPT TO PASS: Detects tamper via HMAC invalidation', () => {
    const failedReceipt = createValidV2Receipt({
      exitCode: 1,
      status: 'EXECUTED — FAIL',
      testCounts: { total: 1, passed: 0, failed: 1, skipped: 0 },
      secretKey: testSecret,
    });

    // Manually tamper with receipt JSON
    const tampered = {
      ...failedReceipt,
      status: 'EXECUTED — PASS' as const,
      executionTelemetry: {
        ...failedReceipt.executionTelemetry,
        exitCode: 0,
      },
    };

    const validation = validateRunnerReceipt(tampered, {
      verificationSecret: testSecret,
    });

    expect(validation.valid).toBe(false);
    expect(validation.reason).toContain('TAMPER_DETECTED');
  });

  it('WRONG BUILD SHA: Rejects receipt due to commit mismatch', () => {
    const receipt = createValidV2Receipt({
      commitSha: 'commit_1111111111111111111111111111111111111111',
      secretKey: testSecret,
    });

    const validation = validateRunnerReceipt(receipt, {
      expectedCommitSha: 'commit_2222222222222222222222222222222222222222',
      verificationSecret: testSecret,
    });

    expect(validation.valid).toBe(false);
    expect(validation.reason).toContain('COMMIT_MISMATCH');
  });

  it('OLD TIMESTAMP: Rejects stale receipt', () => {
    const twoDaysAgo = new Date(Date.now() - 172800000).toISOString();
    const unsigned: any = {
      schemaVersion: GATE_SCHEMA_VERSION,
      gateId: 'GATE_L01_TOOLCHAIN',
      receiptId: 'rcpt-stale-1',
      issuedAt: twoDaysAgo,
      environment: 'development',
      commitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      runnerIdentity: { runnerId: 'r1', runnerType: 'LOCAL' },
      providerType: 'REAL',
      executionTelemetry: {
        command: 'pnpm install',
        exitCode: 0,
        startedAt: twoDaysAgo,
        completedAt: twoDaysAgo,
        durationMs: 100,
        stdoutDigest: 'abcd1234abcd1234',
        logPointer: '/tmp/log.log',
        testedRevision: 'a1b2c3d4e5f6',
      },
      testCounts: { total: 1, passed: 1, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      blockers: [],
    };
    unsigned.tamperProofHmac = calculateReceiptHmac(unsigned, testSecret);

    const validation = validateRunnerReceipt(unsigned, {
      maxAgeMs: 3600000, // 1 hour max age
      verificationSecret: testSecret,
    });

    expect(validation.valid).toBe(false);
    expect(validation.reason).toContain('STALE_RECEIPT');
  });

  it('MISMATCHED ENVIRONMENT: Rejects development receipt for production gate', () => {
    const receipt = createValidV2Receipt({
      environment: 'development',
      secretKey: testSecret,
    });

    const validation = validateRunnerReceipt(receipt, {
      expectedEnvironment: 'production',
      verificationSecret: testSecret,
    });

    expect(validation.valid).toBe(false);
    expect(validation.reason).toContain('ENVIRONMENT_MISMATCH');
  });

  it('KMS CONFIGURED=TRUE WITHOUT OPERATION: Evaluates as CONFIGURED — NOT VERIFIED, not PASS', () => {
    // Seed KMS receipt claiming configured=true but tamperDetectionVerified=false
    const kmsReceiptPath = path.join(tempDir, 'kms-receipt.json');
    fs.writeFileSync(kmsReceiptPath, JSON.stringify({
      harnessVersion: '1.0.0',
      timestamp: new Date().toISOString(),
      status: 'EXECUTED — PASS',
      kmsConfigured: true,
      tamperDetectionVerified: false, // Not actually verified!
      blockers: [],
    }), 'utf-8');

    const manifest = evaluateAllReleaseGates({
      receiptsDir: tempDir,
      manifestOutputPath: path.join(tempDir, 'manifest.json'),
      releaseFreeze: false,
    });

    const kmsGate = manifest.gates.find(g => g.gateId === 'GATE_L07_KMS_ATTESTATION');
    expect(kmsGate?.status).toBe('CONFIGURED — NOT VERIFIED');
    expect(manifest.overallVerdict).toBe('DO NOT SHIP');
  });

  it('SHIPPING CONFIGURED=TRUE WITHOUT RECEIPT: Evaluates as CONFIGURED — NOT VERIFIED, not PASS', () => {
    // Seed shipping receipt claiming s3TargetConfigured=true but deliveryVerified=false
    const shippingReceiptPath = path.join(tempDir, 'shipping-receipt.json');
    fs.writeFileSync(shippingReceiptPath, JSON.stringify({
      harnessVersion: '1.0.0',
      timestamp: new Date().toISOString(),
      status: 'EXECUTED — PASS',
      s3TargetConfigured: true,
      deliveryVerified: false, // Not verified!
      blockers: [],
    }), 'utf-8');

    const manifest = evaluateAllReleaseGates({
      receiptsDir: tempDir,
      manifestOutputPath: path.join(tempDir, 'manifest.json'),
      releaseFreeze: false,
    });

    const shipGate = manifest.gates.find(g => g.gateId === 'GATE_L09_REMOTE_SHIPPING');
    expect(shipGate?.status).toBe('CONFIGURED — NOT VERIFIED');
    expect(manifest.overallVerdict).toBe('DO NOT SHIP');
  });

  it('OMITTED COMMAND LOGS: Missing logPointer fails receipt validation', () => {
    const invalidReceipt: any = {
      schemaVersion: GATE_SCHEMA_VERSION,
      gateId: 'GATE_L01_TOOLCHAIN',
      receiptId: 'rcpt-test-no-log',
      issuedAt: new Date().toISOString(),
      environment: 'development',
      commitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      runnerIdentity: { runnerId: 'r1', runnerType: 'LOCAL' },
      providerType: 'REAL',
      executionTelemetry: {
        command: 'pnpm install',
        exitCode: 0,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 100,
        stdoutDigest: 'abcd1234abcd1234',
        logPointer: '', // OMITTED!
        testedRevision: 'a1b2c3d4e5f6',
      },
      testCounts: { total: 1, passed: 1, failed: 0, skipped: 0 },
      status: 'EXECUTED — PASS',
      blockers: [],
    };

    const validation = validateRunnerReceipt(invalidReceipt);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toMatch(/logPointer|OMITTED_COMMAND_LOGS/);
  });

  it('SKIPPED MANDATORY TEST: Contradictory test counts fail receipt validation', () => {
    const invalidReceipt: any = {
      schemaVersion: GATE_SCHEMA_VERSION,
      gateId: 'GATE_L03_SANDBOX_SECURITY',
      receiptId: 'rcpt-test-skipped',
      issuedAt: new Date().toISOString(),
      environment: 'development',
      commitSha: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      runnerIdentity: { runnerId: 'r1', runnerType: 'LOCAL' },
      providerType: 'REAL',
      executionTelemetry: {
        command: 'vitest',
        exitCode: 0,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 100,
        stdoutDigest: 'abcd1234abcd1234',
        logPointer: '/tmp/test.log',
        testedRevision: 'a1b2c3d4e5f6',
      },
      testCounts: { total: 10, passed: 0, failed: 0, skipped: 10 }, // All skipped!
      status: 'EXECUTED — PASS', // Claims PASS despite 0 passed
      blockers: [],
    };

    const validation = validateRunnerReceipt(invalidReceipt);
    expect(validation.valid).toBe(false);
    expect(validation.reason).toContain('ZERO_TESTS_EXECUTED');
  });

  it('CONTRADICTORY RELEASEFREEZE AND SHIP: releaseFreeze=true strictly forbids SHIP', () => {
    // Mock 10 perfectly passed gates
    const allPassedGates: EvaluatedGateResult[] = [
      { gateId: 'GATE_L01_TOOLCHAIN', layer: 'L01', name: 'L01', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L02_TYPES', layer: 'L02', name: 'L02', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L03_SANDBOX_SECURITY', layer: 'L03', name: 'L03', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L04_SHIPPING_TRUTH', layer: 'L04', name: 'L04', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L05_SLOW_SUITE', layer: 'L05', name: 'L05', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L06_POSTGRES_RLS', layer: 'L06', name: 'L06', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L07_KMS_ATTESTATION', layer: 'L07', name: 'L07', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L08_E2B_SANDBOX', layer: 'L08', name: 'L08', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L09_REMOTE_SHIPPING', layer: 'L09', name: 'L09', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
      { gateId: 'GATE_L10_GIT_SECRET_SCAN', layer: 'L10', name: 'L10', providerType: 'REAL', status: 'EXECUTED — PASS', blockers: [] },
    ];

    // Even if ALL 10 gates passed, if releaseFreeze is true:
    const decisionWithFreeze = evaluateReleaseDecision(allPassedGates, true);
    expect(decisionWithFreeze.verdict).toBe('DO NOT SHIP');
    expect(decisionWithFreeze.reason).toContain('RELEASE_FROZEN');

    // Only when releaseFreeze is false AND all 10 gates passed can it SHIP:
    const decisionWithoutFreeze = evaluateReleaseDecision(allPassedGates, false);
    expect(decisionWithoutFreeze.verdict).toBe('SHIP');
  });
});
