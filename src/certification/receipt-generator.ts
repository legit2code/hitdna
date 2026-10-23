/**
 * CAIM Authentic Runner Receipt Generator
 * Architecture P103 — Secure Receipt Producer
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { 
  RunnerReceipt, 
  GATE_SCHEMA_VERSION, 
  GateId, 
  GateEvidenceStatus, 
  ProviderType,
  calculateReceiptHmac,
  RunnerReceiptSchema 
} from './gate-schema.ts';

export interface CreateReceiptParams {
  gateId: GateId;
  environment?: 'development' | 'staging' | 'production' | 'ci' | 'test';
  commitSha?: string;
  runnerType?: 'LOCAL' | 'CI_GITHUB_ACTIONS' | 'CI_REMOTE' | 'TEST_HARNESS';
  providerType: ProviderType;
  command: string;
  exitCode: number;
  durationMs: number;
  stdout: string;
  logPointer: string;
  testedRevision?: string;
  testCounts: { total: number; passed: number; failed: number; skipped: number };
  status: GateEvidenceStatus;
  providerReceipt?: Record<string, unknown>;
  secretKey?: string;
  blockers?: string[];
  outputPath?: string;
}

export function createAndSaveRunnerReceipt(params: CreateReceiptParams): RunnerReceipt {
  const startedAt = new Date(Date.now() - params.durationMs).toISOString();
  const completedAt = new Date().toISOString();
  const stdoutDigest = crypto.createHash('sha256').update(params.stdout || '').digest('hex');
  const commitSha = params.commitSha || process.env.GITHUB_SHA || process.env.COMMIT_SHA || '0000000000000000000000000000000000000000';
  const environment = params.environment || (process.env.NODE_ENV as any) || 'development';

  const unsignedReceipt: Omit<RunnerReceipt, 'tamperProofHmac'> = {
    schemaVersion: GATE_SCHEMA_VERSION,
    gateId: params.gateId,
    receiptId: `rcpt-${params.gateId.toLowerCase()}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    issuedAt: completedAt,
    environment,
    commitSha,
    runnerIdentity: {
      runnerId: process.env.RUNNER_NAME || process.env.HOSTNAME || 'local-runner',
      runnerType: params.runnerType || 'LOCAL',
      attestedBy: 'caim-runner-attestation-v2',
    },
    providerType: params.providerType,
    executionTelemetry: {
      command: params.command,
      exitCode: params.exitCode,
      startedAt,
      completedAt,
      durationMs: params.durationMs,
      stdoutDigest,
      logPointer: params.logPointer,
      testedRevision: params.testedRevision || commitSha,
    },
    testCounts: params.testCounts,
    status: params.status,
    providerReceipt: params.providerReceipt,
    blockers: params.blockers || [],
  };

  const secretKey = params.secretKey || process.env.CAIM_RUNNER_SECRET || 'caim-local-runner-integrity-key-2026';
  const tamperProofHmac = calculateReceiptHmac(unsignedReceipt as Record<string, unknown>, secretKey);

  const fullReceipt: RunnerReceipt = {
    ...unsignedReceipt,
    tamperProofHmac,
  };

  // Validate self with Zod
  RunnerReceiptSchema.parse(fullReceipt);

  if (params.outputPath) {
    const resolvedPath = path.resolve(process.cwd(), params.outputPath);
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, JSON.stringify(fullReceipt, null, 2), 'utf-8');
  }

  return fullReceipt;
}
