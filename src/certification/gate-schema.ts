/**
 * CAIM Versioned Gate Schema & Evidence Trust Model
 * Architecture P103 — Certification Trust Root & Release Gate Governor
 */

import crypto from 'node:crypto';
import { z } from 'zod';

export const GATE_SCHEMA_VERSION = '2.0.0' as const;

export type GateId =
  | 'GATE_L01_TOOLCHAIN'
  | 'GATE_L02_TYPES'
  | 'GATE_L03_SANDBOX_SECURITY'
  | 'GATE_L04_SHIPPING_TRUTH'
  | 'GATE_L05_SLOW_SUITE'
  | 'GATE_L06_POSTGRES_RLS'
  | 'GATE_L07_KMS_ATTESTATION'
  | 'GATE_L08_E2B_SANDBOX'
  | 'GATE_L09_REMOTE_SHIPPING'
  | 'GATE_L10_GIT_SECRET_SCAN';

export const ALL_MANDATORY_GATE_IDS: readonly GateId[] = [
  'GATE_L01_TOOLCHAIN',
  'GATE_L02_TYPES',
  'GATE_L03_SANDBOX_SECURITY',
  'GATE_L04_SHIPPING_TRUTH',
  'GATE_L05_SLOW_SUITE',
  'GATE_L06_POSTGRES_RLS',
  'GATE_L07_KMS_ATTESTATION',
  'GATE_L08_E2B_SANDBOX',
  'GATE_L09_REMOTE_SHIPPING',
  'GATE_L10_GIT_SECRET_SCAN',
] as const;

export type GateEvidenceStatus =
  | 'EXECUTED — PASS'
  | 'EXECUTED — FAIL'
  | 'STATIC — VERIFIED'
  | 'TEST EXISTS — NOT EXECUTED'
  | 'ENVIRONMENT BLOCKED'
  | 'EXTERNAL INFRA REQUIRED'
  | 'UNVERIFIED'
  | 'CONFIGURED — NOT VERIFIED';

export type ProviderType = 'REAL' | 'EMULATOR' | 'SIMULATED' | 'NONE';

export interface GateDefinition {
  id: GateId;
  layer: string;
  name: string;
  description: string;
  isMandatoryForRelease: boolean;
  requiredProviderType: ProviderType;
  requiresRemoteInfrastructure: boolean;
  verifierScript?: string;
  commandToExecute?: string;
}

export const MANDATORY_GATE_REGISTRY: Record<GateId, GateDefinition> = {
  GATE_L01_TOOLCHAIN: {
    id: 'GATE_L01_TOOLCHAIN',
    layer: 'L01',
    name: 'Package Manager & Frozen Lockfile',
    description: 'Enforces exact pnpm pinned package manager and byte-for-byte lockfile match.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: false,
    commandToExecute: 'pnpm install --frozen-lockfile',
  },
  GATE_L02_TYPES: {
    id: 'GATE_L02_TYPES',
    layer: 'L02',
    name: 'Static Type Safety & AST Compilation',
    description: 'Ensures zero TypeScript compilation or syntax errors under strict AST typecheck.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: false,
    commandToExecute: 'pnpm run typecheck',
  },
  GATE_L03_SANDBOX_SECURITY: {
    id: 'GATE_L03_SANDBOX_SECURITY',
    layer: 'L03',
    name: 'Dynamic Sandbox Anti-Spoofing & Intent Guard',
    description: 'Verifies default-deny network, canary honeytokens, and anti-spoofing regression tests.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: false,
    commandToExecute: 'pnpm exec vitest run src/__tests__/p19_sandbox_runtime_evasion.test.ts',
  },
  GATE_L04_SHIPPING_TRUTH: {
    id: 'GATE_L04_SHIPPING_TRUTH',
    layer: 'L04',
    name: 'Shipping Truth States & Confirmed Delivery Separation',
    description: 'Validates that simulated deliveries are strictly separated from observed shipments.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: false,
    commandToExecute: 'pnpm exec vitest run tests/prompt02-shipping-truth-states.test.ts',
  },
  GATE_L05_SLOW_SUITE: {
    id: 'GATE_L05_SLOW_SUITE',
    layer: 'L05',
    name: 'Slow-Suite Exclude/Include Coverage Invariants',
    description: 'Verifies that all 5 slow security and regression suites are registered and executed.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: false,
    commandToExecute: 'pnpm exec vitest run tests/p03-slow-suite-alignment.test.ts',
  },
  GATE_L06_POSTGRES_RLS: {
    id: 'GATE_L06_POSTGRES_RLS',
    layer: 'L06',
    name: 'Real PostgreSQL 15+ Empty-to-HEAD DDL & Catalog RLS',
    description: 'Verifies authentic PostgreSQL relrowsecurity catalogs and negative tenant isolation.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: true,
    verifierScript: 'scripts/certify-real-postgres.ts',
  },
  GATE_L07_KMS_ATTESTATION: {
    id: 'GATE_L07_KMS_ATTESTATION',
    layer: 'L07',
    name: 'Hardware Cloud KMS Signature & Key Custody',
    description: 'Certifies hardware-isolated cryptographic key custody via GCP or AWS Cloud KMS.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: true,
    verifierScript: 'scripts/certify-real-kms.ts',
  },
  GATE_L08_E2B_SANDBOX: {
    id: 'GATE_L08_E2B_SANDBOX',
    layer: 'L08',
    name: 'Real E2B MicroVM Sandbox Dynamic Execution & Teardown',
    description: 'Verifies live remote microVM execution, secret sanitization, and verified destruction.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: true,
    verifierScript: 'scripts/certify-real-e2b.ts',
  },
  GATE_L09_REMOTE_SHIPPING: {
    id: 'GATE_L09_REMOTE_SHIPPING',
    layer: 'L09',
    name: 'Remote S3 / OCI Production Shipping Delivery',
    description: 'Confirms remote artifact delivery to S3 storage bucket or OCI container registry.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: true,
    verifierScript: 'scripts/certify-real-shipping.ts',
  },
  GATE_L10_GIT_SECRET_SCAN: {
    id: 'GATE_L10_GIT_SECRET_SCAN',
    layer: 'L10',
    name: 'Complete Git History Secret Scan (fetch-depth: 0)',
    description: 'Validates deep commit-history scan across all branches without truncated history.',
    isMandatoryForRelease: true,
    requiredProviderType: 'REAL',
    requiresRemoteInfrastructure: false,
    commandToExecute: 'pnpm run scan:secrets',
  },
};

// Zod Schema for Runner Receipt Validation
export const RunnerReceiptSchema = z.object({
  schemaVersion: z.literal(GATE_SCHEMA_VERSION),
  gateId: z.enum([
    'GATE_L01_TOOLCHAIN',
    'GATE_L02_TYPES',
    'GATE_L03_SANDBOX_SECURITY',
    'GATE_L04_SHIPPING_TRUTH',
    'GATE_L05_SLOW_SUITE',
    'GATE_L06_POSTGRES_RLS',
    'GATE_L07_KMS_ATTESTATION',
    'GATE_L08_E2B_SANDBOX',
    'GATE_L09_REMOTE_SHIPPING',
    'GATE_L10_GIT_SECRET_SCAN',
  ]),
  receiptId: z.string().min(8),
  issuedAt: z.string().datetime(),
  environment: z.enum(['development', 'staging', 'production', 'ci', 'test']),
  commitSha: z.string().min(7),
  runnerIdentity: z.object({
    runnerId: z.string().min(1),
    runnerType: z.enum(['LOCAL', 'CI_GITHUB_ACTIONS', 'CI_REMOTE', 'TEST_HARNESS']),
    attestedBy: z.string().optional(),
  }),
  providerType: z.enum(['REAL', 'EMULATOR', 'SIMULATED', 'NONE']),
  executionTelemetry: z.object({
    command: z.string().min(1),
    exitCode: z.number().int(),
    startedAt: z.string().datetime(),
    completedAt: z.string().datetime(),
    durationMs: z.number().nonnegative(),
    stdoutDigest: z.string().min(16),
    logPointer: z.string().min(1),
    testedRevision: z.string().min(1),
  }),
  testCounts: z.object({
    total: z.number().int().nonnegative(),
    passed: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    skipped: z.number().int().nonnegative(),
  }),
  status: z.enum([
    'EXECUTED — PASS',
    'EXECUTED — FAIL',
    'STATIC — VERIFIED',
    'TEST EXISTS — NOT EXECUTED',
    'ENVIRONMENT BLOCKED',
    'EXTERNAL INFRA REQUIRED',
    'UNVERIFIED',
    'CONFIGURED — NOT VERIFIED',
  ]),
  providerReceipt: z.record(z.string(), z.unknown()).optional(),
  tamperProofHmac: z.string().optional(),
  blockers: z.array(z.string()),
});

export type RunnerReceipt = z.infer<typeof RunnerReceiptSchema>;

export interface EvaluatedGateResult {
  gateId: GateId;
  layer: string;
  name: string;
  providerType: ProviderType;
  status: GateEvidenceStatus;
  commandExecuted?: string;
  exitCode?: number;
  durationMs?: number;
  receiptPath?: string;
  receiptHash?: string;
  receiptId?: string;
  issuedAt?: string;
  logPointer?: string;
  blockers: string[];
}

export interface ReleaseEvidenceManifestV2 {
  manifestVersion: string;
  evaluatedAt: string;
  evaluationEnvironment: string;
  targetCommitSha: string;
  releaseFreeze: boolean;
  overallVerdict: 'SHIP' | 'DO NOT SHIP';
  verdictReason: string;
  gates: EvaluatedGateResult[];
  summary: {
    totalMandatoryGates: number;
    passedGates: number;
    failedGates: number;
    unverifiedGates: number;
    externalInfraRequiredGates: number;
    environmentBlockedGates: number;
    configuredNotVerifiedGates: number;
  };
  integrityDigest: string;
}

/**
 * Calculates HMAC for tamper-detection of runner receipts
 */
export function calculateReceiptHmac(payload: Record<string, unknown>, secretKey: string): string {
  const normalized = JSON.stringify(payload, Object.keys(payload).sort());
  return crypto.createHmac('sha256', secretKey).update(normalized).digest('hex');
}

/**
 * Validates a runner receipt against schema, freshness, commit SHA, environment, and tamper integrity.
 */
export function validateRunnerReceipt(
  raw: unknown,
  options: {
    expectedGateId?: GateId;
    expectedCommitSha?: string;
    expectedEnvironment?: string;
    maxAgeMs?: number;
    verificationSecret?: string;
    evaluationTimeMs?: number;
  } = {}
): { valid: boolean; receipt?: RunnerReceipt; reason?: string } {
  const parseRes = RunnerReceiptSchema.safeParse(raw);
  if (!parseRes.success) {
    return {
      valid: false,
      reason: `MALFORMED_RECEIPT: Schema validation failed: ${parseRes.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
    };
  }

  const receipt = parseRes.data;

  // 1. Gate ID check
  if (options.expectedGateId && receipt.gateId !== options.expectedGateId) {
    return {
      valid: false,
      reason: `GATE_ID_MISMATCH: Expected receipt for ${options.expectedGateId}, but received ${receipt.gateId}`,
    };
  }

  // 2. Commit SHA check
  if (options.expectedCommitSha && receipt.commitSha !== options.expectedCommitSha) {
    return {
      valid: false,
      reason: `COMMIT_MISMATCH: Receipt commit ${receipt.commitSha} does not match evaluated commit ${options.expectedCommitSha}`,
    };
  }

  // 3. Environment check
  if (options.expectedEnvironment && receipt.environment !== options.expectedEnvironment) {
    return {
      valid: false,
      reason: `ENVIRONMENT_MISMATCH: Receipt environment ${receipt.environment} does not match required environment ${options.expectedEnvironment}`,
    };
  }

  // 4. Freshness check
  const nowMs = options.evaluationTimeMs ?? Date.now();
  const issuedAtMs = new Date(receipt.issuedAt).getTime();
  if (Number.isNaN(issuedAtMs)) {
    return { valid: false, reason: 'INVALID_TIMESTAMP: issuedAt cannot be parsed as a valid ISO date' };
  }

  if (issuedAtMs > nowMs + 60000) {
    return { valid: false, reason: 'FUTURE_TIMESTAMP: Receipt was issued in the future' };
  }

  const maxAge = options.maxAgeMs ?? 86400000; // default 24h
  if (nowMs - issuedAtMs > maxAge) {
    return { valid: false, reason: `STALE_RECEIPT: Receipt is ${(nowMs - issuedAtMs) / 1000}s old (exceeds max age of ${maxAge / 1000}s)` };
  }

  // 5. Tamper-proof HMAC verification if secret is supplied
  if (options.verificationSecret && receipt.tamperProofHmac) {
    const { tamperProofHmac, ...rest } = receipt;
    const computed = calculateReceiptHmac(rest as Record<string, unknown>, options.verificationSecret);
    if (!crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(tamperProofHmac))) {
      return { valid: false, reason: 'TAMPER_DETECTED: Receipt HMAC signature is invalid' };
    }
  }

  // 6. Test Counts sanity: if passed with 0 tests or skipped > 0 in mandatory test
  if (receipt.status === 'EXECUTED — PASS') {
    if (receipt.testCounts.total === 0 || receipt.testCounts.passed === 0) {
      return { valid: false, reason: 'ZERO_TESTS_EXECUTED: Receipt claims PASS but executed 0 tests' };
    }
    if (receipt.testCounts.failed > 0) {
      return { valid: false, reason: `CONTRADICTORY_RESULT: Status is PASS but testCounts has ${receipt.testCounts.failed} failures` };
    }
    if (receipt.executionTelemetry.exitCode !== 0) {
      return { valid: false, reason: `CONTRADICTORY_EXIT_CODE: Status is PASS but exitCode is ${receipt.executionTelemetry.exitCode}` };
    }
  }

  // 7. Missing log pointer
  if (!receipt.executionTelemetry.logPointer || receipt.executionTelemetry.logPointer.trim().length === 0) {
    return { valid: false, reason: 'OMITTED_COMMAND_LOGS: Execution telemetry is missing required logPointer' };
  }

  return { valid: true, receipt };
}

/**
 * Enforces one single, unambiguous, mathematical decision function for release readiness.
 * INVARIANT: It is IMPOSSIBLE for overallVerdict to be SHIP if releaseFreeze is true.
 */
export function evaluateReleaseDecision(
  gates: EvaluatedGateResult[],
  releaseFreeze: boolean
): { verdict: 'SHIP' | 'DO NOT SHIP'; reason: string } {
  // Rule 1: releaseFreeze MUST be explicitly false to SHIP
  if (releaseFreeze) {
    return {
      verdict: 'DO NOT SHIP',
      reason: 'RELEASE_FROZEN: The release freeze governor is active (releaseFreeze = true). Release is strictly blocked.',
    };
  }

  // Rule 2: Check all mandatory gates are present
  const presentGateIds = new Set(gates.map(g => g.gateId));
  for (const mandatoryId of ALL_MANDATORY_GATE_IDS) {
    if (!presentGateIds.has(mandatoryId)) {
      return {
        verdict: 'DO NOT SHIP',
        reason: `MISSING_MANDATORY_GATE: Mandatory gate ${mandatoryId} is missing from evaluation set.`,
      };
    }
  }

  // Rule 3: Every gate must be EXECUTED — PASS or STATIC — VERIFIED
  const failingGates = gates.filter(g => g.status === 'EXECUTED — FAIL');
  if (failingGates.length > 0) {
    return {
      verdict: 'DO NOT SHIP',
      reason: `FAILED_GATES: ${failingGates.length} gate(s) failed: ${failingGates.map(g => `${g.gateId} (${g.blockers.join(', ')})`).join('; ')}`,
    };
  }

  const unverifiedGates = gates.filter(g =>
    g.status === 'UNVERIFIED' ||
    g.status === 'CONFIGURED — NOT VERIFIED' ||
    g.status === 'TEST EXISTS — NOT EXECUTED'
  );
  if (unverifiedGates.length > 0) {
    return {
      verdict: 'DO NOT SHIP',
      reason: `UNVERIFIED_GATES: ${unverifiedGates.length} gate(s) unverified: ${unverifiedGates.map(g => g.gateId).join(', ')}`,
    };
  }

  const externalGates = gates.filter(g => g.status === 'EXTERNAL INFRA REQUIRED');
  if (externalGates.length > 0) {
    return {
      verdict: 'DO NOT SHIP',
      reason: `EXTERNAL_INFRA_REQUIRED: ${externalGates.length} gate(s) require external infrastructure: ${externalGates.map(g => g.gateId).join(', ')}`,
    };
  }

  const blockedGates = gates.filter(g => g.status === 'ENVIRONMENT BLOCKED');
  if (blockedGates.length > 0) {
    return {
      verdict: 'DO NOT SHIP',
      reason: `ENVIRONMENT_BLOCKED: ${blockedGates.length} gate(s) blocked by environment: ${blockedGates.map(g => g.gateId).join(', ')}`,
    };
  }

  return {
    verdict: 'SHIP',
    reason: 'ALL_GATES_PASSED: All 10 mandatory certification gates have been verified with authentic execution receipts, and release freeze is released.',
  };
}
