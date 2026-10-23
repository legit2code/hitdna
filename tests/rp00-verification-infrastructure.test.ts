import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  Rp00VerificationReceiptSchema,
  PreGitHistoryStatusEnum,
} from '@caim/packaging/types.ts';
import { runSecretScan, scanBundleDirectory } from '../scripts/secret-scanner.ts';

describe('RP-00 — Verification Infrastructure & Gate Controls', () => {
  it('enforces exact packageManager in package.json', () => {
    const pkgJsonPath = path.resolve(process.cwd(), 'package.json');
    const content = fs.readFileSync(pkgJsonPath, 'utf-8');
    const pkg = JSON.parse(content);
    expect(pkg.packageManager).toBe('pnpm@9.15.9');
  });

  it('validates Rp00VerificationReceipt schema with preGitHistoryStatus', () => {
    const receiptData = {
      schemaVersion: 'https://caim.security/schema/rp00-receipt/v1' as const,
      phase: 'RP-00' as const,
      phaseStatus: 'BLOCKED' as const,
      timestamp: new Date().toISOString(),
      preGitHistoryStatus: 'NOT_APPLICABLE_NO_PRIOR_GIT_REPOSITORY' as const,
      sourceSnapshotSha256: null,
      gitCommitSha: null,
      releaseArtifactSha256: null,
      ciRunId: null,
      packageManagerVersion: 'pnpm@9.15.9',
      historySecretScan: {
        status: 'NOT_APPLICABLE' as const,
        findingsCount: 0,
        summary: 'No prior Git history in ephemeral Studio runtime.',
      },
      bundleSecretScan: {
        status: 'PENDING_BUILD' as const,
        findingsCount: 0,
        clientBundleClean: true,
        serverBundleClean: true,
        summary: 'Client/server bundle scan to be verified in CI.',
      },
      releaseFreezeActive: true,
      auditNotes: 'RP-00 verification infrastructure in place.',
    };

    const parsed = Rp00VerificationReceiptSchema.safeParse(receiptData);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.preGitHistoryStatus).toBe('NOT_APPLICABLE_NO_PRIOR_GIT_REPOSITORY');
      expect(parsed.data.phaseStatus).toBe('BLOCKED');
      expect(parsed.data.releaseFreezeActive).toBe(true);
    }
  });

  it('runs internal secret scanner cleanly without leaks in tracked repository files', () => {
    const scan = runSecretScan();
    expect(scan.passed).toBe(true);
    expect(scan.findings.length).toBe(0);
  });

  it('verifies CI pipeline config enforces fetch-depth: 0, pnpm/action-setup, and frozen lockfile', () => {
    const ciYamlPath = path.resolve(process.cwd(), '.github/workflows/ci.yml');
    expect(fs.existsSync(ciYamlPath)).toBe(true);
    const content = fs.readFileSync(ciYamlPath, 'utf-8');
    expect(content).toContain('fetch-depth: 0');
    expect(content).toContain('pnpm/action-setup@v4');
    expect(content).toContain('version: 9.15.9');
    expect(content).toContain('pnpm install --frozen-lockfile');
    expect(content).toContain('git log -p');
    expect(content).toContain('scanBundleDirectory');
  });

  it('verifies BUILD_STATE.json tracks RP-00 as BLOCKED with releaseFreeze: true', () => {
    const buildStatePath = path.resolve(process.cwd(), 'docs/implementation/BUILD_STATE.json');
    const content = fs.readFileSync(buildStatePath, 'utf-8');
    const state = JSON.parse(content);
    expect(state.currentPhase).toBe('RP-00');
    expect(state.phaseStatus).toBe('BLOCKED');
    expect(state.releaseFreeze).toBe(true);
  });
});
