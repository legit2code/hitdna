import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { runRootReleaseCheck } from '../scripts/release-check.ts';
import { scanBundleDirectory } from '../scripts/secret-scanner.ts';

describe('Release Check Strictness & Release Gate Assurance', () => {
  const testDistDir = path.resolve(process.cwd(), 'dist-test-strictness');

  beforeEach(() => {
    if (fs.existsSync(testDistDir)) {
      fs.rmSync(testDistDir, { recursive: true, force: true });
    }
    fs.mkdirSync(testDistDir, { recursive: true });
  });

  afterEach(() => {
    if (fs.existsSync(testDistDir)) {
      fs.rmSync(testDistDir, { recursive: true, force: true });
    }
  });

  it('missing Git SHA results in overallStatus BLOCKED (never RELEASE_APPROVED)', async () => {
    // When Git SHA is null or non-40-hex, status must be BLOCKED
    const report = await runRootReleaseCheck({
      overrideBuildCommit: null,
      overrideCiRunId: '12345678',
      overrideArtifactDigest: 'a'.repeat(64),
    });

    expect(report.overallStatus).toBe('BLOCKED');
    expect(report.blockedReasons).toBeDefined();
    expect(report.blockedReasons?.some(r => r.includes('40-character hexadecimal Git commit SHA'))).toBe(true);
  }, 60000);

  it('invalid non-hex Git SHA string results in overallStatus BLOCKED', async () => {
    const report = await runRootReleaseCheck({
      overrideBuildCommit: 'LOCAL_DEV_WORKSPACE_SNAPSHOT_RP00R', // Descriptive string fallback prohibited!
      overrideCiRunId: '12345678',
      overrideArtifactDigest: 'a'.repeat(64),
    });

    expect(report.overallStatus).toBe('BLOCKED');
    expect(report.blockedReasons?.some(r => r.includes('40-character hexadecimal Git commit SHA'))).toBe(true);
  }, 60000);

  it('missing CI run ID results in overallStatus BLOCKED', async () => {
    const report = await runRootReleaseCheck({
      overrideBuildCommit: 'a'.repeat(40),
      overrideCiRunId: null,
      overrideArtifactDigest: 'a'.repeat(64),
    });

    expect(report.overallStatus).toBe('BLOCKED');
    expect(report.blockedReasons?.some(r => r.includes('CI run identifier'))).toBe(true);
  }, 60000);

  it('missing artifact digest results in overallStatus BLOCKED', async () => {
    const report = await runRootReleaseCheck({
      overrideBuildCommit: 'a'.repeat(40),
      overrideCiRunId: '12345678',
      overrideArtifactDigest: null,
    });

    expect(report.overallStatus).toBe('BLOCKED');
    expect(report.blockedReasons?.some(r => r.includes('built artifact digest'))).toBe(true);
  }, 60000);

  it('any NOT_VERIFIED gate results in overallStatus BLOCKED (never RELEASE_APPROVED)', async () => {
    const report = await runRootReleaseCheck({
      overrideBuildCommit: 'a'.repeat(40),
      overrideCiRunId: '12345678',
      overrideArtifactDigest: 'a'.repeat(64),
    });

    // Gate DEPLOY-01 is explicitly NOT_VERIFIED
    const notVerifiedGate = report.gates.find(g => g.status === 'NOT_VERIFIED');
    expect(notVerifiedGate).toBeDefined();
    expect(report.notVerifiedGates).toBeGreaterThan(0);
    expect(report.overallStatus).toBe('BLOCKED');
  }, 60000);

  it('missing dist directory fails bundle scan with FAIL and error', () => {
    const nonExistentDir = path.resolve(process.cwd(), 'does-not-exist-dist-dir-12345');
    const result = scanBundleDirectory(nonExistentDir);

    expect(result.passed).toBe(false);
    expect(result.totalBundlesScanned).toBe(0);
    expect(result.error).toContain('does not exist');
  });

  it('zero eligible bundles fails bundle scan with FAIL and error', () => {
    // Empty directory has zero eligible bundle files
    const result = scanBundleDirectory(testDistDir);

    expect(result.passed).toBe(false);
    expect(result.totalBundlesScanned).toBe(0);
    expect(result.error).toContain('zero eligible bundle files found');
  });

  it('leaked secret in bundle directory fails bundle scan', () => {
    fs.writeFileSync(
      path.join(testDistDir, 'app.bundle.js'),
      'const secret_key = "test_fixture_secret_token_12345678901234567890";\nconsole.log(secret_key);'
    );

    const result = scanBundleDirectory(testDistDir);
    expect(result.passed).toBe(false);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.totalBundlesScanned).toBe(1);
  });
});
