import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalSlowSuites } from '../src/testing/slow-suites.ts';

describe('P03 — Slow Suite Alignment & Coverage Invariants', () => {
  it('canonicalSlowSuites contains all 5 required slow test suites', () => {
    expect(canonicalSlowSuites).toHaveLength(5);
    expect(canonicalSlowSuites).toContain('src/__tests__/p19_sandbox_runtime_evasion.test.ts');
    expect(canonicalSlowSuites).toContain('src/__tests__/p32_ci_migration_dr_release.test.ts');
    expect(canonicalSlowSuites).toContain('src/__tests__/p33_performance_smoke_dedicated.test.ts');
    expect(canonicalSlowSuites).toContain('tests/cross-tenant-rls-fail-closed.test.ts');
    expect(canonicalSlowSuites).toContain('tests/rp00-verification-infrastructure.test.ts');
  });

  it('verifies every slow test file exists on disk', () => {
    for (const suitePath of canonicalSlowSuites) {
      const fullPath = path.resolve(process.cwd(), suitePath);
      expect(fs.existsSync(fullPath), `Expected ${suitePath} to exist on disk`).toBe(true);
    }
  });

  it('deliberate regression test: fails if any required slow-suite file is omitted', () => {
    const requiredSlowSuites = [
      'src/__tests__/p19_sandbox_runtime_evasion.test.ts',
      'src/__tests__/p32_ci_migration_dr_release.test.ts',
      'src/__tests__/p33_performance_smoke_dedicated.test.ts',
      'tests/cross-tenant-rls-fail-closed.test.ts',
      'tests/rp00-verification-infrastructure.test.ts',
    ];

    // Simulating omission of RP00
    const artificiallyCorruptedList = canonicalSlowSuites.filter(
      s => s !== 'tests/rp00-verification-infrastructure.test.ts'
    );

    const checkCoverage = (list: string[]) => {
      const missing = requiredSlowSuites.filter(req => !list.includes(req));
      if (missing.length > 0) {
        throw new Error(`Regression detected: missing slow suites: ${missing.join(', ')}`);
      }
    };

    expect(() => checkCoverage(artificiallyCorruptedList)).toThrowError(
      /Regression detected: missing slow suites: tests\/rp00-verification-infrastructure\.test\.ts/
    );

    // Canonical list passes
    expect(() => checkCoverage(canonicalSlowSuites)).not.toThrow();
  });

  it('verifies package.json scripts match slow test conventions', () => {
    const pkgJsonPath = path.resolve(process.cwd(), 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
    expect(pkg.scripts['test:slow']).toContain('SLOW_TESTS_ONLY=true');
    expect(pkg.scripts['test:all']).toContain('RUN_ALL_TESTS=true');
  });
});
