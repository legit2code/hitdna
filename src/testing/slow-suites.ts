/**
 * Canonical list of slow test suites.
 * Used by vitest.config.ts for exclude and SLOW_TESTS_ONLY include.
 */
export const canonicalSlowSuites = [
  'src/__tests__/p19_sandbox_runtime_evasion.test.ts',
  'src/__tests__/p32_ci_migration_dr_release.test.ts',
  'src/__tests__/p33_performance_smoke_dedicated.test.ts',
  'tests/cross-tenant-rls-fail-closed.test.ts',
  'tests/rp00-verification-infrastructure.test.ts',
];
