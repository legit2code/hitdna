/**
 * TEST FIXTURE DEFINITIONS
 * TAG: TEST_FIXTURE
 * GOVERNANCE: For isolated automated-test/dev-fixture paths ONLY.
 * NEVER written to production collections or rendered as production intelligence.
 */

export const TEST_FIXTURE_SYSTEM_HEALTH = {
  TAG: 'TEST_FIXTURE' as const,
  fixtureId: 'FIX-SYS-001',
  status: 'healthy' as const,
  uptimeSeconds: 120,
  timestamp: '2026-09-03T16:00:00.000Z',
  version: '1.0.0',
  architectureVersion: '5.0.0',
  environment: 'test' as const,
  checks: {
    server: true,
    config: true,
    storage: true,
  },
};

export const TEST_FIXTURE_READINESS = {
  TAG: 'TEST_FIXTURE' as const,
  fixtureId: 'FIX-READY-001',
  ready: true,
  phase: 'P01',
  engineId: 'PF-02',
  missingRequirements: [],
  timestamp: '2026-09-03T16:00:00.000Z',
};
