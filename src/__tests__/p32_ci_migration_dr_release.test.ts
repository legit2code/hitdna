/**
 * P32 — CI/CD, Migration Safety, Security Scanning & DR Automation Test Suite
 * Verifies all 5 mandatory release gate invariants.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { 
  validateMigrationFromEmpty, 
  detectMigrationReordering, 
  detectDestructiveOperations,
  rehearseMigrationRollbackAndForwardFix,
  runSchemaAndRlsAssertions,
  executeFullMigrationSafetySuite,
  queryCatalogRlsCompliance,
  runCrossSessionMultiTenantNegativeTest
} from '@caim/db/migration-safety.js';
import { 
  DisasterRecoveryEngine,
  OutboxStageEvent
} from '@caim/workflow/dr-recovery.js';
import { scanFileForSecrets } from '../../scripts/secret-scanner.js';
import { runRootReleaseCheck } from '../../scripts/release-check.js';

describe('P32 — CI/CD, Migration Safety & Disaster Recovery Verification', () => {
  let drEngine: DisasterRecoveryEngine;

  beforeEach(() => {
    drEngine = new DisasterRecoveryEngine();
  });

  // =========================================================================
  // Requirement 1: Invalid Migration Fixture Fails
  // =========================================================================
  describe('1. Migration Safety & Invalid Fixture Rejections', () => {
    it('should cleanly apply all migrations from an empty database to HEAD', () => {
      const report = validateMigrationFromEmpty();
      expect(report.success).toBe(true);
      expect(report.appliedCount).toBeGreaterThanOrEqual(6);
      expect(report.headVersion).toBeDefined();
      expect(report.errors).toHaveLength(0);
    });

    it('should detect and REJECT out-of-order / backdated migrations', () => {
      const appliedLedger = ['20260823000001', '20260823000002', '20260823000003'];
      const reorderedIncoming = [
        { filename: '20260823000001_a.sql', version: '20260823000001', sql: 'SELECT 1;' },
        { filename: '20260823000000_injected_old.sql', version: '20260823000000', sql: 'SELECT 1;' }, // Out of order!
        { filename: '20260823000002_b.sql', version: '20260823000002', sql: 'SELECT 1;' },
      ];

      const check = detectMigrationReordering(appliedLedger, reorderedIncoming);
      expect(check.hasReordering).toBe(true);
      expect(check.violations.length).toBeGreaterThan(0);
    });

    it('should detect unreviewed destructive DDL operations (DROP TABLE, DROP COLUMN, TRUNCATE)', () => {
      const destructiveMigrations = [
        {
          filename: '20260823999999_unsafe_drop.sql',
          version: '20260823999999',
          sql: `
            DROP TABLE security.tenants;
            ALTER TABLE artifacts.packages DROP COLUMN package_name;
            TRUNCATE core.agent_versions;
          `,
        },
      ];

      const warnings = detectDestructiveOperations(destructiveMigrations);
      expect(warnings.length).toBeGreaterThanOrEqual(3);
      expect(warnings.some(w => w.operationType === 'DROP_TABLE' && w.riskLevel === 'CRITICAL')).toBe(true);
      expect(warnings.some(w => w.operationType === 'DROP_COLUMN' && w.riskLevel === 'HIGH')).toBe(true);
      expect(warnings.some(w => w.operationType === 'TRUNCATE' && w.riskLevel === 'CRITICAL')).toBe(true);
    });

    it('should pass rollback and forward-fix rehearsal simulation', () => {
      const fullReport = executeFullMigrationSafetySuite();
      expect(fullReport.rehearsalPassed).toBe(true);
      expect(fullReport.emptyDbMigrationSuccess).toBe(true);
    });
  });

  // =========================================================================
  // Requirement 2: Authorization Regression Fails (RLS Negative Tenant Probes)
  // =========================================================================
  describe('2. Multi-Tenant Authorization & RLS Negative Probes', () => {
    it('should enforce negative tenant isolation and block cross-tenant queries in memory db', () => {
      const migrationRes = validateMigrationFromEmpty();
      expect(migrationRes.success).toBe(true);

      const rlsResults = runSchemaAndRlsAssertions(migrationRes.db);
      expect(rlsResults.passed).toBe(true);

      const negTest = rlsResults.checks.find(c => c.name.includes('Negative RLS'));
      expect(negTest).toBeDefined();
      expect(negTest?.passed).toBe(true);
    });

    it('should dynamically query pg_class.relrowsecurity joined against classification table without drift', () => {
      const catalogResult = queryCatalogRlsCompliance();
      expect(catalogResult.isCompliant).toBe(true);
      expect(catalogResult.totalTablesChecked).toBeGreaterThanOrEqual(18);
      expect(catalogResult.rlsEnabledTables).toBe(catalogResult.totalTablesChecked);
      expect(catalogResult.unprotectedTables).toHaveLength(0);
      expect(catalogResult.tableDetails.every(t => t.rlsEnabled && t.forceRls)).toBe(true);
    });

    it('should open two real separate sessions with SET LOCAL app.current_tenant_id and confirm Tenant B is denied Tenant A data via select, join, and update', async () => {
      const crossSessionResult = await runCrossSessionMultiTenantNegativeTest();
      expect(crossSessionResult.passed).toBe(true);
      expect(crossSessionResult.probes.directTenantSelectCount).toBe(0);
      expect(crossSessionResult.probes.directScopeSelectCount).toBe(0);
      expect(crossSessionResult.probes.directRunSelectCount).toBe(0);
      expect(crossSessionResult.probes.directFindingSelectCount).toBe(0);
      expect(crossSessionResult.probes.crossTenantJoinCount).toBe(0);
      expect(crossSessionResult.probes.childTableJoinCount).toBe(0);
      expect(crossSessionResult.probes.updateTenantRowCount).toBe(0);
      expect(crossSessionResult.probes.updateRunRowCount).toBe(0);
      expect(crossSessionResult.probes.updateFindingRowCount).toBe(0);
      expect(crossSessionResult.probes.tenantADataIntegrityPreserved).toBe(true);
    });
  });

  // =========================================================================
  // Requirement 3: Fake Test Secret is Caught Without Real Credentials
  // =========================================================================
  describe('3. Zero-Leak Secret & Token Scanning', () => {
    it('should catch fake test secret token fixtures without using real credentials', () => {
      const dummyCodeWithSecret = `
        const cloudConfig = {
          geminiApiKey: "AIzaSyDummyFakeGeminiKey1234567890abcdef",
          awsKey: "AKIAIOSFODNN7EXAMPLE",
        };
      `;

      const findings = scanFileForSecrets('src/sample/config.ts', dummyCodeWithSecret);
      expect(findings.length).toBeGreaterThanOrEqual(2);
      expect(findings.some(f => f.patternName.includes('Gemini API Key'))).toBe(true);
      expect(findings.some(f => f.patternName.includes('AWS'))).toBe(true);
      // Ensure snippet is safely redacted
      expect(findings[0].matchedSnippet).toContain('...');
    });
  });

  // =========================================================================
  // Requirement 4: Rebuildable Vector Projections Can Be Cleared & Rebuilt
  // =========================================================================
  describe('4. Vector Projection Rebuilding from Authoritative KnowledgeObjects', () => {
    it('should wipe derived vector indices and rebuild them deterministically', () => {
      const initialCount = drEngine.getVectorCount();
      expect(initialCount).toBeGreaterThan(0);

      // Step 1: Wipe projections completely
      drEngine.clearVectorProjections();
      expect(drEngine.getVectorCount()).toBe(0);

      // Step 2: Rebuild from authoritative PostgreSQL state
      const rebuildResult = drEngine.rebuildVectorProjections();
      expect(rebuildResult.rebuiltCount).toBe(initialCount);
      expect(drEngine.getVectorCount()).toBe(initialCount);
      expect(Object.keys(rebuildResult.tenantCounts).length).toBeGreaterThanOrEqual(2);
    });
  });

  // =========================================================================
  // Requirement 5: Replay Cannot Duplicate a Committed Authoritative Stage Result
  // =========================================================================
  describe('5. Idempotent Outbox & Workflow Stage Replay', () => {
    it('should guarantee that stage replay cannot duplicate committed authoritative results', () => {
      const idempotencyKey = 'idem-stage-reachability-v1';
      const originalEvent: OutboxStageEvent = {
        eventId: 'evt-0099',
        idempotencyKey,
        pipelineId: 'pipe-prod-001',
        stageName: 'DEPENDENCY_REACHABILITY',
        stageStatus: 'COMPLETED',
        committedResult: { reachabilityScore: 0.95, vulnerableSinks: [] },
        committedAt: new Date().toISOString(),
      };

      // First run: commit
      const firstRun = drEngine.commitStageEvent(originalEvent);
      expect(firstRun.success).toBe(true);
      expect(firstRun.isDuplicate).toBe(false);

      // Replay run: identical idempotency key
      const replayRun = drEngine.commitStageEvent({
        ...originalEvent,
        committedResult: { reachabilityScore: 0.10, vulnerableSinks: ['malicious_sink'] }, // Attempted conflicting duplicate
      });

      expect(replayRun.success).toBe(true);
      expect(replayRun.isDuplicate).toBe(true);
      expect(replayRun.event.isReplay).toBe(true);
      // Invariant: Result must remain the authoritative original result, NOT the duplicate attempt
      expect(replayRun.event.committedResult.reachabilityScore).toBe(0.95);
    });
  });

  // =========================================================================
  // Requirement 6: Full DR Drill & Root Release Check
  // =========================================================================
  describe('6. Disaster Recovery Drills & Root Release Check Runner', () => {
    it('should successfully execute all 8 DR drills', () => {
      const drDrills = drEngine.runFullDRRehearsal();
      expect(drDrills).toHaveLength(8);
      expect(drDrills.every(d => d.passed)).toBe(true);
    });

    it('should run root release check and return BLOCKED pending unverified live gates', async () => {
      const releaseReport = await runRootReleaseCheck();
      expect(releaseReport.overallStatus).toBe('BLOCKED');
      expect(releaseReport.failedGates).toBe(0);
      expect(releaseReport.passedGates + releaseReport.notVerifiedGates).toBe(releaseReport.totalGates);
      expect(releaseReport.notVerifiedGates).toBeGreaterThanOrEqual(1);
    }, 60000);
  });
});
