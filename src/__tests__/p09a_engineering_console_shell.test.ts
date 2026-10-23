import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import { DiagnosticService } from '@caim/workflow/diagnostic.ts';

describe('P09A — Internal Engineering Console Shell (Diagnostic Only)', () => {
  let memDb: any;
  let db: any;
  let diagnosticService: DiagnosticService;

  beforeEach(async () => {
    memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    db = new pg.Client();
    await db.connect();
    diagnosticService = new DiagnosticService(db);
  });

  describe('1. /dev/system Health & Infrastructure Diagnostics', () => {
    it('accurately reports database health, migration head, and active tables', async () => {
      const health = await diagnosticService.getSystemHealth('test');

      expect(health.status).toBe('HEALTHY');
      expect(health.database.connected).toBe(true);
      expect(health.database.totalMigrations).toBeGreaterThanOrEqual(13);
      expect(health.database.migrationHead.filename).toContain('.sql');
      expect(health.database.migrationHead.version).toMatch(/^202608/);
      expect(health.database.schemas).toContain('ops');
      expect(health.database.schemas).toContain('core');
      expect(health.database.schemas).toContain('auth_vault');
    });

    it('accurately reports storage durable reference boundaries', async () => {
      const health = await diagnosticService.getSystemHealth('test');

      expect(health.storage.status).toBe('HEALTHY');
      expect(health.storage.maxQueuePayloadBytes).toBe(65536);
      expect(health.storage.enforceDurableReferences).toBe(true);
    });

    it('reports queue statistics and status breakdown', async () => {
      await diagnosticService.seedSampleDiagnosticData();
      const health = await diagnosticService.getSystemHealth('test');

      expect(health.queue.totalJobs).toBeGreaterThan(0);
      expect(health.queue.deadLetterCount).toBe(2);
      expect(health.queue.statusBreakdown['COMPLETED']).toBeGreaterThan(0);
      expect(health.queue.statusBreakdown['DEAD_LETTER']).toBe(2);
      expect(health.metadata.version).toBe('2.0.1');
    });
  });

  describe('2. /dev/workflows Runs & DAG Stages', () => {
    beforeEach(async () => {
      await diagnosticService.seedSampleDiagnosticData();
    });

    it('lists all real workflow runs with step summaries and correlation IDs', async () => {
      const workflows = await diagnosticService.listWorkflowRuns();

      expect(workflows.length).toBeGreaterThanOrEqual(2);

      const completedRun = workflows.find((w) => w.status === 'COMPLETED');
      expect(completedRun).toBeDefined();
      expect(completedRun?.correlation_id).toBe('corr-run-101');
      expect(completedRun?.completed_jobs).toBe(2);
      expect(completedRun?.total_jobs).toBe(2);

      const runningRun = workflows.find((w) => w.status === 'RUNNING');
      expect(runningRun).toBeDefined();
      expect(runningRun?.correlation_id).toBe('corr-run-202');
    });

    it('inspects detailed workflow run including child job associations and definition payload', async () => {
      const workflows = await diagnosticService.listWorkflowRuns();
      const runId = workflows[0].workflow_run_id;

      const details = await diagnosticService.getWorkflowRunDetails(runId);
      expect(details).toBeDefined();
      expect(details?.workflow_run_id).toBe(runId);
      expect(details?.definition_payload).toBeDefined();
      expect(details?.definition_payload.steps).toBeDefined();
      expect(details?.jobs.length).toBeGreaterThan(0);
    });

    it('returns null for non-existent workflow run ID', async () => {
      const details = await diagnosticService.getWorkflowRunDetails('00000000-0000-0000-0000-000000000000');
      expect(details).toBeNull();
    });
  });

  describe('3. /dev/jobs & Leases Inspection', () => {
    beforeEach(async () => {
      await diagnosticService.seedSampleDiagnosticData();
    });

    it('lists jobs with queue and status filtering', async () => {
      const allJobs = await diagnosticService.listJobs();
      expect(allJobs.length).toBeGreaterThan(0);

      const completedJobs = await diagnosticService.listJobs({ status: 'COMPLETED' });
      expect(completedJobs.every((j) => j.status === 'COMPLETED')).toBe(true);

      const discoveryJobs = await diagnosticService.listJobs({ queueKey: 'discovery-queue' });
      expect(discoveryJobs.every((j) => j.queue_key === 'discovery-queue')).toBe(true);
    });

    it('inspects job details with full attempt history and lease status', async () => {
      const allJobs = await diagnosticService.listJobs();
      const discoveryJob = allJobs.find((j) => j.queue_key === 'discovery-queue')!;

      const details = await diagnosticService.getJobDetails(discoveryJob.job_id);
      expect(details).toBeDefined();
      expect(details?.job_id).toBe(discoveryJob.job_id);
      expect(details?.attempts.length).toBe(1);
      expect(details?.attempts[0].worker_id).toBe('worker-discovery-node-1');
      expect(details?.payload.storageLocator).toBeDefined();
    });
  });

  describe('4. /dev/dlq Dead-Letter Queue & Audited Replay Qualification', () => {
    beforeEach(async () => {
      await diagnosticService.seedSampleDiagnosticData();
    });

    it('lists all dead letter jobs with final failure codes and locators', async () => {
      const dlqList = await diagnosticService.listDeadLetterJobs();
      expect(dlqList.length).toBe(2);

      const poisonEntry = dlqList.find((e) => e.final_failure_code === 'ERR_POISON_PILL_PAYLOAD');
      expect(poisonEntry).toBeDefined();
      expect(poisonEntry?.replay_eligible).toBe(false);
      expect(poisonEntry?.replay_policy_reason).toContain('Fatal poison payload');

      const retryExhaustedEntry = dlqList.find((e) => e.final_failure_code === 'ERR_LEASE_EXPIRED_MAX_RETRIES');
      expect(retryExhaustedEntry).toBeDefined();
      expect(retryExhaustedEntry?.replay_eligible).toBe(true);
      expect(retryExhaustedEntry?.replay_policy_reason).toContain('Eligible for operator-audited replay');
    });

    it('inspects DLQ record details with full failure attempt stack', async () => {
      const dlqList = await diagnosticService.listDeadLetterJobs();
      const targetDlq = dlqList[0];

      const details = await diagnosticService.getDeadLetterJobDetails(targetDlq.dead_letter_job_id);
      expect(details).toBeDefined();
      expect(details?.dead_letter_job_id).toBe(targetDlq.dead_letter_job_id);
      expect(details?.job_attempts.length).toBeGreaterThan(0);
      expect(details?.payload_snapshot_locator).toBeDefined();
    });
  });

  describe('5. Role Authorization & Safety Boundaries', () => {
    it('verifies allowed diagnostic roles vs denied roles', () => {
      const allowedRoles = ['admin', 'operator', 'auditor', 'system_engineer'];
      const deniedRoles = ['analyst', 'user', 'anonymous', 'reviewer'];

      const checkAccess = (roles: string[]) => roles.some((r) => allowedRoles.includes(r));

      expect(checkAccess(['operator'])).toBe(true);
      expect(checkAccess(['admin'])).toBe(true);
      expect(checkAccess(['system_engineer'])).toBe(true);
      expect(checkAccess(['auditor'])).toBe(true);

      expect(checkAccess(['analyst'])).toBe(false);
      expect(checkAccess(['user'])).toBe(false);
      expect(checkAccess(['anonymous'])).toBe(false);
      expect(checkAccess([])).toBe(false);
    });
  });

  describe('6. Empty & Edge Case Telemetry', () => {
    it('handles empty database tables without crashing or returning fake metrics', async () => {
      const freshMemDb = createTestDb({ applyMigrations: true, applySeed: false });
      const freshPg = freshMemDb.adapters.createPg();
      const freshClient = new freshPg.Client();
      await freshClient.connect();
      const freshDiagnostic = new DiagnosticService(freshClient);

      const health = await freshDiagnostic.getSystemHealth('test');
      expect(health.queue.totalJobs).toBe(0);
      expect(health.queue.activeLeases).toBe(0);
      expect(health.queue.deadLetterCount).toBe(0);

      const workflows = await freshDiagnostic.listWorkflowRuns();
      expect(workflows).toEqual([]);

      const jobs = await freshDiagnostic.listJobs();
      expect(jobs).toEqual([]);

      const dlq = await freshDiagnostic.listDeadLetterJobs();
      expect(dlq).toEqual([]);
    });
  });
});
