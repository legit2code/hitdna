import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import {
  ReverificationWorker,
  VulnerabilityRecorrelationWorker,
  GoldenCorpusRegressionWorker,
  StaleAgentCleanupWorker,
} from '@caim/workflow';

describe('Scheduled Background Workers Engine (Architecture V2.0.1)', () => {
  let memDb: any;
  let pgClient: any;

  beforeEach(async () => {
    memDb = createTestDb();
    const pgMem = memDb.adapters.createPg();
    pgClient = new pgMem.Client();
    await pgClient.connect();

    // Seed test access scope
    await pgClient.query(`
      INSERT INTO security.access_scopes (scope_id, scope_type)
      VALUES ('00000000-0000-0000-0000-000000000001', 'PLATFORM')
      ON CONFLICT (scope_id) DO NOTHING;
    `);

    // Seed test canonical agents and agent versions
    await pgClient.query(`
      INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence)
      VALUES 
        ('a1000000-0000-0000-0000-000000000001', 'agent-alpha-langchain', 'ACTIVE', 0.9900),
        ('a2000000-0000-0000-0000-000000000002', 'agent-beta-bomb-drift', 'ACTIVE', 0.9500),
        ('a3000000-0000-0000-0000-000000000003', 'agent-gamma-tombstone-404', 'ACTIVE', 0.9000),
        ('a4000000-0000-0000-0000-000000000004', 'agent-delta-archived-repo', 'ACTIVE', 0.9200)
      ON CONFLICT (agent_id) DO NOTHING;
    `);

    await pgClient.query(`
      INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint)
      VALUES
        ('ba000000-0000-0000-0000-000000000001', 'a1000000-0000-0000-0000-000000000001', 'v1.0.0', 'fp-alpha-001'),
        ('ba000000-0000-0000-0000-000000000002', 'a2000000-0000-0000-0000-000000000002', 'v1.0.0-evasion', 'fp-beta-002'),
        ('ba000000-0000-0000-0000-000000000003', 'a3000000-0000-0000-0000-000000000003', 'v1.0.0', 'fp-gamma-003'),
        ('ba000000-0000-0000-0000-000000000004', 'a4000000-0000-0000-0000-000000000004', 'v1.0.0', 'fp-delta-004')
      ON CONFLICT (agent_version_id) DO NOTHING;
    `);

    // Seed SBOM components
    await pgClient.query(`
      INSERT INTO analysis.analysis_runs (
        analysis_run_id, agent_version_id, scope_id, pipeline_version, caim_version, ontology_version, trigger_type, status
      ) VALUES (
        'ea000000-0000-0000-0000-000000000001', 'ba000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001', '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', 'COMPLETED'
      ) ON CONFLICT (analysis_run_id) DO NOTHING;
    `);

    await pgClient.query(`
      INSERT INTO analysis.sbom_components (
        sbom_component_id, analysis_run_id, name, version, ecosystem
      ) VALUES 
        ('fa000000-0000-0000-0000-000000000001', 'ea000000-0000-0000-0000-000000000001', 'langchain-core', '0.1.2', 'pypi'),
        ('fa000000-0000-0000-0000-000000000002', 'ea000000-0000-0000-0000-000000000001', 'lodash', '4.17.15', 'npm')
      ON CONFLICT (sbom_component_id) DO NOTHING;
    `);
  });

  afterEach(async () => {
    if (pgClient) {
      await pgClient.end();
    }
  });

  describe('1. Re-verification Worker', () => {
    it('periodically re-verifies previously ingested agents, detects drift/timebombs, and writes status to ops.jobs', async () => {
      const worker = new ReverificationWorker(pgClient, { intervalMs: 5000 });

      // Start/stop control test
      expect(worker.getStatus().active).toBe(false);
      worker.start(10000);
      expect(worker.getStatus().active).toBe(true);
      expect(worker.getStatus().interval_ms).toBe(10000);
      expect(worker.getStatus().next_run_at).not.toBeNull();
      worker.stop();
      expect(worker.getStatus().active).toBe(false);
      expect(worker.getStatus().next_run_at).toBeNull();

      // Execute genuine cycle
      const result = await worker.runCycle();
      expect(result).toBeDefined();
      expect(result.phase).toBe('COMPLETED');
      expect(result.agents_inspected).toBeGreaterThanOrEqual(4);
      expect(result.drift_detected_count).toBeGreaterThan(0); // Flagged time-bomb agent-beta-bomb-drift

      // Check status telemetry
      const status = worker.getStatus();
      expect(status.total_runs_count).toBe(1);
      expect(status.last_run_at).not.toBeNull();
      expect(status.metrics.agents_reverified_total).toBeGreaterThanOrEqual(4);
      expect(status.metrics.drift_detected_total).toBeGreaterThan(0);

      // Verify real row written to ops.jobs
      const jobsRes = await pgClient.query(`
        SELECT * FROM ops.jobs WHERE queue_key = 'worker.reverification';
      `);
      expect(jobsRes.rows.length).toBe(1);
      const job = jobsRes.rows[0];
      expect(job.status).toBe('COMPLETED');
      expect(job.queue_key).toBe('worker.reverification');
      const payload = typeof job.payload === 'string' ? JSON.parse(job.payload) : job.payload;
      expect(payload.worker_id).toBe('reverification-worker');
      expect(payload.agents_inspected).toBeGreaterThanOrEqual(4);
      expect(payload.drift_detected_count).toBeGreaterThan(0);

      // Verify finding written to analysis.static_findings
      const findingsRes = await pgClient.query(`
        SELECT * FROM analysis.static_findings WHERE rule_id = 'RULE-DRIFT-TIMEBOMB';
      `);
      expect(findingsRes.rows.length).toBeGreaterThan(0);
      expect(findingsRes.rows[0].severity).toBe('HIGH');
    });
  });

  describe('2. Vulnerability Re-correlation Worker', () => {
    it('correlates post-ingestion CVEs against dependency SBOMs and writes status to ops.jobs', async () => {
      const worker = new VulnerabilityRecorrelationWorker(pgClient, { intervalMs: 6000 });

      // Start/stop control test
      worker.start(8000);
      expect(worker.getStatus().active).toBe(true);
      worker.stop();
      expect(worker.getStatus().active).toBe(false);

      // Execute genuine cycle
      const result = await worker.runCycle();
      expect(result).toBeDefined();
      expect(result.phase).toBe('COMPLETED');
      expect(result.dependencies_scanned).toBeGreaterThan(0);
      expect(result.newly_correlated_cves).toBeGreaterThan(0); // Correlated langchain-core 0.1.2 & lodash 4.17.15

      // Check status telemetry
      const status = worker.getStatus();
      expect(status.total_runs_count).toBe(1);
      expect(status.metrics.cves_correlated_total).toBeGreaterThan(0);

      // Verify real row written to ops.jobs
      const jobsRes = await pgClient.query(`
        SELECT * FROM ops.jobs WHERE queue_key = 'worker.vulnerability_recorrelation';
      `);
      expect(jobsRes.rows.length).toBe(1);
      const job = jobsRes.rows[0];
      expect(job.status).toBe('COMPLETED');
      expect(job.queue_key).toBe('worker.vulnerability_recorrelation');
      const payload = typeof job.payload === 'string' ? JSON.parse(job.payload) : job.payload;
      expect(payload.worker_id).toBe('vulnerability-recorrelation-worker');
      expect(payload.newly_correlated_cves).toBeGreaterThan(0);

      // Verify finding written to analysis.static_findings
      const findingsRes = await pgClient.query(`
        SELECT * FROM analysis.static_findings WHERE rule_id = 'RULE-CVE-CORRELATION';
      `);
      expect(findingsRes.rows.length).toBeGreaterThan(0);
    });
  });

  describe('3. Golden Corpus Regression Worker', () => {
    it('runs the authoritative 19-family golden corpus evaluation suite on schedule and writes status to ops.jobs', async () => {
      const worker = new GoldenCorpusRegressionWorker(pgClient, { intervalMs: 7000 });

      // Start/stop control test
      worker.start(12000);
      expect(worker.getStatus().active).toBe(true);
      worker.stop();
      expect(worker.getStatus().active).toBe(false);

      // Execute genuine evaluation cycle
      const result = await worker.runCycle();
      expect(result).toBeDefined();
      expect(result.phase).toBe('COMPLETED');
      expect(result.families_evaluated).toBe(19);
      expect(result.gate_status).toBe('PASSED');
      expect(result.can_deploy).toBe(true);

      // Check status telemetry
      const status = worker.getStatus();
      expect(status.total_runs_count).toBe(1);
      expect(status.metrics.evaluations_passed_total).toBe(1);
      expect(status.metrics.evaluated_families_count).toBe(19);

      // Verify real row written to ops.jobs
      const jobsRes = await pgClient.query(`
        SELECT * FROM ops.jobs WHERE queue_key = 'worker.golden_corpus_regression';
      `);
      expect(jobsRes.rows.length).toBe(1);
      const job = jobsRes.rows[0];
      expect(job.status).toBe('COMPLETED');
      expect(job.queue_key).toBe('worker.golden_corpus_regression');
      const payload = typeof job.payload === 'string' ? JSON.parse(job.payload) : job.payload;
      expect(payload.worker_id).toBe('golden-corpus-regression-worker');
      expect(payload.families_evaluated).toBe(19);
      expect(payload.gate_status).toBe('PASSED');
    });
  });

  describe('4. Stale-Agent Cleanup Worker', () => {
    it('flags agents whose source repository has been deleted (404/tombstone) or archived and writes status to ops.jobs', async () => {
      const worker = new StaleAgentCleanupWorker(pgClient, { intervalMs: 9000 });

      // Start/stop control test
      worker.start(15000);
      expect(worker.getStatus().active).toBe(true);
      worker.stop();
      expect(worker.getStatus().active).toBe(false);

      // Execute genuine cycle
      const result = await worker.runCycle();
      expect(result).toBeDefined();
      expect(result.phase).toBe('COMPLETED');
      expect(result.agents_inspected).toBeGreaterThanOrEqual(4);
      expect(result.stale_detected_count).toBe(2); // agent-gamma-tombstone-404 and agent-delta-archived-repo
      expect(result.archived_count).toBe(1);
      expect(result.deleted_count).toBe(1);

      // Check status telemetry
      const status = worker.getStatus();
      expect(status.total_runs_count).toBe(1);
      expect(status.metrics.stale_flagged_total).toBe(2);
      expect(status.metrics.archived_total).toBe(1);
      expect(status.metrics.deleted_total).toBe(1);

      // Verify real row written to ops.jobs
      const jobsRes = await pgClient.query(`
        SELECT * FROM ops.jobs WHERE queue_key = 'worker.stale_agent_cleanup';
      `);
      expect(jobsRes.rows.length).toBe(1);
      const job = jobsRes.rows[0];
      expect(job.status).toBe('COMPLETED');
      expect(job.queue_key).toBe('worker.stale_agent_cleanup');
      const payload = typeof job.payload === 'string' ? JSON.parse(job.payload) : job.payload;
      expect(payload.worker_id).toBe('stale-agent-cleanup-worker');
      expect(payload.stale_detected_count).toBe(2);

      // Verify canonical agents marked DEPRECATED in core.canonical_agents
      const gammaRes = await pgClient.query(`
        SELECT status FROM core.canonical_agents WHERE canonical_name = 'agent-gamma-tombstone-404';
      `);
      expect(gammaRes.rows[0].status).toBe('DEPRECATED');

      const deltaRes = await pgClient.query(`
        SELECT status FROM core.canonical_agents WHERE canonical_name = 'agent-delta-archived-repo';
      `);
      expect(deltaRes.rows[0].status).toBe('DEPRECATED');
    });
  });

  describe('5. Cross-Worker Independence & Distinction in ops.jobs', () => {
    it('produces distinct records in ops.jobs distinguishable from each other and from discovery jobs', async () => {
      // Create a simulated discovery job first
      await pgClient.query(`
        INSERT INTO ops.jobs (
          job_id, queue_key, idempotency_key, priority, status, payload, created_at
        ) VALUES (
          'd0000000-0000-0000-0000-000000000001', 'source.discovery', 'disc-cycle-001', 10, 'COMPLETED',
          '{"worker_id": "autonomous-discovery-worker", "candidates_found": 5}', now()
        );
      `);

      const w1 = new ReverificationWorker(pgClient);
      const w2 = new VulnerabilityRecorrelationWorker(pgClient);
      const w3 = new GoldenCorpusRegressionWorker(pgClient);
      const w4 = new StaleAgentCleanupWorker(pgClient);

      // Run each worker
      await w1.runCycle();
      await w2.runCycle();
      await w3.runCycle();
      await w4.runCycle();

      // Query all jobs from ops.jobs
      const allJobs = await pgClient.query(`
        SELECT queue_key, status, payload FROM ops.jobs ORDER BY created_at ASC;
      `);

      const queueKeys = allJobs.rows.map((r: any) => r.queue_key);
      expect(queueKeys).toContain('source.discovery');
      expect(queueKeys).toContain('worker.reverification');
      expect(queueKeys).toContain('worker.vulnerability_recorrelation');
      expect(queueKeys).toContain('worker.golden_corpus_regression');
      expect(queueKeys).toContain('worker.stale_agent_cleanup');

      // Verify every queue_key is unique and distinguishable
      const uniqueKeys = new Set(queueKeys);
      expect(uniqueKeys.size).toBe(5);

      for (const row of allJobs.rows) {
        expect(row.status).toBe('COMPLETED');
        const p = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload;
        expect(p.worker_id).toBeDefined();
      }
    });
  });
});
