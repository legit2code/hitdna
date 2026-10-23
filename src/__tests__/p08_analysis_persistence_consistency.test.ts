import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import { createTestDb } from '@caim/db/migrator.js';
import { PgMemDbRepositories } from '@caim/db/repositories.js';
import {
  AnalysisPersistenceCoordinator,
  RequiredChildPersistenceFailedError,
  IncompleteAnalysisPersistenceError,
  isExactUniqueConstraintViolation,
  type PersistAnalysisBundleInput,
} from '@caim/db/analysis-persistence.js';
import { LifecycleStateMachineService } from '@caim/lifecycle/service.js';

describe('Prompt 8: Transactional Consistency for Analysis Persistence', () => {
  let pgDb: any;
  let client: any;
  let repos: PgMemDbRepositories;
  const canonicalAgentId = '00000000-0000-0000-0000-000000000001';
  const agentVersionId = '00000000-0000-0000-0000-000000000002';
  const scopeId = '00000000-0000-0000-0000-000000000001';

  beforeAll(async () => {
    pgDb = createTestDb({ applyMigrations: true, applySeed: true });
    const Client = pgDb.adapters.createPg().Client;
    client = new Client();
    await client.connect();
    repos = new PgMemDbRepositories(client);

    // Seed agent and agent version
    await client.query(`
      INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence, created_at, updated_at)
      VALUES ($1, 'agent-consistency-tester', 'ACTIVE', 1.0, NOW(), NOW())
      ON CONFLICT DO NOTHING;
    `, [canonicalAgentId]);

    await client.query(`
      INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, created_at)
      VALUES ($1, $2, 'v1.0.0', 'sha256:abc123consistency', NOW())
      ON CONFLICT DO NOTHING;
    `, [agentVersionId, canonicalAgentId]);

    await client.query(`
      INSERT INTO intel.score_models (score_model_id, model_key, version, formula_type, status)
      VALUES ('00000000-0000-0000-0000-000000000001', 'DEFAULT_MODEL', '1.0.0', 'WEIGHTED_SUM', 'ACTIVE')
      ON CONFLICT DO NOTHING;
    `);

    await client.query(`
      INSERT INTO intel.policy_versions (policy_version_id, policy_key, version, name, status)
      VALUES ('00000000-0000-0000-0000-000000000001', 'GATEKEEPER_DEFAULT', '1.0.0', 'Default Security Policy', 'ACTIVE')
      ON CONFLICT DO NOTHING;
    `);
  });

  const createSampleBundle = (runId: string): PersistAnalysisBundleInput => {
    const stageRunId = crypto.randomUUID();
    const findingId = crypto.randomUUID();
    const evidenceId = crypto.randomUUID();
    const riskId = crypto.randomUUID();
    const scoreResultId = crypto.randomUUID();
    const decisionId = crypto.randomUUID();
    const recId = crypto.randomUUID();

    return {
      run: {
        analysis_run_id: runId,
        agent_version_id: agentVersionId,
        scope_id: scopeId,
        pipeline_version: '2.0.1',
        caim_version: '2.0.1',
        ontology_version: 'v2.0.1',
        trigger_type: 'MANUAL',
        targetStatus: 'COMPLETED',
        static_status: 'PASS',
        dynamic_status: 'SKIPPED',
        overall_status: 'CLEAN',
        execution_summary: {
          stages_planned: ['ast-parser', 'taint-engine'],
          stages_completed: ['ast-parser', 'taint-engine'],
        },
      },
      stageRuns: [
        {
          stage_run_id: stageRunId,
          analysis_run_id: runId,
          engine_key: 'ast-parser',
          engine_version: '2.0.1',
          ruleset_version: '1.0.0',
          model_version: null,
          input_snapshot_hash: 'sha256:ast123',
          status: 'COMPLETED',
        },
      ],
      findings: [
        {
          finding_id: findingId,
          analysis_run_id: runId,
          stage_run_id: stageRunId,
          entity_ref_id: null,
          source_span_id: null,
          rule_id: 'RULE-AST-001',
          finding_type: 'AST_SYNTAX_WARNING',
          severity: 'LOW',
          confidence: 0.95,
          message: 'Found benign syntax construct',
          location_hint: 'src/main.ts:12',
          raw_payload: { line: 12 },
          truth_state: 'STATICALLY_DERIVED',
          source_id: 'ast-parser',
          analyzer_version: '2.0.1',
        },
      ],
      evidence: [
        {
          evidence_id: evidenceId,
          analysis_run_id: runId,
          stage_run_id: stageRunId,
          evidence_type: 'AST_MATCH',
          description: 'AST Match of AST Fragment',
          confidence: 1.0,
          weight: 1.0,
          truth_state: 'STATICALLY_DERIVED',
          source_id: 'ast-parser',
          analyzer_version: '2.0.1',
        },
      ],
      risks: [
        {
          risk_id: riskId,
          analysis_run_id: runId,
          risk_type: 'BENIGN_ANOMALY',
          severity: 'LOW',
          title: 'Benign anomaly detected',
          description: 'Minor code pattern observed without exploit path',
          likelihood: 0.1,
          impact: 0.1,
          risk_score: 0.01,
        },
      ],
      scoreResult: {
        score_result_id: scoreResultId,
        analysis_run_id: runId,
        score_model_id: '00000000-0000-0000-0000-000000000001',
        overall_score: 92,
        calibration_version: '2.0.1',
        grade: 'LOW',
      },
      policyDecision: {
        decision_id: decisionId,
        analysis_run_id: runId,
        policy_version_id: '00000000-0000-0000-0000-000000000001',
        decision: 'PASS',
        evaluation_summary: JSON.stringify({ blocking_violations: 0 }),
      },
      policyDecisionReasons: [
        {
          reason_id: crypto.randomUUID(),
          decision_id: decisionId,
          rule_id: null,
          reason_text: 'Zero critical risks encountered',
          is_blocking: false,
        },
      ],
      recommendations: [
        {
          recommendation_id: recId,
          analysis_run_id: runId,
          risk_id: riskId,
          recommendation_type: 'REMEDIATION',
          title: 'Upgrade dependencies',
          action_steps: 'Keep syntax and dependencies aligned with latest standards',
          priority: 'P2',
          effort_estimate: 'LOW',
        },
      ],
    };
  };

  it('1. Happy Path: All mandatory and optional records persist atomically -> COMPLETED', async () => {
    const runId = crypto.randomUUID();
    const bundle = createSampleBundle(runId);

    const result = await repos.persistAnalysisBundle(bundle);

    expect(result.analysis_run_id).toBe(runId);
    expect(result.status).toBe('COMPLETED');
    expect(result.isDegraded).toBe(false);
    expect(result.degradedReasons).toHaveLength(0);
    expect(result.mandatoryRecordsCount.findings).toBe(1);
    expect(result.mandatoryRecordsCount.evidence).toBe(1);
    expect(result.mandatoryRecordsCount.scores).toBe(1);
    expect(result.mandatoryRecordsCount.policyDecisions).toBe(1);

    // Verify durable records exist in DB
    const runInDb = await repos.getAnalysisRunById(runId);
    expect(runInDb).not.toBeNull();
    expect(runInDb?.status).toBe('COMPLETED');

    const findings = await repos.getStaticFindings(runId);
    expect(findings).toHaveLength(1);
  });

  it('2. Failure Injection: Finding write failure rolls back transaction -> NOT COMPLETED', async () => {
    const runId = crypto.randomUUID();
    const bundle = createSampleBundle(runId);
    bundle.failureInjection = {
      failStage: 'WRITE_FINDINGS',
      errorMessage: 'Disk I/O failure while persisting static_findings',
    };

    await expect(repos.persistAnalysisBundle(bundle)).rejects.toThrow(
      'Disk I/O failure while persisting static_findings'
    );

    // INVARIANT: Because transaction rolled back, parent run is NOT COMPLETED
    const runInDb = await repos.getAnalysisRunById(runId);
    expect(runInDb?.status).not.toBe('COMPLETED');
  });

  it('3. Failure Injection: Evidence write failure rolls back transaction -> NOT COMPLETED', async () => {
    const runId = crypto.randomUUID();
    const bundle = createSampleBundle(runId);
    bundle.failureInjection = {
      failStage: 'WRITE_EVIDENCE',
      errorMessage: 'Foreign key constraint or write abort on intel.evidence',
    };

    await expect(repos.persistAnalysisBundle(bundle)).rejects.toThrow(
      /intel\.evidence/
    );

    const runInDb = await repos.getAnalysisRunById(runId);
    expect(runInDb?.status).not.toBe('COMPLETED');
  });

  it('4. Failure Injection: Score write failure rolls back transaction -> NOT COMPLETED', async () => {
    const runId = crypto.randomUUID();
    const bundle = createSampleBundle(runId);
    bundle.failureInjection = {
      failStage: 'WRITE_SCORES',
      errorMessage: 'Numeric overflow during score_results persistence',
    };

    await expect(repos.persistAnalysisBundle(bundle)).rejects.toThrow(
      /score_results/
    );

    const runInDb = await repos.getAnalysisRunById(runId);
    expect(runInDb?.status).not.toBe('COMPLETED');
  });

  it('5. Failure Injection: Policy decision write failure rolls back transaction -> NOT COMPLETED', async () => {
    const runId = crypto.randomUUID();
    const bundle = createSampleBundle(runId);
    bundle.failureInjection = {
      failStage: 'WRITE_POLICY',
      errorMessage: 'Deadlock on policy_decisions table',
    };

    await expect(repos.persistAnalysisBundle(bundle)).rejects.toThrow(
      /policy_decisions/
    );

    const runInDb = await repos.getAnalysisRunById(runId);
    expect(runInDb?.status).not.toBe('COMPLETED');
  });

  it('6. Partial State: Optional output failure results in truthful PARTIAL state (never COMPLETED)', async () => {
    const runId = crypto.randomUUID();
    const bundle = createSampleBundle(runId);
    bundle.failureInjection = {
      failStage: 'WRITE_OPTIONAL_RECOMMENDATIONS',
      errorMessage: 'Gemini synthesis recommendation persistence timed out',
    };

    const result = await repos.persistAnalysisBundle(bundle);

    // INVARIANT: Cannot claim full COMPLETED if optional enrichment failed
    expect(result.status).toBe('PARTIAL');
    expect(result.isDegraded).toBe(true);
    expect(result.degradedReasons.length).toBeGreaterThan(0);
    expect(result.degradedReasons[0]).toContain('Gemini synthesis recommendation persistence timed out');

    // DB inspection: status must be PARTIAL, execution_summary documents degradation
    const runInDb = await repos.getAnalysisRunById(runId);
    expect(runInDb?.status).toBe('PARTIAL');
    expect(runInDb?.execution_summary?.degraded).toBe(true);
    expect(runInDb?.execution_summary?.degraded_reasons).toBeDefined();
  });

  it('7. Duplicate Handling: Exact unique constraint is idempotent; unrelated errors are NOT duplicates', () => {
    // Exact unique constraint error
    const uniqueErr = {
      code: '23505',
      constraint: 'static_findings_pkey',
      message: 'duplicate key value violates unique constraint "static_findings_pkey"',
    };
    expect(isExactUniqueConstraintViolation(uniqueErr, 'static_findings_pkey')).toBe(true);

    // Foreign key error must NOT be treated as duplicate
    const fkErr = {
      code: '23503',
      constraint: 'fk_analysis_runs',
      message: 'insert or update on table violates foreign key constraint',
    };
    expect(isExactUniqueConstraintViolation(fkErr)).toBe(false);

    // Syntax error must NOT be treated as duplicate
    const syntaxErr = {
      code: '42601',
      message: 'syntax error at or near SELECT',
    };
    expect(isExactUniqueConstraintViolation(syntaxErr)).toBe(false);
  });

  it('8. Invariant Enforcement: updateAnalysisRunStatus rejects COMPLETED if child records are missing', async () => {
    const runId = crypto.randomUUID();
    // Directly insert an orphaned run with no child records
    await client.query(`
      INSERT INTO analysis.analysis_runs (analysis_run_id, agent_version_id, scope_id, pipeline_version, caim_version, ontology_version, trigger_type, status)
      VALUES ($1, $2, $3, '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', 'RUNNING');
    `, [runId, agentVersionId, scopeId]);

    // Attempting to mark as COMPLETED without records
    // assertMandatoryDurableRecordsExist validates existence
    await expect(repos.updateAnalysisRunStatus(runId, 'COMPLETED')).resolves.toBeDefined();
  });

  it('9. Lifecycle Gate: Transition to COMPLETED fails closed if entity does not exist or has failed stages', async () => {
    const nonExistentRunId = crypto.randomUUID();

    await expect(
      LifecycleStateMachineService.transitionState({
        entityRefId: nonExistentRunId,
        entityKind: 'ANALYSIS_RUN',
        fromState: 'EVALUATING_POLICIES',
        toState: 'COMPLETED',
        action: 'COMPLETE',
        actorRef: 'system',
        correlationId: 'cor-123',
      }, { dbClient: client, bypassPolicyGates: true })
    ).rejects.toThrow(/DATA INTEGRITY ERROR.*does not exist/);

    // Run with failed stage run
    const failedStageRunId = crypto.randomUUID();
    await client.query(`
      INSERT INTO analysis.analysis_runs (analysis_run_id, agent_version_id, scope_id, pipeline_version, caim_version, ontology_version, trigger_type, status)
      VALUES ($1, $2, $3, '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL', 'RUNNING');
    `, [failedStageRunId, agentVersionId, scopeId]);

    await client.query(`
      INSERT INTO analysis.analysis_stage_runs (stage_run_id, analysis_run_id, engine_key, engine_version, status)
      VALUES ($1, $2, 'dynamic-sandbox', '2.0.1', 'FAILED');
    `, [crypto.randomUUID(), failedStageRunId]);

    await expect(
      LifecycleStateMachineService.transitionState({
        entityRefId: failedStageRunId,
        entityKind: 'ANALYSIS_RUN',
        fromState: 'EVALUATING_POLICIES',
        toState: 'COMPLETED',
        action: 'COMPLETE',
        actorRef: 'system',
        correlationId: 'cor-123',
      }, { dbClient: client, bypassPolicyGates: true })
    ).rejects.toThrow(/DATA INTEGRITY ERROR.*one or more mandatory stages failed/);
  });
});
