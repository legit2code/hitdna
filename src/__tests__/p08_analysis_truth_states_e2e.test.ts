import { describe, it, expect, beforeAll } from 'vitest';
import { resolveAnalysisTruthState } from '@caim/contracts/analysis-states.ts';
import { ScoringEngine } from '../../workers/decision/scoring/engine.ts';
import { DecisionOrchestrationEngine } from '../../workers/decision/engine.ts';
import { createTestDb } from '@caim/db/migrator.js';
import { PgMemDbRepositories } from '@caim/db/repositories.js';
import { ANALYSIS_RUN_RULES } from '@caim/lifecycle/rules.ts';

describe('Prompt 8: Analysis Truth States & Verification Separation E2E', () => {
  describe('1. Conceptual Truth State Resolution', () => {
    const mockStaticReport = {
      summary: { totalFindings: 2, criticalFindings: 0, highFindings: 1 },
      findings: [
        {
          findingId: 'f-1',
          rule_id: 'R-PROMPT-INJECTION',
          title: 'Direct Prompt Injection Vector',
          severity: 'HIGH',
          confidence: 0.95,
        },
        {
          findingId: 'f-2',
          rule_id: 'R-CREDENTIAL-LEAK',
          title: 'Hardcoded API Key',
          severity: 'MEDIUM',
          confidence: 0.9,
        },
      ],
    };

    it('Scenario A: Static scan succeeded, but dynamic E2B provider is unavailable (simulated/mock)', () => {
      const mockDynamicResultSimulated = {
        session_id: 'sim-12345',
        provider_type: 'SIMULATED', // E2B not available
        raw_traces: 'simulated trace',
        events: [],
      };

      const result = resolveAnalysisTruthState({
        staticReport: mockStaticReport,
        dynamicRunResult: mockDynamicResultSimulated,
        isDynamicRequested: true,
        dynamicProvider: 'E2B',
      });

      // MUST conceptually distinguish:
      expect(result.static_status).toBe('STATIC_COMPLETE');
      expect(result.dynamic_status).toBe('DYNAMIC_NOT_VERIFIED');
      expect(result.overall_status).toBe('PARTIAL');
      expect(result.analysis_run_status).toBe('PARTIAL');
      expect(result.truth_state).toBe('STATICALLY_DERIVED');

      // User-facing exposure: what was executed, what was not verified, why
      expect(result.executed.some((e) => e.includes('Static AST'))).toBe(true);
      expect(result.not_verified.some((n) => n.includes('Dynamic Sandbox Execution'))).toBe(true);
      expect(result.why).toMatch(/E2B dynamic sandbox provider is unavailable/i);

      // Which conclusions rely only on static evidence
      expect(result.static_only_conclusions.length).toBeGreaterThan(0);
      expect(result.evidence_classes_available).toContain('STATIC_CODE');
      expect(result.evidence_classes_missing).toContain('DYNAMIC_EXECUTION_TRACE');
      expect(result.evidence_classes_missing).toContain('DYNAMIC_EGRESS_LOG');

      // Invariant: MUST NOT represent unavailable dynamic analysis as completed verification
      expect(result.overall_status).not.toBe('COMPLETE');
      expect(result.dynamic_status).not.toBe('DYNAMIC_COMPLETE');
    });

    it('Scenario B: Static scan succeeded, but dynamic analysis was not requested/configured', () => {
      const result = resolveAnalysisTruthState({
        staticReport: mockStaticReport,
        isDynamicRequested: false,
      });

      expect(result.static_status).toBe('STATIC_COMPLETE');
      expect(result.dynamic_status).toBe('DYNAMIC_NOT_VERIFIED');
      expect(result.overall_status).toBe('PARTIAL');
      expect(result.analysis_run_status).toBe('PARTIAL');
      expect(result.truth_state).toBe('STATICALLY_DERIVED');
      expect(result.why).toMatch(/Dynamic sandbox execution was not requested/i);
      expect(result.static_only_conclusions.length).toBeGreaterThan(0);
    });

    it('Scenario C: Static scan succeeded and real E2B live sandbox microVM executed successfully', () => {
      const mockDynamicResultLiveE2B = {
        session_id: 'e2b-live-session-889',
        provider_type: 'E2B',
        actual_provider: 'E2B',
        status: 'COMPLETED',
        raw_traces: 'e2b vm syscall trace',
        events: [
          { action: 'connect', target: 'api.openai.com', category: 'NETWORK' },
        ],
      };

      const result = resolveAnalysisTruthState({
        staticReport: mockStaticReport,
        dynamicRunResult: mockDynamicResultLiveE2B,
        isDynamicRequested: true,
        dynamicProvider: 'E2B',
      });

      expect(result.static_status).toBe('STATIC_COMPLETE');
      expect(result.dynamic_status).toBe('DYNAMIC_COMPLETE');
      expect(result.overall_status).toBe('COMPLETE');
      expect(result.analysis_run_status).toBe('COMPLETED');
      expect(result.truth_state).toBe('OBSERVED');
      expect(result.static_only_conclusions).toHaveLength(0);
      expect(result.not_verified).toHaveLength(0);
      expect(result.evidence_classes_available).toContain('DYNAMIC_EXECUTION_TRACE');
    });

    it('Scenario D: Static scan succeeded, but dynamic execution encountered runtime failure/error', () => {
      const result = resolveAnalysisTruthState({
        staticReport: mockStaticReport,
        dynamicError: new Error('E2B microVM memory limit exceeded'),
        isDynamicRequested: true,
        dynamicProvider: 'E2B',
      });

      expect(result.static_status).toBe('STATIC_COMPLETE');
      expect(result.dynamic_status).toBe('DYNAMIC_FAILED');
      expect(result.overall_status).toBe('PARTIAL');
      expect(result.analysis_run_status).toBe('PARTIAL');
      expect(result.truth_state).toBe('STATICALLY_DERIVED');
      expect(result.why).toMatch(/memory limit exceeded/i);
      expect(result.static_only_conclusions.length).toBeGreaterThan(0);
    });
  });

  describe('2. Decision Layer: Deterministic Scoring & Epistemic Grounding', () => {
    it('populates evidence_classes_available, evidence_classes_missing, and static_only_conclusions in score result', () => {
      const scoreResult = ScoringEngine.computeScore({
        scoreModelKey: 'caim-standard-risk-v2',
        staticFindings: [
          {
            finding_id: 'f-1',
            rule_id: 'R-PROMPT-INJECTION',
            severity: 'HIGH',
            confidence: 0.9,
          },
        ],
        dynamicFindings: [],
        dynamicStatus: 'DYNAMIC_NOT_VERIFIED',
      });

      expect(scoreResult.overall_score).toBeDefined();
      expect(scoreResult.grade).toBeDefined();
      expect(scoreResult.risk_band).toBeDefined();

      // Explanation metadata MUST reflect evidence classes and static-only grounding
      expect(scoreResult.explanation?.evidence_classes_available).toContain('STATIC_CODE');
      expect(scoreResult.explanation?.evidence_classes_missing).toContain('DYNAMIC_EXECUTION_TRACE');
      expect(
        Array.isArray(scoreResult.explanation?.static_only_conclusions)
          ? scoreResult.explanation.static_only_conclusions.length > 0
          : Boolean(scoreResult.explanation?.static_only_conclusions)
      ).toBe(true);
      expect(scoreResult.explanation?.dynamic_status).toBe('DYNAMIC_NOT_VERIFIED');
    });

    it('populates full evidence provenance in DecisionOrchestrationEngine', async () => {
      const suiteResult = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId: 'run-p08-test',
        entityRefId: 'agent-version-test',
        scoreModelKey: 'caim-standard-risk-v2',
        policyKey: 'pol-enterprise-prod-v2',
        staticFindings: [
          {
            finding_id: 'f-1',
            rule_id: 'R-PROMPT-INJECTION',
            severity: 'HIGH',
            confidence: 0.9,
          },
        ],
        dynamicFindings: [],
        dynamicStatus: 'DYNAMIC_NOT_VERIFIED',
        staticStatus: 'STATIC_COMPLETE',
        overallStatus: 'PARTIAL',
        truthState: 'STATICALLY_DERIVED',
        why: 'E2B dynamic sandbox provider unavailable',
        evidenceClassesAvailable: ['STATIC_CODE', 'STATIC_CONFIG'],
        evidenceClassesMissing: ['DYNAMIC_EXECUTION_TRACE', 'DYNAMIC_EGRESS_LOG'],
        staticOnlyConclusions: true,
      });

      expect(suiteResult.truth_state).toBe('STATICALLY_DERIVED');
      expect(suiteResult.static_status).toBe('STATIC_COMPLETE');
      expect(suiteResult.dynamic_status).toBe('DYNAMIC_NOT_VERIFIED');
      expect(suiteResult.overall_status).toBe('PARTIAL');
      expect(suiteResult.static_only_conclusions).toBe(true);
      expect(suiteResult.why).toBe('E2B dynamic sandbox provider unavailable');
      expect(suiteResult.evidence_classes_available).toEqual(['STATIC_CODE', 'STATIC_CONFIG']);
      expect(suiteResult.evidence_classes_missing).toEqual(['DYNAMIC_EXECUTION_TRACE', 'DYNAMIC_EGRESS_LOG']);
    });
  });

  describe('3. Database Schema & Persistence of Truth States', () => {
    let db: any;
    let pgClient: any;
    const runId = '88888888-8888-8888-8888-888888888888';
    const agentId = '99999999-9999-9999-9999-999999999999';
    const agentVersionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const scopeId = '00000000-0000-0000-0000-000000000001';

    beforeAll(async () => {
      db = createTestDb({ applyMigrations: true, applySeed: true });
      const Client = db.adapters.createPg().Client;
      pgClient = new Client();
      await pgClient.connect();

      // Seed canonical agent & agent version
      await pgClient.query(`
        INSERT INTO core.canonical_agents (agent_id, canonical_name, status, identity_confidence, created_at, updated_at)
        VALUES ('${agentId}', 'P08Agent', 'ACTIVE', 1.0, NOW(), NOW());
      `);

      await pgClient.query(`
        INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, content_fingerprint, created_at)
        VALUES ('${agentVersionId}', '${agentId}', '1.0.0', 'sha256:p08fingerprint', NOW());
      `);
    });

    it('persists analysis_run with status PARTIAL, static_status, dynamic_status, overall_status, and execution_summary', async () => {
      const executionSummary = {
        executed: ['static_ast_scan'],
        not_verified: ['dynamic_sandbox_execution'],
        why: 'E2B microVM dynamic sandbox provider was unavailable or unconfigured',
        evidence_classes_available: ['STATIC_CODE', 'STATIC_CONFIG'],
        evidence_classes_missing: ['DYNAMIC_EXECUTION_TRACE', 'DYNAMIC_EGRESS_LOG'],
        static_only_conclusions: true,
      };

      await pgClient.query(`
        INSERT INTO analysis.analysis_runs (
          analysis_run_id,
          agent_version_id,
          scope_id,
          pipeline_version,
          caim_version,
          ontology_version,
          trigger_type,
          status,
          static_status,
          dynamic_status,
          overall_status,
          execution_summary,
          started_at,
          completed_at,
          created_at
        ) VALUES (
          $1, $2, $3, '2.0.1', '2.0.1', 'v2.0.1', 'MANUAL',
          'PARTIAL', 'STATIC_COMPLETE', 'DYNAMIC_NOT_VERIFIED', 'PARTIAL',
          $4, NOW(), NOW(), NOW()
        );
      `, [runId, agentVersionId, scopeId, JSON.stringify(executionSummary)]);

      const queryRes = await pgClient.query(`
        SELECT status, static_status, dynamic_status, overall_status, execution_summary
        FROM analysis.analysis_runs
        WHERE analysis_run_id = $1;
      `, [runId]);

      expect(queryRes.rows.length).toBe(1);
      const row = queryRes.rows[0];
      expect(row.status).toBe('PARTIAL');
      expect(row.static_status).toBe('STATIC_COMPLETE');
      expect(row.dynamic_status).toBe('DYNAMIC_NOT_VERIFIED');
      expect(row.overall_status).toBe('PARTIAL');

      const parsedSummary = typeof row.execution_summary === 'string'
        ? JSON.parse(row.execution_summary)
        : row.execution_summary;
      expect(parsedSummary.executed).toContain('static_ast_scan');
      expect(parsedSummary.not_verified).toContain('dynamic_sandbox_execution');
      expect(parsedSummary.static_only_conclusions).toBe(true);
      expect(parsedSummary.why).toMatch(/E2B microVM dynamic sandbox provider was unavailable/i);
    });
  });

  describe('4. Lifecycle State Engine Compliance', () => {
    it('allows valid transitions for ANALYSIS_RUN to and from PARTIAL', () => {
      const allowedFromRunning = ANALYSIS_RUN_RULES
        .filter((r) => r.fromState === 'RUNNING')
        .map((r) => r.toState);
      expect(allowedFromRunning).toContain('PARTIAL');

      const allowedFromPartial = ANALYSIS_RUN_RULES
        .filter((r) => r.fromState === 'PARTIAL')
        .map((r) => r.toState);
      expect(allowedFromPartial).toContain('COMPLETED');
      expect(allowedFromPartial).toContain('ARCHIVED');
    });
  });
});
