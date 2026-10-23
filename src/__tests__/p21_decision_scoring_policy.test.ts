import { describe, it, expect, beforeEach } from 'vitest';
import {
  RiskEngine,
  ScoringEngine,
  ScoreModelRegistry,
  PolicyEngine,
  PolicyRegistry,
  PolicyOverrideManager,
  RecommendationEngine,
  UseCaseEngine,
  USE_CASE_PROFILE_V1,
  DecisionOrchestrationEngine,
  RiskRecord,
} from '../../workers/decision/index.ts';

describe('P21 — Risk, Scoring, Policy Decisions, Recommendations & Use Cases', () => {
  beforeEach(() => {
    PolicyOverrideManager.clear();
  });

  describe('1. Versioned Scoring Models & Reproducibility', () => {
    it('should list registered scoring models including Architecture Baseline V1', () => {
      const models = ScoreModelRegistry.listModels();
      expect(models.length).toBeGreaterThanOrEqual(2);
      expect(models.some((m) => m.model_key === 'SCORE-MODEL-V1')).toBe(true);
      expect(models.some((m) => m.model_key === 'SCORE-MODEL-V2-STRICT')).toBe(true);
    });

    it('should compute deterministic scores and risk bands for baseline clean input', () => {
      const scoreResult = ScoringEngine.computeScore({
        analysisRunId: 'test-run-clean',
        modelKey: 'SCORE-MODEL-V1',
        risks: [],
      });

      expect(scoreResult.overall_score).toBe(100);
      expect(['A', 'A+']).toContain(scoreResult.grade);
      expect(scoreResult.risk_band).toBe('MINIMAL');
      expect(scoreResult.dimension_values.length).toBe(5);
    });

    it('should produce a different, reproducible score when scoring model version is changed', () => {
      const sampleRisks: RiskRecord[] = [
        {
          risk_id: 'risk-test-1',
          analysis_run_id: 'run-cmp',
          rule_id: 'R-PROMPT-INJECTION-SINK',
          title: 'Direct injection sink',
          description: 'Direct unsanitized input',
          risk_type: 'PROMPT_INJECTION',
          likelihood: 0.8,
          impact: 0.9,
          severity: 'CRITICAL',
          risk_score: 0.72,
          evidence_links: [{ evidence_id: 'ev-1', relevance_score: 0.9, notes: 'AST finding' }],
          mitigated: false,
          created_at: new Date().toISOString(),
        },
      ];

      const scoreV1 = ScoringEngine.computeScore({
        analysisRunId: 'run-cmp',
        modelKey: 'SCORE-MODEL-V1',
        risks: sampleRisks,
      });

      const scoreV2 = ScoringEngine.computeScore({
        analysisRunId: 'run-cmp',
        modelKey: 'SCORE-MODEL-V2-STRICT',
        risks: sampleRisks,
      });

      // Strict V2 applies higher weight to security (0.30 vs 0.35 or higher prompt resilience) and heavier deductions
      expect(scoreV1.model_key).toBe('SCORE-MODEL-V1');
      expect(scoreV2.model_key).toBe('SCORE-MODEL-V2-STRICT');
      expect(scoreV2.overall_score).toBeLessThan(scoreV1.overall_score);
      expect(scoreV2.dimension_values.find((d) => d.dimension_key === 'SECURITY_POSTURE')?.weight).toBe(0.30);
    });
  });

  describe('2. Policy Engine & Hard Blocks Over Favorable Scores', () => {
    it('should enforce QUARANTINE when canary honeytoken is compromised, overriding a favorable score', () => {
      const mockScore = {
        score_result_id: 'sc-1',
        analysis_run_id: 'run-canary',
        model_key: 'SCORE-MODEL-V1',
        model_version: '1.0.0',
        overall_score: 85,
        normalized_score: 0.85,
        grade: 'B' as const,
        risk_band: 'MODERATE' as const,
        dimension_values: [],
        calibration_version: 'cal-v1',
        explanation: { summary: 'Favorable sub-scores across components', strongest_dimension: 'Security', weakest_dimension: 'Quality', key_deductions: [] },
        created_at: new Date().toISOString(),
      };

      const canaryRisks: RiskRecord[] = [
        {
          risk_id: 'risk-canary',
          analysis_run_id: 'run-canary',
          rule_id: 'R-CANARY-HONEYTOKEN-LEAK',
          title: 'Canary Honeytoken Access',
          description: 'Canary file was read by agent process',
          risk_type: 'HONEYTOKEN_COMPROMISE',
          likelihood: 1.0,
          impact: 1.0,
          severity: 'CRITICAL',
          risk_score: 1.0,
          evidence_links: [{ evidence_id: 'ev-sbx-canary', relevance_score: 1.0, notes: 'Telemetry' }],
          mitigated: false,
          created_at: new Date().toISOString(),
        },
      ];

      const decision = PolicyEngine.evaluatePolicy({
        analysisRunId: 'run-canary',
        scoreResult: mockScore,
        risks: canaryRisks,
        canariesTripped: [{ canary_id: 'c1' }],
      });

      expect(decision.outcome).toBe('QUARANTINE');
      expect(decision.score_override_applied).toBe(true);
      expect(decision.blocking_rule_count).toBeGreaterThan(0);
      expect(decision.score_vs_policy_notes).toContain('overrode the score to QUARANTINE');
    });

    it('should enforce DENY_SHIPPING when critical direct injection sink is present', () => {
      const mockScore = {
        score_result_id: 'sc-2',
        analysis_run_id: 'run-inject',
        model_key: 'SCORE-MODEL-V1',
        model_version: '1.0.0',
        overall_score: 75,
        normalized_score: 0.75,
        grade: 'C' as const,
        risk_band: 'MODERATE' as const,
        dimension_values: [],
        calibration_version: 'cal-v1',
        explanation: { summary: 'Passing score', strongest_dimension: 'Security', weakest_dimension: 'Quality', key_deductions: [] },
        created_at: new Date().toISOString(),
      };

      const injectionRisks: RiskRecord[] = [
        {
          risk_id: 'risk-inject-1',
          analysis_run_id: 'run-inject',
          rule_id: 'R-CODE-EXECUTION-SINK',
          title: 'Unvalidated Subprocess Sink',
          description: 'exec call with tainted input',
          risk_type: 'CODE_EXECUTION',
          likelihood: 0.9,
          impact: 1.0,
          severity: 'CRITICAL',
          risk_score: 0.9,
          evidence_links: [{ evidence_id: 'ev-ast-sink', relevance_score: 0.95, notes: 'Static finding' }],
          mitigated: false,
          created_at: new Date().toISOString(),
        },
      ];

      const decision = PolicyEngine.evaluatePolicy({
        analysisRunId: 'run-inject',
        scoreResult: mockScore,
        risks: injectionRisks,
      });

      expect(decision.outcome).toBe('DENY_SHIPPING');
      expect(decision.blocking_rule_count).toBeGreaterThan(0);
      expect(decision.score_override_applied).toBe(true);
    });

    it('should require manual review when confidence is low (< 0.70)', () => {
      const mockScore = {
        score_result_id: 'sc-3',
        analysis_run_id: 'run-conf',
        model_key: 'SCORE-MODEL-V1',
        model_version: '1.0.0',
        overall_score: 65,
        normalized_score: 0.65,
        grade: 'D' as const,
        risk_band: 'ELEVATED' as const,
        dimension_values: [],
        calibration_version: 'cal-v1',
        explanation: { summary: 'Moderate uncertainty', strongest_dimension: 'Security', weakest_dimension: 'Quality', key_deductions: [] },
        created_at: new Date().toISOString(),
      };

      const decision = PolicyEngine.evaluatePolicy({
        analysisRunId: 'run-conf',
        scoreResult: mockScore,
        risks: [],
        confidenceScore: 0.55,
      });

      expect(decision.outcome).toBe('REQUIRE_REVIEW');
      expect(decision.reasons.some((r) => r.rule_key === 'POL-CONF-01' || r.rule_key?.includes('CONF'))).toBe(true);
    });
  });

  describe('3. Policy Overrides & Audit Trail', () => {
    it('should record an authorized policy override with full audit trail', () => {
      const runId = 'run-override-test';

      const override = PolicyOverrideManager.applyOverride({
        analysisRunId: runId,
        originalOutcome: 'DENY_SHIPPING',
        overriddenOutcome: 'ALLOW_WITH_WARNING',
        reason: 'Temporary approval by SecOps Lead for internal staging deployment sandbox.',
        approverId: 'operator-alice-99',
        approverRole: 'admin',
        justificationDetails: 'Verified restricted test environment with disabled egress.',
      });

      expect(override.status).toBe('ACTIVE');
      expect(override.original_outcome).toBe('DENY_SHIPPING');
      expect(override.overridden_outcome).toBe('ALLOW_WITH_WARNING');

      const active = PolicyOverrideManager.getActiveOverride(runId);
      expect(active).toBeDefined();
      expect(active?.override_id).toBe(override.override_id);

      const history = PolicyOverrideManager.getOverrideHistory(runId);
      expect(history.length).toBe(1);
    });

    it('should revoke an active override', () => {
      const runId = 'run-revoke-test';

      const override = PolicyOverrideManager.applyOverride({
        analysisRunId: runId,
        originalOutcome: 'QUARANTINE',
        overriddenOutcome: 'REQUIRE_REVIEW',
        reason: 'Operator manual inspection in progress.',
        approverId: 'operator-bob-01',
        approverRole: 'operator',
      });

      expect(PolicyOverrideManager.getActiveOverride(runId)).toBeDefined();

      const revoked = PolicyOverrideManager.revokeOverride(override.override_id, 'admin-carol');
      expect(revoked).toBe(true);

      expect(PolicyOverrideManager.getActiveOverride(runId)).toBeUndefined();
      const history = PolicyOverrideManager.getOverrideHistory(runId);
      expect(history[0].status).toBe('REVOKED');
    });

    it('should reject overrides without valid justification reasons', () => {
      expect(() => {
        PolicyOverrideManager.applyOverride({
          analysisRunId: 'run-invalid',
          originalOutcome: 'DENY_SHIPPING',
          overriddenOutcome: 'ALLOW',
          reason: 'too short',
          approverId: 'op-1',
          approverRole: 'admin',
        });
      }).toThrow('Policy override requires a descriptive justification reason (min 10 chars).');
    });
  });

  describe('4. Recommendation Engine & Evidence Validation', () => {
    const validRisks: RiskRecord[] = [
      {
        risk_id: 'risk-rec-1',
        analysis_run_id: 'run-rec',
        rule_id: 'R-PROMPT-INJECTION-SINK',
        title: 'Prompt Injection Risk',
        description: 'Tainted input flows into LLM prompt without escaping',
        risk_type: 'PROMPT_INJECTION',
        likelihood: 0.8,
        impact: 0.8,
        severity: 'HIGH',
        risk_score: 0.64,
        evidence_links: [{ evidence_id: 'ev-taint-01', relevance_score: 0.9, notes: 'Finding' }],
        mitigated: false,
        created_at: new Date().toISOString(),
      },
    ];

    it('should generate recommendations linked directly to identified risks and evidence', () => {
      const recs = RecommendationEngine.generateRecommendations({
        analysisRunId: 'run-rec',
        risks: validRisks,
      });

      expect(recs.length).toBe(1);
      expect(recs[0].priority).toBe('P1');
      expect(recs[0].risk_id).toBe('risk-rec-1');
      expect(recs[0].evidence_ids).toContain('ev-taint-01');

      const validation = RecommendationEngine.validateRecommendations(recs, validRisks);
      expect(validation.valid).toBe(true);
      expect(validation.errors.length).toBe(0);
    });

    it('should reject recommendations referencing unknown or orphaned risk IDs or invalid evidence', () => {
      const invalidRecs = [
        {
          recommendation_id: 'rec-orphaned',
          analysis_run_id: 'run-rec',
          risk_id: 'non-existent-risk-id',
          recommendation_type: 'REMEDIATION' as const,
          title: 'Orphaned Action',
          action_steps: 'Do something unsupported',
          priority: 'P0' as const,
          effort_estimate: 'HIGH' as const,
          evidence_ids: ['ev-unknown-99'],
          created_at: new Date().toISOString(),
        },
      ];

      const validation = RecommendationEngine.validateRecommendations(
        invalidRecs,
        validRisks,
        [{ evidence_id: 'ev-taint-01' }]
      );

      expect(validation.valid).toBe(false);
      expect(validation.errors.some((e) => e.includes('unknown or orphaned risk_id'))).toBe(true);
      expect(validation.errors.some((e) => e.includes('invalid or unverified evidence_id'))).toBe(true);
    });
  });

  describe('5. Use-Case Intelligence & 3+3 Profile Mandate', () => {
    it('should evaluate exactly 3 positive and 3 negative use cases under V1 profile', () => {
      const scoreResult = {
        score_result_id: 'sc-uc',
        analysis_run_id: 'run-uc',
        model_key: 'SCORE-MODEL-V1',
        model_version: '1.0.0',
        overall_score: 90,
        normalized_score: 0.9,
        grade: 'A' as const,
        risk_band: 'MINIMAL' as const,
        dimension_values: [],
        calibration_version: 'cal-v1',
        explanation: { summary: 'Strong safety posture', strongest_dimension: 'Security', weakest_dimension: 'Quality', key_deductions: [] },
        created_at: new Date().toISOString(),
      };

      const policyDecision = {
        decision_id: 'dec-uc',
        analysis_run_id: 'run-uc',
        policy_key: 'POLICY-V1-DEFAULT',
        policy_version: '1.0.0',
        outcome: 'ALLOW' as const,
        evaluation_summary: 'Clean policy evaluation',
        score_override_applied: false,
        reasons: [],
        blocking_rule_count: 0,
        created_at: new Date().toISOString(),
      };

      const useCases = UseCaseEngine.evaluateUseCases({
        analysisRunId: 'run-uc',
        scoreResult,
        policyDecision,
        risks: [],
        evidenceList: [{ evidence_id: 'ev-base-1' }],
      });

      expect(useCases.length).toBe(6);
      const positive = useCases.filter((u) => u.category === 'POSITIVE');
      const negative = useCases.filter((u) => u.category === 'NEGATIVE');

      expect(positive.length).toBe(3);
      expect(negative.length).toBe(3);

      expect(positive.every((p) => p.suitability === 'APPROVED')).toBe(true);
      expect(negative.every((n) => n.suitability === 'DISAPPROVED')).toBe(true);

      const validation = UseCaseEngine.validateUseCaseSuite(useCases, USE_CASE_PROFILE_V1);
      expect(validation.valid).toBe(true);
      expect(validation.positiveCount).toBe(3);
      expect(validation.negativeCount).toBe(3);
    });

    it('should disapprove positive use cases if critical risks or policy violations are present', () => {
      const scoreResult = {
        score_result_id: 'sc-uc-fail',
        analysis_run_id: 'run-uc-fail',
        model_key: 'SCORE-MODEL-V1',
        model_version: '1.0.0',
        overall_score: 40,
        normalized_score: 0.4,
        grade: 'F' as const,
        risk_band: 'SEVERE' as const,
        dimension_values: [],
        calibration_version: 'cal-v1',
        explanation: { summary: 'Critical findings', strongest_dimension: 'Security', weakest_dimension: 'Quality', key_deductions: [] },
        created_at: new Date().toISOString(),
      };

      const policyDecision = {
        decision_id: 'dec-fail',
        analysis_run_id: 'run-uc-fail',
        policy_key: 'POLICY-V1-DEFAULT',
        policy_version: '1.0.0',
        outcome: 'DENY_SHIPPING' as const,
        evaluation_summary: 'Hard deny',
        score_override_applied: false,
        reasons: [],
        blocking_rule_count: 1,
        created_at: new Date().toISOString(),
      };

      const criticalRisk: RiskRecord = {
        risk_id: 'risk-crit-uc',
        analysis_run_id: 'run-uc-fail',
        rule_id: 'R-PROMPT-INJECTION-SINK',
        title: 'Critical Injection',
        description: 'Direct shell execution',
        risk_type: 'CODE_EXECUTION',
        likelihood: 0.95,
        impact: 1.0,
        severity: 'CRITICAL',
        risk_score: 0.95,
        evidence_links: [{ evidence_id: 'ev-crit', relevance_score: 0.95, notes: 'Finding' }],
        mitigated: false,
        created_at: new Date().toISOString(),
      };

      const useCases = UseCaseEngine.evaluateUseCases({
        analysisRunId: 'run-uc-fail',
        scoreResult,
        policyDecision,
        risks: [criticalRisk],
      });

      const positive = useCases.filter((u) => u.category === 'POSITIVE');
      expect(positive.every((p) => p.suitability === 'DISAPPROVED')).toBe(true);
    });
  });

  describe('6. Full Decision Orchestration Suite Integration', () => {
    it('should coordinate the full pipeline from raw findings to decisions, recommendations, and use cases', async () => {
      const suiteResult = await DecisionOrchestrationEngine.runDecisionSuite({
        analysisRunId: 'run-e2e-01',
        entityRefId: 'agent-production-v1',
        confidenceScore: 0.95,
        staticFindings: [
          {
            rule_id: 'R-SECRET-TOKEN-LEAK',
            category: 'SECRET_EXPOSURE',
            title: 'Hardcoded API Token detected',
            severity: 'HIGH',
            confidence: 0.9,
          },
        ],
        evidenceList: [
          { evidence_id: 'ev-ast-secret', summary: 'AST Token Scanner' },
        ],
      });

      expect(suiteResult.analysis_run_id).toBe('run-e2e-01');
      expect(suiteResult.risks.length).toBeGreaterThan(0);
      expect(suiteResult.score_result).toBeDefined();
      expect(suiteResult.policy_decision).toBeDefined();
      expect(suiteResult.recommendations.length).toBeGreaterThan(0);
      expect(suiteResult.use_case_evaluations.length).toBe(6);
      expect(suiteResult.duration_ms).toBeGreaterThanOrEqual(0);
    });
  });
});
