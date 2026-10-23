/**
 * Decision Orchestration Engine (Architecture V2.0.1)
 * Coordinates Risk Evaluation, Scoring Calculation, Policy Decision, Recommendations, and Use-Case Intelligence.
 */

import {
  DecisionSuiteResult,
  RiskRecord,
  ScoreResult,
  PolicyDecision,
  RecommendationRecord,
  UseCaseEvaluationRecord,
} from './types.ts';
import { RiskEngine, RiskEvaluationInput } from './risk/engine.ts';
import { ScoringEngine } from './scoring/engine.ts';
import { PolicyEngine } from './policy/engine.ts';
import { PolicyOverrideManager } from './policy/overrides.ts';
import { RecommendationEngine } from './recommendations/engine.ts';
import { UseCaseEngine } from './use-cases/engine.ts';
import { GeminiDecisionAssistant } from './ai/gemini-assistant.ts';

export interface RunDecisionSuiteInput extends RiskEvaluationInput {
  scoreModelKey?: string;
  scoreModelVersion?: string;
  policyKey?: string;
  policyVersion?: string;
  confidenceScore?: number;
  promptInjectionScore?: number;
  useAiSynthesis?: boolean;
  staticStatus?: string;
  dynamicStatus?: string;
  overallStatus?: string;
  truthState?: string;
  why?: string;
  evidenceClassesAvailable?: string[];
  evidenceClassesMissing?: string[];
  staticOnlyConclusions?: string[] | boolean;
  executionSummary?: any;
}

export class DecisionOrchestrationEngine {
  /**
   * Executes the complete decision suite pipeline.
   */
  public static async runDecisionSuite(input: RunDecisionSuiteInput): Promise<DecisionSuiteResult> {
    const startTime = Date.now();
    const runId = input.analysisRunId;

    // 1. Evaluate Risks
    const risks: RiskRecord[] = RiskEngine.evaluateRisks(input);

    // 2. Compute Multi-dimensional Score
    const scoreResult: ScoreResult = ScoringEngine.computeScore({
      analysisRunId: runId,
      modelKey: input.scoreModelKey,
      modelVersion: input.scoreModelVersion,
      risks,
      promptInjectionScore: input.promptInjectionScore,
      evidenceClassesAvailable: input.evidenceClassesAvailable,
      evidenceClassesMissing: input.evidenceClassesMissing,
      staticOnlyConclusions: Array.isArray(input.staticOnlyConclusions)
        ? input.staticOnlyConclusions
        : (input.staticOnlyConclusions ? ['Overall score and risk band are calculated solely from static AST and taint deductions.'] : undefined),
      executionSummary: input.executionSummary,
      dynamicStatus: input.dynamicStatus,
      why: input.why,
    });

    // 3. Evaluate Policy Decision (Enforcing Hard Blocks)
    const policyDecision: PolicyDecision = PolicyEngine.evaluatePolicy({
      analysisRunId: runId,
      policyKey: input.policyKey,
      policyVersion: input.policyVersion,
      scoreResult,
      risks,
      confidenceScore: input.confidenceScore,
      canariesTripped: input.canariesTripped,
      runtimeEvents: input.runtimeEvents,
    });

    // 4. Check for active Policy Override
    const activeOverride = PolicyOverrideManager.getActiveOverride(runId);

    // 5. Generate & Validate Recommendations
    let recommendations: RecommendationRecord[];
    if (input.useAiSynthesis && process.env.GEMINI_API_KEY) {
      recommendations = await GeminiDecisionAssistant.synthesizeRecommendations({
        analysisRunId: runId,
        entityRefId: input.entityRefId,
        risks,
        evidenceList: input.evidenceList,
      });
    } else {
      recommendations = RecommendationEngine.generateRecommendations({
        analysisRunId: runId,
        entityRefId: input.entityRefId,
        risks,
        evidenceList: input.evidenceList,
      });
    }

    const recValidation = RecommendationEngine.validateRecommendations(
      recommendations,
      risks,
      input.evidenceList
    );
    if (!recValidation.valid) {
      console.warn('Recommendation validation warning:', recValidation.errors);
    }

    // 6. Evaluate & Validate Use Cases (Mandate 3 Positive + 3 Negative)
    let useCases: UseCaseEvaluationRecord[];
    if (input.useAiSynthesis && process.env.GEMINI_API_KEY) {
      useCases = await GeminiDecisionAssistant.synthesizeUseCases({
        analysisRunId: runId,
        scoreResult,
        policyDecision,
        risks,
        evidenceList: input.evidenceList,
      });
    } else {
      useCases = UseCaseEngine.evaluateUseCases({
        analysisRunId: runId,
        scoreResult,
        policyDecision,
        risks,
        evidenceList: input.evidenceList,
      });
    }

    const ucValidation = UseCaseEngine.validateUseCaseSuite(useCases, undefined, input.evidenceList);
    if (!ucValidation.valid) {
      console.warn('Use-case suite validation warning:', ucValidation.errors);
    }

    const durationMs = Date.now() - startTime;

    return {
      analysis_run_id: runId,
      entity_ref_id: input.entityRefId,
      risks,
      score_result: scoreResult,
      policy_decision: policyDecision,
      active_override: activeOverride,
      recommendations,
      use_case_evaluations: useCases,
      confidence_score: input.confidenceScore ?? 0.95,
      duration_ms: durationMs,
      created_at: new Date().toISOString(),
      static_status: input.staticStatus,
      dynamic_status: input.dynamicStatus,
      overall_status: input.overallStatus,
      truth_state: input.truthState,
      why: input.why,
      executed: input.executionSummary?.executed,
      not_verified: input.executionSummary?.not_verified,
      static_only_conclusions: input.staticOnlyConclusions || input.executionSummary?.static_only_conclusions,
      evidence_classes_available: input.evidenceClassesAvailable || input.executionSummary?.evidence_classes_available,
      evidence_classes_missing: input.evidenceClassesMissing || input.executionSummary?.evidence_classes_missing,
      execution_summary: input.executionSummary,
    };
  }
}
