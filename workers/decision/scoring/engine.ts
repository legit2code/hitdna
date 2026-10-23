/**
 * Scoring Engine (Architecture V2.0.1)
 * Evaluates multi-dimensional scores with explicit deductions, risk-band mapping, and explanations.
 */

import {
  ScoreResult,
  ScoreDimensionValue,
  ScoreExplanation,
  ScoreRiskBand,
  RiskRecord,
} from '../types.ts';
import { ScoreModelRegistry } from './registry.ts';

export interface ScoreCalculationInput {
  analysisRunId?: string;
  modelKey?: string;
  scoreModelKey?: string;
  modelVersion?: string;
  risks?: RiskRecord[];
  staticFindings?: any[];
  dynamicFindings?: any[];
  promptInjectionScore?: number; // 0.0 to 1.0 (1.0 = highly resilient)
  evidenceClassesAvailable?: string[];
  evidenceClassesMissing?: string[];
  staticOnlyConclusions?: string[];
  executionSummary?: any;
  dynamicStatus?: string;
  staticStatus?: string;
  why?: string;
}

export class ScoringEngine {
  /**
   * Computes the multi-dimensional score result according to the specified model version.
   */
  public static computeScore(input: ScoreCalculationInput): ScoreResult {
    const modelKey = input.modelKey || input.scoreModelKey || 'SCORE-MODEL-V1-ARCH';
    const modelVersion = input.modelVersion || '1.0.0';
    const model = ScoreModelRegistry.getModel(modelKey, modelVersion);
    const runId = input.analysisRunId || `run-${Date.now()}`;

    const dimensionValues: ScoreDimensionValue[] = [];
    const keyDeductions: string[] = [];
    const risks = input.risks || [];

    // Map risks by category for dimensional evaluation
    for (const dim of model.dimensions) {
      let rawScore = 100.0;
      const deductions: Array<{ reason: string; points: number; evidence_ids?: string[] }> = [];

      switch (dim.dimension_key) {
        case 'SECURITY_POSTURE': {
          for (const risk of risks) {
            if (risk.risk_type === 'CODE_EXECUTION' || risk.risk_type === 'CREDENTIAL_EXPOSURE' || risk.risk_type === 'PROMPT_INJECTION') {
              let basePenalty = risk.severity === 'CRITICAL' ? 35 : risk.severity === 'HIGH' ? 20 : 10;
              if (model.formula_type === 'NON_LINEAR_PENALTY') {
                basePenalty = Math.round(basePenalty * 1.3);
              }

              // Dynamic Verification Weighting
              let penalty = basePenalty;
              let statusLabel = '';
              if (risk.verification_status === 'DYNAMIC_CONFIRMED') {
                penalty = Math.round(basePenalty * 1.35); // 35% higher penalty when confirmed by live execution
                statusLabel = ' [DYNAMICALLY CONFIRMED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_CONTRADICTED') {
                penalty = Math.round(basePenalty * 0.35); // Lower penalty because execution contradicted static alert
                statusLabel = ' [DYNAMICALLY CONTRADICTED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_UNREPRODUCED') {
                penalty = Math.round(basePenalty * 0.70); // Static flagged but not materialized during run
                statusLabel = ' [STATIC-ONLY / UNREPRODUCED DYNAMICALLY]';
              } else {
                statusLabel = ' [STATIC-ONLY]';
              }

              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `${risk.severity} Risk: ${risk.title}${statusLabel}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Security] -${penalty}pts: ${risk.title}${statusLabel}`);
            }
          }
          break;
        }

        case 'RUNTIME_SAFETY': {
          for (const risk of risks) {
            if (risk.risk_type === 'HONEYTOKEN_COMPROMISE' || risk.risk_type === 'DATA_EXFILTRATION' || risk.risk_type === 'DEFENSIVE_EVASION') {
              let basePenalty = risk.severity === 'CRITICAL' ? 40 : risk.severity === 'HIGH' ? 25 : 10;
              let penalty = basePenalty;
              let statusLabel = '';

              if (risk.verification_status === 'DYNAMIC_CONFIRMED') {
                penalty = Math.round(basePenalty * 1.4); // Heavy penalty for confirmed runtime threats
                statusLabel = ' [DYNAMICALLY CONFIRMED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_CONTRADICTED') {
                penalty = Math.round(basePenalty * 0.3);
                statusLabel = ' [DYNAMICALLY CONTRADICTED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_UNREPRODUCED') {
                penalty = Math.round(basePenalty * 0.7);
                statusLabel = ' [STATIC-ONLY / UNREPRODUCED DYNAMICALLY]';
              } else {
                statusLabel = ' [STATIC-ONLY]';
              }

              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `${risk.severity} Runtime Threat: ${risk.title}${statusLabel}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Runtime] -${penalty}pts: ${risk.title}${statusLabel}`);
            }
          }
          break;
        }

        case 'DEPENDENCY_HEALTH': {
          for (const risk of risks) {
            if (risk.risk_type === 'SUPPLY_CHAIN') {
              let basePenalty = risk.severity === 'CRITICAL' ? 30 : risk.severity === 'HIGH' ? 20 : 10;
              let penalty = basePenalty;
              let statusLabel = '';

              if (risk.verification_status === 'DYNAMIC_CONFIRMED') {
                penalty = Math.round(basePenalty * 1.25);
                statusLabel = ' [DYNAMICALLY REACHED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_UNREPRODUCED') {
                penalty = Math.round(basePenalty * 0.8);
                statusLabel = ' [STATIC REACHABLE / UNEXECUTED]';
              }

              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `Reachable Dependency Vulnerability: ${risk.title}${statusLabel}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Supply Chain] -${penalty}pts: ${risk.title}${statusLabel}`);
            }
          }
          break;
        }

        case 'CODE_QUALITY': {
          for (const risk of risks) {
            if (risk.risk_type === 'DATA_INTEGRITY' || risk.risk_type === 'FILE_SYSTEM' || risk.risk_type === 'GOVERNANCE') {
              let basePenalty = risk.severity === 'HIGH' ? 15 : risk.severity === 'MEDIUM' ? 10 : 5;
              let penalty = basePenalty;
              let statusLabel = '';

              if (risk.verification_status === 'DYNAMIC_CONFIRMED') {
                penalty = Math.round(basePenalty * 1.2);
                statusLabel = ' [DYNAMICALLY CONFIRMED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_CONTRADICTED') {
                penalty = Math.round(basePenalty * 0.5);
                statusLabel = ' [DYNAMICALLY CONTRADICTED IN E2B]';
              } else if (risk.verification_status === 'DYNAMIC_UNREPRODUCED') {
                statusLabel = ' [STATIC-ONLY / UNREPRODUCED]';
              }

              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `${risk.severity} Quality Defect: ${risk.title}${statusLabel}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Quality] -${penalty}pts: ${risk.title}${statusLabel}`);
            }
          }
          break;
        }

        case 'PROMPT_RESILIENCE': {
          if (input.promptInjectionScore !== undefined) {
            const shortfall = Math.max(0, (1.0 - input.promptInjectionScore) * 100);
            if (shortfall > 0) {
              const penalty = Math.round(shortfall);
              rawScore -= penalty;
              deductions.push({
                reason: `Prompt injection safety resilience shortfall (${Math.round(input.promptInjectionScore * 100)}% resilience)`,
                points: penalty,
              });
              keyDeductions.push(`[Prompt] -${penalty}pts: Prompt injection vulnerability probe`);
            }
          }
          break;
        }
      }

      rawScore = Math.max(0, Math.min(100, rawScore));
      const weightedScore = parseFloat((rawScore * dim.weight).toFixed(4));

      dimensionValues.push({
        dimension_key: dim.dimension_key,
        display_name: dim.display_name,
        raw_score: rawScore,
        weight: dim.weight,
        weighted_score: weightedScore,
        deductions,
      });
    }

    // Aggregate overall score
    let overallScore = 0;
    for (const d of dimensionValues) {
      overallScore += d.weighted_score;
    }
    overallScore = parseFloat(Math.max(0, Math.min(100, overallScore)).toFixed(2));
    const normalizedScore = parseFloat((overallScore / 100.0).toFixed(4));

    // Grade assignment
    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    if (overallScore >= 95) grade = 'A+';
    else if (overallScore >= 85) grade = 'A';
    else if (overallScore >= 70) grade = 'B';
    else if (overallScore >= 50) grade = 'C';
    else if (overallScore >= 30) grade = 'D';
    else grade = 'F';

    // Risk band mapping
    let riskBand: ScoreRiskBand;
    if (overallScore >= 85) riskBand = 'MINIMAL';
    else if (overallScore >= 70) riskBand = 'LOW';
    else if (overallScore >= 50) riskBand = 'MODERATE';
    else if (overallScore >= 30) riskBand = 'ELEVATED';
    else riskBand = 'SEVERE';

    // Dynamic Verification Breakdown Calculation
    let dynamicConfirmedCount = 0;
    let dynamicUnreproducedCount = 0;
    let dynamicContradictedCount = 0;
    let staticOnlyCount = 0;
    const dynamicBreakdown: Array<{ risk_id: string; title: string; verification_status: any; detail: string }> = [];

    for (const r of risks) {
      const vStatus = r.verification_status || 'STATIC_ONLY';
      if (vStatus === 'DYNAMIC_CONFIRMED') {
        dynamicConfirmedCount++;
        dynamicBreakdown.push({
          risk_id: r.risk_id,
          title: r.title,
          verification_status: vStatus,
          detail: r.dynamic_context?.summary || 'Static risk hypothesis confirmed via dynamic execution.',
        });
      } else if (vStatus === 'DYNAMIC_CONTRADICTED') {
        dynamicContradictedCount++;
        dynamicBreakdown.push({
          risk_id: r.risk_id,
          title: r.title,
          verification_status: vStatus,
          detail: r.dynamic_context?.summary || 'Static risk hypothesis contradicted; live runtime executed safely without reproducing vulnerability.',
        });
      } else if (vStatus === 'DYNAMIC_UNREPRODUCED') {
        dynamicUnreproducedCount++;
        dynamicBreakdown.push({
          risk_id: r.risk_id,
          title: r.title,
          verification_status: vStatus,
          detail: r.dynamic_context?.summary || 'Static risk flagged by AST/taint analysis; dormant during scenario execution (did not materialize).',
        });
      } else {
        staticOnlyCount++;
        dynamicBreakdown.push({
          risk_id: r.risk_id,
          title: r.title,
          verification_status: vStatus,
          detail: 'Evaluated purely via static AST/symbol graph analysis (no dynamic scenario correlated).',
        });
      }
    }

    // Identify strongest and weakest dimensions
    const sortedDims = [...dimensionValues].sort((a, b) => b.raw_score - a.raw_score);
    const strongest = sortedDims[0]?.display_name || 'N/A';
    const weakest = sortedDims[sortedDims.length - 1]?.display_name || 'N/A';

    const isDynamicVerified = input.dynamicStatus === 'DYNAMIC_COMPLETE' || (dynamicConfirmedCount > 0 && input.dynamicStatus !== 'DYNAMIC_NOT_VERIFIED' && input.dynamicStatus !== 'DYNAMIC_FAILED');

    const availableEvidence = input.evidenceClassesAvailable || (
      isDynamicVerified
        ? ['STATIC_CODE', 'STATIC_AST', 'DYNAMIC_RUNTIME', 'DYNAMIC_EXECUTION_TRACE', 'DYNAMIC_EGRESS_LOG', 'RUNTIME_SYSCALL_TRACES']
        : ['STATIC_CODE', 'STATIC_AST']
    );

    const missingEvidence = input.evidenceClassesMissing || (
      isDynamicVerified
        ? []
        : ['DYNAMIC_RUNTIME', 'DYNAMIC_EXECUTION_TRACE', 'DYNAMIC_EGRESS_LOG', 'RUNTIME_SYSCALL_TRACES', 'NETWORK_EGRESS_CAPTURE']
    );

    const staticConclusions = input.staticOnlyConclusions || (
      isDynamicVerified
        ? []
        : [
            'Overall score and risk band are calculated solely from static AST and taint deductions.',
            'Absence of malicious runtime behavior was not verified via live dynamic sandbox execution.',
            'Vulnerability severity has not been dynamically confirmed in microVM.',
          ]
    );

    const summaryText = isDynamicVerified
      ? `Overall score ${overallScore}/100 (Grade ${grade}, Risk Band ${riskBand}) computed via ${model.name} (${model.version}) with verified dynamic runtime telemetry.`
      : `Overall score ${overallScore}/100 (Grade ${grade}, Risk Band ${riskBand}) computed via ${model.name} (${model.version}) from STATIC EVIDENCE ONLY (dynamic verification was not performed: ${input.why || 'dynamic execution unverified'}).`;

    const explanation: ScoreExplanation = {
      summary: summaryText,
      strongest_dimension: strongest,
      weakest_dimension: weakest,
      key_deductions: keyDeductions.length > 0 ? keyDeductions : ['No deductions; flawless evaluation posture.'],
      dynamic_verification_summary: {
        dynamic_confirmed_count: dynamicConfirmedCount,
        dynamic_unreproduced_count: dynamicUnreproducedCount,
        dynamic_contradicted_count: dynamicContradictedCount,
        static_only_count: staticOnlyCount,
        dynamic_findings_breakdown: dynamicBreakdown,
      },
      evidence_classes_available: availableEvidence,
      evidence_classes_missing: missingEvidence,
      static_only_conclusions: staticConclusions,
      dynamic_status: input.dynamicStatus,
      static_status: input.staticStatus,
      execution_summary: input.executionSummary,
    };

    return {
      score_result_id: `score-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      analysis_run_id: runId,
      model_key: model.model_key,
      model_version: model.version,
      overall_score: overallScore,
      normalized_score: normalizedScore,
      grade,
      risk_band: riskBand,
      dimension_values: dimensionValues,
      explanation,
      calibration_version: model.calibration_version,
      created_at: new Date().toISOString(),
    };
  }
}
