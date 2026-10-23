import {
  AgentVersionSnapshot,
  DiffAnalysisResult,
  ValidationRunRecord,
  ValidationResultItem,
  ValidationType,
  ApprovalRecord,
} from '../types.ts';
import { DifferentialAnalysisEngine } from '../differential/comparator.ts';

export interface ExecuteValidationParams {
  validationType: ValidationType;
  baseline: AgentVersionSnapshot;
  modified: AgentVersionSnapshot;
  validationAnalysisRunId: string;
  scopeId: string;
  scenarioPackId?: string;
  validationPlanVersion?: string;
  policyRulesetVersion?: string;
  approvals?: ApprovalRecord[];
  requireApprovalForSourceMod?: boolean;
}

export class ValidationEngine {
  /**
   * Executes formal validation comparison between baseline and modified candidate versions
   * in strict compliance with Architecture V2.0.1 Document 21B.
   */
  public static execute(params: ExecuteValidationParams): ValidationRunRecord {
    const validationRunId = `val-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const startedAt = new Date().toISOString();
    const validationPlanVersion = params.validationPlanVersion || '2.0.1';

    // 1. Invariant Validation (Document 21B Section 5)
    if (
      params.validationType === 'SOURCE_MODIFICATION' &&
      params.baseline.agentVersionId === params.modified.agentVersionId
    ) {
      const failedRecord: ValidationRunRecord = {
        validation_run_id: validationRunId,
        validation_type: params.validationType,
        baseline_agent_version_id: params.baseline.agentVersionId,
        modified_agent_version_id: params.modified.agentVersionId,
        baseline_analysis_run_id: params.baseline.analysisRunId,
        modified_analysis_run_id: params.modified.analysisRunId,
        validation_analysis_run_id: params.validationAnalysisRunId,
        scenario_pack_id: params.scenarioPackId || null,
        validation_plan_version: validationPlanVersion,
        policy_ruleset_version: params.policyRulesetVersion || null,
        scope_id: params.scopeId,
        status: 'ERROR',
        started_at: startedAt,
        completed_at: new Date().toISOString(),
        created_at: startedAt,
        results: [
          {
            resultType: 'POLICY_EVALUATION',
            status: 'FAILED',
            details:
              'Invariant check violated: SOURCE_MODIFICATION requires baseline_agent_version_id != modified_agent_version_id',
          },
        ],
        validationDecision: {
          passed: false,
          verdict: 'REJECTED_REGRESSION',
          reason: 'Schema invariant violated: baseline and modified versions cannot be identical for SOURCE_MODIFICATION.',
          riskReduced: false,
          capabilitiesPreserved: false,
          hasCriticalViolations: true,
        },
      };
      return failedRecord;
    }

    // 2. Approval Gate Invariant: Unapproved modification cannot validate or ship
    if (params.requireApprovalForSourceMod && params.validationType === 'SOURCE_MODIFICATION') {
      const hasApproval = (params.approvals || []).some((a) => a.decision === 'APPROVED');
      if (!hasApproval) {
        return {
          validation_run_id: validationRunId,
          validation_type: params.validationType,
          baseline_agent_version_id: params.baseline.agentVersionId,
          modified_agent_version_id: params.modified.agentVersionId,
          baseline_analysis_run_id: params.baseline.analysisRunId,
          modified_analysis_run_id: params.modified.analysisRunId,
          validation_analysis_run_id: params.validationAnalysisRunId,
          scenario_pack_id: params.scenarioPackId || null,
          validation_plan_version: validationPlanVersion,
          policy_ruleset_version: params.policyRulesetVersion || null,
          scope_id: params.scopeId,
          status: 'FAILED',
          started_at: startedAt,
          completed_at: new Date().toISOString(),
          created_at: startedAt,
          results: [
            {
              resultType: 'POLICY_EVALUATION',
              status: 'FAILED',
              details: 'Unapproved modification workspace cannot proceed through validation.',
            },
          ],
          validationDecision: {
            passed: false,
            verdict: 'REJECTED_UNAPPROVED_CHANGES',
            reason: 'Formal security approval missing; unapproved modifications cannot validate or ship.',
            riskReduced: false,
            capabilitiesPreserved: false,
            hasCriticalViolations: true,
          },
        };
      }
    }

    // 3. Compute Full Differential Analysis
    const diff = DifferentialAnalysisEngine.compare(params.baseline, params.modified);
    const results: ValidationResultItem[] = [];

    // Check A: Risk Delta
    const riskReduced =
      params.modified.riskScore.riskIndex <= params.baseline.riskScore.riskIndex &&
      params.modified.riskScore.criticalFindingsCount <= params.baseline.riskScore.criticalFindingsCount;

    results.push({
      resultType: 'RISK_DELTA',
      status: riskReduced ? 'PASSED' : 'FAILED',
      beforeValue: { riskIndex: params.baseline.riskScore.riskIndex, critical: params.baseline.riskScore.criticalFindingsCount },
      afterValue: { riskIndex: params.modified.riskScore.riskIndex, critical: params.modified.riskScore.criticalFindingsCount },
      details: riskReduced
        ? `Risk index improved or remained stable (baseline: ${params.baseline.riskScore.riskIndex}, modified: ${params.modified.riskScore.riskIndex}).`
        : `Risk index regressed or critical findings increased (baseline: ${params.baseline.riskScore.riskIndex}, modified: ${params.modified.riskScore.riskIndex}).`,
    });

    // Check B: Capability Preservation & Regression
    const lostEssentialCaps = diff.capabilityDiffs.filter((c) => c.changeType === 'LOST' && c.isEssential);
    const capabilitiesPreserved = lostEssentialCaps.length === 0;

    results.push({
      resultType: 'CAPABILITY_PRESERVATION',
      status: capabilitiesPreserved ? 'PASSED' : 'FAILED',
      beforeValue: params.baseline.capabilities.map((c) => c.name),
      afterValue: params.modified.capabilities.map((c) => c.name),
      details: capabilitiesPreserved
        ? 'All essential agent capabilities were successfully preserved in candidate version.'
        : `Unacceptable capability regression: ${lostEssentialCaps.map((c) => c.name).join(', ')} were lost.`,
    });

    // Check C: Behavioral Scenario Rerun
    const scenarioRegressions = diff.behaviorDiffs.filter((b) => b.changeType === 'REGRESSED');
    const behaviorsPreserved = scenarioRegressions.length === 0;

    results.push({
      resultType: 'BEHAVIORAL_REPLAY',
      status: behaviorsPreserved ? 'PASSED' : 'FAILED',
      details: behaviorsPreserved
        ? `All dynamic test scenarios verified (${diff.behaviorDiffs.length} total).`
        : `Behavioral scenario regression detected in: ${scenarioRegressions.map((b) => b.name).join(', ')}`,
    });

    // Check D: Policy & Critical Violations
    const hasCriticalViolations =
      params.modified.riskScore.criticalFindingsCount > 0 ||
      params.modified.riskScore.policyViolationsCount > 0;

    results.push({
      resultType: 'POLICY_EVALUATION',
      status: !hasCriticalViolations ? 'PASSED' : 'FAILED',
      details: !hasCriticalViolations
        ? 'Zero critical findings and zero policy violations.'
        : `Detected ${params.modified.riskScore.criticalFindingsCount} critical findings and ${params.modified.riskScore.policyViolationsCount} policy violations.`,
    });

    // 4. Decision Synthesis
    // CRITICAL REQUIREMENT: "risk improvement with unacceptable capability regression fails"
    let overallPassed = false;
    let verdict: 'APPROVED_FOR_RELEASE' | 'REJECTED_REGRESSION' | 'REJECTED_UNAPPROVED_CHANGES' | 'REQUIRES_MANUAL_REVIEW' =
      'REJECTED_REGRESSION';
    let decisionReason = '';

    if (!capabilitiesPreserved) {
      overallPassed = false;
      verdict = 'REJECTED_REGRESSION';
      decisionReason =
        'Validation failed: Candidate version exhibited unacceptable capability regression despite any risk improvements.';
    } else if (!riskReduced || hasCriticalViolations) {
      overallPassed = false;
      verdict = 'REJECTED_REGRESSION';
      decisionReason =
        'Validation failed: Candidate version failed risk reduction or contains unmitigated critical security findings.';
    } else if (!behaviorsPreserved) {
      overallPassed = false;
      verdict = 'REQUIRES_MANUAL_REVIEW';
      decisionReason =
        'Validation requires review: Behavioral scenario regressions observed during replay.';
    } else {
      overallPassed = true;
      verdict = 'APPROVED_FOR_RELEASE';
      decisionReason =
        'Validation passed: Clean improvement verified with risk reduction, complete capability preservation, and scenario parity.';
    }

    const finalStatus = overallPassed ? 'PASSED' : verdict === 'REQUIRES_MANUAL_REVIEW' ? 'REQUIRES_REVIEW' : 'FAILED';

    return {
      validation_run_id: validationRunId,
      validation_type: params.validationType,
      baseline_agent_version_id: params.baseline.agentVersionId,
      modified_agent_version_id: params.modified.agentVersionId,
      baseline_analysis_run_id: params.baseline.analysisRunId,
      modified_analysis_run_id: params.modified.analysisRunId,
      validation_analysis_run_id: params.validationAnalysisRunId,
      scenario_pack_id: params.scenarioPackId || null,
      validation_plan_version: validationPlanVersion,
      policy_ruleset_version: params.policyRulesetVersion || null,
      scope_id: params.scopeId,
      status: finalStatus,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      created_at: startedAt,
      results,
      validationDecision: {
        passed: overallPassed,
        verdict,
        reason: decisionReason,
        riskReduced,
        capabilitiesPreserved,
        hasCriticalViolations,
      },
    };
  }
}
