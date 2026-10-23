/**
 * Policy Engine (Architecture V2.0.1)
 * Evaluates versioned policy rules, computes outcomes, enforces hard blocks, and logs score overrides.
 */

import {
  PolicyDecision,
  PolicyDecisionReason,
  PolicyOutcome,
  ScoreResult,
  RiskRecord,
} from '../types.ts';
import { PolicyRegistry } from './registry.ts';

export interface PolicyEvaluationInput {
  analysisRunId: string;
  policyKey?: string;
  policyVersion?: string;
  scoreResult: ScoreResult;
  risks: RiskRecord[];
  confidenceScore?: number; // 0.0 to 1.0
  canariesTripped?: any[];
  runtimeEvents?: any[];
}

export class PolicyEngine {
  /**
   * Evaluates policy rules against score results, risks, and runtime observations.
   * Never collapses score into policy: Hard blocks override high scores.
   */
  public static evaluatePolicy(input: PolicyEvaluationInput): PolicyDecision {
    const policyKey = input.policyKey || 'POLICY-V1-DEFAULT';
    const policyVersion = input.policyVersion || '1.0.0';
    const policy = PolicyRegistry.getPolicy(policyKey, policyVersion);
    const runId = input.analysisRunId;
    const confidence = input.confidenceScore ?? 0.95;

    const reasons: PolicyDecisionReason[] = [];
    let hardBlockOutcome: PolicyOutcome | null = null;
    let blockingRuleCount = 0;

    for (const rule of policy.rules) {
      switch (rule.condition_type) {
        case 'CANARY_LEAK': {
          const canaryCompromised = input.risks.some(
            (r) => r.risk_type === 'HONEYTOKEN_COMPROMISE' && !r.mitigated
          ) || (input.canariesTripped && input.canariesTripped.length > 0);

          if (canaryCompromised) {
            reasons.push({
              reason_id: `rsn-canary-${Date.now()}`,
              rule_key: rule.rule_key,
              rule_name: rule.rule_name,
              reason_text: 'Deceptive canary honeytoken was compromised during dynamic analysis.',
              is_blocking: rule.is_blocking,
              severity: rule.severity,
            });
            if (rule.is_blocking) {
              blockingRuleCount++;
              hardBlockOutcome = 'QUARANTINE';
            }
          }
          break;
        }

        case 'DIRECT_INJECTION_SINK': {
          const injectionRisks = input.risks.filter(
            (r) => r.risk_type === 'CODE_EXECUTION' && !r.mitigated
          );
          if (injectionRisks.length > 0) {
            for (const r of injectionRisks) {
              reasons.push({
                reason_id: `rsn-inject-${Date.now()}`,
                rule_key: rule.rule_key,
                rule_name: rule.rule_name,
                risk_id: r.risk_id,
                reason_text: `Unsanitized input sink detected: ${r.title}`,
                is_blocking: rule.is_blocking,
                severity: rule.severity,
                evidence_ids: r.evidence_links.map((e) => e.evidence_id),
              });
            }
            if (rule.is_blocking) {
              blockingRuleCount++;
              if (hardBlockOutcome !== 'QUARANTINE') {
                hardBlockOutcome = 'DENY_SHIPPING';
              }
            }
          }
          break;
        }

        case 'CRITICAL_RISK_THRESHOLD': {
          const criticals = input.risks.filter(
            (r) => r.severity === 'CRITICAL' && !r.mitigated
          );
          if (criticals.length > 0) {
            for (const r of criticals) {
              reasons.push({
                reason_id: `rsn-crit-${Date.now()}`,
                rule_key: rule.rule_key,
                rule_name: rule.rule_name,
                risk_id: r.risk_id,
                reason_text: `Unmitigated CRITICAL risk: ${r.title}`,
                is_blocking: rule.is_blocking,
                severity: 'CRITICAL',
                evidence_ids: r.evidence_links.map((e) => e.evidence_id),
              });
            }
            if (rule.is_blocking) {
              blockingRuleCount++;
              if (!hardBlockOutcome || hardBlockOutcome !== 'QUARANTINE') {
                hardBlockOutcome = 'DENY_SHIPPING';
              }
            }
          }
          break;
        }

        case 'EGRESS_VIOLATION': {
          const egressRisks = input.risks.filter(
            (r) => r.risk_type === 'DATA_EXFILTRATION' && !r.mitigated
          );
          if (egressRisks.length > 0) {
            for (const r of egressRisks) {
              reasons.push({
                reason_id: `rsn-egress-${Date.now()}`,
                rule_key: rule.rule_key,
                rule_name: rule.rule_name,
                risk_id: r.risk_id,
                reason_text: `Unauthorized network egress violation: ${r.title}`,
                is_blocking: rule.is_blocking,
                severity: rule.severity,
                evidence_ids: r.evidence_links.map((e) => e.evidence_id),
              });
            }
            if (rule.is_blocking) {
              blockingRuleCount++;
              if (!hardBlockOutcome) {
                hardBlockOutcome = 'RESTRICT';
              }
            }
          }
          break;
        }

        case 'UNCERTAINTY_CONFIDENCE': {
          const threshold = rule.threshold ?? 0.70;
          if (confidence < threshold) {
            reasons.push({
              reason_id: `rsn-conf-${Date.now()}`,
              rule_key: rule.rule_key,
              rule_name: rule.rule_name,
              reason_text: `Evaluation confidence (${(confidence * 100).toFixed(1)}%) is below required threshold (${(threshold * 100).toFixed(1)}%). Requires manual security review.`,
              is_blocking: false,
              severity: rule.severity,
            });
          }
          break;
        }

        case 'MIN_SCORE_THRESHOLD': {
          const minScore = rule.threshold ?? 70;
          if (input.scoreResult.overall_score < minScore) {
            reasons.push({
              reason_id: `rsn-score-${Date.now()}`,
              rule_key: rule.rule_key,
              rule_name: rule.rule_name,
              reason_text: `Overall score (${input.scoreResult.overall_score}) is below standard passing threshold (${minScore}).`,
              is_blocking: false,
              severity: rule.severity,
            });
          }
          break;
        }
      }
    }

    // Determine final policy outcome
    let outcome: PolicyOutcome;
    let scoreOverrideApplied = false;
    let scoreVsPolicyNotes: string | undefined;

    if (hardBlockOutcome) {
      outcome = hardBlockOutcome;
      // If score was passing (>= 70), policy explicitly overrode score
      if (input.scoreResult.overall_score >= 70) {
        scoreOverrideApplied = true;
        scoreVsPolicyNotes = `Score of ${input.scoreResult.overall_score}/100 was favorable, but hard policy blocking rule(s) (${blockingRuleCount}) overrode the score to ${outcome}.`;
      }
    } else {
      // Check for manual review requirements
      const requiresReview = reasons.some((r) => r.rule_key?.includes('CONF') || r.severity === 'HIGH');
      if (requiresReview || (input.scoreResult.overall_score >= 50 && input.scoreResult.overall_score < 70 && confidence < 0.8)) {
        outcome = 'REQUIRE_REVIEW';
      } else if (input.scoreResult.overall_score >= 85) {
        outcome = 'ALLOW';
      } else if (input.scoreResult.overall_score >= 70) {
        outcome = reasons.length > 0 ? 'ALLOW_WITH_WARNING' : 'ALLOW';
      } else if (input.scoreResult.overall_score >= 50) {
        outcome = 'ALLOW_WITH_WARNING';
      } else if (input.scoreResult.overall_score >= 30) {
        outcome = 'RESTRICT';
      } else {
        outcome = 'DENY_SHIPPING';
      }
    }

    const evaluationSummary = `Policy evaluation against ${policy.name} (${policy.version}) resulted in ${outcome}. ${
      blockingRuleCount > 0 ? `${blockingRuleCount} hard blocking rule(s) triggered.` : 'No hard blocking violations.'
    } ${scoreVsPolicyNotes || ''}`.trim();

    return {
      decision_id: `dec-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
      analysis_run_id: runId,
      policy_key: policy.policy_key,
      policy_version: policy.version,
      outcome,
      evaluation_summary: evaluationSummary,
      score_override_applied: scoreOverrideApplied,
      score_vs_policy_notes: scoreVsPolicyNotes,
      reasons,
      blocking_rule_count: blockingRuleCount,
      created_at: new Date().toISOString(),
    };
  }
}
