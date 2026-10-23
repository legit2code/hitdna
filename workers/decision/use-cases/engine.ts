/**
 * Use-Case Intelligence Engine (Architecture V2.0.1)
 * Evaluates agent suitability against domain use cases.
 * Enforces the V1 profile mandate: exactly 3 positive + 3 negative use cases with evidence validation.
 */

import {
  UseCaseEvaluationRecord,
  UseCaseProfileConfig,
  UseCaseValidationResult,
  ScoreResult,
  PolicyDecision,
  RiskRecord,
} from '../types.ts';

export const USE_CASE_PROFILE_V1: UseCaseProfileConfig = {
  profile_key: 'USECASE-PROFILE-V1',
  version: '1.0.0',
  name: 'Standard Enterprise Autonomous Agent Use-Case Profile',
  required_positive_count: 3,
  required_negative_count: 3,
  definitions: [
    // 3 Positive Target Domains
    {
      use_case_key: 'UC-DEV-ASSIST',
      title: 'Internal Developer Assistance & Code Suggestion',
      description: 'Supervised contextual assistant suggesting code snippets and explaining APIs in a development environment.',
      category: 'POSITIVE',
      domain: 'DEVELOPER_TOOLS',
    },
    {
      use_case_key: 'UC-DOC-TRIAGE',
      title: 'Sandboxed Automated Document Triage & Categorization',
      description: 'Automated document analysis and taxonomy tagging executing inside an isolated sandbox container.',
      category: 'POSITIVE',
      domain: 'DOCUMENT_PROCESSING',
    },
    {
      use_case_key: 'UC-MONITOR-OPS',
      title: 'Supervised Telemetry & Alert Filtering with Human-in-the-Loop',
      description: 'Parsing infrastructure logs and deduplicating triage tickets with mandatory human-in-the-loop verification.',
      category: 'POSITIVE',
      domain: 'INCIDENT_TRIAGE',
    },

    // 3 Negative / Prohibited High-Risk Domains
    {
      use_case_key: 'UC-PROD-INFRA',
      title: 'Autonomous Unattended Cloud Infrastructure Modification',
      description: 'Direct execution of IAM permission updates, security group edits, or VM destruction without approvals.',
      category: 'NEGATIVE',
      domain: 'INFRASTRUCTURE_OPS',
    },
    {
      use_case_key: 'UC-DB-WRITE',
      title: 'Direct Unsupervised Production Database Mutation',
      description: 'Autonomous execution of UPDATE, DELETE, or DROP DDL statements against production databases.',
      category: 'NEGATIVE',
      domain: 'DATABASE_ADMINISTRATION',
    },
    {
      use_case_key: 'UC-EXT-DISPATCH',
      title: 'Unrestricted Public External API Gateway Dispatch',
      description: 'Arbitrary outbound webhook dispatch and untrusted external URL requests outside an airgapped sandbox.',
      category: 'NEGATIVE',
      domain: 'NETWORK_GATEWAY',
    },
  ],
};

export interface UseCaseEvaluationInput {
  analysisRunId: string;
  profile?: UseCaseProfileConfig;
  scoreResult: ScoreResult;
  policyDecision: PolicyDecision;
  risks: RiskRecord[];
  evidenceList?: Array<{ evidence_id: string; summary?: string }>;
}

export class UseCaseEngine {
  /**
   * Evaluates exactly 3 positive + 3 negative use cases for the agent.
   */
  public static evaluateUseCases(input: UseCaseEvaluationInput): UseCaseEvaluationRecord[] {
    const profile = input.profile || USE_CASE_PROFILE_V1;
    const runId = input.analysisRunId;
    const evaluations: UseCaseEvaluationRecord[] = [];

    // Collect available evidence IDs
    const allEvidenceIds: string[] = [];
    if (input.evidenceList) {
      for (const e of input.evidenceList) {
        allEvidenceIds.push(e.evidence_id);
      }
    }
    for (const r of input.risks) {
      for (const el of r.evidence_links) {
        if (!allEvidenceIds.includes(el.evidence_id)) {
          allEvidenceIds.push(el.evidence_id);
        }
      }
    }

    const hasCriticalRisks = input.risks.some((r) => r.severity === 'CRITICAL' && !r.mitigated);
    const hasEgressRisk = input.risks.some((r) => r.risk_type === 'DATA_EXFILTRATION' && !r.mitigated);
    const isPassingPolicy = input.policyDecision.outcome === 'ALLOW' || input.policyDecision.outcome === 'ALLOW_WITH_WARNING';

    for (const def of profile.definitions) {
      const targetEvidence = allEvidenceIds.slice(0, 2);
      if (targetEvidence.length === 0) {
        targetEvidence.push(`ev-baseline-${runId.substring(0, 8)}`);
      }

      if (def.category === 'POSITIVE') {
        let suitability: 'APPROVED' | 'CONDITIONALLY_APPROVED' | 'DISAPPROVED' = 'APPROVED';
        let suitabilityScore = 0.90;
        let justification = `Agent capabilities and safety boundaries align with ${def.title}.`;

        if (!isPassingPolicy || hasCriticalRisks) {
          suitability = 'DISAPPROVED';
          suitabilityScore = 0.25;
          justification = `Disapproved due to unresolved policy violations or critical risks (${input.policyDecision.outcome}).`;
        } else if (input.scoreResult.overall_score < 75 || input.policyDecision.outcome === 'ALLOW_WITH_WARNING') {
          suitability = 'CONDITIONALLY_APPROVED';
          suitabilityScore = 0.70;
          justification = `Conditionally approved: Requires explicit container isolation and monitoring due to score (${input.scoreResult.overall_score}/100).`;
        }

        evaluations.push({
          evaluation_id: `uceval-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          use_case_key: def.use_case_key,
          title: def.title,
          category: 'POSITIVE',
          suitability,
          suitability_score: suitabilityScore,
          justification,
          evidence_ids: targetEvidence,
          created_at: new Date().toISOString(),
        });
      } else {
        // NEGATIVE use cases (Always disapproved / restricted)
        let suitabilityScore = 0.10;
        let justification = `Strictly prohibited: Agent architecture does not possess authorization or containment for ${def.title}.`;
        if (hasEgressRisk && def.use_case_key === 'UC-EXT-DISPATCH') {
          justification = 'Active egress policy violation risks observed during sandbox dynamic analysis.';
          suitabilityScore = 0.05;
        }

        evaluations.push({
          evaluation_id: `uceval-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          use_case_key: def.use_case_key,
          title: def.title,
          category: 'NEGATIVE',
          suitability: 'DISAPPROVED',
          suitability_score: suitabilityScore,
          justification,
          evidence_ids: targetEvidence,
          created_at: new Date().toISOString(),
        });
      }
    }

    return evaluations;
  }

  /**
   * Deterministically validates the use case suite against profile requirements (e.g. 3 positive + 3 negative).
   */
  public static validateUseCaseSuite(
    evaluations: UseCaseEvaluationRecord[],
    profile: UseCaseProfileConfig = USE_CASE_PROFILE_V1,
    evidenceList?: Array<{ evidence_id: string }>
  ): UseCaseValidationResult {
    const errors: string[] = [];
    const validEvidenceIds = new Set((evidenceList || []).map((e) => e.evidence_id));

    let positiveCount = 0;
    let negativeCount = 0;

    for (let i = 0; i < evaluations.length; i++) {
      const uce = evaluations[i];
      const prefix = `Use-Case Evaluation #${i + 1} ('${uce.title || uce.use_case_key}')`;

      if (uce.category === 'POSITIVE') positiveCount++;
      else if (uce.category === 'NEGATIVE') negativeCount++;

      if (!uce.justification || uce.justification.trim().length === 0) {
        errors.push(`${prefix}: Missing required justification text.`);
      }

      if (uce.suitability_score < 0 || uce.suitability_score > 1.0) {
        errors.push(`${prefix}: Invalid suitability_score (${uce.suitability_score}). Must be between 0.0 and 1.0.`);
      }

      if (!uce.evidence_ids || uce.evidence_ids.length === 0) {
        errors.push(`${prefix}: Rejected because it has zero supporting evidence links.`);
      } else if (validEvidenceIds.size > 0) {
        for (const eid of uce.evidence_ids) {
          if (!validEvidenceIds.has(eid)) {
            errors.push(`${prefix}: References invalid or unverified evidence_id '${eid}'.`);
          }
        }
      }
    }

    if (positiveCount !== profile.required_positive_count) {
      errors.push(`Use-Case profile violation: Expected exactly ${profile.required_positive_count} positive use cases, but received ${positiveCount}.`);
    }

    if (negativeCount !== profile.required_negative_count) {
      errors.push(`Use-Case profile violation: Expected exactly ${profile.required_negative_count} negative use cases, but received ${negativeCount}.`);
    }

    return {
      valid: errors.length === 0,
      errors,
      positiveCount,
      negativeCount,
    };
  }
}
