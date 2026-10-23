/**
 * Recommendation Engine (Architecture V2.0.1)
 * Generates evidence-backed recommendations and deterministically validates support requirements.
 */

import {
  RecommendationRecord,
  RecommendationValidationResult,
  RecommendationPriority,
  RecommendationEffort,
  RecommendationType,
  RiskRecord,
} from '../types.ts';

export interface GenerateRecommendationsInput {
  analysisRunId: string;
  entityRefId?: string;
  risks: RiskRecord[];
  evidenceList?: Array<{ evidence_id: string; summary?: string }>;
}

export class RecommendationEngine {
  /**
   * Generates actionable recommendations directly traced to identified risks and evidence.
   */
  public static generateRecommendations(input: GenerateRecommendationsInput): RecommendationRecord[] {
    const recommendations: RecommendationRecord[] = [];
    const runId = input.analysisRunId;
    const entityRefId = input.entityRefId;

    for (const risk of input.risks) {
      if (risk.mitigated) continue;

      let priority: RecommendationPriority = 'P2';
      let effort: RecommendationEffort = 'MEDIUM';
      let recType: RecommendationType = 'REMEDIATION';

      if (risk.severity === 'CRITICAL') {
        priority = 'P0';
        effort = 'HIGH';
        recType = 'REMEDIATION';
      } else if (risk.severity === 'HIGH') {
        priority = 'P1';
        effort = 'MEDIUM';
        recType = 'REMEDIATION';
      } else if (risk.severity === 'MEDIUM') {
        priority = 'P2';
        effort = 'LOW';
        recType = 'MITIGATION';
      } else {
        priority = 'P3';
        effort = 'LOW';
        recType = 'HARDENING';
      }

      const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
      // If risk has no direct evidence links, link available general evidence if available
      if (evidenceIds.length === 0 && input.evidenceList && input.evidenceList.length > 0) {
        evidenceIds.push(input.evidenceList[0].evidence_id);
      }

      const actionSteps = risk.remediation_guidance ||
        `Address identified ${risk.severity} risk in ${risk.risk_type}: Review call graphs, add input schema bounds, and isolate execution boundaries.`;

      recommendations.push({
        recommendation_id: `rec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        analysis_run_id: runId,
        entity_ref_id: entityRefId,
        risk_id: risk.risk_id,
        recommendation_type: recType,
        title: `Remediate ${risk.title}`,
        action_steps: actionSteps,
        priority,
        effort_estimate: effort,
        evidence_ids: evidenceIds,
        created_at: new Date().toISOString(),
      });
    }

    return recommendations;
  }

  /**
   * Deterministic validation: Rejects any recommendation lacking concrete risk links or valid evidence references.
   */
  public static validateRecommendations(
    recommendations: RecommendationRecord[],
    risks: RiskRecord[],
    evidenceList?: Array<{ evidence_id: string }>
  ): RecommendationValidationResult {
    const errors: string[] = [];
    const validRiskIds = new Set(risks.map((r) => r.risk_id));
    const validEvidenceIds = new Set((evidenceList || []).map((e) => e.evidence_id));

    // Also include evidence IDs already embedded inside risks
    for (const r of risks) {
      for (const el of r.evidence_links) {
        validEvidenceIds.add(el.evidence_id);
      }
    }

    for (let i = 0; i < recommendations.length; i++) {
      const rec = recommendations[i];
      const prefix = `Recommendation #${i + 1} ('${rec.title || rec.recommendation_id}')`;

      if (!rec.title || rec.title.trim().length === 0) {
        errors.push(`${prefix}: Missing required title.`);
      }

      if (!rec.action_steps || rec.action_steps.trim().length === 0) {
        errors.push(`${prefix}: Missing required action steps.`);
      }

      if (rec.risk_id && !validRiskIds.has(rec.risk_id)) {
        errors.push(`${prefix}: Unsupported recommendation references unknown or orphaned risk_id '${rec.risk_id}'.`);
      }

      if (!rec.evidence_ids || rec.evidence_ids.length === 0) {
        errors.push(`${prefix}: Rejected because it has zero supporting evidence links.`);
      } else if (validEvidenceIds.size > 0) {
        for (const eid of rec.evidence_ids) {
          if (!validEvidenceIds.has(eid)) {
            errors.push(`${prefix}: References invalid or unverified evidence_id '${eid}'.`);
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      recommendationCount: recommendations.length,
    };
  }
}
