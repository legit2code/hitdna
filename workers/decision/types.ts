/**
 * Decision, Risk, Scoring, Policy, Recommendations & Use Cases Types
 * Architecture V2.0.1 — P21 Standard
 */

import {
  PolicyOutcome,
  RiskSeverity,
  ScoreRiskBand,
  RecommendationPriority,
  RecommendationEffort,
  RecommendationType,
  UseCaseSuitability,
} from '@caim/contracts/enums.ts';

export type {
  PolicyOutcome,
  RiskSeverity,
  ScoreRiskBand,
  RecommendationPriority,
  RecommendationEffort,
  RecommendationType,
  UseCaseSuitability,
};

// ==========================================
// 1. RISK TYPES
// ==========================================

export interface RiskEvidenceLink {
  evidence_id: string;
  relevance_score: number; // 0.0 to 1.0
  notes?: string;
}

export type RiskVerificationStatus = 'STATIC_ONLY' | 'DYNAMIC_CONFIRMED' | 'DYNAMIC_CONTRADICTED' | 'DYNAMIC_UNREPRODUCED';

export interface DynamicFindingMatch {
  finding_id?: string;
  rule_id?: string;
  category?: string;
  severity?: string;
  static_prediction?: string;
  dynamic_evidence: {
    matched_event_ids?: string[];
    summary?: string;
    syscalls?: string[];
    network_egress_attempted?: string[];
    filesystem_access?: string[];
    exit_code?: number;
    raw_traces?: string[];
  };
  concordance: 'CONFIRMED' | 'CONTRADICTED' | 'UNREPRODUCED' | 'PARTIAL';
  notes?: string;
}

export interface RiskRecord {
  risk_id: string;
  analysis_run_id: string;
  entity_ref_id?: string;
  rule_id?: string;
  claim_id?: string;
  risk_type: string;
  title: string;
  description: string;
  severity: RiskSeverity;
  likelihood: number; // 0.0 to 1.0
  impact: number; // 0.0 to 1.0
  risk_score: number; // likelihood * impact (0.0 to 1.0)
  mitigated: boolean;
  verification_status?: RiskVerificationStatus;
  dynamic_context?: {
    concordance: string;
    summary: string;
    syscalls?: string[];
    network_egress_attempted?: string[];
    filesystem_access?: string[];
    exit_code?: number;
  };
  mitigation_notes?: string;
  remediation_guidance?: string;
  evidence_links: RiskEvidenceLink[];
  created_at: string;
}

export interface RiskTaxonomyRule {
  rule_id: string;
  category: string;
  title_template: string;
  severity: RiskSeverity;
  base_likelihood: number;
  base_impact: number;
  description_template: string;
  remediation_template: string;
}

// ==========================================
// 2. SCORING TYPES
// ==========================================

export interface ScoreDimensionConfig {
  dimension_key: string;
  display_name: string;
  description: string;
  weight: number; // 0.0 to 1.0, sum of weights = 1.0
  min_score: number; // 0
  max_score: number; // 100
}

export interface ScoreModelConfig {
  model_key: string;
  version: string;
  name: string;
  description: string;
  formula_type: 'WEIGHTED_LINEAR' | 'NON_LINEAR_PENALTY';
  dimensions: ScoreDimensionConfig[];
  calibration_version: string;
  status: 'ACTIVE' | 'DEPRECATED';
}

export interface ScoreDimensionValue {
  dimension_key: string;
  display_name: string;
  raw_score: number; // 0.0 to 100.0
  weight: number;
  weighted_score: number; // raw_score * weight
  deductions: Array<{
    reason: string;
    points: number;
    evidence_ids?: string[];
  }>;
}

export interface ScoreExplanation {
  summary: string;
  strongest_dimension: string;
  weakest_dimension: string;
  key_deductions: string[];
  dynamic_verification_summary?: {
    dynamic_confirmed_count: number;
    dynamic_unreproduced_count: number;
    dynamic_contradicted_count: number;
    static_only_count: number;
    dynamic_findings_breakdown: Array<{
      risk_id: string;
      title: string;
      verification_status: RiskVerificationStatus;
      detail: string;
    }>;
  };
  evidence_classes_available?: string[];
  evidence_classes_missing?: string[];
  static_only_conclusions?: string[];
  dynamic_status?: string;
  static_status?: string;
  execution_summary?: {
    executed: string[];
    not_verified: string[];
    why?: string;
    static_only_conclusions: string[];
    evidence_classes_available: string[];
    evidence_classes_missing: string[];
    provider_status?: string;
    actual_provider?: string;
  };
}

export interface ScoreResult {
  score_result_id: string;
  analysis_run_id: string;
  model_key: string;
  model_version: string;
  overall_score: number; // 0.0 to 100.0
  normalized_score: number; // 0.00 to 1.00
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  risk_band: ScoreRiskBand;
  dimension_values: ScoreDimensionValue[];
  explanation: ScoreExplanation;
  calibration_version: string;
  created_at: string;
}

// ==========================================
// 3. POLICY TYPES
// ==========================================

export interface PolicyRuleConfig {
  rule_key: string;
  rule_name: string;
  description: string;
  severity: RiskSeverity;
  is_blocking: boolean; // Hard Block
  condition_type: 
    | 'CRITICAL_RISK_THRESHOLD' 
    | 'CANARY_LEAK' 
    | 'EGRESS_VIOLATION' 
    | 'MIN_SCORE_THRESHOLD' 
    | 'UNCERTAINTY_CONFIDENCE' 
    | 'DIRECT_INJECTION_SINK'
    | 'UNVERIFIED_PACKAGE';
  threshold?: number;
  target_outcome_on_violation: PolicyOutcome;
}

export interface PolicyConfig {
  policy_key: string;
  version: string;
  name: string;
  description: string;
  rules: PolicyRuleConfig[];
  status: 'ACTIVE' | 'DEPRECATED' | 'DRAFT';
}

export interface PolicyDecisionReason {
  reason_id: string;
  rule_key?: string;
  rule_name?: string;
  risk_id?: string;
  reason_text: string;
  is_blocking: boolean;
  severity: RiskSeverity;
  evidence_ids?: string[];
}

export interface PolicyDecision {
  decision_id: string;
  analysis_run_id: string;
  policy_key: string;
  policy_version: string;
  outcome: PolicyOutcome;
  evaluation_summary: string;
  score_override_applied: boolean;
  score_vs_policy_notes?: string;
  reasons: PolicyDecisionReason[];
  blocking_rule_count: number;
  created_at: string;
}

export interface PolicyOverrideRecord {
  override_id: string;
  analysis_run_id: string;
  original_outcome: PolicyOutcome;
  overridden_outcome: PolicyOutcome;
  reason: string;
  justification_details?: string;
  approver_id: string;
  approver_role: string;
  status: 'ACTIVE' | 'SUPERSEDED' | 'REVOKED';
  created_at: string;
}

// ==========================================
// 4. RECOMMENDATIONS TYPES
// ==========================================

export interface RecommendationRecord {
  recommendation_id: string;
  analysis_run_id: string;
  entity_ref_id?: string;
  risk_id?: string;
  recommendation_type: RecommendationType;
  title: string;
  action_steps: string;
  priority: RecommendationPriority;
  effort_estimate: RecommendationEffort;
  evidence_ids: string[];
  created_at: string;
}

export interface RecommendationValidationResult {
  valid: boolean;
  errors: string[];
  recommendationCount: number;
}

// ==========================================
// 5. USE CASE TYPES
// ==========================================

export interface UseCaseDefinition {
  use_case_key: string;
  title: string;
  description: string;
  category: 'POSITIVE' | 'NEGATIVE';
  domain: string;
}

export interface UseCaseEvaluationRecord {
  evaluation_id: string;
  analysis_run_id: string;
  use_case_key: string;
  title: string;
  category: 'POSITIVE' | 'NEGATIVE';
  suitability: UseCaseSuitability;
  suitability_score: number; // 0.0 to 1.0
  justification: string;
  evidence_ids: string[];
  created_at: string;
}

export interface UseCaseProfileConfig {
  profile_key: string;
  version: string;
  name: string;
  required_positive_count: number;
  required_negative_count: number;
  definitions: UseCaseDefinition[];
}

export interface UseCaseValidationResult {
  valid: boolean;
  errors: string[];
  positiveCount: number;
  negativeCount: number;
}

// ==========================================
// 6. SUITE RESULT
// ==========================================

export interface DecisionSuiteResult {
  analysis_run_id: string;
  entity_ref_id?: string;
  risks: RiskRecord[];
  score_result: ScoreResult;
  policy_decision: PolicyDecision;
  active_override?: PolicyOverrideRecord;
  recommendations: RecommendationRecord[];
  use_case_evaluations: UseCaseEvaluationRecord[];
  confidence_score: number;
  duration_ms: number;
  created_at: string;
  static_status?: string;
  dynamic_status?: string;
  overall_status?: string;
  truth_state?: string;
  executed?: string[];
  not_verified?: string[];
  why?: string;
  static_only_conclusions?: string[] | boolean;
  evidence_classes_available?: string[];
  evidence_classes_missing?: string[];
  execution_summary?: {
    executed: string[];
    not_verified: string[];
    why?: string;
    static_only_conclusions: string[];
    evidence_classes_available: string[];
    evidence_classes_missing: string[];
    provider_status?: string;
    actual_provider?: string;
  };
}
