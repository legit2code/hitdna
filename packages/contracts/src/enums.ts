import { z } from 'zod';

/**
 * Evidence & Epistemic Controlled Enums (Architecture V2.0.1)
 */

export const EvidenceTypeEnum = z.enum([
  'STATIC_CODE',
  'AST_MATCH',
  'DYNAMIC_CALL',
  'METADATA_MANIFEST',
  'EXTERNAL_INTEL',
  'HEURISTIC',
]);
export type EvidenceType = z.infer<typeof EvidenceTypeEnum>;

export const EvidenceClassEnum = z.enum([
  'DIRECT_OBSERVATION',
  'STRUCTURAL_EXTRACTION',
  'DYNAMIC_TRACE',
  'DERIVED_INFERENCE',
  'HEURISTIC_ESTIMATE',
  'EXTERNAL_FEED',
]);
export type EvidenceClass = z.infer<typeof EvidenceClassEnum>;

export const EpistemicStateEnum = z.enum([
  'OBSERVED_FACT',
  'DERIVED_ASSERTION',
  'HYPOTHESIS',
  'CONTRADICTED',
  'DISPROVEN',
  'UNKNOWN',
]);
export type EpistemicState = z.infer<typeof EpistemicStateEnum>;

export const ClaimStateEnum = z.enum([
  'SUPPORTED',
  'CONTESTED',
  'REFUTED',
  'UNVERIFIED',
]);
export type ClaimState = z.infer<typeof ClaimStateEnum>;

export const ClaimTypeEnum = z.enum([
  'SECURITY_POSTURE',
  'CAPABILITY',
  'COMPLIANCE',
  'BEHAVIORAL_SAFETY',
  'DATA_INTEGRITY',
  'SUPPLY_CHAIN',
]);
export type ClaimType = z.infer<typeof ClaimTypeEnum>;

export const FindingSeverityEnum = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFORMATIONAL',
]);
export type FindingSeverity = z.infer<typeof FindingSeverityEnum>;

export const UncertaintyFactorEnum = z.enum([
  'MISSING_SOURCE',
  'DYNAMIC_DISPATCH',
  'HEURISTIC_WEIGHT',
  'STALE_INTEL',
  'AMBIGUOUS_SPEC',
  'UNVERIFIED_ECOSYSTEM',
]);
export type UncertaintyFactor = z.infer<typeof UncertaintyFactorEnum>;

export const SecurityClassificationEnum = z.enum([
  'PUBLIC_METADATA',
  'INTERNAL',
  'SENSITIVE',
  'VAULT_RESTRICTED',
]);
export type SecurityClassification = z.infer<typeof SecurityClassificationEnum>;

/**
 * P21 — Risk, Scoring, Policy Outcomes, Recommendations & Use Cases
 */
export const PolicyOutcomeEnum = z.enum([
  'ALLOW',
  'ALLOW_WITH_WARNING',
  'REQUIRE_REVIEW',
  'RESTRICT',
  'QUARANTINE',
  'DENY_SHIPPING',
]);
export type PolicyOutcome = z.infer<typeof PolicyOutcomeEnum>;

export const RiskSeverityEnum = z.enum([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFORMATIONAL',
]);
export type RiskSeverity = z.infer<typeof RiskSeverityEnum>;

export const ScoreRiskBandEnum = z.enum([
  'MINIMAL',
  'LOW',
  'MODERATE',
  'ELEVATED',
  'SEVERE',
]);
export type ScoreRiskBand = z.infer<typeof ScoreRiskBandEnum>;

export const RecommendationPriorityEnum = z.enum([
  'P0',
  'P1',
  'P2',
  'P3',
]);
export type RecommendationPriority = z.infer<typeof RecommendationPriorityEnum>;

export const RecommendationEffortEnum = z.enum([
  'LOW',
  'MEDIUM',
  'HIGH',
]);
export type RecommendationEffort = z.infer<typeof RecommendationEffortEnum>;

export const RecommendationTypeEnum = z.enum([
  'REMEDIATION',
  'MITIGATION',
  'HARDENING',
  'GOVERNANCE',
]);
export type RecommendationType = z.infer<typeof RecommendationTypeEnum>;

export const UseCaseSuitabilityEnum = z.enum([
  'APPROVED',
  'CONDITIONALLY_APPROVED',
  'DISAPPROVED',
  'UNKNOWN',
]);
export type UseCaseSuitability = z.infer<typeof UseCaseSuitabilityEnum>;
