import { z } from 'zod';
import { 
  EvidenceTypeEnum, 
  EvidenceClassEnum, 
  EpistemicStateEnum, 
  ClaimStateEnum, 
  ClaimTypeEnum, 
  FindingSeverityEnum, 
  UncertaintyFactorEnum 
} from './enums.ts';
import { SourceSpanLocatorSchema } from './provenance.ts';

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const uuidSchema = z.string().regex(uuidRegex, 'Invalid UUID');

/**
 * 1. FindingContract (Raw detector / AST pattern match)
 */
export const FindingContractSchema = z.object({
  _contract_type: z.literal('FINDING').default('FINDING'),
  finding_id: uuidSchema,
  analysis_run_id: uuidSchema,
  stage_run_id: uuidSchema.optional(),
  rule_id: z.string().min(1),
  severity: FindingSeverityEnum,
  message: z.string().min(1),
  source_span: SourceSpanLocatorSchema.optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type FindingContract = z.infer<typeof FindingContractSchema>;

/**
 * 2. EvidenceContract (Contextualized, provenance-grounded proof item)
 */
export const EvidenceContractSchema = z.object({
  _contract_type: z.literal('EVIDENCE').default('EVIDENCE'),
  evidence_id: uuidSchema,
  analysis_run_id: uuidSchema,
  scope_id: uuidSchema,
  evidence_type: EvidenceTypeEnum,
  evidence_class: EvidenceClassEnum,
  source_entity_ref_id: uuidSchema.optional(),
  static_finding_id: uuidSchema.optional(),
  runtime_event_id: uuidSchema.optional(),
  description: z.string().min(1),
  confidence: z.number().min(0).max(1).default(1.0),
  weight: z.number().min(0).max(1).default(1.0),
  provenance_id: uuidSchema.optional(),
  observed_payload: z.record(z.string(), z.unknown()).default({}),
});
export type EvidenceContract = z.infer<typeof EvidenceContractSchema>;

/**
 * 3. AssertionContract (Epistemic predicate evaluated from evidence)
 */
export const AssertionContractSchema = z.object({
  _contract_type: z.literal('ASSERTION').default('ASSERTION'),
  assertion_id: uuidSchema,
  analysis_run_id: uuidSchema,
  scope_id: uuidSchema,
  assertion_key: z.string().min(1),
  concept_id: z.string().optional(),
  predicate: z.string().optional(),
  epistemic_state: EpistemicStateEnum,
  evidence_ids: z.array(uuidSchema).default([]),
  confidence: z.number().min(0).max(1),
  uncertainty_score: z.number().min(0).max(1).default(0.0),
  uncertainty_factors: z.array(UncertaintyFactorEnum).default([]),
  engine_key: z.string().min(1),
});
export type AssertionContract = z.infer<typeof AssertionContractSchema>;

/**
 * 4. ClaimContract (High-level posture/safety assertion evaluated from assertions)
 */
export const ClaimContractSchema = z.object({
  _contract_type: z.literal('CLAIM').default('CLAIM'),
  claim_id: uuidSchema,
  analysis_run_id: uuidSchema,
  scope_id: uuidSchema,
  claim_type: ClaimTypeEnum,
  claim_text: z.string().min(1),
  state: ClaimStateEnum,
  assertion_ids: z.array(uuidSchema).default([]),
  confidence: z.number().min(0).max(1),
  uncertainty_score: z.number().min(0).max(1).default(0.0),
});
export type ClaimContract = z.infer<typeof ClaimContractSchema>;
