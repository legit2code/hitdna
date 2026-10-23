import { SecurityClassificationCode } from '@caim/auth/types.ts';
import { AssembledContextPackage } from '../context/types.ts';

export type GroundingVerdict =
  | 'FULLY_GROUNDED'
  | 'PARTIALLY_GROUNDED'
  | 'CONTRADICTED'
  | 'UNSUPPORTED'
  | 'NO_EVIDENCE';

export type EpistemicDecision =
  | 'ACCEPT'
  | 'REVISE'
  | 'REMOVE_UNSUPPORTED'
  | 'ABSTAIN';

export type CitationTargetType =
  | 'agent'
  | 'version'
  | 'run'
  | 'claim'
  | 'evidence'
  | 'finding'
  | 'runtime'
  | 'file_line'
  | 'dependency'
  | 'vulnerability'
  | 'policy'
  | 'package';

export interface ResolvedCitation {
  citation_raw: string; // e.g. [citation:vulnerability:CVE-2026-44012]
  target_type: CitationTargetType;
  target_id: string;
  source_locator?: string;
  is_valid: boolean;
  resolved_summary?: string;
  security_classification?: SecurityClassificationCode;
  rejection_reason?: string;
}

export interface DraftClaim {
  claim_index: number;
  statement: string;
  is_substantive: boolean;
  citation_tags: string[];
  grounding_score: number; // 0.0 to 1.0
  supported: boolean;
  contradicted: boolean;
  contradiction_reason?: string;
  supporting_evidence_ids: string[];
  supporting_fact_ids: string[];
}

export interface EvidenceConflict {
  entity_ref_id: string;
  conflict_type: 'SEVERITY' | 'POLICY' | 'CVSS' | 'STATUS';
  conflicting_values: string[];
  description: string;
}

export interface ValidatedFactStatement {
  fact_id: string;
  entity_ref_id: string;
  entity_type: string;
  citation_tag: string;
  statement: string;
  attributes_rendered: Record<string, any>;
}

export interface AnswerAuditRecord {
  audit_id: string;
  timestamp: string;
  model_name: string;
  prompt_version: string;
  context_package_hash: string;
  query: string;
  caller_user_id?: string;
  draft_claims_count: number;
  grounded_claims_count: number;
  unsupported_claims_count: number;
  contradictions_count: number;
  grounding_verdict: GroundingVerdict;
  epistemic_decision: EpistemicDecision;
  total_citations_emitted: number;
  valid_citations_count: number;
  invalid_citations_count: number;
  abstention_reason?: string;
  missing_evidence_count?: number;
  conflicts_count?: number;
  latency_ms: number;
}

export interface SynthesisOutput {
  answer: string;
  raw_draft_answer: string;
  epistemic_decision: EpistemicDecision;
  grounding_verdict: GroundingVerdict;
  abstention: boolean;
  abstention_reason?: string;
  missing_evidence?: string[];
  evidence_conflicts?: EvidenceConflict[];
  canonical_statements?: ValidatedFactStatement[];
  draft_claims: DraftClaim[];
  grounded_claims: DraftClaim[];
  unsupported_claims: DraftClaim[];
  contradicted_claims: DraftClaim[];
  resolved_citations: ResolvedCitation[];
  invalid_citations: ResolvedCitation[];
  context_package: AssembledContextPackage;
  audit: AnswerAuditRecord;
}
