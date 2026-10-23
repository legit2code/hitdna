import { FindingContract, EvidenceContract, AssertionContract, ClaimContract } from './epistemic.ts';
import { EvidenceClassEnum, EpistemicStateEnum } from './enums.ts';

export class InvariantViolationError extends Error {
  constructor(message: string) {
    super(`Invariant Violation: ${message}`);
    this.name = 'InvariantViolationError';
  }
}

export class EpistemicTransitionError extends Error {
  constructor(message: string) {
    super(`Epistemic Invariant Transition Error: ${message}`);
    this.name = 'EpistemicTransitionError';
  }
}

/**
 * 1. Invariant: AgentVersion != AnalysisRun
 */
export function assertAgentVersionNotAnalysisRun(obj: unknown): void {
  if (!obj || typeof obj !== 'object') return;
  const record = obj as Record<string, unknown>;

  // Check for conflation
  if (record._entity_kind === 'AGENT_VERSION' && 'analysis_run_id' in record) {
    throw new InvariantViolationError(
      'AgentVersion cannot contain analysis_run_id; AgentVersion is content identity, while AnalysisRun is execution state'
    );
  }

  if (record._entity_kind === 'ANALYSIS_RUN' && !('analysis_run_id' in record)) {
    throw new InvariantViolationError(
      'AnalysisRun must have analysis_run_id'
    );
  }
}

/**
 * 2. Invariant: Finding != Evidence != Assertion != Claim
 */
export function assertDistinctIntelligenceHierarchy(obj: unknown): void {
  if (!obj || typeof obj !== 'object') return;
  const record = obj as Record<string, unknown>;
  const contractType = record._contract_type;

  if (contractType === 'FINDING') {
    if ('evidence_class' in record || 'epistemic_state' in record || 'assertion_ids' in record) {
      throw new InvariantViolationError(
        'Finding cannot contain higher-order Evidence, Assertion, or Claim attributes'
      );
    }
  }

  if (contractType === 'EVIDENCE') {
    if ('assertion_ids' in record || 'claim_type' in record) {
      throw new InvariantViolationError(
        'Evidence cannot contain Assertion or Claim attributes'
      );
    }
    if (!('evidence_class' in record) || !('evidence_type' in record)) {
      throw new InvariantViolationError(
        'Evidence must specify evidence_class and evidence_type'
      );
    }
  }

  if (contractType === 'ASSERTION') {
    if ('severity' in record || 'source_span' in record) {
      throw new InvariantViolationError(
        'Assertion cannot contain raw Finding attributes'
      );
    }
    if (!('epistemic_state' in record)) {
      throw new InvariantViolationError(
        'Assertion must specify epistemic_state'
      );
    }
  }

  if (contractType === 'CLAIM') {
    if ('evidence_class' in record || 'rule_id' in record) {
      throw new InvariantViolationError(
        'Claim cannot contain raw Evidence or Finding attributes'
      );
    }
    if (!('state' in record) || !('claim_type' in record)) {
      throw new InvariantViolationError(
        'Claim must specify state and claim_type'
      );
    }
  }
}

/**
 * 3. Invariant: Inferred state cannot deserialize as observed without evidence class change
 * 
 * Specifically:
 * - If source/antecedent has derived/inferred class ('DERIVED_INFERENCE', 'HEURISTIC_ESTIMATE') or derived epistemic state ('DERIVED_ASSERTION', 'HYPOTHESIS'),
 * - It CANNOT be deserialized as direct observation ('OBSERVED_FACT', 'DIRECT_OBSERVATION', 'DYNAMIC_TRACE') without an explicit attested evidence class promotion and provenance record.
 */
export function deserializeEpistemicState(payload: {
  intended_epistemic_state: string;
  source_evidence_class: string;
  has_direct_observation_proof: boolean;
}): string {
  const isInferredClass = ['DERIVED_INFERENCE', 'HEURISTIC_ESTIMATE'].includes(payload.source_evidence_class);
  const isObservedTarget = ['OBSERVED_FACT'].includes(payload.intended_epistemic_state);

  if (isInferredClass && isObservedTarget && !payload.has_direct_observation_proof) {
    throw new EpistemicTransitionError(
      `Cannot deserialize inferred/derived evidence (${payload.source_evidence_class}) as OBSERVED_FACT without direct empirical observation proof`
    );
  }

  return payload.intended_epistemic_state;
}
