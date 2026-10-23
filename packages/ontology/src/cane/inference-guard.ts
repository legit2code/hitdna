/**
 * Security-Relevant Inference Guard
 * P14 — Canonicalization & Epistemic Boundaries
 * 
 * CRITICAL INVARIANT:
 * No inference-only concept, capability, permission, or behavioral assertion may EVER
 * escalate to a CONFIRMED, OBSERVED, OBSERVED_RUNTIME, or DECLARED_EXPLICIT state.
 * Inferences must remain strictly quarantined in INFERRED_STATIC or SYNTHESIZED.
 */

import { DeclarationState } from '../../../caim/src/index.ts';

export class SecurityInferenceGuardViolationError extends Error {
  constructor(message: string, public readonly entityId?: string, public readonly attemptedState?: string) {
    super(`[SECURITY INFERENCE GUARD VIOLATION]: ${message}`);
    this.name = 'SecurityInferenceGuardViolationError';
  }
}

export class SecurityInferenceGuard {
  /**
   * Asserts that an inferred entity does not illegally claim direct observation or explicit declaration
   */
  public static assertInferenceStateCompliant(params: {
    entity_id: string;
    entity_kind: string;
    declaration_state?: string;
    epistemic_state?: string;
    has_direct_evidence: boolean;
    is_inferred: boolean;
  }): void {
    const { entity_id, entity_kind, declaration_state, epistemic_state, has_direct_evidence, is_inferred } = params;

    // If it is derived via inference, it CANNOT be OBSERVED_RUNTIME or DECLARED_EXPLICIT
    if (is_inferred && !has_direct_evidence) {
      if (declaration_state === 'OBSERVED_RUNTIME') {
        throw new SecurityInferenceGuardViolationError(
          `Inferred ${entity_kind} '${entity_id}' attempted to claim OBSERVED_RUNTIME state without direct runtime trace proof. Inferred state must be INFERRED_STATIC or SYNTHESIZED.`,
          entity_id,
          declaration_state
        );
      }

      if (declaration_state === 'DECLARED_EXPLICIT') {
        throw new SecurityInferenceGuardViolationError(
          `Inferred ${entity_kind} '${entity_id}' attempted to claim DECLARED_EXPLICIT state without direct manifest/code declaration. Inferred state must be INFERRED_STATIC or SYNTHESIZED.`,
          entity_id,
          declaration_state
        );
      }

      if (epistemic_state === 'epistemic.observed_fact' || epistemic_state === 'CONFIRMED' || epistemic_state === 'OBSERVED') {
        throw new SecurityInferenceGuardViolationError(
          `Inferred concept '${entity_id}' attempted to claim CONFIRMED/OBSERVED epistemic status. Inferred concepts must be epistemic.derived_assertion or epistemic.hypothesis.`,
          entity_id,
          epistemic_state
        );
      }
    }
  }

  /**
   * Sanitizes or coerces declaration state to strictly obey inference boundaries
   */
  public static enforceSafeDeclarationState(
    requestedState: DeclarationState | string,
    hasDirectEvidence: boolean
  ): DeclarationState {
    if (!hasDirectEvidence) {
      if (requestedState === 'OBSERVED_RUNTIME' || requestedState === 'DECLARED_EXPLICIT') {
        return 'INFERRED_STATIC';
      }
    }
    return (requestedState as DeclarationState) || 'INFERRED_STATIC';
  }

  /**
   * Validates all capabilities and permissions in a manifest for inference boundary compliance
   */
  public static validateInferenceBoundaries(
    capabilities: Array<{ capability_id: string; declaration_state: DeclarationState; source_type?: string }>,
    inferredCapabilityIds: Set<string>
  ): { valid: boolean; violations: string[] } {
    const violations: string[] = [];

    for (const cap of capabilities) {
      if (inferredCapabilityIds.has(cap.capability_id)) {
        if (cap.declaration_state === 'DECLARED_EXPLICIT' || cap.declaration_state === 'OBSERVED_RUNTIME') {
          violations.push(
            `Capability ${cap.capability_id} is marked as ${cap.declaration_state} but originates from an inference rule.`
          );
        }
      }
    }

    return {
      valid: violations.length === 0,
      violations,
    };
  }
}
