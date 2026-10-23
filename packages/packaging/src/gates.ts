import { PolicyOutcome } from '../../contracts/src/index.ts';
import { 
  PolicyGateResult, 
  ShippingGateResult, 
  ApprovalReference, 
  ValidationReference, 
  PolicyReference, 
  SignedPackageBundle, 
  ShippingTargetType 
} from './types.ts';
import { SignatureVerifier } from './crypto/verifier.ts';

/**
 * Packaging & Shipping Policy Gates (Architecture V2.0.1)
 */

export interface PreSigningGateInput {
  agentStatus?: string;
  validationReference: ValidationReference;
  policyReference: PolicyReference;
  approvalReferences: ApprovalReference[];
  requireTwoPersonApproval?: boolean;
}

export class PackagingPolicyGate {
  /**
   * Evaluates if a package is eligible for cryptographic signing.
   */
  static evaluatePreSigningGate(input: PreSigningGateInput): PolicyGateResult {
    const blockers: string[] = [];
    const reasons: string[] = [];

    // 1. Check Policy Outcome
    const disallowedOutcomes: PolicyOutcome[] = ['DENY_SHIPPING', 'QUARANTINE', 'RESTRICT'];
    if (disallowedOutcomes.includes(input.policyReference.policy_outcome as PolicyOutcome)) {
      if (!input.policyReference.override_id) {
        blockers.push(`Policy outcome is ${input.policyReference.policy_outcome} without an active audited override`);
      } else {
        reasons.push(`Policy outcome ${input.policyReference.policy_outcome} permitted via audited override ${input.policyReference.override_id}`);
      }
    } else {
      reasons.push(`Policy outcome is compliant: ${input.policyReference.policy_outcome}`);
    }

    if (!input.policyReference.policy_allowed && !input.policyReference.override_id) {
      blockers.push('Policy reference policy_allowed is false');
    }

    // 2. Check Validation Run
    if (input.validationReference.status !== 'PASSED') {
      blockers.push(`Validation run status is ${input.validationReference.status} (must be PASSED)`);
    } else {
      reasons.push('Validation run status is PASSED');
    }

    if (input.validationReference.verdict === 'REJECTED_REGRESSION') {
      blockers.push('Validation run rejected release due to regression');
    }

    // 3. Two-Person Approvals Check
    const requireTwoPerson = input.requireTwoPersonApproval !== false;
    const validApprovals = input.approvalReferences.filter((a) => a.decision === 'APPROVED');
    
    // Check distinct approver IDs
    const distinctApprovers = new Set(validApprovals.map((a) => a.approver_id));

    if (requireTwoPerson) {
      if (distinctApprovers.size < 2) {
        blockers.push(
          `Two-person security sign-off required: found ${distinctApprovers.size} distinct approved sign-off(s), expected at least 2`
        );
      } else {
        reasons.push(`Two-person security sign-off satisfied (${distinctApprovers.size} approvers)`);
      }
    } else if (distinctApprovers.size < 1) {
      blockers.push('At least one approval is required');
    }

    // 4. Agent Status
    if (input.agentStatus && ['DISCARDED', 'QUARANTINE', 'REJECTED'].includes(input.agentStatus)) {
      blockers.push(`Agent status is ${input.agentStatus} (ineligible for release)`);
    }

    const allowed = blockers.length === 0;

    return {
      allowed,
      gate_name: 'PRE_SIGNING_POLICY_GATE',
      reasons,
      blockers,
      evaluated_at: new Date().toISOString(),
    };
  }

  /**
   * Evaluates if a signed package is eligible for shipping to the target destination.
   */
  static evaluatePreShippingGate(
    bundle: SignedPackageBundle,
    targetType: ShippingTargetType,
    trustedPublicKeyPem?: string
  ): ShippingGateResult {
    const blockers: string[] = [];
    const reasons: string[] = [];

    if (!bundle) {
      return {
        allowed: false,
        target_type: targetType,
        reasons: [],
        blockers: ['Package bundle is null or undefined'],
        signature_valid: false,
        evaluated_at: new Date().toISOString(),
      };
    }

    if (!bundle.manifest) {
      blockers.push('Missing package manifest');
    }
    if (!bundle.signature) {
      blockers.push('Missing cryptographic signature');
    }
    if (!bundle.attestation) {
      blockers.push('Missing release attestation');
    }

    // 1. Verify bundle cryptographic integrity
    const verification = SignatureVerifier.verifyBundle(bundle, trustedPublicKeyPem);
    const signatureValid = verification.valid && !verification.tampered;

    if (!signatureValid) {
      blockers.push('Cryptographic signature verification or content tamper check failed');
      blockers.push(...verification.errors);
    } else {
      reasons.push('Cryptographic signature and all content hashes verified intact');
    }

    // 2. Check manifest policy reference
    if (bundle.manifest?.policy_reference) {
      if (bundle.manifest.policy_reference.policy_outcome === 'DENY_SHIPPING' && !bundle.manifest.policy_reference.override_id) {
        blockers.push('Manifest declares DENY_SHIPPING policy outcome');
      }
      if (bundle.manifest.policy_reference.policy_allowed === false && !bundle.manifest.policy_reference.override_id) {
        blockers.push('Manifest policy reference policy_allowed is false');
      }
    } else if (bundle.manifest) {
      blockers.push('Manifest missing policy reference');
    }

    // 3. Check manifest validation reference
    if (bundle.manifest?.validation_reference) {
      if (bundle.manifest.validation_reference.status !== 'PASSED') {
        blockers.push(`Manifest validation status is ${bundle.manifest.validation_reference.status}`);
      }
      if (bundle.manifest.validation_reference.verdict === 'REJECTED_REGRESSION') {
        blockers.push('Manifest validation verdict indicates regression');
      }
    } else if (bundle.manifest) {
      blockers.push('Manifest missing validation reference');
    }

    // 4. Check attestation verification & verdict
    if (bundle.attestation) {
      const pred = bundle.attestation.predicate;
      if (!pred) {
        blockers.push('Attestation missing predicate definition');
      } else {
        const valSummary = pred.validation_summary || {};
        const verdict = valSummary.verdict || (bundle.attestation as any).verdict;
        if (verdict && verdict !== 'APPROVED_FOR_RELEASE') {
          blockers.push(`Attestation verdict is ${verdict}, expected APPROVED_FOR_RELEASE`);
        }
      }
    }

    const allowed = blockers.length === 0 && signatureValid;

    return {
      allowed,
      target_type: targetType,
      reasons,
      blockers,
      signature_valid: signatureValid,
      evaluated_at: new Date().toISOString(),
    };
  }
}
