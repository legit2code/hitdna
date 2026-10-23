import { DraftClaim, EpistemicDecision, GroundingVerdict, EvidenceConflict } from './types.ts';
import { AssembledContextPackage } from '../context/types.ts';

export class EpistemicDecisionEngine {
  public static readonly ABSTENTION_MESSAGE =
    'I do not have sufficient authorized evidence to answer this inquiry based on verified platform knowledge.';

  /**
   * Identifies specific missing evidence required by the inquiry or claims.
   * INVARIANT: Never fill gaps with assumed or fabricated security narratives.
   */
  public static identifyMissingEvidence(
    query: string,
    contextPackage: AssembledContextPackage,
    unsupportedClaims: DraftClaim[],
    conflicts: EvidenceConflict[] = []
  ): string[] {
    const missing: string[] = [];
    const queryLower = (query || '').toLowerCase();

    // 1. If context has zero facts
    if (!contextPackage || contextPackage.serialized_facts.length === 0) {
      missing.push('No authorized knowledge objects or records found in context matching inquiry topic.');
      return missing;
    }

    // 2. Conflicting evidence
    for (const conflict of conflicts) {
      missing.push(
        `Authoritative resolution required for conflicting evidence on entity '${conflict.entity_ref_id}' (${conflict.conflicting_values.join(' vs ')}).`
      );
    }

    // 3. Inspect unsupported claims for specific missing evidence
    for (const claim of unsupportedClaims) {
      const stmtLower = claim.statement.toLowerCase();
      if (/\bcvss\b/i.test(stmtLower)) {
        missing.push(`Verified CVSS score not present in authoritative evidence for target entity.`);
      }
      if (/\b(exec|spawn|sink|shell execution|rce|remote code execution)\b/i.test(stmtLower)) {
        missing.push(`Verified reachable command sink (exec/spawn) or taint execution flow not recorded in context.`);
      }
      if (/\b(policy|gate|deployment)\b/i.test(stmtLower)) {
        missing.push(`Verified policy evaluation record not recorded in context.`);
      }
      if (/\b(critical|high severity)\b/i.test(stmtLower)) {
        missing.push(`Authoritative finding record supporting CRITICAL/HIGH severity classification.`);
      }
    }

    // 4. Query entity check
    const entityMatch = queryLower.match(/\b(agent-[a-z0-9_-]+|cve-[0-9]{4}-[0-9]+)\b/i);
    if (entityMatch) {
      const entityId = entityMatch[1];
      const hasFact = contextPackage.serialized_facts.some(
        (f) =>
          f.entity_ref_id.toLowerCase() === entityId.toLowerCase() ||
          f.agent_id?.toLowerCase() === entityId.toLowerCase()
      );
      if (!hasFact) {
        missing.push(`Authoritative knowledge objects or security analysis runs for target entity '${entityId}'.`);
      }
    }

    if (missing.length === 0) {
      missing.push('Verified authoritative evidence supporting requested security assertions.');
    }

    return Array.from(new Set(missing));
  }

  /**
   * Evaluates the grounding results and decides whether to accept, revise, strip unsupported claims, or abstain.
   */
  public static evaluateDecision(
    rawDraft: string,
    claims: DraftClaim[],
    groundingVerdict: GroundingVerdict,
    contextPackage: AssembledContextPackage,
    options?: {
      query?: string;
      contradictionReason?: string;
      evidenceConflicts?: EvidenceConflict[];
    }
  ): {
    decision: EpistemicDecision;
    finalAnswer: string;
    abstentionReason?: string;
    missingEvidence: string[];
    evidenceConflicts: EvidenceConflict[];
  } {
    const conflicts = options?.evidenceConflicts || [];
    const unsupportedClaims = claims.filter((c) => !c.supported);

    // 1. If no evidence was retrieved in the context package -> ABSTAIN
    if (contextPackage.serialized_facts.length === 0 || groundingVerdict === 'NO_EVIDENCE') {
      const missingEvidence = this.identifyMissingEvidence(options?.query || '', contextPackage, unsupportedClaims, conflicts);
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: `Insufficient evidence: Zero authorized facts or evidence available in context for this query. Missing evidence: ${missingEvidence.join('; ')}`,
        missingEvidence,
        evidenceConflicts: conflicts,
      };
    }

    // 2. If severe contradiction or evidence conflict detected -> ABSTAIN and SURFACE CONFLICT
    if (groundingVerdict === 'CONTRADICTED') {
      const missingEvidence = this.identifyMissingEvidence(options?.query || '', contextPackage, unsupportedClaims, conflicts);
      let conflictSurfacing = options?.contradictionReason;
      if (!conflictSurfacing && conflicts.length > 0) {
        conflictSurfacing = conflicts.map((c) => c.description).join(' ');
      }

      let answer = this.ABSTENTION_MESSAGE;
      if (conflicts.length > 0) {
        answer = `I do not have sufficient authorized evidence to answer this inquiry. Evidence conflict detected: ${conflicts.map((c) => c.description).join(' ')} Factual determination cannot be made without resolving conflicting evidence.`;
      }

      return {
        decision: 'ABSTAIN',
        finalAnswer: answer,
        abstentionReason: `Insufficient evidence: ${conflictSurfacing || 'Draft answer contains factual assertions that contradict verified platform findings.'}`,
        missingEvidence,
        evidenceConflicts: conflicts,
      };
    }

    // 3. If all claims are unsupported -> ABSTAIN
    if (groundingVerdict === 'UNSUPPORTED') {
      const missingEvidence = this.identifyMissingEvidence(options?.query || '', contextPackage, unsupportedClaims, conflicts);
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: `Insufficient evidence: None of the substantive claims in the draft answer could be grounded in context. Missing evidence: ${missingEvidence.join('; ')}`,
        missingEvidence,
        evidenceConflicts: conflicts,
      };
    }

    // 4. If fully grounded -> ACCEPT
    if (groundingVerdict === 'FULLY_GROUNDED') {
      return {
        decision: 'ACCEPT',
        finalAnswer: rawDraft,
        missingEvidence: [],
        evidenceConflicts: [],
      };
    }

    // 5. Partially Grounded -> REMOVE_UNSUPPORTED
    const supportedSentences: string[] = [];

    // Reconstruct answer containing ONLY supported claims
    for (const claim of claims) {
      if (claim.supported) {
        let stmt = claim.statement;
        if (claim.citation_tags.length > 0) {
          stmt = `${stmt} ${claim.citation_tags.join(' ')}`;
        }
        supportedSentences.push(stmt);
      }
    }

    if (supportedSentences.length === 0) {
      const missingEvidence = this.identifyMissingEvidence(options?.query || '', contextPackage, unsupportedClaims, conflicts);
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: `Insufficient evidence: No grounded substantive statements remained after unsupported claim removal. Missing evidence: ${missingEvidence.join('; ')}`,
        missingEvidence,
        evidenceConflicts: conflicts,
      };
    }

    const revisedAnswer = supportedSentences.join(' ');

    return {
      decision: 'REMOVE_UNSUPPORTED',
      finalAnswer: revisedAnswer,
      abstentionReason: undefined,
      missingEvidence: this.identifyMissingEvidence(options?.query || '', contextPackage, unsupportedClaims, conflicts),
      evidenceConflicts: conflicts,
    };
  }
}
