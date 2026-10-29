/**
 * Epistemic Governance & Truth Validation Engine
 * Engines: PF-04, PF-09, RI-09
 * Architecture Version: 5.0.0 | Phase: P04
 *
 * Implements strict runtime validation enforcing the P00 Master Build Constitution
 * and v6 Evidence/Epistemic Governance Delta:
 * 1. AI-only records cannot masquerade as measured provider values.
 * 2. Model confidence alone CANNOT promote AI-derived records to VERIFIED.
 * 3. Community-dictionary or AI-derived terms cannot become VERIFIED without human review.
 * 4. PatternReferenceExample must be aggregate-measured and containsCopiedMelody must be false.
 * 5. Single-song chord/arrangement sequences cannot be relabeled as aggregate Hit DNA patterns without cohort analysis.
 * 6. Published metrics require frozen cohort denominator > 0, coverage rate, and versioned formula.
 */

import {
  EpistemicState,
  SourceOrigin,
  ProvenanceMetadata,
  StatisticalMetric,
  PatternReferenceExample,
  VernacularTerm,
} from '../contracts/research.js';

export interface PromotionActor {
  actorId: string;
  role: 'ADMIN' | 'RESEARCHER' | 'SYSTEM' | 'AI_AGENT';
  hasHumanReview: boolean;
  hasEmpiricalEvidence: boolean;
  auditNote: string;
}

export class EpistemicGovernanceError extends Error {
  public readonly errorCode: string;
  constructor(message: string, public readonly code: string) {
    super(`[EpistemicGovernanceViolation: ${code}] ${message}`);
    this.name = 'EpistemicGovernanceError';
    this.errorCode = code;
  }
}

/**
 * Validates that an epistemic state transition conforms to truth rules.
 * Rule: Model confidence alone CANNOT promote an AI-derived or inferred record to VERIFIED.
 */
export function validateEpistemicPromotion(
  current: EpistemicState,
  target: EpistemicState,
  actor: PromotionActor,
  provenance: ProvenanceMetadata
): { success: boolean; error?: string } {
  // If target is VERIFIED, strict validation is required
  if (target === 'VERIFIED') {
    // 1. AI Agents or autonomous systems without human/empirical validation cannot verify
    if (actor.role === 'AI_AGENT') {
      throw new EpistemicGovernanceError(
        'Autonomous AI agents cannot promote records to VERIFIED state. Human researcher or empirical multi-source audit is required.',
        'AI_PROMOTION_PROHIBITED'
      );
    }

    // 2. If origin was AI_MODEL, must have explicit human review or empirical cross-source evidence
    if (provenance.sourceOrigin === 'AI_MODEL') {
      if (!actor.hasHumanReview && !actor.hasEmpiricalEvidence) {
        throw new EpistemicGovernanceError(
          'AI-derived records cannot be promoted to VERIFIED based solely on model confidence. Requires qualified human review or multi-source empirical validation.',
          'MODEL_CONFIDENCE_INSUFFICIENT'
        );
      }
    }

    // 3. If origin was COMMUNITY_IMPORT, must have human researcher review
    if (provenance.sourceOrigin === 'COMMUNITY_IMPORT' && !actor.hasHumanReview) {
      throw new EpistemicGovernanceError(
        'Community-imported data cannot be promoted to VERIFIED without verified human researcher vetting.',
        'COMMUNITY_IMPORT_UNVETTED'
      );
    }
  }

  // State cannot jump from CONTRADICTED to VERIFIED directly without resolving the conflict
  if (current === 'CONTRADICTED' && target === 'VERIFIED') {
    throw new EpistemicGovernanceError(
      'Contradicted records must be resolved to RESOLVED_PRIMARY or HUMAN_REVIEWED before verification.',
      'UNRESOLVED_CONTRADICTION'
    );
  }

  return { success: true };
}

/**
 * Validates that source origin and epistemic state are logically compatible.
 * An AI-only record cannot claim to be MEASURED or EXTERNAL_PROVIDER.
 */
export function validateSourceOriginCompatibility(
  sourceOrigin: SourceOrigin,
  epistemicState: EpistemicState
): void {
  if (sourceOrigin === 'AI_MODEL') {
    if (epistemicState === 'MEASURED' || epistemicState === 'SOURCE_REPORTED' || epistemicState === 'OBSERVED') {
      throw new EpistemicGovernanceError(
        `AI origin cannot claim epistemic state ${epistemicState}. Must be AI_DRAFT, AI_CLASSIFIED, INFERRED, or undergo human review.`,
        'AI_ORIGIN_SPOOFING_PROHIBITED'
      );
    }
  }

  if (sourceOrigin === 'COMMUNITY_IMPORT') {
    if (epistemicState === 'MEASURED' || epistemicState === 'VERIFIED') {
      throw new EpistemicGovernanceError(
        `Community imports cannot claim epistemic state ${epistemicState} at ingestion time.`,
        'COMMUNITY_ORIGIN_RESTRICTION'
      );
    }
  }
}

/**
 * Validates a StatisticalMetric according to HD-01 & HD-03 denominator-before-percentage mandate.
 */
export function validateStatisticalMetric(metric: StatisticalMetric): void {
  if (metric.denominator <= 0) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' has invalid denominator: ${metric.denominator}. Must be > 0.`,
      'INVALID_DENOMINATOR'
    );
  }

  if (metric.numerator < 0) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' has negative numerator: ${metric.numerator}.`,
      'NEGATIVE_NUMERATOR'
    );
  }

  if (metric.numerator > metric.denominator) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' numerator (${metric.numerator}) exceeds cohort denominator (${metric.denominator}).`,
      'NUMERATOR_EXCEEDS_DENOMINATOR'
    );
  }

  const expectedValue = metric.numerator / metric.denominator;
  if (Math.abs(metric.value - expectedValue) > 0.0001) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' value (${metric.value}) does not match numerator/denominator (${expectedValue}).`,
      'METRIC_VALUE_MISMATCH'
    );
  }

  const expectedPercentage = expectedValue * 100;
  if (Math.abs(metric.percentage - expectedPercentage) > 0.01) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' percentage (${metric.percentage}) does not match value * 100 (${expectedPercentage}).`,
      'PERCENTAGE_MISMATCH'
    );
  }

  if (metric.coverageCount < 0 || metric.coverageCount > metric.denominator) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' coverageCount (${metric.coverageCount}) is invalid for cohort denominator (${metric.denominator}).`,
      'INVALID_COVERAGE_COUNT'
    );
  }

  if (!metric.formula || metric.formula.trim().length === 0) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' missing required formula specification.`,
      'MISSING_FORMULA'
    );
  }

  if (!metric.calculationVersion || metric.calculationVersion.trim().length === 0) {
    throw new EpistemicGovernanceError(
      `Statistical metric '${metric.metricName}' missing required calculationVersion.`,
      'MISSING_CALCULATION_VERSION'
    );
  }
}

/**
 * Validates PatternReferenceExample according to MI-10 No-Copy Protection Invariant.
 * 1. Must reference aggregate measured patterns/archetypes.
 * 2. containsCopiedMelody must be FALSE.
 * 3. A single-song chord sequence cannot be relabeled as aggregate without cohort analysis.
 */
export function validatePatternReferenceExample(example: PatternReferenceExample): void {
  if (example.containsCopiedMelody) {
    throw new EpistemicGovernanceError(
      `PatternReferenceExample '${example.exampleId}' violates the No-Copy Protection Invariant. Copied melody passages are strictly prohibited.`,
      'COPIED_MELODY_PROHIBITED'
    );
  }

  if (!example.isAggregateMeasured) {
    throw new EpistemicGovernanceError(
      `PatternReferenceExample '${example.exampleId}' is not aggregate measured. Single-song sequences cannot be published as aggregate patterns without cohort analysis.`,
      'NON_AGGREGATE_PATTERN_PROHIBITED'
    );
  }

  if (!example.archetypeId || example.archetypeId.trim().length === 0) {
    throw new EpistemicGovernanceError(
      `PatternReferenceExample '${example.exampleId}' missing aggregate archetype link.`,
      'MISSING_ARCHETYPE_LINK'
    );
  }

  if (!example.abstractTemplate || example.abstractTemplate.trim().length === 0) {
    throw new EpistemicGovernanceError(
      `PatternReferenceExample '${example.exampleId}' missing abstract transposition template.`,
      'MISSING_ABSTRACT_TEMPLATE'
    );
  }
}

/**
 * Validates VernacularTerm review and generation eligibility.
 */
export function validateVernacularTerm(term: VernacularTerm): void {
  // If reviewState is VERIFIED, cannot have sourceOrigin == COMMUNITY_IMPORT without reviewedBy
  if (term.reviewState === 'VERIFIED') {
    if (term.provenance.sourceOrigin === 'COMMUNITY_IMPORT' && !term.provenance.reviewedBy) {
      throw new EpistemicGovernanceError(
        `Vernacular term '${term.term}' from community import cannot be VERIFIED without human reviewer attribution.`,
        'COMMUNITY_TERM_UNVERIFIED'
      );
    }
    if (term.provenance.sourceOrigin === 'AI_MODEL' && !term.provenance.reviewedBy) {
      throw new EpistemicGovernanceError(
        `Vernacular term '${term.term}' inferred by AI model cannot be VERIFIED without human reviewer attribution.`,
        'AI_TERM_UNVERIFIED'
      );
    }
  }

  // Slurs or prohibited terms cannot be generation eligible
  if (term.explicitness === 'SLUR_PROHIBITED' && term.generationEligibility) {
    throw new EpistemicGovernanceError(
      `Vernacular term '${term.term}' marked SLUR_PROHIBITED cannot have generationEligibility: true.`,
      'PROHIBITED_TERM_GENERATION_BLOCKED'
    );
  }
}

/**
 * Validates Creative Output Isolation Invariant (P05 Mandate).
 * Creative outputs (lyrics, sound prompts, generation blueprints, generation records)
 * MUST NEVER be ingested as empirical research evidence or assigned MEASURED/OBSERVED status.
 */
export function validateCreativeIsolation(entity: any): void {
  if (!entity || typeof entity !== 'object') return;

  const isCreative =
    entity.isCreativeOutput === true ||
    entity.epistemicStatus === 'CREATIVE_OUTPUT' ||
    (typeof entity.id === 'string' &&
      (entity.id.startsWith('lyr_') ||
        entity.id.startsWith('sndp_') ||
        entity.id.startsWith('genrec_') ||
        entity.id.startsWith('genreq_') ||
        entity.id.startsWith('songspec_')));

  if (isCreative) {
    throw new EpistemicGovernanceError(
      `Entity '${entity.id || 'anonymous'}' is a creative generation output and CANNOT be ingested as empirical research evidence.`,
      'CREATIVE_EVIDENCE_CONTAMINATION'
    );
  }
}

/**
 * Validates Generation Feedback Invariant (P05 Mandate).
 * Feedback represents user/creator sentiment and can NEVER be promoted into factual empirical research.
 */
export function validateFeedbackIsolation(feedback: any): void {
  if (!feedback || typeof feedback !== 'object') return;

  if (feedback.promotedToResearch === true) {
    throw new EpistemicGovernanceError(
      `Feedback '${feedback.id}' cannot be promoted into factual research. Feedback represents subjective user sentiment, not empirical music research.`,
      'FEEDBACK_PROMOTION_PROHIBITED'
    );
  }
}

/**
 * Validates Suno-Style Sound Prompt Constraints (CG-07 / P05 Mandate).
 * 1. Character count MUST be strictly < 1000 characters.
 * 2. Artist leakage MUST be scrubbed (artistLeakageScrubbed: true).
 */
export function validateSoundPromptConstraints(promptResult: {
  id: string;
  promptText: string;
  artistLeakageScrubbed: boolean;
}): void {
  if (promptResult.promptText.length >= 1000) {
    throw new EpistemicGovernanceError(
      `Sound prompt '${promptResult.id}' exceeds the 1000 character limit (length: ${promptResult.promptText.length}).`,
      'SOUND_PROMPT_LENGTH_EXCEEDED'
    );
  }

  if (!promptResult.artistLeakageScrubbed) {
    throw new EpistemicGovernanceError(
      `Sound prompt '${promptResult.id}' has unverified artist leakage. Real artist names and trademarks must be scrubbed before persistence.`,
      'ARTIST_LEAKAGE_UNSCRUBBED'
    );
  }
}

/**
 * Validates Retention and Versioning Semantics (P05 Mandate).
 * Published snapshots, generation records, and empirical source lineage are IMMUTABLE.
 * Hard purge of immutable records is strictly prohibited; only status: 'ARCHIVED' is permitted.
 */
export function validateRetentionAction(
  entityType: string,
  action: 'ARCHIVE' | 'PURGE',
  entity: { id: string; status?: string; isImmutable?: boolean }
): void {
  if (action === 'PURGE') {
    const isImmutableType =
      entityType === 'DatasetVersion' ||
      entityType === 'GenerationRecord' ||
      entityType === 'SourceRecord' ||
      entityType === 'AnalysisRun' ||
      entityType === 'AuditEvent';

    if (isImmutableType || entity.isImmutable) {
      throw new EpistemicGovernanceError(
        `Cannot purge immutable entity '${entityType}' with ID '${entity.id}'. Published history and source lineage must be preserved. Use ARCHIVE instead.`,
        'IMMUTABLE_RECORD_PURGE_PROHIBITED'
      );
    }
  }
}

