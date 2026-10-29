/**
 * Research, Evidence, Epistemic States & Music Pattern Intelligence Contracts
 * Engines: PF-04 (Canonical Music Data Model & Repository Engine)
 *          PF-09 (Version, Prompt & Methodology Governance)
 *          RI-09 (Rights, Licensing & Source Policy Engine)
 * Architecture Version: 5.0.0 | Phase: P04
 *
 * Mandatory Truth & Epistemic Invariants:
 * 1. Source origin and epistemic status are persisted separately.
 * 2. AI-derived fields must NEVER overwrite original measured/source-reported state.
 * 3. Epistemic state promotion to VERIFIED requires human review or reproducible empirical validation.
 * 4. Model confidence alone cannot promote AI-derived records to VERIFIED.
 * 5. Published metrics require explicit numerator, denominator, formula, coverage, and immutable cohort lineage.
 * 6. Abstract pattern references contain non-melodic transposable blueprints only — zero copied melodies.
 */

import { StorageReference } from './persistence.js';

// ============================================================================
// 1. Epistemic States & Provenance Contracts (v6 Delta)
// ============================================================================

export type EpistemicState =
  | 'OBSERVED'          // Raw external signal recorded directly from source provider
  | 'MEASURED'          // Quantitatively computed by deterministic code/analyzer
  | 'DERIVED'           // Deterministically transformed from validated observations
  | 'SOURCE_REPORTED'   // Reported by third-party authority without internal measurement
  | 'AI_DRAFT'          // Initial model generation or hypothesis
  | 'AI_CLASSIFIED'     // Model-inferred classification or tag
  | 'INFERRED'          // Statistically extrapolated or heuristic inference
  | 'HUMAN_REVIEWED'    // Vetted by qualified musicologist or human researcher
  | 'VERIFIED'          // Ground-truth verified through multi-source or formal audit
  | 'CONTRADICTED'      // Disputed or conflicted by competing observations
  | 'UNRESOLVED'        // Awaiting resolution or further observation
  | 'NOT_AVAILABLE';    // Explicitly unmeasured or unavailable (never defaulted to 0 or null-guess)

export type SourceOrigin =
  | 'EXTERNAL_PROVIDER' // Spotify, Billboard, Genius, Soundcharts, etc.
  | 'INTERNAL_EXTRACTOR'// Deterministic audio/harmonic/rhythmic extractor
  | 'HUMAN_RESEARCHER'  // Internal curator or musicologist
  | 'AI_MODEL'          // Gemini or external LLM/inference model
  | 'AGGREGATE_CALCULATION' // Statistical cohort pipeline
  | 'COMMUNITY_IMPORT'; // External dictionary or community dataset (non-authoritative)

export interface ProvenanceMetadata {
  sourceOrigin: SourceOrigin;
  sourceProviderId?: string;
  sourceRecordId?: string;
  epistemicState: EpistemicState;
  observedAt: string; // UTC ISO-8601
  capturedBy: string; // Actor ID or Engine ID
  methodologyVersion?: string;
  taxonomyVersion?: string;
  confidence: number; // 0.0 to 1.0
  reviewNotes?: string;
  reviewedBy?: string;
  reviewedAt?: string;
}

// ============================================================================
// 2. Normalized Music Feature Observation Schemas
// ============================================================================

export interface AudioFeatureObservation {
  observationId: string; // afo_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  key: string;           // e.g. "C", "F#", "Bb"
  scaleMode: 'MAJOR' | 'MINOR' | 'DORIAN' | 'MIXOLYDIAN' | 'PENTATONIC' | 'OTHER';
  tempoBpm: number;
  dynamicRangeDb: number | null;
  loudnessLufs: number | null;
  acousticness: number | null; // 0.0 - 1.0
  energy: number | null;       // 0.0 - 1.0
  danceability: number | null; // 0.0 - 1.0
  valence: number | null;      // 0.0 - 1.0
  instrumentalness: number | null;
  durationMs: number;
  stemStorageRef?: StorageReference | null;
  spectrogramStorageRef?: StorageReference | null;
  provenance: ProvenanceMetadata;
}

export type SectionType =
  | 'INTRO'
  | 'VERSE'
  | 'PRE_CHORUS'
  | 'CHORUS'
  | 'POST_CHORUS'
  | 'BRIDGE'
  | 'HOOK'
  | 'DROP'
  | 'SOLO'
  | 'OUTRO';

export interface SectionStructure {
  sectionIndex: number;
  sectionType: SectionType;
  startMs: number;
  endMs: number;
  durationMs: number;
  barsCount: number | null;
  energyLiftPercent: number | null;
}

export interface StructureFeatureObservation {
  observationId: string; // sfo_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  sections: SectionStructure[];
  totalDurationMs: number;
  introDurationMs: number;
  outroDurationMs: number;
  outroFadeout: boolean;
  timeToFirstHookMs: number | null;
  chorusCount: number;
  verseCount: number;
  bridgePresent: boolean;
  postChorusPresent: boolean;
  provenance: ProvenanceMetadata;
}

export interface HookFeatureObservation {
  observationId: string; // hfo_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  hookCount: number;
  primaryHookSectionIndex: number | null;
  timeToFirstHookMs: number;
  hookDurationMs: number;
  hookRecurrenceCount: number;
  titleInHook: boolean;
  hookRepetitionFactor: number; // Repetitions of key phrase within hook
  hookSalienceScore: number | null; // 0.0 - 1.0 measured
  provenance: ProvenanceMetadata;
}

export interface RhythmGrooveObservation {
  observationId: string; // rgo_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  primaryTimeSignature: '4/4' | '3/4' | '6/8' | '12/8' | 'OTHER';
  tempoBpm: number;
  grooveDescriptor: string; // e.g. "Straight 16th Trap", "Four-on-the-floor", "Boom-Bap Swing"
  syncopationIndex: number; // 0.0 to 1.0
  swingRatioPercent: number; // e.g. 50% = straight, 66% = triplet swing
  kickPattern16Grid: boolean[]; // 16 steps
  snarePattern16Grid: boolean[]; // 16 steps
  vocalDensitySyllablesPerSec: number | null;
  provenance: ProvenanceMetadata;
}

export interface ArrangementSectionDetail {
  sectionType: SectionType;
  instrumentTrackCount: number;
  hasDrums: boolean;
  hasBass: boolean;
  hasLeadVocal: boolean;
  hasBackingVocal: boolean;
  hasAcousticElements: boolean;
  hasSynth808: boolean;
  rmsLevelDb: number | null;
}

export interface ProductionArrangementObservation {
  observationId: string; // pao_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  arrangementSections: ArrangementSectionDetail[];
  dropCount: number;
  dropTimestampsMs: number[];
  subBass808Present: boolean;
  bass808DecayMs: number | null;
  vocalLayerCountMax: number;
  stereoWidthProfile: 'NARROW' | 'BALANCED' | 'WIDE' | 'IMMERSIVE';
  dynamicContrastDb: number;
  provenance: ProvenanceMetadata;
}

export interface LyricThemeObservation {
  observationId: string; // lto_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  lyricsStorageRef?: StorageReference | null;
  language: string; // e.g. "en", "es", "ko"
  explicitContent: boolean;
  primaryThemes: string[]; // e.g. ["HEARTBREAK", "TRIUMPH", "NARRATIVE_STORY"]
  narrativePerspective: 'FIRST_PERSON' | 'SECOND_PERSON' | 'THIRD_PERSON_OMNISCIENT';
  emotionalTone: string;
  lineCount: number;
  uniqueWordCount: number;
  rhymeSchemeSummary: string; // e.g. "AABB / ABAB"
  provenance: ProvenanceMetadata;
}

export interface ChordEvent {
  chordIndex: number;
  root: string;       // e.g. "C", "F#", "Bb"
  quality: string;    // e.g. "maj", "min", "7", "maj7", "min7", "dim", "sus4"
  romanNumeral: string; // e.g. "I", "vi", "IV", "V"
  durationBeats: number;
  bassNote: string | null;
}

export interface ChordHarmonicObservation {
  observationId: string; // cho_...
  songId: string;
  sourceRecordId: string;
  analysisRunId?: string;
  primaryKey: string;
  primaryMode: 'MAJOR' | 'MINOR' | 'MODAL';
  harmonicPaceBarsPerChord: number;
  chordProgression: ChordEvent[];
  cadenceTypes: string[]; // e.g. ["PERFECT_AUTHENTIC", "DECEPTIVE", "PLAGAL"]
  borrowedChordsPresent: boolean;
  provenance: ProvenanceMetadata;
}

// Canonical fact observation for undisputed musicological facts (release date, composer, publisher)
export interface CanonicalFactObservation {
  factId: string; // cfo_...
  songId: string;
  factType: 'RELEASE_DATE' | 'ISRC' | 'PRODUCER' | 'SONGWRITER' | 'PUBLISHER' | 'RECORD_LABEL';
  factValue: string;
  citationRef: string;
  provenance: ProvenanceMetadata;
}

// ============================================================================
// 3. Modern Language, Slang & Vernacular Intelligence (MI-08 / CG-02)
// ============================================================================

export type VernacularTrajectory =
  | 'EMERGING'
  | 'PEAK'
  | 'STABLE'
  | 'OBSOLETE';

export type VernacularReviewState =
  | 'PROVISIONAL'
  | 'HUMAN_REVIEWED'
  | 'VERIFIED'
  | 'REJECTED';

export type ExplicitnessRating =
  | 'CLEAN'
  | 'EXPLICIT'
  | 'SLUR_PROHIBITED';

export interface VernacularTerm {
  termId: string; // vt_...
  term: string; // The canonical word or phrase (e.g. "no cap", "locked in")
  canonicalMeaning: string;
  regionSceneContext: string[]; // e.g. ["Atlanta Trap", "UK Drill", "Internet Subculture"]
  genreContext: string[]; // e.g. ["gn_root_hip_hop"]
  firstObservedDate: string; // ISO-8601 Date
  lastObservedDate: string; // ISO-8601 Date
  trajectory: VernacularTrajectory;
  frequencyPerMillionWords: number | null; // Null unless empirically measured across corpus
  authoritySource: string; // e.g. "Curated Lexicon Corpus v5"
  reviewState: VernacularReviewState;
  generationEligibility: boolean; // Allowed in creative lyric brief
  explicitness: ExplicitnessRating;
  provenance: ProvenanceMetadata;
  createdAt: string;
  updatedAt: string;
}

export interface VernacularObservation {
  observationId: string; // vto_...
  termId: string;
  sourceRecordId: string;
  sourceType: 'LYRICS_ANNOTATION' | 'ARTIST_INTERVIEWS' | 'CULTURAL_COMMENTARY' | 'REVIEWED_LEXICON';
  songId: string | null;
  sentenceContext: string;
  confidence: number;
  provenance: ProvenanceMetadata;
}

export interface LanguageSourceRecord {
  sourceRecordId: string; // lsr_...
  sourceType: string;
  authorityRating: number; // 1 to 5
  urlOrCitation: string;
  permittedSource: boolean; // Must pass RI-09 rights policy
  recordedAt: string;
}

export interface LanguageSignal {
  signalId: string; // lsig_...
  termId: string;
  timeWindow: string; // e.g. "2026-Q1"
  occurrenceCount: number;
  velocity: number; // Rate of trajectory change
  genreContext: string;
  analysisRunId: string;
  provenance: ProvenanceMetadata;
}

export interface LanguageSnapshot {
  snapshotId: string; // lsnap_...
  snapshotDate: string;
  terms: Array<{
    termId: string;
    term: string;
    trajectory: VernacularTrajectory;
    frequencyPerMillion: number | null;
  }>;
  analysisRunId: string;
  methodologyVersion: string;
  provenance: ProvenanceMetadata;
}

export interface KeywordSignal {
  keywordId: string; // kws_...
  keyword: string;
  associatedGenres: string[];
  salienceWeight: number; // 0.0 - 1.0
  generationApproved: boolean;
  provenance: ProvenanceMetadata;
}

// ============================================================================
// 4. Musical Pattern Intelligence & Safe Abstraction (MI-09 / MI-10)
// ============================================================================

export interface ChordProgressionPattern {
  patternId: string; // cpp_...
  progressionName: string; // e.g. "Axis Progression", "Doo-Wop Progression"
  romanNumerals: string[]; // e.g. ["I", "V", "vi", "IV"]
  harmonicRhythm: string; // e.g. "1 bar per chord"
  cadence: string;
  extractorVersion: string;
  methodologyVersion: string;
  provenance: ProvenanceMetadata;
}

export interface GroovePattern {
  grooveId: string; // gp_...
  name: string;
  timeSignature: '4/4' | '3/4' | '6/8';
  swingPercent: number;
  gridResolution: string; // "1/16"
  kickGrid: boolean[];
  snareGrid: boolean[];
  hiHatGrid: boolean[];
  extractorVersion: string;
  provenance: ProvenanceMetadata;
}

export interface ArrangementPattern {
  arrangementId: string; // ap_...
  name: string; // e.g. "Standard Modern Pop Radio Format"
  sectionSequence: SectionType[];
  totalBars: number;
  energyCurveNormalized: number[]; // 0 - 100 per section
  extractorVersion: string;
  provenance: ProvenanceMetadata;
}

export interface SectionHarmony {
  sectionId: string; // sh_...
  sectionType: SectionType;
  chordProgressionPatternId: string;
  keyCenter: string;
  bars: number;
}

export interface SectionRhythm {
  sectionId: string; // sr_...
  sectionType: SectionType;
  groovePatternId: string;
  tempoBpm: number;
  syncopationLevel: number;
}

/**
 * PatternReferenceExample
 * INVARIANT: Must reference aggregate measured patterns/archetypes and
 * contain ONLY abstract, transposable, non-melodic templates.
 * Never copied song content or identifiable melody lines.
 */
export interface PatternReferenceExample {
  exampleId: string; // pre_...
  patternId: string;
  patternType: 'CHORD' | 'GROOVE' | 'ARRANGEMENT';
  archetypeId: string; // Aggregate cluster archetype reference
  abstractTemplate: string; // Key-agnostic roman numeral or rhythm grid descriptor
  transpositionAnchor: string; // e.g. "Relative to Major Key I"
  isAggregateMeasured: boolean; // MUST BE TRUE
  containsCopiedMelody: boolean; // MUST BE FALSE (No-Copy Protection Invariant)
  analysisRunId: string;
  methodologyVersion: string;
  provenance: ProvenanceMetadata;
}

// ============================================================================
// 5. Hit DNA Analytics, Statistical Truth & Snapshot Governance (HD-01 to HD-06)
// ============================================================================

export interface CohortDefinition {
  cohortId: string; // coh_...
  name: string; // e.g. "Billboard Hot 100 Pop Hits 2024-2025"
  genreId: string;
  chartProvider: string;
  timeframeStart: string; // YYYY-MM-DD
  timeframeEnd: string;
  minWeeksOnChart: number;
  peakRankMax: number;
  frozenMemberCount: number;
  isFrozen: boolean;
  frozenAt: string | null;
  methodologyVersion: string;
  createdAt: string;
}

export interface CohortMembership {
  membershipId: string; // cmem_...
  cohortId: string;
  songId: string;
  rankAchieved: number;
  weeksAchieved: number;
  isQualified: boolean;
  addedAt: string;
}

export interface AnalysisRun {
  analysisRunId: string; // arun_...
  cohortId: string;
  taxonomyVersion: string;
  methodologyVersion: string;
  promptVersion: string | null;
  extractorVersion: string;
  runStartedAt: string;
  runCompletedAt: string | null;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'ARCHIVED';
  sampleCount: number;
  executionFingerprint: string; // SHA-256 of code & config state
  performedBy: string;
}

export type FeatureFamily =
  | 'AUDIO'
  | 'STRUCTURE'
  | 'HOOK'
  | 'RHYTHM'
  | 'ARRANGEMENT'
  | 'HARMONY'
  | 'LYRIC';

export type MetricPublishability =
  | 'PUBLISHABLE'
  | 'INSUFFICIENT_EVIDENCE'
  | 'INTERNAL_ONLY';

/**
 * StatisticalMetric
 * MANDATORY STATISTICAL TRUTH CONTRACT:
 * No percentage without explicit numerator, denominator, formula, and coverage.
 */
export interface StatisticalMetric {
  metricId: string; // smet_...
  analysisRunId: string;
  cohortId: string;
  featureFamily: FeatureFamily;
  metricName: string;
  numerator: number;           // Count of songs matching condition
  denominator: number;         // Frozen cohort size (must be > 0)
  value: number;               // numerator / denominator
  percentage: number;          // value * 100
  coverageCount: number;       // Number of songs where feature was observed
  coverageRate: number;        // coverageCount / denominator
  marginOfError: number;       // Statistical error bound
  formula: string;             // Exact calculation string e.g. "COUNT(timeToFirstHook <= 30) / TOTAL_COHORT"
  calculationVersion: string;  // e.g. "HD-03.v1"
  publishability: MetricPublishability;
  provenance: ProvenanceMetadata;
  calculatedAt: string;
}

export interface EvidenceRecord {
  evidenceId: string; // evr_...
  analysisRunId: string;
  targetEntityId: string; // songId, metricId, etc.
  targetEntityType: string;
  sourceRecordId: string;
  sourceProviderId: string;
  featureKey: string;
  rawValue: unknown;
  normalizedValue: unknown;
  confidence: number;
  provenance: ProvenanceMetadata;
  recordedAt: string;
}

export interface Assertion {
  assertionId: string; // asr_...
  analysisRunId: string;
  subjectId: string;
  predicate: string;
  objectValue: unknown;
  confidence: number;
  derivedFromEvidenceIds: string[];
  provenance: ProvenanceMetadata;
  createdAt: string;
}

export interface Claim {
  claimId: string; // clm_...
  analysisRunId: string;
  statement: string;
  metricId: string | null;
  assertionIds: string[];
  auditStatus: 'PENDING' | 'VALIDATED' | 'CHALLENGED' | 'REVOKED';
  published: boolean;
  provenance: ProvenanceMetadata;
  createdAt: string;
}

export interface Contradiction {
  contradictionId: string; // cnt_...
  analysisRunId: string;
  entityId: string;
  field: string;
  evidenceAId: string;
  evidenceBId: string;
  description: string;
  resolution: 'UNRESOLVED' | 'RESOLVED_PRIMARY' | 'AVERAGED' | 'DISCARDED';
  provenance: ProvenanceMetadata;
  createdAt: string;
}

export interface CoverageGap {
  gapId: string; // gap_...
  analysisRunId: string;
  cohortId: string;
  featureFamily: FeatureFamily;
  missingCount: number;
  totalExpected: number;
  gapSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'BLOCKING';
  reportedAt: string;
}

export interface ClusterRun {
  clusterRunId: string; // crun_...
  analysisRunId: string;
  cohortId: string;
  algorithm: string; // e.g. "K_MEANS_STANDARDIZED_ACOUSTIC_V1"
  kClusters: number;
  clusterSilhouetteScore: number;
  completedAt: string;
}

export interface HitDnaArchetype {
  archetypeId: string; // arch_...
  clusterRunId: string;
  cohortId: string;
  archetypeCode: string; // e.g. "POP_DANCE_ENERGY_01"
  humanLabel: string; // Descriptive label assigned post-clustering e.g. "High-Tempo Kinetic Dance-Pop"
  memberCount: number;
  cohortSharePercentage: number;
  distinctiveFeatures: Record<string, { mean: number; stdDev: number; median: number }>;
  methodologyVersion: string;
  provenance: ProvenanceMetadata;
}

export interface DnaSnapshot {
  snapshotId: string; // dsnap_...
  analysisRunId: string;
  cohortId: string;
  taxonomyVersion: string;
  methodologyVersion: string;
  metricIds: string[];
  archetypeIds: string[];
  immutableHash: string; // SHA-256
  isFrozen: boolean;
  frozenAt: string;
  createdAt: string;
}

export interface PublicationRecord {
  publicationId: string; // pub_...
  dnaSnapshotId: string;
  targetAudience: 'PUBLIC_API' | 'CREATOR_CONSOLE' | 'RESEARCH_REPORT';
  publishedBy: string;
  publishedAt: string;
  status: 'ACTIVE' | 'RETRACTED' | 'SUPERSEDED';
}
