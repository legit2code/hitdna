/**
 * Generation, Lifecycle, Feedback & Operations Persistence Contracts
 * Engines: PF-04 (Canonical Music Data Model & Repository Engine)
 *          PF-09 (Version, Prompt & Methodology Governance)
 *          CG-11 (Generation History, Feedback & Reproducibility)
 * Architecture Version: 5.0.0 | Phase: P05
 *
 * Adheres strictly to the P00 Master Build Constitution:
 * - Complete separation of creative outputs from empirical research facts
 * - Generated lyrics/sound prompts are NEVER research evidence
 * - Feedback is NEVER automatically promoted into factual research
 * - Large imported raw files & analysis artifacts use storage references (StorageReference)
 * - Immutable retention semantics preserving published snapshots and source lineage
 */

import { StorageReference } from './persistence.js';

// ============================================================================
// 1. Generation Requests & Specifications
// ============================================================================

export type KeywordDirective = 'MUST_USE' | 'PREFER' | 'INSPIRE_ONLY' | 'AVOID';
export type KeywordProvenance = 'USER_SUPPLIED' | 'SOURCE_BACKED' | 'AI_CREATIVE';

export interface KeywordDirectiveItem {
  keyword: string;
  directive: KeywordDirective;
  provenance: KeywordProvenance;
  sourceTermId?: string | null;
  rationale?: string;
}

export type GenerationRequestStatus =
  | 'PENDING'
  | 'VALIDATING'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'FAILED'
  | 'REJECTED';

export interface GenerationRequest {
  id: string; // genreq_...
  userId: string;
  titleSeed?: string | null;
  concept: string;
  genrePreferences: string[]; // references genre IDs or hybrid IDs
  keywordBrief: KeywordDirectiveItem[];
  targetEra?: string | null;
  targetArchetypeId?: string | null;
  targetArtistProfileId?: string | null;
  status: GenerationRequestStatus;
  isCreativeOutput: true;
  createdAt: string; // UTC ISO-8601
  updatedAt: string; // UTC ISO-8601
}

export interface PatternBreakGuideline {
  aspect: string; // e.g. 'CHORD_PROGRESSION', 'CHORUS_ARRIVAL_TIME', 'HOOK_DENSITY'
  ruleName: string;
  decision: 'CONFORM' | 'INTENTIONAL_BREAK';
  justification: string;
}

export interface SongSpecification {
  id: string; // songspec_...
  generationRequestId: string;
  targetStructure: string[]; // e.g. ['INTRO', 'VERSE_1', 'CHORUS', 'VERSE_2', 'CHORUS', 'BRIDGE', 'CHORUS', 'OUTRO']
  targetBpm: number;
  targetKey: string;
  targetTimeSignature: string;
  harmonicPalette: string[]; // e.g. ['I-V-vi-IV', 'vi-IV-I-V']
  rhythmGrooveSpec: {
    groovePatternId?: string;
    feel: string;
    swingPercentage?: number;
    drumAesthetic: string;
  };
  lyricThemes: string[];
  vocalDirectives: {
    timbre: string;
    delivery: string;
    leadStyle: string;
  };
  patternBreakGuidelines: PatternBreakGuideline[];
  datasetSnapshotId: string; // Immutable research snapshot referenced
  isCreativeOutput: true;
  createdAt: string;
}

// ============================================================================
// 2. Creative Outputs: Lyrics & Sound Prompts
// ============================================================================

export interface LyricSection {
  sectionType: string; // 'VERSE', 'CHORUS', 'PRE_CHORUS', 'BRIDGE', 'OUTRO'
  lines: string[];
  rhymeScheme?: string;
  hookCallouts?: string[];
}

export interface UsedVernacularTerm {
  term: string;
  termId?: string;
  provenance: KeywordProvenance;
}

export interface LyricsResult {
  id: string; // lyr_...
  generationRequestId: string;
  songSpecificationId: string;
  sections: LyricSection[];
  fullText: string;
  wordCount: number;
  vernacularTermsUsed: UsedVernacularTerm[];
  storageRef: StorageReference | null;
  isCreativeOutput: true;
  epistemicStatus: 'CREATIVE_OUTPUT';
  createdAt: string;
}

export interface SoundPromptResult {
  id: string; // sndp_...
  generationRequestId: string;
  songSpecificationId: string;
  promptText: string; // STRICT CONSTRAINT: Must be < 1000 characters
  characterCount: number;
  tags: string[];
  negativePrompt?: string;
  artistLeakageScrubbed: boolean; // Must be true; real artist names strictly prohibited
  storageRef: StorageReference | null;
  isCreativeOutput: true;
  epistemicStatus: 'CREATIVE_OUTPUT';
  createdAt: string;
}

// ============================================================================
// 3. Validation, Generation Record & Lineage
// ============================================================================

export interface GenerationValidationCheck {
  checkName: string; // 'ZERO_ARTIST_LEAKAGE', 'PROMPT_LENGTH_UNDER_1000', 'STRUCTURE_CONFORMANCE', 'KEYWORD_COMPLIANCE'
  passed: boolean;
  details: string;
}

export interface GenerationValidation {
  id: string; // genval_...
  generationRequestId: string;
  lyricsResultId?: string;
  soundPromptResultId?: string;
  passed: boolean;
  checks: GenerationValidationCheck[];
  leakageDetected: boolean;
  leakageDetails: string[];
  validatorVersion: string;
  validatedAt: string;
}

export interface GenerationModelMetadata {
  provider: string; // e.g. 'GOOGLE_GEMINI'
  modelName: string; // e.g. 'gemini-1.5-pro'
  temperature: number;
  topP?: number;
  seed?: number;
  modelVersion?: string;
}

export interface GenerationEvidenceManifestItem {
  evidenceId: string;
  claimOrMetricId: string;
  description: string;
  sourceOrigin: string;
}

/**
 * GenerationRecord
 * Mandatory fields per Architecture v5.0.0 & P05:
 * - dataset snapshot ID
 * - archetype ID/version
 * - artist profile ID/version when used
 * - prompt versions
 * - model metadata
 * - pattern-break decisions
 * - validation result
 * - evidence manifest
 */
export interface GenerationRecord {
  id: string; // genrec_...
  generationRequestId: string;
  songSpecificationId: string;
  lyricsResultId: string;
  soundPromptResultId: string;
  validationResultId: string;
  datasetSnapshotId: string; // Mandatory: immutable snapshot ID
  archetypeId: string; // Mandatory: archetype ID
  archetypeVersion: string; // Mandatory: archetype version
  artistProfileId: string | null; // Mandatory: artist profile ID when used
  artistProfileVersion: string | null; // Mandatory: artist profile version
  promptVersions: Record<string, string>; // Mandatory: prompt versions
  modelMetadata: GenerationModelMetadata; // Mandatory: model metadata
  patternBreakDecisions: PatternBreakGuideline[]; // Mandatory: pattern-break decisions
  validationResult: {
    passed: boolean;
    leakageFree: boolean;
    validationScore: number;
    details: string;
  }; // Mandatory: validation result
  evidenceManifest: GenerationEvidenceManifestItem[]; // Mandatory: evidence manifest
  isCreativeOutput: true;
  epistemicStatus: 'CREATIVE_OUTPUT';
  status: 'ACTIVE' | 'ARCHIVED';
  createdAt: string;
}

// ============================================================================
// 4. Generation Feedback & Sentiment
// ============================================================================

export interface GenerationFeedbackAspects {
  lyricsQuality?: number; // 1-5
  musicalAtmosphere?: number; // 1-5
  promptUsability?: number; // 1-5
  novelty?: number; // 1-5
}

/**
 * Hard boundary: Feedback is creator sentiment, NOT empirical research facts.
 * promotedToResearch must ALWAYS be false.
 */
export interface GenerationFeedback {
  id: string; // genfb_...
  generationRecordId: string;
  userId: string;
  rating: number; // 1-5
  aspectRatings?: GenerationFeedbackAspects;
  userNotes?: string;
  promotedToResearch: false; // Invariant: cannot be promoted to research!
  createdAt: string;
}

// ============================================================================
// 5. Artist Style Profiles & Evidence
// ============================================================================

export interface ArtistStyleProfileGroove {
  typicalBpmRange: [number, number];
  swingTendency: string;
  drumAesthetic: string;
}

export interface ArtistStyleProfile {
  id: string; // asp_...
  name: string;
  version: string;
  artistId?: string | null;
  abstractStyleAesthetic: string;
  signatureTechniques: string[];
  harmonicTendencies: string[];
  grooveProfile: ArtistStyleProfileGroove;
  lyricThemes: string[];
  status: 'ACTIVE' | 'ARCHIVED';
  createdAt: string;
  updatedAt: string;
}

export interface ArtistProfileEvidence {
  id: string; // ape_...
  artistStyleProfileId: string;
  evidenceType: 'OBSERVED_SONG_ANALYSIS' | 'INTERVIEW_TRANSCRIPT' | 'CHART_RECORD';
  sourceRecordId: string; // Links to empirical SourceRecord
  referenceSongId?: string | null;
  observationId?: string | null;
  citation: string;
  verified: boolean;
  createdAt: string;
}

// ============================================================================
// 6. Research & Workflow Lifecycle Runs
// ============================================================================

export type ResearchRunStatus = 'SCHEDULED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface ResearchRun {
  id: string; // rsr_...
  name: string;
  targetCohortId: string;
  methodologyVersionId: string;
  status: ResearchRunStatus;
  datasetSnapshotId?: string | null;
  recordsAnalyzed: number;
  metricsComputed: number;
  errorSummary?: string | null;
  storageRef: StorageReference | null; // Large imported raw files & analysis artifacts use storage refs
  startedAt: string;
  completedAt?: string | null;
  createdAt: string;
}

export type WorkflowType =
  | 'RESEARCH_PIPELINE'
  | 'GENERATION_PIPELINE'
  | 'EVALUATION_PIPELINE'
  | 'SNAPSHOT_PUBLISH';

export type WorkflowRunStatus = 'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'TIMED_OUT';

export interface WorkflowStepSummary {
  stepName: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'SKIPPED';
  startedAt: string;
  completedAt?: string | null;
  details?: string | null;
}

export interface WorkflowRun {
  id: string; // wfr_...
  workflowType: WorkflowType;
  status: WorkflowRunStatus;
  trigger: 'SCHEDULED' | 'MANUAL' | 'API' | 'EVENT';
  context: Record<string, unknown>;
  stepSummaries: WorkflowStepSummary[];
  storageRef: StorageReference | null;
  startedAt: string;
  completedAt?: string | null;
  createdAt: string;
}

// ============================================================================
// 7. Background Jobs, Attempts & Outbox Events
// ============================================================================

export type JobPriority = 'LOW' | 'NORMAL' | 'HIGH' | 'CRITICAL';
export type JobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface Job {
  id: string; // job_...
  type: string; // e.g. 'INGEST_SOURCE', 'ANALYZE_AUDIO', 'GENERATE_BLUEPRINT', 'VERIFY_EVAL'
  queueName: string;
  priority: JobPriority;
  payloadRef: StorageReference | null; // Large payloads use storage reference rather than bloating queue/job docs
  payloadMetadata: Record<string, unknown>; // Small lightweight metadata only
  status: JobStatus;
  maxAttempts: number;
  attemptCount: number;
  scheduledFor?: string | null;
  lockedBy?: string | null;
  lockedUntil?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface JobAttempt {
  id: string; // jba_...
  jobId: string;
  attemptNumber: number;
  workerId: string;
  status: 'RUNNING' | 'SUCCESS' | 'ERROR';
  errorMessage?: string | null;
  artifactRef: StorageReference | null;
  startedAt: string;
  finishedAt?: string | null;
}

export interface OutboxEvent {
  id: string; // obx_...
  aggregateType: string; // 'GENERATION', 'RESEARCH', 'SNAPSHOT', 'USER'
  aggregateId: string;
  eventType: string; // 'GENERATION_COMPLETED', 'SNAPSHOT_PUBLISHED', etc.
  payload: Record<string, unknown>;
  payloadRef: StorageReference | null;
  published: boolean;
  publishedAt?: string | null;
  retryCount: number;
  createdAt: string;
}

// ============================================================================
// 8. Audit, Evaluation & Release Checks
// ============================================================================

export interface AuditEvent {
  id: string; // aud_...
  actorId: string;
  actorRole: 'ADMIN' | 'RESEARCHER' | 'CREATOR' | 'SYSTEM';
  action: string;
  resourceType: string;
  resourceId: string;
  details: Record<string, unknown>;
  ipAddress?: string | null;
  timestamp: string;
}

export interface EvaluationRun {
  id: string; // evr_...
  name: string;
  targetType: 'MODEL_PROMPT' | 'DATASET_INTEGRITY' | 'LEAKAGE_ASSURANCE' | 'RHYME_ALGORITHM';
  benchmarkVersion: string;
  score: number; // 0.0 to 1.0
  metrics: Record<string, number>;
  passed: boolean;
  evaluator: string;
  storageRef: StorageReference | null; // Full evaluation report in object storage
  createdAt: string;
}

export interface ReleaseCheck {
  id: string; // rlc_...
  releaseVersion: string;
  checkType: 'ARCHITECTURE_INTEGRITY' | 'FIXTURE_ISOLATION' | 'PROVENANCE_VERIFICATION' | 'LEAKAGE_SAFETY' | 'NEGATIVE_TEST_SUITE';
  passed: boolean;
  blocking: boolean;
  evidenceReceiptPath: string; // e.g. 'docs/implementation/evidence/P05_RECEIPT.json'
  receiptHash: string;
  evaluatedAt: string;
}

// ============================================================================
// 9. Retention & Version Semantics Contracts
// ============================================================================

export type RetentionLifecycleAction = 'ARCHIVE' | 'PURGE';

export interface RetentionPolicyCheckResult {
  allowed: boolean;
  action: RetentionLifecycleAction;
  reason?: string;
}
