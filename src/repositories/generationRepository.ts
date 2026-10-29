/**
 * Generation, Lifecycle, Feedback & Operations Repository Engine
 * Engines: PF-04 (Canonical Music Data Model & Repository Engine)
 *          PF-09 (Version, Prompt & Methodology Governance)
 *          CG-11 (Generation History, Feedback & Reproducibility)
 * Architecture Version: 5.0.0 | Phase: P05
 *
 * Implements persistence for:
 * 1. generationRequests
 * 2. songSpecifications
 * 3. lyricsResults
 * 4. soundPromptResults
 * 5. generationValidations
 * 6. generationRecords
 * 7. generationFeedback
 * 8. artistStyleProfiles
 * 9. artistProfileEvidence
 * 10. researchRuns
 * 11. workflowRuns
 * 12. jobs
 * 13. jobAttempts
 * 14. outboxEvents
 * 15. auditEvents
 * 16. evaluationRuns
 * 17. releaseChecks
 */

import {
  GenerationRequest,
  SongSpecification,
  LyricsResult,
  SoundPromptResult,
  GenerationValidation,
  GenerationRecord,
  GenerationFeedback,
  ArtistStyleProfile,
  ArtistProfileEvidence,
  ResearchRun,
  WorkflowRun,
  WorkflowType,
  Job,
  JobStatus,
  JobAttempt,
  OutboxEvent,
  AuditEvent,
  EvaluationRun,
  ReleaseCheck,
  RetentionLifecycleAction,
} from '../contracts/generationLifecycle.js';

import {
  validateCreativeIsolation,
  validateFeedbackIsolation,
  validateSoundPromptConstraints,
  validateRetentionAction,
  EpistemicGovernanceError,
} from '../domain/epistemicGovernance.js';

export interface GenerationLineagePackage {
  generationRecord: GenerationRecord;
  generationRequest: GenerationRequest | null;
  songSpecification: SongSpecification | null;
  lyricsResult: LyricsResult | null;
  soundPromptResult: SoundPromptResult | null;
  generationValidation: GenerationValidation | null;
  artistStyleProfile: ArtistStyleProfile | null;
  artistProfileEvidence: ArtistProfileEvidence[];
}

export interface IGenerationLifecycleRepository {
  // 1. generationRequests
  saveGenerationRequest(request: GenerationRequest): Promise<void>;
  getGenerationRequest(id: string): Promise<GenerationRequest | null>;
  listGenerationRequests(userId?: string): Promise<GenerationRequest[]>;

  // 2. songSpecifications
  saveSongSpecification(spec: SongSpecification): Promise<void>;
  getSongSpecification(id: string): Promise<SongSpecification | null>;
  getSongSpecificationByRequest(requestId: string): Promise<SongSpecification | null>;

  // 3. lyricsResults
  saveLyricsResult(result: LyricsResult): Promise<void>;
  getLyricsResult(id: string): Promise<LyricsResult | null>;
  getLyricsResultsByRequest(requestId: string): Promise<LyricsResult[]>;

  // 4. soundPromptResults
  saveSoundPromptResult(result: SoundPromptResult): Promise<void>;
  getSoundPromptResult(id: string): Promise<SoundPromptResult | null>;
  getSoundPromptResultsByRequest(requestId: string): Promise<SoundPromptResult[]>;

  // 5. generationValidations
  saveGenerationValidation(validation: GenerationValidation): Promise<void>;
  getGenerationValidation(id: string): Promise<GenerationValidation | null>;
  getValidationsByRequest(requestId: string): Promise<GenerationValidation[]>;

  // 6. generationRecords
  saveGenerationRecord(record: GenerationRecord): Promise<void>;
  getGenerationRecord(id: string): Promise<GenerationRecord | null>;
  listGenerationRecords(filters?: {
    datasetSnapshotId?: string;
    archetypeId?: string;
    artistProfileId?: string;
  }): Promise<GenerationRecord[]>;

  // 7. generationFeedback
  saveGenerationFeedback(feedback: GenerationFeedback): Promise<void>;
  getGenerationFeedback(id: string): Promise<GenerationFeedback | null>;
  listFeedbackByRecord(recordId: string): Promise<GenerationFeedback[]>;

  // 8. artistStyleProfiles
  saveArtistStyleProfile(profile: ArtistStyleProfile): Promise<void>;
  getArtistStyleProfile(id: string): Promise<ArtistStyleProfile | null>;
  listArtistStyleProfiles(status?: 'ACTIVE' | 'ARCHIVED'): Promise<ArtistStyleProfile[]>;

  // 9. artistProfileEvidence
  saveArtistProfileEvidence(evidence: ArtistProfileEvidence): Promise<void>;
  getArtistProfileEvidence(id: string): Promise<ArtistProfileEvidence | null>;
  listEvidenceByProfile(profileId: string): Promise<ArtistProfileEvidence[]>;

  // 10. researchRuns
  saveResearchRun(run: ResearchRun): Promise<void>;
  getResearchRun(id: string): Promise<ResearchRun | null>;
  listResearchRuns(cohortId?: string): Promise<ResearchRun[]>;

  // 11. workflowRuns
  saveWorkflowRun(run: WorkflowRun): Promise<void>;
  getWorkflowRun(id: string): Promise<WorkflowRun | null>;
  listWorkflowRuns(workflowType?: WorkflowType): Promise<WorkflowRun[]>;

  // 12. jobs
  saveJob(job: Job): Promise<void>;
  getJob(id: string): Promise<Job | null>;
  listJobs(queueName?: string, status?: JobStatus): Promise<Job[]>;
  claimNextJob(queueName: string, workerId: string, lockDurationMs: number): Promise<Job | null>;

  // 13. jobAttempts
  saveJobAttempt(attempt: JobAttempt): Promise<void>;
  getJobAttempt(id: string): Promise<JobAttempt | null>;
  listAttemptsByJob(jobId: string): Promise<JobAttempt[]>;

  // 14. outboxEvents
  saveOutboxEvent(event: OutboxEvent): Promise<void>;
  getOutboxEvent(id: string): Promise<OutboxEvent | null>;
  listUnpublishedOutboxEvents(): Promise<OutboxEvent[]>;
  markOutboxEventPublished(id: string): Promise<void>;

  // 15. auditEvents
  saveAuditEvent(event: AuditEvent): Promise<void>;
  getAuditEvent(id: string): Promise<AuditEvent | null>;
  listAuditEvents(resourceType?: string, resourceId?: string): Promise<AuditEvent[]>;

  // 16. evaluationRuns
  saveEvaluationRun(run: EvaluationRun): Promise<void>;
  getEvaluationRun(id: string): Promise<EvaluationRun | null>;
  listEvaluationRuns(targetType?: string): Promise<EvaluationRun[]>;

  // 17. releaseChecks
  saveReleaseCheck(check: ReleaseCheck): Promise<void>;
  getReleaseCheck(id: string): Promise<ReleaseCheck | null>;
  listReleaseChecks(releaseVersion?: string): Promise<ReleaseCheck[]>;

  // Lineage & Governance
  resolveGenerationLineage(generationRecordId: string): Promise<GenerationLineagePackage>;
  applyRetentionAction(
    entityType: string,
    action: RetentionLifecycleAction,
    entityId: string
  ): Promise<void>;
}

export class InMemoryGenerationLifecycleRepository implements IGenerationLifecycleRepository {
  private generationRequests: Map<string, GenerationRequest> = new Map();
  private songSpecifications: Map<string, SongSpecification> = new Map();
  private lyricsResults: Map<string, LyricsResult> = new Map();
  private soundPromptResults: Map<string, SoundPromptResult> = new Map();
  private generationValidations: Map<string, GenerationValidation> = new Map();
  private generationRecords: Map<string, GenerationRecord> = new Map();
  private generationFeedback: Map<string, GenerationFeedback> = new Map();
  private artistStyleProfiles: Map<string, ArtistStyleProfile> = new Map();
  private artistProfileEvidence: Map<string, ArtistProfileEvidence> = new Map();
  private researchRuns: Map<string, ResearchRun> = new Map();
  private workflowRuns: Map<string, WorkflowRun> = new Map();
  private jobs: Map<string, Job> = new Map();
  private jobAttempts: Map<string, JobAttempt> = new Map();
  private outboxEvents: Map<string, OutboxEvent> = new Map();
  private auditEvents: Map<string, AuditEvent> = new Map();
  private evaluationRuns: Map<string, EvaluationRun> = new Map();
  private releaseChecks: Map<string, ReleaseCheck> = new Map();

  // 1. generationRequests
  async saveGenerationRequest(request: GenerationRequest): Promise<void> {
    this.generationRequests.set(request.id, { ...request });
  }

  async getGenerationRequest(id: string): Promise<GenerationRequest | null> {
    return this.generationRequests.get(id) ? { ...this.generationRequests.get(id)! } : null;
  }

  async listGenerationRequests(userId?: string): Promise<GenerationRequest[]> {
    const all = Array.from(this.generationRequests.values());
    if (userId) return all.filter(r => r.userId === userId);
    return all;
  }

  // 2. songSpecifications
  async saveSongSpecification(spec: SongSpecification): Promise<void> {
    this.songSpecifications.set(spec.id, { ...spec });
  }

  async getSongSpecification(id: string): Promise<SongSpecification | null> {
    return this.songSpecifications.get(id) ? { ...this.songSpecifications.get(id)! } : null;
  }

  async getSongSpecificationByRequest(requestId: string): Promise<SongSpecification | null> {
    for (const spec of this.songSpecifications.values()) {
      if (spec.generationRequestId === requestId) return { ...spec };
    }
    return null;
  }

  // 3. lyricsResults
  async saveLyricsResult(result: LyricsResult): Promise<void> {
    // Invariant: creative output isolation
    if (!result.isCreativeOutput || result.epistemicStatus !== 'CREATIVE_OUTPUT') {
      throw new EpistemicGovernanceError(
        'LyricsResult must be explicitly tagged as CREATIVE_OUTPUT.',
        'INVALID_CREATIVE_METADATA'
      );
    }
    this.lyricsResults.set(result.id, { ...result });
  }

  async getLyricsResult(id: string): Promise<LyricsResult | null> {
    return this.lyricsResults.get(id) ? { ...this.lyricsResults.get(id)! } : null;
  }

  async getLyricsResultsByRequest(requestId: string): Promise<LyricsResult[]> {
    return Array.from(this.lyricsResults.values()).filter(l => l.generationRequestId === requestId);
  }

  // 4. soundPromptResults
  async saveSoundPromptResult(result: SoundPromptResult): Promise<void> {
    // Enforce constraints: < 1000 characters and artist leakage scrubbed
    validateSoundPromptConstraints(result);
    this.soundPromptResults.set(result.id, { ...result });
  }

  async getSoundPromptResult(id: string): Promise<SoundPromptResult | null> {
    return this.soundPromptResults.get(id) ? { ...this.soundPromptResults.get(id)! } : null;
  }

  async getSoundPromptResultsByRequest(requestId: string): Promise<SoundPromptResult[]> {
    return Array.from(this.soundPromptResults.values()).filter(s => s.generationRequestId === requestId);
  }

  // 5. generationValidations
  async saveGenerationValidation(validation: GenerationValidation): Promise<void> {
    this.generationValidations.set(validation.id, { ...validation });
  }

  async getGenerationValidation(id: string): Promise<GenerationValidation | null> {
    return this.generationValidations.get(id) ? { ...this.generationValidations.get(id)! } : null;
  }

  async getValidationsByRequest(requestId: string): Promise<GenerationValidation[]> {
    return Array.from(this.generationValidations.values()).filter(v => v.generationRequestId === requestId);
  }

  // 6. generationRecords
  async saveGenerationRecord(record: GenerationRecord): Promise<void> {
    // Enforce required fields per Architecture v5.0.0 & P05:
    if (!record.datasetSnapshotId) {
      throw new EpistemicGovernanceError('GenerationRecord missing datasetSnapshotId.', 'MISSING_SNAPSHOT_ID');
    }
    if (!record.archetypeId || !record.archetypeVersion) {
      throw new EpistemicGovernanceError('GenerationRecord missing archetypeId or archetypeVersion.', 'MISSING_ARCHETYPE_METADATA');
    }
    if (!record.promptVersions || Object.keys(record.promptVersions).length === 0) {
      throw new EpistemicGovernanceError('GenerationRecord missing promptVersions.', 'MISSING_PROMPT_VERSIONS');
    }
    if (!record.modelMetadata || !record.modelMetadata.provider || !record.modelMetadata.modelName) {
      throw new EpistemicGovernanceError('GenerationRecord missing modelMetadata.', 'MISSING_MODEL_METADATA');
    }
    if (!Array.isArray(record.patternBreakDecisions)) {
      throw new EpistemicGovernanceError('GenerationRecord missing patternBreakDecisions array.', 'MISSING_PATTERN_BREAK_DECISIONS');
    }
    if (!record.validationResult) {
      throw new EpistemicGovernanceError('GenerationRecord missing validationResult.', 'MISSING_VALIDATION_RESULT');
    }
    if (!Array.isArray(record.evidenceManifest)) {
      throw new EpistemicGovernanceError('GenerationRecord missing evidenceManifest array.', 'MISSING_EVIDENCE_MANIFEST');
    }

    this.generationRecords.set(record.id, { ...record });
  }

  async getGenerationRecord(id: string): Promise<GenerationRecord | null> {
    return this.generationRecords.get(id) ? { ...this.generationRecords.get(id)! } : null;
  }

  async listGenerationRecords(filters?: {
    datasetSnapshotId?: string;
    archetypeId?: string;
    artistProfileId?: string;
  }): Promise<GenerationRecord[]> {
    let all = Array.from(this.generationRecords.values());
    if (filters?.datasetSnapshotId) {
      all = all.filter(r => r.datasetSnapshotId === filters.datasetSnapshotId);
    }
    if (filters?.archetypeId) {
      all = all.filter(r => r.archetypeId === filters.archetypeId);
    }
    if (filters?.artistProfileId) {
      all = all.filter(r => r.artistProfileId === filters.artistProfileId);
    }
    return all;
  }

  // 7. generationFeedback
  async saveGenerationFeedback(feedback: GenerationFeedback): Promise<void> {
    // Hard boundary: Feedback is creator sentiment and CANNOT be promoted to factual research!
    validateFeedbackIsolation(feedback);
    this.generationFeedback.set(feedback.id, { ...feedback });
  }

  async getGenerationFeedback(id: string): Promise<GenerationFeedback | null> {
    return this.generationFeedback.get(id) ? { ...this.generationFeedback.get(id)! } : null;
  }

  async listFeedbackByRecord(recordId: string): Promise<GenerationFeedback[]> {
    return Array.from(this.generationFeedback.values()).filter(f => f.generationRecordId === recordId);
  }

  // 8. artistStyleProfiles
  async saveArtistStyleProfile(profile: ArtistStyleProfile): Promise<void> {
    this.artistStyleProfiles.set(profile.id, { ...profile });
  }

  async getArtistStyleProfile(id: string): Promise<ArtistStyleProfile | null> {
    return this.artistStyleProfiles.get(id) ? { ...this.artistStyleProfiles.get(id)! } : null;
  }

  async listArtistStyleProfiles(status?: 'ACTIVE' | 'ARCHIVED'): Promise<ArtistStyleProfile[]> {
    const all = Array.from(this.artistStyleProfiles.values());
    if (status) return all.filter(p => p.status === status);
    return all;
  }

  // 9. artistProfileEvidence
  async saveArtistProfileEvidence(evidence: ArtistProfileEvidence): Promise<void> {
    this.artistProfileEvidence.set(evidence.id, { ...evidence });
  }

  async getArtistProfileEvidence(id: string): Promise<ArtistProfileEvidence | null> {
    return this.artistProfileEvidence.get(id) ? { ...this.artistProfileEvidence.get(id)! } : null;
  }

  async listEvidenceByProfile(profileId: string): Promise<ArtistProfileEvidence[]> {
    return Array.from(this.artistProfileEvidence.values()).filter(e => e.artistStyleProfileId === profileId);
  }

  // 10. researchRuns
  async saveResearchRun(run: ResearchRun): Promise<void> {
    this.researchRuns.set(run.id, { ...run });
  }

  async getResearchRun(id: string): Promise<ResearchRun | null> {
    return this.researchRuns.get(id) ? { ...this.researchRuns.get(id)! } : null;
  }

  async listResearchRuns(cohortId?: string): Promise<ResearchRun[]> {
    const all = Array.from(this.researchRuns.values());
    if (cohortId) return all.filter(r => r.targetCohortId === cohortId);
    return all;
  }

  // 11. workflowRuns
  async saveWorkflowRun(run: WorkflowRun): Promise<void> {
    this.workflowRuns.set(run.id, { ...run });
  }

  async getWorkflowRun(id: string): Promise<WorkflowRun | null> {
    return this.workflowRuns.get(id) ? { ...this.workflowRuns.get(id)! } : null;
  }

  async listWorkflowRuns(workflowType?: WorkflowType): Promise<WorkflowRun[]> {
    const all = Array.from(this.workflowRuns.values());
    if (workflowType) return all.filter(w => w.workflowType === workflowType);
    return all;
  }

  // 12. jobs
  async saveJob(job: Job): Promise<void> {
    this.jobs.set(job.id, { ...job });
  }

  async getJob(id: string): Promise<Job | null> {
    return this.jobs.get(id) ? { ...this.jobs.get(id)! } : null;
  }

  async listJobs(queueName?: string, status?: JobStatus): Promise<Job[]> {
    let all = Array.from(this.jobs.values());
    if (queueName) all = all.filter(j => j.queueName === queueName);
    if (status) all = all.filter(j => j.status === status);
    return all;
  }

  async claimNextJob(queueName: string, workerId: string, lockDurationMs: number): Promise<Job | null> {
    const nowIso = new Date().toISOString();
    for (const job of this.jobs.values()) {
      if (job.queueName === queueName && job.status === 'QUEUED') {
        const lockedUntil = new Date(Date.now() + lockDurationMs).toISOString();
        const updated: Job = {
          ...job,
          status: 'RUNNING',
          lockedBy: workerId,
          lockedUntil,
          updatedAt: nowIso,
        };
        this.jobs.set(job.id, updated);
        return { ...updated };
      }
    }
    return null;
  }

  // 13. jobAttempts
  async saveJobAttempt(attempt: JobAttempt): Promise<void> {
    this.jobAttempts.set(attempt.id, { ...attempt });
  }

  async getJobAttempt(id: string): Promise<JobAttempt | null> {
    return this.jobAttempts.get(id) ? { ...this.jobAttempts.get(id)! } : null;
  }

  async listAttemptsByJob(jobId: string): Promise<JobAttempt[]> {
    return Array.from(this.jobAttempts.values()).filter(a => a.jobId === jobId);
  }

  // 14. outboxEvents
  async saveOutboxEvent(event: OutboxEvent): Promise<void> {
    this.outboxEvents.set(event.id, { ...event });
  }

  async getOutboxEvent(id: string): Promise<OutboxEvent | null> {
    return this.outboxEvents.get(id) ? { ...this.outboxEvents.get(id)! } : null;
  }

  async listUnpublishedOutboxEvents(): Promise<OutboxEvent[]> {
    return Array.from(this.outboxEvents.values()).filter(e => !e.published);
  }

  async markOutboxEventPublished(id: string): Promise<void> {
    const ev = this.outboxEvents.get(id);
    if (ev) {
      ev.published = true;
      ev.publishedAt = new Date().toISOString();
      this.outboxEvents.set(id, ev);
    }
  }

  // 15. auditEvents
  async saveAuditEvent(event: AuditEvent): Promise<void> {
    this.auditEvents.set(event.id, { ...event });
  }

  async getAuditEvent(id: string): Promise<AuditEvent | null> {
    return this.auditEvents.get(id) ? { ...this.auditEvents.get(id)! } : null;
  }

  async listAuditEvents(resourceType?: string, resourceId?: string): Promise<AuditEvent[]> {
    let all = Array.from(this.auditEvents.values());
    if (resourceType) all = all.filter(a => a.resourceType === resourceType);
    if (resourceId) all = all.filter(a => a.resourceId === resourceId);
    return all;
  }

  // 16. evaluationRuns
  async saveEvaluationRun(run: EvaluationRun): Promise<void> {
    this.evaluationRuns.set(run.id, { ...run });
  }

  async getEvaluationRun(id: string): Promise<EvaluationRun | null> {
    return this.evaluationRuns.get(id) ? { ...this.evaluationRuns.get(id)! } : null;
  }

  async listEvaluationRuns(targetType?: string): Promise<EvaluationRun[]> {
    const all = Array.from(this.evaluationRuns.values());
    if (targetType) return all.filter(e => e.targetType === targetType);
    return all;
  }

  // 17. releaseChecks
  async saveReleaseCheck(check: ReleaseCheck): Promise<void> {
    this.releaseChecks.set(check.id, { ...check });
  }

  async getReleaseCheck(id: string): Promise<ReleaseCheck | null> {
    return this.releaseChecks.get(id) ? { ...this.releaseChecks.get(id)! } : null;
  }

  async listReleaseChecks(releaseVersion?: string): Promise<ReleaseCheck[]> {
    const all = Array.from(this.releaseChecks.values());
    if (releaseVersion) return all.filter(c => c.releaseVersion === releaseVersion);
    return all;
  }

  // Generation Lineage Resolution
  async resolveGenerationLineage(generationRecordId: string): Promise<GenerationLineagePackage> {
    const generationRecord = await this.getGenerationRecord(generationRecordId);
    if (!generationRecord) {
      throw new Error(`Generation record '${generationRecordId}' not found for lineage resolution.`);
    }

    const generationRequest = await this.getGenerationRequest(generationRecord.generationRequestId);
    const songSpecification = await this.getSongSpecification(generationRecord.songSpecificationId);
    const lyricsResult = await this.getLyricsResult(generationRecord.lyricsResultId);
    const soundPromptResult = await this.getSoundPromptResult(generationRecord.soundPromptResultId);
    const generationValidation = await this.getGenerationValidation(generationRecord.validationResultId);

    let artistStyleProfile: ArtistStyleProfile | null = null;
    let artistProfileEvidence: ArtistProfileEvidence[] = [];
    if (generationRecord.artistProfileId) {
      artistStyleProfile = await this.getArtistStyleProfile(generationRecord.artistProfileId);
      if (artistStyleProfile) {
        artistProfileEvidence = await this.listEvidenceByProfile(artistStyleProfile.id);
      }
    }

    return {
      generationRecord,
      generationRequest,
      songSpecification,
      lyricsResult,
      soundPromptResult,
      generationValidation,
      artistStyleProfile,
      artistProfileEvidence,
    };
  }

  // Retention & Version Semantics Enforcement
  async applyRetentionAction(
    entityType: string,
    action: RetentionLifecycleAction,
    entityId: string
  ): Promise<void> {
    if (action === 'PURGE') {
      // Validate with epistemic retention rule
      validateRetentionAction(entityType, action, { id: entityId, isImmutable: true });
    }

    // Archiving is allowed
    if (entityType === 'GenerationRecord') {
      const record = this.generationRecords.get(entityId);
      if (record) {
        record.status = 'ARCHIVED';
        this.generationRecords.set(entityId, record);
      }
    } else if (entityType === 'ArtistStyleProfile') {
      const profile = this.artistStyleProfiles.get(entityId);
      if (profile) {
        profile.status = 'ARCHIVED';
        this.artistStyleProfiles.set(entityId, profile);
      }
    }
  }
}

// Singleton accessor
let globalGenerationLifecycleRepository: IGenerationLifecycleRepository | null = null;

export function getGenerationLifecycleRepository(): IGenerationLifecycleRepository {
  if (!globalGenerationLifecycleRepository) {
    globalGenerationLifecycleRepository = new InMemoryGenerationLifecycleRepository();
  }
  return globalGenerationLifecycleRepository;
}
