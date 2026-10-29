/**
 * P05 Unit & Invariant Test Suite: Generation, Lifecycle, Feedback & Operations Persistence
 * Engines: PF-04 (Canonical Music Data Model & Repository Engine)
 *          PF-09 (Version, Prompt & Methodology Governance)
 *          CG-11 (Generation History, Feedback & Reproducibility)
 * Architecture Version: 5.0.0 | Phase: P05
 *
 * Verifies:
 * 1. Complete persistence lifecycle across all 17 entity collections.
 * 2. Separation of creative outputs from empirical research facts (zero contamination).
 * 3. Feedback isolation (creator sentiment never promoted to empirical research).
 * 4. Sound prompt constraints (< 1000 chars, zero artist leakage).
 * 5. Generation lineage resolution with snapshot, archetype, artist profile, prompt versions, model metadata, and evidence manifest.
 * 6. Storage references for large artifacts and payloads.
 * 7. Retention/version semantics preserving immutable published snapshots and lineage.
 * 8. Background job claiming and outbox event publishing.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  InMemoryGenerationLifecycleRepository,
  IGenerationLifecycleRepository,
} from '../../repositories/generationRepository.js';

import { InMemoryMusicRepository } from '../../repositories/musicRepository.js';

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
  Job,
  JobAttempt,
  OutboxEvent,
  AuditEvent,
  EvaluationRun,
  ReleaseCheck,
} from '../../contracts/generationLifecycle.js';

import {
  validateCreativeIsolation,
  validateFeedbackIsolation,
  validateSoundPromptConstraints,
  validateRetentionAction,
  EpistemicGovernanceError,
} from '../../domain/epistemicGovernance.js';

describe('P05: Generation, Lifecycle, Feedback & Operations Persistence', () => {
  const repo: IGenerationLifecycleRepository = new InMemoryGenerationLifecycleRepository();
  const musicRepo = new InMemoryMusicRepository();

  it('1. Persists and retrieves GenerationRequest and SongSpecification', async () => {
    const req: GenerationRequest = {
      id: 'genreq_001',
      userId: 'usr_creator_42',
      concept: 'A melancholic synthwave ballad exploring technological solitude in 2080',
      genrePreferences: ['gnr_synthwave', 'gnr_retropop'],
      keywordBrief: [
        {
          keyword: 'neon drift',
          directive: 'MUST_USE',
          provenance: 'USER_SUPPLIED',
        },
        {
          keyword: 'phosphor',
          directive: 'PREFER',
          provenance: 'SOURCE_BACKED',
          sourceTermId: 'vtm_phosphor_01',
        },
      ],
      targetArchetypeId: 'arch_synth_ballad_v1',
      status: 'COMPLETED',
      isCreativeOutput: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await repo.saveGenerationRequest(req);
    const retrievedReq = await repo.getGenerationRequest('genreq_001');
    assert.ok(retrievedReq);
    assert.equal(retrievedReq.concept, req.concept);
    assert.equal(retrievedReq.isCreativeOutput, true);

    const spec: SongSpecification = {
      id: 'songspec_001',
      generationRequestId: 'genreq_001',
      targetStructure: ['INTRO', 'VERSE_1', 'CHORUS', 'VERSE_2', 'CHORUS', 'BRIDGE', 'CHORUS', 'OUTRO'],
      targetBpm: 92,
      targetKey: 'F# minor',
      targetTimeSignature: '4/4',
      harmonicPalette: ['i - VI - III - VII', 'iv - i - V - i'],
      rhythmGrooveSpec: {
        groovePatternId: 'grv_gated_reverb_80s',
        feel: 'STRAIGHT_EIGHTHS',
        swingPercentage: 0,
        drumAesthetic: 'LINNDRUM_GATED',
      },
      lyricThemes: ['ISOLATION', 'NOSTALGIA', 'CYBERNETIC_LONGING'],
      vocalDirectives: {
        timbre: 'WARM_ANALOG_REVERB',
        delivery: 'INTIMATE_CLOSE_MIC',
        leadStyle: 'ANDROGYNOUS_ETHEREAL',
      },
      patternBreakGuidelines: [
        {
          aspect: 'CHORUS_ARRIVAL_TIME',
          ruleName: 'RULE_CHORUS_UNDER_60S',
          decision: 'INTENTIONAL_BREAK',
          justification: 'Delayed chorus arrival to 75s to build cinematic atmospheric tension.',
        },
      ],
      datasetSnapshotId: 'snap_2026_09_canonical',
      isCreativeOutput: true,
      createdAt: new Date().toISOString(),
    };

    await repo.saveSongSpecification(spec);
    const retrievedSpec = await repo.getSongSpecification('songspec_001');
    assert.ok(retrievedSpec);
    assert.equal(retrievedSpec.targetBpm, 92);
    assert.equal(retrievedSpec.patternBreakGuidelines[0].decision, 'INTENTIONAL_BREAK');
  });

  it('2. Enforces SoundPromptResult length (<1000 chars) and artist leakage scrubbing', async () => {
    // Valid sound prompt
    const validSoundPrompt: SoundPromptResult = {
      id: 'sndp_valid_01',
      generationRequestId: 'genreq_001',
      songSpecificationId: 'songspec_001',
      promptText: 'Melancholic 80s synthwave ballad, warm analog Juno-106 pads, gated LinnDrum, gated reverb, emotional arpeggiated synth bassline, 92 bpm, F# minor, pristine production, spacious vocal reverb',
      characterCount: 194,
      tags: ['synthwave', 'ballad', 'linndrum', 'analog-synth', 'atmospheric'],
      artistLeakageScrubbed: true,
      storageRef: null,
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
      createdAt: new Date().toISOString(),
    };

    await repo.saveSoundPromptResult(validSoundPrompt);
    const retrieved = await repo.getSoundPromptResult('sndp_valid_01');
    assert.ok(retrieved);
    assert.equal(retrieved.artistLeakageScrubbed, true);

    // Invalid sound prompt: > 1000 characters
    const oversizedSoundPrompt: SoundPromptResult = {
      id: 'sndp_oversized_01',
      generationRequestId: 'genreq_001',
      songSpecificationId: 'songspec_001',
      promptText: 'X'.repeat(1005),
      characterCount: 1005,
      tags: ['oversized'],
      artistLeakageScrubbed: true,
      storageRef: null,
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
      createdAt: new Date().toISOString(),
    };

    await assert.rejects(
      async () => repo.saveSoundPromptResult(oversizedSoundPrompt),
      (err: any) => {
        assert.equal(err.errorCode, 'SOUND_PROMPT_LENGTH_EXCEEDED');
        return true;
      }
    );

    // Invalid sound prompt: unscrubbed artist leakage
    const leakySoundPrompt: SoundPromptResult = {
      id: 'sndp_leaky_01',
      generationRequestId: 'genreq_001',
      songSpecificationId: 'songspec_001',
      promptText: 'Synth ballad in the exact vocal style of The Weeknd with Daft Punk production',
      characterCount: 77,
      tags: ['synthwave'],
      artistLeakageScrubbed: false, // Leaky!
      storageRef: null,
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
      createdAt: new Date().toISOString(),
    };

    await assert.rejects(
      async () => repo.saveSoundPromptResult(leakySoundPrompt),
      (err: any) => {
        assert.equal(err.errorCode, 'ARTIST_LEAKAGE_UNSCRUBBED');
        return true;
      }
    );
  });

  it('3. Persists LyricsResult with StorageReference for large lyric documents', async () => {
    const lyrics: LyricsResult = {
      id: 'lyr_neon_01',
      generationRequestId: 'genreq_001',
      songSpecificationId: 'songspec_001',
      sections: [
        {
          sectionType: 'VERSE_1',
          lines: ['Empty streets and neon rain', 'Phosphor memories of your name'],
          rhymeScheme: 'AABB',
        },
        {
          sectionType: 'CHORUS',
          lines: ['Caught in the neon drift tonight', 'Signal fades into the white'],
          rhymeScheme: 'AABB',
          hookCallouts: ['Catchy melodic leap on "drift"'],
        },
      ],
      fullText: 'Empty streets and neon rain\nPhosphor memories of your name\n\nCaught in the neon drift tonight\nSignal fades into the white',
      wordCount: 22,
      vernacularTermsUsed: [
        {
          term: 'neon drift',
          provenance: 'USER_SUPPLIED',
        },
        {
          term: 'phosphor',
          provenance: 'SOURCE_BACKED',
          termId: 'vtm_phosphor_01',
        },
      ],
      storageRef: {
        id: 'sref_lyr_neon_01',
        bucket: 'music-generation-lyrics-prod',
        key: 'users/usr_creator_42/lyr_neon_01.txt',
        contentType: 'text/plain',
        byteSize: 128,
        sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        accessTier: 'HOT',
        createdAt: new Date().toISOString(),
      },
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
      createdAt: new Date().toISOString(),
    };

    await repo.saveLyricsResult(lyrics);
    const retrieved = await repo.getLyricsResult('lyr_neon_01');
    assert.ok(retrieved);
    assert.equal(retrieved.vernacularTermsUsed.length, 2);
    assert.ok(retrieved.storageRef);
    assert.equal(retrieved.storageRef.bucket, 'music-generation-lyrics-prod');
  });

  it('4. Creative output isolation invariant: Creative outputs cannot be ingested as empirical research evidence', async () => {
    // Attempting to save a creative lyrics output as a research SourceRecord must fail!
    const contaminatedRecord: any = {
      id: 'lyr_sample_record',
      sourceOrigin: 'AI_MODEL',
      epistemicState: 'AI_DRAFT',
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
      rawPayloadHash: 'hash123',
    };

    assert.throws(
      () => validateCreativeIsolation(contaminatedRecord),
      (err: any) => {
        assert.equal(err.errorCode, 'CREATIVE_EVIDENCE_CONTAMINATION');
        return true;
      }
    );

    // Attempting to pass it to musicRepo.saveSourceRecord must be rejected
    await assert.rejects(
      async () => musicRepo.saveSourceRecord(contaminatedRecord),
      (err: any) => {
        assert.equal(err.errorCode, 'CREATIVE_EVIDENCE_CONTAMINATION');
        return true;
      }
    );
  });

  it('5. User feedback isolation invariant: Creator sentiment is never promoted to factual research', async () => {
    const validFeedback: GenerationFeedback = {
      id: 'genfb_001',
      generationRecordId: 'genrec_001',
      userId: 'usr_creator_42',
      rating: 5,
      aspectRatings: {
        lyricsQuality: 5,
        musicalAtmosphere: 4,
        promptUsability: 5,
        novelty: 4,
      },
      userNotes: 'The chorus transition is great. Very atmospheric.',
      promotedToResearch: false,
      createdAt: new Date().toISOString(),
    };

    await repo.saveGenerationFeedback(validFeedback);
    const retrieved = await repo.getGenerationFeedback('genfb_001');
    assert.ok(retrieved);
    assert.equal(retrieved.rating, 5);
    assert.equal(retrieved.promotedToResearch, false);

    // Unlawful attempt to promote user feedback into factual research evidence
    const illicitFeedback: any = {
      id: 'genfb_illicit',
      generationRecordId: 'genrec_001',
      userId: 'usr_creator_42',
      rating: 5,
      promotedToResearch: true, // PROHIBITED!
      createdAt: new Date().toISOString(),
    };

    await assert.rejects(
      async () => repo.saveGenerationFeedback(illicitFeedback),
      (err: any) => {
        assert.equal(err.errorCode, 'FEEDBACK_PROMOTION_PROHIBITED');
        return true;
      }
    );
  });

  it('6. Full GenerationRecord lineage assembly with metadata, snapshot lock, and validation', async () => {
    // Save ArtistStyleProfile & evidence
    const profile: ArtistStyleProfile = {
      id: 'asp_synth_retro_01',
      name: 'Cinematic Synthwave Aesthetic',
      version: '1.0.0',
      abstractStyleAesthetic: 'Dystopian neon noir with analog polyphonic textures',
      signatureTechniques: ['Filtered noise sweeps', 'Sidechain pad compression', 'Modal interchange on minor iv'],
      harmonicTendencies: ['i - VI - III - VII', 'i - iv - v - i'],
      grooveProfile: {
        typicalBpmRange: [85, 110],
        swingTendency: 'STRAIGHT',
        drumAesthetic: 'GATED_REVERB_ANALOG',
      },
      lyricThemes: ['DIGITAL_SOLITUDE', 'RETRO_FUTURISM'],
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await repo.saveArtistStyleProfile(profile);

    const profileEvidence: ArtistProfileEvidence = {
      id: 'ape_001',
      artistStyleProfileId: 'asp_synth_retro_01',
      evidenceType: 'OBSERVED_SONG_ANALYSIS',
      sourceRecordId: 'sr_analysis_synth_99',
      citation: 'Cohort Audio Analysis 2026, Section 4.2',
      verified: true,
      createdAt: new Date().toISOString(),
    };
    await repo.saveArtistProfileEvidence(profileEvidence);

    // Save validation
    const validation: GenerationValidation = {
      id: 'genval_001',
      generationRequestId: 'genreq_001',
      lyricsResultId: 'lyr_neon_01',
      soundPromptResultId: 'sndp_valid_01',
      passed: true,
      checks: [
        { checkName: 'ZERO_ARTIST_LEAKAGE', passed: true, details: '0 artist names detected.' },
        { checkName: 'PROMPT_LENGTH_UNDER_1000', passed: true, details: '194/1000 characters used.' },
        { checkName: 'STRUCTURE_CONFORMANCE', passed: true, details: 'Conforms to 8-part spec.' },
      ],
      leakageDetected: false,
      leakageDetails: [],
      validatorVersion: 'val_2.1.0',
      validatedAt: new Date().toISOString(),
    };
    await repo.saveGenerationValidation(validation);

    // Save GenerationRecord with all mandatory fields per Architecture v5.0.0
    const record: GenerationRecord = {
      id: 'genrec_001',
      generationRequestId: 'genreq_001',
      songSpecificationId: 'songspec_001',
      lyricsResultId: 'lyr_neon_01',
      soundPromptResultId: 'sndp_valid_01',
      validationResultId: 'genval_001',
      datasetSnapshotId: 'snap_2026_09_canonical',
      archetypeId: 'arch_synth_ballad_v1',
      archetypeVersion: '1.0.0',
      artistProfileId: 'asp_synth_retro_01',
      artistProfileVersion: '1.0.0',
      promptVersions: {
        lyricsPromptVersion: 'lyr_prompt_v3.2',
        soundPromptVersion: 'snd_prompt_v4.0',
      },
      modelMetadata: {
        provider: 'GOOGLE_GEMINI',
        modelName: 'gemini-1.5-pro',
        temperature: 0.7,
        topP: 0.95,
        seed: 42881,
        modelVersion: 'gemini-1.5-pro-002',
      },
      patternBreakDecisions: [
        {
          aspect: 'CHORUS_ARRIVAL_TIME',
          ruleName: 'RULE_CHORUS_UNDER_60S',
          decision: 'INTENTIONAL_BREAK',
          justification: 'Delayed chorus arrival to 75s to build cinematic atmospheric tension.',
        },
      ],
      validationResult: {
        passed: true,
        leakageFree: true,
        validationScore: 0.98,
        details: 'Zero leakage, full structural and keyword compliance.',
      },
      evidenceManifest: [
        {
          evidenceId: 'ev_groove_metric_92bpm',
          claimOrMetricId: 'metric_synth_tempo_dist',
          description: 'Cohort median tempo 92 bpm with +/- 4 bpm standard deviation.',
          sourceOrigin: 'PROVIDER_API',
        },
      ],
      isCreativeOutput: true,
      epistemicStatus: 'CREATIVE_OUTPUT',
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
    };

    await repo.saveGenerationRecord(record);

    // Resolve complete generation lineage
    const lineage = await repo.resolveGenerationLineage('genrec_001');
    assert.ok(lineage.generationRecord);
    assert.equal(lineage.generationRecord.id, 'genrec_001');
    assert.ok(lineage.generationRequest);
    assert.equal(lineage.generationRequest.id, 'genreq_001');
    assert.ok(lineage.songSpecification);
    assert.equal(lineage.songSpecification.targetBpm, 92);
    assert.ok(lineage.lyricsResult);
    assert.ok(lineage.soundPromptResult);
    assert.ok(lineage.generationValidation);
    assert.equal(lineage.generationValidation.passed, true);
    assert.ok(lineage.artistStyleProfile);
    assert.equal(lineage.artistStyleProfile.name, 'Cinematic Synthwave Aesthetic');
    assert.equal(lineage.artistProfileEvidence.length, 1);
  });

  it('7. Retention semantics: Prevents hard purge of immutable GenerationRecords and supports archiving', async () => {
    // Attempting to hard PURGE an immutable GenerationRecord must throw
    await assert.rejects(
      async () => repo.applyRetentionAction('GenerationRecord', 'PURGE', 'genrec_001'),
      (err: any) => {
        assert.equal(err.errorCode, 'IMMUTABLE_RECORD_PURGE_PROHIBITED');
        return true;
      }
    );

    // ARCHIVE action is permitted and sets status to ARCHIVED
    await repo.applyRetentionAction('GenerationRecord', 'ARCHIVE', 'genrec_001');
    const updated = await repo.getGenerationRecord('genrec_001');
    assert.ok(updated);
    assert.equal(updated.status, 'ARCHIVED');
  });

  it('8. Operations: Jobs, job attempts, locking, and outbox event publishing', async () => {
    // Save job with StorageReference payload
    const job: Job = {
      id: 'job_pipeline_01',
      type: 'SYNTHESIZE_GENERATION_PACKAGE',
      queueName: 'generation_jobs',
      priority: 'HIGH',
      payloadRef: {
        id: 'sref_job_payload_01',
        bucket: 'jobs-payload-store',
        key: 'jobs/job_pipeline_01/payload.json',
        contentType: 'application/json',
        byteSize: 4096,
        sha256Checksum: 'a69f73cca23a9ac5c8b567dc185a756e97a9fbfe',
        accessTier: 'HOT',
        createdAt: new Date().toISOString(),
      },
      payloadMetadata: { requestId: 'genreq_001', priorityLevel: 1 },
      status: 'QUEUED',
      maxAttempts: 3,
      attemptCount: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await repo.saveJob(job);
    const queuedJobs = await repo.listJobs('generation_jobs', 'QUEUED');
    assert.equal(queuedJobs.length, 1);

    // Claim next job
    const claimed = await repo.claimNextJob('generation_jobs', 'worker_cloud_run_01', 30000);
    assert.ok(claimed);
    assert.equal(claimed.status, 'RUNNING');
    assert.equal(claimed.lockedBy, 'worker_cloud_run_01');

    // Save job attempt
    const attempt: JobAttempt = {
      id: 'jba_001',
      jobId: 'job_pipeline_01',
      attemptNumber: 1,
      workerId: 'worker_cloud_run_01',
      status: 'SUCCESS',
      artifactRef: null,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
    };
    await repo.saveJobAttempt(attempt);
    const attempts = await repo.listAttemptsByJob('job_pipeline_01');
    assert.equal(attempts.length, 1);
    assert.equal(attempts[0].status, 'SUCCESS');

    // Outbox event
    const event: OutboxEvent = {
      id: 'obx_gen_completed_01',
      aggregateType: 'GENERATION',
      aggregateId: 'genrec_001',
      eventType: 'GENERATION_RECORD_PUBLISHED',
      payload: { generationRecordId: 'genrec_001' },
      payloadRef: null,
      published: false,
      retryCount: 0,
      createdAt: new Date().toISOString(),
    };
    await repo.saveOutboxEvent(event);
    const unpublished = await repo.listUnpublishedOutboxEvents();
    assert.equal(unpublished.length, 1);

    await repo.markOutboxEventPublished('obx_gen_completed_01');
    const remainingUnpublished = await repo.listUnpublishedOutboxEvents();
    assert.equal(remainingUnpublished.length, 0);
  });

  it('9. Operations: ResearchRuns, WorkflowRuns, AuditEvents, EvaluationRuns, and ReleaseChecks', async () => {
    // Research Run
    const rrun: ResearchRun = {
      id: 'rsr_cohort_001',
      name: 'Global Synthwave Cohort Analysis',
      targetCohortId: 'cohort_synthwave_2020s',
      methodologyVersionId: 'mth_harmonic_v4',
      status: 'COMPLETED',
      datasetSnapshotId: 'snap_2026_09_canonical',
      recordsAnalyzed: 1500,
      metricsComputed: 48,
      storageRef: {
        id: 'sref_rsr_001',
        bucket: 'research-artifacts',
        key: 'runs/rsr_cohort_001/full_report.parquet',
        contentType: 'application/octet-stream',
        byteSize: 1048576,
        sha256Checksum: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        accessTier: 'COLD',
        createdAt: new Date().toISOString(),
      },
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };
    await repo.saveResearchRun(rrun);
    const retrievedRRun = await repo.getResearchRun('rsr_cohort_001');
    assert.ok(retrievedRRun);
    assert.equal(retrievedRRun.recordsAnalyzed, 1500);

    // Workflow Run
    const wfr: WorkflowRun = {
      id: 'wfr_pipeline_01',
      workflowType: 'GENERATION_PIPELINE',
      status: 'SUCCEEDED',
      trigger: 'API',
      context: { userId: 'usr_creator_42' },
      stepSummaries: [
        { stepName: 'VALIDATE_REQUEST', status: 'COMPLETED', startedAt: new Date().toISOString() },
        { stepName: 'GENERATE_SPEC', status: 'COMPLETED', startedAt: new Date().toISOString() },
        { stepName: 'SYNTHESIZE_SOUND_PROMPT', status: 'COMPLETED', startedAt: new Date().toISOString() },
      ],
      storageRef: null,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };
    await repo.saveWorkflowRun(wfr);
    const retrievedWfr = await repo.getWorkflowRun('wfr_pipeline_01');
    assert.ok(retrievedWfr);
    assert.equal(retrievedWfr.status, 'SUCCEEDED');

    // Audit Event
    const aud: AuditEvent = {
      id: 'aud_action_001',
      actorId: 'usr_creator_42',
      actorRole: 'CREATOR',
      action: 'CREATE_GENERATION_RECORD',
      resourceType: 'GenerationRecord',
      resourceId: 'genrec_001',
      details: { model: 'gemini-1.5-pro' },
      timestamp: new Date().toISOString(),
    };
    await repo.saveAuditEvent(aud);
    const audEvents = await repo.listAuditEvents('GenerationRecord', 'genrec_001');
    assert.equal(audEvents.length, 1);

    // Evaluation Run
    const evr: EvaluationRun = {
      id: 'evr_leakage_01',
      name: 'Zero Artist Leakage Benchmark Suite',
      targetType: 'LEAKAGE_ASSURANCE',
      benchmarkVersion: 'bench_v2.0',
      score: 1.0,
      metrics: { falsePositiveRate: 0.0, trueNegativeRate: 1.0 },
      passed: true,
      evaluator: 'automated_leakage_auditor',
      storageRef: null,
      createdAt: new Date().toISOString(),
    };
    await repo.saveEvaluationRun(evr);
    const retrievedEvr = await repo.getEvaluationRun('evr_leakage_01');
    assert.ok(retrievedEvr);
    assert.equal(retrievedEvr.score, 1.0);

    // Release Check
    const rlc: ReleaseCheck = {
      id: 'rlc_p05_verification',
      releaseVersion: '5.0.0',
      checkType: 'PROVENANCE_VERIFICATION',
      passed: true,
      blocking: true,
      evidenceReceiptPath: 'docs/implementation/evidence/P05_RECEIPT.json',
      receiptHash: 'c7b50f7543a6039535f29910d55e8',
      evaluatedAt: new Date().toISOString(),
    };
    await repo.saveReleaseCheck(rlc);
    const retrievedRlc = await repo.getReleaseCheck('rlc_p05_verification');
    assert.ok(retrievedRlc);
    assert.equal(retrievedRlc.passed, true);
  });
});
