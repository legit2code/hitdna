/**
 * P04 Unit & Negative Test Suite: Research, Evidence & Epistemic Persistence
 * Architecture Version: 5.0.0 | Phase: P04
 *
 * Verifies:
 * 1. Independent histories across multiple analysis runs.
 * 2. Three-way Lineage Resolution:
 *    - Metric -> Cohort -> Feature -> Observation -> Source Record -> Provider
 *    - Language Signal -> Vernacular Term -> Observation -> Source Record
 *    - PatternReferenceExample -> Aggregate Archetype -> Member Observations
 * 3. Abstract pattern no-copy rule (clean-room invariant).
 * 4. Epistemic promotion guards (model confidence cannot promote to VERIFIED).
 * 5. Negative tests proving AI-only records cannot masquerade as measured provider values.
 * 6. Statistical metric denominator, coverage, and formula validation.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

function expect(actual: any) {
  return {
    toBe: (expected: any) => assert.equal(actual, expected),
    toHaveLength: (expected: number) => assert.equal(actual.length, expected),
    toThrowError: (regexOrClass?: any) => {
      assert.throws(() => {
        if (typeof actual === 'function') actual();
      }, regexOrClass);
    },
    not: {
      toBe: (expected: any) => assert.notEqual(actual, expected),
    },
  };
}
import { InMemoryMusicRepository } from '../../repositories/musicRepository.js';
import {
  EpistemicState,
  SourceOrigin,
  CohortDefinition,
  CohortMembership,
  AnalysisRun,
  StatisticalMetric,
  AudioFeatureObservation,
  VernacularTerm,
  VernacularObservation,
  LanguageSourceRecord,
  LanguageSignal,
  ChordProgressionPattern,
  HitDnaArchetype,
  PatternReferenceExample,
  ChordHarmonicObservation,
} from '../../contracts/research.js';
import { SourceProvider, SourceRecord, Song } from '../../contracts/persistence.js';
import {
  validateEpistemicPromotion,
  validateSourceOriginCompatibility,
  validateStatisticalMetric,
  validatePatternReferenceExample,
  validateVernacularTerm,
  EpistemicGovernanceError,
} from '../../domain/epistemicGovernance.js';

describe('P04 Research Persistence & Epistemic Governance', () => {
  const repo = new InMemoryMusicRepository(false);

  it('verifies independent histories across two separate analysis runs', async () => {
    // Cohort 1: Hot 100 2024
    const cohort1: CohortDefinition = {
      cohortId: 'coh_pop_2024',
      name: 'Pop Hits 2024',
      genreId: 'gn_pop',
      chartProvider: 'BILLBOARD',
      timeframeStart: '2024-01-01',
      timeframeEnd: '2024-12-31',
      minWeeksOnChart: 10,
      peakRankMax: 10,
      frozenMemberCount: 50,
      isFrozen: true,
      frozenAt: '2025-01-01T00:00:00Z',
      methodologyVersion: 'HD-METH-V1',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await repo.saveCohort(cohort1);

    // Cohort 2: Hot 100 2025
    const cohort2: CohortDefinition = {
      cohortId: 'coh_pop_2025',
      name: 'Pop Hits 2025',
      genreId: 'gn_pop',
      chartProvider: 'BILLBOARD',
      timeframeStart: '2025-01-01',
      timeframeEnd: '2025-12-31',
      minWeeksOnChart: 10,
      peakRankMax: 10,
      frozenMemberCount: 40,
      isFrozen: true,
      frozenAt: '2026-01-01T00:00:00Z',
      methodologyVersion: 'HD-METH-V2',
      createdAt: '2026-01-01T00:00:00Z',
    };
    await repo.saveCohort(cohort2);

    // Run 1
    const run1: AnalysisRun = {
      analysisRunId: 'arun_pop_2024_v1',
      cohortId: cohort1.cohortId,
      taxonomyVersion: '5.0.0',
      methodologyVersion: 'HD-METH-V1',
      promptVersion: null,
      extractorVersion: 'EX-01.v2',
      runStartedAt: '2025-01-02T10:00:00Z',
      runCompletedAt: '2025-01-02T10:15:00Z',
      status: 'COMPLETED',
      sampleCount: 50,
      executionFingerprint: 'sha256_hash_run_1',
      performedBy: 'researcher_1',
    };
    await repo.saveAnalysisRun(run1);

    // Run 2
    const run2: AnalysisRun = {
      analysisRunId: 'arun_pop_2025_v2',
      cohortId: cohort2.cohortId,
      taxonomyVersion: '5.0.0',
      methodologyVersion: 'HD-METH-V2',
      promptVersion: null,
      extractorVersion: 'EX-01.v3',
      runStartedAt: '2026-01-02T10:00:00Z',
      runCompletedAt: '2026-01-02T10:18:00Z',
      status: 'COMPLETED',
      sampleCount: 40,
      executionFingerprint: 'sha256_hash_run_2',
      performedBy: 'researcher_2',
    };
    await repo.saveAnalysisRun(run2);

    // Metric for Run 1
    const metricRun1: StatisticalMetric = {
      metricId: 'smet_tempo_2024',
      analysisRunId: run1.analysisRunId,
      cohortId: cohort1.cohortId,
      featureFamily: 'AUDIO',
      metricName: 'High Energy Up-Tempo Share',
      numerator: 35,
      denominator: 50,
      value: 0.7,
      percentage: 70.0,
      coverageCount: 50,
      coverageRate: 1.0,
      marginOfError: 0.05,
      formula: 'COUNT(tempoBpm >= 120 AND energy >= 0.7) / TOTAL_COHORT',
      calculationVersion: 'HD-03.v1',
      publishability: 'PUBLISHABLE',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'MEASURED',
        observedAt: '2025-01-02T10:15:00Z',
        capturedBy: 'engine_hd03',
        confidence: 1.0,
      },
      calculatedAt: '2025-01-02T10:15:00Z',
    };
    await repo.saveStatisticalMetric(metricRun1);

    // Metric for Run 2
    const metricRun2: StatisticalMetric = {
      metricId: 'smet_tempo_2025',
      analysisRunId: run2.analysisRunId,
      cohortId: cohort2.cohortId,
      featureFamily: 'AUDIO',
      metricName: 'High Energy Up-Tempo Share',
      numerator: 20,
      denominator: 40,
      value: 0.5,
      percentage: 50.0,
      coverageCount: 40,
      coverageRate: 1.0,
      marginOfError: 0.06,
      formula: 'COUNT(tempoBpm >= 120 AND energy >= 0.7) / TOTAL_COHORT',
      calculationVersion: 'HD-03.v2',
      publishability: 'PUBLISHABLE',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'MEASURED',
        observedAt: '2026-01-02T10:18:00Z',
        capturedBy: 'engine_hd03',
        confidence: 1.0,
      },
      calculatedAt: '2026-01-02T10:18:00Z',
    };
    await repo.saveStatisticalMetric(metricRun2);

    const run1Metrics = await repo.getMetricsForAnalysisRun(run1.analysisRunId);
    const run2Metrics = await repo.getMetricsForAnalysisRun(run2.analysisRunId);

    expect(run1Metrics).toHaveLength(1);
    expect(run1Metrics[0].percentage).toBe(70.0);
    expect(run2Metrics).toHaveLength(1);
    expect(run2Metrics[0].percentage).toBe(50.0);
    expect(run1Metrics[0].metricId).not.toBe(run2Metrics[0].metricId);
  });

  it('resolves metric lineage: Metric -> Cohort -> Feature -> Observation -> Source Record -> Provider', async () => {
    // Provider
    const provider: SourceProvider = {
      id: 'sp_provider_spotify',
      name: 'Spotify Web API',
      code: 'SPOTIFY',
      category: 'AUDIO_ANALYSIS',
      enabled: true,
      rateLimitPerMinute: 300,
      requiresAuth: true,
      authType: 'OAUTH2',
      lastHealthCheck: '2025-01-01T00:00:00Z',
      configMetadata: { baseUrl: 'https://api.spotify.com' },
      createdAt: '2025-01-01T00:00:00Z',
    };
    await repo.saveProvider(provider);

    // Source Record
    const sourceRecord: SourceRecord = {
      id: 'sr_track_audio_features_001',
      providerId: provider.id,
      externalId: 'track123',
      recordType: 'AUDIO_ANALYSIS',
      rawPayloadHash: 'sha256_mock_raw_audio_payload_hash_001',
      storageRef: null,
      status: 'ACCEPTED',
      ingestedAt: '2025-01-01T12:00:00Z',
      createdAt: '2025-01-01T12:00:00Z',
    };
    await repo.saveSourceRecord(sourceRecord);

    // Song
    const song: Song = {
      id: 'sng_test_song_001',
      title: 'Midnight Drive',
      isrc: 'USRC12400001',
      primaryArtistId: 'art_artist_001',
      artistIds: ['art_artist_001'],
      releaseDate: '2024-03-15',
      durationMs: 195000,
      explicit: false,
      status: 'ACTIVE',
      storageRefs: [],
      createdAt: '2025-01-01T12:00:00Z',
      updatedAt: '2025-01-01T12:00:00Z',
    };
    await repo.saveSong(song);

    // Audio Feature Observation
    const audioObs: AudioFeatureObservation = {
      observationId: 'afo_song_001',
      songId: song.id,
      sourceRecordId: sourceRecord.id,
      key: 'F#',
      scaleMode: 'MINOR',
      tempoBpm: 124,
      dynamicRangeDb: -6.5,
      loudnessLufs: -5.4,
      acousticness: 0.12,
      energy: 0.85,
      danceability: 0.78,
      valence: 0.62,
      instrumentalness: 0.01,
      durationMs: 195000,
      provenance: {
        sourceOrigin: 'EXTERNAL_PROVIDER',
        sourceProviderId: provider.id,
        sourceRecordId: sourceRecord.id,
        epistemicState: 'OBSERVED',
        observedAt: '2025-01-01T12:00:00Z',
        capturedBy: 'RI-01-connector',
        confidence: 1.0,
      },
    };
    await repo.saveAudioFeature(audioObs);

    // Cohort
    const cohort: CohortDefinition = {
      cohortId: 'coh_synth_pop_2024',
      name: 'Synth Pop 2024 Cohort',
      genreId: 'gn_pop_dance',
      chartProvider: 'SPOTIFY_CHARTS',
      timeframeStart: '2024-01-01',
      timeframeEnd: '2024-12-31',
      minWeeksOnChart: 8,
      peakRankMax: 20,
      frozenMemberCount: 1,
      isFrozen: true,
      frozenAt: '2025-01-01T00:00:00Z',
      methodologyVersion: 'HD-METH-V1',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await repo.saveCohort(cohort);

    // Membership
    const membership: CohortMembership = {
      membershipId: 'cmem_001',
      cohortId: cohort.cohortId,
      songId: song.id,
      rankAchieved: 4,
      weeksAchieved: 12,
      isQualified: true,
      addedAt: '2025-01-01T00:00:00Z',
    };
    await repo.saveCohortMembership(membership);

    // Analysis Run
    const run: AnalysisRun = {
      analysisRunId: 'arun_synth_2024',
      cohortId: cohort.cohortId,
      taxonomyVersion: '5.0.0',
      methodologyVersion: 'HD-METH-V1',
      promptVersion: null,
      extractorVersion: 'EX-01.v2',
      runStartedAt: '2025-01-02T10:00:00Z',
      runCompletedAt: '2025-01-02T10:05:00Z',
      status: 'COMPLETED',
      sampleCount: 1,
      executionFingerprint: 'sha256_fp_synth_2024',
      performedBy: 'researcher_1',
    };
    await repo.saveAnalysisRun(run);

    // Metric
    const metric: StatisticalMetric = {
      metricId: 'smet_danceability_synth',
      analysisRunId: run.analysisRunId,
      cohortId: cohort.cohortId,
      featureFamily: 'AUDIO',
      metricName: 'Danceability >= 0.70 Share',
      numerator: 1,
      denominator: 1,
      value: 1.0,
      percentage: 100.0,
      coverageCount: 1,
      coverageRate: 1.0,
      marginOfError: 0.0,
      formula: 'COUNT(danceability >= 0.70) / TOTAL_COHORT',
      calculationVersion: 'HD-03.v1',
      publishability: 'PUBLISHABLE',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'MEASURED',
        observedAt: '2025-01-02T10:05:00Z',
        capturedBy: 'engine_hd03',
        confidence: 1.0,
      },
      calculatedAt: '2025-01-02T10:05:00Z',
    };
    await repo.saveStatisticalMetric(metric);

    // Resolve Lineage
    const lineage = await repo.resolveMetricLineage(metric.metricId);
    expect(lineage.resolutionStatus).toBe('FULLY_RESOLVED');
    expect(lineage.metric.metricId).toBe(metric.metricId);
    expect(lineage.cohort.cohortId).toBe(cohort.cohortId);
    expect(lineage.analysisRun.analysisRunId).toBe(run.analysisRunId);
    expect(lineage.featureObservations).toHaveLength(1);
    expect(lineage.featureObservations[0].observationId).toBe(audioObs.observationId);
    expect(lineage.sourceRecords).toHaveLength(1);
    expect(lineage.sourceRecords[0].id).toBe(sourceRecord.id);
    expect(lineage.providers).toHaveLength(1);
    expect(lineage.providers[0].code).toBe('SPOTIFY');
    expect(lineage.verifications.denominatorFrozen).toBe(true);
    expect(lineage.verifications.reproducibleCalculation).toBe(true);
  });

  it('resolves language signal lineage: Signal -> Term -> Observation -> Source Record', async () => {
    const provider: SourceProvider = {
      id: 'sp_provider_lexicon',
      name: 'Authorized Contemporary Lyric Lexicon',
      code: 'LEXICON_CORPUS',
      category: 'LYRICS',
      enabled: true,
      rateLimitPerMinute: 60,
      requiresAuth: true,
      authType: 'API_KEY',
      lastHealthCheck: '2025-01-01T00:00:00Z',
      configMetadata: { baseUrl: 'https://lexicon.corpus.internal' },
      createdAt: '2025-01-01T00:00:00Z',
    };
    await repo.saveProvider(provider);

    const sourceRecord: SourceRecord = {
      id: 'sr_vernacular_record_001',
      providerId: provider.id,
      externalId: 'slang_locked_in',
      recordType: 'LYRICS_TEXT',
      rawPayloadHash: 'sha256_locked_in_payload_hash',
      storageRef: null,
      status: 'ACCEPTED',
      ingestedAt: '2026-01-10T14:00:00Z',
      createdAt: '2026-01-10T14:00:00Z',
    };
    await repo.saveSourceRecord(sourceRecord);

    const term: VernacularTerm = {
      termId: 'vt_locked_in',
      term: 'locked in',
      canonicalMeaning: 'Intensely focused and operating at peak productivity or flow state',
      regionSceneContext: ['Internet Culture', 'Hip Hop Scene'],
      genreContext: ['gn_root_hip_hop', 'gn_pop'],
      firstObservedDate: '2022-04-01',
      lastObservedDate: '2026-01-10',
      trajectory: 'PEAK',
      frequencyPerMillionWords: 142.5,
      authoritySource: 'Curated Lexicon Corpus v5',
      reviewState: 'HUMAN_REVIEWED',
      generationEligibility: true,
      explicitness: 'CLEAN',
      provenance: {
        sourceOrigin: 'HUMAN_RESEARCHER',
        sourceProviderId: provider.id,
        sourceRecordId: sourceRecord.id,
        epistemicState: 'HUMAN_REVIEWED',
        observedAt: '2026-01-10T14:00:00Z',
        capturedBy: 'researcher_mary',
        reviewedBy: 'researcher_mary',
        confidence: 0.98,
      },
      createdAt: '2026-01-10T14:00:00Z',
      updatedAt: '2026-01-10T14:00:00Z',
    };
    await repo.saveVernacularTerm(term);

    const observation: VernacularObservation = {
      observationId: 'vto_locked_in_001',
      termId: term.termId,
      sourceRecordId: sourceRecord.id,
      sourceType: 'REVIEWED_LEXICON',
      songId: null,
      sentenceContext: 'We been in the studio all night, completely locked in on the bridge.',
      confidence: 0.95,
      provenance: {
        sourceOrigin: 'HUMAN_RESEARCHER',
        sourceRecordId: sourceRecord.id,
        epistemicState: 'OBSERVED',
        observedAt: '2026-01-10T14:00:00Z',
        capturedBy: 'researcher_mary',
        confidence: 0.95,
      },
    };
    await repo.saveVernacularObservation(observation);

    const signal: LanguageSignal = {
      signalId: 'lsig_locked_in_2026q1',
      termId: term.termId,
      timeWindow: '2026-Q1',
      occurrenceCount: 85,
      velocity: 1.45,
      genreContext: 'gn_root_hip_hop',
      analysisRunId: 'arun_lang_2026_q1',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'MEASURED',
        observedAt: '2026-01-10T14:00:00Z',
        capturedBy: 'MI-08-language-engine',
        confidence: 0.96,
      },
    };
    await repo.saveLanguageSignal(signal);

    const lineage = await repo.resolveLanguageSignalLineage(signal.signalId);
    expect(lineage.resolutionStatus).toBe('FULLY_RESOLVED');
    expect(lineage.term.term).toBe('locked in');
    expect(lineage.observations).toHaveLength(1);
    expect(lineage.sourceRecords).toHaveLength(1);
    expect(lineage.providers[0].code).toBe('LEXICON_CORPUS');
    expect(lineage.verifications.permittedSourceConfirmed).toBe(true);
  });

  it('resolves pattern reference example lineage and enforces clean-room no-copy invariant', async () => {
    const cohort: CohortDefinition = {
      cohortId: 'coh_anthem_rock_2024',
      name: 'Anthem Rock 2024',
      genreId: 'gn_rock',
      chartProvider: 'BILLBOARD_MAINSTREAM_ROCK',
      timeframeStart: '2024-01-01',
      timeframeEnd: '2024-12-31',
      minWeeksOnChart: 12,
      peakRankMax: 10,
      frozenMemberCount: 25,
      isFrozen: true,
      frozenAt: '2025-01-01T00:00:00Z',
      methodologyVersion: 'HD-METH-V1',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await repo.saveCohort(cohort);

    const run: AnalysisRun = {
      analysisRunId: 'arun_rock_2024',
      cohortId: cohort.cohortId,
      taxonomyVersion: '5.0.0',
      methodologyVersion: 'HD-METH-V1',
      promptVersion: null,
      extractorVersion: 'EX-02.v1',
      runStartedAt: '2025-01-05T08:00:00Z',
      runCompletedAt: '2025-01-05T08:20:00Z',
      status: 'COMPLETED',
      sampleCount: 25,
      executionFingerprint: 'sha256_rock_2024_fp',
      performedBy: 'researcher_paul',
    };
    await repo.saveAnalysisRun(run);

    const archetype: HitDnaArchetype = {
      archetypeId: 'arch_anthemic_power_chord_01',
      clusterRunId: 'crun_rock_k3',
      cohortId: cohort.cohortId,
      archetypeCode: 'ROCK_ANTHEM_01',
      humanLabel: 'Driving Four-Chord Mid-Tempo Rock Anthem',
      memberCount: 16,
      cohortSharePercentage: 64.0,
      distinctiveFeatures: {
        tempoBpm: { mean: 122, stdDev: 4.5, median: 120 },
        distortionRmsDb: { mean: -4.2, stdDev: 0.8, median: -4.0 },
      },
      methodologyVersion: 'HD-METH-V1',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'DERIVED',
        observedAt: '2025-01-05T08:20:00Z',
        capturedBy: 'HD-05-cluster-engine',
        confidence: 0.94,
      },
    };
    await repo.saveHitDnaArchetype(archetype);

    // Valid abstract pattern reference example
    const validExample: PatternReferenceExample = {
      exampleId: 'pre_rock_axis_01',
      patternId: 'cpp_axis_progression',
      patternType: 'CHORD',
      archetypeId: archetype.archetypeId,
      abstractTemplate: 'I - V - vi - IV (Relative Roman Numeral Harmonic Pace: 1 bar/chord)',
      transpositionAnchor: 'Relative to Major Key Tonic I',
      isAggregateMeasured: true,
      containsCopiedMelody: false, // Strict invariant
      analysisRunId: run.analysisRunId,
      methodologyVersion: 'HD-METH-V1',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'MEASURED',
        observedAt: '2025-01-05T08:20:00Z',
        capturedBy: 'MI-10-pattern-engine',
        confidence: 1.0,
      },
    };
    await repo.savePatternReferenceExample(validExample);

    const lineage = await repo.resolvePatternReferenceLineage(validExample.exampleId);
    expect(lineage.resolutionStatus).toBe('FULLY_RESOLVED');
    expect(lineage.example.isAggregateMeasured).toBe(true);
    expect(lineage.verifications.zeroCopiedMelodyPassages).toBe(true);

    // NEGATIVE TEST: Copied melody violation MUST fail
    const infringingExample: PatternReferenceExample = {
      ...validExample,
      exampleId: 'pre_infringing_01',
      containsCopiedMelody: true, // VIOLATION!
    };
    expect(() => validatePatternReferenceExample(infringingExample)).toThrowError(
      EpistemicGovernanceError
    );

    // NEGATIVE TEST: Non-aggregate pattern cannot be published as Hit DNA pattern
    const singleSongExample: PatternReferenceExample = {
      ...validExample,
      exampleId: 'pre_single_song_01',
      isAggregateMeasured: false, // VIOLATION!
    };
    expect(() => validatePatternReferenceExample(singleSongExample)).toThrowError(
      EpistemicGovernanceError
    );
  });

  it('enforces that AI-derived records cannot be promoted to VERIFIED by model confidence alone', () => {
    // Attempt promotion by autonomous AI agent
    expect(() =>
      validateEpistemicPromotion(
        'AI_DRAFT',
        'VERIFIED',
        {
          actorId: 'agent_gemini_flash',
          role: 'AI_AGENT',
          hasHumanReview: false,
          hasEmpiricalEvidence: false,
          auditNote: 'Model confidence is 0.99',
        },
        {
          sourceOrigin: 'AI_MODEL',
          epistemicState: 'AI_DRAFT',
          observedAt: '2026-01-01T00:00:00Z',
          capturedBy: 'gemini_agent',
          confidence: 0.99,
        }
      )
    ).toThrowError(/Autonomous AI agents cannot promote records to VERIFIED state/);

    // Attempt promotion by human researcher without review/evidence
    expect(() =>
      validateEpistemicPromotion(
        'AI_CLASSIFIED',
        'VERIFIED',
        {
          actorId: 'admin_user',
          role: 'ADMIN',
          hasHumanReview: false,
          hasEmpiricalEvidence: false,
          auditNote: 'Looks confident enough',
        },
        {
          sourceOrigin: 'AI_MODEL',
          epistemicState: 'AI_CLASSIFIED',
          observedAt: '2026-01-01T00:00:00Z',
          capturedBy: 'gemini_agent',
          confidence: 0.99,
        }
      )
    ).toThrowError(/AI-derived records cannot be promoted to VERIFIED based solely on model confidence/);

    // Legitimate promotion by human researcher WITH review
    const validPromotion = validateEpistemicPromotion(
      'AI_CLASSIFIED',
      'VERIFIED',
      {
        actorId: 'musicologist_dave',
        role: 'RESEARCHER',
        hasHumanReview: true,
        hasEmpiricalEvidence: true,
        auditNote: 'Independently audited against audio stems and multi-source sheet music',
      },
      {
        sourceOrigin: 'AI_MODEL',
        epistemicState: 'AI_CLASSIFIED',
        observedAt: '2026-01-01T00:00:00Z',
        capturedBy: 'gemini_agent',
        confidence: 0.99,
      }
    );
    expect(validPromotion.success).toBe(true);
  });

  it('negative test: AI-only record cannot masquerade as measured provider value', () => {
    expect(() => validateSourceOriginCompatibility('AI_MODEL', 'MEASURED')).toThrowError(
      EpistemicGovernanceError
    );

    expect(() => validateSourceOriginCompatibility('AI_MODEL', 'SOURCE_REPORTED')).toThrowError(
      EpistemicGovernanceError
    );

    expect(() => validateSourceOriginCompatibility('AI_MODEL', 'OBSERVED')).toThrowError(
      EpistemicGovernanceError
    );

    expect(() => validateSourceOriginCompatibility('COMMUNITY_IMPORT', 'MEASURED')).toThrowError(
      EpistemicGovernanceError
    );
  });

  it('validates statistical metric denominator, formula, and value/percentage consistency', () => {
    // Denominator zero violation
    const invalidDenominator: StatisticalMetric = {
      metricId: 'smet_invalid_denom',
      analysisRunId: 'arun_test',
      cohortId: 'coh_test',
      featureFamily: 'AUDIO',
      metricName: 'Invalid Denom Metric',
      numerator: 5,
      denominator: 0, // INVALID!
      value: 0,
      percentage: 0,
      coverageCount: 0,
      coverageRate: 0,
      marginOfError: 0,
      formula: 'COUNT(x)/TOTAL',
      calculationVersion: 'v1',
      publishability: 'INTERNAL_ONLY',
      provenance: {
        sourceOrigin: 'AGGREGATE_CALCULATION',
        epistemicState: 'MEASURED',
        observedAt: '2026-01-01T00:00:00Z',
        capturedBy: 'test',
        confidence: 1,
      },
      calculatedAt: '2026-01-01T00:00:00Z',
    };
    expect(() => validateStatisticalMetric(invalidDenominator)).toThrowError(
      /has invalid denominator/
    );

    // Numerator > Denominator violation
    const invalidNumerator: StatisticalMetric = {
      ...invalidDenominator,
      denominator: 10,
      numerator: 15, // INVALID!
      value: 1.5,
      percentage: 150,
    };
    expect(() => validateStatisticalMetric(invalidNumerator)).toThrowError(
      /numerator \(15\) exceeds cohort denominator \(10\)/
    );

    // Missing formula violation
    const missingFormula: StatisticalMetric = {
      ...invalidDenominator,
      denominator: 10,
      numerator: 5,
      value: 0.5,
      percentage: 50.0,
      coverageCount: 10,
      formula: '', // INVALID!
    };
    expect(() => validateStatisticalMetric(missingFormula)).toThrowError(
      /missing required formula specification/
    );
  });
});
