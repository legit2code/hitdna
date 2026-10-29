/**
 * Lineage Resolver & Provenance Resolution Engine
 * Engines: PF-04, PF-09, HD-01, HD-02, MI-08, MI-10
 * Architecture Version: 5.0.0 | Phase: P04
 *
 * Implements end-to-end provenance resolution:
 * 1. Metric -> Cohort -> Feature Observation -> Source Record -> Provider
 * 2. Language Signal -> Vernacular Term -> Vernacular Observation -> Source
 * 3. PatternReferenceExample -> Aggregate Metric / Archetype -> Member Observations
 */

import {
  StatisticalMetric,
  CohortDefinition,
  CohortMembership,
  AnalysisRun,
  VernacularTerm,
  VernacularObservation,
  LanguageSignal,
  PatternReferenceExample,
  HitDnaArchetype,
  AudioFeatureObservation,
  StructureFeatureObservation,
  HookFeatureObservation,
  ChordHarmonicObservation,
} from '../contracts/research.js';

import { SourceRecord, SourceProvider, Song } from '../contracts/persistence.js';

export interface MetricLineageResult {
  metric: StatisticalMetric;
  cohort: CohortDefinition;
  analysisRun: AnalysisRun;
  memberships: CohortMembership[];
  sampleSongs: Song[];
  featureObservations: Array<
    | AudioFeatureObservation
    | StructureFeatureObservation
    | HookFeatureObservation
    | ChordHarmonicObservation
  >;
  sourceRecords: SourceRecord[];
  providers: SourceProvider[];
  resolutionStatus: 'FULLY_RESOLVED' | 'PARTIALLY_RESOLVED' | 'UNRESOLVABLE';
  verifications: {
    denominatorFrozen: boolean;
    hasSourceLineage: boolean;
    coverageDisclosed: boolean;
    reproducibleCalculation: boolean;
  };
}

export interface LanguageSignalLineageResult {
  signal: LanguageSignal;
  term: VernacularTerm;
  observations: VernacularObservation[];
  sourceRecords: SourceRecord[];
  providers: SourceProvider[];
  resolutionStatus: 'FULLY_RESOLVED' | 'PARTIALLY_RESOLVED' | 'UNRESOLVABLE';
  verifications: {
    permittedSourceConfirmed: boolean;
    noUnauthorizedScraping: boolean;
    reviewStateDisclosed: boolean;
  };
}

export interface PatternReferenceLineageResult {
  example: PatternReferenceExample;
  archetype: HitDnaArchetype;
  analysisRun: AnalysisRun;
  cohort: CohortDefinition;
  memberSongIds: string[];
  sampleObservations: Array<ChordHarmonicObservation | AudioFeatureObservation>;
  resolutionStatus: 'FULLY_RESOLVED' | 'PARTIALLY_RESOLVED' | 'UNRESOLVABLE';
  verifications: {
    isAggregateMeasured: boolean;
    zeroCopiedMelodyPassages: boolean;
    abstractTranspositionTemplateValid: boolean;
  };
}
