/**
 * Core Registries: Language Sources, Pattern Extractors & Version Governance
 * Engine: PF-09 (Version, Prompt & Methodology Governance)
 * Architecture Version: 5.0.0 | Phase: P03
 *
 * Constitution Invariant:
 * Centralizes permitted research sources, pattern extractors, and methodology versions
 * so later phases do not scatter raw strings, unvetted sources, or model IDs across the codebase.
 */

export interface LanguageSourceTypeDefinition {
  code: string;
  name: string;
  category: 'EDITORIAL' | 'ANNOTATION' | 'INTERVIEW' | 'LEXICON' | 'COMMUNITY';
  permitted: boolean;
  requiresConsent: boolean;
  freshnessCadenceDays: number;
  description: string;
}

export const LANGUAGE_SOURCE_REGISTRY: Record<string, LanguageSourceTypeDefinition> = {
  LYRICS_ANNOTATION: {
    code: 'LYRICS_ANNOTATION',
    name: 'Licensed Lyrics & Verified Annotations',
    category: 'ANNOTATION',
    permitted: true,
    requiresConsent: false,
    freshnessCadenceDays: 7,
    description: 'Authorized lyric transcriptions and verified line-by-line annotations from licensed platforms.',
  },
  ARTIST_INTERVIEWS: {
    code: 'ARTIST_INTERVIEWS',
    name: 'Primary Artist Interview Transcripts',
    category: 'INTERVIEW',
    permitted: true,
    requiresConsent: false,
    freshnessCadenceDays: 30,
    description: 'Direct audio/video interview transcriptions providing first-person vernacular and era phrasing context.',
  },
  CULTURAL_COMMENTARY: {
    code: 'CULTURAL_COMMENTARY',
    name: 'Cultural Music Commentary & Essays',
    category: 'EDITORIAL',
    permitted: true,
    requiresConsent: false,
    freshnessCadenceDays: 14,
    description: 'In-depth essays from musicologists and cultural commentators documenting slang origins and genre movements.',
  },
  MUSIC_JOURNALISM: {
    code: 'MUSIC_JOURNALISM',
    name: 'Accredited Music Journalism',
    category: 'EDITORIAL',
    permitted: true,
    requiresConsent: false,
    freshnessCadenceDays: 7,
    description: 'Articles, reviews, and features from accredited trade and music publications.',
  },
  COLLOQUIAL_DICTIONARIES: {
    code: 'COLLOQUIAL_DICTIONARIES',
    name: 'Colloquial & Vernacular Lexicons',
    category: 'LEXICON',
    permitted: true,
    requiresConsent: false,
    freshnessCadenceDays: 14,
    description: 'Reviewed modern vernacular dictionaries documenting slang meanings, region of origin, and temporal shelf-life.',
  },
  UNAUTHORIZED_SCRAPING: {
    code: 'UNAUTHORIZED_SCRAPING',
    name: 'Unauthorized Web Scraping',
    category: 'COMMUNITY',
    permitted: false, // Strictly prohibited by P00 Constitution
    requiresConsent: true,
    freshnessCadenceDays: 0,
    description: 'Prohibited arbitrary web scraping without license or terms compliance.',
  },
};

export interface PatternExtractorDefinition {
  code: string;
  name: string;
  version: string;
  targetFeature: string;
  determinismGuarantee: 'STRICT_DETERMINISTIC' | 'HEURISTIC_DETERMINISTIC' | 'AI_ASSISTED_REVIEWED';
  supportedAudioFormats: string[];
  description: string;
}

export const PATTERN_EXTRACTOR_REGISTRY: Record<string, PatternExtractorDefinition> = {
  CHORD_PROGRESSION_EXTRACTOR: {
    code: 'CHORD_PROGRESSION_EXTRACTOR',
    name: 'Harmonic Chord Progression Extractor',
    version: '1.2.0',
    targetFeature: 'HARMONIC_CHORD_SEQUENCE',
    determinismGuarantee: 'STRICT_DETERMINISTIC',
    supportedAudioFormats: ['wav', 'flac', 'mp3', 'midi'],
    description: 'Extracts transposable chord numerals (e.g. I-V-vi-IV) and harmonic rhythm timing.',
  },
  RHYTHM_GROOVE_EXTRACTOR: {
    code: 'RHYTHM_GROOVE_EXTRACTOR',
    name: 'Rhythm Pocket & Groove Quantization Extractor',
    version: '1.1.0',
    targetFeature: 'RHYTHM_SWING_POCKET',
    determinismGuarantee: 'STRICT_DETERMINISTIC',
    supportedAudioFormats: ['wav', 'flac', 'mp3'],
    description: 'Analyzes microtiming offsets, syncopation ratio, and drum grid subdivisions.',
  },
  ARRANGEMENT_STRUCTURE_EXTRACTOR: {
    code: 'ARRANGEMENT_STRUCTURE_EXTRACTOR',
    name: 'Arrangement & Section Boundary Extractor',
    version: '2.0.0',
    targetFeature: 'SECTION_TIMINGS_AND_DYNAMICS',
    determinismGuarantee: 'HEURISTIC_DETERMINISTIC',
    supportedAudioFormats: ['wav', 'flac', 'mp3'],
    description: 'Identifies intro, verse, pre-chorus, chorus, bridge, drop, and outro timestamps and bar counts.',
  },
  VOCAL_DELIVERY_EXTRACTOR: {
    code: 'VOCAL_DELIVERY_EXTRACTOR',
    name: 'Vocal Cadence & Syllabic Density Extractor',
    version: '1.0.0',
    targetFeature: 'VOCAL_CADENCE_METRICS',
    determinismGuarantee: 'HEURISTIC_DETERMINISTIC',
    supportedAudioFormats: ['wav', 'flac', 'mp3'],
    description: 'Measures syllables per second, rhyme density, and melody-vs-speech delivery ratio.',
  },
  TONAL_HARMONY_EXTRACTOR: {
    code: 'TONAL_HARMONY_EXTRACTOR',
    name: 'Tonal Center & Mode Detection Extractor',
    version: '1.0.0',
    targetFeature: 'KEY_SCALE_MODE',
    determinismGuarantee: 'STRICT_DETERMINISTIC',
    supportedAudioFormats: ['wav', 'flac', 'mp3', 'midi'],
    description: 'Detects musical key, scale mode (Aeolian, Dorian, Major, etc.), and pitch distribution.',
  },
};

export interface RegisteredMethodology {
  id: string;
  version: string;
  name: string;
  effectiveDate: string;
  confidenceThreshold: number;
  description: string;
  active: boolean;
}

export const METHODOLOGY_VERSION_CATALOG: RegisteredMethodology[] = [
  {
    id: 'mv_hit_dna_5_0_0',
    version: '5.0.0',
    name: 'Hit DNA Canonical Analysis Methodology v5',
    effectiveDate: '2026-09-01T00:00:00Z',
    confidenceThreshold: 0.95,
    description: 'Canonical 7-domain statistical analysis with denominator-first reporting and multi-archetype clustering.',
    active: true,
  },
  {
    id: 'mv_hit_dna_4_2_0',
    version: '4.2.0',
    name: 'Hit DNA Analysis Methodology v4.2 (Legacy)',
    effectiveDate: '2025-06-01T00:00:00Z',
    confidenceThreshold: 0.90,
    description: 'Previous generation methodology without multi-archetype cluster separation.',
    active: false,
  },
];
