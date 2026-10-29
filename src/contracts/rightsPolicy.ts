/**
 * Rights, Licensing & Source Policy Contracts
 * Engine: RI-09 (Rights, Licensing & Source Policy Engine)
 * Architecture Version: 5.0.0 | Phase: P04
 *
 * Mandatory Rights & Policy Boundaries:
 * 1. Unauthorized scraping of lyrics or media is strictly prohibited.
 * 2. Snippet lengths must adhere to statutory fair use / authorized quotas.
 * 3. Raw audio storage is prohibited unless explicitly authorized under clean licensing.
 * 4. Clean-room verification: abstract style generation must not leak protected melody,
 *    copyrighted lyrics, or real artist names.
 */

export type StoragePolicyTier =
  | 'METADATA_ONLY'        // Permitted to store title, artist, ISRC, release date, durations
  | 'ANALYTICS_ONLY'       // Permitted to store calculated numeric features and aggregate stats
  | 'EXCERPT_LIMITED'      // Permitted to store short excerpts up to maxSnippetLengthChars
  | 'FULL_ARCHIVE_LICENSED'// Fully licensed storage of full lyric/analysis payload
  | 'PROHIBITED';          // Storage strictly forbidden

export interface SourcePolicyDefinition {
  policyId: string; // rpol_...
  sourceProviderId: string; // Provider ID or code (e.g. "SPOTIFY", "GENIUS", "BILLBOARD")
  providerName: string;
  storageTier: StoragePolicyTier;
  maxExcerptLengthChars: number;
  allowAudioWaveformStorage: boolean;
  allowAudioStemStorage: boolean;
  allowLyricsIngestion: boolean;
  prohibitUnauthorizedScraping: boolean; // Always true
  requiresAttribution: boolean;
  attributionStatement: string | null;
  policyVersion: string;
  effectiveDate: string;
  reviewedBy: string;
}

export interface CleanRoomAudit {
  auditId: string; // cra_...
  targetEntityId: string;
  targetEntityType: 'SONG' | 'PATTERN' | 'GENERATION_BRIEF' | 'PROMPT';
  hasDirectMelodyCopy: boolean; // Must be false
  hasDirectLyricsInfringement: boolean; // Must be false
  hasArtistNameLeakage: boolean; // Must be false (AR-05)
  passed: boolean;
  auditorActorId: string;
  auditedAt: string;
  notes: string;
}
