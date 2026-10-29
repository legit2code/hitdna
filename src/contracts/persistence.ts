/**
 * Persistence & Data Model Contracts
 * Engine: PF-04 (Canonical Music Data Model & Repository Engine)
 * Architecture Version: 5.0.0 | Phase: P03
 *
 * Adheres strictly to the P00 Master Build Constitution:
 * - Stable internal IDs separate from provider-scoped external identifiers
 * - Immutable raw references, hashes, and UTC timestamps
 * - Object storage references for large artifacts
 * - First-class genre graph models (NO canonical song.genre string!)
 */

export type UserRole = 'ADMIN' | 'RESEARCHER' | 'CREATOR' | 'SYSTEM';
export type UserStatus = 'ACTIVE' | 'SUSPENDED';

export interface User {
  id: string; // e.g. usr_01H...
  email: string;
  displayName: string;
  role: UserRole;
  status: UserStatus;
  createdAt: string; // UTC ISO-8601
  updatedAt: string; // UTC ISO-8601
}

export type ProviderCategory = 'METADATA' | 'CHART' | 'LYRICS' | 'AUDIO_ANALYSIS' | 'INFERENCE';
export type ProviderAuthType = 'API_KEY' | 'OAUTH2' | 'BASIC' | 'NONE';

export interface SourceProvider {
  id: string; // e.g. sp_spotify
  code: string; // SPOTIFY, BILLBOARD, GENIUS, SOUNDCHARTS, GEMINI
  name: string;
  category: ProviderCategory;
  enabled: boolean;
  rateLimitPerMinute: number;
  requiresAuth: boolean;
  authType: ProviderAuthType;
  lastHealthCheck: string | null;
  configMetadata: Record<string, unknown>;
  createdAt: string;
}

export type SourceRecordType = 'TRACK_METADATA' | 'CHART_ENTRY' | 'LYRICS_TEXT' | 'AUDIO_ANALYSIS' | 'ARTIST_METADATA';
export type SourceRecordStatus = 'ACCEPTED' | 'REJECTED' | 'PENDING_REVIEW';

export interface StorageReference {
  id: string; // stg_...
  bucket: string;
  key: string;
  sha256Checksum: string;
  byteSize: number;
  contentType: string;
  accessTier: 'HOT' | 'COLD' | 'ARCHIVE';
  createdAt: string;
}

export interface SourceRecord {
  id: string; // sr_...
  providerId: string;
  externalId: string;
  recordType: SourceRecordType;
  rawPayloadHash: string; // SHA-256 of raw received payload
  storageRef: StorageReference | null;
  status: SourceRecordStatus;
  ingestedAt: string;
  createdAt: string;
}

export type ObservationEntityType = 'SONG' | 'ARTIST' | 'CHART';

export interface SourceObservation {
  id: string; // so_...
  sourceRecordId: string;
  providerId: string;
  entityType: ObservationEntityType;
  entityId: string; // internal entity ID
  observationType: string;
  observedAt: string;
  payload: Record<string, unknown>;
  confidence: number; // 0.0 to 1.0
  createdAt: string;
}

export type SongStatus = 'ACTIVE' | 'PROVISIONAL' | 'ARCHIVED';

/**
 * Song Entity
 * CRITICAL ARCHITECTURAL INVARIANT:
 * songs do NOT have a `genre: string` property.
 * All genre relationships are modeled via SongGenreAssignment and GenreNode.
 */
export interface Song {
  id: string; // song_... stable internal ID
  title: string;
  primaryArtistId: string;
  artistIds: string[];
  isrc: string | null; // International Standard Recording Code
  releaseDate: string | null;
  durationMs: number | null;
  explicit: boolean;
  status: SongStatus;
  storageRefs: StorageReference[];
  createdAt: string;
  updatedAt: string;
}

export interface SongAlias {
  id: string; // sga_...
  songId: string;
  alias: string;
  providerId: string | null;
  externalId: string | null;
  confidence: number;
  source: string;
  createdAt: string;
}

export type ArtistStatus = 'ACTIVE' | 'PROVISIONAL' | 'ARCHIVED';

export interface Artist {
  id: string; // art_... stable internal ID
  name: string;
  stageName: string;
  isni: string | null; // International Standard Name Identifier
  country: string | null;
  debutYear: number | null;
  status: ArtistStatus;
  createdAt: string;
  updatedAt: string;
}

export interface ArtistAlias {
  id: string; // ara_...
  artistId: string;
  alias: string;
  providerId: string | null;
  externalId: string | null;
  source: string;
  createdAt: string;
}

export interface ChartObservation {
  id: string; // co_...
  songId: string;
  chartProvider: string;
  chartName: string;
  chartDate: string; // YYYY-MM-DD
  rank: number;
  peakRank: number;
  weeksOnChart: number;
  entryRank: number;
  isNew: boolean;
  sourceRecordId: string;
  observedAt: string;
  createdAt: string;
}

export type VersionStatus = 'DRAFT' | 'ACTIVE' | 'ARCHIVED';

export interface DatasetVersion {
  id: string; // ds_...
  version: string;
  name: string;
  description: string;
  recordCount: number;
  snapshotHash: string;
  storageRef: StorageReference | null;
  status: VersionStatus;
  publishedAt: string | null;
  createdAt: string;
}

export interface MethodologyVersion {
  id: string; // mv_...
  version: string;
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  active: boolean;
  activatedAt: string;
  createdAt: string;
}

export interface PromptVersion {
  id: string; // pv_...
  promptId: string;
  version: string;
  category: string;
  template: string;
  requiredVariables: string[];
  createdBy: string;
  createdAt: string;
}

export interface ApplicationSetting {
  id: string; // cfg_...
  key: string;
  value: unknown;
  description: string;
  updatedBy: string;
  updatedAt: string;
}

export interface AuditVersionRegistry {
  id: string; // aud_...
  entityType: string;
  entityId: string;
  changeType: 'CREATE' | 'UPDATE' | 'DELETE' | 'ACTIVATE' | 'ARCHIVE';
  changes: Record<string, { before: unknown; after: unknown }>;
  performedBy: string;
  timestamp: string;
}
