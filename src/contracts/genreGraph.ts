/**
 * Genre Graph, Hybrid Taxonomy & Multi-Assignment Contracts
 * Engines: RI-06 (Genre, Subgenre, Scene & Hybrid Taxonomy) / PF-04
 * Architecture Version: 5.0.0 | Phase: P03
 *
 * Constitution Invariants:
 * 1. Genres are a versioned directed graph, never a single-string field on a song.
 * 2. GenreBlendDefinition distinguishes RESEARCHED_HYBRID from CREATIVE_BLEND.
 * 3. Component weights are nullable unless measured or explicitly chosen as creative input.
 * 4. Researched hybrids require verifiable qualifying cohort evidence; creative blends never fabricate statistics.
 */

export type GenreNodeType =
  | 'ROOT_FAMILY'
  | 'GENRE'
  | 'SUBGENRE'
  | 'REGIONAL_STYLE'
  | 'SCENE'
  | 'HYBRID_LABEL'
  | 'ERA_STYLE';

export type GenreEdgeType =
  | 'IS_A'
  | 'DERIVED_FROM'
  | 'FUSED_WITH'
  | 'INFLUENCED_BY'
  | 'REGIONAL_VARIANT'
  | 'ERA_VARIANT'
  | 'RELATED_TO';

export type GenreBlendType =
  | 'RESEARCHED_HYBRID'
  | 'CREATIVE_BLEND';

export type GenreReviewStatus =
  | 'PROVISIONAL'
  | 'REVIEWED'
  | 'VERIFIED';

export type GenreAssignmentMethod =
  | 'SOURCE_METADATA'
  | 'RESEARCHER_REVIEW'
  | 'ACOUSTIC_CLASSIFIER'
  | 'HYBRID_INFERENCE';

export interface GenreNode {
  genreId: string; // gn_... stable internal ID
  name: string;
  slug: string;
  nodeType: GenreNodeType;
  aliases: string[];
  sourceLabels: Record<string, string[]>; // e.g. { spotify: ['trap', 'southern hip hop'] }
  taxonomyVersion: string; // e.g. '5.0.0'
  description: string;
  parentFamilies: string[]; // Root family references e.g. ['gn_hip_hop']
  createdAt: string;
  updatedAt: string;
}

export interface GenreEdge {
  edgeId: string; // ge_... stable internal ID
  sourceGenreId: string;
  targetGenreId: string;
  edgeType: GenreEdgeType;
  evidence: string | null;
  sourceRef: string | null;
  confidence: number; // 0.0 to 1.0
  taxonomyVersion: string;
  weight: number | null; // Nullable unless measured or explicitly parameterized
  reviewStatus: GenreReviewStatus;
  createdAt: string;
}

export interface EmpiricalSupport {
  qualifyingCohortId: string | null;
  sampleSongCount: number | null;
  hasEmpiricalPrevalence: boolean;
  citationRef: string | null;
}

export interface GenreBlendDefinition {
  blendId: string; // gb_... stable internal ID
  blendType: GenreBlendType;
  name: string;
  primaryGenreId: string;
  secondaryGenreIds: string[];
  /**
   * Component weights are nullable unless measured (for RESEARCHED_HYBRID)
   * or explicitly chosen by creator (for CREATIVE_BLEND).
   */
  weights: Record<string, number> | null;
  empiricalSupport: EmpiricalSupport;
  evidence: string | null;
  status: 'ACTIVE' | 'EXPERIMENTAL' | 'DEPRECATED';
  createdAt: string;
  updatedAt: string;
}

export interface SongGenreAssignment {
  assignmentId: string; // sga_... stable internal ID
  songId: string;
  genreId: string;
  sourceProvider: string;
  method: GenreAssignmentMethod;
  confidence: number; // 0.0 to 1.0
  evidence: string | null;
  reviewState: GenreReviewStatus;
  taxonomyVersion: string;
  isPrimary: boolean;
  assignedAt: string;
}

export interface GenreTaxonomyVersion {
  version: string; // e.g. '5.0.0'
  name: string;
  releaseDate: string;
  active: boolean;
  nodeCount: number;
  edgeCount: number;
  checksum: string;
  reviewedBy: string;
  createdAt: string;
}
