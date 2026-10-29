# Core Music & Genre Schema Specification

**Architecture Engine:** `PF-04` / `RI-06`  
**Architecture Version:** 5.0.0  

---

## 1. The All-Genre Graph Invariant

A fundamental tenet of the Hit DNA architecture is that musical genres, subgenres, scenes, and hybrids are modeled as a versioned directed graph, never as single-string fields or closed enums.

### Core Contracts

```typescript
export interface GenreNode {
  genreId: string;
  name: string;
  slug: string;
  level: 'ROOT_GENRE' | 'SUBGENRE' | 'SCENE' | 'RESEARCHED_HYBRID';
  eraOrigin?: string;
  geographicOrigin?: string;
  description: string;
  taxonomyVersion: string;
}

export interface GenreEdge {
  edgeId: string;
  sourceGenreId: string;
  targetGenreId: string;
  relationship: 'CHILD_OF' | 'INFLUENCED_BY' | 'FUSED_INTO' | 'CONTEMPORARY_WITH';
  weight: number; // 0.0 to 1.0
  reviewStatus: 'PROVISIONAL' | 'REVIEWED' | 'VERIFIED';
}

export interface GenreBlendDefinition {
  blendId: string;
  name: string;
  primaryGenreId: string;
  secondaryGenreId: string;
  blendType: 'RESEARCHED_HYBRID' | 'CREATIVE_BLEND';
  empiricalSupport: {
    qualifyingCohortId?: string;
    sampleSongCount?: number;
    hasEmpiricalPrevalence: boolean;
  };
}

export interface SongGenreAssignment {
  songId: string;
  genreId: string;
  confidence: number;
  assignedBy: 'SOURCE_METADATA' | 'RESEARCHER_REVIEW' | 'ACOUSTIC_CLASSIFIER';
  isPrimary: boolean;
  assignedAt: string;
}

export interface GenreTaxonomyVersion {
  version: string;
  activatedAt: string;
  nodeCount: number;
  edgeCount: number;
  reviewedBy: string;
}
```

### Distinction: Researched Hybrid vs. Creative Blend
- **`RESEARCHED_HYBRID`:** An established, empirically attested fusion (e.g., Country Rap, Pop Punk, Trap Metal, Afro-House) with qualifying chart records, identifiable cohort denominator, and measurable feature distributions.
- **`CREATIVE_BLEND`:** An arbitrary user-directed fusion specified at creative generation time. A creative blend never inherits or manufactures fake statistical percentages from unmeasured cohorts.
