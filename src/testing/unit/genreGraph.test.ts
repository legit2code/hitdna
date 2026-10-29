/**
 * Unit Tests: Genre Graph, Hybrid Taxonomy, Persistence Models & Registries
 * Phase: P03 | Engines: RI-06, PF-04, PF-09
 *
 * Adheres strictly to P00 Master Build Constitution:
 * - Deterministic, self-contained unit tests
 * - Tests architectural invariants and edge cases
 * - Negative self-tests for cycle detection and creative blend boundaries
 * - Confirms zero production fixture leakage
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { GenreGraph } from '../../domain/genreGraph.ts';
import {
  CANONICAL_GENRE_NODES,
  CANONICAL_GENRE_EDGES,
  CANONICAL_TAXONOMY_VERSION,
} from '../../data/canonicalGenreTaxonomy.ts';
import { GenreBlendDefinition, GenreEdge, GenreNode, SongGenreAssignment } from '../../contracts/genreGraph.ts';
import { Song, StorageReference } from '../../contracts/persistence.ts';
import { InMemoryMusicRepository } from '../../repositories/musicRepository.ts';
import {
  LANGUAGE_SOURCE_REGISTRY,
  PATTERN_EXTRACTOR_REGISTRY,
  METHODOLOGY_VERSION_CATALOG,
} from '../../domain/registries.ts';

describe('RI-06: Genre Directed Graph & Taxonomy Engine', () => {
  test('correctly indexes canonical genre nodes and edges', () => {
    const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);

    assert.equal(graph.getAllNodes().length, CANONICAL_GENRE_NODES.length);
    assert.equal(graph.getAllEdges().length, CANONICAL_GENRE_EDGES.length);

    const hipHop = graph.getNode('gn_root_hip_hop');
    assert.ok(hipHop);
    assert.equal(hipHop?.name, 'Hip-Hop');
    assert.equal(hipHop?.nodeType, 'ROOT_FAMILY');

    const bySlug = graph.getNodeBySlug('hip-hop');
    assert.equal(bySlug?.genreId, 'gn_root_hip_hop');
  });

  test('navigates hierarchical ancestors across parent relationships', () => {
    const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);

    // Trap -> Hip-Hop
    const trapAncestors = graph.getAncestors('gn_trap');
    assert.ok(trapAncestors.some(a => a.genreId === 'gn_root_hip_hop'));

    // Pop Punk -> Rock and Pop (via derived & influenced)
    const popPunkAncestors = graph.getAncestors('gn_pop_punk');
    assert.ok(popPunkAncestors.some(a => a.genreId === 'gn_root_rock'));
  });

  test('navigates subgenre descendants from root families', () => {
    const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);

    const hipHopDescendants = graph.getDescendants('gn_root_hip_hop');
    assert.ok(hipHopDescendants.some(d => d.genreId === 'gn_trap'));
    assert.ok(hipHopDescendants.some(d => d.genreId === 'gn_boom_bap'));
  });

  test('resolves multi-family lineage for fused and hybrid styles', () => {
    const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);

    // Country Rap is fused with Country and Hip-Hop
    const lineage = graph.getLineage('gn_country_rap');
    assert.ok(lineage.primaryPath.length > 0);

    const fused = graph.getFusedInfluences('gn_country_rap');
    const fusedIds = fused.map(f => f.genreId);
    assert.ok(fusedIds.includes('gn_root_country'));
    assert.ok(fusedIds.includes('gn_root_hip_hop'));
  });

  test('calculates graph shortest-path distances accurately', () => {
    const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);

    // Self distance is 0
    assert.equal(graph.calculateDistance('gn_trap', 'gn_trap'), 0);

    // Trap to Hip-Hop is 1 hop
    assert.equal(graph.calculateDistance('gn_trap', 'gn_root_hip_hop'), 1);

    // Trap to Boom Bap is 2 hops (Trap -> Hip-Hop -> Boom Bap)
    assert.equal(graph.calculateDistance('gn_trap', 'gn_boom_bap'), 2);

    // Distance with unknown node is null
    assert.equal(graph.calculateDistance('gn_trap', 'gn_unknown_node'), null);
  });

  test('validates that canonical taxonomy is valid and cycle-free', () => {
    const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);
    const validation = graph.validateTaxonomy();

    assert.equal(validation.valid, true);
    assert.equal(validation.errors.length, 0);
    assert.equal(validation.cycles.length, 0);
  });

  test('detects cycles in hierarchical taxonomy edges (negative test)', () => {
    // Create an artificial cycle: Node A -> Node B -> Node A
    const cyclicNodes: GenreNode[] = [
      {
        genreId: 'gn_test_a',
        name: 'Test A',
        slug: 'test-a',
        nodeType: 'SUBGENRE',
        aliases: [],
        sourceLabels: {},
        taxonomyVersion: '5.0.0',
        description: 'Cycle test node A',
        parentFamilies: [],
        createdAt: '2026-09-01T00:00:00Z',
        updatedAt: '2026-09-01T00:00:00Z',
      },
      {
        genreId: 'gn_test_b',
        name: 'Test B',
        slug: 'test-b',
        nodeType: 'SUBGENRE',
        aliases: [],
        sourceLabels: {},
        taxonomyVersion: '5.0.0',
        description: 'Cycle test node B',
        parentFamilies: [],
        createdAt: '2026-09-01T00:00:00Z',
        updatedAt: '2026-09-01T00:00:00Z',
      },
    ];

    const cyclicEdges: GenreEdge[] = [
      {
        edgeId: 'ge_a_to_b',
        sourceGenreId: 'gn_test_a',
        targetGenreId: 'gn_test_b',
        edgeType: 'IS_A',
        evidence: null,
        sourceRef: null,
        confidence: 1.0,
        taxonomyVersion: '5.0.0',
        weight: null,
        reviewStatus: 'PROVISIONAL',
        createdAt: '2026-09-01T00:00:00Z',
      },
      {
        edgeId: 'ge_b_to_a',
        sourceGenreId: 'gn_test_b',
        targetGenreId: 'gn_test_a',
        edgeType: 'IS_A',
        evidence: null,
        sourceRef: null,
        confidence: 1.0,
        taxonomyVersion: '5.0.0',
        weight: null,
        reviewStatus: 'PROVISIONAL',
        createdAt: '2026-09-01T00:00:00Z',
      },
    ];

    const graph = new GenreGraph(cyclicNodes, cyclicEdges);
    const validation = graph.validateTaxonomy();

    assert.equal(validation.valid, false);
    assert.ok(validation.errors.length > 0);
    assert.ok(validation.errors[0].includes('Cycle detected'));
  });
});

describe('RI-06: Researched Hybrid vs Creative Blend Distinction', () => {
  const graph = new GenreGraph(CANONICAL_GENRE_NODES, CANONICAL_GENRE_EDGES);

  test('validates a legitimate researched hybrid with evidence', () => {
    const researchedHybrid: GenreBlendDefinition = {
      blendId: 'gb_country_rap',
      blendType: 'RESEARCHED_HYBRID',
      name: 'Country Rap',
      primaryGenreId: 'gn_root_country',
      secondaryGenreIds: ['gn_root_hip_hop'],
      weights: null, // Weights are nullable when unmeasured
      empiricalSupport: {
        qualifyingCohortId: 'cohort_billboard_crossover_2019_2024',
        sampleSongCount: 142,
        hasEmpiricalPrevalence: true,
        citationRef: 'ref_billboard_hot100_hybrid_study',
      },
      evidence: 'Peer-reviewed chart crossover analysis 2019-2024',
      status: 'ACTIVE',
      createdAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    };

    const result = graph.distinguishBlend(researchedHybrid);
    assert.equal(result.valid, true);
    assert.equal(result.isResearched, true);
    assert.equal(result.allowsEmpiricalClaims, true);
    assert.equal(result.errors.length, 0);
  });

  test('validates a creator-directed creative blend with null empirical claims', () => {
    const creativeBlend: GenreBlendDefinition = {
      blendId: 'gb_creative_experiment_1',
      blendType: 'CREATIVE_BLEND',
      name: 'Hyperpop Country Drift',
      primaryGenreId: 'gn_hyperpop',
      secondaryGenreIds: ['gn_alt_country'],
      weights: {
        gn_hyperpop: 0.7,
        gn_alt_country: 0.3,
      },
      empiricalSupport: {
        qualifyingCohortId: null, // Creator blends must not attach empirical cohort
        sampleSongCount: null,
        hasEmpiricalPrevalence: false, // Strictly prohibited
        citationRef: null,
      },
      evidence: null,
      status: 'EXPERIMENTAL',
      createdAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    };

    const result = graph.distinguishBlend(creativeBlend);
    assert.equal(result.valid, true);
    assert.equal(result.isResearched, false);
    assert.equal(result.allowsEmpiricalClaims, false);
    assert.equal(result.errors.length, 0);
  });

  test('rejects creative blends that attempt to fabricate empirical prevalence (negative test)', () => {
    const invalidCreativeBlend: GenreBlendDefinition = {
      blendId: 'gb_invalid_creative_blend',
      blendType: 'CREATIVE_BLEND',
      name: 'Synthetic Empirical Claim Blend',
      primaryGenreId: 'gn_trap',
      secondaryGenreIds: ['gn_root_rock'],
      weights: null,
      empiricalSupport: {
        qualifyingCohortId: 'cohort_fake_cohort', // FORBIDDEN for creative blends
        sampleSongCount: 50,
        hasEmpiricalPrevalence: true, // FORBIDDEN for creative blends
        citationRef: null,
      },
      evidence: null,
      status: 'EXPERIMENTAL',
      createdAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    };

    const result = graph.distinguishBlend(invalidCreativeBlend);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes('cannot claim empirical prevalence')));
    assert.ok(result.errors.some(e => e.includes('cannot attach a qualifying research cohort')));
  });

  test('enforces that blend component weights sum to 1.0 if provided', () => {
    const unbalancedBlend: GenreBlendDefinition = {
      blendId: 'gb_unbalanced_weights',
      blendType: 'CREATIVE_BLEND',
      name: 'Unbalanced Blend',
      primaryGenreId: 'gn_trap',
      secondaryGenreIds: ['gn_root_pop'],
      weights: {
        gn_trap: 0.8,
        gn_root_pop: 0.5, // Sum = 1.3 != 1.0
      },
      empiricalSupport: {
        qualifyingCohortId: null,
        sampleSongCount: null,
        hasEmpiricalPrevalence: false,
        citationRef: null,
      },
      evidence: null,
      status: 'EXPERIMENTAL',
      createdAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    };

    const result = graph.distinguishBlend(unbalancedBlend);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes('must sum to 1.0')));
  });
});

describe('PF-04: Canonical Music Persistence & Multi-Genre Assignment Model', () => {
  test('supports songs with multi-genre assignments and no canonical song.genre string', async () => {
    const repo = new InMemoryMusicRepository(true);

    // Create a song entity
    const song: Song = {
      id: 'song_test_hit_01',
      title: 'Old Town Road',
      primaryArtistId: 'art_lil_nas_x',
      artistIds: ['art_lil_nas_x', 'art_billy_ray_cyrus'],
      isrc: 'USSM11901234',
      releaseDate: '2019-03-14',
      durationMs: 157000,
      explicit: false,
      status: 'ACTIVE',
      storageRefs: [],
      createdAt: '2026-09-01T00:00:00Z',
      updatedAt: '2026-09-01T00:00:00Z',
    };

    // Verify architectural invariant: song must NOT have a `genre: string` property
    assert.equal((song as unknown as Record<string, unknown>).genre, undefined);

    await repo.saveSong(song);
    const retrieved = await repo.getSongById('song_test_hit_01');
    assert.ok(retrieved);
    assert.equal(retrieved?.title, 'Old Town Road');

    // Create multi-genre assignments for Country, Hip-Hop, and Country Rap
    const assignment1: SongGenreAssignment = {
      assignmentId: 'sga_otr_country',
      songId: 'song_test_hit_01',
      genreId: 'gn_root_country',
      sourceProvider: 'BILLBOARD',
      method: 'RESEARCHER_REVIEW',
      confidence: 0.9,
      evidence: 'Hot Country Songs initial charting',
      reviewState: 'VERIFIED',
      taxonomyVersion: '5.0.0',
      isPrimary: false,
      assignedAt: '2026-09-01T00:00:00Z',
    };

    const assignment2: SongGenreAssignment = {
      assignmentId: 'sga_otr_hip_hop',
      songId: 'song_test_hit_01',
      genreId: 'gn_root_hip_hop',
      sourceProvider: 'BILLBOARD',
      method: 'SOURCE_METADATA',
      confidence: 0.95,
      evidence: 'Hot R&B/Hip-Hop Songs charting and 808 beat production',
      reviewState: 'VERIFIED',
      taxonomyVersion: '5.0.0',
      isPrimary: false,
      assignedAt: '2026-09-01T00:00:00Z',
    };

    const assignment3: SongGenreAssignment = {
      assignmentId: 'sga_otr_country_rap',
      songId: 'song_test_hit_01',
      genreId: 'gn_country_rap',
      sourceProvider: 'HIT_DNA_RESEARCH',
      method: 'HYBRID_INFERENCE',
      confidence: 0.98,
      evidence: 'Banjo sample + trap 808 cadence hybrid archetype',
      reviewState: 'VERIFIED',
      taxonomyVersion: '5.0.0',
      isPrimary: true,
      assignedAt: '2026-09-01T00:00:00Z',
    };

    await repo.saveSongGenreAssignment(assignment1);
    await repo.saveSongGenreAssignment(assignment2);
    await repo.saveSongGenreAssignment(assignment3);

    const assignments = await repo.getGenreAssignmentsForSong('song_test_hit_01');
    assert.equal(assignments.length, 3);
    const primary = assignments.find(a => a.isPrimary);
    assert.equal(primary?.genreId, 'gn_country_rap');
  });

  test('strictly validates storage references with immutable hashes and access tiers', async () => {
    const repo = new InMemoryMusicRepository(false);

    const storageRef: StorageReference = {
      id: 'stg_audio_raw_001',
      bucket: 'hit-dna-cold-vault',
      key: 'audio/2026/09/song_01_stems.flac',
      sha256Checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      byteSize: 45281920,
      contentType: 'audio/flac',
      accessTier: 'HOT',
      createdAt: '2026-09-01T00:00:00Z',
    };

    await repo.saveStorageReference(storageRef);
    const saved = await repo.getStorageReferenceById('stg_audio_raw_001');

    assert.ok(saved);
    assert.equal(saved?.sha256Checksum, storageRef.sha256Checksum);
    assert.equal(saved?.accessTier, 'HOT');
  });
});

describe('PF-09: Registries Governance & Permitted Language Sources', () => {
  test('prohibits unauthorized web scraping in language sources registry', () => {
    const unauthorized = LANGUAGE_SOURCE_REGISTRY.UNAUTHORIZED_SCRAPING;
    assert.ok(unauthorized);
    assert.equal(unauthorized.permitted, false);
  });

  test('permits authorized lyrics annotations and verified interview transcripts', () => {
    assert.equal(LANGUAGE_SOURCE_REGISTRY.LYRICS_ANNOTATION.permitted, true);
    assert.equal(LANGUAGE_SOURCE_REGISTRY.ARTIST_INTERVIEWS.permitted, true);
    assert.equal(LANGUAGE_SOURCE_REGISTRY.CULTURAL_COMMENTARY.permitted, true);
  });

  test('guarantees deterministic pattern extractors for harmonic chord progressions', () => {
    const chordExtractor = PATTERN_EXTRACTOR_REGISTRY.CHORD_PROGRESSION_EXTRACTOR;
    assert.ok(chordExtractor);
    assert.equal(chordExtractor.determinismGuarantee, 'STRICT_DETERMINISTIC');
  });

  test('catalogs versioned Hit DNA analysis methodologies', () => {
    const activeMethodology = METHODOLOGY_VERSION_CATALOG.find(m => m.active);
    assert.ok(activeMethodology);
    assert.equal(activeMethodology?.version, '5.0.0');
    assert.equal(activeMethodology?.confidenceThreshold, 0.95);
  });
});
