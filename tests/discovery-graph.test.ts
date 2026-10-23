import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import {
  DiscoveryGraphEngine,
  DiscoveryGraphWorker,
  UrlNormalizer,
  PivotExtractor,
} from '@caim/source';

describe('Discovery Graph Foundation (Step 1 of 5)', () => {
  let memDb: any;
  let pgClient: any;
  let engine: DiscoveryGraphEngine;
  let worker: DiscoveryGraphWorker;

  beforeEach(async () => {
    memDb = createTestDb();
    const pgMem = memDb.adapters.createPg();
    pgClient = new pgMem.Client();
    await pgClient.connect();
    engine = new DiscoveryGraphEngine(pgClient);
    worker = new DiscoveryGraphWorker(pgClient, engine);
  });

  afterEach(async () => {
    if (pgClient) {
      await pgClient.end();
    }
  });

  describe('Part A — Schema Verification', () => {
    it('creates all discovery graph tables and edge types', async () => {
      const roots = await pgClient.query('SELECT * FROM source.discovery_roots LIMIT 1;');
      expect(roots).toBeDefined();

      const candidates = await pgClient.query('SELECT * FROM source.discovery_candidates LIMIT 1;');
      expect(candidates).toBeDefined();

      const edges = await pgClient.query('SELECT * FROM source.discovery_edges LIMIT 1;');
      expect(edges).toBeDefined();

      const edgeTypes = await pgClient.query('SELECT * FROM source.discovery_edge_types;');
      const types = edgeTypes.rows.map((r: any) => r.edge_type);
      expect(types).toContain('ROOT_SOURCE');
      expect(types).toContain('DEPENDENCY');
      expect(types).toContain('DEV_DEPENDENCY');
      expect(types).toContain('UPSTREAM_SOURCE');
      expect(types).toContain('README_LINK');
    });
  });

  describe('Part B — Canonical URL Normalization & Adapters', () => {
    it('normalizes URLs canonically across all 7 supported source adapters', () => {
      // 1. GitHub
      const gh1 = UrlNormalizer.normalize('https://github.com/langchain-ai/langchainjs/blob/main/README.md#getting-started');
      expect(gh1.normalized_url).toBe('github://langchain-ai/langchainjs');
      expect(gh1.canonical_url).toBe('https://github.com/langchain-ai/langchainjs');
      expect(gh1.domain).toBe('github.com');

      // 2. GitLab
      const gl = UrlNormalizer.normalize('https://gitlab.com/group/project.git');
      expect(gl.normalized_url).toBe('gitlab://group/project');
      expect(gl.canonical_url).toBe('https://gitlab.com/group/project');

      // 3. PyPI
      const pypi = UrlNormalizer.normalize('https://pypi.org/project/langchain-core/0.1.0/');
      expect(pypi.normalized_url).toBe('pypi://langchain-core');

      // 4. npm
      const npm = UrlNormalizer.normalize('https://www.npmjs.com/package/@langchain/core');
      expect(npm.normalized_url).toBe('npm://@langchain/core');

      // 5. Hugging Face
      const hf = UrlNormalizer.normalize('https://huggingface.co/mistralai/Mistral-7B-v0.1');
      expect(hf.normalized_url).toBe('huggingface://mistralai/mistral-7b-v0.1');

      // 6. Docker Hub
      const docker = UrlNormalizer.normalize('https://hub.docker.com/r/ollama/ollama');
      expect(docker.normalized_url).toBe('docker://ollama/ollama');

      // 7. Codeberg
      const codeberg = UrlNormalizer.normalize('https://codeberg.org/forgejo/forgejo.git');
      expect(codeberg.normalized_url).toBe('codeberg://forgejo/forgejo');
    });
  });

  describe('Part B — Entity Deduplication & Provenance Preservation', () => {
    it('preserves single candidate row while recording distinct provenance edges when candidate C is discovered via path 1 (root -> A -> C) and path 2 (root -> B -> C)', async () => {
      const rootRes = await engine.registerRoot('npm', 'PACKAGE_NAME', 'npm://root-app');
      const rootId = rootRes.root.id;
      const rootEdgeId = rootRes.edge.id;
      const rootCandId = rootRes.candidate.id;

      // Path 1 (root -> A) and Path 2 (root -> B)
      const rootPivots = [
        {
          discovered_url: 'npm://pkg-a',
          normalized_url: 'npm://pkg-a',
          canonical_url: 'https://www.npmjs.com/package/pkg-a',
          candidate_type: 'PACKAGE' as const,
          domain: 'npmjs.com',
          edge_type: 'DEPENDENCY' as const,
          discovery_confidence: 0.9,
          extractor: 'NPM_PACKAGE_JSON',
          evidence_type: 'METADATA_EXTRACT',
          evidence_location: 'dependencies.pkg-a',
        },
        {
          discovered_url: 'npm://pkg-b',
          normalized_url: 'npm://pkg-b',
          canonical_url: 'https://www.npmjs.com/package/pkg-b',
          candidate_type: 'PACKAGE' as const,
          domain: 'npmjs.com',
          edge_type: 'DEPENDENCY' as const,
          discovery_confidence: 0.9,
          extractor: 'NPM_PACKAGE_JSON',
          evidence_type: 'METADATA_EXTRACT',
          evidence_location: 'dependencies.pkg-b',
        },
      ];

      const rootSched = await engine.evaluateAndSchedulePivots({
        root_seed_id: rootId,
        parent_edge_id: rootEdgeId,
        source_candidate_id: rootCandId,
        parent_crawl_depth: 0,
        cycle_id: 'test-dedup-cycle',
        pivots: rootPivots,
        source_content_hash: 'hash-root',
      });

      const edgeA = rootSched.accepted_edges.find((e) => e.normalized_url === 'npm://pkg-a')!;
      const edgeB = rootSched.accepted_edges.find((e) => e.normalized_url === 'npm://pkg-b')!;
      const candA = edgeA.target_candidate_id;
      const candB = edgeB.target_candidate_id;

      // Path 1 continuation: A -> C
      const pivotFromA = [
        {
          discovered_url: 'npm://shared-c',
          normalized_url: 'npm://shared-c',
          canonical_url: 'https://www.npmjs.com/package/shared-c',
          candidate_type: 'PACKAGE' as const,
          domain: 'npmjs.com',
          edge_type: 'DEPENDENCY' as const,
          discovery_confidence: 0.95,
          extractor: 'NPM_PACKAGE_JSON',
          evidence_type: 'METADATA_EXTRACT',
          evidence_location: 'dependencies.shared-c-from-A',
        },
      ];

      await engine.evaluateAndSchedulePivots({
        root_seed_id: rootId,
        parent_edge_id: edgeA.id,
        source_candidate_id: candA,
        parent_crawl_depth: 1,
        cycle_id: 'test-dedup-cycle',
        pivots: pivotFromA,
        source_content_hash: 'hash-a',
      });

      // Path 2 continuation: B -> C
      const pivotFromB = [
        {
          discovered_url: 'npm://shared-c',
          normalized_url: 'npm://shared-c',
          canonical_url: 'https://www.npmjs.com/package/shared-c',
          candidate_type: 'PACKAGE' as const,
          domain: 'npmjs.com',
          edge_type: 'PEER_DEPENDENCY' as const,
          discovery_confidence: 0.85,
          extractor: 'NPM_PACKAGE_JSON',
          evidence_type: 'METADATA_EXTRACT',
          evidence_location: 'peerDependencies.shared-c-from-B',
        },
      ];

      await engine.evaluateAndSchedulePivots({
        root_seed_id: rootId,
        parent_edge_id: edgeB.id,
        source_candidate_id: candB,
        parent_crawl_depth: 1,
        cycle_id: 'test-dedup-cycle',
        pivots: pivotFromB,
        source_content_hash: 'hash-b',
      });

      // 1. Entity Deduplication: Exactly ONE row in discovery_candidates for C
      const candRows = await pgClient.query(
        "SELECT * FROM source.discovery_candidates WHERE normalized_url = 'npm://shared-c';"
      );
      expect(candRows.rows.length).toBe(1);
      const candC = candRows.rows[0];

      // 2. Provenance Preservation: Exactly TWO edges targeting C
      const edgeRows = await pgClient.query(
        'SELECT * FROM source.discovery_edges WHERE target_candidate_id = $1;',
        [candC.id]
      );
      expect(edgeRows.rows.length).toBe(2);

      // 3. Each edge has distinct parent_edge_id, source_candidate_id, and evidence
      const edge1 = edgeRows.rows.find((e: any) => e.edge_type === 'DEPENDENCY');
      const edge2 = edgeRows.rows.find((e: any) => e.edge_type === 'PEER_DEPENDENCY');

      expect(edge1).toBeDefined();
      expect(edge2).toBeDefined();
      expect(edge1.parent_edge_id).toBe(edgeA.id);
      expect(edge2.parent_edge_id).toBe(edgeB.id);
      expect(edge1.evidence_location).toBe('dependencies.shared-c-from-A');
      expect(edge2.evidence_location).toBe('peerDependencies.shared-c-from-B');
    });
  });

  describe('Part C — Hard Crawl Boundaries & Safeguards', () => {
    it('Safeguard 1: MAX_CRAWL_DEPTH hit rejects pivots beyond depth 4 with DEPTH_LIMIT', async () => {
      const rootRes = await engine.registerRoot('npm', 'PACKAGE_NAME', 'npm://root-pkg');

      const pivots = [
        {
          discovered_url: 'npm://deep-pkg',
          normalized_url: 'npm://deep-pkg',
          canonical_url: 'https://www.npmjs.com/package/deep-pkg',
          candidate_type: 'PACKAGE' as const,
          domain: 'npmjs.com',
          edge_type: 'DEPENDENCY' as const,
          discovery_confidence: 0.9,
          extractor: 'NPM_PACKAGE_JSON',
          evidence_type: 'METADATA_EXTRACT',
          evidence_location: 'dependencies.deep-pkg',
        },
      ];

      // Attempt to schedule pivot from parent at depth 4 (target depth = 5)
      const res = await engine.evaluateAndSchedulePivots({
        root_seed_id: rootRes.root.id,
        parent_edge_id: rootRes.edge.id,
        source_candidate_id: rootRes.candidate.id,
        parent_crawl_depth: 4,
        cycle_id: 'cycle-depth-test',
        pivots,
        source_content_hash: 'hash-deep',
        boundaries: { max_crawl_depth: 4 },
      });

      expect(res.accepted_edges.length).toBe(0);
      expect(res.rejected_edges.length).toBe(1);
      expect(res.rejected_edges[0].decision).toBe('REJECTED');
      expect(res.rejected_edges[0].rejection_reason).toBe('DEPTH_LIMIT');
      expect(res.boundary_violations.depth_limit).toBe(1);
    });

    it('Safeguard 2: MAX_PIVOTS_PER_PARENT rejects excess pivots with PARENT_FANOUT_LIMIT ordered by discovery_confidence', async () => {
      const rootRes = await engine.registerRoot('npm', 'PACKAGE_NAME', 'npm://root-pkg');

      // Create 5 pivots with varying discovery confidences, max fanout = 2
      const pivots = [0.2, 0.9, 0.4, 0.8, 0.1].map((conf, idx) => ({
        discovered_url: `npm://fanout-pkg-${idx}`,
        normalized_url: `npm://fanout-pkg-${idx}`,
        canonical_url: `https://www.npmjs.com/package/fanout-pkg-${idx}`,
        candidate_type: 'PACKAGE' as const,
        domain: 'npmjs.com',
        edge_type: 'DEPENDENCY' as const,
        discovery_confidence: conf,
        extractor: 'NPM_PACKAGE_JSON',
        evidence_type: 'METADATA_EXTRACT',
        evidence_location: `dependencies.fanout-pkg-${idx}`,
      }));

      const res = await engine.evaluateAndSchedulePivots({
        root_seed_id: rootRes.root.id,
        parent_edge_id: rootRes.edge.id,
        source_candidate_id: rootRes.candidate.id,
        parent_crawl_depth: 0,
        cycle_id: 'cycle-fanout-test',
        pivots,
        source_content_hash: 'hash-fanout',
        boundaries: { max_pivots_per_parent: 2 },
      });

      // Top 2 confidences (0.9, 0.8) are accepted; remaining 3 are rejected with PARENT_FANOUT_LIMIT
      expect(res.accepted_edges.length).toBe(2);
      expect(res.rejected_edges.length).toBe(3);
      expect(res.boundary_violations.parent_fanout_limit).toBe(3);

      for (const rej of res.rejected_edges) {
        expect(rej.decision).toBe('REJECTED');
        expect(rej.rejection_reason).toBe('PARENT_FANOUT_LIMIT');
      }
    });

    it('Safeguard 3: MAX_DISCOVERIES_PER_ROOT_PER_CYCLE enforces root cap with ROOT_BUDGET_EXCEEDED', async () => {
      const rootRes = await engine.registerRoot('npm', 'PACKAGE_NAME', 'npm://root-pkg', {
        cycle_id: 'cycle-root-cap',
      });

      // Root registration already consumes 1 edge at depth 0
      const pivots = [1, 2, 3].map((idx) => ({
        discovered_url: `npm://budget-pkg-${idx}`,
        normalized_url: `npm://budget-pkg-${idx}`,
        canonical_url: `https://www.npmjs.com/package/budget-pkg-${idx}`,
        candidate_type: 'PACKAGE' as const,
        domain: 'npmjs.com',
        edge_type: 'DEPENDENCY' as const,
        discovery_confidence: 0.9,
        extractor: 'NPM_PACKAGE_JSON',
        evidence_type: 'METADATA_EXTRACT',
        evidence_location: `dependencies.budget-pkg-${idx}`,
      }));

      // Set max per root to 2 (root edge = 1, allows 1 more, rejects 2)
      const res = await engine.evaluateAndSchedulePivots({
        root_seed_id: rootRes.root.id,
        parent_edge_id: rootRes.edge.id,
        source_candidate_id: rootRes.candidate.id,
        parent_crawl_depth: 0,
        cycle_id: 'cycle-root-cap',
        pivots,
        source_content_hash: 'hash-budget',
        boundaries: { max_discoveries_per_root_per_cycle: 2 },
      });

      expect(res.accepted_edges.length).toBe(1);
      expect(res.rejected_edges.length).toBe(2);
      expect(res.rejected_edges[0].rejection_reason).toBe('ROOT_BUDGET_EXCEEDED');
      expect(res.boundary_violations.root_budget_exceeded).toBe(2);
    });

    it('Safeguard 4: MAX_PIVOTS_PER_DISCOVERY_CYCLE retains unqueued candidates for next cycle', async () => {
      const rootRes = await engine.registerRoot('npm', 'PACKAGE_NAME', 'npm://root-pkg', {
        cycle_id: 'cycle-global-cap',
      });

      const pivots = [1, 2, 3].map((idx) => ({
        discovered_url: `npm://retained-pkg-${idx}`,
        normalized_url: `npm://retained-pkg-${idx}`,
        canonical_url: `https://www.npmjs.com/package/retained-pkg-${idx}`,
        candidate_type: 'PACKAGE' as const,
        domain: 'npmjs.com',
        edge_type: 'DEPENDENCY' as const,
        discovery_confidence: 0.8,
        extractor: 'NPM_PACKAGE_JSON',
        evidence_type: 'METADATA_EXTRACT',
        evidence_location: `dependencies.retained-pkg-${idx}`,
      }));

      // Cap global cycle to 2 jobs (root job = 1, allowed = 1, retained = 2)
      const res = await engine.evaluateAndSchedulePivots({
        root_seed_id: rootRes.root.id,
        parent_edge_id: rootRes.edge.id,
        source_candidate_id: rootRes.candidate.id,
        parent_crawl_depth: 0,
        cycle_id: 'cycle-global-cap',
        pivots,
        source_content_hash: 'hash-retain',
        boundaries: { max_pivots_per_discovery_cycle: 2 },
      });

      expect(res.accepted_edges.length).toBe(3); // 1 queued, 2 deferred
      expect(res.retained_candidates.length).toBe(2);
      expect(res.boundary_violations.cycle_budget_retained).toBe(2);

      // Verify unqueued candidates are retained with queued_at NULL and status DISCOVERED
      for (const retained of res.retained_candidates) {
        expect(retained.status).toBe('DISCOVERED');
        expect(retained.queued_at).toBeNull();
      }
    });
  });

  describe('Part D & E — Asynchronous Execution & Confidence Independence', () => {
    it('executes discovery cycle asynchronously via ops.jobs maintaining independence between discovery_confidence and classification_confidence', async () => {
      // 1. Register root
      await engine.registerRoot('npm', 'PACKAGE_NAME', 'npm://langchain');

      // 2. Lease job from ops.jobs
      const job = await worker.leaseNextJob();
      expect(job).not.toBeNull();
      expect(job!.queue_key).toBe('discovery_graph_queue');
      expect(job!.status).toBe('LEASED');

      // 3. Process job
      const result = await worker.processJob(job!);
      expect(result.success).toBe(true);
      expect(result.pivots_found).toBeGreaterThan(0);
      expect(result.classification).toBeDefined();

      // 4. Verify candidate record has independent confidences
      const candRes = await pgClient.query(
        'SELECT * FROM source.discovery_candidates WHERE id = $1;',
        [result.candidate_id]
      );
      const cand = candRes.rows[0];

      // discovery_confidence = 1.0 (seed or manifest extract confidence)
      expect(Number(cand.discovery_confidence)).toBe(1.0);
      // classification_confidence comes from ArtifactClassifier (separate metric)
      expect(Number(cand.classification_confidence)).toBeGreaterThan(0);
      expect(cand.classification).toBeDefined();

      // 5. Verify ops.jobs status updated to COMPLETED
      const jobRes = await pgClient.query(
        'SELECT status FROM ops.jobs WHERE job_id = $1;',
        [job!.id]
      );
      expect(jobRes.rows[0].status).toBe('COMPLETED');
    }, 20000);
  });
});
