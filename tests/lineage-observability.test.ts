import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import {
  DiscoveryGraphEngine,
  DiscoveryLineageService,
  PivotExtractor,
  RelevanceGate,
  VerifiedAgentContent,
} from '@caim/source';

describe('Step 6 of 6 — Discovery Lineage API, UI, and Observability', () => {
  let memDb: any;
  let pgClient: any;
  let engine: DiscoveryGraphEngine;
  let lineageService: DiscoveryLineageService;

  beforeEach(async () => {
    memDb = createTestDb();
    const pgMem = memDb.adapters.createPg();
    pgClient = new pgMem.Client();
    await pgClient.connect();
    engine = new DiscoveryGraphEngine(pgClient);
    lineageService = new DiscoveryLineageService(pgClient);
  });

  afterEach(async () => {
    if (pgClient) {
      await pgClient.end();
    }
  });

  describe('Part A — Real Discovery Lineage Traversal API', () => {
    it('returns honest empty lineage for an agent with no discovery graph records', async () => {
      const nonExistentAgentId = '00000000-0000-0000-0000-000000009999';
      const result = await lineageService.getDiscoveryLineage(nonExistentAgentId);

      expect(result.found).toBe(false);
      expect(result.immediate_parent).toBeNull();
      expect(result.root_source).toBeNull();
      expect(result.ancestor_chain).toHaveLength(0);
      expect(result.full_path).toHaveLength(0);
      expect(result.raw_edges).toHaveLength(0);
      expect(result.message).toContain('No discovery lineage recorded');
    });

    it('reconstructs the real ancestor chain for an agent discovered via a real pivot', async () => {
      // 1. Create a root source in source.discovery_roots
      const rootRes = await pgClient.query(`
        INSERT INTO source.discovery_roots (
          source_adapter, root_type, root_value, active, metadata_json
        ) VALUES (
          'github', 'REPO_SEED', 'https://github.com/agent-labs/seed-registry', true, '{"max_depth": 3}'::jsonb
        ) RETURNING id;
      `);
      const rootSeedId = rootRes.rows[0].id;

      // 2. Candidate 1 (Parent Agent: Autonomous Coder)
      const cand1Res = await pgClient.query(`
        INSERT INTO source.discovery_candidates (
          id, candidate_id, canonical_url, normalized_url, domain,
          discovery_confidence, status, metadata_json
        ) VALUES (
          gen_random_uuid(), gen_random_uuid(), 'https://github.com/agent-labs/autonomous-coder', 'github://agent-labs/autonomous-coder', 'github.com',
          0.95, 'VERIFIED_AGENT', '{"agent_id": "a0000000-0000-0000-0000-000000000101", "name": "autonomous-coder"}'::jsonb
        ) RETURNING id;
      `);
      const cand1Id = cand1Res.rows[0].id;
      const agent1Id = 'a0000000-0000-0000-0000-000000000101';

      // Insert root edge (Root -> Candidate 1)
      const edge1Res = await pgClient.query(`
        INSERT INTO source.discovery_edges (
          id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id, target_candidate_id,
          discovered_url, normalized_url, edge_type, crawl_depth, extractor,
          evidence_type, evidence_location, decision
        ) VALUES (
          $1, $2, NULL, NULL, NULL, $3,
          'https://github.com/agent-labs/autonomous-coder', 'github://agent-labs/autonomous-coder',
          'ROOT_SOURCE', 0, 'seed_loader', 'SEED_REGISTRATION', 'seed:config', 'QUEUED'
        ) RETURNING id;
      `, [crypto.randomUUID(), rootSeedId, cand1Id]);
      const rootEdgeId = edge1Res.rows[0].id;

      // 3. Candidate 2 (Pivot Agent: AutoGen), discovered from Agent 1's README
      const cand2Res = await pgClient.query(`
        INSERT INTO source.discovery_candidates (
          id, candidate_id, canonical_url, normalized_url, domain,
          discovery_confidence, status, metadata_json
        ) VALUES (
          $1, $1, 'https://github.com/microsoft/autogen', 'github://microsoft/autogen', 'github.com',
          0.92, 'VERIFIED_AGENT', '{"agent_id": "b0000000-0000-0000-0000-000000000202", "name": "autogen"}'::jsonb
        ) RETURNING id;
      `, [crypto.randomUUID()]);
      const cand2Id = cand2Res.rows[0].id;
      const agent2Id = 'b0000000-0000-0000-0000-000000000202';

      // Insert pivot edge (Edge 1 -> Candidate 2) with real evidence
      const edge2Res = await pgClient.query(`
        INSERT INTO source.discovery_edges (
          id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id, target_candidate_id,
          discovered_url, normalized_url, edge_type, crawl_depth, extractor,
          evidence_type, evidence_location, evidence_snippet_hash, decision
        ) VALUES (
          $1, $2, $3, $4, $5, $6,
          'https://github.com/microsoft/autogen', 'github://microsoft/autogen',
          'README_LINK', 1, 'readme_markdown_ast',
          'DOC_LINK', 'README.md: Related Projects', 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          'QUEUED'
        ) RETURNING id;
      `, [crypto.randomUUID(), rootSeedId, rootEdgeId, cand1Id, agent1Id, cand2Id]);
      const pivotEdgeId = edge2Res.rows[0].id;

      // 4. Also register both agents in core.canonical_agents
      await pgClient.query(`
        INSERT INTO core.canonical_agents (agent_id, canonical_name)
        VALUES 
          ($1, 'autonomous-coder'),
          ($2, 'autogen');
      `, [agent1Id, agent2Id]);

      // 5. CALL LINEAGE API for Agent 2
      const lineage = await lineageService.getDiscoveryLineage(agent2Id);

      // Verify returned lineage strictly matches discovery_edges data
      expect(lineage.found).toBe(true);
      expect(lineage.agent_id).toBe(agent2Id);
      expect(lineage.candidate_id).toBe(cand2Id);
      expect(lineage.depth).toBe(1);
      expect(lineage.edge_type).toBe('README_LINK');

      // Verify evidence
      expect(lineage.evidence).toBeDefined();
      expect(lineage.evidence?.type).toBe('DOC_LINK');
      expect(lineage.evidence?.location).toBe('README.md: Related Projects');
      expect(lineage.evidence?.snippet_hash).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

      // Verify immediate parent
      expect(lineage.immediate_parent).toBeDefined();
      expect(lineage.immediate_parent?.edge_id).toBe(rootEdgeId);
      expect(lineage.immediate_parent?.parent_agent_id).toBe(agent1Id);
      expect(lineage.immediate_parent?.parent_candidate_id).toBe(cand1Id);
      expect(lineage.immediate_parent?.edge_type).toBe('README_LINK');

      // Verify root source
      expect(lineage.root_source).toBeDefined();
      expect(lineage.root_source?.source_adapter).toBe('github');
      expect(lineage.root_source?.root_value).toBe('https://github.com/agent-labs/seed-registry');

      // Verify full ancestor chain (root -> Agent 1 -> Agent 2)
      expect(lineage.ancestor_chain.length).toBe(3);
      expect(lineage.ancestor_chain[0].node_type).toBe('ROOT');
      expect(lineage.ancestor_chain[1].node_type).toBe('PIVOT');
      expect(lineage.ancestor_chain[2].node_type).toBe('TARGET');

      // Full path
      expect(lineage.full_path).toEqual([
        'https://github.com/agent-labs/seed-registry',
        'https://github.com/agent-labs/autonomous-coder',
        'https://github.com/microsoft/autogen',
      ]);
    });
  });

  describe('Part B — Real Discovered Descendants Reverse Traversal', () => {
    it('returns reverse traversal from source.discovery_edges', async () => {
      // Setup Root -> Agent A -> Child 1 & Child 2
      const rootRes = await pgClient.query(`
        INSERT INTO source.discovery_roots (
          source_adapter, root_type, root_value, active, metadata_json
        ) VALUES (
          'github', 'REPO_SEED', 'https://github.com/agent-labs/root', true, '{}'::jsonb
        ) RETURNING id;
      `);
      const rootSeedId = rootRes.rows[0].id;
      const agentParentId = 'a1111111-1111-1111-1111-111111111111';

      // Insert Agent A candidate & edge
      const candARes = await pgClient.query(`
        INSERT INTO source.discovery_candidates (
          id, candidate_id, canonical_url, normalized_url, domain,
          discovery_confidence, status, metadata_json
        ) VALUES (
          gen_random_uuid(), gen_random_uuid(), 'https://github.com/agent-labs/agent-a', 'github://agent-labs/agent-a', 'github.com',
          0.95, 'VERIFIED_AGENT', '{"agent_id": "a1111111-1111-1111-1111-111111111111"}'::jsonb
        ) RETURNING id;
      `);
      const candAId = candARes.rows[0].id;

      const edgeAId = crypto.randomUUID();
      await pgClient.query(`
        INSERT INTO source.discovery_edges (
          id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id, target_candidate_id,
          discovered_url, normalized_url, edge_type, crawl_depth, extractor,
          evidence_type, evidence_location, decision
        ) VALUES (
          $1, $2, NULL, NULL, NULL, $3,
          'https://github.com/agent-labs/agent-a', 'github://agent-labs/agent-a',
          'ROOT_SOURCE', 0, 'seed_loader', 'SEED', 'root', 'QUEUED'
        ) RETURNING id;
      `, [edgeAId, rootSeedId, candAId]);

      // Insert Child 1 (MCP SDK dependency)
      const candBId = crypto.randomUUID();
      await pgClient.query(`
        INSERT INTO source.discovery_candidates (
          id, candidate_id, canonical_url, normalized_url, domain,
          discovery_confidence, status
        ) VALUES (
          $1, $1, 'https://www.npmjs.com/package/@modelcontextprotocol/sdk', 'npm://@modelcontextprotocol/sdk', 'npmjs.com',
          0.90, 'QUEUED'
        ) RETURNING id;
      `, [candBId]);

      await pgClient.query(`
        INSERT INTO source.discovery_edges (
          id, root_seed_id, parent_edge_id, source_candidate_id, source_agent_id, target_candidate_id,
          discovered_url, normalized_url, edge_type, crawl_depth, extractor,
          evidence_type, evidence_location, decision
        ) VALUES (
          $1, $2, $3, $4, $5, $6,
          'npm://@modelcontextprotocol/sdk', 'npm://@modelcontextprotocol/sdk',
          'DEPENDENCY', 1, 'package_manifest', 'PACKAGE_JSON', 'dependencies', 'QUEUED'
        );
      `, [crypto.randomUUID(), rootSeedId, edgeAId, candAId, agentParentId, candBId]);

      // Call descendants API
      const descendantsRes = await lineageService.getDiscoveredDescendants(agentParentId);

      expect(descendantsRes.total_descendants).toBe(1);
      expect(descendantsRes.max_depth).toBe(1);
      expect(descendantsRes.descendants[0].target_url).toBe('npm://@modelcontextprotocol/sdk');
      expect(descendantsRes.descendants[0].edge_type).toBe('DEPENDENCY');
      expect(descendantsRes.descendants[0].evidence.location).toBe('dependencies');
    });
  });

  describe('Part C — Real Observability Counters', () => {
    it('reports 0 for zero events on a fresh system (no fabricated numbers)', async () => {
      const metrics = await lineageService.getDiscoveryMetrics();

      expect(metrics.discovery_candidates_seen_total).toBe(0);
      expect(metrics.discovery_candidates_queued_total).toBe(0);
      expect(metrics.discovery_candidates_verified_total).toBe(0);
      expect(metrics.discovery_candidates_rejected_total).toBe(0);
      expect(metrics.discovery_duplicates_total).toBe(0);
      expect(metrics.discovery_pivots_generated_total).toBe(0);
      expect(metrics.discovery_depth_rejections_total).toBe(0);
      expect(metrics.discovery_budget_rejections_total).toBe(0);
      expect(metrics.discovery_ssrf_rejections_total).toBe(0);
      expect(metrics.discovery_robots_rejections_total).toBe(0);
      expect(metrics.discovery_rate_limit_events_total).toBe(0);
      expect(metrics.discovery_fetch_failures_total).toBe(0);
      expect(metrics.discovery_source_latency).toBe(0);
      expect(metrics.discovery_queue_depth).toBe(0);
      expect(metrics.discovery_agents_per_root).toBe(0);
      expect(metrics.discovery_pivot_conversion_rate).toBe(0);
    });

    it('tracks real system activity strictly from database state', async () => {
      // 1. Create root
      const rootRes = await pgClient.query(`
        INSERT INTO source.discovery_roots (
          source_adapter, root_type, root_value, active, metadata_json
        ) VALUES (
          'github', 'REPO_SEED', 'https://github.com/agent-labs/seed-test', true, '{}'::jsonb
        ) RETURNING id;
      `);
      const rootSeedId = rootRes.rows[0].id;

      // 2. Candidates: 1 verified, 1 queued, 1 rejected
      await pgClient.query(`
        INSERT INTO source.discovery_candidates (
          id, candidate_id, canonical_url, normalized_url, domain,
          discovery_confidence, status
        ) VALUES 
          (gen_random_uuid(), gen_random_uuid(), 'https://github.com/agent-labs/agent-1', 'github://agent-labs/agent-1', 'github.com', 0.95, 'VERIFIED_AGENT'),
          (gen_random_uuid(), gen_random_uuid(), 'https://github.com/agent-labs/agent-2', 'github://agent-labs/agent-2', 'github.com', 0.85, 'QUEUED'),
          (gen_random_uuid(), gen_random_uuid(), 'https://github.com/agent-labs/agent-3', 'github://agent-labs/agent-3', 'github.com', 0.20, 'REJECTED');
      `);

      // 3. Edges: 1 root edge + 2 pivot edges (one rejected for DEPTH_LIMIT, one rejected for SSRF)
      await pgClient.query(`
        INSERT INTO source.discovery_edges (
          id, root_seed_id, target_candidate_id, discovered_url, normalized_url, edge_type, crawl_depth,
          extractor, evidence_type, evidence_location, decision, rejection_reason
        ) VALUES 
          ($1, $2, gen_random_uuid(), 'https://github.com/agent-labs/agent-1', 'github://agent-labs/agent-1', 'ROOT_SOURCE', 0, 'seed', 'SEED', 'loc', 'QUEUED', NULL),
          ($3, $2, gen_random_uuid(), 'https://github.com/agent-labs/agent-4', 'github://agent-labs/agent-4', 'README_LINK', 4, 'readme', 'DOC', 'loc', 'REJECTED', 'DEPTH_LIMIT'),
          ($4, $2, gen_random_uuid(), 'https://github.com/agent-labs/agent-5', 'github://agent-labs/agent-5', 'DEPENDENCY', 1, 'manifest', 'PKG', 'loc', 'REJECTED', 'SSRF_BLOCKED');
      `, [crypto.randomUUID(), rootSeedId, crypto.randomUUID(), crypto.randomUUID()]);

      const metrics = await lineageService.getDiscoveryMetrics();

      expect(metrics.discovery_candidates_seen_total).toBe(3);
      expect(metrics.discovery_candidates_queued_total).toBe(1);
      expect(metrics.discovery_candidates_verified_total).toBe(1);
      expect(metrics.discovery_candidates_rejected_total).toBe(1);
      expect(metrics.discovery_pivots_generated_total).toBe(2);
      expect(metrics.discovery_depth_rejections_total).toBe(1);
      expect(metrics.discovery_ssrf_rejections_total).toBe(1);
      expect(metrics.discovery_agents_per_root).toBe(1); // 1 verified / 1 root = 1
      expect(metrics.discovery_pivot_conversion_rate).toBe(0.5); // 1 verified / 2 pivots = 0.5
    });
  });
});
