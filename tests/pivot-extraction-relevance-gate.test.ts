import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestDb } from '@caim/db/migrator.ts';
import {
  DiscoveryGraphEngine,
  PivotExtractor,
  RelevanceGate,
  VerifiedAgentContent,
} from '@caim/source';

describe('Step 5 of 6 — Pivot Extraction & Relevance Gate', () => {
  let memDb: any;
  let pgClient: any;
  let engine: DiscoveryGraphEngine;

  beforeEach(async () => {
    memDb = createTestDb();
    const pgMem = memDb.adapters.createPg();
    pgClient = new pgMem.Client();
    await pgClient.connect();
    engine = new DiscoveryGraphEngine(pgClient);
  });

  afterEach(async () => {
    if (pgClient) {
      await pgClient.end();
    }
  });

  // Real verified agent fixture exercising all 6 pivot extraction signals
  const verifiedAgentFixture: VerifiedAgentContent = {
    locator: 'https://github.com/agent-labs/autonomous-coder',
    source_type: 'github',
    source_agent_id: 'a0000000-0000-0000-0000-000000000101',
    metadata: {
      name: 'autonomous-coder',
      description: 'Autonomous software engineering agent powered by LLMs and MCP tools',
    },
    readme: `
# Autonomous Coder

Autonomous software engineering agent that plans, codes, and executes tasks.

## Inspired By
- Inspired by [BabyAGI](https://github.com/yoheinakajima/babyagi)

## Related Projects
- Built on top of [AutoGen](https://github.com/microsoft/autogen) and [LlamaIndex](https://github.com/run-llama/llama_index)
- Check our documentation at [Autonomous Docs](https://docs.autonomous-coder.dev/guide)
- Follow the author on [Twitter](https://twitter.com/agent_labs)
- Support development on [Patreon](https://patreon.com/agentlabs)
- Build status: [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
`,
    manifests: {
      package_json: {
        name: 'autonomous-coder',
        dependencies: {
          '@modelcontextprotocol/sdk': '^1.0.0', // Agent framework / MCP SDK -> ACCEPT
          'langchain': '^0.1.0',                 // Agent framework -> ACCEPT
          'lodash': '^4.17.21',                  // General utility -> REJECT (GENERAL_LIBRARY)
          'chalk': '^5.0.0',                     // CLI styling -> REJECT (GENERAL_LIBRARY)
          'express': '^4.18.2',                  // Web server -> REJECT (GENERAL_LIBRARY)
        },
        devDependencies: {
          'jest': '^29.0.0',                     // Test runner -> REJECT (GENERAL_LIBRARY)
        },
      },
      requirements_txt: `
crewai>=0.1.0
numpy>=1.24.0
pytest>=7.0.0
requests>=2.28.0
      `,
    },
    maintainer_repos: [
      {
        name: 'agent-memory-engine',
        full_name: 'agent-labs/agent-memory-engine',
        html_url: 'https://github.com/agent-labs/agent-memory-engine',
        description: 'Hierarchical long-term episodic memory for autonomous agents',
        topics: ['agent', 'memory', 'rag', 'llm'],
        stargazers_count: 240,
      },
      {
        name: 'dotfiles',
        full_name: 'agent-labs/dotfiles',
        html_url: 'https://github.com/agent-labs/dotfiles',
        description: 'Personal terminal and shell configuration files',
        topics: ['dotfiles', 'zsh', 'tmux'],
        stargazers_count: 12,
      },
    ],
    fork_metadata: {
      is_fork: true,
      parent_url: 'https://github.com/stale-org/stale-agent-template',
      parent_name: 'stale-org/stale-agent-template',
      commits_ahead: 0,
      commits_behind: 140,
      independent_releases: false,
      substantive_delta: false,
    },
    mcp_references: [
      {
        server_name: 'postgres-mcp-server',
        url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/postgres',
      },
    ],
    demo_links: [
      {
        url: 'https://huggingface.co/spaces/agent-labs/autonomous-coder-demo',
        title: 'Live Interactive Demo on Hugging Face Spaces',
        type: 'HUGGING_FACE_SPACE',
      },
    ],
  };

  describe('Part A — Signal Extraction from Verified Agent', () => {
    it('extracts candidate pivots across all applicable signals', () => {
      const { pivots, source_content_hash } = PivotExtractor.extractFromVerifiedAgent(verifiedAgentFixture);

      expect(source_content_hash).toBeDefined();
      expect(pivots.length).toBeGreaterThan(10);

      // Verify presence of README extracted links
      const babyagiPivot = pivots.find((p) => p.normalized_url.includes('babyagi'));
      expect(babyagiPivot).toBeDefined();
      expect(babyagiPivot?.extractor).toBe('README_DOCUMENTATION_EXTRACTOR');
      expect(babyagiPivot?.edge_type).toBe('RELATED_PROJECT');

      const autogenPivot = pivots.find((p) => p.normalized_url.includes('autogen'));
      expect(autogenPivot).toBeDefined();
      expect(autogenPivot?.extractor).toBe('README_DOCUMENTATION_EXTRACTOR');

      // Verify presence of package manifest dependencies
      const mcpSdk = pivots.find((p) => p.discovered_url === 'npm://@modelcontextprotocol/sdk');
      expect(mcpSdk).toBeDefined();
      expect(mcpSdk?.extractor).toBe('MANIFEST_DEPENDENCY_EXTRACTOR');

      const lodash = pivots.find((p) => p.discovered_url === 'npm://lodash');
      expect(lodash).toBeDefined();
      expect(lodash?.extractor).toBe('MANIFEST_DEPENDENCY_EXTRACTOR');

      const crewai = pivots.find((p) => p.discovered_url === 'pypi://crewai');
      expect(crewai).toBeDefined();
      expect(crewai?.extractor).toBe('MANIFEST_DEPENDENCY_EXTRACTOR');

      const numpy = pivots.find((p) => p.discovered_url === 'pypi://numpy');
      expect(numpy).toBeDefined();
      expect(numpy?.extractor).toBe('MANIFEST_DEPENDENCY_EXTRACTOR');

      // Verify presence of maintainer repos
      const memoryRepo = pivots.find((p) => p.discovered_url.includes('agent-memory-engine'));
      expect(memoryRepo).toBeDefined();
      expect(memoryRepo?.edge_type).toBe('MAINTAINER_OTHER_REPO');

      const dotfilesRepo = pivots.find((p) => p.discovered_url.includes('dotfiles'));
      expect(dotfilesRepo).toBeDefined();

      // Verify presence of fork metadata
      const forkPivot = pivots.find((p) => p.discovered_url.includes('stale-agent-template'));
      expect(forkPivot).toBeDefined();
      expect(forkPivot?.edge_type).toBe('FORK');

      // Verify presence of MCP references
      const mcpPivot = pivots.find((p) => p.edge_type === 'MCP_REFERENCE');
      expect(mcpPivot).toBeDefined();
      expect(mcpPivot?.extractor).toBe('MCP_REFERENCE_EXTRACTOR');

      // Verify presence of Demo / Space link
      const demoPivot = pivots.find((p) => p.edge_type === 'DEMO_LINK');
      expect(demoPivot).toBeDefined();
      expect(demoPivot?.domain).toBe('huggingface.co');
    });
  });

  describe('Part B — Deterministic Relevance Gate (Noise Rejection)', () => {
    it('accepts agent frameworks and rejects general-purpose libraries and noise with accurate reasons', () => {
      const { pivots } = PivotExtractor.extractFromVerifiedAgent(verifiedAgentFixture);

      // 1. Agent frameworks: ACCEPTED
      const mcpSdk = pivots.find((p) => p.discovered_url === 'npm://@modelcontextprotocol/sdk');
      expect(mcpSdk?.relevance_gate_decision?.accepted).toBe(true);

      const langchain = pivots.find((p) => p.discovered_url === 'npm://langchain');
      expect(langchain?.relevance_gate_decision?.accepted).toBe(true);

      const crewai = pivots.find((p) => p.discovered_url === 'pypi://crewai');
      expect(crewai?.relevance_gate_decision?.accepted).toBe(true);

      // 2. General-purpose libraries: REJECTED with GENERAL_LIBRARY
      const lodash = pivots.find((p) => p.discovered_url === 'npm://lodash');
      expect(lodash?.relevance_gate_decision?.accepted).toBe(false);
      expect(lodash?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      const chalk = pivots.find((p) => p.discovered_url === 'npm://chalk');
      expect(chalk?.relevance_gate_decision?.accepted).toBe(false);
      expect(chalk?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      const express = pivots.find((p) => p.discovered_url === 'npm://express');
      expect(express?.relevance_gate_decision?.accepted).toBe(false);
      expect(express?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      const jestPkg = pivots.find((p) => p.discovered_url === 'npm://jest');
      expect(jestPkg?.relevance_gate_decision?.accepted).toBe(false);
      expect(jestPkg?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      const numpy = pivots.find((p) => p.discovered_url === 'pypi://numpy');
      expect(numpy?.relevance_gate_decision?.accepted).toBe(false);
      expect(numpy?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      const pytest = pivots.find((p) => p.discovered_url === 'pypi://pytest');
      expect(pytest?.relevance_gate_decision?.accepted).toBe(false);
      expect(pytest?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      const requests = pivots.find((p) => p.discovered_url === 'pypi://requests');
      expect(requests?.relevance_gate_decision?.accepted).toBe(false);
      expect(requests?.relevance_gate_decision?.rejection_reason).toBe('GENERAL_LIBRARY');

      // 3. Documentation site: REJECTED with DOCUMENTATION_ONLY
      const docs = pivots.find((p) => p.discovered_url.includes('docs.autonomous-coder.dev'));
      expect(docs?.relevance_gate_decision?.accepted).toBe(false);
      expect(docs?.relevance_gate_decision?.rejection_reason).toBe('DOCUMENTATION_ONLY');

      // 4. Social profile: REJECTED with SOCIAL_PROFILE
      const twitter = pivots.find((p) => p.discovered_url.includes('twitter.com'));
      expect(twitter?.relevance_gate_decision?.accepted).toBe(false);
      expect(twitter?.relevance_gate_decision?.rejection_reason).toBe('SOCIAL_PROFILE');

      // 5. Donation link: REJECTED with DONATION_LINK
      const patreon = pivots.find((p) => p.discovered_url.includes('patreon.com'));
      expect(patreon?.relevance_gate_decision?.accepted).toBe(false);
      expect(patreon?.relevance_gate_decision?.rejection_reason).toBe('DONATION_LINK');

      // 6. Badge/license link: REJECTED with ASSET_OR_BADGE
      const badge = pivots.find((p) => p.discovered_url.includes('shields.io'));
      expect(badge?.relevance_gate_decision?.accepted).toBe(false);
      expect(badge?.relevance_gate_decision?.rejection_reason).toBe('ASSET_OR_BADGE');

      // 7. Stale fork with 0 commits ahead: REJECTED with STALE_FORK
      const fork = pivots.find((p) => p.discovered_url.includes('stale-agent-template'));
      expect(fork?.relevance_gate_decision?.accepted).toBe(false);
      expect(fork?.relevance_gate_decision?.rejection_reason).toBe('STALE_FORK');

      // 8. Maintainer repo without agent topics: REJECTED with UNRELATED_DOMAIN
      const dotfiles = pivots.find((p) => p.discovered_url.includes('dotfiles'));
      expect(dotfiles?.relevance_gate_decision?.accepted).toBe(false);
      expect(dotfiles?.relevance_gate_decision?.rejection_reason).toBe('UNRELATED_DOMAIN');

      // 9. Maintainer repo WITH agent topics: ACCEPTED
      const memoryEngine = pivots.find((p) => p.discovered_url.includes('agent-memory-engine'));
      expect(memoryEngine?.relevance_gate_decision?.accepted).toBe(true);

      // 10. Demo deployment URL: ACCEPTED
      const demo = pivots.find((p) => p.edge_type === 'DEMO_LINK');
      expect(demo?.relevance_gate_decision?.accepted).toBe(true);
    });
  });

  describe('Part C & D — Database Persistence & Candidate Leakage Prevention', () => {
    it('persists QUEUED vs REJECTED edges with rejection reasons, and confirms zero general libraries leak into QUEUED candidates', async () => {
      // 1. Setup root seed
      const rootRes = await engine.registerRoot(
        'github',
        'REPOSITORY',
        'https://github.com/agent-labs/autonomous-coder'
      );

      const rootSeedId = rootRes.root.id;
      const rootEdgeId = rootRes.edge.id;
      const rootCandId = rootRes.candidate.id;

      // 2. Extract pivots
      const { pivots, source_content_hash } = PivotExtractor.extractFromVerifiedAgent(verifiedAgentFixture);

      // 3. Schedule pivots through the engine
      const scheduleResult = await engine.evaluateAndSchedulePivots({
        root_seed_id: rootSeedId,
        parent_edge_id: rootEdgeId,
        source_candidate_id: rootCandId,
        source_agent_id: verifiedAgentFixture.source_agent_id,
        parent_crawl_depth: 0,
        cycle_id: 'test-pivot-cycle-1',
        pivots,
        source_content_hash,
      });

      // Verify boundary violations
      expect(scheduleResult.boundary_violations.relevance_gate_rejected).toBeGreaterThan(0);
      expect(scheduleResult.accepted_edges.length).toBeGreaterThan(0);
      expect(scheduleResult.rejected_edges.length).toBeGreaterThan(0);

      // 4. Query source.discovery_edges to verify decisions and rejection reasons
      const edgesRes = await pgClient.query(`
        SELECT discovered_url, edge_type, decision, rejection_reason, metadata_json
        FROM source.discovery_edges
        WHERE root_seed_id = $1;
      `, [rootSeedId]);

      const allEdges = edgesRes.rows;

      // Check specific rejected edges in database
      const lodashEdge = allEdges.find((e: any) => e.discovered_url === 'npm://lodash');
      expect(lodashEdge).toBeDefined();
      expect(lodashEdge.decision).toBe('REJECTED');
      expect(lodashEdge.rejection_reason).toBe('GENERAL_LIBRARY');

      const numpyEdge = allEdges.find((e: any) => e.discovered_url === 'pypi://numpy');
      expect(numpyEdge).toBeDefined();
      expect(numpyEdge.decision).toBe('REJECTED');
      expect(numpyEdge.rejection_reason).toBe('GENERAL_LIBRARY');

      const twitterEdge = allEdges.find((e: any) => e.discovered_url.includes('twitter.com'));
      expect(twitterEdge).toBeDefined();
      expect(twitterEdge.decision).toBe('REJECTED');
      expect(twitterEdge.rejection_reason).toBe('SOCIAL_PROFILE');

      const forkEdge = allEdges.find((e: any) => e.discovered_url.includes('stale-agent-template'));
      expect(forkEdge).toBeDefined();
      expect(forkEdge.decision).toBe('REJECTED');
      expect(forkEdge.rejection_reason).toBe('STALE_FORK');

      // Check specific accepted edges in database
      const mcpSdkEdge = allEdges.find((e: any) => e.discovered_url === 'npm://@modelcontextprotocol/sdk');
      expect(mcpSdkEdge).toBeDefined();
      expect(mcpSdkEdge.decision).toBe('QUEUED');
      expect(mcpSdkEdge.rejection_reason).toBeNull();

      const memoryRepoEdge = allEdges.find((e: any) => e.discovered_url.includes('agent-memory-engine'));
      expect(memoryRepoEdge).toBeDefined();
      expect(memoryRepoEdge.decision).toBe('QUEUED');
      expect(memoryRepoEdge.rejection_reason).toBeNull();

      // 5. CRITICAL REQUIREMENT: Verify NO general-purpose library dependencies leaked into discovery_candidates as QUEUED
      const queuedCandidatesRes = await pgClient.query(`
        SELECT normalized_url, canonical_url, status, rejection_reason
        FROM source.discovery_candidates
        WHERE status = 'QUEUED';
      `);

      const queuedCandidates = queuedCandidatesRes.rows;
      const queuedUrls = queuedCandidates.map((c: any) => c.normalized_url.toLowerCase());

      // General utility libraries MUST NOT be queued
      expect(queuedUrls).not.toContain('npm://lodash');
      expect(queuedUrls).not.toContain('npm://chalk');
      expect(queuedUrls).not.toContain('npm://express');
      expect(queuedUrls).not.toContain('npm://jest');
      expect(queuedUrls).not.toContain('pypi://numpy');
      expect(queuedUrls).not.toContain('pypi://pytest');
      expect(queuedUrls).not.toContain('pypi://requests');

      // Instead, verify they are in discovery_candidates as REJECTED with rejection_reason
      const rejectedCandidatesRes = await pgClient.query(`
        SELECT normalized_url, status, rejection_reason
        FROM source.discovery_candidates
        WHERE status = 'REJECTED';
      `);

      const rejectedCandidates = rejectedCandidatesRes.rows;
      const lodashCand = rejectedCandidates.find((c: any) => c.normalized_url === 'npm://lodash');
      expect(lodashCand).toBeDefined();
      expect(lodashCand.status).toBe('REJECTED');
      expect(lodashCand.rejection_reason).toBe('GENERAL_LIBRARY');

      const numpyCand = rejectedCandidates.find((c: any) => c.normalized_url === 'pypi://numpy');
      expect(numpyCand).toBeDefined();
      expect(numpyCand.status).toBe('REJECTED');
      expect(numpyCand.rejection_reason).toBe('GENERAL_LIBRARY');
    });
  });
});
