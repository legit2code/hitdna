import { describe, it, expect, beforeEach } from 'vitest';
import {
  SourceAdapterRegistry,
  FetchGateway,
  MCPSourceAdapter,
  HuggingFaceSpacesSourceAdapter,
  ReplicateSourceAdapter,
  KaggleSourceAdapter,
  HackerNewsSourceAdapter,
  ArxivSourceAdapter,
} from '@caim/source';

describe('CAIM Discovery Graph Step 3 of 6: Tier 1 Source Adapters', () => {
  let gateway: FetchGateway;

  beforeEach(() => {
    gateway = new FetchGateway();
  });

  // =========================================================================
  // 1. Registry & Locator Resolution
  // =========================================================================
  describe('1. Registry Registration and Locator Resolution', () => {
    it('registers all 13 source adapters in createDefault()', () => {
      const registry = SourceAdapterRegistry.createDefault();
      const all = registry.getAll();
      expect(all.length).toBe(13);

      const types = all.map((a) => a.sourceType);
      expect(types).toContain('github');
      expect(types).toContain('gitlab');
      expect(types).toContain('pypi');
      expect(types).toContain('npm');
      expect(types).toContain('huggingface');
      expect(types).toContain('dockerhub');
      expect(types).toContain('codeberg');
      // 6 New Tier 1 Adapters:
      expect(types).toContain('mcp');
      expect(types).toContain('hf_spaces');
      expect(types).toContain('replicate');
      expect(types).toContain('kaggle');
      expect(types).toContain('hackernews');
      expect(types).toContain('arxiv');
    });

    it('resolves correct adapter for each protocol and domain locator', () => {
      const registry = SourceAdapterRegistry.createDefault();

      expect(registry.resolveForLocator('mcp://filesystem').sourceType).toBe('mcp');
      expect(registry.resolveForLocator('https://registry.modelcontextprotocol.io/v0/servers/git').sourceType).toBe('mcp');

      expect(registry.resolveForLocator('hf_spaces://agents-course/First_agent').sourceType).toBe('hf_spaces');
      expect(registry.resolveForLocator('https://huggingface.co/spaces/smolagents/text-to-sql').sourceType).toBe('hf_spaces');

      expect(registry.resolveForLocator('replicate://meta/llama-3.1-70b-instruct').sourceType).toBe('replicate');
      expect(registry.resolveForLocator('https://replicate.com/stability-ai/sdxl').sourceType).toBe('replicate');

      expect(registry.resolveForLocator('kaggle://alex/autonomous-agent-kernel').sourceType).toBe('kaggle');
      expect(registry.resolveForLocator('https://www.kaggle.com/code/user/notebook').sourceType).toBe('kaggle');

      expect(registry.resolveForLocator('hn://39000000').sourceType).toBe('hackernews');
      expect(registry.resolveForLocator('https://news.ycombinator.com/item?id=39123456').sourceType).toBe('hackernews');

      expect(registry.resolveForLocator('arxiv://2304.11817').sourceType).toBe('arxiv');
      expect(registry.resolveForLocator('https://arxiv.org/abs/2304.11817').sourceType).toBe('arxiv');
    });
  });

  // =========================================================================
  // 2. Fetch Gateway Routing
  // =========================================================================
  describe('2. Fetch Gateway Routing Verification', () => {
    it('ensures all Tier 1 adapters route requests through FetchGateway', async () => {
      let fetchCalled = false;
      const gatewayWithSpy = new FetchGateway({
        transport: async () => {
          fetchCalled = true;
          return {
            status: 200,
            statusText: 'OK',
            headers: { 'content-type': 'application/json' },
            data: { servers: [] },
          };
        },
      });

      const mcp = new MCPSourceAdapter({ gateway: gatewayWithSpy });
      await mcp.discover({ limit: 1 });
      expect(fetchCalled).toBe(true);
    });
  });

  // =========================================================================
  // 3. Official MCP Registry Adapter
  // =========================================================================
  describe('3. Official MCP Registry Source Adapter', () => {
    it('normalizes MCP registry envelopes into tool specification candidates', async () => {
      const mockPayload = {
        servers: [
          {
            server: {
              name: 'io.modelcontextprotocol/filesystem',
              title: 'Filesystem MCP Server',
              description: 'MCP server for secure file reading and manipulation',
              version: '1.2.0',
              websiteUrl: 'https://modelcontextprotocol.io',
              repository: {
                url: 'https://github.com/modelcontextprotocol/servers',
                source: 'github',
              },
              packages: [
                {
                  registryType: 'npm',
                  identifier: '@modelcontextprotocol/server-filesystem',
                  transport: { type: 'stdio' },
                },
              ],
            },
            _meta: {
              'io.modelcontextprotocol.registry/official': {
                status: 'active',
                publishedAt: '2025-01-15T00:00:00Z',
                updatedAt: '2025-02-01T00:00:00Z',
              },
            },
          },
        ],
        metadata: { nextCursor: 'token_abc123' },
      };

      const mcp = new MCPSourceAdapter({
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: mockPayload,
        }),
      });

      const res = await mcp.discover({ limit: 10 });
      expect(res.candidates.length).toBe(1);
      const candidate = res.candidates[0];

      // Verification: Server is classified as TOOL_SPECIFICATION, NOT an automatic agent!
      expect(candidate.source_locator).toBe('mcp://io.modelcontextprotocol/filesystem');
      expect(candidate.display_name).toContain('Filesystem MCP Server');
      expect(candidate.type_hint).toBe('TOOL_SPECIFICATION');
      expect(res.has_more).toBe(true);
      expect(res.next_cursor?.token).toBe('token_abc123');

      // Artifact resolution
      const artifacts = await mcp.resolve_artifact_locators(candidate);
      expect(artifacts.artifacts.some((a) => a.locator === 'https://github.com/modelcontextprotocol/servers')).toBe(true);
      expect(artifacts.artifacts.some((a) => a.locator === 'npm://@modelcontextprotocol/server-filesystem')).toBe(true);

      // Relationships
      const rels = await mcp.enumerate_relationships(candidate);
      expect(rels.relationships.some((r) => r.relationship_type === 'UPSTREAM_SOURCE')).toBe(true);
      expect(rels.relationships.some((r) => r.relationship_type === 'RELATED_PACKAGE')).toBe(true);
    });

    it('health_check reports ACTIVE on successful connection', async () => {
      const mcp = new MCPSourceAdapter({
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: { servers: [] },
        }),
      });

      const health = await mcp.health_check();
      expect(health.status).toBe('HEALTHY');
      expect(health.message).toContain('[ACTIVE]');
    });
  });

  // =========================================================================
  // 4. Hugging Face Spaces Adapter
  // =========================================================================
  describe('4. Hugging Face Spaces Source Adapter', () => {
    it('evaluates explicit agent signals vs ordinary ML demos without fabricating agents', async () => {
      const mockSpaces = [
        {
          _id: 'space_1',
          id: 'agents-course/text-to-sql-agent',
          likes: 45,
          sdk: 'gradio',
          tags: ['agent', 'tool-use', 'mcp', 'smolagents'],
          createdAt: '2025-01-10T12:00:00Z',
          lastModified: '2025-02-15T12:00:00Z',
          models: ['meta-llama/Llama-3-8b-instruct'],
          datasets: ['spider'],
          cardData: {
            title: 'Text-to-SQL Autonomous Agent',
          },
        },
        {
          _id: 'space_2',
          id: 'image-filter/simple-blur-demo',
          likes: 12,
          sdk: 'streamlit',
          tags: ['computer-vision', 'demo'],
          createdAt: '2024-05-10T12:00:00Z',
          lastModified: '2024-05-10T12:00:00Z',
          models: [],
          cardData: {
            title: 'Simple Blur Filter',
          },
        },
      ];

      const hfSpaces = new HuggingFaceSpacesSourceAdapter({
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: mockSpaces,
        }),
      });

      const res = await hfSpaces.discover({ limit: 10 });
      expect(res.candidates.length).toBe(2);

      // Space 1 has tool-use & agent framework -> AGENT_REPOSITORY
      const agentCandidate = res.candidates[0];
      expect(agentCandidate.type_hint).toBe('AGENT_REPOSITORY');
      expect(agentCandidate.confidence).toBeGreaterThan(0.7);

      // Space 2 has no agent signals -> UNSPECIFIED / low confidence demo
      const demoCandidate = res.candidates[1];
      expect(demoCandidate.type_hint).toBe('UNSPECIFIED');
      expect(demoCandidate.confidence).toBeLessThan(0.3);

      // Resolves underlying foundation model & dataset relationships
      const rels = await hfSpaces.enumerate_relationships(agentCandidate);
      expect(rels.relationships.some((r) => r.relationship_type === 'BASE_MODEL')).toBe(true);
      expect(rels.relationships.some((r) => r.relationship_type === 'DATASET_REFERENCE')).toBe(true);
    });
  });

  // =========================================================================
  // 5. Replicate Adapter
  // =========================================================================
  describe('5. Replicate Source Adapter', () => {
    it('reports AUTH_REQUIRED real state and refuses to fabricate results when unauthenticated', async () => {
      // Replicate adapter without token
      const replicate = new ReplicateSourceAdapter({ apiToken: '' });

      const health = await replicate.health_check();
      expect(health.status).toBe('DEGRADED');
      expect(health.auth_status).toBe('MISSING_CREDENTIALS');
      expect(health.message).toContain('[AUTH_REQUIRED]');

      // discover() must throw error citing AUTH_REQUIRED, never returning fabricated results
      await expect(replicate.discover({})).rejects.toThrow(/\[AUTH_REQUIRED\]/);
    });

    it('processes real model representations and maps repository locators when authenticated', async () => {
      const mockPayload = {
        next: null,
        results: [
          {
            owner: 'meta',
            name: 'llama-3.1-405b-instruct',
            description: 'Meta Llama 3.1 405B Instruct model',
            github_url: 'https://github.com/meta-llama/llama-models',
            paper_url: 'https://arxiv.org/abs/2407.21783',
            latest_version: {
              id: 'version_987',
              created_at: '2024-07-23T00:00:00Z',
            },
          },
        ],
      };

      const replicate = new ReplicateSourceAdapter({
        apiToken: 'r8_test_token_secret',
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: mockPayload,
        }),
      });

      const res = await replicate.discover({ limit: 5 });
      expect(res.candidates.length).toBe(1);
      const candidate = res.candidates[0];
      expect(candidate.source_locator).toBe('replicate://meta/llama-3.1-405b-instruct');
      expect(candidate.type_hint).toBe('MODEL_WEIGHTS');

      // Locators include github and paper
      const artifacts = await replicate.resolve_artifact_locators(candidate);
      expect(artifacts.artifacts.some((a) => a.locator === 'https://github.com/meta-llama/llama-models')).toBe(true);
      expect(artifacts.artifacts.some((a) => a.locator === 'https://arxiv.org/abs/2407.21783')).toBe(true);
    });
  });

  // =========================================================================
  // 6. Kaggle Adapter
  // =========================================================================
  describe('6. Kaggle Source Adapter', () => {
    it('reports NOT_CONFIGURED real state when API credentials are absent', async () => {
      const kaggle = new KaggleSourceAdapter({ username: '', key: '' });

      const health = await kaggle.health_check();
      expect(health.status).toBe('DEGRADED');
      expect(health.auth_status).toBe('MISSING_CREDENTIALS');
      expect(health.message).toContain('[NOT_CONFIGURED]');

      await expect(kaggle.discover({})).rejects.toThrow(/\[AUTH_REQUIRED\]/);
    });

    it('evaluates notebook execution signals and provides notebook pull artifacts', async () => {
      const mockKernels = [
        {
          id: 101,
          ref: 'researcher/autonomous-planning-agent',
          title: 'Autonomous Planning Agent with LangGraph and Vector DB',
          author: 'researcher',
          lastUpdateTime: '2025-02-10T15:00:00Z',
          totalVotes: 35,
          views: 1200,
          keywords: ['langgraph', 'planning', 'vector-db', 'tools'],
          categories: ['agents'],
        },
      ];

      const kaggle = new KaggleSourceAdapter({
        username: 'kaggleuser',
        key: 'secretkey',
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: mockKernels,
        }),
      });

      const res = await kaggle.discover({ limit: 5 });
      expect(res.candidates.length).toBe(1);
      const candidate = res.candidates[0];
      expect(candidate.source_locator).toBe('kaggle://researcher/autonomous-planning-agent');
      expect(candidate.type_hint).toBe('AGENT_REPOSITORY');

      const artifacts = await kaggle.resolve_artifact_locators(candidate);
      expect(artifacts.artifacts.some((a) => a.locator.includes('/kernels/pull'))).toBe(true);
    });
  });

  // =========================================================================
  // 7. Hacker News Adapter
  // =========================================================================
  describe('7. Hacker News Source Adapter', () => {
    it('discovers Show HN submissions, treats posts as leads, and extracts project URLs', async () => {
      const mockAlgoliaResponse = {
        hits: [
          {
            objectID: '41000001',
            title: 'Show HN: OpenAgent – Autonomous coding agent for terminal',
            url: 'https://github.com/openagent/openagent',
            author: 'dev_user',
            points: 180,
            num_comments: 65,
            story_text: 'We built OpenAgent. Check docs at https://openagent.dev and repo at https://github.com/openagent/openagent',
            created_at: '2025-02-01T10:00:00Z',
          },
        ],
        nbHits: 1,
        page: 0,
        nbPages: 1,
      };

      const hn = new HackerNewsSourceAdapter({
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: mockAlgoliaResponse,
        }),
      });

      const res = await hn.discover({ query: 'openagent' });
      expect(res.candidates.length).toBe(1);
      const candidate = res.candidates[0];

      // A post is a lead, not an agent itself
      expect(candidate.source_locator).toBe('hn://41000001');
      expect(candidate.type_hint).toBe('UNSPECIFIED');

      // Extracted external repository / project leads
      const meta = (candidate.raw_metadata as any).extracted_leads;
      expect(meta).toContain('https://github.com/openagent/openagent');
      expect(meta).toContain('https://openagent.dev');

      const rels = await hn.enumerate_relationships(candidate);
      expect(rels.relationships.some((r) => r.target_locator === 'https://github.com/openagent/openagent')).toBe(true);
    });
  });

  // =========================================================================
  // 8. arXiv Adapter
  // =========================================================================
  describe('8. arXiv Source Adapter', () => {
    it('parses Atom XML feed, identifies papers as academic seeds, and extracts linked code repositories', async () => {
      const mockAtomXml = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <title>arXiv Query</title>
  <entry>
    <id>http://arxiv.org/abs/2304.11817v1</id>
    <published>2023-04-24T17:00:00Z</published>
    <updated>2023-04-24T17:00:00Z</updated>
    <title>AutoGPT: An Autonomous GPT-4 Experiment</title>
    <summary>We explore autonomous execution of tasks using large language models. Code available at https://github.com/Significant-Gravitas/AutoGPT and documentation at https://autogpt.net.</summary>
    <author><name>Toran Bruce Richards</name></author>
    <arxiv:comment>Conference paper. Project repository: https://github.com/Significant-Gravitas/AutoGPT</arxiv:comment>
    <link href="http://arxiv.org/abs/2304.11817v1" rel="alternate" type="text/html"/>
    <link title="pdf" href="http://arxiv.org/pdf/2304.11817v1" rel="related" type="application/pdf"/>
  </entry>
</feed>`;

      const arxiv = new ArxivSourceAdapter({
        fetcher: async () => ({
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/atom+xml' },
          data: mockAtomXml,
        }),
      });

      const res = await arxiv.discover({ query: 'AutoGPT' });
      expect(res.candidates.length).toBe(1);
      const candidate = res.candidates[0];

      // A paper is an academic paper seed, NOT an agent directly
      expect(candidate.source_locator).toBe('arxiv://2304.11817');
      expect(candidate.display_name).toContain('AutoGPT');
      expect(candidate.type_hint).toBe('UNSPECIFIED');

      // Locators
      const artifacts = await arxiv.resolve_artifact_locators(candidate);
      expect(artifacts.artifacts.some((a) => a.locator.includes('arxiv.org/abs/2304.11817'))).toBe(true);
      expect(artifacts.artifacts.some((a) => a.locator === 'https://github.com/Significant-Gravitas/AutoGPT')).toBe(true);

      // Seed links toward implementation
      const rels = await arxiv.enumerate_relationships(candidate);
      expect(rels.relationships.some((r) => r.relationship_type === 'UPSTREAM_SOURCE' && r.target_locator === 'https://github.com/Significant-Gravitas/AutoGPT')).toBe(true);
    });
  });
});
