import { describe, it, expect } from 'vitest';
import {
  SourceAdapter,
  GitHubSourceAdapter,
  GitLabSourceAdapter,
  PyPISourceAdapter,
  NpmSourceAdapter,
  HuggingFaceSourceAdapter,
  DockerHubSourceAdapter,
  CodebergSourceAdapter,
  SourceAdapterRegistry,
  DiscoveryEngine,
  createMockHttpFetcher,
  SourceAuthenticationError,
  SourceNotFoundError,
  SourceRateLimitExhaustedError,
  SourceTransientError,
  SourceNetworkError,
  normalizeSourceHttpError,
} from '@caim/source';
import { ProvenanceRecordSchema } from '@caim/contracts/provenance.ts';

describe('P11: Source Adapter Framework & Structured Discovery', () => {
  const mockFetcher = createMockHttpFetcher();

  const adapters: Array<{ name: string; adapter: SourceAdapter; testLocator: string }> = [
    {
      name: 'GitHub',
      adapter: new GitHubSourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'github://caim-org/autonomous-caim-agent',
    },
    {
      name: 'GitLab',
      adapter: new GitLabSourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'gitlab://security-research/caim-pipeline-runner',
    },
    {
      name: 'PyPI',
      adapter: new PyPISourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'pypi://caim-agent-sdk',
    },
    {
      name: 'npm',
      adapter: new NpmSourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'npm://@caim/contracts',
    },
    {
      name: 'Hugging Face',
      adapter: new HuggingFaceSourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'hf://models/caim-ai/caim-reasoner-7b',
    },
    {
      name: 'Docker Hub',
      adapter: new DockerHubSourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'docker://caimorg/caim-sandbox-runner',
    },
    {
      name: 'Codeberg',
      adapter: new CodebergSourceAdapter({ fetcher: mockFetcher }),
      testLocator: 'codeberg://libre-ai/caim-libre-agent',
    },
  ];

  describe('1. Shared Adapter Contract Conformance (All 7 Adapters)', () => {
    for (const { name, adapter, testLocator } of adapters) {
      describe(`Adapter: ${name}`, () => {
        it('1.1 should declare canonical metadata (sourceType, sourceName, adapterVersion)', () => {
          expect(adapter.sourceType).toBeDefined();
          expect(typeof adapter.sourceType).toBe('string');
          expect(adapter.sourceName).toBeDefined();
          expect(typeof adapter.sourceName).toBe('string');
          expect(adapter.adapterVersion).toBeDefined();
          expect(typeof adapter.adapterVersion).toBe('string');
        });

        it('1.2 should implement discover(criteria, cursor) returning candidates, cursor, and valid provenance', async () => {
          const res = await adapter.discover({ query: 'agent', limit: 5 });
          expect(res).toBeDefined();
          expect(Array.isArray(res.candidates)).toBe(true);
          expect(res.candidates.length).toBeGreaterThan(0);

          const first = res.candidates[0];
          expect(first.source_locator).toBeDefined();
          expect(first.source_type).toBe(adapter.sourceType);
          expect(first.display_name).toBeDefined();
          expect(first.confidence).toBeGreaterThanOrEqual(0);
          expect(first.confidence).toBeLessThanOrEqual(1.0);
          // Raw source metadata must be preserved
          expect(first.raw_metadata).toBeDefined();
          expect(typeof first.raw_metadata).toBe('object');

          // Provenance validation
          const prov = ProvenanceRecordSchema.safeParse(res.provenance);
          expect(prov.success).toBe(true);
        });

        it('1.3 should implement fetch_metadata(locator) preserving raw metadata and content hash', async () => {
          const res = await adapter.fetch_metadata(testLocator);
          expect(res).toBeDefined();
          expect(res.source_locator).toBeDefined();
          expect(res.raw_metadata).toBeDefined();
          expect(typeof res.raw_metadata).toBe('object');
          expect(res.content_hash).toMatch(/^[a-f0-9]{64}$/);
          expect(res.observed_at).toBeDefined();

          const prov = ProvenanceRecordSchema.safeParse(res.provenance);
          expect(prov.success).toBe(true);
        });

        it('1.4 should implement resolve_artifact_locators(candidate) resolving primary and secondary artifacts', async () => {
          const res = await adapter.resolve_artifact_locators(testLocator);
          expect(res).toBeDefined();
          expect(res.primary_locator).toBeDefined();
          expect(Array.isArray(res.artifacts)).toBe(true);
          expect(res.artifacts.length).toBeGreaterThan(0);

          const primary = res.artifacts.find(a => a.is_primary);
          expect(primary).toBeDefined();
          expect(primary?.locator).toBeDefined();

          const prov = ProvenanceRecordSchema.safeParse(res.provenance);
          expect(prov.success).toBe(true);
        });

        it('1.5 should implement enumerate_relationships(candidate) returning candidate relationships', async () => {
          const res = await adapter.enumerate_relationships(testLocator);
          expect(res).toBeDefined();
          expect(Array.isArray(res.relationships)).toBe(true);

          if (res.relationships.length > 0) {
            const rel = res.relationships[0];
            expect(rel.from_locator).toBeDefined();
            expect(rel.target_locator).toBeDefined();
            expect(rel.relationship_type).toBeDefined();
            expect(rel.depth).toBeGreaterThanOrEqual(1);
          }

          const prov = ProvenanceRecordSchema.safeParse(res.provenance);
          expect(prov.success).toBe(true);
        });

        it('1.6 should implement get_change_token(candidate) returning typed change token', async () => {
          const res = await adapter.get_change_token(testLocator);
          expect(res).toBeDefined();
          expect(res.source_locator).toBeDefined();
          expect(res.change_token).toBeDefined();
          expect(['ETAG', 'COMMIT_SHA', 'VERSION', 'DIGEST', 'TIMESTAMP']).toContain(res.token_type);
        });

        it('1.7 should implement get_rate_limit_state() returning explicit rate limit telemetry', () => {
          const rl = adapter.get_rate_limit_state();
          expect(rl).toBeDefined();
          expect(rl.limit).toBeGreaterThan(0);
          expect(rl.remaining).toBeGreaterThanOrEqual(0);
          expect(rl.window_seconds).toBeGreaterThan(0);
          expect(typeof rl.is_exhausted).toBe('boolean');
          expect(rl.reset_at).toBeDefined();
        });

        it('1.8 should implement get_source_policy() returning operational capabilities and policies', () => {
          const policy = adapter.get_source_policy();
          expect(policy).toBeDefined();
          expect(policy.source_type).toBe(adapter.sourceType);
          expect(['AUTHENTICATED', 'ANONYMOUS', 'DEGRADED', 'DISABLED']).toContain(policy.auth_mode);
          expect(policy.max_page_size).toBeGreaterThan(0);
          expect(policy.rate_limit_per_minute).toBeGreaterThan(0);
          expect(policy.capabilities).toBeDefined();
          expect(typeof policy.capabilities.can_search).toBe('boolean');
          expect(typeof policy.capabilities.provides_artifacts).toBe('boolean');
        });

        it('1.9 should implement health_check() reporting status and auth status', async () => {
          const health = await adapter.health_check();
          expect(health).toBeDefined();
          expect(['HEALTHY', 'DEGRADED', 'DISABLED', 'UNHEALTHY']).toContain(health.status);
          expect(['AUTHENTICATED', 'ANONYMOUS', 'MISSING_CREDENTIALS', 'INVALID_CREDENTIALS']).toContain(health.auth_status);
          expect(health.message).toBeDefined();
          expect(health.rate_limit).toBeDefined();
        });

        it('1.10 should implement generate_provenance() returning valid CAIM ProvenanceRecord', () => {
          const prov = adapter.generate_provenance('CUSTOM_ACTION', ['samplehash123']);
          const parsed = ProvenanceRecordSchema.safeParse(prov);
          expect(parsed.success).toBe(true);
          expect(prov.engine_signature).toContain(`caim:source-adapter:${adapter.sourceType}`);
        });
      });
    }
  });

  describe('2. Missing Credential & Degraded Status Handling', () => {
    it('2.1 should report DEGRADED auth mode when optional GitHub token is missing', async () => {
      const ghAdapter = new GitHubSourceAdapter({ token: undefined, fetcher: mockFetcher });
      const policy = ghAdapter.get_source_policy();
      expect(policy.auth_mode).toBe('DEGRADED');

      const health = await ghAdapter.health_check();
      expect(health.status).toBe('DEGRADED');
      expect(health.auth_status).toBe('ANONYMOUS');
      expect(health.message).toContain('degraded anonymous mode');
    });

    it('2.2 should report AUTHENTICATED when GitHub token is supplied', async () => {
      const ghAdapter = new GitHubSourceAdapter({ token: 'ghp_syntheticSecretToken12345', fetcher: mockFetcher });
      const policy = ghAdapter.get_source_policy();
      expect(policy.auth_mode).toBe('AUTHENTICATED');

      const health = await ghAdapter.health_check();
      expect(health.status).toBe('HEALTHY');
      expect(health.auth_status).toBe('AUTHENTICATED');
    });

    it('2.3 should report ANONYMOUS auth mode for PyPI and npm by default', () => {
      const pypi = new PyPISourceAdapter({ fetcher: mockFetcher });
      expect(pypi.get_source_policy().auth_mode).toBe('ANONYMOUS');

      const npm = new NpmSourceAdapter({ fetcher: mockFetcher });
      expect(npm.get_source_policy().auth_mode).toBe('ANONYMOUS');
    });
  });

  describe('3. Normalized Error Conversion', () => {
    it('3.1 should normalize 401/403 to SourceAuthenticationError', () => {
      const err = normalizeSourceHttpError('github', 401, 'Unauthorized', { message: 'Bad credentials' });
      expect(err).toBeInstanceOf(SourceAuthenticationError);
      expect((err as SourceAuthenticationError).authStatus).toBe('INVALID_CREDENTIALS');
      expect(err.isRetryable).toBe(false);
    });

    it('3.2 should normalize 404 to SourceNotFoundError', () => {
      const err = normalizeSourceHttpError('pypi', 404, 'Not Found', {}, 'pypi://nonexistent-pkg');
      expect(err).toBeInstanceOf(SourceNotFoundError);
      expect(err.statusCode).toBe(404);
      expect(err.locator).toBe('pypi://nonexistent-pkg');
    });

    it('3.3 should normalize 429 to SourceRateLimitExhaustedError', () => {
      const err = normalizeSourceHttpError('dockerhub', 429, 'Too Many Requests', 'Rate limit exceeded');
      expect(err).toBeInstanceOf(SourceRateLimitExhaustedError);
      expect((err as SourceRateLimitExhaustedError).retryAfterSeconds).toBeGreaterThan(0);
      expect(err.isRetryable).toBe(true);
    });

    it('3.4 should normalize 502/503 to SourceTransientError', () => {
      const err = normalizeSourceHttpError('gitlab', 503, 'Service Unavailable', 'Backend overloaded');
      expect(err).toBeInstanceOf(SourceTransientError);
      expect(err.statusCode).toBe(503);
      expect(err.isRetryable).toBe(true);
    });
  });

  describe('4. SourceAdapterRegistry & Dynamic Resolution', () => {
    it('4.1 should create default registry with all 13 adapters', () => {
      const reg = SourceAdapterRegistry.createDefault({
        github: { fetcher: mockFetcher },
        gitlab: { fetcher: mockFetcher },
        pypi: { fetcher: mockFetcher },
        npm: { fetcher: mockFetcher },
        huggingface: { fetcher: mockFetcher },
        dockerhub: { fetcher: mockFetcher },
        codeberg: { fetcher: mockFetcher },
        mcp: { fetcher: mockFetcher },
        hfSpaces: { fetcher: mockFetcher },
        replicate: { fetcher: mockFetcher },
        kaggle: { fetcher: mockFetcher },
        hackernews: { fetcher: mockFetcher },
        arxiv: { fetcher: mockFetcher },
      });

      const all = reg.getAll();
      expect(all.length).toBe(13);
      const types = all.map(a => a.sourceType).sort();
      expect(types).toEqual(['arxiv', 'codeberg', 'dockerhub', 'github', 'gitlab', 'hackernews', 'hf_spaces', 'huggingface', 'kaggle', 'mcp', 'npm', 'pypi', 'replicate']);
    });

    it('4.2 should resolve correct adapter for various locators polymorphically', () => {
      const reg = SourceAdapterRegistry.createDefault({
        github: { fetcher: mockFetcher },
        gitlab: { fetcher: mockFetcher },
        pypi: { fetcher: mockFetcher },
        npm: { fetcher: mockFetcher },
        huggingface: { fetcher: mockFetcher },
        dockerhub: { fetcher: mockFetcher },
        codeberg: { fetcher: mockFetcher },
        mcp: { fetcher: mockFetcher },
        hfSpaces: { fetcher: mockFetcher },
        replicate: { fetcher: mockFetcher },
        kaggle: { fetcher: mockFetcher },
        hackernews: { fetcher: mockFetcher },
        arxiv: { fetcher: mockFetcher },
      });

      expect(reg.resolveForLocator('github://owner/repo').sourceType).toBe('github');
      expect(reg.resolveForLocator('https://github.com/owner/repo').sourceType).toBe('github');
      expect(reg.resolveForLocator('gitlab://namespace/proj').sourceType).toBe('gitlab');
      expect(reg.resolveForLocator('pypi://requests').sourceType).toBe('pypi');
      expect(reg.resolveForLocator('npm://@scope/pkg').sourceType).toBe('npm');
      expect(reg.resolveForLocator('hf://models/meta/llama').sourceType).toBe('huggingface');
      expect(reg.resolveForLocator('docker://library/ubuntu').sourceType).toBe('dockerhub');
      expect(reg.resolveForLocator('codeberg://libre/agent').sourceType).toBe('codeberg');
    });
  });

  describe('5. GATE VERIFICATION: Source-Independent Discovery Engine (Zero Source Branching)', () => {
    it('5.1 should execute multi-source discovery across all 7 sources polymorphically', async () => {
      const registry = SourceAdapterRegistry.createDefault({
        github: { fetcher: mockFetcher },
        gitlab: { fetcher: mockFetcher },
        pypi: { fetcher: mockFetcher },
        npm: { fetcher: mockFetcher },
        huggingface: { fetcher: mockFetcher },
        dockerhub: { fetcher: mockFetcher },
        codeberg: { fetcher: mockFetcher },
        mcp: { fetcher: mockFetcher },
        hfSpaces: { fetcher: mockFetcher },
        replicate: { fetcher: mockFetcher },
        kaggle: { fetcher: mockFetcher },
        hackernews: { fetcher: mockFetcher },
        arxiv: { fetcher: mockFetcher },
      });

      const engine = new DiscoveryEngine(registry);

      const report = await engine.runDiscovery({
        criteria: { query: 'agent' },
        sourceTypes: ['codeberg', 'dockerhub', 'github', 'gitlab', 'huggingface', 'npm', 'pypi'],
        maxPagesPerSource: 1,
        maxCandidatesTotal: 50,
      });

      expect(report).toBeDefined();
      expect(report.status).toBe('COMPLETED');
      expect(report.totalCandidates).toBeGreaterThan(0);
      expect(report.packages.length).toBeGreaterThan(0);

      // Verify every source participated
      const sourceTypesDiscovered = Object.keys(report.sourceBreakdown).sort();
      expect(sourceTypesDiscovered).toEqual(['codeberg', 'dockerhub', 'github', 'gitlab', 'huggingface', 'npm', 'pypi']);

      for (const st of sourceTypesDiscovered) {
        expect(report.sourceBreakdown[st].pagesFetched).toBe(1);
        expect(report.sourceBreakdown[st].candidatesDiscovered).toBeGreaterThan(0);
      }

      // Verify enriched entity packages contain metadata, artifacts, and relationships
      for (const pkg of report.packages) {
        expect(pkg.candidate.source_locator).toBeDefined();
        expect(pkg.metadata.content_hash).toBeDefined();
        expect(pkg.artifacts.primary_locator).toBeDefined();
        expect(Array.isArray(pkg.relationships.relationships)).toBe(true);

        const prov = ProvenanceRecordSchema.safeParse(pkg.provenance);
        expect(prov.success).toBe(true);
      }
    });

    it('5.2 should perform polymorphic health check across all registered adapters', async () => {
      const registry = SourceAdapterRegistry.createDefault({
        github: { fetcher: mockFetcher },
        gitlab: { fetcher: mockFetcher },
        pypi: { fetcher: mockFetcher },
        npm: { fetcher: mockFetcher },
        huggingface: { fetcher: mockFetcher },
        dockerhub: { fetcher: mockFetcher },
        codeberg: { fetcher: mockFetcher },
        mcp: { fetcher: mockFetcher },
        hfSpaces: { fetcher: mockFetcher },
        replicate: { fetcher: mockFetcher },
        kaggle: { fetcher: mockFetcher },
        hackernews: { fetcher: mockFetcher },
        arxiv: { fetcher: mockFetcher },
      });

      const engine = new DiscoveryEngine(registry);
      const healthMap = await engine.checkAllHealth();

      expect(Object.keys(healthMap).length).toBe(13);
      for (const [sourceType, health] of Object.entries(healthMap)) {
        expect(['HEALTHY', 'DEGRADED']).toContain(health.status);
        expect(health.rate_limit).toBeDefined();
      }
    });
  });
});
