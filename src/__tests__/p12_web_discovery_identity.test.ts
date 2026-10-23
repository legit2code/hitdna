import { describe, it, expect, beforeEach } from 'vitest';
import {
  BraveSearchProvider,
  QueryStrategyRegistry,
  FreshnessScheduler,
  ArtifactClassifier,
  IdentityResolver,
  ManualReviewQueue,
  RecursiveExpansionEngine,
  SourceAdapterRegistry,
  createMockHttpFetcher,
  EntityObservation,
} from '@caim/source';

describe('P12 — General Web Discovery, Recursive Expansion, Classification & Identity', () => {
  const mockFetcher = createMockHttpFetcher();

  // ---------------------------------------------------------------------------
  // 1. WebSearchProvider & Brave Search Implementation
  // ---------------------------------------------------------------------------
  describe('1. WebSearchProvider & BraveSearchProvider', () => {
    it('initializes with degraded status when BRAVE_API_KEY is not configured', async () => {
      const provider = new BraveSearchProvider({ apiKey: undefined, fetcher: undefined });
      const health = await provider.health_check();
      expect(health.status).toBe('DEGRADED');
      expect(health.auth_status).toBe('MISSING_CREDENTIALS');
    });

    it('executes web search queries with synthetic fetcher and returns structured items and provenance', async () => {
      const provider = new BraveSearchProvider({ apiKey: 'synth-brave-key', fetcher: mockFetcher });
      const result = await provider.search('autonomous caim agent', { count: 5 });

      expect(result.query).toBe('autonomous caim agent');
      expect(result.provider).toBe('BraveSearch');
      expect(result.items.length).toBeGreaterThan(0);

      const first = result.items[0];
      expect(first.title).toBeDefined();
      expect(first.url).toBeDefined();
      expect(first.description).toBeDefined();
      expect(first.source_hostname).toBeDefined();
      expect(first.confidence).toBeGreaterThan(0.5);

      // Provenance
      expect(result.provenance).toBeDefined();
      expect(result.provenance.rule_id).toBe('WEB_SEARCH_WEB_SEARCH');
      expect(result.provenance.engine_signature).toContain('caim:web-search');
    });

    it('tracks rate limits correctly', async () => {
      const provider = new BraveSearchProvider({ apiKey: 'synth-brave-key', fetcher: mockFetcher });
      const rateState = provider.get_rate_limit_state();
      expect(rateState.limit).toBe(1000);
      expect(rateState.remaining).toBe(1000);
      expect(rateState.is_exhausted).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Query Strategy & Rules Registry
  // ---------------------------------------------------------------------------
  describe('2. QueryStrategyRegistry', () => {
    let registry: QueryStrategyRegistry;

    beforeEach(() => {
      registry = new QueryStrategyRegistry();
    });

    it('loads default query rules across all required query families', () => {
      const rules = registry.getAllRules();
      expect(rules.length).toBeGreaterThanOrEqual(7);

      const families = rules.map(r => r.family);
      expect(families).toContain('AGENT_DISCOVERY');
      expect(families).toContain('TOOL_ECOSYSTEM');
      expect(families).toContain('MODEL_WEIGHTS');
      expect(families).toContain('CODE_REPOSITORY');
      expect(families).toContain('PACKAGE_DISTRIBUTION');
      expect(families).toContain('CONTAINER_SANDBOX');
      expect(families).toContain('SPECIFICATION_STANDARD');
    });

    it('generates formatted query strings from seed keywords prioritized by strategy', () => {
      const generated = registry.generateQueries('caim-agent');
      expect(generated.length).toBeGreaterThan(0);
      expect(generated[0].query).toContain('caim-agent');
      expect(generated[0].priority).toBeLessThanOrEqual(generated[generated.length - 1].priority);
    });

    it('filters query generation by family or target source', () => {
      const modelQueries = registry.generateQueries('reasoner', { family: 'MODEL_WEIGHTS' });
      expect(modelQueries.every(q => q.family === 'MODEL_WEIGHTS')).toBe(true);
      expect(modelQueries[0].query).toContain('huggingface');
    });

    it('allows toggling rule enabled state', () => {
      const ruleId = 'RULE_AGENT_DISCOVERY_PRIMARY';
      expect(registry.setRuleEnabled(ruleId, false)).toBe(true);
      expect(registry.getRule(ruleId)?.enabled).toBe(false);

      const activeRules = registry.getAllRules().filter(r => r.enabled);
      expect(activeRules.some(r => r.id === ruleId)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Freshness Scheduler & Metrics
  // ---------------------------------------------------------------------------
  describe('3. FreshnessScheduler & Metrics', () => {
    let scheduler: FreshnessScheduler;

    beforeEach(() => {
      scheduler = new FreshnessScheduler();
    });

    it('evaluates recently observed locators as FRESH', () => {
      const res = scheduler.recordObservation({
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        strategy_id: 'RULE_AGENT_DISCOVERY_PRIMARY',
        change_token: 'commit-sha-1234',
        token_type: 'COMMIT_SHA',
        observed_at: new Date().toISOString(),
      });

      expect(res.status).toBe('FRESH');
      expect(res.age_seconds).toBeLessThan(10);
      expect(res.change_token).toBe('commit-sha-1234');
    });

    it('evaluates older observations as STALE or EXPIRED based on TTL', () => {
      const twoHoursAgo = new Date(Date.now() - 7200 * 1000).toISOString();
      scheduler.recordObservation({
        source_locator: 'github://caim-org/stale-agent',
        source_type: 'github', // default TTL = 3600s
        observed_at: twoHoursAgo,
      });

      const evalRes = scheduler.evaluateLocator('github://caim-org/stale-agent');
      expect(evalRes.status).toBe('EXPIRED');
    });

    it('computes coverage & freshness metrics with explicit bounded sample notice', () => {
      scheduler.recordObservation({
        source_locator: 'github://caim-org/agent-1',
        source_type: 'github',
        observed_at: new Date().toISOString(),
      });
      scheduler.recordObservation({
        source_locator: 'pypi://caim-package',
        source_type: 'pypi',
        observed_at: new Date().toISOString(),
      });

      const metrics = scheduler.computeMetrics('24h');
      expect(metrics.total_observed).toBe(2);
      expect(metrics.fresh_count).toBe(2);
      expect(metrics.freshness_ratio).toBe(1.0);
      expect(metrics.by_source.github.total).toBe(1);
      expect(metrics.by_source.pypi.total).toBe(1);

      // Verify strict directive: Never claim complete internet coverage
      expect(metrics.sample_coverage_note).toContain('Bounded Public Discovery Sample');
      expect(metrics.sample_coverage_note).toContain('Never claim complete Internet coverage');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Recursive Expansion Engine
  // ---------------------------------------------------------------------------
  describe('4. RecursiveExpansionEngine', () => {
    let registry: SourceAdapterRegistry;
    let engine: RecursiveExpansionEngine;

    beforeEach(() => {
      registry = SourceAdapterRegistry.createDefault({
        github: { fetcher: mockFetcher },
        pypi: { fetcher: mockFetcher },
        npm: { fetcher: mockFetcher },
      });
      engine = new RecursiveExpansionEngine(registry);
    });

    it('recursively expands relationships within max_depth bounds', async () => {
      const report = await engine.expand(
        ['github://caim-org/autonomous-caim-agent'],
        { max_depth: 2, max_total_candidates: 20 }
      );

      expect(report.expansion_id).toBeDefined();
      expect(report.depth_reached).toBeLessThanOrEqual(2);
      expect(report.total_candidates_discovered).toBeGreaterThan(0);
      expect(report.tree.length).toBe(1);
      expect(report.tree[0].locator).toBe('github://caim-org/autonomous-caim-agent');
      expect(report.provenance.rule_id).toBe('RECURSIVE_RELATIONSHIP_EXPANSION_V1');
    });

    it('enforces candidate budget limit and reports budget exhaustion reason', async () => {
      const report = await engine.expand(
        ['github://caim-org/autonomous-caim-agent', 'pypi://autonomous-caim-agent'],
        { max_depth: 3, max_total_candidates: 1 }
      );

      expect(report.budget_exhausted).toBe(true);
      expect(report.budget_exhaustion_reason).toBe('MAX_CANDIDATES');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Artifact Classification Taxonomy & Confidence
  // ---------------------------------------------------------------------------
  describe('5. ArtifactClassifier', () => {
    let classifier: ArtifactClassifier;

    beforeEach(() => {
      classifier = new ArtifactClassifier();
    });

    it('classifies Hugging Face safetensors model repositories as REASONING_MODEL', () => {
      const result = classifier.classify({
        candidate: {
          source_locator: 'hf://caim-org/caim-reasoner-7b',
          display_name: 'caim-reasoner-7b',
          source_type: 'huggingface',
          summary: 'Fine-tuned reasoning model weights in safetensors format with pipeline_tag text-generation',
        },
        artifacts: {
          source_locator: 'hf://caim-org/caim-reasoner-7b',
          primary_locator: 'hf://caim-org/caim-reasoner-7b/model.safetensors',
          artifacts: [
            {
              artifact_type: 'MODEL_FILE',
              locator: 'hf://caim-org/caim-reasoner-7b/model.safetensors',
              filename: 'model.safetensors',
              is_primary: true,
            },
          ],
          provenance: {} as any,
        },
      });

      expect(result.primary_category).toBe('REASONING_MODEL');
      expect(result.confidence).toBeGreaterThanOrEqual(0.7);
      expect(result.signals.some(s => s.feature === 'SOURCE_HUGGINGFACE' && s.matched)).toBe(true);
      expect(result.signals.some(s => s.feature === 'WEIGHTS_ARTIFACTS' && s.matched)).toBe(true);
    });

    it('classifies DockerHub images as CONTAINER_SANDBOX', () => {
      const result = classifier.classify({
        candidate: {
          source_locator: 'docker://caim-org/sandbox-runner:latest',
          display_name: 'sandbox-runner',
          source_type: 'dockerhub',
          summary: 'OCI Container execution sandbox for autonomous agent tasks',
        },
      });

      expect(result.primary_category).toBe('CONTAINER_SANDBOX');
      expect(result.confidence).toBeGreaterThanOrEqual(0.6);
    });

    it('classifies CAIM ontology specifications as AGENT_SPECIFICATION', () => {
      const result = classifier.classify({
        candidate: {
          source_locator: 'https://caim.dev/spec/ontology-schema.json',
          display_name: 'caim-ontology-spec',
          source_type: 'web',
          summary: 'Official CAIM specification schema and ontology manifest definitions',
        },
      });

      expect(result.primary_category).toBe('AGENT_SPECIFICATION');
      expect(result.confidence).toBeGreaterThanOrEqual(0.4);
    });

    it('classifies Autonomous Agents with high confidence and rationale', () => {
      const result = classifier.classify({
        candidate: {
          source_locator: 'github://caim-org/autonomous-caim-agent',
          display_name: 'autonomous-caim-agent',
          source_type: 'github',
          summary: 'Reference autonomous caim agent with reasoning, memory, tools and planning loop',
        },
      });

      expect(result.primary_category).toBe('AUTONOMOUS_AGENT');
      expect(result.confidence).toBeGreaterThanOrEqual(0.5);
      expect(result.rationale).toContain('AUTONOMOUS_AGENT');
      expect(result.provenance).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Identity Resolution & All 8 Outcomes
  // ---------------------------------------------------------------------------
  describe('6. IdentityResolver — All 8 Required Outcomes', () => {
    let resolver: IdentityResolver;

    beforeEach(() => {
      resolver = new IdentityResolver();
    });

    it('resolves SAME_CANONICAL_AGENT when matching publisher, repo, and manifest identity', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        version: '1.0.0',
      };
      const obsB: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        version: '1.0.0',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('SAME_CANONICAL_AGENT');
      expect(result.confidence).toBeGreaterThanOrEqual(0.9);
    });

    it('resolves SAME_AGENT_DIFFERENT_VERSION when identical publisher/repo but differing version tags', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent@v1.0.0',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        version: '1.0.0',
      };
      const obsB: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent@v2.1.0',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        version: '2.1.0',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('SAME_AGENT_DIFFERENT_VERSION');
    });

    it('resolves SAME_AGENT_DIFFERENT_DISTRIBUTION when same agent distributed across PyPI and GitHub', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        version: '1.0.0',
      };
      const obsB: EntityObservation = {
        source_locator: 'pypi://autonomous-caim-agent',
        source_type: 'pypi',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        version: '1.0.0',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('SAME_AGENT_DIFFERENT_DISTRIBUTION');
    });

    it('resolves FORK_OR_DERIVATIVE when repository explicitly has FORK_OF relationship', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://community/autonomous-caim-agent-fork',
        source_type: 'github',
        display_name: 'autonomous-caim-agent-fork',
        publisher: 'community',
        relationships: [{ target_locator: 'github://caim-org/autonomous-caim-agent', relationship_type: 'FORK_OF' }],
      };
      const obsB: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('FORK_OR_DERIVATIVE');
    });

    it('resolves MIRROR when identical checksums exist on differing forge platforms', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        checksums: ['sha256-abcde1234567890'],
      };
      const obsB: EntityObservation = {
        source_locator: 'codeberg://caim-org/autonomous-caim-agent',
        source_type: 'codeberg',
        display_name: 'autonomous-caim-agent',
        checksums: ['sha256-abcde1234567890'],
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('MIRROR');
    });

    it('resolves RELATED_ENTITY when publisher matches and items are linked ecosystem components', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        relationships: [{ target_locator: 'npm://@caim/agent-sdk', relationship_type: 'DEPENDENCY' }],
      };
      const obsB: EntityObservation = {
        source_locator: 'npm://@caim/agent-sdk',
        source_type: 'npm',
        display_name: 'agent-sdk',
        publisher: 'caim-org',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('RELATED_ENTITY');
    });

    it('resolves UNRESOLVED when conflicting signals or ambiguous identity evidence occurs', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
      };
      const obsB: EntityObservation = {
        source_locator: 'github://unknown-user/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'unverified-unknown-user',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('UNRESOLVED');
      expect(result.is_provisional).toBe(true);
      expect(result.conflict_reasons?.length).toBeGreaterThan(0);
    });

    it('resolves DISTINCT for completely unrelated entities', () => {
      const obsA: EntityObservation = {
        source_locator: 'github://caim-org/autonomous-caim-agent',
        source_type: 'github',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
      };
      const obsB: EntityObservation = {
        source_locator: 'pypi://flask-restful',
        source_type: 'pypi',
        display_name: 'flask-restful',
        publisher: 'flask-team',
      };

      const result = resolver.compare(obsA, obsB);
      expect(result.outcome).toBe('DISTINCT');
    });

    it('builds canonical candidate graph clustering multiple source observations without destroying provenance', () => {
      const observations: EntityObservation[] = [
        {
          source_locator: 'github://caim-org/autonomous-caim-agent',
          source_type: 'github',
          display_name: 'autonomous-caim-agent',
          publisher: 'caim-org',
          repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
          version: '1.0.0',
        },
        {
          source_locator: 'pypi://autonomous-caim-agent',
          source_type: 'pypi',
          display_name: 'autonomous-caim-agent',
          publisher: 'caim-org',
          repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
          version: '1.0.0',
        },
        {
          source_locator: 'hf://caim-org/caim-reasoner-7b',
          source_type: 'huggingface',
          display_name: 'caim-reasoner-7b',
          publisher: 'caim-org',
          version: '1.0',
        },
      ];

      const graph = resolver.buildCandidateGraph(observations);
      expect(graph.nodes.length).toBeGreaterThanOrEqual(2);
      expect(graph.graph_provenance).toBeDefined();
      expect(graph.graph_provenance.rule_id).toBe('CANONICAL_CANDIDATE_GRAPH_BUILD_V1');

      // The GitHub and PyPI distributions should be clustered together
      const agentNode = graph.nodes.find(n => n.canonical_name.includes('autonomous-caim-agent'));
      expect(agentNode).toBeDefined();
      expect(agentNode?.locators.length).toBe(2);
      expect(agentNode?.distributions).toContain('github');
      expect(agentNode?.distributions).toContain('pypi');
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Manual Review Queue for High-Value Conflicts
  // ---------------------------------------------------------------------------
  describe('7. ManualReviewQueue', () => {
    let queue: ManualReviewQueue;

    beforeEach(() => {
      queue = new ManualReviewQueue();
    });

    it('enqueues unresolved conflict and tracks pending count', () => {
      const item = queue.enqueueConflict({
        candidate_locators: ['github://caim-org/agent', 'github://unverified/agent'],
        conflict_summary: 'Duplicate naming with conflicting maintainer signatures',
        suggested_outcome: 'UNRESOLVED',
        confidence: 0.5,
        evidence: {
          publisher_match: 0.1,
          repo_match: 0.3,
          homepage_match: 0.5,
          manifest_match: 0.9,
          checksum_match: 0.0,
          distribution_match: 0.5,
          similarity_score: 0.9,
          composite_confidence: 0.5,
          details: ['Name matches but disparate cryptographic signatures'],
        },
      });

      expect(item.id).toBeDefined();
      expect(item.status).toBe('PENDING_REVIEW');
      expect(queue.getPendingCount()).toBe(1);
    });

    it('resolves conflicts with audited operator decision and provenance override record', () => {
      const item = queue.enqueueConflict({
        candidate_locators: ['github://caim-org/agent', 'github://unverified/agent'],
        conflict_summary: 'Duplicate naming',
        suggested_outcome: 'UNRESOLVED',
        confidence: 0.5,
        evidence: {
          publisher_match: 0.1,
          repo_match: 0.3,
          homepage_match: 0.5,
          manifest_match: 0.9,
          checksum_match: 0.0,
          distribution_match: 0.5,
          similarity_score: 0.9,
          composite_confidence: 0.5,
          details: [],
        },
      });

      const { item: resolved, provenance } = queue.resolveConflict(item.id, {
        status: 'RESOLVED_DISTINCT',
        reviewed_by: 'lead-security-operator',
        review_note: 'Verified unverified repo is a malicious typosquat; marked distinct.',
      });

      expect(resolved.status).toBe('RESOLVED_DISTINCT');
      expect(resolved.resolved_outcome).toBe('DISTINCT');
      expect(resolved.reviewed_by).toBe('lead-security-operator');
      expect(queue.getPendingCount()).toBe(0);

      expect(provenance.transformation_type).toBe('EXTERNAL_ENRICHMENT');
      expect(provenance.rule_id).toBe('MANUAL_IDENTITY_REVIEW_AUDIT_V1');
    });
  });
});
