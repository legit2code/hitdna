import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  initializeKnowledgeAndRetrieval,
  seedCanonicalKnowledgeCorpus,
  resetKnowledgeInstancesForTesting,
} from '../workers/knowledge/bootstrap.ts';
import {
  DeterministicMockEmbeddingProvider,
  GeminiEmbeddingProvider,
} from '../workers/knowledge/embeddings/provider.ts';
import { ApplicationApiRouter } from '@caim/api/router.ts';
import {
  VulnerabilityRecorrelationWorker,
  DEV_SAMPLE_ADVISORIES,
} from '@caim/workflow/scheduled-workers/vulnerability-recorrelation-worker.ts';
import { DiagnosticService } from '@caim/workflow/diagnostic.ts';
import { PostgresDatabaseAdapter } from '@caim/db/postgres-adapter.ts';

describe('Prompt 2 — Eliminate Production Mock / Synthetic / Fixture Contamination', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalGeminiKey = process.env.GEMINI_API_KEY;

  beforeEach(() => {
    resetKnowledgeInstancesForTesting();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
    if (originalGeminiKey !== undefined) {
      process.env.GEMINI_API_KEY = originalGeminiKey;
    } else {
      delete process.env.GEMINI_API_KEY;
    }
    resetKnowledgeInstancesForTesting();
  });

  describe('1. Production startup creates zero demo intelligence', () => {
    it('initializes an empty knowledge corpus in production mode with zero seeded documents or facts', async () => {
      process.env.NODE_ENV = 'production';
      process.env.GEMINI_API_KEY = 'test-gemini-key-prod-simulation';

      const { corpus } = await initializeKnowledgeAndRetrieval('test-gemini-key-prod-simulation', undefined, { reset: true });

      // Verify that exactly zero entities, zero projections, and zero chunks are seeded in production
      expect(corpus.getAuthoritativeSourceCount()).toBe(0);
      expect(corpus.getRegistry().listObjects().length).toBe(0);
      expect(corpus.getProjections().size).toBe(0);
      expect(corpus.getChunks().size).toBe(0);
    });

    it('strictly forbids seedCanonicalKnowledgeCorpus execution when NODE_ENV is production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.GEMINI_API_KEY = 'test-gemini-key-prod-simulation';

      const { corpus } = await initializeKnowledgeAndRetrieval('test-gemini-key-prod-simulation', undefined, { reset: true });

      await expect(seedCanonicalKnowledgeCorpus(corpus)).rejects.toThrow(
        /\[FATAL SECURITY VIOLATION\] seedCanonicalKnowledgeCorpus\(\) is strictly prohibited in production mode/
      );
    });

    it('strictly rejects seedDemoCorpus option in production mode', async () => {
      process.env.NODE_ENV = 'production';
      process.env.GEMINI_API_KEY = 'test-gemini-key-prod-simulation';

      await expect(
        initializeKnowledgeAndRetrieval('test-gemini-key-prod-simulation', undefined, {
          reset: true,
          seedDemoCorpus: true,
        })
      ).rejects.toThrow(/\[FATAL SECURITY VIOLATION\] seedDemoCorpus is strictly prohibited in production mode/);
    });
  });

  describe('2. Dev fixture mode still works where intentionally supported', () => {
    it('seeds canonical knowledge entities when running in test / dev mode', async () => {
      process.env.NODE_ENV = 'test';

      const { corpus } = await initializeKnowledgeAndRetrieval(undefined, undefined, {
        reset: true,
        seedDemoCorpus: true,
      });

      expect(corpus.getAuthoritativeSourceCount()).toBeGreaterThanOrEqual(5);
      expect(corpus.getRegistry().listObjects().length).toBeGreaterThanOrEqual(5);
      expect(corpus.getProjections().size).toBeGreaterThanOrEqual(5);
    });

    it('loads DEV_SAMPLE_ADVISORIES into VulnerabilityRecorrelationWorker in non-production mode', () => {
      process.env.NODE_ENV = 'test';
      const mockDb = { query: async () => ({ rows: [] }) };
      const worker = new VulnerabilityRecorrelationWorker(mockDb);

      const status = worker.getStatus();
      expect(status.worker_id).toBe('vulnerability-recorrelation-worker');
      expect(status.metrics.published_advisories_count).toBe(DEV_SAMPLE_ADVISORIES.length);
      expect(status.metrics.published_advisories_count).toBeGreaterThan(0);
    });
  });

  describe('3. Production cannot activate fixture providers accidentally (Fail-Closed)', () => {
    it('throws fatal error when DeterministicMockEmbeddingProvider is instantiated in production', () => {
      process.env.NODE_ENV = 'production';
      expect(() => new DeterministicMockEmbeddingProvider()).toThrow(
        /\[FATAL PRODUCTION ERROR\] DeterministicMockEmbeddingProvider is strictly prohibited in production mode/
      );
    });

    it('throws fatal error when GeminiEmbeddingProvider has no API key in production', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.GEMINI_API_KEY;
      expect(() => new GeminiEmbeddingProvider('')).toThrow(
        /\[FATAL PRODUCTION ERROR\] Gemini API key is missing/
      );
    });

    it('throws fatal error when seedDefaultEntities is called in production on ApplicationApiRouter', () => {
      process.env.NODE_ENV = 'production';
      const router = new ApplicationApiRouter();
      expect(() => router.seedDefaultEntities()).toThrow(
        /\[FATAL SECURITY VIOLATION\] seedDefaultEntities is strictly prohibited in production mode/
      );
    });

    it('leaves advisories empty by default in VulnerabilityRecorrelationWorker in production', () => {
      process.env.NODE_ENV = 'production';
      const mockDb = { query: async () => ({ rows: [] }) };
      const worker = new VulnerabilityRecorrelationWorker(mockDb);

      // Under production, no fictional CVEs are automatically loaded
      const status = worker.getStatus();
      expect(status.worker_id).toBe('vulnerability-recorrelation-worker');
      expect(status.metrics.published_advisories_count).toBe(0);
    });

    it('throws fatal error when seedSampleDiagnosticData is called in production', async () => {
      process.env.NODE_ENV = 'production';
      const mockDb = { query: async () => ({ rows: [] }) };
      const diagnostic = new DiagnosticService(mockDb);

      await expect(diagnostic.seedSampleDiagnosticData()).rejects.toThrow(
        /Sample diagnostic data seeding is strictly prohibited in production mode/
      );
    });

    it('throws fatal error when applySeed is passed to PostgresDatabaseAdapter in production', async () => {
      process.env.NODE_ENV = 'production';
      const adapter = new PostgresDatabaseAdapter({ connectionString: 'postgres://localhost:5432/caim_test' });

      await expect(adapter.runMigrations({ applySeed: true })).rejects.toThrow(
        /\[FATAL SECURITY VIOLATION\] applySeed is strictly prohibited in production mode/
      );
    });

    it('throws fatal error when createMockHttpFetcher is called in production', async () => {
      process.env.NODE_ENV = 'production';
      const { createMockHttpFetcher } = await import('@caim/source/fixtures/index.ts');
      expect(() => createMockHttpFetcher()).toThrow(
        /\[FATAL PRODUCTION ERROR\] createMockHttpFetcher is strictly prohibited in production mode/
      );
    });

    it('fails closed when BraveSearchProvider has no API key in production', async () => {
      process.env.NODE_ENV = 'production';
      const { BraveSearchProvider } = await import('@caim/source/web-search.ts');
      const provider = new BraveSearchProvider({ apiKey: '' });
      await expect(provider.search('test query')).rejects.toThrow(
        /BRAVE_API_KEY environment variable is not configured in production mode/
      );
    });

    it('throws fatal error when SyntheticTargetService.handleSyntheticRequest is invoked in production', async () => {
      process.env.NODE_ENV = 'production';
      const { SyntheticTargetService } = await import('../workers/sandbox-orchestrator/security/synthetic-target.ts');
      expect(() => SyntheticTargetService.handleSyntheticRequest({ path: '/api/v1/health', method: 'GET' })).toThrow(
        /\[FATAL PRODUCTION ERROR\] SyntheticTargetService\.handleSyntheticRequest is strictly prohibited in production mode/
      );
    });

    it('throws fatal error when SimulatedSandboxProvider.provision is invoked in production', async () => {
      process.env.NODE_ENV = 'production';
      const { SimulatedSandboxProvider } = await import('../workers/sandbox-orchestrator/providers/simulated-provider.ts');
      const provider = new SimulatedSandboxProvider();
      await expect(provider.provision({ sessionId: 'prod-test-session' } as any)).rejects.toThrow(
        /\[FATAL PRODUCTION ERROR\] SimulatedSandboxProvider\.provision is strictly prohibited in production mode/
      );
    });

    it('fails closed when S3StorageAdapter has simulate flag in production', async () => {
      process.env.NODE_ENV = 'production';
      const { S3StorageAdapter } = await import('@caim/packaging/shipping/s3-adapter.ts');
      const adapter = new S3StorageAdapter({ bucketName: 'prod-vault' });
      const result = await adapter.ship(
        {
          package_id: 'pkg-123',
          manifest_hash: 'dummy-manifest-hash',
          manifest: { agent_id: 'agent-1', version_label: '1.0.0' },
          files: new Map(),
        } as any,
        { targetLocator: 's3://prod-vault/releases/bundle.tar.gz', simulate: true }
      );
      expect(result.status).toBe('FAILED');
      expect(result.error).toContain('SIMULATED_DELIVERY is strictly forbidden in production scenarios');
    });

    it('fails closed when OciRegistryAdapter has simulate flag in production', async () => {
      process.env.NODE_ENV = 'production';
      const { OciRegistryAdapter } = await import('@caim/packaging/shipping/oci-adapter.ts');
      const adapter = new OciRegistryAdapter({ registryHost: 'registry.example.com' });
      const result = await adapter.ship(
        {
          package_id: 'pkg-123',
          manifest_hash: 'dummy-manifest-hash',
          manifest: { agent_id: 'agent-1', version_label: '1.0.0' },
          files: new Map(),
        } as any,
        { targetLocator: 'oci://registry.example.com/caim/agent:1.0.0', simulate: true }
      );
      expect(result.status).toBe('FAILED');
      expect(result.error).toContain('SIMULATED_DELIVERY is strictly forbidden in production scenarios');
    });

    it('throws fatal error when passing sample CVE advisories to VulnerabilityRecorrelationWorker in production', () => {
      process.env.NODE_ENV = 'production';
      const mockDb = { query: async () => ({ rows: [] }) };
      expect(() => new VulnerabilityRecorrelationWorker(mockDb, { advisories: [...DEV_SAMPLE_ADVISORIES] })).toThrow(
        /\[FATAL PRODUCTION ERROR\] Ingesting fictional sample CVE advisories is strictly prohibited in production mode/
      );
    });

    it('throws fatal error when simulateRegression is passed to GoldenCorpusEvaluationEngine in production', async () => {
      process.env.NODE_ENV = 'production';
      const { GoldenCorpusEvaluationEngine } = await import('@caim/workflow/evaluation.ts');
      const engine = new GoldenCorpusEvaluationEngine();
      expect(() =>
        engine.evaluateEngineVersion({
          engineVersion: 'v2.1.0',
          isConclusionChanging: true,
          simulateRegression: true,
        })
      ).toThrow(/\[FATAL PRODUCTION ERROR\] simulateRegression is strictly prohibited in production mode/);
    });

    it('throws fatal error when runEvaluationVerificationTests is called in production', async () => {
      process.env.NODE_ENV = 'production';
      const { runEvaluationVerificationTests } = await import('@caim/workflow/evaluation.ts');
      expect(() => runEvaluationVerificationTests()).toThrow(
        /\[FATAL PRODUCTION ERROR\] runEvaluationVerificationTests is strictly prohibited in production mode/
      );
    });

    it('throws fatal error when router constructor is passed seedEntities: true in production', () => {
      process.env.NODE_ENV = 'production';
      expect(() => new ApplicationApiRouter({ isProduction: true, seedEntities: true })).toThrow(
        /\[FATAL SECURITY VIOLATION\] seedEntities option is strictly prohibited in production mode/
      );
    });
  });
});
