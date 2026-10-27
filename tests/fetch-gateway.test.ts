import { describe, it, expect, beforeEach, vi } from 'vitest';
import zlib from 'zlib';
import {
  FetchGateway,
  SsrfFilter,
  SsrfBlockedError,
  RobotsPolicyEnforcer,
  RobotsDisallowedError,
  DomainRateLimiter,
  SourceCircuitBreaker,
  CircuitBreakerOpenError,
  ArchiveSafetyInspector,
  ArchiveBombError,
  ArchiveTraversalError,
  ArchiveSymlinkEscapeError,
  SafeRepositoryAcquisition,
  DiscoveryExecutionSandboxSafety,
  GitHubSourceAdapter,
  GitLabSourceAdapter,
  PyPISourceAdapter,
  NpmSourceAdapter,
  HuggingFaceSourceAdapter,
  DockerHubSourceAdapter,
  CodebergSourceAdapter,
  HttpResponse,
} from '@caim/source';

describe('CAIM Discovery Graph Step 2 of 6: Fetch Gateway & Untrusted-Content Safety', () => {
  let gateway: FetchGateway;

  beforeEach(() => {
    gateway = new FetchGateway();
  });

  // =========================================================================
  // ACCEPTANCE TEST 1: SSRF Prevention
  // Attempt a real fetch through the gateway targeting localhost, a private IP
  // (e.g. 10.0.0.0/8 range), and a cloud-metadata-pattern address — demonstrate
  // each is rejected before any network request is made.
  // =========================================================================
  describe('Acceptance Test 1: SSRF Prevention Before Network Request', () => {
    it('rejects localhost and loopback addresses immediately', async () => {
      const targets = [
        'http://localhost:8080/internal-metrics',
        'http://127.0.0.1:3000/api/admin',
        'http://127.0.0.254:9999/debug',
        'http://[::1]:8080/config',
      ];

      for (const target of targets) {
        await expect(gateway.request(target)).rejects.toThrow(SsrfBlockedError);
      }

      // Verify audit logs record SSRF_BLOCKED with zero bytes received
      const logs = gateway.getAuditLogs().filter((l) => l.outcome === 'SSRF_BLOCKED');
      expect(logs.length).toBe(targets.length);
      for (const log of logs) {
        expect(log.bytesReceived).toBe(0);
      }
    });

    it('rejects private RFC1918 IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)', async () => {
      const targets = [
        'http://10.0.0.1/private-repo',
        'http://10.254.12.34:8000/manifest.json',
        'http://172.16.0.50/source',
        'http://172.31.255.254:8080/tokens',
        'http://192.168.1.1/router-admin',
        'http://192.168.100.20/db',
      ];

      for (const target of targets) {
        await expect(gateway.request(target)).rejects.toThrow(SsrfBlockedError);
      }
    });

    it('rejects cloud metadata endpoints (169.254.169.254, metadata.google.internal)', async () => {
      const targets = [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/computeMetadata/v1/',
        'http://169.254.169.253/dns',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
        'http://metadata.internal/info',
        'http://instance-data/credentials',
      ];

      for (const target of targets) {
        await expect(gateway.request(target)).rejects.toThrow(SsrfBlockedError);
      }
    });

    it('rejects non-HTTP protocols (file://, ftp://, gopher://)', async () => {
      const targets = [
        'file:///etc/passwd',
        'ftp://ftp.example.com/dump.tar',
        'gopher://gopher.floodgap.com/',
        'data:text/plain;base64,SGVsbG8=',
      ];

      for (const target of targets) {
        await expect(gateway.request(target)).rejects.toThrow(SsrfBlockedError);
      }
    });
  });

  // =========================================================================
  // ACCEPTANCE TEST 2: Re-validation on Redirect Chain
  // Construct a real redirect chain where the final hop points to a blocked target —
  // demonstrate the redirect is rejected even though the first hop was clean.
  // =========================================================================
  describe('Acceptance Test 2: Hop-by-Hop Redirect Re-validation', () => {
    it('rejects redirect chain when the final hop points to a blocked private IP', async () => {
      // Create gateway with custom transport simulating clean initial hop redirecting to 10.0.0.1
      const mockTransport = vi.fn(async (targetUrl: string): Promise<HttpResponse> => {
        if (targetUrl === 'https://public-mirror.example.org/download/agent') {
          return {
            status: 302,
            statusText: 'Found',
            headers: {
              location: 'http://10.0.0.1/internal/secret.tar.gz',
            },
            data: null,
          };
        }
        return {
          status: 200,
          statusText: 'OK',
          headers: {},
          data: 'ok',
        };
      });

      // Custom DNS resolver that marks public-mirror.example.org as safe public IP 93.184.216.34
      const ssrfFilter = new SsrfFilter([], [], async (host) => {
        if (host === 'public-mirror.example.org') return ['93.184.216.34'];
        return ['10.0.0.1'];
      });

      const redirectGateway = new FetchGateway({
        transport: mockTransport,
        ssrfFilter,
      });

      await expect(
        redirectGateway.request('https://public-mirror.example.org/download/agent', { skipRobots: true })
      ).rejects.toThrow(SsrfBlockedError);

      // Verify hop 1 was reached, but hop 2 was blocked by SSRF
      expect(mockTransport).toHaveBeenCalledTimes(1);
      expect(mockTransport).toHaveBeenCalledWith(
        'https://public-mirror.example.org/download/agent',
        expect.anything()
      );
    });

    it('rejects redirect chain when final hop points to cloud metadata endpoint', async () => {
      const mockTransport = vi.fn(async (targetUrl: string): Promise<HttpResponse> => {
        if (targetUrl === 'https://repo.example.org/archive') {
          return {
            status: 301,
            statusText: 'Moved Permanently',
            headers: {
              location: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            },
            data: null,
          };
        }
        return { status: 200, statusText: 'OK', headers: {}, data: '' };
      });

      const ssrfFilter = new SsrfFilter([], [], async (host) => {
        if (host === 'repo.example.org') return ['93.184.216.34'];
        return ['169.254.169.254'];
      });

      const redirectGateway = new FetchGateway({
        transport: mockTransport,
        ssrfFilter,
      });

      await expect(
        redirectGateway.request('https://repo.example.org/archive', { skipRobots: true })
      ).rejects.toThrow(SsrfBlockedError);
    });

    it('strips credentials when redirecting across different origins', async () => {
      let forwardedHeaders: Record<string, string> = {};

      const mockTransport = vi.fn(async (targetUrl: string, opts: any): Promise<HttpResponse> => {
        if (targetUrl === 'https://source.example.org/repo') {
          return {
            status: 302,
            statusText: 'Found',
            headers: {
              location: 'https://cdn.anotherdomain.org/tarball.tgz',
            },
            data: null,
          };
        }
        forwardedHeaders = opts.headers || {};
        return {
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/gzip' },
          data: 'binary-payload',
        };
      });

      const ssrfFilter = new SsrfFilter([], [], async () => ['93.184.216.34']);
      const redirectGateway = new FetchGateway({
        transport: mockTransport,
        ssrfFilter,
      });

      await redirectGateway.request('https://source.example.org/repo', {
        headers: {
          authorization: 'Bearer secret-developer-token',
          cookie: 'session=12345',
          'x-custom-metric': 'reproducible',
        },
        skipRobots: true,
      });

      expect(forwardedHeaders['authorization']).toBeUndefined();
      expect(forwardedHeaders['cookie']).toBeUndefined();
      expect(forwardedHeaders['x-custom-metric']).toBe('reproducible');
    });
  });

  // =========================================================================
  // ACCEPTANCE TEST 3: Download Safety & Decompression Limits
  // Attempt to fetch/expand a deliberately oversized or high-ratio test archive —
  // demonstrate it's rejected by the size/ratio limits, not silently truncated.
  // =========================================================================
  describe('Acceptance Test 3: Download Safety & Zip-Bomb / Ratio Limits', () => {
    const inspector = new ArchiveSafetyInspector({
      maxArchiveBytes: 10 * 1024 * 1024,
      maxExpandedBytes: 20 * 1024 * 1024,
      maxDecompressionRatio: 50, // 50:1 limit
      maxFileCount: 100,
    });

    it('rejects high-ratio compression bombs (ratio > 50:1) with ArchiveBombError', () => {
      // Generate a buffer with 5MB of repeated zeros that compresses to ~5KB (ratio ~1000:1)
      const rawPayload = Buffer.alloc(5 * 1024 * 1024, 0);
      const gzipBomb = zlib.gzipSync(rawPayload);

      const ratio = rawPayload.length / gzipBomb.length;
      expect(ratio).toBeGreaterThan(100);

      // Verify that gunzip with inspector catches the high ratio and rejects, not truncates
      expect(() => inspector.decompressGzipSafely(gzipBomb)).toThrow(ArchiveBombError);
    });

    it('rejects archives containing path traversal entries with ArchiveTraversalError', () => {
      expect(() => inspector.validateEntryPath('../../etc/shadow')).toThrow(ArchiveTraversalError);
      expect(() => inspector.validateEntryPath('/etc/passwd')).toThrow(ArchiveTraversalError);
      expect(() => inspector.validateEntryPath('subdir/../../root.sh')).toThrow(ArchiveTraversalError);
      expect(() => inspector.validateEntryPath('C:\\Windows\\System32\\cmd.exe')).toThrow(ArchiveTraversalError);
    });

    it('rejects symlinks that point outside destination root with ArchiveSymlinkEscapeError', () => {
      expect(() => inspector.validateSymlinkTarget('sub/link', '../../etc/passwd')).toThrow(ArchiveSymlinkEscapeError);
      expect(() => inspector.validateSymlinkTarget('agent/sym', '/var/run/docker.sock')).toThrow(ArchiveSymlinkEscapeError);
    });

    it('permits safe archive entries and safe normal compression', () => {
      expect(() => inspector.validateEntryPath('package/src/index.js')).not.toThrow();
      expect(() => inspector.validateSymlinkTarget('lib/current.js', 'v1.0.0.js')).not.toThrow();

      const normalData = Buffer.from('console.log("safe content");'.repeat(500), 'utf8');
      const normalGzip = zlib.gzipSync(normalData);
      const decompressed = inspector.decompressGzipSafely(normalGzip);
      expect(decompressed.toString('utf8')).toBe(normalData.toString('utf8'));
    });
  });

  // =========================================================================
  // ACCEPTANCE TEST 4: Robots.txt Disallowed Path Enforcement
  // Demonstrate a robots.txt-disallowed path is never fetched.
  // =========================================================================
  describe('Acceptance Test 4: Robots.txt Disallowed Path Policy', () => {
    it('blocks access to disallowed path and permits allowed path', async () => {
      const mockTransport = vi.fn(async (targetUrl: string): Promise<HttpResponse> => {
        return {
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: { success: true },
        };
      });

      const robotsEnforcer = new RobotsPolicyEnforcer('caim-bot');
      robotsEnforcer.setDomainRules('https://target-source.org', [
        { path: '/private-crawl', allow: false },
        { path: '/api/v1/internal', allow: false },
        { path: '/public-data', allow: true },
      ]);

      const ssrfFilter = new SsrfFilter([], [], async () => ['93.184.216.34']);
      const robotsGateway = new FetchGateway({
        transport: mockTransport,
        robotsEnforcer,
        ssrfFilter,
      });

      // 1. Attempt to fetch disallowed path: MUST be rejected before transport is called
      await expect(
        robotsGateway.request('https://target-source.org/private-crawl/agent.json')
      ).rejects.toThrow(RobotsDisallowedError);

      expect(mockTransport).not.toHaveBeenCalled();

      // 2. Fetch allowed path: MUST succeed
      const allowedRes = await robotsGateway.request('https://target-source.org/public-data/info.json');
      expect(allowedRes.status).toBe(200);
      expect(mockTransport).toHaveBeenCalledTimes(1);
    });
  });

  // =========================================================================
  // ACCEPTANCE TEST 5: Centralized Rate-Limiting Across Adapters
  // Demonstrate centralized rate-limiting actually throttles a burst of requests
  // to one domain rather than each adapter independently hammering it.
  // =========================================================================
  describe('Acceptance Test 5: Centralized Rate-Limiting & Domain Concurrency', () => {
    it('throttles burst requests across adapters using shared rate limiter', async () => {
      let inFlight = 0;
      let maxSeenInFlight = 0;
      const requestTimestamps: number[] = [];

      const mockTransport = vi.fn(async (url: string): Promise<HttpResponse> => {
        inFlight += 1;
        maxSeenInFlight = Math.max(maxSeenInFlight, inFlight);
        requestTimestamps.push(Date.now());
        // Simulate 50ms upstream processing
        await new Promise((resolve) => setTimeout(resolve, 50));
        inFlight -= 1;
        return {
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: { name: 'caim-test-repo' },
        };
      });

      // Centralized rate limiter: maxConcurrency = 2, burstCapacity = 2, 5 tokens/sec
      const sharedRateLimiter = new DomainRateLimiter({
        burstCapacity: 2,
        tokensPerSecond: 10,
        maxConcurrency: 2,
      });

      const robotsEnforcer = new RobotsPolicyEnforcer('caim-bot');
      robotsEnforcer.setDomainRules('https://api.github.com', []);

      const ssrfFilter = new SsrfFilter([], [], async () => ['140.82.121.4']); // GitHub public IP
      const sharedGateway = new FetchGateway({
        transport: mockTransport,
        rateLimiter: sharedRateLimiter,
        robotsEnforcer,
        ssrfFilter,
      });

      // Create two distinct adapter instances sharing the SAME centralized gateway
      const githubAdapter1 = new GitHubSourceAdapter({
        token: 'test-token',
        fetcher: sharedGateway.createFetcher(),
      });

      const githubAdapter2 = new GitHubSourceAdapter({
        token: 'test-token',
        fetcher: sharedGateway.createFetcher(),
      });

      // Launch a burst of 6 concurrent metadata fetches targeting the same domain
      const promises = [
        githubAdapter1.fetch_metadata('github://caim-org/repo-1'),
        githubAdapter1.fetch_metadata('github://caim-org/repo-2'),
        githubAdapter1.fetch_metadata('github://caim-org/repo-3'),
        githubAdapter2.fetch_metadata('github://caim-org/repo-4'),
        githubAdapter2.fetch_metadata('github://caim-org/repo-5'),
        githubAdapter2.fetch_metadata('github://caim-org/repo-6'),
      ];

      const results = await Promise.all(promises);

      expect(results.length).toBe(6);
      expect(mockTransport).toHaveBeenCalledTimes(6);

      // Verify that concurrency was strictly capped at 2, never exceeding maxConcurrency
      expect(maxSeenInFlight).toBeLessThanOrEqual(2);
    });

    it('honors Retry-After header and stops hitting the upstream until reset', async () => {
      const mockTransport = vi.fn(async (url: string): Promise<HttpResponse> => {
        return {
          status: 429,
          statusText: 'Too Many Requests',
          headers: {
            'retry-after': '60', // 60 seconds backoff
          },
          data: { message: 'Rate limit exceeded' },
        };
      });

      const sharedRateLimiter = new DomainRateLimiter({
        burstCapacity: 5,
        tokensPerSecond: 5,
        maxConcurrency: 2,
      });

      const ssrfFilter = new SsrfFilter([], [], async () => ['140.82.121.4']);
      const retryGateway = new FetchGateway({
        transport: mockTransport,
        rateLimiter: sharedRateLimiter,
        ssrfFilter,
      });

      // First request receives 429 with Retry-After: 60
      const res = await retryGateway.request('https://api.github.com/repos/caim/agent', { skipRobots: true });
      expect(res.status).toBe(429);

      // Check domain status: retryAfterRemainingMs should be active (~60,000ms)
      const status = sharedRateLimiter.getStatus('api.github.com');
      expect(status.retryAfterRemainingMs).toBeGreaterThan(50000);
    });
  });

  // =========================================================================
  // PART D & E: Safe Acquisition & No Execution Guarantees
  // =========================================================================
  describe('Part D & E: Safe Repository Acquisition & No Code Execution', () => {
    it('strips credentials and sets safe git flags in SafeRepositoryAcquisition', () => {
      const testEnv = {
        PATH: '/usr/bin',
        GITHUB_TOKEN: 'test_token_val_123',
        AWS_SECRET_ACCESS_KEY: 'test_aws_val_456',
        CUSTOM_VAR: 'clean_val',
      };

      const sanitized = SafeRepositoryAcquisition.getSanitizedGitEnvironment(testEnv);
      expect(sanitized.GITHUB_TOKEN).toBeUndefined();
      expect(sanitized.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(sanitized.PATH).toBe('/usr/bin');
      expect(sanitized.GIT_TERMINAL_PROMPT).toBe('0');
      expect(sanitized.GIT_ASKPASS).toBe('/bin/false');

      const cloneArgs = SafeRepositoryAcquisition.getGitCloneArguments('https://github.com/org/repo', '/tmp/repo');
      expect(cloneArgs).toContain('-c');
      expect(cloneArgs).toContain('core.hooksPath=/dev/null');
      expect(cloneArgs).toContain('--no-recurse-submodules');
      expect(cloneArgs).toContain('--depth');
    });

    it('verifies Discovery Execution Sandbox Safety guarantees no-eval and no-install', () => {
      const verification = DiscoveryExecutionSandboxSafety.verifyExecutionIsolation();
      expect(verification.executionPrimitiveDisabled).toBe(true);
      expect(verification.manifestParsersPurelyDeclarative).toBe(true);
      expect(verification.sandboxPolicy).toBe('NO_EVAL_NO_INSTALL_STATIC_AST_ONLY');

      // Test safe JSON parsing with prototype pollution defense
      const maliciousJson = '{"name":"agent","__proto__":{"polluted":true},"version":"1.0.0"}';
      const parsed = DiscoveryExecutionSandboxSafety.parseJsonSafely(maliciousJson);
      expect(parsed.name).toBe('agent');
      expect((Object.prototype as any).polluted).toBeUndefined();

      // Test safe requirements.txt parsing
      const reqs = 'caim-agent>=1.0.0\n# comment\nrequests==2.31.0\n';
      const parsedReqs = DiscoveryExecutionSandboxSafety.parseRequirementsTxt(reqs);
      expect(parsedReqs).toHaveLength(2);
      expect(parsedReqs[0]).toEqual({ name: 'caim-agent', specifier: '>=1.0.0' });
    });
  });

  // =========================================================================
  // RETROFIT VERIFICATION: All 7 Adapters Route Through Gateway
  // =========================================================================
  describe('Adapter Retrofit Verification: All 7 Adapters Route Through Fetch Gateway', () => {
    it('verifies all 7 adapters instantiate and route through the centralized gateway by default', async () => {
      const recordedUrls: string[] = [];
      const mockTransport = vi.fn(async (url: string): Promise<HttpResponse> => {
        recordedUrls.push(url);
        return {
          status: 200,
          statusText: 'OK',
          headers: { 'content-type': 'application/json' },
          data: {
            id: 1,
            name: 'test-entity',
            full_name: 'test/test-entity',
            description: 'test entity for caim',
            updated_at: '2026-01-01T00:00:00Z',
            default_branch: 'main',
            info: { version: '1.0.0', summary: 'test' },
            releases: { '1.0.0': [] },
            'dist-tags': { latest: '1.0.0' },
            versions: { '1.0.0': { name: 'test', version: '1.0.0', dist: { tarball: 'http://example.com' } } },
            id_hf: 'models/test/test-entity',
            repository: { name: 'test', namespace: 'test' },
          },
        };
      });

      const ssrfFilter = new SsrfFilter([], [], async () => ['93.184.216.34']);
      const robotsEnforcer = new RobotsPolicyEnforcer('caim-bot');
      for (const origin of [
        'https://api.github.com',
        'https://gitlab.com',
        'https://pypi.org',
        'https://registry.npmjs.org',
        'https://huggingface.co',
        'https://hub.docker.com',
        'https://codeberg.org',
      ]) {
        robotsEnforcer.setDomainRules(origin, []);
      }

      const testGateway = new FetchGateway({
        transport: mockTransport,
        robotsEnforcer,
        ssrfFilter,
      });

      const fetcher = testGateway.createFetcher();

      const adapters = [
        { name: 'GitHub', adapter: new GitHubSourceAdapter({ fetcher }), locator: 'github://test/test-entity' },
        { name: 'GitLab', adapter: new GitLabSourceAdapter({ fetcher }), locator: 'gitlab://test/test-entity' },
        { name: 'PyPI', adapter: new PyPISourceAdapter({ fetcher }), locator: 'pypi://test-entity' },
        { name: 'npm', adapter: new NpmSourceAdapter({ fetcher }), locator: 'npm://test-entity' },
        { name: 'HuggingFace', adapter: new HuggingFaceSourceAdapter({ fetcher }), locator: 'hf://models/test/test-entity' },
        { name: 'DockerHub', adapter: new DockerHubSourceAdapter({ fetcher }), locator: 'docker://test/test-entity' },
        { name: 'Codeberg', adapter: new CodebergSourceAdapter({ fetcher }), locator: 'codeberg://test/test-entity' },
      ];

      for (const { name, adapter, locator } of adapters) {
        const result = await adapter.fetch_metadata(locator);
        expect(result).toBeDefined();
        expect(result.source_locator).toBe(locator);
      }

      // Confirm that all 7 adapters made their outbound network requests through testGateway
      expect(mockTransport).toHaveBeenCalledTimes(7);
      expect(recordedUrls.length).toBe(7);
    });
  });
});
