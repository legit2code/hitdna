import { describe, it, expect } from 'vitest';
import {
  ImmutableVersionResolver,
  ProviderIntegrityVerifier,
  HttpFetcher,
  HttpResponse,
} from '@caim/source';

describe('PROMPT 04: Immutable Version Resolution & Provider Integrity Verification', () => {
  // Helper to create mock HttpFetcher
  const createMockFetcher = (routes: Record<string, { status: number; data: any }>): HttpFetcher => {
    return async (url: string): Promise<HttpResponse> => {
      const match = routes[url];
      if (match) {
        return {
          status: match.status,
          statusText: match.status === 200 ? 'OK' : 'Error',
          data: match.data,
          headers: { 'content-type': 'application/json' },
        };
      }
      return {
        status: 404,
        statusText: 'Not Found',
        data: null,
        headers: {},
      };
    };
  };

  // -------------------------------------------------------------------------
  // 1. GitHub: Default branch HEAD to exact 40-character SHA
  // -------------------------------------------------------------------------
  describe('1. GitHub: Default Branch HEAD to Exact 40-character SHA Resolution', () => {
    const validSha = '4f8b2c1a9e3d5f7b0a1c2d3e4f5a6b7c8d9e0f1a';

    it('resolves default branch HEAD through GitHub API to an exact 40-char commit SHA', async () => {
      const fetcher = createMockFetcher({
        'https://api.github.com/repos/openai/swarm': {
          status: 200,
          data: { id: 85291, default_branch: 'main' },
        },
        'https://api.github.com/repos/openai/swarm/commits/main': {
          status: 200,
          data: {
            sha: validSha,
            commit: {
              author: { name: 'Lead Architect', date: '2026-09-01T10:00:00Z' },
            },
          },
        },
      });

      const res = await ImmutableVersionResolver.resolveGitHub('https://github.com/openai/swarm', undefined, fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.commit_sha).toBe(validSha);
      expect(res.resolved_version).toBe(validSha);
      expect(res.immutable_locator).toBe(`github://openai/swarm#${validSha}`);
      expect(res.distribution_filename).toBe(`swarm-${validSha}.tar.gz`);
      expect(res.metadata.repository_id).toBe(85291);
      expect(res.metadata.archive_url).toBe(`https://github.com/openai/swarm/archive/${validSha}.tar.gz`);
      expect(res.is_source_code).toBe(true);
      expect(res.is_container_artifact).toBe(false);
    });

    it('never treats main, master, HEAD, or branch names as immutable identity', () => {
      expect(ImmutableVersionResolver.isMutableReference('main')).toBe(true);
      expect(ImmutableVersionResolver.isMutableReference('master')).toBe(true);
      expect(ImmutableVersionResolver.isMutableReference('HEAD')).toBe(true);
      expect(ImmutableVersionResolver.isMutableReference('latest')).toBe(true);
      expect(ImmutableVersionResolver.isMutableReference('develop')).toBe(true);
      expect(ImmutableVersionResolver.isMutableReference('refs/heads/feature-x')).toBe(true);

      // Valid 40-character SHA is NOT mutable
      expect(ImmutableVersionResolver.isMutableReference(validSha)).toBe(false);
      expect(ImmutableVersionResolver.isCommitSha(validSha)).toBe(true);
      expect(ImmutableVersionResolver.isCommitSha('main')).toBe(false);
      expect(ImmutableVersionResolver.isCommitSha('v1.0.0')).toBe(false);
    });

    it('throws PROVIDER_INTEGRITY_ERROR when GitHub API returns a non-40-char SHA', async () => {
      const fetcher = createMockFetcher({
        'https://api.github.com/repos/openai/swarm': {
          status: 200,
          data: { id: 85291, default_branch: 'main' },
        },
        'https://api.github.com/repos/openai/swarm/commits/main': {
          status: 200,
          data: { sha: 'short-sha-123' }, // Invalid!
        },
      });

      await expect(
        ImmutableVersionResolver.resolveGitHub('https://github.com/openai/swarm', undefined, fetcher)
      ).rejects.toThrow(/invalid non-40-character commit SHA/i);
    });
  });

  // -------------------------------------------------------------------------
  // 2. GitLab & Codeberg: Project/repo and exact commit SHA resolution
  // -------------------------------------------------------------------------
  describe('2. GitLab & Codeberg: Exact Commit SHA Resolution', () => {
    const gitlabSha = '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b';
    const codebergSha = '11223344556677889900aabbccddeeff00112233';

    it('resolves GitLab project repository to exact commit SHA and archive URL', async () => {
      const fetcher = createMockFetcher({
        'https://gitlab.com/api/v4/projects/group%2Fsec-agent': {
          status: 200,
          data: { id: 10492, default_branch: 'main' },
        },
        'https://gitlab.com/api/v4/projects/group%2Fsec-agent/repository/commits/main': {
          status: 200,
          data: { id: gitlabSha },
        },
      });

      const res = await ImmutableVersionResolver.resolveGitLab('gitlab://group/sec-agent', undefined, fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.commit_sha).toBe(gitlabSha);
      expect(res.immutable_locator).toBe(`gitlab://group/sec-agent#${gitlabSha}`);
      expect(res.metadata.project_id).toBe(10492);
      expect(res.metadata.archive_url).toContain(`sha=${gitlabSha}`);
      expect(res.is_source_code).toBe(true);
    });

    it('resolves Codeberg repository to exact commit SHA and archive URL', async () => {
      const fetcher = createMockFetcher({
        'https://codeberg.org/api/v1/repos/community/open-agent': {
          status: 200,
          data: { id: 5541, default_branch: 'main' },
        },
        'https://codeberg.org/api/v1/repos/community/open-agent/commits/main': {
          status: 200,
          data: { sha: codebergSha },
        },
      });

      const res = await ImmutableVersionResolver.resolveCodeberg('codeberg://community/open-agent', undefined, fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.commit_sha).toBe(codebergSha);
      expect(res.immutable_locator).toBe(`codeberg://community/open-agent#${codebergSha}`);
      expect(res.metadata.repo_id).toBe(5541);
      expect(res.metadata.archive_url).toBe(`https://codeberg.org/community/open-agent/archive/${codebergSha}.tar.gz`);
    });
  });

  // -------------------------------------------------------------------------
  // 3. npm: Semver, SRI (SHA-512 base64), and SHA-1 legacy shasum
  // -------------------------------------------------------------------------
  describe('3. npm: Semver Resolution, Subresource Integrity (SRI), and Algorithm Typing', () => {
    it('resolves exact semver and correctly parses SHA-512 SRI string without mislabeling as SHA-256', async () => {
      // Test fixture: sample payload and its true SHA-512 base64
      const sampleTarballBytes = Buffer.from('package-tarball-bytes-content-v1.2.3');
      const crypto = await import('node:crypto');
      const trueSha512Base64 = crypto.createHash('sha512').update(sampleTarballBytes).digest('base64');
      const sriString = `sha512-${trueSha512Base64}`;

      const fetcher = createMockFetcher({
        'https://registry.npmjs.org/%40modelcontextprotocol%2Fsdk': {
          status: 200,
          data: {
            'dist-tags': { latest: '1.2.3' },
            versions: {
              '1.2.3': {
                dist: {
                  tarball: 'https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.2.3.tgz',
                  integrity: sriString,
                  shasum: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
                  unpackedSize: 45000,
                  fileCount: 15,
                },
              },
            },
          },
        },
      });

      const res = await ImmutableVersionResolver.resolveNpm('@modelcontextprotocol/sdk', 'latest', fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.resolved_version).toBe('1.2.3');
      expect(res.immutable_locator).toBe('npm://@modelcontextprotocol/sdk@1.2.3');
      expect(res.integrity_metadata).toBeDefined();

      // STRICT REQUIREMENT: SHA-512 is preserved and NEVER called SHA-256
      expect(res.integrity_metadata?.algorithm).toBe('sha512');
      expect(res.integrity_metadata?.algorithm).not.toBe('sha256');
      expect(res.integrity_metadata?.encoding).toBe('base64');
      expect(res.integrity_metadata?.expected_value).toBe(trueSha512Base64);

      // Verify integrity check succeeds with authentic bytes
      const checkResult = ProviderIntegrityVerifier.verifyBytes(sampleTarballBytes, res.integrity_metadata!);
      expect(checkResult.verified).toBe(true);
      expect(checkResult.matched).toBe(true);
      expect(checkResult.algorithm).toBe('sha512');
    });

    it('throws INTEGRITY_MISMATCH when npm payload bytes do not match SHA-512 SRI', () => {
      const tamperedBytes = Buffer.from('TAMPERED_CONTENT_MALICIOUS_INJECTION');
      const expectedIntegrity = {
        algorithm: 'sha512' as const,
        expected_value: 'dummyBase64ThatDoesNotMatch==',
        encoding: 'base64' as const,
      };

      expect(() => {
        ProviderIntegrityVerifier.verifyBytes(tamperedBytes, expectedIntegrity);
      }).toThrow(/INTEGRITY_MISMATCH/);
    });

    it('correctly parses legacy SHA-1 shasum as sha1 and never labels it sha256', () => {
      const shasumHex = '0123456789abcdef0123456789abcdef01234567';
      const parsed = ProviderIntegrityVerifier.parseNpmShasum(shasumHex);

      expect(parsed).toBeDefined();
      expect(parsed?.algorithm).toBe('sha1');
      expect(parsed?.algorithm).not.toBe('sha256');
      expect(parsed?.expected_value).toBe(shasumHex);
      expect(parsed?.encoding).toBe('hex');
    });
  });

  // -------------------------------------------------------------------------
  // 4. PyPI: Exact version, distribution filename, and SHA-256 verification
  // -------------------------------------------------------------------------
  describe('4. PyPI: Exact Distribution Identity and SHA-256 Verification', () => {
    it('resolves exact distribution filename and validates provider-supplied SHA-256', async () => {
      const sampleWheelBytes = Buffer.from('wheel-bytes-payload-for-crewai');
      const crypto = await import('node:crypto');
      const trueSha256Hex = crypto.createHash('sha256').update(sampleWheelBytes).digest('hex');

      const fetcher = createMockFetcher({
        'https://pypi.org/pypi/crewai/json': {
          status: 200,
          data: {
            info: { version: '0.28.8' },
            urls: [
              {
                filename: 'crewai-0.28.8-py3-none-any.whl',
                packagetype: 'bdist_wheel',
                python_version: 'py3',
                url: 'https://files.pythonhosted.org/packages/crewai-0.28.8.whl',
                digests: {
                  sha256: trueSha256Hex,
                },
              },
            ],
          },
        },
      });

      const res = await ImmutableVersionResolver.resolvePyPi('crewai', undefined, fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.resolved_version).toBe('0.28.8');
      expect(res.distribution_filename).toBe('crewai-0.28.8-py3-none-any.whl');
      expect(res.immutable_locator).toBe('pypi://crewai@0.28.8#crewai-0.28.8-py3-none-any.whl');
      expect(res.integrity_metadata?.algorithm).toBe('sha256');
      expect(res.integrity_metadata?.expected_value).toBe(trueSha256Hex);

      // Verify authentic bytes match
      const checkResult = ProviderIntegrityVerifier.verifyBytes(sampleWheelBytes, res.integrity_metadata!);
      expect(checkResult.matched).toBe(true);
    });

    it('throws INTEGRITY_MISMATCH when PyPI package bytes do not match expected SHA-256', () => {
      const tamperedBytes = Buffer.from('TAMPERED_PYTHON_CODE');
      const integrity = {
        algorithm: 'sha256' as const,
        expected_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        encoding: 'hex' as const,
      };

      expect(() => {
        ProviderIntegrityVerifier.verifyBytes(tamperedBytes, integrity);
      }).toThrow(/INTEGRITY_MISMATCH/);
    });
  });

  // -------------------------------------------------------------------------
  // 5. Hugging Face / Spaces: Commit revision SHA resolution
  // -------------------------------------------------------------------------
  describe('5. Hugging Face / Spaces: Commit Revision Resolution', () => {
    const modelSha = 'aabbccddeeff00112233445566778899aabbccdd';
    const spaceSha = '99887766554433221100ffeeddccbbaa99887766';

    it('resolves model repository to exact 40-character revision commit SHA', async () => {
      const fetcher = createMockFetcher({
        'https://huggingface.co/api/models/meta-llama/Llama-3-8B': {
          status: 200,
          data: { sha: modelSha, id: 'meta-llama/Llama-3-8B' },
        },
      });

      const res = await ImmutableVersionResolver.resolveHuggingFace('hf://models/meta-llama/Llama-3-8B', 'main', false, fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.commit_sha).toBe(modelSha);
      expect(res.immutable_locator).toBe(`hf://models/meta-llama/Llama-3-8B#${modelSha}`);
    });

    it('resolves Spaces repository to exact revision commit SHA', async () => {
      const fetcher = createMockFetcher({
        'https://huggingface.co/api/spaces/acme/interactive-agent': {
          status: 200,
          data: { sha: spaceSha, id: 'acme/interactive-agent' },
        },
      });

      const res = await ImmutableVersionResolver.resolveHuggingFace('hf://spaces/acme/interactive-agent', 'main', true, fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.source_type).toBe('hf-spaces');
      expect(res.commit_sha).toBe(spaceSha);
      expect(res.immutable_locator).toBe(`hf://spaces/acme/interactive-agent#${spaceSha}`);
    });
  });

  // -------------------------------------------------------------------------
  // 6. Docker Hub / OCI: Image tag to immutable manifest digest
  // -------------------------------------------------------------------------
  describe('6. Docker Hub / OCI: Manifest Digest Resolution & Container Boundary', () => {
    const validDigest = 'sha256:7173b809ca12ec5dee4506cd86be934c4596dd234ee822834b51da0464c6e2fd';

    it('resolves mutable tag (e.g. :latest) to immutable OCI sha256 manifest digest', async () => {
      const fetcher = createMockFetcher({
        'https://hub.docker.com/v2/repositories/library/python/tags/3.11-slim': {
          status: 200,
          data: {
            digest: validDigest,
            images: [{ architecture: 'amd64', os: 'linux', digest: validDigest }],
          },
        },
      });

      const res = await ImmutableVersionResolver.resolveDockerHub('docker.io/library/python:3.11-slim', '3.11-slim', fetcher);

      expect(res.is_immutable).toBe(true);
      expect(res.manifest_digest).toBe(validDigest);
      expect(res.immutable_locator).toBe(`docker.io/library/python@${validDigest}`);

      // STRICT REQUIREMENT: Container artifacts are clearly distinguished from source code
      expect(res.is_container_artifact).toBe(true);
      expect(res.is_source_code).toBe(false);
    });

    it('throws PROVIDER_INTEGRITY_ERROR when Docker tag response lacks valid OCI digest', async () => {
      const fetcher = createMockFetcher({
        'https://hub.docker.com/v2/repositories/acme/bad-image/tags/latest': {
          status: 200,
          data: { digest: 'malformed_digest_no_sha' },
        },
      });

      await expect(
        ImmutableVersionResolver.resolveDockerHub('docker.io/acme/bad-image:latest', 'latest', fetcher)
      ).rejects.toThrow(/did not yield a valid OCI sha256 manifest digest/i);
    });
  });

  // -------------------------------------------------------------------------
  // 7. Unsupported Acquisition Truth-States (Replicate, Kaggle)
  // -------------------------------------------------------------------------
  describe('7. Truth-State Enforcement: SOURCE_ACQUISITION_UNSUPPORTED for Non-Source APIs', () => {
    it('returns SOURCE_ACQUISITION_UNSUPPORTED for closed-weight Replicate models and pivots to GitHub if available', async () => {
      const fetcher = createMockFetcher({
        'https://api.replicate.com/v1/models/meta/llama-2-70b': {
          status: 200,
          data: {
            latest_version: { id: 'ver_99281' },
            github_url: 'https://github.com/facebookresearch/llama',
          },
        },
      });

      const res = await ImmutableVersionResolver.resolveReplicate('replicate://meta/llama-2-70b', fetcher);

      expect(res.source_type).toBe('replicate');
      expect(res.is_source_code).toBe(false);
      expect(res.pivot_required).toBe(true);
      expect(res.canonical_pivots).toEqual([
        { provider: 'github', locator: 'https://github.com/facebookresearch/llama' },
      ]);
    });

    it('returns explicit SOURCE_ACQUISITION_UNSUPPORTED for Replicate model without open-source repository', async () => {
      const fetcher = createMockFetcher({
        'https://api.replicate.com/v1/models/proprietary/secret-model': {
          status: 200,
          data: {
            latest_version: { id: 'ver_00112' },
            github_url: null,
          },
        },
      });

      const res = await ImmutableVersionResolver.resolveReplicate('replicate://proprietary/secret-model', fetcher);

      expect(res.acquisition_supported).toBe(false);
      expect(res.unsupported_reason).toContain('SOURCE_ACQUISITION_UNSUPPORTED');
      expect(res.canonical_pivots).toHaveLength(0);
    });

    it('returns SOURCE_ACQUISITION_UNSUPPORTED for Kaggle kernels without fabricating notebook content', async () => {
      const fetcher = createMockFetcher({
        'https://www.kaggle.com/api/v1/kernels/list?search=agent-eval': {
          status: 200,
          data: [
            { ref: 'user123/agent-eval', author: 'user123', slug: 'agent-eval', lastUpdateTime: '2026-08-01' },
          ],
        },
      });

      const res = await ImmutableVersionResolver.resolveKaggle('kaggle://user123/agent-eval', fetcher);

      expect(res.acquisition_supported).toBe(false);
      expect(res.is_source_code).toBe(false);
      expect(res.unsupported_reason).toContain('SOURCE_ACQUISITION_UNSUPPORTED');
    });
  });

  // -------------------------------------------------------------------------
  // 8. Discovery-Only Providers: Canonical Pivots & No Synthetic Authenticity
  // -------------------------------------------------------------------------
  describe('8. Discovery-Only Providers: Strict Pivot Architecture', () => {
    it('pivots MCP registry entry to canonical GitHub repository and package registries', () => {
      const res = ImmutableVersionResolver.resolveDiscoveryOnlyPivot('mcp', 'mcp://servers/github-analyst', {
        server: {
          repository: { url: 'https://github.com/modelcontextprotocol/servers' },
          packages: [
            { registryType: 'npm', identifier: '@modelcontextprotocol/server-github' },
            { registryType: 'pypi', identifier: 'mcp-server-github' },
          ],
        },
      });

      expect(res.acquisition_supported).toBe(false);
      expect(res.pivot_required).toBe(true);
      expect(res.canonical_pivots).toEqual([
        { provider: 'github', locator: 'https://github.com/modelcontextprotocol/servers' },
        { provider: 'npm', locator: 'npm://@modelcontextprotocol/server-github' },
        { provider: 'pypi', locator: 'pypi://mcp-server-github' },
      ]);
      expect(res.unsupported_reason).toContain('discovery-only index');
    });

    it('pivots Hacker News story to linked GitHub repository', () => {
      const res = ImmutableVersionResolver.resolveDiscoveryOnlyPivot('hackernews', 'hn://item/41029481', {
        url: 'https://github.com/langchain-ai/langchain',
      });

      expect(res.pivot_required).toBe(true);
      expect(res.canonical_pivots).toEqual([
        { provider: 'github', locator: 'https://github.com/langchain-ai/langchain' },
      ]);
    });

    it('pivots arXiv paper metadata to associated code repository', () => {
      const res = ImmutableVersionResolver.resolveDiscoveryOnlyPivot('arxiv', 'arxiv://2603.12345', {
        code_links: ['https://github.com/princeton-nlp/SWE-agent'],
      });

      expect(res.pivot_required).toBe(true);
      expect(res.canonical_pivots).toEqual([
        { provider: 'github', locator: 'https://github.com/princeton-nlp/SWE-agent' },
      ]);
    });
  });
});
