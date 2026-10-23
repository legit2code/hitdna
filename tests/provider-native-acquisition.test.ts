import { describe, it, expect, vi } from 'vitest';
import crypto from 'crypto';
import {
  AuthenticSourceAcquisitionService,
  DiscoveryCandidate,
} from '@caim/source';
import { FetchGateway } from '@caim/source/fetch-gateway/fetch-gateway.ts';
import { ArchiveSafetyInspector } from '@caim/source/fetch-gateway/archive-safety.ts';

// Helper to construct a minimal valid ZIP buffer in memory
function createTestZipBuffer(files: Array<{ name: string; content: string }>): Buffer {
  const localHeaders: Buffer[] = [];
  const cdHeaders: Buffer[] = [];
  let offset = 0;

  for (const file of files) {
    const fileBytes = Buffer.from(file.content, 'utf8');
    const nameBytes = Buffer.from(file.name, 'utf8');

    // Local file header (30 bytes + name + content)
    const local = Buffer.alloc(30 + nameBytes.length + fileBytes.length);
    local.writeUInt32LE(0x04034b50, 0); // Signature
    local.writeUInt16LE(20, 4); // Min version
    local.writeUInt16LE(0, 6); // Flags
    local.writeUInt16LE(0, 8); // Compression = none
    local.writeUInt16LE(0, 10); // Time
    local.writeUInt16LE(0, 12); // Date
    local.writeUInt32LE(0, 14); // CRC32 (dummy)
    local.writeUInt32LE(fileBytes.length, 18); // Compressed size
    local.writeUInt32LE(fileBytes.length, 22); // Uncompressed size
    local.writeUInt16LE(nameBytes.length, 26); // Filename length
    local.writeUInt16LE(0, 28); // Extra field length
    nameBytes.copy(local, 30);
    fileBytes.copy(local, 30 + nameBytes.length);

    localHeaders.push(local);

    // Central directory header (46 bytes + name)
    const cd = Buffer.alloc(46 + nameBytes.length);
    cd.writeUInt32LE(0x02014b50, 0); // Signature
    cd.writeUInt16LE(20, 4); // Version made by
    cd.writeUInt16LE(20, 6); // Version needed
    cd.writeUInt16LE(0, 8); // Flags
    cd.writeUInt16LE(0, 10); // Compression
    cd.writeUInt16LE(0, 12); // Time
    cd.writeUInt16LE(0, 14); // Date
    cd.writeUInt32LE(0, 16); // CRC32
    cd.writeUInt32LE(fileBytes.length, 20); // Compressed size
    cd.writeUInt32LE(fileBytes.length, 24); // Uncompressed size
    cd.writeUInt16LE(nameBytes.length, 28); // Filename length
    cd.writeUInt16LE(0, 30); // Extra field len
    cd.writeUInt16LE(0, 32); // Comment len
    cd.writeUInt16LE(0, 34); // Disk start
    cd.writeUInt16LE(0, 36); // Internal attr
    cd.writeUInt32LE(0, 38); // External attr
    cd.writeUInt32LE(offset, 42); // Relative offset
    nameBytes.copy(cd, 46);

    cdHeaders.push(cd);
    offset += local.length;
  }

  const cdTotalSize = cdHeaders.reduce((acc, h) => acc + h.length, 0);
  const cdOffset = offset;

  // End of Central Directory Record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // Disk num
  eocd.writeUInt16LE(0, 6); // Disk with CD
  eocd.writeUInt16LE(files.length, 8); // Entries on this disk
  eocd.writeUInt16LE(files.length, 10); // Total entries
  eocd.writeUInt32LE(cdTotalSize, 12); // Size of CD
  eocd.writeUInt32LE(cdOffset, 16); // Offset of CD
  eocd.writeUInt16LE(0, 20); // Comment len

  return Buffer.concat([...localHeaders, ...cdHeaders, eocd]);
}

describe('TEST_ONLY: Provider-Native SourceArtifact Acquisition Pipeline', () => {
  it('acquires authentic GitHub artifact with immutable commit SHA', async () => {
    const testZip = createTestZipBuffer([
      { name: 'repo-abc1234/index.ts', content: 'export const hello = "world";' },
      { name: 'repo-abc1234/package.json', content: '{"name": "test-repo", "version": "1.0.0"}' },
    ]);

    const mockTransport = vi.fn().mockResolvedValue({
      status: 200,
      statusText: 'OK',
      headers: { 'content-type': 'application/zip' },
      data: testZip,
    });

    const gateway = new FetchGateway({ transport: mockTransport });

    const candidate: DiscoveryCandidate = {
      source_type: 'github',
      display_name: 'test-org/test-repo',
      source_locator: 'https://github.com/test-org/test-repo',
      type_hint: 'AGENT_REPOSITORY',
      confidence: 1.0,
      discovered_at: new Date().toISOString(),
      raw_metadata: {
        commit: '1234567890123456789012345678901234567890', // Exact 40-hex commit
      },
    };

    const result = await AuthenticSourceAcquisitionService.acquireProviderSourceArtifact(candidate, {
      gateway,
    });

    expect(result.has_authentic_source).toBe(true);
    expect(result.source_status).toBe('ACQUIRED');
    expect(result.analysis_status).toBe('ANALYSIS_COMPLETE');
    expect(result.files.length).toBeGreaterThan(0);
    expect(result.provenance).toBeDefined();
    expect(result.provenance?.version_identity).toBe('1234567890123456789012345678901234567890');
    expect(result.provenance?.verification_status).toBe('VERIFIED_AUTHENTIC');
  });

  it('rejects mutable default branch or missing immutable commit for GitHub candidate', async () => {
    const candidate: DiscoveryCandidate = {
      source_type: 'github',
      display_name: 'test-org/test-repo',
      source_locator: 'https://github.com/test-org/test-repo',
      type_hint: 'AGENT_REPOSITORY',
      confidence: 1.0,
      discovered_at: new Date().toISOString(),
      raw_metadata: {
        branch: 'main', // Mutable branch - NOT allowed as immutable revision!
      },
    };

    const result = await AuthenticSourceAcquisitionService.acquireProviderSourceArtifact(candidate);

    expect(result.has_authentic_source).toBe(false);
    expect(result.source_status).toBe('SOURCE_UNAVAILABLE');
    expect(result.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
    expect(result.rejection_reason).toContain('SOURCE_UNAVAILABLE');
  });

  it('acquires authentic npm package tarball with exact semver and integrity verification', async () => {
    const testZip = createTestZipBuffer([
      { name: 'package/index.js', content: 'module.exports = {};' },
    ]);
    const zipSha256 = crypto.createHash('sha256').update(testZip).digest('hex');

    const mockTransport = vi.fn().mockResolvedValue({
      status: 200,
      statusText: 'OK',
      headers: { 'content-type': 'application/gzip' },
      data: testZip,
    });

    const gateway = new FetchGateway({ transport: mockTransport });

    const candidate: DiscoveryCandidate = {
      source_type: 'npm',
      display_name: '@caim/contracts',
      source_locator: 'npm://@caim/contracts',
      type_hint: 'PACKAGE_DISTRIBUTION',
      confidence: 1.0,
      discovered_at: new Date().toISOString(),
      raw_metadata: {
        version: '2.0.1',
        dist: {
          tarball: 'https://registry.npmjs.org/@caim/contracts/-/@caim/contracts-2.0.1.tgz',
          shasum: zipSha256,
        },
      },
    };

    const result = await AuthenticSourceAcquisitionService.acquireProviderSourceArtifact(candidate, {
      gateway,
    });

    expect(result.has_authentic_source).toBe(true);
    expect(result.source_status).toBe('ACQUIRED');
    expect(result.provenance?.version_identity).toBe('2.0.1');
    expect(result.provenance?.verification_status).toBe('VERIFIED_AUTHENTIC');
  });

  it('rejects npm candidate with mutable "latest" tag instead of exact version', async () => {
    const candidate: DiscoveryCandidate = {
      source_type: 'npm',
      display_name: '@caim/contracts',
      source_locator: 'npm://@caim/contracts',
      type_hint: 'PACKAGE_DISTRIBUTION',
      confidence: 1.0,
      discovered_at: new Date().toISOString(),
      raw_metadata: {
        version: 'latest', // Mutable tag prohibited!
      },
    };

    const result = await AuthenticSourceAcquisitionService.acquireProviderSourceArtifact(candidate);

    expect(result.has_authentic_source).toBe(false);
    expect(result.source_status).toBe('SOURCE_UNAVAILABLE');
    expect(result.analysis_status).toBe('ANALYSIS_NOT_PERFORMED');
  });

  it('acquires authentic PyPI package distribution with exact version and SHA-256 validation', async () => {
    const testZip = createTestZipBuffer([
      { name: 'caim_agent_sdk-2.1.0/setup.py', content: '# setup.py' },
    ]);
    const zipSha256 = crypto.createHash('sha256').update(testZip).digest('hex');

    const mockTransport = vi.fn().mockResolvedValue({
      status: 200,
      statusText: 'OK',
      headers: { 'content-type': 'application/x-tar' },
      data: testZip,
    });

    const gateway = new FetchGateway({ transport: mockTransport });

    const candidate: DiscoveryCandidate = {
      source_type: 'pypi',
      display_name: 'caim-agent-sdk',
      source_locator: 'pypi://caim-agent-sdk',
      type_hint: 'PACKAGE_DISTRIBUTION',
      confidence: 1.0,
      discovered_at: new Date().toISOString(),
      raw_metadata: {
        info: { version: '2.1.0' },
        urls: [
          {
            packagetype: 'sdist',
            url: 'https://files.pythonhosted.org/packages/caim-agent-sdk-2.1.0.tar.gz',
            digests: { sha256: zipSha256 },
          },
        ],
      },
    };

    const result = await AuthenticSourceAcquisitionService.acquireProviderSourceArtifact(candidate, {
      gateway,
    });

    expect(result.has_authentic_source).toBe(true);
    expect(result.source_status).toBe('ACQUIRED');
    expect(result.provenance?.version_identity).toBe('2.1.0');
  });

  it('fails acquisition if provider checksum mismatches downloaded bytes', async () => {
    const testZip = createTestZipBuffer([
      { name: 'caim_agent_sdk-2.1.0/setup.py', content: '# setup.py' },
    ]);

    const mockTransport = vi.fn().mockResolvedValue({
      status: 200,
      statusText: 'OK',
      headers: { 'content-type': 'application/x-tar' },
      data: testZip,
    });

    const gateway = new FetchGateway({ transport: mockTransport });

    const candidate: DiscoveryCandidate = {
      source_type: 'pypi',
      display_name: 'caim-agent-sdk',
      source_locator: 'pypi://caim-agent-sdk',
      type_hint: 'PACKAGE_DISTRIBUTION',
      confidence: 1.0,
      discovered_at: new Date().toISOString(),
      raw_metadata: {
        info: { version: '2.1.0' },
        urls: [
          {
            packagetype: 'sdist',
            url: 'https://files.pythonhosted.org/packages/caim-agent-sdk-2.1.0.tar.gz',
            digests: { sha256: '0'.repeat(64) }, // Mismatched SHA-256
          },
        ],
      },
    };

    const result = await AuthenticSourceAcquisitionService.acquireProviderSourceArtifact(candidate, {
      gateway,
    });

    expect(result.has_authentic_source).toBe(false);
    expect(result.source_status).toBe('SOURCE_UNAVAILABLE');
    expect(result.rejection_reason).toContain('Checksum mismatch');
  });
});
