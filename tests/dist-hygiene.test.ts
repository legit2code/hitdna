import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { checkDistHygiene, checkRepoArchiveHygiene, PERMITTED_REPOSITORY_ARCHIVES, PERMITTED_REPOSITORY_ARCHIVES_SHA256 } from '../scripts/dist-hygiene.ts';

describe('Dist Hygiene Gate (F-01, F-14)', () => {
  it('passes on clean dist directory', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-dist-clean-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'index.html'), '<html></html>');
      fs.writeFileSync(path.join(tempDir, 'server.cjs'), 'console.log("server");');
      const result = checkDistHygiene(tempDir);
      expect(result.passed).toBe(true);
      expect(result.violations).toHaveLength(0);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('fails if dist contains any *.zip archive', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-dist-zip-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'caim-repository.zip'), 'dummy zip');
      const result = checkDistHygiene(tempDir);
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.file.endsWith('.zip'))).toBe(true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('fails if dist contains *.map unless ALLOW_SOURCEMAPS=1', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-dist-map-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'server.cjs.map'), 'dummy sourcemap');
      const resultBlocked = checkDistHygiene(tempDir, { allowSourcemaps: false });
      expect(resultBlocked.passed).toBe(false);
      expect(resultBlocked.violations.some((v) => v.file.endsWith('.map'))).toBe(true);

      const resultAllowed = checkDistHygiene(tempDir, { allowSourcemaps: true });
      expect(resultAllowed.passed).toBe(true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('fails if dist contains .env files', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-dist-env-'));
    try {
      fs.writeFileSync(path.join(tempDir, '.env.production'), 'SECRET=123');
      const result = checkDistHygiene(tempDir);
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.file.includes('.env'))).toBe(true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('fails if any file in dist exceeds 5 MB', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-dist-large-'));
    try {
      const largeFile = path.join(tempDir, 'large-bundle.js');
      // Allocate 5.5 MB file
      const fd = fs.openSync(largeFile, 'w');
      fs.writeSync(fd, Buffer.alloc(1024), 0, 1024, 5.5 * 1024 * 1024);
      fs.closeSync(fd);

      const result = checkDistHygiene(tempDir);
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.reason.includes('exceeds 5 MB limit'))).toBe(true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('asserts current production dist directory is compliant', () => {
    const distPath = path.join(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      const result = checkDistHygiene(distPath);
      expect(result.passed).toBe(true);
      expect(result.violations).toEqual([]);
    }
  });

  describe('Repository Archive Hygiene & Explicit Narrow Exception (SECURITY.md)', () => {
    it('verifies that artifacts/corpus-held-out.tar.gz is the only permitted committed archive and matches registered SHA-256', () => {
      expect(PERMITTED_REPOSITORY_ARCHIVES.has('artifacts/corpus-held-out.tar.gz')).toBe(true);
      const expectedSha = PERMITTED_REPOSITORY_ARCHIVES_SHA256['artifacts/corpus-held-out.tar.gz'];
      expect(expectedSha).toBe('9807a12237b9c4157f942bd9f1e2ee788ed668942e837feba0cdefd2785701ed');

      const repoResult = checkRepoArchiveHygiene(process.cwd());
      expect(repoResult.passed).toBe(true);
      expect(repoResult.violations).toHaveLength(0);
      expect(repoResult.verifiedArchives.some((a) => a.file === 'artifacts/corpus-held-out.tar.gz')).toBe(true);
    });

    it('rejects unauthorized zip or tar.gz archives in repository', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-repo-archive-test-'));
      try {
        fs.mkdirSync(path.join(tempDir, 'some-dir'), { recursive: true });
        fs.writeFileSync(path.join(tempDir, 'some-dir', 'unauthorized.zip'), 'PK fake zip');

        const result = checkRepoArchiveHygiene(tempDir);
        expect(result.passed).toBe(false);
        expect(result.violations.some((v) => v.file.includes('unauthorized.zip'))).toBe(true);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('rejects permitted archive if its checksum is tampered', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-repo-tamper-test-'));
      try {
        fs.mkdirSync(path.join(tempDir, 'artifacts'), { recursive: true });
        fs.writeFileSync(path.join(tempDir, 'artifacts', 'corpus-held-out.tar.gz'), 'tampered content');

        const result = checkRepoArchiveHygiene(tempDir);
        expect(result.passed).toBe(false);
        expect(result.violations.some((v) => v.reason.includes('checksum mismatch'))).toBe(true);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });
});
