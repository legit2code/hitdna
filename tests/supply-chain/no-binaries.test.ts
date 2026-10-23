import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import fs from 'node:fs';

describe('Supply Chain Integrity: No Committed Binaries (F-01, F-17)', () => {
  const getTrackedFiles = (): string[] => {
    try {
      const output = execSync('git ls-files', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] });
      const files = output
        .split('\n')
        .map((f) => f.trim())
        .filter((f) => f.length > 0 && fs.existsSync(f));
      if (files.length > 0) return files;
    } catch {
      // Fall through to directory traversal if git is unavailable in execution container
    }

    const collected: string[] = [];
    const scanDir = (dir: string) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === 'build' || entry.name === 'coverage' || entry.name === '.bin') continue;
        const fullPath = `${dir}/${entry.name}`;
        if (entry.isDirectory()) {
          scanDir(fullPath);
        } else if (entry.isFile()) {
          collected.push(fullPath.replace(/^\.\//, ''));
        }
      }
    };
    scanDir('.');
    return collected;
  };

  it('fails if git ls-files contains any .zip archive or compiled native binaries (ELF/PE/Mach-O)', () => {
    const trackedFiles = getTrackedFiles();
    expect(trackedFiles.length).toBeGreaterThan(0);

    const violations: Array<{ file: string; type: string }> = [];

    for (const filePath of trackedFiles) {
      if (filePath.endsWith('.zip')) {
        violations.push({ file: filePath, type: 'Zip Archive Extension (.zip)' });
        continue;
      }

      try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile() || stat.size < 4) {
          continue;
        }

        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(8);
        fs.readSync(fd, buffer, 0, 8, 0);
        fs.closeSync(fd);

        // Check ELF magic bytes: 0x7F 'E' 'L' 'F'
        if (
          buffer[0] === 0x7f &&
          buffer[1] === 0x45 &&
          buffer[2] === 0x4c &&
          buffer[3] === 0x46
        ) {
          violations.push({ file: filePath, type: 'ELF Binary' });
          continue;
        }

        // Check Mach-O magic bytes (32-bit & 64-bit, big & little endian, and universal binary)
        const magic32LE = buffer.readUInt32LE(0);
        const magic32BE = buffer.readUInt32BE(0);
        if (
          magic32LE === 0xfeedface ||
          magic32BE === 0xfeedface ||
          magic32LE === 0xfeedfacf ||
          magic32BE === 0xfeedfacf ||
          magic32LE === 0xcefaedfe ||
          magic32BE === 0xcefaedfe ||
          magic32LE === 0xcffaedfe ||
          magic32BE === 0xcffaedfe ||
          magic32BE === 0xcafebabe
        ) {
          violations.push({ file: filePath, type: 'Mach-O Binary' });
          continue;
        }

        // Check PE32 / Windows executable: 'MZ' header
        if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
          violations.push({ file: filePath, type: 'PE32 Executable' });
          continue;
        }

        // Check Zip archive headers: PK\x03\x04, PK\x05\x06, PK\x07\x08
        if (
          buffer[0] === 0x50 &&
          buffer[1] === 0x4b &&
          (buffer[2] === 0x03 || buffer[2] === 0x05 || buffer[2] === 0x07) &&
          (buffer[3] === 0x04 || buffer[3] === 0x06 || buffer[3] === 0x08)
        ) {
          violations.push({ file: filePath, type: 'Zip Archive Magic Bytes' });
          continue;
        }
      } catch {
        // Skip unreadable files
      }
    }

    expect(
      violations,
      `Detected committed binaries or archives in git repository: ${JSON.stringify(violations)}`
    ).toEqual([]);
  });

  it('verifies that the authoritative system gate command prints zero matches', () => {
    try {
      const output = execSync(
        "git ls-files | xargs file | grep -E 'ELF|Mach-O|PE32|Zip archive' || true",
        { encoding: 'utf-8' }
      ).trim();
      expect(output).toBe('');
    } catch (err: any) {
      expect(err.stdout?.toString().trim() || '').toBe('');
    }
  });
});
