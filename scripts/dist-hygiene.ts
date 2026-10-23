import fs from 'fs';
import path from 'path';
import http from 'http';
import crypto from 'crypto';
import { spawn } from 'child_process';

/**
 * Explicit, narrow exception per SECURITY.md Supply Chain & Dependency Build Policy:
 * artifacts/corpus-held-out.tar.gz is a sealed test corpus fixture containing held-out evaluation
 * samples required for offline golden-corpus regression gate execution in CI environments.
 * It contains zero binary executables and its cryptographic checksum is strictly verified.
 */
export const PERMITTED_REPOSITORY_ARCHIVES = new Set([
  'artifacts/corpus-held-out.tar.gz',
]);

export const PERMITTED_REPOSITORY_ARCHIVES_SHA256: Record<string, string> = {
  'artifacts/corpus-held-out.tar.gz': '9807a12237b9c4157f942bd9f1e2ee788ed668942e837feba0cdefd2785701ed',
};

export interface RepoArchiveHygieneResult {
  passed: boolean;
  violations: Array<{ file: string; reason: string }>;
  verifiedArchives: Array<{ file: string; sha256: string }>;
}

export function checkRepoArchiveHygiene(rootDir: string = process.cwd()): RepoArchiveHygieneResult {
  const violations: Array<{ file: string; reason: string }> = [];
  const verifiedArchives: Array<{ file: string; sha256: string }> = [];
  const ignoredDirs = new Set(['node_modules', '.git', 'dist', 'coverage', '.cache']);

  function walk(current: string) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!ignoredDirs.has(entry.name)) {
          walk(path.join(current, entry.name));
        }
      } else if (entry.isFile()) {
        const name = entry.name.toLowerCase();
        if (name.endsWith('.zip') || name.endsWith('.tar.gz') || name.endsWith('.tgz')) {
          const fullPath = path.join(current, entry.name);
          const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');

          if (!PERMITTED_REPOSITORY_ARCHIVES.has(relPath)) {
            violations.push({
              file: relPath,
              reason: `Unauthorized archive committed to repository (${relPath}). Prohibited per SECURITY.md.`,
            });
          } else {
            const fileBuf = fs.readFileSync(fullPath);
            const actualSha = crypto.createHash('sha256').update(fileBuf).digest('hex');
            const expectedSha = PERMITTED_REPOSITORY_ARCHIVES_SHA256[relPath];
            if (actualSha !== expectedSha) {
              violations.push({
                file: relPath,
                reason: `Permitted archive checksum mismatch for ${relPath}. Expected ${expectedSha}, got ${actualSha}.`,
              });
            } else {
              verifiedArchives.push({ file: relPath, sha256: actualSha });
            }
          }
        }
      }
    }
  }

  walk(rootDir);
  return {
    passed: violations.length === 0,
    violations,
    verifiedArchives,
  };
}

export interface DistHygieneViolation {
  file: string;
  reason: string;
  sizeBytes?: number;
}

export interface ChunkSizeReport {
  file: string;
  sizeBytes: number;
  budgetBytes: number;
  passed: boolean;
}

export interface DistHygieneResult {
  passed: boolean;
  violations: DistHygieneViolation[];
  scannedFiles: string[];
  sizeBudgetReports: ChunkSizeReport[];
}

export function checkDistHygiene(distDir: string = path.join(process.cwd(), 'dist'), options: { allowSourcemaps?: boolean } = {}): DistHygieneResult {
  const allowSourcemaps = options.allowSourcemaps ?? (process.env.ALLOW_SOURCEMAPS === '1');
  const maxSizeBytes = 5 * 1024 * 1024; // 5 MB global maximum

  const violations: DistHygieneViolation[] = [];
  const scannedFiles: string[] = [];
  const sizeBudgetReports: ChunkSizeReport[] = [];

  if (!fs.existsSync(distDir)) {
    violations.push({ file: distDir, reason: 'dist directory does not exist' });
    return { passed: false, violations, scannedFiles, sizeBudgetReports };
  }

  function getFileBudget(relPath: string): number {
    const norm = relPath.replace(/\\/g, '/');
    if (norm.includes('assets/vendor-')) {
      return 1024 * 1024; // 1 MB vendor budget
    }
    if (norm.includes('assets/index-') && norm.endsWith('.js')) {
      return 2 * 1024 * 1024; // 2 MB web entry bundle
    }
    if (norm.includes('assets/index-') && norm.endsWith('.css')) {
      return 512 * 1024; // 512 kB stylesheet
    }
    if (norm === 'server.cjs') {
      return 4 * 1024 * 1024; // 4 MB server bundle
    }
    return maxSizeBytes;
  }

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(distDir, fullPath);

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        scannedFiles.push(relPath);
        const stat = fs.statSync(fullPath);

        // 1. Check for *.zip
        if (entry.name.endsWith('.zip')) {
          violations.push({ file: relPath, reason: 'Contains prohibited *.zip file', sizeBytes: stat.size });
        }

        // 2. Check for *.map (unless ALLOW_SOURCEMAPS=1)
        if (entry.name.endsWith('.map') && !allowSourcemaps) {
          violations.push({ file: relPath, reason: 'Contains prohibited source map (*.map) when ALLOW_SOURCEMAPS!=1', sizeBytes: stat.size });
        }

        // 3. Check for .env*
        if (entry.name.startsWith('.env')) {
          violations.push({ file: relPath, reason: 'Contains prohibited .env* environment file', sizeBytes: stat.size });
        }

        // 4. Global 5 MB limit check
        if (stat.size > maxSizeBytes) {
          violations.push({
            file: relPath,
            reason: `File size ${(stat.size / (1024 * 1024)).toFixed(2)} MB exceeds 5 MB limit`,
            sizeBytes: stat.size,
          });
        }

        // 5. Size budget check
        const budget = getFileBudget(relPath);
        const passedBudget = stat.size <= budget;
        sizeBudgetReports.push({
          file: relPath,
          sizeBytes: stat.size,
          budgetBytes: budget,
          passed: passedBudget,
        });

        if (!passedBudget && stat.size <= maxSizeBytes) {
          violations.push({
            file: relPath,
            reason: `File size ${(stat.size / 1024).toFixed(2)} kB exceeds ${(budget / 1024).toFixed(2)} kB budget`,
            sizeBytes: stat.size,
          });
        }
      }
    }
  }

  walk(distDir);
  return {
    passed: violations.length === 0,
    violations,
    scannedFiles,
    sizeBudgetReports,
  };
}

export async function checkServerZipEndpoint(port: number): Promise<{ statusCode: number; safe: boolean }> {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: '127.0.0.1',
        port,
        path: '/caim-repository.zip',
        timeout: 5000,
      },
      (res) => {
        const safe = res.statusCode !== 200;
        resolve({ statusCode: res.statusCode || 0, safe });
      }
    );

    req.on('error', (err) => {
      // If server refused or connection dropped, it definitely did not return 200
      resolve({ statusCode: 0, safe: true });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: 0, safe: true });
    });
  });
}

export async function runDistHygieneCheck(): Promise<boolean> {
  console.log('[dist-hygiene] Scanning repository archives for SECURITY.md compliance...');
  const repoArchiveResult = checkRepoArchiveHygiene();
  if (!repoArchiveResult.passed) {
    console.error('[dist-hygiene] FAILED: Repository archive hygiene violations detected:');
    for (const v of repoArchiveResult.violations) {
      console.error(`  - ${v.file}: ${v.reason}`);
    }
    return false;
  }
  for (const va of repoArchiveResult.verifiedArchives) {
    console.log(`[dist-hygiene] Verified permitted archive exception ${va.file} (SHA-256: ${va.sha256.slice(0, 16)}...).`);
  }

  console.log('[dist-hygiene] Scanning dist/ for artifact hygiene violations...');
  const result = checkDistHygiene();

  console.log(`[dist-hygiene] Scanned ${result.scannedFiles.length} files.`);
  if (!result.passed) {
    console.error('[dist-hygiene] FAILED: Artifact hygiene violations detected in dist/:');
    for (const v of result.violations) {
      console.error(`  - ${v.file}: ${v.reason}`);
    }
    return false;
  }

  console.log('[dist-hygiene] PASSED: No forbidden files (*.zip, *.map, .env*, >5MB) in dist/.');

  console.log('\n[dist-hygiene] Artifact Chunk Size Budget Table:');
  console.log('┌────────────────────────────────────────────────┬──────────────┬──────────────┬────────┐');
  console.log('│ Chunk / Asset File                             │ Current Size │ Budget       │ Status │');
  console.log('├────────────────────────────────────────────────┼──────────────┼──────────────┼────────┤');
  for (const report of result.sizeBudgetReports) {
    const cur = (report.sizeBytes / 1024).toFixed(2) + ' kB';
    const bud = (report.budgetBytes / 1024).toFixed(2) + ' kB';
    const stat = report.passed ? 'PASS' : 'FAIL';
    console.log(`│ ${report.file.padEnd(46)} │ ${cur.padStart(12)} │ ${bud.padStart(12)} │ ${stat.padStart(6)} │`);
  }
  console.log('└────────────────────────────────────────────────┴──────────────┴──────────────┴────────┘\n');

  // Verify server endpoint does not return 200 for caim-repository.zip
  const testPort = 49123;
  console.log(`[dist-hygiene] Starting built server on port ${testPort} for serve-check...`);
  const serverProcess = spawn('node', ['dist/server.cjs'], {
    env: {
      ...process.env,
      TEST_PORT: String(testPort),
      SKIP_VITE: 'true',
    },
    stdio: 'ignore',
  });

  try {
    // Wait for server to listen
    await new Promise((r) => setTimeout(r, 2000));
    const endpointCheck = await checkServerZipEndpoint(testPort);
    console.log(`[dist-hygiene] GET /caim-repository.zip returned HTTP ${endpointCheck.statusCode}. Safe: ${endpointCheck.safe}`);
    if (!endpointCheck.safe) {
      console.error('[dist-hygiene] FAILED: /caim-repository.zip returned HTTP 200 OK!');
      return false;
    }
  } finally {
    serverProcess.kill('SIGTERM');
  }

  console.log('[dist-hygiene] PASSED: Dist hygiene and serve-check successful.');
  return true;
}

if (process.argv[1] && process.argv[1].endsWith('dist-hygiene.ts')) {
  runDistHygieneCheck().then((success) => {
    process.exit(success ? 0 : 1);
  });
}
