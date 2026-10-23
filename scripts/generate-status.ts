import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import pg from 'pg';

export interface EngineStatusResult {
  engineId: string;
  modulePath: string;
  lineCount: number;
  isTested: boolean;
  status: 'IMPLEMENTED' | 'STUB';
  testsReferencing: string[];
}

export interface SchemaRlsInfo {
  schemaName: string;
  totalTables: number;
  rlsEnabledTables: number;
  rlsCoveragePct: number;
  tables: Array<{
    name: string;
    rlsEnabled: boolean;
    rlsForced: boolean;
  }>;
}

export interface GeneratedStatusData {
  generatedAt: string;
  githubRunId: string;
  commitSha: string;
  testSuiteDurationMs: number | null;
  migrations: {
    count: number;
    head: string;
    files: string[];
  };
  tests: {
    count: number;
    files: string[];
  };
  databaseCatalog: {
    connected: boolean;
    totalTables: number;
    totalRlsEnabled: number;
    overallRlsCoveragePct: number;
    schemas: Record<string, SchemaRlsInfo>;
  };
  engines: {
    total: number;
    implementedCount: number;
    stubCount: number;
    workerStubs: Record<string, 'IMPLEMENTED' | 'STUB'>;
    items: EngineStatusResult[];
  };
}

/**
 * Strips comments and returns count of substantive code lines.
 */
export function countNonCommentLines(content: string): number {
  // Strip block comments /* ... */
  const noBlockComments = content.replace(/\/\*[\s\S]*?\*\//g, '');
  const lines = noBlockComments.split(/\r?\n/);
  let count = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('//')) continue;
    if (line.startsWith('*')) continue;
    count++;
  }

  return count;
}

/**
 * Checks if any test file imports or references a module.
 */
export function isModuleImportedByTests(
  moduleRelativePath: string,
  testFiles: Array<{ path: string; content: string }>
): { imported: boolean; referencingTests: string[] } {
  const normalizedModule = moduleRelativePath.replace(/\\/g, '/').replace(/\/index\.ts$/, '');
  const baseName = path.basename(normalizedModule, path.extname(normalizedModule));
  const dirName = path.dirname(normalizedModule);

  const referencingTests: string[] = [];

  for (const test of testFiles) {
    const content = test.content;
    // Check if test imports or references module path, directory, or package name
    const hasPathRef =
      content.includes(normalizedModule) ||
      (dirName !== '.' && content.includes(dirName)) ||
      content.includes(`@caim/${baseName}`) ||
      content.includes(`@workers/${baseName}`) ||
      content.includes(`workers/${baseName}`);
    const hasImportRef =
      new RegExp(`(?:import|require)\\s*\\(?['"][^'"]*${baseName}['"]\\)?`).test(content) ||
      new RegExp(`from\\s+['"][^'"]*${baseName}['"]`).test(content);

    if (hasPathRef || hasImportRef) {
      referencingTests.push(test.path);
    }
  }

  return {
    imported: referencingTests.length > 0,
    referencingTests,
  };
}

/**
 * Evaluates an engine file or directory against classification rules:
 * Counts all non-test .ts/.tsx files and substantive LOC recursively under directory.
 * Classify STUB only when total LOC is under a threshold AND code returns constants.
 */
export function evaluateEngineModule(
  engineId: string,
  moduleRelativePath: string,
  rootDir: string,
  testFiles: Array<{ path: string; content: string }>,
  locThreshold: number = 40
): EngineStatusResult {
  const fullPath = path.resolve(rootDir, moduleRelativePath);

  if (!fs.existsSync(fullPath)) {
    return {
      engineId,
      modulePath: moduleRelativePath,
      lineCount: 0,
      isTested: false,
      status: 'STUB',
      testsReferencing: [],
    };
  }

  const stat = fs.statSync(fullPath);
  let totalLineCount = 0;
  let allContent = '';

  // Determine target directory if this is a directory or a worker module
  let targetDir: string | null = null;
  if (stat.isDirectory()) {
    targetDir = fullPath;
  } else if (moduleRelativePath.startsWith('workers/')) {
    const candidateDir = path.dirname(fullPath);
    if (candidateDir !== path.resolve(rootDir, 'workers') && fs.existsSync(candidateDir) && fs.statSync(candidateDir).isDirectory()) {
      targetDir = candidateDir;
    }
  }

  if (targetDir) {
    function walk(dir: string) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const entryFull = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(entryFull);
        } else if (
          /\.(ts|tsx|js|jsx)$/.test(entry.name) &&
          !/\.(test|spec)\./.test(entry.name) &&
          !entry.name.endsWith('.d.ts')
        ) {
          const content = fs.readFileSync(entryFull, 'utf-8');
          allContent += '\n' + content;
          totalLineCount += countNonCommentLines(content);
        }
      }
    }
    walk(targetDir);
  } else {
    allContent = fs.readFileSync(fullPath, 'utf-8');
    totalLineCount = countNonCommentLines(allContent);
  }

  const { imported, referencingTests } = isModuleImportedByTests(moduleRelativePath, testFiles);

  // Check if code returns hardcoded constants or stubs
  const returnsConstantsPattern = /return\s*\{\s*(?:success:\s*true\s*,\s*)?(?:artifactsCount:\s*1\b|astNodesCount:\s*10\b|passedSuites:\s*10\b)/;
  const hasStubConstantReturn = returnsConstantsPattern.test(allContent);
  const isStubEntry = allContent.includes('NotImplementedError') && totalLineCount < locThreshold;

  // classify STUB only when total LOC is under a threshold AND code returns constants
  const isStub =
    !imported ||
    (totalLineCount <= locThreshold && (hasStubConstantReturn || isStubEntry || totalLineCount <= 2));

  return {
    engineId,
    modulePath: moduleRelativePath,
    lineCount: totalLineCount,
    isTested: imported,
    status: isStub ? 'STUB' : 'IMPLEMENTED',
    testsReferencing: referencingTests,
  };
}

/**
 * Computes migrations count and head from supabase/migrations.
 */
export function getMigrationsInfo(rootDir: string): { count: number; head: string; files: string[] } {
  const migrationsDir = path.join(rootDir, 'supabase', 'migrations');
  if (!fs.existsSync(migrationsDir)) {
    return { count: 0, head: 'NONE', files: [] };
  }

  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  return {
    count: files.length,
    head: files.length > 0 ? files[files.length - 1] : 'NONE',
    files,
  };
}

/**
 * Globs all test files in the workspace.
 */
export function getTestFiles(rootDir: string): Array<{ path: string; content: string }> {
  const testFiles: Array<{ path: string; content: string }> = [];

  function scan(current: string) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git' || entry.name === 'coverage') {
        continue;
      }
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        scan(full);
      } else if (entry.isFile()) {
        if (/\.(test|spec)\.(ts|tsx|js|jsx)$/.test(entry.name)) {
          const relPath = path.relative(rootDir, full).replace(/\\/g, '/');
          testFiles.push({
            path: relPath,
            content: fs.readFileSync(full, 'utf-8'),
          });
        }
      }
    }
  }

  scan(rootDir);
  return testFiles.sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Queries pg_catalog for per-schema tables and RLS status.
 */
export async function queryPgCatalogRls(databaseUrl?: string): Promise<GeneratedStatusData['databaseCatalog']> {
  const connString = databaseUrl || process.env.DATABASE_URL;

  if (!connString) {
    return {
      connected: false,
      totalTables: 0,
      totalRlsEnabled: 0,
      overallRlsCoveragePct: 0,
      schemas: {},
    };
  }

  const client = new pg.Client({ connectionString: connString });
  try {
    await client.connect();
    const query = `
      SELECT
        n.nspname AS schemaname,
        c.relname AS tablename,
        c.relrowsecurity AS rls_enabled,
        c.relforcerowsecurity AS rls_forced
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind = 'r'
        AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      ORDER BY n.nspname, c.relname;
    `;
    const res = await client.query(query);
    await client.end();

    const schemas: Record<string, SchemaRlsInfo> = {};
    let totalTables = 0;
    let totalRlsEnabled = 0;

    for (const row of res.rows) {
      const s = row.schemaname;
      if (!schemas[s]) {
        schemas[s] = {
          schemaName: s,
          totalTables: 0,
          rlsEnabledTables: 0,
          rlsCoveragePct: 0,
          tables: [],
        };
      }

      schemas[s].totalTables++;
      totalTables++;

      const isRls = Boolean(row.rls_enabled);
      if (isRls) {
        schemas[s].rlsEnabledTables++;
        totalRlsEnabled++;
      }

      schemas[s].tables.push({
        name: row.tablename,
        rlsEnabled: isRls,
        rlsForced: Boolean(row.rls_forced),
      });
    }

    for (const s of Object.keys(schemas)) {
      schemas[s].rlsCoveragePct =
        schemas[s].totalTables > 0
          ? Math.round((schemas[s].rlsEnabledTables / schemas[s].totalTables) * 1000) / 10
          : 0;
    }

    const overallRlsCoveragePct =
      totalTables > 0 ? Math.round((totalRlsEnabled / totalTables) * 1000) / 10 : 0;

    return {
      connected: true,
      totalTables,
      totalRlsEnabled,
      overallRlsCoveragePct,
      schemas,
    };
  } catch (err) {
    return {
      connected: false,
      totalTables: 0,
      totalRlsEnabled: 0,
      overallRlsCoveragePct: 0,
      schemas: {},
    };
  }
}

/**
 * Computes complete status data.
 */
export async function computeStatusData(rootDir: string = process.cwd()): Promise<GeneratedStatusData> {
  const migrations = getMigrationsInfo(rootDir);
  const testFiles = getTestFiles(rootDir);
  const dbCatalog = await queryPgCatalogRls();

  let commitSha = process.env.GITHUB_SHA || '';
  if (!commitSha) {
    const gitDir = path.join(rootDir, '.git');
    if (!fs.existsSync(gitDir)) {
      commitSha = 'GIT_SHA: UNAVAILABLE';
    } else {
      try {
        commitSha = execSync('git rev-parse HEAD', { cwd: rootDir, encoding: 'utf-8' }).trim();
      } catch {
        commitSha = 'GIT_SHA: UNAVAILABLE';
      }
    }
  }

  const githubRunId = process.env.GITHUB_RUN_ID || 'LOCAL';
  const testSuiteDurationMs = process.env.TEST_SUITE_DURATION_MS
    ? parseInt(process.env.TEST_SUITE_DURATION_MS, 10)
    : null;

  // Key worker engines to evaluate explicitly
  const workerModules = [
    { id: 'workers/discovery', path: 'workers/discovery' },
    { id: 'workers/semantic', path: 'workers/semantic' },
    { id: 'workers/evaluation', path: 'workers/evaluation' },
    { id: 'workers/static-analysis', path: 'workers/static-analysis' },
    { id: 'workers/composition', path: 'workers/composition' },
    { id: 'workers/sandbox-orchestrator', path: 'workers/sandbox-orchestrator' },
    { id: 'workers/decision', path: 'workers/decision' },
    { id: 'workers/knowledge', path: 'workers/knowledge' },
    { id: 'workers/lifecycle', path: 'workers/lifecycle' },
    { id: 'workers/composer', path: 'workers/composer' },
  ];

  // Also read ENGINE_IMPLEMENTATION_COVERAGE.csv if available
  const csvPath = path.join(rootDir, 'docs', 'implementation', 'ENGINE_IMPLEMENTATION_COVERAGE.csv');
  const engineItems: EngineStatusResult[] = [];
  const workerStubs: Record<string, 'IMPLEMENTED' | 'STUB'> = {};

  // First evaluate workers
  for (const wm of workerModules) {
    const res = evaluateEngineModule(wm.id, wm.path, rootDir, testFiles);
    workerStubs[wm.id] = res.status;
    engineItems.push(res);
  }

  // Next evaluate engines from CSV if present
  if (fs.existsSync(csvPath)) {
    const csvLines = fs.readFileSync(csvPath, 'utf-8').split(/\r?\n/).slice(1);
    for (const line of csvLines) {
      if (!line.trim()) continue;
      const parts = line.split(',');
      if (parts.length < 4) continue;
      const engineId = parts[1]?.trim();
      const primaryPkgs = (parts[3] || '').split(';').map((p) => p.trim());
      if (!engineId || !primaryPkgs[0]) continue;

      // Avoid duplicating items already evaluated
      if (engineItems.some((e) => e.engineId === engineId)) continue;

      const evalRes = evaluateEngineModule(engineId, primaryPkgs[0], rootDir, testFiles);
      engineItems.push(evalRes);
    }
  }

  const implementedCount = engineItems.filter((e) => e.status === 'IMPLEMENTED').length;
  const stubCount = engineItems.filter((e) => e.status === 'STUB').length;

  return {
    generatedAt: new Date().toISOString(),
    githubRunId,
    commitSha,
    testSuiteDurationMs,
    migrations: {
      count: migrations.count,
      head: migrations.head,
      files: migrations.files,
    },
    tests: {
      count: testFiles.length,
      files: testFiles.map((t) => t.path),
    },
    databaseCatalog: dbCatalog,
    engines: {
      total: engineItems.length,
      implementedCount,
      stubCount,
      workerStubs,
      items: engineItems,
    },
  };
}

/**
 * Formats status data as markdown for STATUS.generated.md
 */
export function formatStatusMarkdown(data: GeneratedStatusData): string {
  const dbSection = data.databaseCatalog.connected
    ? `
| Schema | Total Tables | RLS Enabled | Coverage |
| --- | --- | --- | --- |
${Object.values(data.databaseCatalog.schemas)
  .map(
    (s) =>
      `| \`${s.schemaName}\` | ${s.totalTables} | ${s.rlsEnabledTables} | ${s.rlsCoveragePct}% |`
  )
  .join('\n')}

**Overall RLS Coverage**: ${data.databaseCatalog.overallRlsCoveragePct}% (${data.databaseCatalog.totalRlsEnabled}/${data.databaseCatalog.totalTables} tables)
`
    : `*PostgreSQL catalog offline / not connected during this generation pass.*`;

  return `# CAIM Platform Generated Status Report

> **Automated Notice**: This document is generated machine-authoritatively by \`scripts/generate-status.ts\` in CI.
> Hand-written status claims are strictly prohibited. Refer to \`docs/implementation/TRUTH_LEDGER.md\` for audit findings.

- **Generated At**: \`${data.generatedAt}\`
- **Git Commit SHA**: \`${data.commitSha}\`
- **GitHub Run ID**: \`${data.githubRunId}\`
- **Test Suite Duration**: \`${data.testSuiteDurationMs !== null ? data.testSuiteDurationMs + ' ms' : 'N/A'}\`

---

## 1. Database Migrations
- **Total Migrations**: \`${data.migrations.count}\`
- **Migration Head**: \`${data.migrations.head}\`

---

## 2. Test Suite
- **Total Test Files**: \`${data.tests.count}\`

---

## 3. Database Catalog & RLS Security
${dbSection}

---

## 4. Engine Coverage & Worker Verification
- **Total Engines Evaluated**: \`${data.engines.total}\`
- **Implemented Engines (>40 lines & tested)**: \`${data.engines.implementedCount}\`
- **Stub Engines**: \`${data.engines.stubCount}\`

### Worker Module Status
| Worker Module | Status | Line Count | Tested |
| --- | --- | --- | --- |
| \`workers/discovery\` | **${data.engines.workerStubs['workers/discovery'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/discovery')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/discovery')?.isTested ? 'YES' : 'NO'} |
| \`workers/semantic\` | **${data.engines.workerStubs['workers/semantic'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/semantic')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/semantic')?.isTested ? 'YES' : 'NO'} |
| \`workers/evaluation\` | **${data.engines.workerStubs['workers/evaluation'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/evaluation')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/evaluation')?.isTested ? 'YES' : 'NO'} |
| \`workers/static-analysis\` | **${data.engines.workerStubs['workers/static-analysis'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/static-analysis')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/static-analysis')?.isTested ? 'YES' : 'NO'} |
| \`workers/composition\` | **${data.engines.workerStubs['workers/composition'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/composition')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/composition')?.isTested ? 'YES' : 'NO'} |
| \`workers/sandbox-orchestrator\` | **${data.engines.workerStubs['workers/sandbox-orchestrator'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/sandbox-orchestrator')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/sandbox-orchestrator')?.isTested ? 'YES' : 'NO'} |
| \`workers/decision\` | **${data.engines.workerStubs['workers/decision'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/decision')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/decision')?.isTested ? 'YES' : 'NO'} |
| \`workers/knowledge\` | **${data.engines.workerStubs['workers/knowledge'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/knowledge')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/knowledge')?.isTested ? 'YES' : 'NO'} |
| \`workers/lifecycle\` | **${data.engines.workerStubs['workers/lifecycle'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/lifecycle')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/lifecycle')?.isTested ? 'YES' : 'NO'} |
| \`workers/composer\` | **${data.engines.workerStubs['workers/composer'] || 'STUB'}** | ${data.engines.items.find((i) => i.engineId === 'workers/composer')?.lineCount ?? 0} | ${data.engines.items.find((i) => i.engineId === 'workers/composer')?.isTested ? 'YES' : 'NO'} |

---
`;
}

/**
 * Main execution routine.
 */
export async function runGenerateStatus(rootDir: string = process.cwd()): Promise<GeneratedStatusData> {
  const data = await computeStatusData(rootDir);

  const docsDir = path.join(rootDir, 'docs', 'implementation');
  if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true });
  }

  const jsonPath = path.join(docsDir, 'status.generated.json');
  fs.writeFileSync(jsonPath, JSON.stringify(data, null, 2), 'utf-8');

  const mdPath = path.join(docsDir, 'STATUS.generated.md');
  fs.writeFileSync(mdPath, formatStatusMarkdown(data), 'utf-8');

  console.log(`[generate-status] Successfully generated:`);
  console.log(`  - ${jsonPath}`);
  console.log(`  - ${mdPath}`);
  console.log(`  Migrations: ${data.migrations.count}, Head: ${data.migrations.head}`);
  console.log(`  Test Files: ${data.tests.count}`);
  const stubs = Object.entries(data.engines.workerStubs)
    .filter(([_, st]) => st === 'STUB')
    .map(([id]) => id)
    .join(', ');
  console.log(`  Workers marked STUB: ${stubs || 'none'}`);

  return data;
}

if (process.argv[1] && process.argv[1].endsWith('generate-status.ts')) {
  runGenerateStatus().catch((err) => {
    console.error('[generate-status] Error:', err);
    process.exit(1);
  });
}
