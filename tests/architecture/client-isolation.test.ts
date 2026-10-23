import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';

describe('Architecture Boundary: Web Client Isolation (F-19)', () => {
  it('strictly verifies zero dependency violations from apps/web to forbidden modules via dependency-cruiser', async () => {
    const { cruise } = await import('dependency-cruiser');
    const configPath = path.resolve(process.cwd(), '.dependency-cruiser.cjs');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const config = require(configPath);

    const result = await cruise(
      ['apps/web'],
      {
        validate: true,
        ruleSet: config,
        tsPreCompilationDeps: true,
        tsConfig: { fileName: 'tsconfig.json' },
      }
    );

    const output = result.output as any;
    const violations = output.summary?.violations || output.violations || [];
    expect(violations).toEqual([]);
    expect(output.summary?.error ?? output.error ?? 0).toBe(0);
  });

  it('verifies that dependency-cruiser rules catch forbidden imports (negative verification)', async () => {
    const { cruise } = await import('dependency-cruiser');
    const configPath = path.resolve(process.cwd(), '.dependency-cruiser.cjs');
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const config = require(configPath);

    // Test negative synthetic imports:
    // 1. node:* builtin
    // 2. packages/auth
    // 3. packages/db
    // 4. packages/packaging/src/crypto
    // 5. workers/*
    const syntheticChecks = [
      {
        name: 'forbidden node:crypto',
        file: 'apps/web/test-node-violation.ts',
        content: `import crypto from 'node:crypto'; export const x = crypto;`,
        rule: 'no-web-to-node-builtins',
      },
      {
        name: 'forbidden packages/auth',
        file: 'apps/web/test-auth-violation.ts',
        content: `import { AuthService } from '../../packages/auth/src/index.ts'; export const x = AuthService;`,
        rule: 'no-web-to-auth',
      },
      {
        name: 'forbidden packages/db',
        file: 'apps/web/test-db-violation.ts',
        content: `import { DatabasePool } from '../../packages/db/src/index.ts'; export const x = DatabasePool;`,
        rule: 'no-web-to-db',
      },
      {
        name: 'forbidden packages/packaging/src/crypto',
        file: 'apps/web/test-crypto-violation.ts',
        content: `import { SignatureVerifier } from '../../packages/packaging/src/crypto/verifier.ts'; export const x = SignatureVerifier;`,
        rule: 'no-web-to-packaging-crypto',
      },
      {
        name: 'forbidden workers/discovery',
        file: 'apps/web/test-worker-violation.ts',
        content: `import { runDiscoveryJob } from '../../workers/discovery/index.ts'; export const x = runDiscoveryJob;`,
        rule: 'no-web-to-workers',
      },
    ];

    for (const testCase of syntheticChecks) {
      const tempPath = path.resolve(process.cwd(), testCase.file);
      try {
        fs.writeFileSync(tempPath, testCase.content, 'utf-8');
        const result = await cruise(
          [testCase.file],
          {
            validate: true,
            ruleSet: config,
            tsPreCompilationDeps: true,
            tsConfig: { fileName: 'tsconfig.json' },
          }
        );
        const output = result.output as any;
        const violations = output.summary?.violations || output.violations || [];
        const matchingViolation = violations.find((v: any) => v.rule?.name === testCase.rule);
        expect(
          matchingViolation,
          `Expected ${testCase.name} to trigger rule ${testCase.rule}`
        ).toBeDefined();
      } finally {
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
      }
    }
  });

  it('scans all source files under apps/web to ensure none directly import node:*, packages/auth, packages/db, packages/packaging/src/crypto, or workers/*', () => {
    const webDir = path.resolve(process.cwd(), 'apps/web');
    const forbiddenPatterns = [
      /from\s+['"]node:[^'"]+['"]/,
      /from\s+['"][^'"]*packages\/auth(?:\/|['"])/,
      /from\s+['"][^'"]*packages\/db(?:\/|['"])/,
      /from\s+['"][^'"]*packages\/packaging\/src\/crypto(?:\/|['"])/,
      /from\s+['"][^'"]*workers\/[^'"]+['"]/,
    ];

    const violations: Array<{ file: string; match: string }> = [];

    function scan(dir: string) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          scan(fullPath);
        } else if (/\.(tsx?|jsx?)$/.test(entry.name)) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          for (const pattern of forbiddenPatterns) {
            const m = content.match(pattern);
            if (m) {
              violations.push({ file: path.relative(process.cwd(), fullPath), match: m[0] });
            }
          }
        }
      }
    }

    scan(webDir);
    expect(violations).toEqual([]);
  });
});
