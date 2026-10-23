import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Architectural Boundary — Prevent Header-Derived Identity Regressions', () => {
  const rootDir = path.resolve(__dirname, '..');
  const targetDirs = [
    path.join(rootDir, 'apps/server'),
    path.join(rootDir, 'packages/api/src'),
    path.join(rootDir, 'packages/auth/src'),
  ];

  const forbiddenHeaders = [
    'x-role',
    'x-roles',
    'x-principal-roles',
    'x-user-role',
    'x-principal-id',
    'x-max-classification',
  ];

  function getAllProductionSourceFiles(dir: string): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '__tests__' || entry.name === 'tests' || entry.name === 'dist') {
          continue;
        }
        results.push(...getAllProductionSourceFiles(fullPath));
      } else if (
        (entry.name.endsWith('.ts') || entry.name.endsWith('.js')) &&
        !entry.name.endsWith('.test.ts') &&
        !entry.name.endsWith('.spec.ts')
      ) {
        results.push(fullPath);
      }
    }
    return results;
  }

  const productionFiles = targetDirs.flatMap((d) => getAllProductionSourceFiles(d));

  it('verifies that no production route, adapter, or service reads client-controlled identity headers', () => {
    const violations: { file: string; header: string; line: number; text: string }[] = [];

    for (const file of productionFiles) {
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      lines.forEach((line, index) => {
        // Skip comment lines
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
          return;
        }

        for (const forbidden of forbiddenHeaders) {
          // Look for direct header accesses such as headers['x-role'] or get('x-role') or "x-role"
          const regex = new RegExp(`['"\`]${forbidden}['"\`]`, 'i');
          if (regex.test(line)) {
            violations.push({
              file: path.relative(rootDir, file),
              header: forbidden,
              line: index + 1,
              text: trimmed,
            });
          }
        }
      });
    }

    expect(
      violations,
      `Detected unauthorized header-derived identity inspection in production files:\n${violations
        .map((v) => `  ${v.file}:${v.line} -> ${v.header} in: "${v.text}"`)
        .join('\n')}`
    ).toEqual([]);
  });

  it('guarantees ApiAuthenticator.extractPrincipal does NOT exist in production packages/api/src/auth.ts', () => {
    const authPath = path.join(rootDir, 'packages/api/src/auth.ts');
    const content = fs.readFileSync(authPath, 'utf-8');

    expect(content).not.toContain('extractPrincipal(');
    expect(content).toContain('resolveVerifiedPrincipal');
  });

  it('guarantees ApiAuthenticator requires verified req.principal and fails closed if absent or unauthenticated', () => {
    const authPath = path.join(rootDir, 'packages/api/src/auth.ts');
    const content = fs.readFileSync(authPath, 'utf-8');

    expect(content).toContain('if (!principal.is_authenticated || principal.roles.includes');
    expect(content).toContain('resolveVerifiedPrincipal');
  });

  it('ensures Express and Fastify adapters forward req.principal to router context', () => {
    const expressAdapterPath = path.join(rootDir, 'packages/api/src/express-adapter.ts');
    const fastifyAdapterPath = path.join(rootDir, 'packages/api/src/fastify-adapter.ts');

    const expressContent = fs.readFileSync(expressAdapterPath, 'utf-8');
    expect(expressContent).toContain('principal: (req as any).principal');

    const fastifyContent = fs.readFileSync(fastifyAdapterPath, 'utf-8');
    expect(fastifyContent).toContain('principal: req.principal');
  });
});
