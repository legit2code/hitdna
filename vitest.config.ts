import { defineConfig, Plugin } from 'vitest/config';
import path from 'path';
import fs from 'fs';

function resolveWorkspaceTsPaths(): Plugin {
  const tsconfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'tsconfig.json'), 'utf-8'));
  const paths = (tsconfig.compilerOptions.paths || {}) as Record<string, string[]>;

  return {
    name: 'resolve-workspace-ts-paths',
    enforce: 'pre',
    resolveId(source) {
      if (source.startsWith('@caim/')) {
        for (const [pattern, targets] of Object.entries(paths)) {
          const target = targets[0];
          if (pattern.endsWith('/*')) {
            const prefix = pattern.slice(0, -2);
            if (source.startsWith(prefix + '/')) {
              const subpath = source.slice(prefix.length + 1);
              const targetSub = target.slice(0, -2) + '/' + subpath;
              let resolved = path.resolve(__dirname, targetSub);
              if (resolved.endsWith('.js') && !fs.existsSync(resolved)) {
                const tsCand = resolved.slice(0, -3) + '.ts';
                if (fs.existsSync(tsCand)) {
                  resolved = tsCand;
                }
              }
              if (!fs.existsSync(resolved)) {
                if (fs.existsSync(resolved + '.ts')) {
                  resolved = resolved + '.ts';
                } else if (fs.existsSync(resolved + '/index.ts')) {
                  resolved = resolved + '/index.ts';
                }
              }
              return resolved;
            }
          } else if (source === pattern) {
            return path.resolve(__dirname, target);
          }
        }
      }
      return null;
    },
  };
}

export const canonicalSlowSuites = [
  'src/__tests__/p19_sandbox_runtime_evasion.test.ts',
  'src/__tests__/p32_ci_migration_dr_release.test.ts',
  'src/__tests__/p33_performance_smoke_dedicated.test.ts',
  'tests/cross-tenant-rls-fail-closed.test.ts',
  'tests/rp00-verification-infrastructure.test.ts',
];

const slowSuites = canonicalSlowSuites.map(suite => `**/${suite}`);

const isSlowOnly = process.env.SLOW_TESTS_ONLY === 'true';
const isRunAll = process.env.RUN_ALL_TESTS === 'true';
const hasSpecificTarget = process.argv.some(arg =>
  canonicalSlowSuites.some(suite => arg.includes(path.basename(suite, '.ts')))
);

export default defineConfig({
  plugins: [resolveWorkspaceTsPaths()],
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000,
    hookTimeout: 60000,
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.git/**',
      ...(isSlowOnly || isRunAll || hasSpecificTarget ? [] : slowSuites),
    ],
    include: isSlowOnly
      ? canonicalSlowSuites
      : [
          'src/**/*.{test,spec}.{ts,tsx}',
          'tests/**/*.{test,spec}.{ts,tsx}',
          'packages/**/*.{test,spec}.{ts,tsx}',
          'workers/**/*.{test,spec}.{ts,tsx}',
          'scripts/**/*.{test,spec}.{ts,tsx}',
        ],
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
});
