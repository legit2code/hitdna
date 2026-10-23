import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/coverage/**',
      '**/.git/**',
      'packages/syntax/bin/**',
    ],
  },
  ...tseslint.configs.recommended,
  {
    files: [
      'apps/server/**/*.{ts,tsx}',
      'packages/**/*.{ts,tsx}',
      'workers/**/*.{ts,tsx}',
      'tests/**/*.{ts,tsx}',
      'src/__tests__/**/*.{ts,tsx}',
      'scripts/**/*.{ts,tsx}',
      'server.ts',
      'vite.config.ts',
      'vitest.config.ts',
    ],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-misused-promises': 'warn',
    },
  },
  {
    rules: {
      'no-console': 'warn',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-namespace': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      'prefer-const': 'warn',
      'no-var': 'warn',
    },
  },
  // Boundary Rule 1: apps/web may not import workers/**, apps/server, packages/db
  {
    files: ['apps/web/**/*.{ts,tsx}', 'apps/web/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'pg',
              message:
                'Architecture Invariant Violation (R05): Direct database access via `pg` is forbidden outside packages/db. All database access must use DatabaseClient in packages/db.',
            },
          ],
          patterns: [
            {
              group: [
                '**/workers/**',
                '**/workers',
                'workers/**',
                'workers',
                '../workers/**',
                '../workers',
                '../../workers/**',
                '../../workers',
                '../../../workers/**',
                '../../../workers',
                '@caim/composer/**',
                '@caim/composer',
                '@caim/composition/**',
                '@caim/composition',
                '@caim/decision/**',
                '@caim/decision',
                '@caim/discovery/**',
                '@caim/discovery',
                '@caim/evaluation/**',
                '@caim/evaluation',
                '@caim/knowledge/**',
                '@caim/knowledge',
                '@caim/worker-lifecycle/**',
                '@caim/worker-lifecycle',
                '@caim/sandbox-orchestrator/**',
                '@caim/sandbox-orchestrator',
                '@caim/semantic/**',
                '@caim/semantic',
                '@caim/static-analysis/**',
                '@caim/static-analysis',
                '@caim/cloudflare-scheduler/**',
                '@caim/cloudflare-scheduler',
              ],
              message:
                'Architecture Invariant Violation: apps/web may not import workers directly. Workers run out-of-process.',
            },
            {
              group: [
                '**/apps/server/**',
                '**/apps/server',
                'apps/server/**',
                'apps/server',
                '../apps/server/**',
                '../apps/server',
                '../../apps/server/**',
                '../../apps/server',
                '../server/**',
                '../server',
                '../../server/**',
                '../../server',
                '@caim/server',
                '@caim/server/**',
              ],
              message:
                'Architecture Invariant Violation: apps/web may not import apps/server directly.',
            },
            {
              group: [
                '**/packages/db/**',
                '**/packages/db',
                'packages/db/**',
                'packages/db',
                '../packages/db/**',
                '../packages/db',
                '../../packages/db/**',
                '../../packages/db',
                '../db/**',
                '../db',
                '../../db/**',
                '../../db',
                '@caim/db',
                '@caim/db/**',
              ],
              message:
                'Architecture Invariant Violation: apps/web may not import packages/db directly. Direct database access from client is prohibited.',
            },
          ],
        },
      ],
    },
  },
  // Boundary Rule 2: packages/** may not import apps/** or workers/**
  // Boundary Rule 2A: packages/** may not import apps/**
  {
    files: ['packages/**/*.{ts,tsx}', 'packages/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '**/apps/**',
                '**/apps',
                'apps/**',
                'apps',
                '../apps/**',
                '../apps',
                '../../apps/**',
                '../../apps',
                '@caim/server',
                '@caim/server/**',
                '@caim/web',
                '@caim/web/**',
              ],
              message: 'Architecture Invariant Violation: packages/** may not import apps/**.',
            },
          ],
        },
      ],
    },
  },
  // Boundary Rule 2B: Direct database access via `pg` is forbidden outside packages/db
  {
    files: ['packages/!(db)/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'pg',
              message:
                'Architecture Invariant Violation (R05): Direct database access via `pg` is forbidden outside packages/db. All database access must use DatabaseClient in packages/db.',
            },
          ],
        },
      ],
    },
  },
  // Boundary Rule 2C: packages/** may not import workers/** (except workflow orchestrator)
  {
    files: ['packages/!(workflow)/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '**/workers/**',
                '**/workers',
                'workers/**',
                'workers',
                '../workers/**',
                '../workers',
                '../../workers/**',
                '../../workers',
                '@caim/composer/**',
                '@caim/composer',
                '@caim/composition/**',
                '@caim/composition',
                '@caim/decision/**',
                '@caim/decision',
                '@caim/discovery/**',
                '@caim/discovery',
                '@caim/evaluation/**',
                '@caim/evaluation',
                '@caim/knowledge/**',
                '@caim/knowledge',
                '@caim/worker-lifecycle/**',
                '@caim/worker-lifecycle',
                '@caim/sandbox-orchestrator/**',
                '@caim/sandbox-orchestrator',
                '@caim/semantic/**',
                '@caim/semantic',
                '@caim/static-analysis/**',
                '@caim/static-analysis',
                '@caim/cloudflare-scheduler/**',
                '@caim/cloudflare-scheduler',
              ],
              message: 'Architecture Invariant Violation: packages/** may not import workers/**.',
            },
          ],
        },
      ],
    },
  },
  // Boundary Rule 3: apps/server may not import workers/** (ADR-002 Worker Isolation)
  {
    files: ['apps/server/**/*.{ts,tsx}', 'apps/server/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'warn',
        {
          paths: [
            {
              name: 'pg',
              message:
                'Architecture Invariant Violation (R05): Direct database access via `pg` is forbidden outside packages/db. All database access must use DatabaseClient in packages/db.',
            },
          ],
          patterns: [
            {
              group: [
                '**/workers/**',
                '**/workers',
                'workers/**',
                'workers',
                '../workers/**',
                '../workers',
                '../../workers/**',
                '../../workers',
                '../../../workers/**',
                '../../../workers',
                '@caim/composer/**',
                '@caim/composer',
                '@caim/composition/**',
                '@caim/composition',
                '@caim/decision/**',
                '@caim/decision',
                '@caim/discovery/**',
                '@caim/discovery',
                '@caim/evaluation/**',
                '@caim/evaluation',
                '@caim/knowledge/**',
                '@caim/knowledge',
                '@caim/worker-lifecycle/**',
                '@caim/worker-lifecycle',
                '@caim/sandbox-orchestrator/**',
                '@caim/sandbox-orchestrator',
                '@caim/semantic/**',
                '@caim/semantic',
                '@caim/static-analysis/**',
                '@caim/static-analysis',
                '@caim/cloudflare-scheduler/**',
                '@caim/cloudflare-scheduler',
              ],
              message:
                'Architecture Warning (pre-R09): apps/server should communicate with workers asynchronously via queues and events.',
            },
          ],
        },
      ],
    },
  },
  // R04 Security Gate: no raw === or !== comparison on secrets/tokens in packages/auth
  {
    files: ['packages/auth/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "BinaryExpression[operator=/^(===|!==|==|!=)$/][left.name=/secret|token|credential/i], BinaryExpression[operator=/^(===|!==|==|!=)$/][right.name=/secret|token|credential/i]",
          message:
            'Direct equality comparison on secrets, tokens, or credentials is strictly forbidden in packages/auth. Use crypto.timingSafeEqual or safeCompareSecrets.',
        },
      ],
    },
  },
  // R05 Data Access Gate: forbid pool.query and client.query outside packages/db
  {
    files: [
      'apps/**/*.{ts,tsx}',
      'packages/!(db)/**/*.{ts,tsx}',
      'workers/**/*.{ts,tsx}',
    ],
    rules: {
      'no-restricted-properties': [
        'error',
        {
          object: 'pool',
          property: 'query',
          message:
            'Architecture Invariant Violation (R05): Direct pool.query is forbidden outside packages/db. All database access must use DatabaseClient (withTenantTx / withSystemTx).',
        },
        {
          object: 'client',
          property: 'query',
          message:
            'Architecture Invariant Violation (R05): Direct client.query is forbidden outside packages/db. All database access must use DatabaseClient (withTenantTx / withSystemTx).',
        },
      ],
    },
  }
);
