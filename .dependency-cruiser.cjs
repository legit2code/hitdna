/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: 'no-web-to-node-builtins',
      comment: 'apps/web must not depend on node:* built-in modules',
      severity: 'error',
      from: {
        path: '^apps/web',
      },
      to: {
        dependencyTypes: ['core'],
      },
    },
    {
      name: 'no-web-to-auth',
      comment: 'apps/web must not import packages/auth directly',
      severity: 'error',
      from: {
        path: '^apps/web',
      },
      to: {
        path: '^packages/auth',
      },
    },
    {
      name: 'no-web-to-db',
      comment: 'apps/web must not import packages/db directly',
      severity: 'error',
      from: {
        path: '^apps/web',
      },
      to: {
        path: '^packages/db',
      },
    },
    {
      name: 'no-web-to-packaging-crypto',
      comment: 'apps/web must not import packages/packaging/src/crypto directly',
      severity: 'error',
      from: {
        path: '^apps/web',
      },
      to: {
        path: '^packages/packaging/src/crypto',
      },
    },
    {
      name: 'no-web-to-workers',
      comment: 'apps/web must not import any workers directly',
      severity: 'error',
      from: {
        path: '^apps/web',
      },
      to: {
        path: '^workers',
      },
    },
  ],
  options: {
    doNotFollow: {
      path: 'node_modules',
    },
    tsPreCompilationDeps: true,
    tsConfig: {
      fileName: 'tsconfig.json',
    },
  },
};
