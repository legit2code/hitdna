import { describe, it, expect } from 'vitest';
import { ESLint } from 'eslint';
import path from 'node:path';

describe('Architecture Boundary Enforcement (F-07, F-08)', () => {
  const eslint = new ESLint();

  it('asserts apps/web/App.tsx strictly obeys boundary rules without restricted imports', async () => {
    const results = await eslint.lintFiles(['apps/web/App.tsx']);
    expect(results).toHaveLength(1);
    const boundaryErrors = results[0].messages.filter(
      (m) => m.ruleId === 'no-restricted-imports' && m.severity === 2
    );
    expect(boundaryErrors).toHaveLength(0);
  });

  it('fails with restricted import error when apps/web imports workers', async () => {
    const badCode = `
      import { DecisionEngine } from '../../workers/decision';
      export const test = () => DecisionEngine;
    `;
    const results = await eslint.lintText(badCode, {
      filePath: path.resolve(process.cwd(), 'apps/web/src/boundary-violation-test.tsx'),
    });
    expect(results).toHaveLength(1);
    const messages = results[0].messages;
    const restrictedImportErr = messages.find(
      (m) =>
        m.ruleId === 'no-restricted-imports' &&
        m.message.includes('apps/web may not import workers directly')
    );
    expect(restrictedImportErr).toBeDefined();
    expect(restrictedImportErr?.severity).toBe(2); // Error
  });

  it('fails with restricted import error when apps/web imports apps/server', async () => {
    const badCode = `
      import { ServerApp } from '../../apps/server';
      export const test = () => ServerApp;
    `;
    const results = await eslint.lintText(badCode, {
      filePath: path.resolve(process.cwd(), 'apps/web/App.tsx'),
    });
    expect(results).toHaveLength(1);
    const restrictedImportErr = results[0].messages.find(
      (m) =>
        m.ruleId === 'no-restricted-imports' &&
        m.message.includes('apps/web may not import apps/server directly')
    );
    expect(restrictedImportErr).toBeDefined();
    expect(restrictedImportErr?.severity).toBe(2);
  });

  it('fails with restricted import error when apps/web imports packages/db', async () => {
    const badCode = `
      import { PostgresDatabaseAdapter } from '../../packages/db';
      export const test = () => PostgresDatabaseAdapter;
    `;
    const results = await eslint.lintText(badCode, {
      filePath: path.resolve(process.cwd(), 'apps/web/App.tsx'),
    });
    expect(results).toHaveLength(1);
    const restrictedImportErr = results[0].messages.find(
      (m) =>
        m.ruleId === 'no-restricted-imports' &&
        m.message.includes('apps/web may not import packages/db directly')
    );
    expect(restrictedImportErr).toBeDefined();
    expect(restrictedImportErr?.severity).toBe(2);
  });

  it('fails with restricted import error when packages/** imports workers/** or apps/**', async () => {
    const badCode = `
      import { DecisionEngine } from '../../workers/decision';
      export const test = () => DecisionEngine;
    `;
    const results = await eslint.lintText(badCode, {
      filePath: path.resolve(process.cwd(), 'packages/auth/src/service.ts'),
    });
    expect(results).toHaveLength(1);
    const restrictedImportErr = results[0].messages.find(
      (m) =>
        m.ruleId === 'no-restricted-imports' &&
        m.message.includes('packages/** may not import workers/**')
    );
    expect(restrictedImportErr).toBeDefined();
    expect(restrictedImportErr?.severity).toBe(2);
  });

  it('warns when apps/server imports workers/** prior to R09 async decoupling', async () => {
    const serverWorkerImportCode = `
      import { DecisionEngine } from '../../workers/decision';
      export const test = () => DecisionEngine;
    `;
    const results = await eslint.lintText(serverWorkerImportCode, {
      filePath: path.resolve(process.cwd(), 'apps/server/index.ts'),
    });
    expect(results).toHaveLength(1);
    const restrictedImportWarn = results[0].messages.find(
      (m) =>
        m.ruleId === 'no-restricted-imports' &&
        m.message.includes('Architecture Warning (pre-R09): apps/server should communicate with workers asynchronously')
    );
    expect(restrictedImportWarn).toBeDefined();
    expect(restrictedImportWarn?.severity).toBe(1); // Warning
  });

  it('passes when apps/web imports permitted contracts', async () => {
    const validCode = `
      import type { AnalysisRun } from '@caim/contracts';
      export const getStatus = (run: AnalysisRun) => run.status;
    `;
    const results = await eslint.lintText(validCode, {
      filePath: path.resolve(process.cwd(), 'apps/web/App.tsx'),
    });
    expect(results).toHaveLength(1);
    const errors = results[0].messages.filter((m) => m.severity === 2);
    expect(errors).toHaveLength(0);
  });
});
