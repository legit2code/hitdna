import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
  countNonCommentLines,
  evaluateEngineModule,
  computeStatusData,
} from './generate-status.ts';

describe('Generate Status Engine Rules (F-13, F-14)', () => {
  it('correctly counts non-comment lines', () => {
    const sample = `
      // Single line comment
      import express from 'express';

      /*
        Block comment
        Multiple lines
      */
      const app = express();
      * comment continuation
      export default app;
    `;
    const count = countNonCommentLines(sample);
    expect(count).toBe(3); // import express, const app, export default app
  });

  it('given a fixture tree with a 10-line stub engine and a 200-line tested engine, the generator marks them STUB and IMPLEMENTED', async () => {
    const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-engine-fixture-'));

    try {
      // 1. Create a 10-line stub engine (<= 40 lines)
      const stubLines: string[] = [];
      for (let i = 1; i <= 10; i++) {
        stubLines.push(`export const stubField${i} = ${i};`);
      }
      const stubEnginePath = path.join(fixtureDir, 'stub-engine.ts');
      fs.writeFileSync(stubEnginePath, stubLines.join('\n'), 'utf-8');

      // 2. Create a 200-line engine (> 40 lines)
      const implementedLines: string[] = [];
      for (let i = 1; i <= 200; i++) {
        implementedLines.push(`export function func${i}() { return ${i}; }`);
      }
      const implementedEnginePath = path.join(fixtureDir, 'implemented-engine.ts');
      fs.writeFileSync(implementedEnginePath, implementedLines.join('\n'), 'utf-8');

      // 3. Create a test importing the implemented engine
      const testFilePath = path.join(fixtureDir, 'implemented.test.ts');
      const testContent = `
        import { func1, func2 } from './implemented-engine';
        describe('implemented engine', () => {
          it('works', () => { expect(func1()).toBe(1); });
        });
      `;
      fs.writeFileSync(testFilePath, testContent, 'utf-8');

      const testFiles = [
        {
          path: 'implemented.test.ts',
          content: testContent,
        },
      ];

      // 4. Evaluate stub engine
      const stubResult = evaluateEngineModule(
        'stub-engine',
        'stub-engine.ts',
        fixtureDir,
        testFiles
      );
      expect(stubResult.lineCount).toBe(10);
      expect(stubResult.status).toBe('STUB');

      // 5. Evaluate implemented engine
      const implementedResult = evaluateEngineModule(
        'implemented-engine',
        'implemented-engine.ts',
        fixtureDir,
        testFiles
      );
      expect(implementedResult.lineCount).toBe(200);
      expect(implementedResult.isTested).toBe(true);
      expect(implementedResult.status).toBe('IMPLEMENTED');
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('marks a 200-line engine as STUB if no test imports it', () => {
    const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-engine-untested-'));

    try {
      const lines: string[] = [];
      for (let i = 1; i <= 200; i++) {
        lines.push(`export const untestField${i} = ${i};`);
      }
      const enginePath = path.join(fixtureDir, 'untested-engine.ts');
      fs.writeFileSync(enginePath, lines.join('\n'), 'utf-8');

      const result = evaluateEngineModule('untested', 'untested-engine.ts', fixtureDir, []);
      expect(result.lineCount).toBe(200);
      expect(result.isTested).toBe(false);
      expect(result.status).toBe('STUB');
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('marks a 10-line engine as STUB even if tested', () => {
    const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'caim-engine-short-tested-'));

    try {
      const enginePath = path.join(fixtureDir, 'short-engine.ts');
      fs.writeFileSync(enginePath, 'export const a = 1;\nexport const b = 2;\n', 'utf-8');

      const testFiles = [{ path: 'test.ts', content: "import { a } from './short-engine';" }];
      const result = evaluateEngineModule('short', 'short-engine.ts', fixtureDir, testFiles);
      expect(result.lineCount).toBe(2);
      expect(result.isTested).toBe(true);
      expect(result.status).toBe('STUB');
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });
});
