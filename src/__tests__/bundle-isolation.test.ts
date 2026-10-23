import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Architecture Boundary: Client Bundle & Worker Isolation', () => {
  it('should verify that apps/web/App.tsx NEVER imports from workers/*', () => {
    const appTsxPath = path.resolve(process.cwd(), 'apps/web/App.tsx');
    const content = fs.readFileSync(appTsxPath, 'utf-8');

    expect(content).not.toMatch(/from\s+['"].*workers\/.+['"]/);
    expect(content).not.toMatch(/from\s+['"]@workers.*['"]/);
  });

  it('should verify that src/main.tsx NEVER imports from workers/*', () => {
    const mainTsxPath = path.resolve(process.cwd(), 'src/main.tsx');
    const content = fs.readFileSync(mainTsxPath, 'utf-8');

    expect(content).not.toMatch(/from\s+['"].*workers\/.+['"]/);
    expect(content).not.toMatch(/from\s+['"]@workers.*['"]/);
  });

  it('should recursively scan all source files in src/ and apps/web/ to ensure zero worker imports in client bundle', () => {
    const srcDir = path.resolve(process.cwd(), 'src');
    const webDir = path.resolve(process.cwd(), 'apps/web');
    
    function checkDir(dir: string) {
      if (!fs.existsSync(dir)) return;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name !== '__tests__') {
            checkDir(fullPath);
          }
        } else if (/\.(tsx?|jsx?)$/.test(entry.name)) {
          const fileContent = fs.readFileSync(fullPath, 'utf-8');
          const hasWorkerImport = /from\s+['"].*(?:\/|\b)workers\/.+['"]/.test(fileContent);
          expect(hasWorkerImport).toBe(false);
        }
      }
    }

    checkDir(srcDir);
    checkDir(webDir);
  });

  it('should verify top-level workers directory exists as sibling to packages and apps', () => {
    const workersDir = path.resolve(process.cwd(), 'workers');
    const packagesDir = path.resolve(process.cwd(), 'packages');
    const appsDir = path.resolve(process.cwd(), 'apps');

    expect(fs.existsSync(workersDir)).toBe(true);
    expect(fs.existsSync(packagesDir)).toBe(true);
    expect(fs.existsSync(appsDir)).toBe(true);

    const workerEntries = fs.readdirSync(workersDir);
    expect(workerEntries).toContain('discovery');
    expect(workerEntries).toContain('semantic');
    expect(workerEntries).toContain('static-analysis');
    expect(workerEntries).toContain('composition');
    expect(workerEntries).toContain('sandbox-orchestrator');
    expect(workerEntries).toContain('decision');
    expect(workerEntries).toContain('knowledge');
    expect(workerEntries).toContain('lifecycle');
    expect(workerEntries).toContain('evaluation');
    expect(workerEntries).toContain('registry.ts');
  });
});
