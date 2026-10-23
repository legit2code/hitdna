import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Repository Integrity Test: Dead Security Code Guard
 *
 * Ensures no dead or shadow security enforcement classes (with SSRF or Archive in their name)
 * exist under packages/ or workers/ without being imported and used by real production modules.
 */
describe('Security Architecture: Dead Security Code Check', () => {
  it('fails if any class with SSRF or Archive in its name is defined under packages/ or workers/ but not imported by a production module', () => {
    const rootDir = process.cwd();
    const targetDirs = [path.join(rootDir, 'packages'), path.join(rootDir, 'workers')];

    // Collect all production ts files (excluding tests)
    const productionFiles: string[] = [];
    function collectFiles(dir: string) {
      if (!fs.existsSync(dir)) return;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '__tests__') continue;
          collectFiles(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') && !entry.name.endsWith('.spec.ts')) {
          productionFiles.push(fullPath);
        }
      }
    }

    targetDirs.forEach(d => collectFiles(d));
    collectFiles(path.join(rootDir, 'apps'));

    // Find all classes with SSRF or Archive in their name
    const securityClasses: Array<{ className: string; filePath: string }> = [];
    const classDefRegex = /(?:export\s+)?class\s+([A-Za-z0-9_]*(?:SSRF|Ssrf|Archive|archive)[A-Za-z0-9_]*)/g;

    for (const filePath of productionFiles) {
      const content = fs.readFileSync(filePath, 'utf8');
      let match: RegExpExecArray | null;
      while ((match = classDefRegex.exec(content)) !== null) {
        securityClasses.push({
          className: match[1],
          filePath: path.relative(rootDir, filePath),
        });
      }
    }

    // For each defined security class, verify it is imported or referenced by at least one OTHER production module
    const deadClasses: Array<{ className: string; filePath: string }> = [];

    for (const { className, filePath } of securityClasses) {
      // Error classes extending FetchGatewayError or Error can be considered used if imported
      const otherFiles = productionFiles.filter(f => path.relative(rootDir, f) !== filePath);
      
      const isImported = otherFiles.some(f => {
        const fileContent = fs.readFileSync(f, 'utf8');
        // Check if class name is referenced in imports or usages
        const importPattern = new RegExp(`\\b${className}\\b`);
        return importPattern.test(fileContent);
      });

      if (!isImported) {
        deadClasses.push({ className, filePath });
      }
    }

    expect(
      deadClasses,
      `Found dead security class(es) not imported by any production module: ${deadClasses.map(d => `${d.className} (${d.filePath})`).join(', ')}`
    ).toEqual([]);
  });
});
