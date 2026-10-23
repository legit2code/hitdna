import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

/**
 * Checks whether an AST node is a literal-only object expression.
 * Returns true if the node is an ObjectLiteralExpression where ALL properties
 * have values that are Literals (String, Numeric, Boolean, Null) and zero expressions.
 */
function isLiteralOnlyObjectExpression(node: ts.Node): boolean {
  if (!ts.isObjectLiteralExpression(node)) {
    return false;
  }

  if (node.properties.length === 0) {
    return true;
  }

  return node.properties.every((prop) => {
    if (ts.isPropertyAssignment(prop)) {
      const init = prop.initializer;
      return (
        ts.isStringLiteral(init) ||
        ts.isNumericLiteral(init) ||
        init.kind === ts.SyntaxKind.TrueKeyword ||
        init.kind === ts.SyntaxKind.FalseKeyword ||
        init.kind === ts.SyntaxKind.NullKeyword
      );
    }
    return false;
  });
}

/**
 * Checks whether a function body returns ONLY a hardcoded object literal.
 */
function functionReturnsLiteralOnlyObject(fnNode: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression): boolean {
  if (!fnNode.body) return false;

  // Single expression arrow function: () => ({ a: 1 })
  if (!ts.isBlock(fnNode.body)) {
    return isLiteralOnlyObjectExpression(fnNode.body);
  }

  // Block body: check statements
  const statements = fnNode.body.statements.filter((s) => !ts.isEmptyStatement(s));
  if (statements.length === 1 && ts.isReturnStatement(statements[0])) {
    const retExpr = statements[0].expression;
    if (retExpr && isLiteralOnlyObjectExpression(retExpr)) {
      return true;
    }
  }

  return false;
}

describe('Workers Guard: Anti-Literal Job Return Guard', () => {
  it('detects and flags synthetic stub functions returning literal-only objects', () => {
    const fakeStubSource = `
      export async function runFakeDiscoveryJob(job: any) {
        return { status: 'DISCOVERY_COMPLETED', artifactsCount: 1 };
      }
    `;
    const sourceFile = ts.createSourceFile('fake.ts', fakeStubSource, ts.ScriptTarget.Latest, true);

    let flagged = false;
    ts.forEachChild(sourceFile, (node) => {
      if (ts.isFunctionDeclaration(node) && node.name?.text.endsWith('Job')) {
        if (functionReturnsLiteralOnlyObject(node)) {
          flagged = true;
        }
      }
    });

    expect(flagged).toBe(true);
  });

  it('verifies all exported *Job worker functions in workers/ do NOT return literal-only objects', () => {
    const workersDir = path.resolve(process.cwd(), 'workers');
    const workerDirs = fs.readdirSync(workersDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);

    const violations: Array<{ worker: string; fnName: string }> = [];
    let jobFunctionsFound = 0;

    for (const workerName of workerDirs) {
      const indexFile = path.join(workersDir, workerName, 'index.ts');
      if (!fs.existsSync(indexFile)) continue;

      const sourceCode = fs.readFileSync(indexFile, 'utf-8');
      const sourceFile = ts.createSourceFile(indexFile, sourceCode, ts.ScriptTarget.Latest, true);

      ts.forEachChild(sourceFile, (node) => {
        if (ts.isFunctionDeclaration(node)) {
          const fnName = node.name?.text || '';
          const isExported = node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

          if (isExported && fnName.endsWith('Job')) {
            jobFunctionsFound++;
            if (functionReturnsLiteralOnlyObject(node)) {
              violations.push({ worker: workerName, fnName });
            }
          }
        }
      });
    }

    expect(jobFunctionsFound).toBeGreaterThanOrEqual(3);
    expect(violations).toEqual([]);
  });
});
