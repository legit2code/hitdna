/**
 * Symbol & Import Graph Builder
 * P15 — Static Analysis & Control Flow
 */

import { SymbolImportGraph, ModuleExport, ModuleImport, CrossFileBinding } from './types.ts';
import { ArtifactParseResult } from '@caim/syntax/types.ts';

export class StaticSymbolGraphBuilder {
  /**
   * Constructs the cross-file symbol and import dependency graph
   */
  public static build(
    artifactParse: ArtifactParseResult,
    filePaths: string[]
  ): SymbolImportGraph {
    const modules: SymbolImportGraph['modules'] = {};
    const crossFileBindings: CrossFileBinding[] = [];
    const unresolvedImports: SymbolImportGraph['unresolved_imports'] = [];

    const fileSet = new Set(filePaths);

    // 1. First pass: Register all module exports & raw imports
    for (const fileFact of artifactParse.file_facts) {
      const exports: ModuleExport[] = [];
      const imports: ModuleImport[] = [];
      const dependencies: string[] = [];

      // Collect exports
      for (const exp of fileFact.exports) {
        exports.push({
          name: exp.exported_symbol,
          kind: 'FUNCTION',
          span: exp.span,
          is_default: exp.is_default,
        });
      }

      // If no explicit exports found but top-level symbols exist, record functions/classes
      if (exports.length === 0) {
        for (const sym of fileFact.symbols) {
          if (sym.visibility === 'PUBLIC' || !sym.parent_symbol) {
            exports.push({
              name: sym.name,
              kind: (sym.kind as any) || 'FUNCTION',
              span: sym.span,
              is_default: false,
            });
          }
        }
      }

      // Collect imports
      for (const imp of fileFact.imports) {
        const isRelative = imp.module_specifier.startsWith('.') || imp.module_specifier.startsWith('/');
        const importedSymbolNames = imp.imported_symbols.map(s => s.name);

        const resolvedPath = isRelative 
          ? this.resolveRelativePath(fileFact.file_path, imp.module_specifier, fileSet)
          : undefined;

        if (!isRelative) {
          dependencies.push(imp.module_specifier);
        }

        imports.push({
          module_specifier: imp.module_specifier,
          resolved_path: resolvedPath,
          imported_symbols: importedSymbolNames,
          is_relative: isRelative,
          span: imp.span,
        });

        if (isRelative && !resolvedPath) {
          unresolvedImports.push({
            from_file: fileFact.file_path,
            specifier: imp.module_specifier,
            span: imp.span,
          });
        }
      }

      modules[fileFact.file_path] = {
        file_path: fileFact.file_path,
        exports,
        imports,
        dependencies,
      };
    }

    // 2. Second pass: Establish cross-file symbol bindings
    for (const [filePath, mod] of Object.entries(modules)) {
      for (const imp of mod.imports) {
        if (imp.resolved_path && modules[imp.resolved_path]) {
          const targetModule = modules[imp.resolved_path];

          for (const symName of imp.imported_symbols) {
            // Find in target module exports
            const targetExport = targetModule.exports.find(e => e.name === symName || (e.is_default && symName === 'default'));
            const isResolved = Boolean(targetExport);

            crossFileBindings.push({
              binding_id: `bind_${crypto.randomUUID().slice(0, 8)}`,
              from_file: filePath,
              from_symbol: symName,
              to_file: imp.resolved_path,
              to_symbol: targetExport ? targetExport.name : symName,
              is_resolved: isResolved,
              confidence: isResolved ? 0.98 : 0.60,
            });
          }
        }
      }
    }

    return {
      modules,
      cross_file_bindings: crossFileBindings,
      unresolved_imports: unresolvedImports,
    };
  }

  /**
   * Resolves a relative import specifier to an actual known file path in the workspace
   */
  private static resolveRelativePath(
    currentFilePath: string,
    specifier: string,
    allFiles: Set<string>
  ): string | undefined {
    const currentDirParts = currentFilePath.split('/');
    currentDirParts.pop(); // Remove filename

    const specParts = specifier.split('/');
    const combinedParts = [...currentDirParts];

    for (const part of specParts) {
      if (part === '.' || part === '') {
        continue;
      } else if (part === '..') {
        if (combinedParts.length > 0) combinedParts.pop();
      } else {
        combinedParts.push(part);
      }
    }

    const basePath = combinedParts.join('/');

    // Check exact match
    if (allFiles.has(basePath)) return basePath;

    // Check candidate extensions
    const candidateExtensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.go', '.rs'];
    for (const ext of candidateExtensions) {
      if (allFiles.has(`${basePath}${ext}`)) {
        return `${basePath}${ext}`;
      }
    }

    // Check index file inside directory
    for (const ext of candidateExtensions) {
      if (allFiles.has(`${basePath}/index${ext}`)) {
        return `${basePath}/index${ext}`;
      }
      if (allFiles.has(`${basePath}/main${ext}`)) {
        return `${basePath}/main${ext}`;
      }
    }

    // Strip existing JS/TS extension if specifier had it (e.g. ./foo.js -> ./foo.ts)
    const stripped = basePath.replace(/\.(js|jsx|ts|tsx|mjs)$/, '');
    for (const ext of candidateExtensions) {
      if (allFiles.has(`${stripped}${ext}`)) {
        return `${stripped}${ext}`;
      }
    }

    return undefined;
  }
}
