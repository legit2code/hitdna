/**
 * Static & Dynamic Reachability Engine
 * Invariant: VULNERABLE_PRESENT and VULNERABILITY_REACHABLE are strictly independent states.
 * A dependency being installed does NOT imply vulnerability reachability.
 */

import { 
  VulnerabilityAdvisory, 
  PackageIdentifier, 
  ReachabilityTrace, 
  ReachabilityStatus 
} from '../types.ts';
import { CallGraph, SymbolImportGraph } from '../../static-analysis/types.ts';

export interface ReachabilityContext {
  files: Map<string, string>;
  symbolGraph?: SymbolImportGraph;
  callGraph?: CallGraph;
  runtimeEvents?: Array<{ event_type: string; payload?: any }>;
}

export class ReachabilityEngine {
  /**
   * Evaluates reachability of vulnerabilities across components
   */
  public static evaluate(
    componentVulnMap: Map<string, VulnerabilityAdvisory[]>,
    allComponents: PackageIdentifier[],
    context: ReachabilityContext
  ): ReachabilityTrace[] {
    const traces: ReachabilityTrace[] = [];

    for (const comp of allComponents) {
      const advisories = componentVulnMap.get(comp.purl) || [];
      if (advisories.length === 0) continue;

      const compName = comp.name.toLowerCase();

      // Find all source files importing this package
      const importedInFiles: string[] = [];
      const importedSymbols: string[] = [];

      for (const [filePath, content] of context.files.entries()) {
        // Match import statements: import ... from 'pkg' or require('pkg')
        const importRegex = new RegExp(`(?:from\\s+['"]|require\\(['"])${compName}(?:/[^'"]+)?['"]`, 'g');
        if (importRegex.test(content)) {
          importedInFiles.push(filePath);

          // Extract named symbols: import { a, b } from 'pkg'
          const namedImportMatch = content.match(new RegExp(`import\\s*\\{([\\s\\S]*?)\\}\\s*from\\s*['"]${compName}['"]`));
          if (namedImportMatch) {
            const syms = namedImportMatch[1].split(',').map(s => s.trim().split(/\s+as\s+/)[0]).filter(Boolean);
            importedSymbols.push(...syms);
          }

          // Extract default/namespace: import lodash from 'lodash' or const lodash = require('lodash')
          const defaultImportMatch = content.match(new RegExp(`(?:import\\s+([a-zA-Z0-9_$]+)|const\\s+([a-zA-Z0-9_$]+)\\s*=\\s*require)\\(['"]${compName}['"]`));
          if (defaultImportMatch) {
            const sym = defaultImportMatch[1] || defaultImportMatch[2];
            if (sym) importedSymbols.push(sym);
          }
        }
      }

      for (const adv of advisories) {
        let status: ReachabilityStatus = 'VULNERABLE_PRESENT';
        let reachabilityPath: string[] = [];
        let confidence = 0.50;
        let evidenceDesc = '';
        let staticDepth = 0;
        let runtimeConfirmed = false;

        const targetVulnSymbols = adv.vulnerable_symbols || [];

        // Check if package is imported at all
        if (importedInFiles.length === 0) {
          status = 'VULNERABLE_PRESENT';
          confidence = 0.90;
          evidenceDesc = `Dependency [${comp.name}@${comp.version}] is present in manifest/lockfile but never imported in source files (Unreferenced).`;
        } else {
          // Package is imported. Check if vulnerable symbols are referenced / called.
          let symbolCalled = false;
          let matchedCallPath: string[] = [];

          // 1. Check direct imported symbols against vulnerable symbols
          for (const impSym of importedSymbols) {
            for (const vulnSym of targetVulnSymbols) {
              const baseVulnSym = vulnSym.split('.').pop() || vulnSym;
              if (impSym === baseVulnSym || impSym === vulnSym) {
                symbolCalled = true;
                matchedCallPath = [`import:${impSym}`, `call:${vulnSym}`];
                break;
              }
            }
            if (symbolCalled) break;
          }

          // 2. Check call graph reachability if available
          if (!symbolCalled && context.callGraph) {
            for (const edge of context.callGraph.edges) {
              for (const vulnSym of targetVulnSymbols) {
                const baseVulnSym = vulnSym.split('.').pop() || vulnSym;
                if (edge.callee_name.includes(baseVulnSym) || edge.callee_node_id.includes(baseVulnSym) || edge.callee_node_id.includes(comp.name)) {
                  symbolCalled = true;
                  matchedCallPath = [edge.caller_node_id, edge.callee_node_id];
                  staticDepth = 2;
                  break;
                }
              }
              if (symbolCalled) break;
            }
          }

          // 3. Scan code content for direct member invocations e.g. lodash.zipObjectDeep(...)
          if (!symbolCalled) {
            for (const [filePath, content] of context.files.entries()) {
              for (const vulnSym of targetVulnSymbols) {
                const baseVulnSym = vulnSym.split('.').pop() || vulnSym;
                const callRegex = new RegExp(`\\b(?:${compName}|_)\\.${baseVulnSym}\\s*\\(`, 'g');
                if (callRegex.test(content)) {
                  symbolCalled = true;
                  matchedCallPath = [`${filePath}`, `${compName}.${baseVulnSym}()`];
                  staticDepth = 1;
                  break;
                }
              }
              if (symbolCalled) break;
            }
          }

          if (symbolCalled) {
            status = 'VULNERABILITY_REACHABLE';
            reachabilityPath = matchedCallPath;
            confidence = 0.95;
            evidenceDesc = `Vulnerability [${adv.vuln_id}] is statically REACHABLE. Vulnerable symbol [${matchedCallPath.join(' -> ')}] is invoked in application call flow.`;
          } else {
            status = 'PRESENT_UNREACHED';
            confidence = 0.85;
            evidenceDesc = `Dependency [${comp.name}] is imported in source code, but specific vulnerable symbols [${targetVulnSymbols.join(', ') || 'N/A'}] are NOT invoked in static call graph.`;
          }
        }

        // 4. Runtime Confirmation Hook for Dynamic Telemetry
        if (context.runtimeEvents && context.runtimeEvents.length > 0) {
          for (const ev of context.runtimeEvents) {
            if (ev.payload && (ev.payload.package === comp.name || ev.payload.symbol_called)) {
              status = 'DYNAMICALLY_CONFIRMED_REACHABLE';
              runtimeConfirmed = true;
              confidence = 1.00;
              evidenceDesc = `Vulnerability [${adv.vuln_id}] in [${comp.name}] was DYNAMICALLY CONFIRMED executed during runtime instrumentation.`;
              break;
            }
          }
        }

        traces.push({
          vulnerability_id: adv.vuln_id,
          package_name: comp.name,
          package_purl: comp.purl,
          installed_version: comp.resolved_version || comp.version,
          status,
          is_direct_dependency: comp.is_direct,
          imported_in_files: importedInFiles,
          imported_symbols: importedSymbols,
          target_vulnerable_symbols: targetVulnSymbols,
          reachability_path: reachabilityPath,
          confidence,
          confidence_level: confidence >= 0.9 ? 'HIGH' : confidence >= 0.7 ? 'MEDIUM' : 'LOW',
          evidence_description: evidenceDesc,
          static_call_depth: staticDepth,
          runtime_confirmed: runtimeConfirmed,
        });
      }
    }

    return traces;
  }
}
