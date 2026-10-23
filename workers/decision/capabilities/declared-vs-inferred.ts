/**
 * E36: Declared vs Inferred Capability Engine
 * Architecture V2.0.1 - Capability Analysis Subsystem
 *
 * Reconciles explicit agent capability claims (declared in manifests, system prompts,
 * or documentation) against actual AST/semantic inferred capabilities.
 * Detects under-declarations (undeclared capabilities = security risk) and
 * over-declarations (phantom capabilities = integrity/trust risk).
 */

export interface DeclaredCapability {
  name: string;
  category: 'NETWORK' | 'FILESYSTEM' | 'EXECUTION' | 'MEMORY' | 'MULTIMODAL' | 'TOOL_INVOCATION' | 'AUTH';
  description?: string;
  sourceLocation?: string;
  scope?: string[];
}

export interface InferredCapability {
  name: string;
  category: 'NETWORK' | 'FILESYSTEM' | 'EXECUTION' | 'MEMORY' | 'MULTIMODAL' | 'TOOL_INVOCATION' | 'AUTH';
  confidence: number; // 0.0 to 1.0
  evidenceSource: string; // AST node, rule ID, or API trace
  extractedSymbols: string[];
  scope?: string[];
}

export type CapabilityDiscrepancyType = 
  | 'UNDECLARED_CAPABILITY' // High Risk: Code has power not declared in manifest
  | 'OVERDECLARED_CAPABILITY' // Integrity Risk: Manifest claims power code cannot execute
  | 'SCOPE_ESCALATION' // Risk: Inferred scope exceeds declared scope bounds
  | 'RECONCILED_MATCH'; // Clean match

export interface CapabilityDiscrepancy {
  capabilityName: string;
  category: string;
  discrepancyType: CapabilityDiscrepancyType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  description: string;
  declaredScope?: string[];
  inferredScope?: string[];
  evidence: string[];
}

export interface CapabilityReconciliationReport {
  analysisRunId: string;
  agentId: string;
  declaredCount: number;
  inferredCount: number;
  matchedCount: number;
  discrepancies: CapabilityDiscrepancy[];
  undeclaredCapabilities: InferredCapability[];
  overdeclaredCapabilities: DeclaredCapability[];
  reconciliationScore: number; // 0.0 (total mismatch) to 1.0 (perfect harmony)
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
}

export class DeclaredVsInferredCapabilityEngine {
  public reconcile(
    analysisRunId: string,
    agentId: string,
    declared: DeclaredCapability[],
    inferred: InferredCapability[]
  ): CapabilityReconciliationReport {
    const discrepancies: CapabilityDiscrepancy[] = [];
    const matchedNames = new Set<string>();

    const declaredMap = new Map<string, DeclaredCapability>();
    for (const d of declared) {
      declaredMap.set(d.name.toLowerCase(), d);
    }

    const inferredMap = new Map<string, InferredCapability>();
    for (const inf of inferred) {
      inferredMap.set(inf.name.toLowerCase(), inf);
    }

    const undeclared: InferredCapability[] = [];
    const overdeclared: DeclaredCapability[] = [];

    // 1. Check inferred capabilities against declared
    for (const [infKey, inf] of inferredMap.entries()) {
      const decl = declaredMap.get(infKey);
      if (!decl) {
        // High severity undeclared power
        undeclared.push(inf);
        const isCritical = inf.category === 'EXECUTION' || inf.category === 'AUTH' || inf.category === 'NETWORK';
        discrepancies.push({
          capabilityName: inf.name,
          category: inf.category,
          discrepancyType: 'UNDECLARED_CAPABILITY',
          severity: isCritical ? 'CRITICAL' : 'HIGH',
          description: `Agent executes ${inf.category} capability '${inf.name}' but never declares it in its manifest or specification.`,
          inferredScope: inf.scope,
          evidence: [inf.evidenceSource, ...inf.extractedSymbols],
        });
      } else {
        matchedNames.add(infKey);
        // Check scope escalation
        if (inf.scope && decl.scope) {
          const declaredScopeSet = new Set(decl.scope.map((s) => s.toLowerCase()));
          const escalated = inf.scope.filter((s) => !declaredScopeSet.has(s.toLowerCase()));
          if (escalated.length > 0) {
            discrepancies.push({
              capabilityName: inf.name,
              category: inf.category,
              discrepancyType: 'SCOPE_ESCALATION',
              severity: 'HIGH',
              description: `Capability '${inf.name}' operates in undeclared scopes: [${escalated.join(', ')}]`,
              declaredScope: decl.scope,
              inferredScope: inf.scope,
              evidence: [inf.evidenceSource],
            });
          }
        }
      }
    }

    // 2. Check declared capabilities that have no inferred implementation
    for (const [declKey, decl] of declaredMap.entries()) {
      if (!matchedNames.has(declKey)) {
        overdeclared.push(decl);
        discrepancies.push({
          capabilityName: decl.name,
          category: decl.category,
          discrepancyType: 'OVERDECLARED_CAPABILITY',
          severity: 'MEDIUM',
          description: `Manifest advertises capability '${decl.name}' but no corresponding AST or semantic implementation was detected.`,
          declaredScope: decl.scope,
          evidence: [decl.sourceLocation || 'manifest.json'],
        });
      }
    }

    // 3. Compute score and risk level
    const totalUnique = new Set([...declaredMap.keys(), ...inferredMap.keys()]).size;
    const matchedCount = matchedNames.size;
    
    // Penalize heavily for undeclared critical capabilities
    const criticalDiscrepancies = discrepancies.filter((d) => d.severity === 'CRITICAL').length;
    const highDiscrepancies = discrepancies.filter((d) => d.severity === 'HIGH').length;

    let score = totalUnique === 0 ? 1.0 : Math.max(0, matchedCount / totalUnique - (criticalDiscrepancies * 0.3) - (highDiscrepancies * 0.1));
    score = Math.round(score * 100) / 100;

    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN' = 'CLEAN';
    if (criticalDiscrepancies > 0) {
      riskLevel = 'CRITICAL';
    } else if (highDiscrepancies > 0) {
      riskLevel = 'HIGH';
    } else if (discrepancies.length > 0) {
      riskLevel = 'MEDIUM';
    }

    return {
      analysisRunId,
      agentId,
      declaredCount: declared.length,
      inferredCount: inferred.length,
      matchedCount,
      discrepancies,
      undeclaredCapabilities: undeclared,
      overdeclaredCapabilities: overdeclared,
      reconciliationScore: score,
      riskLevel,
    };
  }
}
