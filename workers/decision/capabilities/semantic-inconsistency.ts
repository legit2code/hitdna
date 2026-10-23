/**
 * E41: Semantic Inconsistency Detection Engine
 * Architecture V2.0.1 - Capability Analysis Subsystem
 *
 * Discovers logical contradictions, semantic mismatches, and behavioral conflicts between:
 * 1. Stated safety guidelines vs implemented system prompt directives
 * 2. Advertised tool description vs actual underlying executable function signature
 * 3. Marketing/README claims vs AST-extracted control-flow behaviors
 * 4. User role boundaries vs accessible tool permissions
 */

export interface SemanticAssertion {
  assertionId: string;
  source: 'SYSTEM_PROMPT' | 'README' | 'TOOL_DOCSTRING' | 'SECURITY_POLICY' | 'AST_EXTRACTED_BEHAVIOR' | 'MANIFEST';
  statement: string;
  scope: string; // e.g. "privacy", "execution", "auth", "read_only"
  polarity: 'ALLOW' | 'DENY' | 'REQUIRES_AUTH' | 'CLAIMS_SAFETY' | 'READ_ONLY';
}

export type InconsistencyType =
  | 'POLICY_PROMPT_CONTRADICTION' // Policy denies, Prompt explicitly commands
  | 'DOCSTRING_CODE_MISMATCH' // Doc says read-only, code executes mutations
  | 'UNAUTHENTICATED_PROMOTION' // Policy requires auth, implementation skips guard
  | 'SAFETY_CLAIM_REFUTATION'; // README claims no network egress, AST has fetch()

export interface SemanticContradiction {
  contradictionId: string;
  inconsistencyType: InconsistencyType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  scope: string;
  assertionA: SemanticAssertion;
  assertionB: SemanticAssertion;
  explanation: string;
  impact: string;
}

export interface SemanticInconsistencyReport {
  analysisRunId: string;
  agentId: string;
  totalAssertionsAnalyzed: number;
  contradictionCount: number;
  inconsistencies: SemanticContradiction[];
  semanticIntegrityScore: number; // 0.0 to 1.0 (1.0 = completely consistent)
  isTrustworthy: boolean;
  status: 'CONSISTENT' | 'SUSPICIOUS_CONTRADICTIONS' | 'CRITICAL_SAFETY_MISMATCH';
}

export class SemanticInconsistencyDetectionEngine {
  public detectInconsistencies(
    analysisRunId: string,
    agentId: string,
    assertions: SemanticAssertion[]
  ): SemanticInconsistencyReport {
    const inconsistencies: SemanticContradiction[] = [];
    let contradictionCounter = 1;

    // Compare pairwise assertions on matching scopes
    for (let i = 0; i < assertions.length; i++) {
      for (let j = i + 1; j < assertions.length; j++) {
        const a = assertions[i];
        const b = assertions[j];

        if (a.scope.toLowerCase() !== b.scope.toLowerCase()) {
          continue;
        }

        // 1. Policy vs System Prompt Contradiction
        if (
          (a.source === 'SECURITY_POLICY' && b.source === 'SYSTEM_PROMPT' && a.polarity === 'DENY' && b.polarity === 'ALLOW') ||
          (b.source === 'SECURITY_POLICY' && a.source === 'SYSTEM_PROMPT' && b.polarity === 'DENY' && a.polarity === 'ALLOW')
        ) {
          const policyAss = a.source === 'SECURITY_POLICY' ? a : b;
          const promptAss = a.source === 'SYSTEM_PROMPT' ? a : b;

          inconsistencies.push({
            contradictionId: `SC-${contradictionCounter++}`,
            inconsistencyType: 'POLICY_PROMPT_CONTRADICTION',
            severity: 'CRITICAL',
            scope: a.scope,
            assertionA: policyAss,
            assertionB: promptAss,
            explanation: `Security policy specifies DENY for '${a.scope}', but system prompt commands the agent to ALLOW/execute it.`,
            impact: 'Agent prompt intentionally overrides organizational governance boundaries.',
          });
        }

        // 2. Docstring vs Code AST Mismatch (e.g. Read-Only claim vs mutation behavior)
        if (
          (a.source === 'TOOL_DOCSTRING' && b.source === 'AST_EXTRACTED_BEHAVIOR' && a.polarity === 'READ_ONLY' && b.polarity === 'ALLOW') ||
          (b.source === 'TOOL_DOCSTRING' && a.source === 'AST_EXTRACTED_BEHAVIOR' && b.polarity === 'READ_ONLY' && a.polarity === 'ALLOW')
        ) {
          const docAss = a.source === 'TOOL_DOCSTRING' ? a : b;
          const codeAss = a.source === 'AST_EXTRACTED_BEHAVIOR' ? a : b;

          inconsistencies.push({
            contradictionId: `SC-${contradictionCounter++}`,
            inconsistencyType: 'DOCSTRING_CODE_MISMATCH',
            severity: 'HIGH',
            scope: a.scope,
            assertionA: docAss,
            assertionB: codeAss,
            explanation: `Tool docstring claims operation is strictly READ_ONLY, but extracted AST code performs state mutations.`,
            impact: 'LLM tool-call planner may invoke dangerous mutation expecting harmless read-only behavior.',
          });
        }

        // 3. Safety Claim Refutation (README claims no network/filesystem access, AST performs egress)
        if (
          (a.source === 'README' && b.source === 'AST_EXTRACTED_BEHAVIOR' && a.polarity === 'CLAIMS_SAFETY' && b.polarity === 'ALLOW') ||
          (b.source === 'README' && a.source === 'AST_EXTRACTED_BEHAVIOR' && b.polarity === 'CLAIMS_SAFETY' && a.polarity === 'ALLOW')
        ) {
          const readmeAss = a.source === 'README' ? a : b;
          const astAss = a.source === 'AST_EXTRACTED_BEHAVIOR' ? a : b;

          inconsistencies.push({
            contradictionId: `SC-${contradictionCounter++}`,
            inconsistencyType: 'SAFETY_CLAIM_REFUTATION',
            severity: 'HIGH',
            scope: a.scope,
            assertionA: readmeAss,
            assertionB: astAss,
            explanation: `Documentation claims safety isolation for '${a.scope}', but AST code executes unmonitored operations in this domain.`,
            impact: 'Deceptive packaging or supply-chain trojan vector.',
          });
        }
      }
    }

    const criticalCount = inconsistencies.filter((c) => c.severity === 'CRITICAL').length;
    const highCount = inconsistencies.filter((c) => c.severity === 'HIGH').length;

    let score = assertions.length === 0 ? 1.0 : Math.max(0, 1.0 - (criticalCount * 0.4) - (highCount * 0.2) - (inconsistencies.length * 0.05));
    score = Math.round(score * 100) / 100;

    let status: 'CONSISTENT' | 'SUSPICIOUS_CONTRADICTIONS' | 'CRITICAL_SAFETY_MISMATCH' = 'CONSISTENT';
    if (criticalCount > 0) {
      status = 'CRITICAL_SAFETY_MISMATCH';
    } else if (inconsistencies.length > 0) {
      status = 'SUSPICIOUS_CONTRADICTIONS';
    }

    return {
      analysisRunId,
      agentId,
      totalAssertionsAnalyzed: assertions.length,
      contradictionCount: inconsistencies.length,
      inconsistencies,
      semanticIntegrityScore: score,
      isTrustworthy: criticalCount === 0 && highCount === 0,
      status,
    };
  }
}
