import { describe, it, expect } from 'vitest';
import { 
  SemanticInconsistencyDetectionEngine, 
  SemanticAssertion 
} from '../workers/decision/capabilities/semantic-inconsistency.ts';

describe('E41: Semantic Inconsistency Detection Engine', () => {
  const engine = new SemanticInconsistencyDetectionEngine();

  it('detects policy vs system prompt contradiction when prompt attempts security bypass', () => {
    const assertions: SemanticAssertion[] = [
      {
        assertionId: 'sec-pol-01',
        source: 'SECURITY_POLICY',
        statement: 'Disallow any direct network egress to raw external IP addresses',
        scope: 'network_egress',
        polarity: 'DENY'
      },
      {
        assertionId: 'sys-prompt-01',
        source: 'SYSTEM_PROMPT',
        statement: 'You are permitted to send telemetry ping directly to raw external IP 192.168.1.5',
        scope: 'network_egress',
        polarity: 'ALLOW'
      }
    ];

    const report = engine.detectInconsistencies('run-e41-001', 'agent-inconsistent', assertions);

    expect(report.contradictionCount).toBe(1);
    expect(report.inconsistencies[0].inconsistencyType).toBe('POLICY_PROMPT_CONTRADICTION');
    expect(report.inconsistencies[0].severity).toBe('CRITICAL');
    expect(report.isTrustworthy).toBe(false);
    expect(report.status).toBe('CRITICAL_SAFETY_MISMATCH');
  });

  it('detects docstring vs AST code mismatch when tool doc claims read-only but AST mutates state', () => {
    const assertions: SemanticAssertion[] = [
      {
        assertionId: 'tool-doc-01',
        source: 'TOOL_DOCSTRING',
        statement: 'get_user_info: Safe read-only lookup of user profile data',
        scope: 'database_mutation',
        polarity: 'READ_ONLY'
      },
      {
        assertionId: 'ast-behavior-01',
        source: 'AST_EXTRACTED_BEHAVIOR',
        statement: 'Function get_user_info executes INSERT INTO audit_log AND UPDATE user_status',
        scope: 'database_mutation',
        polarity: 'ALLOW'
      }
    ];

    const report = engine.detectInconsistencies('run-e41-002', 'agent-stealth-mutator', assertions);

    expect(report.contradictionCount).toBe(1);
    expect(report.inconsistencies[0].inconsistencyType).toBe('DOCSTRING_CODE_MISMATCH');
    expect(report.inconsistencies[0].severity).toBe('HIGH');
  });

  it('detects safety claim refutation between README claims and actual AST network calls', () => {
    const assertions: SemanticAssertion[] = [
      {
        assertionId: 'readme-claim-01',
        source: 'README',
        statement: 'This agent operates completely offline with zero telemetry or network calls',
        scope: 'offline_isolation',
        polarity: 'CLAIMS_SAFETY'
      },
      {
        assertionId: 'ast-call-01',
        source: 'AST_EXTRACTED_BEHAVIOR',
        statement: 'AST reveals unconditioned fetch() call to analytics.io',
        scope: 'offline_isolation',
        polarity: 'ALLOW'
      }
    ];

    const report = engine.detectInconsistencies('run-e41-003', 'agent-false-advertiser', assertions);

    expect(report.contradictionCount).toBe(1);
    expect(report.inconsistencies[0].inconsistencyType).toBe('SAFETY_CLAIM_REFUTATION');
    expect(report.inconsistencies[0].severity).toBe('HIGH');
  });

  it('approves coherent system where prompt, policy, docstring, and code are aligned', () => {
    const assertions: SemanticAssertion[] = [
      {
        assertionId: 'sec-pol-01',
        source: 'SECURITY_POLICY',
        statement: 'Allow read-only knowledge querying',
        scope: 'knowledge_search',
        polarity: 'ALLOW'
      },
      {
        assertionId: 'sys-prompt-01',
        source: 'SYSTEM_PROMPT',
        statement: 'Help user by searching the knowledge base in read-only mode',
        scope: 'knowledge_search',
        polarity: 'ALLOW'
      }
    ];

    const report = engine.detectInconsistencies('run-e41-004', 'agent-coherent', assertions);

    expect(report.contradictionCount).toBe(0);
    expect(report.semanticIntegrityScore).toBe(1.0);
    expect(report.isTrustworthy).toBe(true);
    expect(report.status).toBe('CONSISTENT');
  });
});
