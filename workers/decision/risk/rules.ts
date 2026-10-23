/**
 * Versioned Risk Taxonomy & Evaluation Rules (V1 Baseline)
 * Architecture V2.0.1
 */

import { RiskTaxonomyRule } from '../types.ts';

export const RISK_TAXONOMY_V1: Record<string, RiskTaxonomyRule> = {
  // 1. Critical Hardcoded Secrets / Canaries
  CANARY_HONEYTOKEN_LEAK: {
    rule_id: 'RSK-CANARY-01',
    category: 'HONEYTOKEN_COMPROMISE',
    title_template: 'Canary Honeytoken Exfiltration Detected',
    severity: 'CRITICAL',
    base_likelihood: 1.0,
    base_impact: 1.0,
    description_template: 'Deceptive canary honeytoken was accessed and attempted exfiltration during execution.',
    remediation_template: 'Immediately revoke leaked credentials and investigate unauthorized environmental secret access.',
  },

  // 2. Critical Remote Code Execution / Dynamic Eval
  CODE_INJECTION_SINK: {
    rule_id: 'RSK-INJECT-01',
    category: 'CODE_EXECUTION',
    title_template: 'Arbitrary Code Execution via Dynamic Eval Sink',
    severity: 'CRITICAL',
    base_likelihood: 0.95,
    base_impact: 0.95,
    description_template: 'Unsanitized input flows directly into dynamic code execution sink (eval / Function constructor).',
    remediation_template: 'Refactor code to avoid dynamic eval; use safe AST interpretation or static schema parsers.',
  },

  // 3. Command Injection
  COMMAND_INJECTION_SINK: {
    rule_id: 'RSK-CMD-01',
    category: 'CODE_EXECUTION',
    title_template: 'OS Command Injection Vulnerability',
    severity: 'CRITICAL',
    base_likelihood: 0.90,
    base_impact: 0.95,
    description_template: 'Untrusted user or tool input is passed directly to child_process.exec without shell escape protection.',
    remediation_template: 'Use child_process.execFile with rigid array arguments instead of raw shell execution.',
  },

  // 4. Unauthorized Network Egress
  EGRESS_POLICY_VIOLATION: {
    rule_id: 'RSK-NET-01',
    category: 'DATA_EXFILTRATION',
    title_template: 'Unauthorized Network Egress Attempt',
    severity: 'HIGH',
    base_likelihood: 0.85,
    base_impact: 0.80,
    description_template: 'Agent attempted unauthorized outbound network connection violating default-deny network policy.',
    remediation_template: 'Enforce strict domain allowlists and verify sandbox network boundary restrictions.',
  },

  // 5. Anti-Analysis / Evasion Behavior
  SANDBOX_EVASION_BEHAVIOR: {
    rule_id: 'RSK-EVASION-01',
    category: 'DEFENSIVE_EVASION',
    title_template: 'Anti-Analysis & Evasion Probing Detected',
    severity: 'HIGH',
    base_likelihood: 0.85,
    base_impact: 0.75,
    description_template: 'Agent demonstrated sleep delays, environment fingerprinting, or anti-analysis probing.',
    remediation_template: 'Audit runtime scripts for evasion loops; require strict execution introspection.',
  },

  // 6. Reachable Vulnerable Dependency
  REACHABLE_CVE_DEPENDENCY: {
    rule_id: 'RSK-DEP-01',
    category: 'SUPPLY_CHAIN',
    title_template: 'Reachable High-Severity Vulnerability in Third-Party Dependency',
    severity: 'HIGH',
    base_likelihood: 0.75,
    base_impact: 0.85,
    description_template: 'A third-party dependency with known CVE is invoked via active call-graph path.',
    remediation_template: 'Upgrade dependency to patched release or remove reachability paths to vulnerable symbols.',
  },

  // 7. Hardcoded Static Secret / API Key
  HARDCODED_API_KEY: {
    rule_id: 'RSK-SECRET-01',
    category: 'CREDENTIAL_EXPOSURE',
    title_template: 'Hardcoded API Key or Secret in Source Artifact',
    severity: 'HIGH',
    base_likelihood: 0.90,
    base_impact: 0.80,
    description_template: 'Static source code analysis detected high-entropy token or hardcoded secret literal.',
    remediation_template: 'Move secrets to secure runtime environment variables or external secret vault.',
  },

  // 8. Missing Input Schema Validation
  MISSING_INPUT_VALIDATION: {
    rule_id: 'RSK-VAL-01',
    category: 'DATA_INTEGRITY',
    title_template: 'Missing Strict Schema Validation on Tool Boundary',
    severity: 'MEDIUM',
    base_likelihood: 0.60,
    base_impact: 0.50,
    description_template: 'Tool input payload is processed without comprehensive JSON schema or Zod validation.',
    remediation_template: 'Apply strict Zod or JSON Schema verification to all external tool parameters.',
  },

  // 9. Unhandled File System Traversal
  PATH_TRAVERSAL: {
    rule_id: 'RSK-FS-01',
    category: 'FILE_SYSTEM',
    title_template: 'Relative Path Traversal Exposure',
    severity: 'MEDIUM',
    base_likelihood: 0.65,
    base_impact: 0.55,
    description_template: 'File operations accept relative path components without root jail validation.',
    remediation_template: 'Normalize paths using path.resolve and verify they reside strictly within working root.',
  },

  // 10. Low Confidence / Ambiguous Spec
  AMBIGUOUS_SPECIFICATION: {
    rule_id: 'RSK-SPEC-01',
    category: 'GOVERNANCE',
    title_template: 'Ambiguous Tool Specification or Missing Semantic Docs',
    severity: 'LOW',
    base_likelihood: 0.40,
    base_impact: 0.30,
    description_template: 'Agent specification contains missing descriptions or untyped tool parameters.',
    remediation_template: 'Provide complete semantic parameter annotations and usage guidelines.',
  },
};
