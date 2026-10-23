import { OntologyConcept, ONTOLOGY_SPEC_VERSION } from './types.ts';

/**
 * Standard Controlled Vocabulary Concepts Catalog (V2.0.1)
 */
export const STANDARD_CONCEPTS: Record<string, OntologyConcept> = {
  // --- Capabilities ---
  'capability.tools.exec': {
    concept_id: 'c0000000-0001-0000-0000-000000000001',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'capability',
    canonical_key: 'capability.tools.exec',
    display_name: 'Process Execution Tool',
    description: 'Capability to execute shell or child process commands on the host or in a sandbox',
    aliases: ['exec', 'bash', 'spawn_process', 'shell_tool'],
    status: 'ACTIVE',
  },
  'capability.tools.mcp': {
    concept_id: 'c0000000-0001-0000-0000-000000000002',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'capability',
    canonical_key: 'capability.tools.mcp',
    display_name: 'Model Context Protocol (MCP) Tool Integration',
    description: 'Capability to interact with external tools via Model Context Protocol servers',
    aliases: ['mcp_tool', 'mcp_client', 'mcp_server'],
    status: 'ACTIVE',
  },
  'capability.network.egress': {
    concept_id: 'c0000000-0001-0000-0000-000000000003',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'capability',
    canonical_key: 'capability.network.egress',
    display_name: 'Outbound Network Connectivity',
    description: 'Capability to make outbound HTTP/TCP/UDP connections to external addresses',
    aliases: ['http_client', 'fetch', 'axios', 'curl', 'network_out'],
    status: 'ACTIVE',
  },
  'capability.fs.read': {
    concept_id: 'c0000000-0001-0000-0000-000000000004',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'capability',
    canonical_key: 'capability.fs.read',
    display_name: 'Filesystem Read Access',
    description: 'Capability to inspect and read files from the host or storage workspace',
    aliases: ['read_file', 'fs_read', 'cat', 'open_file'],
    status: 'ACTIVE',
  },
  'capability.fs.write': {
    concept_id: 'c0000000-0001-0000-0000-000000000005',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'capability',
    canonical_key: 'capability.fs.write',
    display_name: 'Filesystem Write Access',
    description: 'Capability to create, edit, or delete files on the filesystem',
    aliases: ['write_file', 'edit_file', 'rm_file', 'fs_write'],
    status: 'ACTIVE',
  },
  'capability.code.eval': {
    concept_id: 'c0000000-0001-0000-0000-000000000006',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'capability',
    canonical_key: 'capability.code.eval',
    display_name: 'Dynamic Code Evaluation',
    description: 'Capability to dynamically parse and evaluate code at runtime (e.g. eval, Function constructor)',
    aliases: ['eval', 'vm_run', 'python_exec', 'dynamic_eval'],
    status: 'ACTIVE',
  },

  // --- Permissions ---
  'permission.fs.write': {
    concept_id: 'p0000000-0001-0000-0000-000000000001',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'permission',
    canonical_key: 'permission.fs.write',
    display_name: 'Filesystem Mutation Permission',
    description: 'Permission granting or requesting the ability to write or delete local files',
    aliases: ['write_permission', 'fs_write_grant'],
    status: 'ACTIVE',
  },
  'permission.net.outbound': {
    concept_id: 'p0000000-0001-0000-0000-000000000002',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'permission',
    canonical_key: 'permission.net.outbound',
    display_name: 'Outbound Network Permission',
    description: 'Permission granting outbound network egress to external endpoints',
    aliases: ['egress_permission', 'net_grant'],
    status: 'ACTIVE',
  },
  'permission.process.spawn': {
    concept_id: 'p0000000-0001-0000-0000-000000000003',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'permission',
    canonical_key: 'permission.process.spawn',
    display_name: 'Subprocess Execution Permission',
    description: 'Permission granting the ability to spawn sub-processes on the system',
    aliases: ['exec_permission', 'process_grant'],
    status: 'ACTIVE',
  },

  // --- Behaviors (Observed Runtime) ---
  'behavior.evasion.obfuscation': {
    concept_id: 'b0000000-0001-0000-0000-000000000001',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'behavior',
    canonical_key: 'behavior.evasion.obfuscation',
    display_name: 'Dynamic Payload Obfuscation',
    description: 'Empirical detection of dynamic decoding, string deobfuscation, or evasive execution',
    aliases: ['obfuscation', 'evasion', 'anti_analysis'],
    status: 'ACTIVE',
  },
  'behavior.data.exfiltration': {
    concept_id: 'b0000000-0001-0000-0000-000000000002',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'behavior',
    canonical_key: 'behavior.data.exfiltration',
    display_name: 'Sensitive Data Exfiltration',
    description: 'Empirical observed outbound transmission of sensitive memory or filesystem data',
    aliases: ['data_leak', 'exfiltration', 'secret_leak'],
    status: 'ACTIVE',
  },

  // --- Risks ---
  'risk.supply_chain.untrusted_dep': {
    concept_id: 'r0000000-0001-0000-0000-000000000001',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'risk',
    canonical_key: 'risk.supply_chain.untrusted_dep',
    display_name: 'Untrusted Supply Chain Dependency',
    description: 'Risk arising from unverified, typosquatted, or compromised dependencies',
    aliases: ['malicious_dep', 'supply_chain_vulnerability'],
    status: 'ACTIVE',
  },
  'risk.injection.prompt': {
    concept_id: 'r0000000-0001-0000-0000-000000000002',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'risk',
    canonical_key: 'risk.injection.prompt',
    display_name: 'Indirect Prompt Injection Susceptibility',
    description: 'Risk that external inputs can override system instructions and hijack execution',
    aliases: ['prompt_injection', 'jailbreak'],
    status: 'ACTIVE',
  },

  // --- Epistemic States ---
  'epistemic.observed_fact': {
    concept_id: 'e0000000-0001-0000-0000-000000000001',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'epistemic',
    canonical_key: 'epistemic.observed_fact',
    display_name: 'Directly Observed Empirical Fact',
    description: 'Fact directly verified from deterministic AST or dynamic execution trace',
    aliases: ['observed', 'fact'],
    status: 'ACTIVE',
  },
  'epistemic.derived_assertion': {
    concept_id: 'e0000000-0001-0000-0000-000000000002',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'epistemic',
    canonical_key: 'epistemic.derived_assertion',
    display_name: 'Analytically Derived Assertion',
    description: 'Assertion synthesized from evidence items through calibrated engine rules',
    aliases: ['derived', 'assertion', 'inferred'],
    status: 'ACTIVE',
  },
  'epistemic.hypothesis': {
    concept_id: 'e0000000-0001-0000-0000-000000000003',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'epistemic',
    canonical_key: 'epistemic.hypothesis',
    display_name: 'Candidate Analytical Hypothesis',
    description: 'Plausible condition with partial evidence requiring further evaluation or validation',
    aliases: ['hypothesis', 'candidate'],
    status: 'ACTIVE',
  },
  'epistemic.contradicted': {
    concept_id: 'e0000000-0001-0000-0000-000000000004',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'epistemic',
    canonical_key: 'epistemic.contradicted',
    display_name: 'Contradicted Hypothesis or Assertion',
    description: 'Condition with mutually exclusive opposing evidence',
    aliases: ['contradicted', 'refuted'],
    status: 'ACTIVE',
  },

  // --- Evidence Types ---
  'evidence.static_code': {
    concept_id: 'ev000000-0001-0000-0000-000000000001',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'evidence',
    canonical_key: 'evidence.static_code',
    display_name: 'Static Source Code Evidence',
    description: 'Proof extracted from source spans, AST syntax, or static text matches',
    aliases: ['static_code', 'ast_match'],
    status: 'ACTIVE',
  },
  'evidence.dynamic_call': {
    concept_id: 'ev000000-0001-0000-0000-000000000002',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'evidence',
    canonical_key: 'evidence.dynamic_call',
    display_name: 'Dynamic Execution Trace Evidence',
    description: 'Proof captured from sandbox runtime events, system calls, or network packets',
    aliases: ['dynamic_call', 'sandbox_event'],
    status: 'ACTIVE',
  },
  'evidence.metadata_manifest': {
    concept_id: 'ev000000-0001-0000-0000-000000000003',
    ontology_version: ONTOLOGY_SPEC_VERSION,
    namespace: 'evidence',
    canonical_key: 'evidence.metadata_manifest',
    display_name: 'Metadata Manifest Evidence',
    description: 'Proof declared in package.json, requirements.txt, Dockerfile, or MCP manifest',
    aliases: ['manifest', 'declaration'],
    status: 'ACTIVE',
  },
};

export function getConceptByCanonicalKey(canonicalKey: string): OntologyConcept | undefined {
  return STANDARD_CONCEPTS[canonicalKey];
}

export function getConceptsByNamespace(namespace: string): OntologyConcept[] {
  return Object.values(STANDARD_CONCEPTS).filter(c => c.namespace === namespace);
}
